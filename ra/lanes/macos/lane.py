"""macOS VM lane adapter (tart + pinned Xcode + sccache + build-webkit)."""

from __future__ import annotations

import json
import shlex
import shutil
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ra.lanes.base import (
    BaseLane,
    CrashRef,
    DeviceProfile,
    FeedStatus,
    Handle,
    HarnessRef,
    HumanCard,
    LaneError,
    LaneErrorCode,
    ProvisionResult,
    ProvisionState,
    Thermal,
    Tier,
)
from ra.lanes.commands import CommandRunner, SubprocessRunner

from .tart import TartVMController

MACOS_VM_CAPABILITIES = frozenset(
    {"macos", "vm", "tart", "xcode", "xcodes", "sccache", "webkit_jsc"}
)
DEFAULT_VM_NAME = "redapple-macos"
DEFAULT_CRASH_COMMAND = (
    "find \"$HOME/Library/Logs/DiagnosticReports\" -name '*.ips' -mmin -15 "
    "-print 2>/dev/null | head -50"
)


class MacOSVMLane(BaseLane):
    """Lane adapter for a tart macOS VM.

    The host only needs tart and the VM image. Xcode (pinned through xcodes),
    sccache, and ``build-webkit --jsc-only`` are wired as guest commands because
    the VM is the execution environment. Guest provisioning gaps discovered at
    launch emit one human card and park the lane in ``needs_hand``.
    """

    name = "macos-vm"

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        controller: TartVMController | None = None,
        card_sink: Callable[[HumanCard], None] | None = None,
        ring: Any | None = None,
        which: Callable[[str], str | None] | None = None,
        thermal_reader: Callable[[], Thermal | str] | None = None,
        feed_timeout_s: float = 30.0,
        vm_name: str = DEFAULT_VM_NAME,
        pinned_xcode_version: str | None = None,
        developer_dir: str | None = None,
        webkit_dir: str | None = None,
        sccache: bool = True,
        build_timeout_s: float = 3600.0,
        crash_command: str = DEFAULT_CRASH_COMMAND,
    ) -> None:
        super().__init__(feed_timeout_s=feed_timeout_s, card_sink=card_sink, ring=ring)
        self._runner = runner or SubprocessRunner()
        self._controller = controller or TartVMController(self._runner)
        self._which = which or shutil.which
        self._thermal_reader = thermal_reader
        self._vm_name = vm_name
        self._pinned_xcode_version = pinned_xcode_version
        self._developer_dir = developer_dir
        self._webkit_dir = webkit_dir
        self._sccache = sccache
        self._build_timeout_s = build_timeout_s
        self._crash_command = crash_command
        self._guest_ready_vms: set[str] = set()

    def capability(self) -> tuple[Tier, frozenset[str]]:
        """Report Tier.A as the highest-privilege execution environment.

        Appendix C requires a Tier; for the macOS VM slice a tart VM is the
        strongest lane. RA-LAN-004's A/B/C ladder remains the iOS device tiers.
        """
        return Tier.A, MACOS_VM_CAPABILITIES

    async def provision(self, p: DeviceProfile) -> ProvisionResult:
        """Verify host tart and the VM image, parking gaps as needs_hand."""
        self._profile = p
        self._ready = False
        self._paused = False
        self._drained = False

        if self._ring is not None and not self._ring.allows(p.ring_node, p.build):
            raise LaneError(
                LaneErrorCode.OUT_OF_RING,
                f"{p.ring_node}/{p.build or '<unknown>'} is outside the ring",
            )

        vm = self._vm_name_for(p)
        missing = [tool for tool in ("tart",) if self._which(tool) is None]
        if missing:
            return self._provision_gap(
                p,
                action="install_macos_lane_tools",
                title="Install macOS lane host tools",
                instruction="Install tart (brew install cirruslabs/cli/tart) and retry attach.",
                blocker="missing_host_tools",
                details={"missing": missing},
            )

        version = await self._runner.run(["tart", "--version"], timeout_s=10)
        if version.returncode != 0 or version.timed_out:
            return self._provision_gap(
                p,
                action="repair_tart",
                title="Repair tart installation",
                instruction="Run `tart --version` on the station host and fix the failure.",
                blocker="tart_unhealthy",
                details={"stderr": version.stderr[-500:]},
            )

        listing = await self._runner.run(["tart", "list", "--format=json"], timeout_s=30)
        if listing.returncode != 0 or listing.timed_out:
            return self._provision_gap(
                p,
                action="repair_tart",
                title="Repair tart installation",
                instruction="Run `tart list` on the station host and fix the failure.",
                blocker="tart_list_failed",
                details={"stderr": listing.stderr[-500:]},
            )
        if not self._vm_listed(listing.stdout, vm):
            return self._provision_gap(
                p,
                action="create_tart_vm",
                title=f"Create tart VM `{vm}`",
                instruction=f"Create or clone the pinned macOS VM image as `{vm}`, then retry attach.",
                blocker="vm_image_missing",
                details={"vm": vm},
            )

        p.tier = Tier.A
        p.state = "ready"
        p.thermal = Thermal.NOMINAL
        self._ready = True
        return ProvisionResult(
            ok=True,
            detail="ready",
            profile=p,
            state=ProvisionState.READY,
            tier=Tier.A,
            capabilities=MACOS_VM_CAPABILITIES,
            details={
                "vm": vm,
                "guest_checks": "deferred_to_launch",
                "webkit_dir": self._webkit_dir_for(p),
                "pinned_xcode_version": self._pinned_xcode_version,
            },
        )

    async def _launch(self, handle: Handle, target: str, harness: HarnessRef) -> None:
        vm = self._vm_name_for(self._profile)
        await self._ensure_vm_running(vm)
        await self._ensure_guest_ready(vm)
        if self._build_webkit_enabled(harness):
            await self._build_webkit(vm, harness)
        handle.metadata.update({"vm": vm, "guest_ready": True})

    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedStatus:
        vm = str(handle.metadata.get("vm") or self._vm_name_for(self._profile))
        if not await self._controller.is_running(vm):
            raise LaneError(LaneErrorCode.DEVICE_LOST, f"tart VM {vm} is not running")
        argv = self._feed_argv(handle.harness)
        if not argv:
            raise LaneError(
                LaneErrorCode.HARNESS_REJECTED,
                "macOS lane feed requires harness.argv or harness.metadata['feed_argv']",
            )
        guest_argv = self._guest_command(argv, handle.harness.env)
        res = await self._controller.exec(vm, guest_argv, input_bytes=data)
        if res.returncode == 0:
            return FeedStatus.ACCEPTED
        saturated = self._saturated_codes(handle.harness)
        if res.returncode in saturated:
            return FeedStatus.SATURATED
        return FeedStatus.REJECTED

    async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
        vm = str(handle.metadata.get("vm") or self._vm_name_for(self._profile))
        if not await self._controller.is_running(vm):
            raise LaneError(LaneErrorCode.DEVICE_LOST, f"tart VM {vm} is not running")
        command = str(handle.harness.metadata.get("crash_command") or self._crash_command)
        res = await self._controller.exec(vm, ["zsh", "-lc", command], timeout_s=30)
        if res.returncode != 0 or res.timed_out:
            raise LaneError(
                LaneErrorCode.DEVICE_LOST,
                "macOS crash collection failed",
                details={"vm": vm, "stderr": res.stderr[-500:]},
            )
        refs: list[CrashRef] = []
        for line in res.stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            refs.append(
                CrashRef(
                    id=f"crash_macos_{uuid.uuid4().hex[:12]}",
                    kind="macos_vm_crash",
                    handle_id=handle.handle_id,
                    path=path,
                    context="app",
                    metadata={"vm": vm},
                )
            )
            if len(refs) >= 50:
                break
        return refs

    async def _reset(self, handle: Handle) -> None:
        vm = str(handle.metadata.get("vm") or self._vm_name_for(self._profile))
        await self._controller.stop(vm)
        self._guest_ready_vms.discard(vm)

    async def _teardown(self) -> None:
        profile = self._profile
        vm = self._vm_name_for(profile) if profile is not None else self._vm_name
        try:
            await self._controller.stop(vm)
        finally:
            await self._controller.close()
            self._guest_ready_vms.clear()

    async def _read_thermal(self) -> Thermal | str:
        if self._thermal_reader is not None:
            return self._thermal_reader()
        vm = self._vm_name_for(self._profile)
        if not await self._controller.is_running(vm):
            return Thermal.NOMINAL
        res = await self._controller.exec(
            vm, ["zsh", "-lc", "pmset -g therm 2>/dev/null || true"], timeout_s=10
        )
        text = res.stdout.lower()
        if "critical" in text:
            return Thermal.CRITICAL
        if "no thermal warning" in text or "no thermal warnings" in text:
            return Thermal.NOMINAL
        if "serious" in text or "thermal warning" in text:
            return Thermal.SERIOUS
        return Thermal.NOMINAL

    def _vm_name_for(self, profile: DeviceProfile | None) -> str:
        meta: Mapping[str, Any] = profile.metadata if profile is not None else {}
        return str(meta.get("vm_name") or meta.get("vm_image") or self._vm_name)

    def _webkit_dir_for(self, profile: DeviceProfile | None) -> str | None:
        meta: Mapping[str, Any] = profile.metadata if profile is not None else {}
        value = meta.get("webkit_dir") or self._webkit_dir
        return None if value is None else str(value)

    def _build_webkit_enabled(self, harness: HarnessRef) -> bool:
        return bool(harness.metadata.get("build_webkit", True))

    @staticmethod
    def _vm_listed(stdout: str, vm: str) -> bool:
        text = stdout.strip()
        if not text:
            return False
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    name = item.get("Name") or item.get("name")
                    if name == vm:
                        return True
            return False
        if isinstance(data, dict):
            for key in ("VMs", "vms", "Vms"):
                items = data.get(key)
                if isinstance(items, list):
                    return any(
                        isinstance(item, dict) and (item.get("Name") or item.get("name")) == vm
                        for item in items
                    )
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == vm:
                return True
            if len(parts) == 1 and parts[0] == vm:
                return True
        return False

    def _provision_gap(
        self,
        profile: DeviceProfile,
        *,
        action: str,
        title: str,
        instruction: str,
        blocker: str,
        details: Mapping[str, Any],
    ) -> ProvisionResult:
        card = HumanCard(
            card_id=f"card_{uuid.uuid4().hex[:12]}",
            action=action,
            title=title,
            instruction=instruction,
            device_udid=profile.udid,
            blocker=blocker,
            metadata=dict(details),
        )
        self._emit_card(card)
        profile.state = "needs_hand"
        self._ready = False
        return ProvisionResult(
            ok=False,
            detail=title,
            profile=profile,
            state=ProvisionState.NEEDS_HAND,
            human_card=card,
            error_code=LaneErrorCode.NOT_PROVISIONED,
            details=dict(details),
        )

    async def _ensure_vm_running(self, vm: str) -> None:
        await self._controller.start(vm)

    async def _ensure_guest_ready(self, vm: str) -> None:
        if vm in self._guest_ready_vms:
            return
        required = ["xcodebuild"]
        if self._pinned_xcode_version:
            required.insert(0, "xcodes")
        if self._sccache:
            required.append("sccache")
        tools = " ".join(shlex.quote(tool) for tool in required)
        missing_script = (
            "missing=''; "
            f"for t in {tools}; do "
            "command -v \"$t\" >/dev/null 2>&1 || missing=\"$missing $t\"; "
            "done; "
            "if [ -n \"$missing\" ]; then printf 'missing:%s\\n' \"$missing\" >&2; exit 1; fi"
        )
        res = await self._controller.exec(vm, ["zsh", "-lc", missing_script], timeout_s=30)
        if res.returncode != 0 or res.timed_out:
            missing = self._parse_missing_tools(res.stderr) or ["unknown"]
            self._guest_gap(
                action="provision_vm_tools",
                title="Provision macOS VM guest tools",
                instruction=(
                    "Install xcodes, sccache, and Xcode command line tools inside the "
                    f"tart VM `{vm}` (missing:{','.join(missing)}), then retry."
                ),
                blocker="guest_tools_missing",
                details={"vm": vm, "missing": missing, "stderr": res.stderr[-500:]},
            )
        if self._pinned_xcode_version:
            installed = await self._controller.exec(
                vm, ["zsh", "-lc", "xcodes installed"], timeout_s=30
            )
            if (
                installed.returncode != 0
                or installed.timed_out
                or self._pinned_xcode_version not in installed.stdout
            ):
                self._guest_gap(
                    action="install_pinned_xcode",
                    title=f"Install pinned Xcode {self._pinned_xcode_version}",
                    instruction=(
                        "Inside the tart VM run "
                        f"`xcodes install {self._pinned_xcode_version} --select`, then retry."
                    ),
                    blocker="pinned_xcode_missing",
                    details={"vm": vm, "xcode": self._pinned_xcode_version},
                )
            selected = await self._controller.exec(
                vm, ["zsh", "-lc", f"xcodes select {shlex.quote(self._pinned_xcode_version)}"],
                timeout_s=60,
            )
            if selected.returncode != 0 or selected.timed_out:
                self._guest_gap(
                    action="select_pinned_xcode",
                    title=f"Select pinned Xcode {self._pinned_xcode_version}",
                    instruction=(
                        "Allow `xcodes select` to run inside the tart VM (sudoers/keychain "
                        "may need one human unlock), then retry."
                    ),
                    blocker="xcode_select_failed",
                    details={"vm": vm, "stderr": selected.stderr[-500:]},
                )
        if self._sccache:
            stats = await self._controller.exec(vm, ["zsh", "-lc", "sccache --show-stats"], timeout_s=30)
            if stats.returncode != 0 or stats.timed_out:
                self._guest_gap(
                    action="repair_sccache",
                    title="Repair guest sccache",
                    instruction="Run `sccache --show-stats` inside the tart VM and fix the failure.",
                    blocker="sccache_unhealthy",
                    details={"vm": vm, "stderr": stats.stderr[-500:]},
                )
        xcode = await self._controller.exec(vm, ["zsh", "-lc", "xcodebuild -version"], timeout_s=30)
        if xcode.returncode != 0 or xcode.timed_out:
            self._guest_gap(
                action="repair_xcode",
                title="Repair guest Xcode",
                instruction="Run `xcodebuild -version` inside the tart VM and fix the failure.",
                blocker="xcode_unhealthy",
                details={"vm": vm, "stderr": xcode.stderr[-500:]},
            )
        self._guest_ready_vms.add(vm)

    @staticmethod
    def _parse_missing_tools(stderr: str) -> list[str]:
        for line in stderr.splitlines():
            if line.startswith("missing:"):
                return [part for part in line.split(":", 1)[1].split() if part]
        return []

    def _guest_gap(
        self,
        *,
        action: str,
        title: str,
        instruction: str,
        blocker: str,
        details: Mapping[str, Any],
    ) -> None:
        profile = self._profile
        if profile is None:
            profile = DeviceProfile(udid="unknown", ring_node="unknown", state="needs_hand", tier=Tier.A)
        card = HumanCard(
            card_id=f"card_{uuid.uuid4().hex[:12]}",
            action=action,
            title=title,
            instruction=instruction,
            device_udid=profile.udid,
            blocker=blocker,
            metadata=dict(details),
        )
        self._emit_card(card)
        profile.state = "needs_hand"
        self._ready = False
        raise LaneError(
            LaneErrorCode.NOT_PROVISIONED,
            title,
            details={**dict(details), "card_id": card.card_id},
        )

    async def _build_webkit(self, vm: str, harness: HarnessRef) -> None:
        webkit_dir = self._webkit_dir_for(self._profile)
        if webkit_dir is None:
            raise LaneError(
                LaneErrorCode.HARNESS_REJECTED,
                "build_webkit requires webkit_dir on the lane or harness metadata",
            )
        build_args = harness.metadata.get("build_args", ())
        if isinstance(build_args, str):
            build_args = tuple(build_args.split())
        exports = self._guest_exports(harness)
        script = "set -euo pipefail\n" + exports
        script += f"cd {shlex.quote(webkit_dir)}\n"
        script += shlex.join(["Tools/Scripts/build-webkit", "--jsc-only", *map(str, build_args)]) + "\n"
        res = await self._controller.exec(vm, ["zsh", "-lc", script], timeout_s=self._build_timeout_s)
        if res.timed_out or res.returncode != 0:
            tail = (res.stderr or res.stdout)[-1000:]
            raise LaneError(
                LaneErrorCode.HARNESS_REJECTED,
                "build-webkit --jsc-only failed",
                details={"vm": vm, "webkit_dir": webkit_dir, "output_tail": tail},
            )

    def _guest_exports(self, harness: HarnessRef) -> str:
        lines: list[str] = []
        developer_dir = harness.metadata.get("developer_dir") or self._developer_dir
        if developer_dir:
            lines.append(f"export DEVELOPER_DIR={shlex.quote(str(developer_dir))}")
        if self._sccache:
            lines.append("export WK_USE_SCCACHE=YES")
        return "".join(line + "\n" for line in lines)

    @staticmethod
    def _feed_argv(harness: HarnessRef) -> Sequence[str]:
        argv = harness.argv
        if not argv:
            feed_argv = harness.metadata.get("feed_argv") or harness.metadata.get("run_argv")
            if isinstance(feed_argv, str):
                return tuple(feed_argv.split())
            if isinstance(feed_argv, Sequence):
                return tuple(str(part) for part in feed_argv)
        return tuple(str(part) for part in argv)

    @staticmethod
    def _saturated_codes(harness: HarnessRef) -> set[int]:
        raw = harness.metadata.get("saturated_return_codes", (75,))
        if isinstance(raw, int):
            return {raw}
        if isinstance(raw, str):
            return {int(part) for part in raw.replace(",", " ").split()}
        return {int(code) for code in raw}

    @staticmethod
    def _guest_command(argv: Sequence[str], env: Mapping[str, str]) -> list[str]:
        if not env:
            return [str(part) for part in argv]
        exports = "".join(f"export {key}={shlex.quote(value)}\n" for key, value in env.items())
        script = exports + "exec " + shlex.join([str(part) for part in argv]) + "\n"
        return ["zsh", "-lc", script]
