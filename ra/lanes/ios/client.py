"""iOS attach client protocols and a best-effort libimobiledevice client.

The automaton order is owned by ``IOSTierCLane``; this module provides the
thin device boundary so unit tests can run against fakes. Commands that need
a physical iPhone, DDI, signing material, or a JSC transport remain
device-gated and are documented in ``README.md``.
"""

from __future__ import annotations

import plistlib
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from ra.lanes.base import (
    CrashRef,
    FeedResult,
    FeedStatus,
    LaneError,
    LaneErrorCode,
    Thermal,
)
from ra.lanes.commands import CommandResult, CommandRunner, SubprocessRunner


@dataclass
class IosDeviceInfo:
    """Mutable device state gathered by the attach automaton."""

    udid: str
    build: str | None = None
    product_type: str | None = None
    product_version: str | None = None
    trusted: bool | None = None
    developer_mode: bool | None = None
    ddi_mounted: bool = False
    capabilities: frozenset[str] = frozenset()
    signing_expires_ms: int | None = None
    signing_renewals: int = 0
    ring_node: str | None = None
    thermal: Thermal = Thermal.NOMINAL
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IosInstallResult:
    ok: bool
    error_code: LaneErrorCode | None = None
    message: str = ""
    signing_expires_ms: int | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


class IosAttachClient(Protocol):
    """Device boundary for the RA-LAN-002 attach automaton."""

    async def identify(self, udid: str) -> IosDeviceInfo: ...

    async def check_trust_dev_mode(self, info: IosDeviceInfo) -> IosDeviceInfo: ...

    async def mount_ddi(self, info: IosDeviceInfo) -> IosDeviceInfo: ...

    async def sign_install(self, info: IosDeviceInfo) -> IosInstallResult: ...

    async def probe_capabilities(self, info: IosDeviceInfo) -> frozenset[str]: ...

    async def collect_crashes(self, info: IosDeviceInfo) -> list[CrashRef]: ...

    async def read_thermal(self, info: IosDeviceInfo) -> Thermal: ...

    async def reset_device(self, info: IosDeviceInfo) -> None: ...

    async def renew_signing(self, info: IosDeviceInfo) -> IosInstallResult: ...

    async def release_udid(self, info: IosDeviceInfo, reason: str) -> None: ...


class JscTransport(Protocol):
    """Transport to the on-device JavaScriptCore harness (device-gated)."""

    async def open(self, handle: Any) -> None: ...

    async def eval(self, handle: Any, data: bytes) -> FeedResult | FeedStatus | str: ...

    async def close(self, handle: Any) -> None: ...


class LibimobiledeviceIosAttachClient:
    """Best-effort usbmuxd/ideviceinfo/pymobiledevice3 attach client.

    Provisioning commands are configurable so the station can wire the real
    signing/install/probe path without changing the lane automaton.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        install_command: Sequence[str] | None = None,
        sign_command: Sequence[str] | None = None,
        probe_command: Sequence[str] | None = None,
        crash_command: Sequence[str] | None = None,
        reset_command: Sequence[str] | None = None,
        thermal_reader: Callable[[], Thermal | str] | None = None,
        signing_ttl_ms: int = 7 * 24 * 60 * 60 * 1000,
    ) -> None:
        self._runner = runner or SubprocessRunner()
        self._install_command = install_command
        self._sign_command = sign_command
        self._probe_command = probe_command
        self._crash_command = crash_command
        self._reset_command = reset_command
        self._thermal_reader = thermal_reader
        self._signing_ttl_ms = signing_ttl_ms

    async def identify(self, udid: str) -> IosDeviceInfo:
        devices = await self._run(["idevice_id", "-l"], timeout_s=10)
        if udid not in devices.stdout.split():
            raise LaneError(LaneErrorCode.DEVICE_LOST, f"udid {udid} is not visible to usbmuxd")
        res = await self._run(["ideviceinfo", "-u", udid, "-x"], timeout_s=30)
        if res.returncode != 0:
            raise LaneError(LaneErrorCode.DEVICE_LOST, "ideviceinfo failed", details={"udid": udid})
        try:
            plist = plistlib.loads(res.stdout.encode("utf-8"))
        except Exception as exc:
            raise LaneError(LaneErrorCode.DEVICE_LOST, "ideviceinfo returned invalid plist") from exc
        raw = {str(k): v for k, v in plist.items()}
        trusted = raw.get("Trusted")
        dev_status = raw.get("DeveloperModeStatus")
        return IosDeviceInfo(
            udid=udid,
            build=self._first(raw, "BuildVersion", "ProductVersion"),
            product_type=self._first(raw, "ProductType"),
            product_version=self._first(raw, "ProductVersion"),
            trusted=trusted if isinstance(trusted, bool) else None,
            developer_mode=self._dev_mode(dev_status),
            raw=raw,
        )

    async def check_trust_dev_mode(self, info: IosDeviceInfo) -> IosDeviceInfo:
        pair = await self._run(["idevicepair", "validate", "-u", info.udid], timeout_s=30)
        trusted = pair.returncode == 0 and not pair.timed_out
        dev = await self._run(["ideviceinfo", "-u", info.udid, "-k", "DeveloperModeStatus"], timeout_s=15)
        developer_mode = self._dev_mode(dev.stdout.strip() if dev.returncode == 0 else None)
        return replace(info, trusted=trusted, developer_mode=developer_mode)

    async def mount_ddi(self, info: IosDeviceInfo) -> IosDeviceInfo:
        res = await self._run(
            ["pymobiledevice3", "mounter", "auto-mount", "--udid", info.udid], timeout_s=120
        )
        mounted = res.returncode == 0 and not res.timed_out
        return replace(info, ddi_mounted=mounted, raw={**info.raw, "ddi_mount": res.stdout[-500:]})

    async def sign_install(self, info: IosDeviceInfo) -> IosInstallResult:
        if self._install_command is None:
            return IosInstallResult(
                ok=False,
                error_code=LaneErrorCode.NOT_PROVISIONED,
                message="iOS harness install command is not configured",
            )
        argv = self._substitute(self._install_command, info)
        res = await self._run(argv, timeout_s=600)
        if res.returncode == 0 and not res.timed_out:
            return IosInstallResult(
                ok=True,
                signing_expires_ms=info.signing_expires_ms or self._next_signing_expiry(),
            )
        code = LaneErrorCode.SIGNING_EXPIRED if self._looks_signing_expired(res) else LaneErrorCode.INSTALL_FAILED
        return IosInstallResult(ok=False, error_code=code, message=(res.stderr or res.stdout)[-500:])

    async def probe_capabilities(self, info: IosDeviceInfo) -> frozenset[str]:
        if self._probe_command is None:
            return frozenset()
        res = await self._run(self._substitute(self._probe_command, info), timeout_s=120)
        if res.returncode != 0 or res.timed_out:
            return frozenset()
        caps: set[str] = set()
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith(("capability:", "CAP:")):
                caps.add(line.split(":", 1)[1].strip())
        return frozenset(caps)

    async def collect_crashes(self, info: IosDeviceInfo) -> list[CrashRef]:
        if self._crash_command is None:
            return []
        res = await self._run(self._substitute(self._crash_command, info), timeout_s=120)
        if res.returncode != 0 or res.timed_out:
            raise LaneError(
                LaneErrorCode.DEVICE_LOST,
                "iOS crash collection failed",
                details={"udid": info.udid, "stderr": res.stderr[-500:]},
            )
        refs: list[CrashRef] = []
        for line in res.stdout.splitlines():
            path = line.strip()
            if path.endswith((".ips", ".crash", ".panic")):
                refs.append(
                    CrashRef(
                        id=f"crash_ios_{uuid.uuid4().hex[:12]}",
                        kind="ios_crash",
                        path=path,
                        context="app",
                        metadata={"udid": info.udid},
                    )
                )
        return refs

    async def read_thermal(self, info: IosDeviceInfo) -> Thermal:
        if self._thermal_reader is not None:
            return Thermal(self._thermal_reader())
        return Thermal.NOMINAL

    async def reset_device(self, info: IosDeviceInfo) -> None:
        if self._reset_command is not None:
            res = await self._run(self._substitute(self._reset_command, info), timeout_s=120)
        else:
            res = await self._run(["idevicediagnostics", "restart", "-u", info.udid], timeout_s=30)
        if res.returncode != 0 or res.timed_out:
            raise LaneError(
                LaneErrorCode.DEVICE_LOST,
                "iOS device reset failed",
                details={"udid": info.udid, "stderr": res.stderr[-500:]},
            )

    async def renew_signing(self, info: IosDeviceInfo) -> IosInstallResult:
        if self._sign_command is None:
            return IosInstallResult(
                ok=False,
                error_code=LaneErrorCode.SIGNING_EXPIRED,
                message="iOS signing renewal command is not configured",
            )
        res = await self._run(self._substitute(self._sign_command, info), timeout_s=600)
        if res.returncode == 0 and not res.timed_out:
            return IosInstallResult(ok=True, signing_expires_ms=self._next_signing_expiry())
        return IosInstallResult(
            ok=False,
            error_code=LaneErrorCode.SIGNING_EXPIRED,
            message=(res.stderr or res.stdout)[-500:],
        )

    async def release_udid(self, info: IosDeviceInfo, reason: str) -> None:
        # The fleet owns the UDID semaphore; device clients have no lease to drop.
        return None

    async def _run(self, argv: Sequence[str], *, timeout_s: float) -> CommandResult:
        try:
            return await self._runner.run(argv, timeout_s=timeout_s)
        except OSError as exc:
            raise LaneError(
                LaneErrorCode.NOT_PROVISIONED,
                f"{argv[0]} is not installed or not executable",
                details={"argv0": argv[0]},
            ) from exc

    @staticmethod
    def _first(raw: Mapping[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in raw:
                return raw[key]
        return None

    @staticmethod
    def _dev_mode(value: Any) -> bool | None:
        if value is None:
            return None
        text = str(value).strip().lower()
        if "enable" in text or text == "1" or text == "true":
            return True
        if "disable" in text or text == "0" or text == "false":
            return False
        return None

    @staticmethod
    def _looks_signing_expired(res: CommandResult) -> bool:
        text = f"{res.stdout}\n{res.stderr}".lower()
        return "expired" in text or "signing certificate" in text or "provisioning profile" in text

    def _next_signing_expiry(self) -> int:
        return int(time.time() * 1000) + self._signing_ttl_ms

    @staticmethod
    def _substitute(argv: Sequence[str], info: IosDeviceInfo) -> list[str]:
        return [
            part.replace("{udid}", info.udid)
            .replace("{bundle_id}", str(info.raw.get("bundle_id", "")))
            .replace("{harness_app}", str(info.raw.get("harness_app", "")))
            for part in argv
        ]
