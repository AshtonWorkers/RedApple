"""iOS Tier C lane: attach automaton + device JavaScriptCore harness."""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any

from ra.lanes.base import (
    BaseLane,
    CrashRef,
    DeviceProfile,
    FeedResult,
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

from .client import IosAttachClient, JscTransport, LibimobiledeviceIosAttachClient

IOS_TIER_C_CAPABILITIES = frozenset(
    {
        "ios",
        "tier_c",
        "usbmuxd",
        "ideviceinfo",
        "pymobiledevice3",
        "ddi",
        "sign_install",
        "javascriptcore",
        "dlopen",
        "context_app",
    }
)
IOS_PROBE_CAPABILITY = "javascriptcore"
DEFAULT_TIER_C_TARGET = "javascriptcore"


class IOSTierCLane(BaseLane):
    """Tier C iOS lane driven by a physical device and JSC harness.

    The lane owns the RA-LAN-002 attach automaton order. Clients are thin
    device boundaries so the lane can be tested without hardware; JSC feeding
    requires a configured ``JscTransport`` and remains device-gated.
    """

    name = "ios-tier-c"

    def __init__(
        self,
        *,
        attach_client: IosAttachClient | None = None,
        client_runner: CommandRunner | None = None,
        jsc_transport: JscTransport | None = None,
        card_sink: Callable[[HumanCard], None] | None = None,
        ring: Any | None = None,
        feed_timeout_s: float = 30.0,
        signing_renew_before_ms: int = 28 * 60 * 60 * 1000,
        max_signing_renewals: int = 3,
    ) -> None:
        super().__init__(feed_timeout_s=feed_timeout_s, card_sink=card_sink, ring=ring)
        self._attach_client = attach_client or LibimobiledeviceIosAttachClient(
            runner=client_runner or SubprocessRunner()
        )
        self._jsc_transport = jsc_transport
        self._signing_renew_before_ms = signing_renew_before_ms
        self._max_signing_renewals = max_signing_renewals
        self._info: Any | None = None
        self._opened_handles: dict[str, Handle] = {}

    def capability(self) -> tuple[Tier, frozenset[str]]:
        return Tier.C, IOS_TIER_C_CAPABILITIES

    async def provision(self, p: DeviceProfile) -> ProvisionResult:
        self._profile = p
        self._ready = False
        self._paused = False
        self._drained = False

        if self._ring is not None and not self._ring.allows(p.ring_node, p.build):
            raise LaneError(
                LaneErrorCode.OUT_OF_RING,
                f"{p.ring_node}/{p.build or '<unknown>'} is outside the ring",
            )

        try:
            info = await self._attach_client.identify(p.udid)
        except LaneError as exc:
            if exc.code in (LaneErrorCode.DEVICE_LOST, LaneErrorCode.NOT_PROVISIONED):
                return self._provision_gap(
                    p,
                    action="connect_ios_device",
                    title="Connect iOS device",
                    instruction="Connect the iPhone by USB, unlock it, and tap Trust if asked.",
                    blocker=exc.code.value.lower(),
                    error_code=exc.code,
                    details={"udid": p.udid, "error": str(exc)},
                )
            raise

        try:
            info = await self._attach_client.check_trust_dev_mode(info)
        except LaneError as exc:
            if exc.code in (LaneErrorCode.DEVICE_LOST, LaneErrorCode.NOT_PROVISIONED):
                return self._ios_tool_gap(p, exc, step="trust/dev-mode check")
            raise
        if info.trusted is not True or info.developer_mode is not True:
            return self._provision_gap(
                p,
                action="trust_enable_developer_mode",
                title="Trust device and enable Developer Mode",
                instruction=(
                    "On the iPhone: tap Trust for this Mac and enable Developer Mode "
                    "(Settings > Privacy & Security > Developer Mode), then retry."
                ),
                blocker="trust_or_dev_mode_missing",
                details={
                    "udid": p.udid,
                    "trusted": info.trusted,
                    "developer_mode": info.developer_mode,
                },
            )

        try:
            info = await self._attach_client.mount_ddi(info)
        except LaneError as exc:
            if exc.code in (LaneErrorCode.DEVICE_LOST, LaneErrorCode.NOT_PROVISIONED):
                return self._ios_tool_gap(p, exc, step="DDI mount")
            raise
        if not info.ddi_mounted:
            return self._provision_gap(
                p,
                action="mount_personalized_ddi",
                title="Mount personalized Developer Disk Image",
                instruction=(
                    "Provision a valid personalized DDI for this device/iOS build "
                    "(Xcode Devices window or pymobiledevice3 mounter), then retry."
                ),
                blocker="ddi_mount_failed",
                details={"udid": p.udid, "build": info.build},
            )

        try:
            install = await self._attach_client.sign_install(info)
        except LaneError as exc:
            if exc.code in (
                LaneErrorCode.NOT_PROVISIONED,
                LaneErrorCode.DEVICE_LOST,
                LaneErrorCode.SIGNING_EXPIRED,
                LaneErrorCode.INSTALL_FAILED,
            ):
                return self._provision_gap(
                    p,
                    action="renew_ios_signing",
                    title="Repair iOS sign/install",
                    instruction="Repair the configured iOS sign/install command and signing material, then retry.",
                    blocker=exc.code.value.lower(),
                    error_code=exc.code,
                    details={"message": str(exc)},
                )
            raise
        if not install.ok:
            code = install.error_code or LaneErrorCode.INSTALL_FAILED
            return self._provision_gap(
                p,
                action="renew_ios_signing",
                title="Renew iOS signing/install",
                instruction="Refresh the harness signing profile/certificate and retry install.",
                blocker=code.value.lower(),
                error_code=code,
                details={"message": install.message},
            )
        if install.signing_expires_ms is not None:
            info = self._with_info(info, signing_expires_ms=install.signing_expires_ms)

        try:
            capabilities = await self._attach_client.probe_capabilities(info)
        except LaneError as exc:
            if exc.code in (LaneErrorCode.DEVICE_LOST, LaneErrorCode.NOT_PROVISIONED):
                return self._ios_tool_gap(p, exc, step="capability probe")
            raise
        if IOS_PROBE_CAPABILITY not in capabilities:
            return self._provision_gap(
                p,
                action="probe_ios_capability",
                title="Probe iOS JavaScriptCore capability",
                instruction=(
                    "Run the configured capability probe and ensure the installed harness "
                    "exposes JavaScriptCore."
                ),
                blocker="capability_probe_failed",
                error_code=LaneErrorCode.NOT_PROVISIONED,
                details={"capabilities": sorted(capabilities)},
            )

        self._info = info
        p.tier = Tier.C
        p.state = "ready"
        p.thermal = Thermal.NOMINAL
        self._ready = True
        return ProvisionResult(
            ok=True,
            detail="ready",
            profile=p,
            state=ProvisionState.READY,
            tier=Tier.C,
            capabilities=IOS_TIER_C_CAPABILITIES,
            details={
                "udid": info.udid,
                "build": info.build,
                "product_type": info.product_type,
                "product_version": info.product_version,
                "probe_capabilities": sorted(capabilities),
                "signing_expires_ms": info.signing_expires_ms,
                "ddi_mounted": info.ddi_mounted,
            },
        )

    async def _launch(self, handle: Handle, target: str, harness: HarnessRef) -> None:
        info = self._require_info()
        await self._renew_signing_if_needed(info)
        if self._jsc_transport is None:
            raise LaneError(
                LaneErrorCode.NOT_PROVISIONED,
                "iOS Tier C feed requires a configured JscTransport (device-gated)",
                details={"device_gated": True},
            )
        await self._jsc_transport.open(handle)
        self._opened_handles[handle.handle_id] = handle

    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult | FeedStatus | str:
        transport = self._jsc_transport
        if transport is None:
            raise LaneError(
                LaneErrorCode.NOT_PROVISIONED,
                "iOS Tier C feed requires a configured JscTransport (device-gated)",
                details={"device_gated": True},
            )
        return await transport.eval(handle, data)

    async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
        info = self._require_info()
        refs = await self._attach_client.collect_crashes(info)
        return [
            replace(ref, handle_id=handle.handle_id if ref.handle_id is None else ref.handle_id)
            for ref in refs
        ]

    async def _reset(self, handle: Handle) -> None:
        transport = self._jsc_transport
        if transport is not None and handle.handle_id in self._opened_handles:
            await transport.close(handle)
            self._opened_handles.pop(handle.handle_id, None)
        info = self._info
        if info is not None:
            await self._attach_client.reset_device(info)

    async def _teardown(self) -> None:
        for handle in list(self._opened_handles.values()):
            if self._jsc_transport is not None:
                with contextlib.suppress(LaneError):
                    await self._jsc_transport.close(handle)
        self._opened_handles.clear()
        info = self._info
        if info is not None:
            with contextlib.suppress(LaneError):
                await self._attach_client.release_udid(info, "teardown")

    async def _read_thermal(self) -> Thermal | str:
        info = self._info
        if info is None:
            return Thermal.NOMINAL
        return await self._attach_client.read_thermal(info)

    def _require_info(self) -> Any:
        if self._info is None:
            raise LaneError(LaneErrorCode.NOT_PROVISIONED, "iOS lane is not provisioned")
        return self._info

    async def _renew_signing_if_needed(self, info: Any) -> None:
        expires = getattr(info, "signing_expires_ms", None)
        if expires is None:
            return
        now_ms = self._now_ms()
        if expires - now_ms > self._signing_renew_before_ms:
            return
        renewals = int(getattr(info, "signing_renewals", 0) or 0)
        if renewals >= self._max_signing_renewals:
            self._park_signing_failure(info, "signing renewal budget exhausted")
            raise LaneError(
                LaneErrorCode.SIGNING_EXPIRED,
                "iOS signing renewal budget exhausted",
                retryable=False,
                details={"udid": getattr(info, "udid", None), "renewals": renewals},
            )
        try:
            result = await self._attach_client.renew_signing(info)
        except LaneError as exc:
            self._park_signing_failure(info, str(exc))
            raise
        if not result.ok:
            self._park_signing_failure(info, result.message or "iOS signing renewal failed")
            raise LaneError(
                result.error_code or LaneErrorCode.SIGNING_EXPIRED,
                result.message or "iOS signing renewal failed",
                details=result.details,
            )
        self._info = self._with_info(
            info,
            signing_expires_ms=result.signing_expires_ms or self._next_signing_expiry(info),
            signing_renewals=renewals + 1,
        )

    def _with_info(self, info: Any, **changes: Any) -> Any:
        return replace(info, **changes)

    def _park_signing_failure(self, info: Any, message: str) -> None:
        profile = self._profile
        udid = getattr(info, "udid", None) or (profile.udid if profile is not None else "unknown")
        card = HumanCard(
            card_id=f"card_{uuid.uuid4().hex[:12]}",
            action="renew_ios_signing",
            title="Renew iOS signing",
            instruction="Refresh the harness signing profile/certificate and retry attach.",
            device_udid=udid,
            blocker=LaneErrorCode.SIGNING_EXPIRED.value.lower(),
            metadata={"message": message},
        )
        self._emit_card(card)
        if profile is not None:
            profile.state = "needs_hand"
        self._ready = False

    @staticmethod
    def _now_ms() -> int:
        import time

        return int(time.time() * 1000)

    def _next_signing_expiry(self, info: Any) -> int:
        return self._now_ms() + 7 * 24 * 60 * 60 * 1000

    def _ios_tool_gap(
        self,
        profile: DeviceProfile,
        exc: LaneError,
        *,
        step: str,
    ) -> ProvisionResult:
        return self._provision_gap(
            profile,
            action="repair_ios_attach_tools",
            title="Repair iOS attach tools",
            instruction=(
                "Install or repair libimobiledevice and pymobiledevice3 on the station "
                f"({step} failed), then retry attach."
            ),
            blocker=exc.code.value.lower(),
            error_code=exc.code,
            details={"udid": profile.udid, "step": step, "error": str(exc)},
        )

    def _provision_gap(
        self,
        profile: DeviceProfile,
        *,
        action: str,
        title: str,
        instruction: str,
        blocker: str,
        error_code: LaneErrorCode = LaneErrorCode.NOT_PROVISIONED,
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
            error_code=error_code,
            details=dict(details),
        )
