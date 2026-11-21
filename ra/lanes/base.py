"""RED APPLE lane protocol, shared types, and base adapter behavior.

Implements Appendix C of the RED APPLE v0.3 specification and the RA-LAN
requirements that can be enforced without a concrete device: feed timeout,
collect-before-reset ordering, thermal pause/drain, and Appendix H errors.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

FEED_TIMEOUT_S = 30.0


class Thermal(StrEnum):
    NOMINAL = "nominal"
    SERIOUS = "serious"
    CRITICAL = "critical"


class Tier(StrEnum):
    A = "A"
    B = "B"
    C = "C"


class FeedStatus(StrEnum):
    """Appendix C feed status."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    SATURATED = "SATURATED"


class ProvisionState(StrEnum):
    READY = "ready"
    NEEDS_HAND = "needs_hand"
    FAILED = "failed"


class LaneErrorCode(StrEnum):
    """Appendix H error codes. Lane adapters may raise only these codes."""

    OUT_OF_RING = "OUT_OF_RING"
    ARM_BLOCKED = "ARM_BLOCKED"
    NOT_PROVISIONED = "NOT_PROVISIONED"
    SIGNING_EXPIRED = "SIGNING_EXPIRED"
    INSTALL_FAILED = "INSTALL_FAILED"
    DEVICE_LOST = "DEVICE_LOST"
    THERMAL_DRAIN = "THERMAL_DRAIN"
    HANG = "HANG"
    HARNESS_REJECTED = "HARNESS_REJECTED"
    DIALECT_DEFECT = "DIALECT_DEFECT"
    CAS_CORRUPT = "CAS_CORRUPT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BUDGET_GATE = "BUDGET_GATE"
    FORMAT_FAIL = "FORMAT_FAIL"
    TRUNCATED = "TRUNCATED"
    TRIAGE_SPLIT = "TRIAGE_SPLIT"
    LADDER_EXHAUSTED = "LADDER_EXHAUSTED"
    DENSITY_LOW = "DENSITY_LOW"
    INVARIANT_BREACH = "INVARIANT_BREACH"


NON_RETRYABLE_LANE_ERRORS = frozenset(
    {
        LaneErrorCode.OUT_OF_RING,
        LaneErrorCode.ARM_BLOCKED,
        LaneErrorCode.BUDGET_GATE,
        LaneErrorCode.INVARIANT_BREACH,
    }
)


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class CrashRef:
    """Reference to crash evidence collected by a lane.

    ``path``/``payload`` are the Appendix C crash fields; the remaining fields
    carry RA-LAN metadata. ``context`` defaults to ``app`` per RA-LAN-010:
    findings remain app-context until a Tier A run proves daemon reach.
    """

    id: str
    path: str | None = None
    payload: bytes = b""
    kind: str = "crash"
    handle_id: str | None = None
    digest: str | None = None
    context: str = "app"
    created_ms: int = field(default_factory=_now_ms)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def hang(cls, handle_id: str) -> CrashRef:
        """Synthetic crash reference for a feed that exceeded 30 seconds."""
        return cls(
            id=f"crash_hang_{handle_id}_{_now_ms()}",
            kind="hang",
            handle_id=handle_id,
            metadata={"feed_timeout_s": FEED_TIMEOUT_S},
        )


@dataclass
class HarnessRef:
    """Reference to the harness a lane should launch."""

    name: str
    kind: str = "command"
    argv: Sequence[str] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class DeviceProfile:
    """Device/VM profile used for lane selection and provisioning.

    Appendix B/C require ``udid``, ``tier``, ``ring_node`` and ``state``; the
    remaining fields mirror the ``device_profile`` DDL in Appendix A.
    """

    udid: str
    tier: Tier
    ring_node: str
    state: str
    build: str | None = None
    thermal: Thermal = Thermal.NOMINAL
    crashes: int = 0
    exclusion_window: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class HumanCard:
    """One-action provisioning card for a human (RA-LAN-003/RA-LAN-006)."""

    card_id: str
    action: str
    title: str
    instruction: str
    device_udid: str
    blocker: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvisionResult:
    """Result of ``Lane.provision``.

    ``ok``/``detail`` are the Appendix C provisioning fields. Provisioning gaps
    are not lane failures: they return ``ok=False`` with ``state=needs_hand``
    and a single ``HumanCard`` so the run can dispatch elsewhere.
    """

    ok: bool = False
    detail: str = ""
    profile: DeviceProfile | None = None
    state: ProvisionState | None = None
    tier: Tier | None = None
    human_card: HumanCard | None = None
    capabilities: frozenset[str] = frozenset()
    error_code: LaneErrorCode | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.ok or self.state is ProvisionState.READY


class LaneError(Exception):
    """Lane failure carrying exactly one Appendix H error code."""

    def __init__(
        self,
        code: LaneErrorCode | str,
        message: str = "",
        *,
        retryable: bool | None = None,
        crash_ref: CrashRef | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if isinstance(code, str):
            code = LaneErrorCode(code)
        self.code = code
        self.message = message
        self.retryable = code not in NON_RETRYABLE_LANE_ERRORS if retryable is None else retryable
        self.crash_ref = crash_ref
        self.details = dict(details or {})
        text = f"{code.value}: {message}" if message else code.value
        super().__init__(text)

    def __str__(self) -> str:
        return str(self.args[0]) if self.args else self.code.value


class RingGate(Protocol):
    """Thin interface to the Version Ring (RA-RING) owned by another module."""

    def allows(self, ring_node: str, build: str | None) -> bool: ...


class UdidLease(Protocol):
    """Optional per-UDID exclusivity lease released on critical thermal."""

    def release(self, reason: str) -> None: ...


@dataclass
class FeedResult:
    """Appendix C feed result."""

    status: FeedStatus
    detail: str = ""
    handle_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Handle:
    """Opaque lane handle returned by ``launch``.

    ``id``/``udid``/``target`` are the Appendix C handle fields;
    ``handle_id`` remains as a compatibility alias for the lane-internal id.
    """

    id: str
    udid: str
    target: str
    lane: str = ""
    harness: HarnessRef = field(default_factory=lambda: HarnessRef(name=""))
    created_ms: int = field(default_factory=_now_ms)
    state: str = "launched"
    metadata: dict[str, Any] = field(default_factory=dict)
    crashes_collected: bool = False
    reset: bool = False

    @property
    def handle_id(self) -> str:
        return self.id


class Lane(Protocol):
    """Appendix C lane interface."""

    name: str

    def capability(self) -> tuple[Tier, frozenset[str]]: ...

    async def provision(self, p: DeviceProfile) -> ProvisionResult: ...

    async def assert_ready(self) -> None: ...

    async def launch(self, target: str, harness: HarnessRef) -> Handle: ...

    async def feed(self, h: Handle, data: bytes) -> FeedResult: ...

    async def collect_crashes(self, h: Handle) -> list[CrashRef]: ...

    async def thermal(self) -> Thermal: ...

    async def reset(self, h: Handle) -> None: ...

    async def teardown(self) -> None: ...


class BaseLane(ABC):
    """Shared Lane implementation for concrete adapters.

    Subclasses implement the platform-specific ``_*`` hooks. This base enforces
    the Appendix C contract: 30 s feed timeout with a HANG crash reference,
    collect-before-reset ordering, thermal pause/drain, and ready checks.
    """

    name: str = "base"

    def __init__(
        self,
        *,
        feed_timeout_s: float = FEED_TIMEOUT_S,
        card_sink: Callable[[HumanCard], None] | None = None,
        ring: RingGate | None = None,
        id_prefix: str | None = None,
    ) -> None:
        self._feed_timeout_s = feed_timeout_s
        self._card_sink = card_sink
        self._ring = ring
        self._id_prefix = id_prefix or self.name
        self._handles: dict[str, Handle] = {}
        self._profile: DeviceProfile | None = None
        self._ready = False
        self._paused = False
        self._drained = False
        self._thermal = Thermal.NOMINAL
        self._udid_lease: UdidLease | None = None
        self._udid_lease_released = False

    @property
    def profile(self) -> DeviceProfile | None:
        """Last profile passed to ``provision``."""
        return self._profile

    @property
    def ready(self) -> bool:
        """Whether the lane is provisioned and not thermal-drained."""
        return self._ready and not self._drained

    @property
    def paused(self) -> bool:
        """Whether a serious thermal reading has paused new work."""
        return self._paused

    @property
    def drained(self) -> bool:
        """Whether a critical thermal reading drained the lane."""
        return self._drained

    def bind_udid_lease(self, lease: UdidLease | None) -> None:
        """Bind the per-UDID semaphore/lease released on critical thermal."""
        self._udid_lease = lease
        self._udid_lease_released = False

    def _emit_card(self, card: HumanCard) -> None:
        if self._card_sink is not None:
            self._card_sink(card)

    @abstractmethod
    def capability(self) -> tuple[Tier, frozenset[str]]:
        """Return capability tier and capability names (RA-LAN-004)."""

    @abstractmethod
    async def provision(self, p: DeviceProfile) -> ProvisionResult:
        """Provision the lane for ``p`` without failing the run on gaps."""

    async def assert_ready(self) -> None:
        """Raise unless the lane is provisioned and allowed to accept work."""
        if not self._ready:
            raise LaneError(LaneErrorCode.NOT_PROVISIONED, f"{self.name} is not provisioned")
        if self._drained:
            raise LaneError(
                LaneErrorCode.THERMAL_DRAIN,
                f"{self.name} drained after critical thermal reading",
                details={"thermal": Thermal.CRITICAL.value},
            )
        if self._paused:
            raise LaneError(
                LaneErrorCode.THERMAL_DRAIN,
                f"{self.name} paused after serious thermal reading",
                details={"thermal": Thermal.SERIOUS.value, "pause": True},
            )

    async def launch(self, target: str, harness: HarnessRef) -> Handle:
        """Launch ``target`` and return a handle for feed/collect/reset."""
        await self.assert_ready()
        handle = self._register_handle(target, harness)
        try:
            await self._launch(handle, target, harness)
        except Exception:
            self._handles.pop(handle.id, None)
            raise
        return handle

    async def feed(self, h: Handle, data: bytes) -> FeedResult:
        """Feed bytes to a handle, never blocking longer than 30 seconds."""
        self._check_handle(h)
        self._check_work_allowed()
        h.crashes_collected = False
        try:
            result = await asyncio.wait_for(self._feed_bytes(h, data), timeout=self._feed_timeout_s)
        except TimeoutError:
            crash = CrashRef.hang(h.handle_id)
            h.state = "hang"
            h.metadata["hang_crash_ref"] = crash.id
            raise LaneError(
                LaneErrorCode.HANG,
                f"feed exceeded {self._feed_timeout_s:.0f}s",
                crash_ref=crash,
                details={"handle_id": h.handle_id, "target": h.target},
            ) from None
        return self._coerce_feed_result(result, handle=h)

    async def collect_crashes(self, h: Handle) -> list[CrashRef]:
        """Collect crash references; valid only before ``reset`` (RA-LAN-007)."""
        self._check_handle(h, allow_reset=True)
        if h.reset:
            raise LaneError(
                LaneErrorCode.FORMAT_FAIL,
                "collect_crashes is not valid after reset",
                details={"handle_id": h.handle_id},
            )
        refs = await self._collect_crashes(h)
        h.crashes_collected = True
        h.state = "crashes_collected"
        return list(refs)

    async def thermal(self) -> Thermal:
        """Read thermal state and apply serious/critical lane behavior."""
        reading = await self._read_thermal()
        self._thermal = Thermal(reading)
        self._apply_thermal(self._thermal)
        return self._thermal

    async def reset(self, h: Handle) -> None:
        """Reset a handle after crashes have been collected (RA-LAN-007)."""
        self._check_handle(h, allow_reset=True)
        if h.reset:
            return
        if not h.crashes_collected:
            raise LaneError(
                LaneErrorCode.FORMAT_FAIL,
                "collect_crashes must precede reset",
                details={"handle_id": h.handle_id},
            )
        await self._reset(h)
        h.reset = True
        h.state = "reset"

    async def teardown(self) -> None:
        """Release lane resources and mark the lane not ready."""
        await self._teardown()
        self._handles.clear()
        self._profile = None
        self._ready = False
        self._paused = False
        self._drained = False

    def _register_handle(self, target: str, harness: HarnessRef) -> Handle:
        udid = self._profile.udid if self._profile is not None else ""
        handle = Handle(
            id=f"{self._id_prefix}-{uuid.uuid4().hex[:12]}",
            udid=udid,
            target=target,
            lane=self.name,
            harness=harness,
            metadata={"target": target, "udid": udid},
        )
        self._handles[handle.id] = handle
        return handle

    def _check_handle(self, h: Handle, *, allow_reset: bool = False) -> None:
        if not isinstance(h, Handle):
            raise LaneError(LaneErrorCode.FORMAT_FAIL, "expected a lane Handle")
        if h.lane != self.name or h.id not in self._handles:
            raise LaneError(
                LaneErrorCode.FORMAT_FAIL,
                "handle does not belong to this lane",
                details={"lane": self.name, "handle_lane": h.lane},
            )
        if h.reset and not allow_reset:
            raise LaneError(
                LaneErrorCode.DEVICE_LOST,
                "handle has already been reset",
                details={"handle_id": h.handle_id},
            )

    def _check_work_allowed(self) -> None:
        if not self._ready:
            raise LaneError(LaneErrorCode.NOT_PROVISIONED, f"{self.name} is not provisioned")
        if self._drained:
            raise LaneError(
                LaneErrorCode.THERMAL_DRAIN,
                f"{self.name} drained after critical thermal reading",
                details={"thermal": Thermal.CRITICAL.value},
            )
        if self._paused:
            raise LaneError(
                LaneErrorCode.THERMAL_DRAIN,
                f"{self.name} paused after serious thermal reading",
                details={"thermal": Thermal.SERIOUS.value, "pause": True},
            )

    def _coerce_feed_result(
        self, result: FeedResult | FeedStatus | str, *, handle: Handle
    ) -> FeedResult:
        if isinstance(result, FeedResult):
            return result
        try:
            status = result if isinstance(result, FeedStatus) else FeedStatus(result)
        except ValueError as exc:
            raise LaneError(
                LaneErrorCode.FORMAT_FAIL,
                f"invalid feed result: {result!r}",
            ) from exc
        return FeedResult(status=status, handle_id=handle.handle_id)

    def _apply_thermal(self, reading: Thermal) -> None:
        if reading is Thermal.CRITICAL:
            self._drained = True
            self._paused = True
            self._release_udid_once("critical_thermal")
        elif reading is Thermal.SERIOUS:
            self._paused = True
        else:
            self._paused = False

    def _release_udid_once(self, reason: str) -> None:
        if self._udid_lease is not None and not self._udid_lease_released:
            self._udid_lease_released = True
            self._udid_lease.release(reason)

    @abstractmethod
    async def _launch(self, handle: Handle, target: str, harness: HarnessRef) -> None:
        """Platform-specific launch work after common checks."""

    @abstractmethod
    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult | FeedStatus | str:
        """Platform-specific feed implementation."""

    @abstractmethod
    async def _collect_crashes(self, handle: Handle) -> Sequence[CrashRef]:
        """Platform-specific crash collection."""

    @abstractmethod
    async def _reset(self, handle: Handle) -> None:
        """Platform-specific reset after crash collection."""

    @abstractmethod
    async def _teardown(self) -> None:
        """Platform-specific teardown."""

    @abstractmethod
    async def _read_thermal(self) -> Thermal | str:
        """Platform-specific thermal read."""
