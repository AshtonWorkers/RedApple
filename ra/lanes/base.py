"""Lane protocol and shared lane types (Appendix C)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class Thermal(StrEnum):
    """Device thermal state."""

    NOMINAL = "nominal"
    SERIOUS = "serious"
    CRITICAL = "critical"


class Tier(StrEnum):
    """iOS capability tier."""

    A = "A"
    B = "B"
    C = "C"


class FeedStatus(StrEnum):
    """Feed result status."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    SATURATED = "SATURATED"


@dataclass(frozen=True)
class DeviceProfile:
    """Minimal device profile used by lane adapters."""

    udid: str
    tier: Tier
    ring_node: str
    state: str
    build: str | None = None


@dataclass(frozen=True)
class ProvisionResult:
    """Provisioning result."""

    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class Handle:
    """Opaque lane handle."""

    id: str
    udid: str
    target: str


@dataclass(frozen=True)
class FeedResult:
    """Feed result."""

    status: FeedStatus
    detail: str = ""


@dataclass(frozen=True)
class CrashRef:
    """Reference to a collected crash artifact."""

    id: str
    path: str
    payload: bytes = b""


class Lane(Protocol):
    """Normative lane interface (Appendix C)."""

    name: str

    def capability(self) -> tuple[Tier, frozenset[str]]:
        """Return tier and capability set."""
        ...

    async def provision(self, profile: DeviceProfile) -> ProvisionResult:
        """Provision the device for a profile."""
        ...

    async def assert_ready(self) -> None:
        """Assert the lane is ready."""
        ...

    async def launch(self, target: str, harness: Any) -> Handle:
        """Launch a target with a harness."""
        ...

    async def feed(self, handle: Handle, data: bytes) -> FeedResult:
        """Feed bytes to a handle; must not exceed 30 seconds (RA-LAN-011)."""
        ...

    async def collect_crashes(self, handle: Handle) -> list[CrashRef]:
        """Collect crashes; valid before reset (RA-LAN-007)."""
        ...

    async def thermal(self) -> Thermal:
        """Return thermal state."""
        ...

    async def reset(self, handle: Handle) -> None:
        """Reset a handle after crash collection."""
        ...

    async def teardown(self) -> None:
        """Release lane resources."""
        ...
