"""Deterministic fake lane for hardware-free load and unit tests."""

from __future__ import annotations

import itertools
from typing import Any

from ..lanes.base import (
    CrashRef,
    DeviceProfile,
    FeedResult,
    FeedStatus,
    Handle,
    ProvisionResult,
    Thermal,
    Tier,
)


class FakeLane:
    """In-memory Lane implementation; no hardware or host corpus parsing (I10)."""

    name = "fake"

    def __init__(self, *, tier: Tier = Tier.C, crash_every: int = 10) -> None:
        self._tier = tier
        self._crash_every = crash_every
        self._feeds = itertools.count(1)
        self._crashes: list[CrashRef] = []
        self._handles: dict[str, Handle] = {}
        self._thermal = Thermal.NOMINAL
        self._torn_down = False

    def capability(self) -> tuple[Tier, frozenset[str]]:
        """Return fake capability."""
        return self._tier, frozenset({"feed", "crash"})

    async def provision(self, profile: DeviceProfile) -> ProvisionResult:
        """Accept any device profile."""
        return ProvisionResult(ok=True, detail=f"provisioned {profile.udid}")

    async def assert_ready(self) -> None:
        """No-op readiness assertion."""
        if self._torn_down:
            raise RuntimeError("fake lane is torn down")

    async def launch(self, target: str, harness: Any) -> Handle:
        """Launch a fake handle."""
        handle = Handle(id=f"fake_{target}_{len(self._handles)}", udid="fake-udid", target=target)
        self._handles[handle.id] = handle
        return handle

    async def feed(self, handle: Handle, data: bytes) -> FeedResult:
        """Accept feeds and synthesize crashes deterministically."""
        if handle.id not in self._handles:
            return FeedResult(FeedStatus.REJECTED, "unknown handle")
        return await self._feed_bytes(handle, data)

    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
        n = next(self._feeds)
        if n % self._crash_every == 0:
            crash = CrashRef(
                id=f"crash_{handle.id}_{n}",
                path=f"/fake/{handle.id}/{n}.ips",
                payload=data[:64],
            )
            self._crashes.append(crash)
        return FeedResult(FeedStatus.ACCEPTED, f"feed {n}")

    async def collect_crashes(self, handle: Handle) -> list[CrashRef]:
        """Return crashes collected since the last reset."""
        return await self._collect_crashes(handle)

    async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
        out = [crash for crash in self._crashes if crash.id.startswith(f"crash_{handle.id}_")]
        self._crashes = [
            crash for crash in self._crashes if not crash.id.startswith(f"crash_{handle.id}_")
        ]
        return out

    async def thermal(self) -> Thermal:
        """Return thermal state."""
        return await self._read_thermal()

    async def _read_thermal(self) -> Thermal:
        return self._thermal

    async def reset(self, handle: Handle) -> None:
        """Clear fake crash state for a handle."""
        await self._reset(handle)

    async def _reset(self, handle: Handle) -> None:
        self._crashes = [
            crash for crash in self._crashes if not crash.id.startswith(f"crash_{handle.id}_")
        ]

    async def teardown(self) -> None:
        """Mark the fake lane torn down."""
        await self._teardown()

    async def _teardown(self) -> None:
        self._torn_down = True
