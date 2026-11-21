"""Unit tests for the shared lane protocol enforcement in ``ra.lanes.base``."""

from __future__ import annotations

import asyncio
import unittest

from ra.lanes.base import (
    BaseLane,
    CrashRef,
    DeviceProfile,
    FeedResult,
    FeedStatus,
    Handle,
    HarnessRef,
    LaneError,
    LaneErrorCode,
    ProvisionResult,
    ProvisionState,
    Thermal,
    Tier,
)


class FakeLease:
    def __init__(self) -> None:
        self.reasons: list[str] = []

    def release(self, reason: str) -> None:
        self.reasons.append(reason)


class FakeLane(BaseLane):
    name = "fake"

    def __init__(
        self,
        *,
        feed_result: FeedResult | FeedStatus | str = FeedStatus.ACCEPTED,
        feed_delay_s: float = 0.0,
        thermal_reading: Thermal | str = Thermal.NOMINAL,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.feed_result = feed_result
        self.feed_delay_s = feed_delay_s
        self.thermal_reading = thermal_reading
        self.teardown_called = False
        self.reset_handles: list[str] = []

    def capability(self) -> tuple[Tier, frozenset[str]]:
        return Tier.B, frozenset({"fake"})

    async def provision(self, p: DeviceProfile) -> ProvisionResult:
        self._profile = p
        p.state = "ready"
        self._ready = True
        return ProvisionResult(
            ok=True,
            detail="ready",
            profile=p,
            state=ProvisionState.READY,
            tier=Tier.B,
            capabilities=self.capability()[1],
        )

    async def _launch(self, handle: Handle, target: str, harness: HarnessRef) -> None:
        handle.metadata["launched"] = True

    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult | FeedStatus | str:
        if self.feed_delay_s:
            await asyncio.sleep(self.feed_delay_s)
        return self.feed_result

    async def _collect_crashes(self, handle: Handle):
        return [CrashRef(id="crash_fake_1", kind="fake", handle_id=handle.handle_id)]

    async def _reset(self, handle: Handle) -> None:
        self.reset_handles.append(handle.handle_id)
        handle.metadata["reset_hook"] = True

    async def _teardown(self) -> None:
        self.teardown_called = True

    async def _read_thermal(self) -> Thermal | str:
        return self.thermal_reading


class BaseLaneTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.lane = FakeLane()
        self.profile = DeviceProfile(
            udid="udid-fake", ring_node="node-fake", state="attached", tier=Tier.B, build="1"
        )
        await self.lane.provision(self.profile)
        self.handle = await self.lane.launch("target", HarnessRef(name="harness", argv=["run"]))

    async def test_feed_result_values(self) -> None:
        for value in FeedStatus:
            self.lane.feed_result = value
            result = await self.lane.feed(self.handle, b"x")
            self.assertIs(result.status, value)
            self.assertEqual(result.handle_id, self.handle.id)

    async def test_feed_timeout_raises_hang_with_crash_ref(self) -> None:
        lane = FakeLane(feed_timeout_s=0.05, feed_delay_s=0.2)
        await lane.provision(self.profile)
        handle = await lane.launch("target", HarnessRef(name="harness"))
        with self.assertRaises(LaneError) as cm:
            await lane.feed(handle, b"x" * 1024)
        self.assertIs(cm.exception.code, LaneErrorCode.HANG)
        self.assertIsNotNone(cm.exception.crash_ref)
        self.assertEqual(cm.exception.crash_ref.kind, "hang")
        self.assertEqual(handle.state, "hang")
        self.assertIn("hang_crash_ref", handle.metadata)

    async def test_collect_crashes_must_precede_reset(self) -> None:
        with self.assertRaises(LaneError) as cm:
            await self.lane.reset(self.handle)
        self.assertIs(cm.exception.code, LaneErrorCode.FORMAT_FAIL)

        refs = await self.lane.collect_crashes(self.handle)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].context, "app")

        await self.lane.reset(self.handle)
        self.assertTrue(self.handle.reset)
        self.assertIn(self.handle.handle_id, self.lane.reset_handles)

        with self.assertRaises(LaneError) as cm:
            await self.lane.collect_crashes(self.handle)
        self.assertIs(cm.exception.code, LaneErrorCode.FORMAT_FAIL)

        with self.assertRaises(LaneError) as cm:
            await self.lane.feed(self.handle, b"x")
        self.assertIs(cm.exception.code, LaneErrorCode.DEVICE_LOST)

    async def test_feed_after_collect_requires_new_collection(self) -> None:
        await self.lane.collect_crashes(self.handle)
        await self.lane.feed(self.handle, b"more input")
        with self.assertRaises(LaneError) as cm:
            await self.lane.reset(self.handle)
        self.assertIs(cm.exception.code, LaneErrorCode.FORMAT_FAIL)
        await self.lane.collect_crashes(self.handle)
        await self.lane.reset(self.handle)

    async def test_serious_thermal_pauses_work(self) -> None:
        self.lane.thermal_reading = Thermal.SERIOUS
        self.assertIs(await self.lane.thermal(), Thermal.SERIOUS)
        self.assertTrue(self.lane.paused)
        self.assertFalse(self.lane.drained)
        with self.assertRaises(LaneError) as cm:
            await self.lane.feed(self.handle, b"x")
        self.assertIs(cm.exception.code, LaneErrorCode.THERMAL_DRAIN)

        self.lane.thermal_reading = Thermal.NOMINAL
        self.assertIs(await self.lane.thermal(), Thermal.NOMINAL)
        self.assertFalse(self.lane.paused)
        self.assertIs((await self.lane.feed(self.handle, b"x")).status, FeedStatus.ACCEPTED)

    async def test_critical_thermal_drains_and_releases_udid_once(self) -> None:
        lease = FakeLease()
        self.lane.bind_udid_lease(lease)
        self.lane.thermal_reading = Thermal.CRITICAL
        self.assertIs(await self.lane.thermal(), Thermal.CRITICAL)
        self.assertTrue(self.lane.drained)
        self.assertEqual(lease.reasons, ["critical_thermal"])

        await self.lane.thermal()
        self.assertEqual(lease.reasons, ["critical_thermal"])

        with self.assertRaises(LaneError) as cm:
            await self.lane.assert_ready()
        self.assertIs(cm.exception.code, LaneErrorCode.THERMAL_DRAIN)

        self.lane.thermal_reading = Thermal.NOMINAL
        await self.lane.thermal()
        self.assertTrue(self.lane.drained)
        self.assertFalse(self.lane.paused)

    async def test_teardown_marks_lane_not_ready(self) -> None:
        await self.lane.teardown()
        self.assertTrue(self.lane.teardown_called)
        self.assertFalse(self.lane.ready)
        with self.assertRaises(LaneError) as cm:
            await self.lane.assert_ready()
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)


if __name__ == "__main__":
    unittest.main()
