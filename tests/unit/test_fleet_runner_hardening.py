"""Adversarial fleet-runner hardening tests (TASK-36)."""

from __future__ import annotations

import asyncio
import random
from dataclasses import replace
from typing import Any

import pytest

from ra.errors import FormatFail, RaError
from ra.fleet import (
    CrashIngest,
    CrashLedgerSink,
    FakeLane,
    FleetBudget,
    FleetLaneSpec,
    FleetLaneStatus,
    FleetRunner,
    FleetTask,
    FleetTaskStatus,
)
from ra.lanes.base import FeedResult, FeedStatus, HarnessRef
from tests.conftest import run
from tests.unit.test_fleet_runner import (
    FeedTracker,
    SlowClaimLedger,
    _ingest,
    _open_ledger,
    _profile,
    _spec,
    _task,
)


class FleetAbort(BaseException):
    pass


class BlockingLane(FakeLane):
    def __init__(self) -> None:
        super().__init__(crash_every=1_000_000)
        self.release = asyncio.Event()
        self.torn = False

    async def _feed_bytes(self, handle: Any, data: bytes) -> FeedResult:
        await self.release.wait()
        return FeedResult(FeedStatus.ACCEPTED)

    async def _teardown(self) -> None:
        self.torn = True
        await super()._teardown()


class TrackedCrashLane(FakeLane):
    def __init__(self, tracker: FeedTracker, crash_every: int) -> None:
        super().__init__(crash_every=crash_every)
        self._tracker = tracker

    async def _feed_bytes(self, handle: Any, data: bytes) -> FeedResult:
        await self._tracker.feed()
        return await super()._feed_bytes(handle, data)


class FailOnceSink(CrashLedgerSink):
    def __init__(self, ledger: Any) -> None:
        super().__init__(ledger)
        self.fail = True

    async def submit(self, ingest: CrashIngest) -> None:
        if self.fail:
            self.fail = False
            raise RuntimeError("injected sink submit failure")
        await super().submit(ingest)


class CancelClaimLedger:
    def claim_by_dedup(self, _dedup_key: str) -> None:
        return None

    async def create_claim(self, _claim: Any) -> str:
        raise asyncio.CancelledError


def test_RA_FLEET_036_validation_rejects_malformed_inputs() -> None:
    profile = _profile("udid-validation")
    with pytest.raises(FormatFail):
        FleetTask(target="", harness=HarnessRef(name="h"))
    with pytest.raises(FormatFail):
        FleetTask(target="target", harness=HarnessRef(name=""), inputs=())
    with pytest.raises(FormatFail):
        FleetTask(target="target", harness=HarnessRef(name="h"), metadata=[])  # type: ignore[arg-type]

    bad_profiles = [
        replace(profile, ring_node=""),
        replace(profile, state=""),
        replace(profile, tier="bad"),  # type: ignore[arg-type]
        replace(profile, build=123),  # type: ignore[arg-type]
        replace(profile, exclusion_window=123),  # type: ignore[arg-type]
        replace(profile, crashes=-1),
    ]
    for bad in bad_profiles:
        with pytest.raises(FormatFail):
            FleetLaneSpec(profile=bad, lane_factory=FakeLane, tasks=(_task(),))


def test_RA_FLEET_036_spec_validation_rejects_bad_udids() -> None:
    async def body() -> None:
        ledger = await _open_ledger()
        blank = _spec("   ", FakeLane, (_task(),))
        with pytest.raises(FormatFail, match="udid"):
            await FleetRunner(ledger).run([blank])
        with pytest.raises(FormatFail, match="FleetLaneSpec"):
            await FleetRunner(ledger).run([object()])  # type: ignore[list-item]

    run(body())


def test_RA_FLEET_036_runner_sink_stats_are_per_run() -> None:
    async def body() -> None:
        ledger = await _open_ledger()
        runner = FleetRunner(ledger)
        first = _spec("udid-stats-a", lambda: FakeLane(crash_every=1), (_task(inputs=(b"first",)),))
        second = _spec("udid-stats-b", lambda: FakeLane(crash_every=1), (_task(inputs=(b"second",)),))
        first_result = await runner.run([first])
        second_result = await runner.run([second])
        assert first_result.crashes_recorded == 1
        assert second_result.crashes_recorded == 1
        assert first_result.queued_crashes_peak == 1
        assert second_result.queued_crashes_peak == 1

    run(body())


def test_RA_FLEET_036_sink_stop_rejects_late_submit_without_losing_queued() -> None:
    async def body() -> None:
        ledger = SlowClaimLedger()
        sink = CrashLedgerSink(ledger, max_queue=2)  # type: ignore[arg-type]
        await sink.start()
        await sink.submit(_ingest(1))
        await sink.submit(_ingest(2))
        await asyncio.wait_for(ledger.entered.wait(), timeout=1.0)

        stop_task = asyncio.create_task(sink.stop())
        await asyncio.sleep(0)
        with pytest.raises(RaError, match="not accepting"):
            await sink.submit(_ingest(3))

        ledger.release.set()
        await asyncio.wait_for(stop_task, timeout=1.0)
        assert sink.submitted == 2
        assert sink.created == 2
        assert sink.duplicates == 0
        assert sink.errors == 0
        assert len(ledger.created) == 2

    run(body())


def test_RA_FLEET_036_sink_stop_cancels_failed_writer() -> None:
    async def body() -> None:
        sink = CrashLedgerSink(CancelClaimLedger(), max_queue=1)  # type: ignore[arg-type]
        await sink.start()
        await sink.submit(_ingest(1))
        with pytest.raises(asyncio.CancelledError):
            await sink.stop()
        assert sink.submitted == 1
        assert sink.created == 0
        assert sink.errors == 0
        assert sink._task is None

    run(body())


def test_RA_FLEET_036_abort_cancels_sibling_lane_and_tears_down() -> None:
    async def body() -> None:
        ledger = await _open_ledger()
        lane = BlockingLane()
        good = _spec("udid-abort-good", lambda: lane, (_task(),))

        def bad_factory() -> FakeLane:
            raise FleetAbort("injected abort")

        bad = _spec("udid-abort-bad", bad_factory, (_task(),))
        runner = FleetRunner(ledger, budget=FleetBudget(max_concurrent_lanes=2))
        with pytest.raises(FleetAbort):
            await runner.run([good, bad])
        assert lane.torn is True
        row = ledger.store._conn.execute("SELECT state FROM run").fetchone()
        assert row is not None
        assert row[0] == "aborted"

    run(body())


def test_RA_FLEET_036_sink_submit_failure_releases_crash_budget() -> None:
    async def body() -> None:
        ledger = await _open_ledger()
        sink = FailOnceSink(ledger)
        first = _spec(
            "udid-release-a",
            lambda: FakeLane(crash_every=1),
            (_task(inputs=(b"release-a",)),),
        )
        second = _spec(
            "udid-release-b",
            lambda: FakeLane(crash_every=1),
            (_task(inputs=(b"release-b",)),),
        )
        runner = FleetRunner(
            ledger,
            budget=FleetBudget(max_total_crashes=1, max_concurrent_lanes=1),
            sink=sink,
        )
        result = await runner.run([first, second])
        assert result.crashes_recorded == 1
        assert result.crashes_duplicate == 0
        assert result.crashes_dropped == 0
        assert result.state == "drained"
        assert result.lanes[1].tasks[0].status is FleetTaskStatus.COMPLETED
        assert result.lanes[1].crashes == 1

    run(body())


def test_RA_FLEET_036_property_budget_and_concurrency_invariants() -> None:
    async def body() -> None:
        for seed in range(4):
            ledger = await _open_ledger()
            tracker = FeedTracker(delay_s=0.001)
            rng = random.Random(seed)
            specs: list[FleetLaneSpec] = []
            for index in range(4):
                tasks = tuple(
                    _task(
                        target=f"target-{seed}-{index}-{task_index}",
                        inputs=tuple(bytes([rng.randrange(256)]) for _ in range(rng.randint(0, 3))),
                        cost_usd_micro=rng.randint(0, 2),
                    )
                    for task_index in range(rng.randint(1, 2))
                )
                crash_every = rng.choice([1, 2, 3, 1_000_000_000])
                specs.append(
                    _spec(
                        f"udid-prop-{seed}-{index}",
                        lambda ce=crash_every, tr=tracker: TrackedCrashLane(tr, ce),
                        tasks,
                    )
                )
            runner = FleetRunner(
                ledger,
                budget=FleetBudget(
                    max_concurrent_lanes=2,
                    max_feeds_per_device=4,
                    max_crashes_per_device=3,
                    max_total_crashes=5,
                    spend_usd_micro=8,
                    thermal_poll_interval_s=0.001,
                ),
            )
            result = await runner.run(specs)
            assert result.state == "drained"
            assert result.ledger_errors == 0
            assert tracker.peak <= 2
            assert result.spend_usd_micro <= 8
            assert result.crashes_recorded <= 5
            assert result.crashes_dropped >= 0
            assert len(result.lanes) == 4
            for lane_result in result.lanes:
                assert lane_result.feeds <= 4
                assert lane_result.crashes <= 3
                assert lane_result.spend_usd_micro <= 8
                assert lane_result.status in set(FleetLaneStatus)
                indices = [task.task_index for task in lane_result.tasks]
                assert indices == sorted(indices)
                assert len(set(indices)) == len(indices)
                assert all(task.status in set(FleetTaskStatus) for task in lane_result.tasks)

    run(body())
