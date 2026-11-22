"""Fleet runner unit, edge, budget, thermal, and backpressure tests."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from ra.errors import DuplicateDedup, FormatFail, RaError
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
from ra.lanes.base import (
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
from ra.ledger import ClaimInput, Ledger
from tests.conftest import run


def _ring_payload(node_id: str = "node-fleet", build: str = "build-1") -> dict[str, Any]:
    return {
        "ring_node_id": node_id,
        "ipsw_sha": f"ipsw-{node_id}",
        "build": build,
        "xcode": "xcode",
        "sdk": "sdk",
        "webkit_commit": "webkit",
        "state": "current",
        "epoch": 1,
    }


async def _open_ledger(node_id: str = "node-fleet") -> Ledger:
    ledger = await Ledger.open(":memory:")
    await ledger.upsert_ring_node(_ring_payload(node_id))
    return ledger


def _profile(udid: str, *, node_id: str = "node-fleet", crashes: int = 0) -> DeviceProfile:
    return DeviceProfile(
        udid=udid,
        ring_node=node_id,
        state="attached",
        tier=Tier.C,
        build="build-1",
        crashes=crashes,
    )


def _task(
    target: str = "target", *, cost_usd_micro: int = 0, inputs: tuple[bytes, ...] = (b"in",)
) -> FleetTask:
    return FleetTask(
        target=target,
        harness=HarnessRef(name="harness", argv=["run"]),
        inputs=inputs,
        metadata={"case": target, "blob": b"metadata"},
        cost_usd_micro=cost_usd_micro,
    )


def _spec(
    udid: str,
    lane_factory: Any,
    tasks: tuple[FleetTask, ...],
    *,
    node_id: str = "node-fleet",
    crashes: int = 0,
) -> FleetLaneSpec:
    return FleetLaneSpec(
        profile=_profile(udid, node_id=node_id, crashes=crashes),
        lane_factory=lane_factory,
        tasks=tasks,
    )


def _profile_row(ledger: Ledger, udid: str) -> dict[str, Any]:
    row = ledger.store._conn.execute(
        "SELECT udid, build, tier, state, thermal, crashes, ring_node FROM device_profile WHERE udid=?",
        (udid,),
    ).fetchone()
    assert row is not None
    return dict(row)


class FeedTracker:
    def __init__(self, delay_s: float = 0.02) -> None:
        self.delay_s = delay_s
        self.active = 0
        self.peak = 0

    async def feed(self) -> None:
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.delay_s)
        finally:
            self.active -= 1


class TrackedFakeLane(FakeLane):
    def __init__(self, tracker: FeedTracker, **kwargs: Any) -> None:
        super().__init__(crash_every=1_000_000, **kwargs)
        self._tracker = tracker

    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
        await self._tracker.feed()
        return FeedResult(FeedStatus.ACCEPTED)


class FixedCrashLane(FakeLane):
    def __init__(self, refs: list[CrashRef], **kwargs: Any) -> None:
        super().__init__(crash_every=1_000_000, **kwargs)
        self._refs = refs

    async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
        return list(self._refs)


class ScriptedThermalLane(FakeLane):
    def __init__(
        self, readings: list[Thermal], default: Thermal = Thermal.NOMINAL, **kwargs: Any
    ) -> None:
        super().__init__(crash_every=1_000_000, **kwargs)
        self._readings = iter(readings)
        self._default = default

    async def _read_thermal(self) -> Thermal:
        return next(self._readings, self._default)


class NeedsHandLane(FakeLane):
    async def provision(self, profile: DeviceProfile) -> ProvisionResult:
        self._profile = profile
        self._ready = False
        return ProvisionResult(
            profile=profile,
            state=ProvisionState.NEEDS_HAND,
            details={"missing": "developer disk", "blob": b"details"},
        )


class FailingProvisionLane(FakeLane):
    async def provision(self, profile: DeviceProfile) -> ProvisionResult:
        raise LaneError(LaneErrorCode.OUT_OF_RING, "build is outside the ring")


class SlowClaimLedger:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.created: list[ClaimInput] = []

    def claim_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
        return None

    async def create_claim(self, claim: ClaimInput) -> str:
        self.entered.set()
        await self.release.wait()
        self.created.append(claim)
        return claim.claim_id


def _ingest(index: int) -> CrashIngest:
    return CrashIngest(
        ref=CrashRef(id=f"crash-{index}", kind="test", payload=b"payload"),
        lane="fake",
        profile=_profile(f"udid-{index}"),
        target="target",
        harness="harness",
        run_id="run-test",
        task_metadata={},
    )


def test_RA_FLEET_001_budget_validation_rejects_bad_values():
    with pytest.raises(FormatFail):
        FleetBudget(max_concurrent_lanes=0)
    with pytest.raises(FormatFail):
        FleetBudget(max_queued_crashes=True)
    with pytest.raises(FormatFail):
        FleetBudget(max_feeds_per_device=-1)
    with pytest.raises(FormatFail):
        FleetBudget(max_crashes_per_device=-1)
    with pytest.raises(FormatFail):
        FleetBudget(max_total_crashes=-1)
    with pytest.raises(FormatFail):
        FleetBudget(spend_usd_micro=-1)
    with pytest.raises(FormatFail):
        FleetBudget(thermal_poll_interval_s=0)
    with pytest.raises(FormatFail):
        FleetBudget(thermal_pause_timeout_s=float("nan"))


def test_RA_FLEET_001_task_and_spec_validation_rejects_bad_values():
    harness = HarnessRef(name="h")
    with pytest.raises(FormatFail):
        FleetTask(target="", harness=harness)
    with pytest.raises(FormatFail):
        FleetTask(target="target", harness=harness, inputs=("not-bytes",))  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        FleetTask(target="target", harness=harness, cost_usd_micro=-1)
    with pytest.raises(FormatFail):
        FleetLaneSpec(profile={"udid": "bad"}, lane_factory=lambda: FakeLane(), tasks=())  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        FleetLaneSpec(profile=_profile("u"), lane_factory="not-callable", tasks=())  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        FleetLaneSpec(profile=_profile("u"), lane_factory=lambda: FakeLane(), tasks=(object(),))  # type: ignore[arg-type]


def test_RA_FLEET_001_duplicate_udids_are_rejected_before_run():
    async def body():
        ledger = await _open_ledger()
        try:
            spec = _spec("same", lambda: FakeLane(), (_task(),))
            with pytest.raises(FormatFail):
                await FleetRunner(ledger).run([spec, spec])
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_concurrent_lanes_respect_semaphore():
    async def body():
        ledger = await _open_ledger()
        tracker = FeedTracker(delay_s=0.03)

        def factory() -> FakeLane:
            return TrackedFakeLane(tracker)

        specs = [
            _spec(f"udid-{index}", factory, (_task(f"target-{index}", inputs=(b"a", b"b", b"c")),))
            for index in range(3)
        ]
        try:
            result = await FleetRunner(ledger, budget=FleetBudget(max_concurrent_lanes=2)).run(
                specs
            )
            assert result.state == "drained"
            assert len(result.lanes) == 3
            assert all(lane.status is FleetLaneStatus.COMPLETED for lane in result.lanes)
            assert tracker.peak == 2
            assert all(lane.feeds == 3 for lane in result.lanes)
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_crash_refs_are_persisted_once_and_deduped():
    async def body():
        ledger = await _open_ledger()
        crash = CrashRef(
            id="crash-fixed",
            kind="fixed",
            handle_id="fixed-handle",
            path="/tmp/fixed.ips",
            digest="sha256:fixed",
            payload=b"crash-payload",
            context="daemon",
            created_ms=123,
            metadata={
                "nested": {"raw": b"bytes"},
                "note": "ok",
                "items": [b"a", {"n": 1}],
                "pair": (b"b", 2),
                "custom": object(),
            },
        )
        lane_factory = lambda: FixedCrashLane([crash])  # noqa: E731
        task = _task("same-target")
        spec = _spec("udid-crash", lane_factory, (task, task))
        try:
            result = await FleetRunner(ledger).run([spec])
            assert result.crashes_recorded == 1
            assert result.crashes_duplicate == 1
            assert result.crashes_dropped == 0
            assert result.lanes[0].crashes == 2
            claims = ledger.claims_by_type("crash")
            assert len(claims) == 1
            claim = claims[0]
            assert claim["run_id"] == result.run_id
            value = json.loads(str(claim["value_json"]))
            assert value["schema"] == "ra.crash.v1"
            assert value["crash_ref_id"] == "crash-fixed"
            assert value["payload_sha256"]
            assert value["metadata"]["nested"]["raw"]["bytes"] == len(b"bytes")
            assert value["task_metadata"]["blob"]["bytes"] == len(b"metadata")
            artifacts = ledger.claim_artifacts(str(claim["id"]))
            assert {row["kind"] for row in artifacts} == {"crash_ref", "crash_payload"}
            assert {row["role"] for row in artifacts} == {"evidence", "payload"}
            row = _profile_row(ledger, "udid-crash")
            assert row["crashes"] == 2
            assert row["state"] == "completed"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_global_crash_budget_drops_overflow():
    async def body():
        ledger = await _open_ledger()
        try:
            spec = _spec(
                "udid-budget",
                lambda: FakeLane(crash_every=1),
                (_task("crashy", inputs=(b"a", b"b", b"c")),),
            )
            result = await FleetRunner(
                ledger,
                budget=FleetBudget(max_concurrent_lanes=1, max_total_crashes=2),
            ).run([spec])
            assert result.crashes_recorded == 2
            assert result.crashes_dropped == 1
            assert result.lanes[0].status is FleetLaneStatus.BUDGET_EXHAUSTED
            assert result.lanes[0].crashes == 2
            assert len(ledger.claims_by_type("crash")) == 2
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_spend_budget_skips_unaffordable_tasks():
    async def body():
        ledger = await _open_ledger()
        try:
            spec = _spec(
                "udid-spend",
                lambda: FakeLane(crash_every=1_000_000),
                (_task("first", cost_usd_micro=3), _task("second", cost_usd_micro=3)),
            )
            result = await FleetRunner(
                ledger,
                budget=FleetBudget(max_concurrent_lanes=1, spend_usd_micro=5),
            ).run([spec])
            lane = result.lanes[0]
            assert lane.status is FleetLaneStatus.BUDGET_EXHAUSTED
            assert lane.spend_usd_micro == 3
            assert result.spend_usd_micro == 3
            assert lane.tasks[0].status is FleetTaskStatus.COMPLETED
            assert lane.tasks[1].status is FleetTaskStatus.SKIPPED_BUDGET
            assert lane.tasks[1].target == "second"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_feed_budget_stops_lane_work():
    async def body():
        ledger = await _open_ledger()
        try:
            spec = _spec(
                "udid-feeds",
                lambda: FakeLane(crash_every=1_000_000),
                (_task("feeds", inputs=(b"a", b"b")), _task("after")),
            )
            result = await FleetRunner(
                ledger,
                budget=FleetBudget(max_concurrent_lanes=1, max_feeds_per_device=1),
            ).run([spec])
            lane = result.lanes[0]
            assert lane.status is FleetLaneStatus.BUDGET_EXHAUSTED
            assert lane.feeds == 1
            assert lane.tasks[0].status is FleetTaskStatus.FAILED
            assert lane.tasks[0].error_code == LaneErrorCode.BUDGET_EXHAUSTED.value
            assert lane.tasks[1].status is FleetTaskStatus.SKIPPED_BUDGET
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_serious_thermal_pauses_until_nominal():
    async def body():
        ledger = await _open_ledger()
        now = [0.0]

        async def sleep(seconds: float) -> None:
            now[0] += seconds

        def clock() -> float:
            return now[0]

        lane_factory = lambda: ScriptedThermalLane([Thermal.SERIOUS, Thermal.NOMINAL])  # noqa: E731
        try:
            result = await FleetRunner(
                ledger,
                budget=FleetBudget(
                    max_concurrent_lanes=1,
                    thermal_poll_interval_s=0.1,
                    thermal_pause_timeout_s=5.0,
                ),
                sleep=sleep,
                clock=clock,
            ).run([_spec("udid-thermal", lane_factory, (_task(),))])
            assert result.lanes[0].status is FleetLaneStatus.COMPLETED
            assert result.lanes[0].tasks[0].status is FleetTaskStatus.COMPLETED
            row = _profile_row(ledger, "udid-thermal")
            assert row["state"] == "completed"
            assert row["thermal"] == "nominal"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_thermal_pause_timeout_drains_lane():
    async def body():
        ledger = await _open_ledger()
        now = [0.0]

        async def sleep(seconds: float) -> None:
            now[0] += seconds

        lane_factory = lambda: ScriptedThermalLane([Thermal.SERIOUS], default=Thermal.SERIOUS)  # noqa: E731
        try:
            result = await FleetRunner(
                ledger,
                budget=FleetBudget(
                    max_concurrent_lanes=1,
                    thermal_poll_interval_s=0.1,
                    thermal_pause_timeout_s=0.25,
                ),
                sleep=sleep,
                clock=lambda: now[0],
            ).run([_spec("udid-hot", lane_factory, (_task(),))])
            assert result.lanes[0].status is FleetLaneStatus.DRAINED
            assert result.lanes[0].tasks == ()
            row = _profile_row(ledger, "udid-hot")
            assert row["state"] == "drained"
            assert row["thermal"] == "critical"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_critical_thermal_drains_before_work():
    async def body():
        ledger = await _open_ledger()
        lane_factory = lambda: ScriptedThermalLane([Thermal.CRITICAL])  # noqa: E731
        try:
            result = await FleetRunner(ledger).run(
                [_spec("udid-critical", lane_factory, (_task(),))]
            )
            assert result.lanes[0].status is FleetLaneStatus.DRAINED
            assert result.lanes[0].tasks == ()
            assert _profile_row(ledger, "udid-critical")["state"] == "drained"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_needs_hand_and_failed_provision_are_lane_outcomes():
    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-hand", lambda: NeedsHandLane(), (_task("hand"),)),
                    _spec("udid-fail", lambda: FailingProvisionLane(), (_task("fail"),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            assert by_udid["udid-hand"].status is FleetLaneStatus.NEEDS_HAND
            assert by_udid["udid-hand"].tasks == ()
            assert by_udid["udid-hand"].error is not None
            assert by_udid["udid-fail"].status is FleetLaneStatus.FAILED
            assert by_udid["udid-fail"].error_code == LaneErrorCode.OUT_OF_RING.value
            assert _profile_row(ledger, "udid-hand")["state"] == "needs_hand"
            assert _profile_row(ledger, "udid-fail")["state"] == "failed"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_launch_and_feed_lane_errors_become_task_results():
    class LaunchFailLane(FakeLane):
        async def launch(self, target: str, harness: HarnessRef) -> Any:
            raise LaneError(LaneErrorCode.HARNESS_REJECTED, "bad harness")

    class FeedCrashLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            crash = CrashRef(id="crash-feed", kind="feed", handle_id=handle.handle_id, payload=data)
            raise LaneError(LaneErrorCode.HANG, "feed hung", crash_ref=crash)

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-launch", lambda: LaunchFailLane(), (_task("bad"),)),
                    _spec("udid-feed", lambda: FeedCrashLane(), (_task("hang"),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            assert by_udid["udid-launch"].tasks[0].status is FleetTaskStatus.FAILED
            assert (
                by_udid["udid-launch"].tasks[0].error_code == LaneErrorCode.HARNESS_REJECTED.value
            )
            assert by_udid["udid-feed"].tasks[0].status is FleetTaskStatus.FAILED
            assert by_udid["udid-feed"].tasks[0].error_code == LaneErrorCode.HANG.value
            assert result.crashes_recorded == 1
            assert len(ledger.claims_by_type("crash")) == 1
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_sink_applies_backpressure_when_ledger_is_slow():
    async def body():
        ledger = SlowClaimLedger()
        sink = CrashLedgerSink(ledger, max_queue=1)  # type: ignore[arg-type]
        await sink.start()
        try:
            await sink.submit(_ingest(1))
            await asyncio.wait_for(sink.submit(_ingest(2)), timeout=1.0)
            await ledger.entered.wait()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sink.submit(_ingest(3)), timeout=0.05)
            ledger.release.set()
            await sink.stop()
            assert len(ledger.created) == 2
            assert sink.submitted == 2
            assert sink.created == 2
        finally:
            ledger.release.set()
            if sink._task is not None:  # type: ignore[union-attr]
                await sink.stop()

    run(body())


def test_RA_FLEET_001_sink_rejects_submit_before_start():
    async def body():
        sink = CrashLedgerSink(SlowClaimLedger(), max_queue=1)  # type: ignore[arg-type]
        with pytest.raises(RaError):
            await sink.submit(_ingest(1))

    run(body())


def test_RA_FLEET_001_layout_boundary_allows_only_fleet_to_import_lanes():
    from ra.cli.main import layout_check

    assert layout_check()[0:0] == []


def test_RA_FLEET_001_budget_validation_rejects_none_and_non_numeric_values():
    with pytest.raises(FormatFail):
        FleetBudget(max_concurrent_lanes=None)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        FleetBudget(thermal_poll_interval_s="fast")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        FleetBudget(max_total_crashes=True)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        FleetLaneSpec(
            profile=DeviceProfile(udid="", ring_node="node-fleet", state="attached", tier=Tier.C),
            lane_factory=lambda: FakeLane(),
            tasks=(),
        )

    from ra.fleet.runner import _thermal_value

    assert _thermal_value(None) is None
    assert _thermal_value(Thermal.SERIOUS) == "serious"
    assert _thermal_value("custom") == "custom"


def test_RA_FLEET_001_sink_lifecycle_counts_errors_and_duplicates():
    async def body():
        class ExplodingLedger:
            def claim_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
                return None

            async def create_claim(self, claim: ClaimInput) -> str:
                raise RuntimeError("ledger exploded")

        class ExistingDedupLedger:
            def claim_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
                return {"id": "existing"}

            async def create_claim(self, claim: ClaimInput) -> str:
                raise AssertionError("dedup hit should not create")

        class DuplicateCreateLedger:
            def claim_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
                return None

            async def create_claim(self, claim: ClaimInput) -> str:
                raise DuplicateDedup("duplicate dedup")

        sink = CrashLedgerSink(ExplodingLedger(), max_queue=2)  # type: ignore[arg-type]
        await sink.stop()
        await sink.start()
        await sink.start()
        await sink.submit(_ingest(1))
        await sink.stop()
        assert sink.errors == 1
        assert sink.last_error is not None
        assert "RuntimeError" in sink.last_error

        for ledger, duplicates, created in (
            (ExistingDedupLedger(), 1, 0),
            (DuplicateCreateLedger(), 1, 0),
        ):
            sink = CrashLedgerSink(ledger, max_queue=2)  # type: ignore[arg-type]
            await sink.start()
            await sink.submit(_ingest(2))
            await sink.stop()
            assert sink.duplicates == duplicates
            assert sink.created == created
            assert sink.errors == 0

    run(body())


def test_RA_FLEET_001_sink_empty_payload_stores_only_evidence_artifact():
    async def body():
        ledger = SlowClaimLedger()
        ledger.release.set()
        sink = CrashLedgerSink(ledger, max_queue=2)  # type: ignore[arg-type]
        await sink.start()
        ingest = CrashIngest(
            ref=CrashRef(id="crash-empty", kind="empty", payload=b""),
            lane="fake",
            profile=_profile("udid-empty"),
            target="target",
            harness="harness",
            run_id="run-test",
            task_metadata={},
        )
        await sink.submit(ingest)
        await sink.stop()
        assert len(ledger.created) == 1
        artifacts = ledger.created[0].artifacts
        assert len(artifacts) == 1
        assert artifacts[0].artifact.kind == "crash_ref"
        assert artifacts[0].role == "evidence"

    run(body())


def test_RA_FLEET_001_run_aborts_ledger_when_lane_factory_raises_base_exception():
    class FleetAbort(BaseException):
        pass

    async def body():
        ledger = await _open_ledger()

        def bad_factory() -> FakeLane:
            raise FleetAbort

        try:
            with pytest.raises(FleetAbort):
                await FleetRunner(ledger).run(
                    [_spec("udid-abort", bad_factory, (_task(),))], mode="macos"
                )
            row = ledger.store._conn.execute("SELECT state FROM run").fetchone()
            assert row is not None
            assert row[0] == "aborted"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_provision_failures_record_error_details():
    class FailedDetailsLane(FakeLane):
        async def provision(self, profile: DeviceProfile) -> ProvisionResult:
            return ProvisionResult(
                profile=profile,
                state=ProvisionState.FAILED,
                tier=Tier.C,
                error_code=LaneErrorCode.SIGNING_EXPIRED,
                details={"reason": "expired", "blob": b"details"},
            )

    class ExplodingProvisionLane(FakeLane):
        async def provision(self, profile: DeviceProfile) -> ProvisionResult:
            raise RuntimeError("provision exploded")

    class BareFailedLane(FakeLane):
        async def provision(self, profile: DeviceProfile) -> ProvisionResult:
            return ProvisionResult(profile=profile, state=ProvisionState.FAILED, tier=Tier.C)

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-details", lambda: FailedDetailsLane(), (_task(),)),
                    _spec("udid-explode", lambda: ExplodingProvisionLane(), (_task(),)),
                    _spec("udid-bare", lambda: BareFailedLane(), (_task(),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            details = by_udid["udid-details"]
            assert details.status is FleetLaneStatus.FAILED
            assert details.error_code == LaneErrorCode.SIGNING_EXPIRED.value
            assert details.error is not None
            assert "expired" in details.error
            exploded = by_udid["udid-explode"]
            assert exploded.status is FleetLaneStatus.FAILED
            assert exploded.error_code == "RA_ERROR"
            assert exploded.error == "provision exploded"
            bare = by_udid["udid-bare"]
            assert bare.status is FleetLaneStatus.FAILED
            assert bare.error_code is None
            assert bare.error is None
            assert _profile_row(ledger, "udid-details")["state"] == "failed"
            assert _profile_row(ledger, "udid-explode")["state"] == "failed"
            assert _profile_row(ledger, "udid-bare")["state"] == "failed"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_feed_budget_skips_remaining_tasks_at_boundary():
    async def body():
        ledger = await _open_ledger()
        try:
            spec = _spec(
                "udid-feed-boundary",
                lambda: FakeLane(crash_every=1_000_000),
                (_task("first", inputs=(b"a",)), _task("second", inputs=(b"b",))),
            )
            result = await FleetRunner(
                ledger, budget=FleetBudget(max_concurrent_lanes=1, max_feeds_per_device=1)
            ).run([spec])
            lane = result.lanes[0]
            assert lane.status is FleetLaneStatus.BUDGET_EXHAUSTED
            assert lane.feeds == 1
            assert [task.status for task in lane.tasks] == [
                FleetTaskStatus.COMPLETED,
                FleetTaskStatus.SKIPPED_BUDGET,
            ]
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_prior_crash_count_skips_tasks_before_launch():
    async def body():
        ledger = await _open_ledger()
        try:
            spec = _spec(
                "udid-crash-cap",
                lambda: FakeLane(crash_every=1_000_000),
                (_task("skipped"),),
                crashes=1,
            )
            result = await FleetRunner(
                ledger, budget=FleetBudget(max_concurrent_lanes=1, max_crashes_per_device=1)
            ).run([spec])
            lane = result.lanes[0]
            assert lane.status is FleetLaneStatus.BUDGET_EXHAUSTED
            assert lane.feeds == 0
            assert lane.tasks[0].status is FleetTaskStatus.SKIPPED_BUDGET
            assert _profile_row(ledger, "udid-crash-cap")["crashes"] == 1
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_critical_thermal_during_feed_drains_task_and_lane():
    async def no_sleep(seconds: float) -> None:
        return None

    async def body():
        ledger = await _open_ledger()
        lane_factory = lambda: ScriptedThermalLane(  # noqa: E731
            [Thermal.NOMINAL, Thermal.SERIOUS, Thermal.CRITICAL],
            default=Thermal.CRITICAL,
        )
        try:
            result = await FleetRunner(ledger, sleep=no_sleep).run(
                [_spec("udid-feed-hot", lane_factory, (_task("hot", inputs=(b"a",)),))]
            )
            lane = result.lanes[0]
            assert lane.status is FleetLaneStatus.DRAINED
            assert lane.tasks[0].status is FleetTaskStatus.FAILED
            assert lane.tasks[0].error_code == LaneErrorCode.THERMAL_DRAIN.value
            assert _profile_row(ledger, "udid-feed-hot")["state"] == "drained"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_non_accepted_feed_result_fails_task_without_counting_feed():
    class RejectedFeedLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            return FeedResult(FeedStatus.REJECTED)

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [_spec("udid-rejected", lambda: RejectedFeedLane(), (_task("rej"),))]
            )
            task = result.lanes[0].tasks[0]
            assert task.status is FleetTaskStatus.FAILED
            assert task.error_code == LaneErrorCode.HARNESS_REJECTED.value
            assert task.error == "feed result REJECTED"
            assert task.feeds == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_launch_and_feed_generic_exceptions_become_task_failures():
    class ExplodingLaunchLane(FakeLane):
        async def launch(self, target: str, harness: HarnessRef) -> Any:
            raise RuntimeError("launch exploded")

    class ExplodingFeedLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            raise RuntimeError("feed exploded")

    class DeviceLostFeedLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            raise LaneError(LaneErrorCode.DEVICE_LOST, "device vanished")

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-launch-explode", lambda: ExplodingLaunchLane(), (_task(),)),
                    _spec("udid-feed-explode", lambda: ExplodingFeedLane(), (_task(),)),
                    _spec("udid-device-lost", lambda: DeviceLostFeedLane(), (_task(),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            assert by_udid["udid-launch-explode"].tasks[0].error_code == "RA_ERROR"
            assert by_udid["udid-launch-explode"].tasks[0].error == "launch exploded"
            assert by_udid["udid-feed-explode"].tasks[0].error_code == "RA_ERROR"
            assert by_udid["udid-feed-explode"].tasks[0].error == "feed exploded"
            lost = by_udid["udid-device-lost"]
            assert lost.status is FleetLaneStatus.FAILED
            assert lost.tasks[0].error_code == LaneErrorCode.DEVICE_LOST.value
            assert lost.error_code == LaneErrorCode.DEVICE_LOST.value
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_collect_and_reset_errors_are_task_failures():
    class CollectLaneErrorLane(FakeLane):
        async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
            raise LaneError(LaneErrorCode.FORMAT_FAIL, "collect rejected")

    class CollectExplodingLane(FakeLane):
        async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
            raise RuntimeError("collect exploded")

    class ResetLaneErrorLane(FakeLane):
        async def _reset(self, handle: Handle) -> None:
            raise LaneError(LaneErrorCode.FORMAT_FAIL, "reset rejected")

    class ResetExplodingLane(FakeLane):
        async def _reset(self, handle: Handle) -> None:
            raise RuntimeError("reset exploded")

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-collect-lane", lambda: CollectLaneErrorLane(), (_task(),)),
                    _spec("udid-collect-explode", lambda: CollectExplodingLane(), (_task(),)),
                    _spec("udid-reset-lane", lambda: ResetLaneErrorLane(), (_task(),)),
                    _spec("udid-reset-explode", lambda: ResetExplodingLane(), (_task(),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            assert (
                by_udid["udid-collect-lane"].tasks[0].error_code == LaneErrorCode.FORMAT_FAIL.value
            )
            assert by_udid["udid-collect-explode"].tasks[0].error_code == "RA_ERROR"
            assert by_udid["udid-reset-lane"].tasks[0].error_code == LaneErrorCode.FORMAT_FAIL.value
            assert by_udid["udid-reset-explode"].tasks[0].error_code == "RA_ERROR"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_thermal_probe_errors_inside_task_fail_task():
    class ThermalLaneErrorLane(FakeLane):
        def __init__(self) -> None:
            super().__init__(crash_every=1_000_000)
            self._calls = 0

        async def _read_thermal(self) -> Thermal:
            self._calls += 1
            if self._calls == 1:
                return Thermal.NOMINAL
            raise LaneError(LaneErrorCode.DEVICE_LOST, "thermal probe lost device")

    class ThermalExplodingLane(FakeLane):
        def __init__(self) -> None:
            super().__init__(crash_every=1_000_000)
            self._calls = 0

        async def _read_thermal(self) -> Thermal:
            self._calls += 1
            if self._calls == 1:
                return Thermal.NOMINAL
            raise RuntimeError("thermal probe exploded")

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-probe-lane", lambda: ThermalLaneErrorLane(), (_task(),)),
                    _spec("udid-probe-explode", lambda: ThermalExplodingLane(), (_task(),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            assert by_udid["udid-probe-lane"].status is FleetLaneStatus.FAILED
            assert by_udid["udid-probe-lane"].tasks[0].error_code == LaneErrorCode.DEVICE_LOST.value
            assert by_udid["udid-probe-explode"].tasks[0].error_code == "RA_ERROR"
            assert by_udid["udid-probe-explode"].tasks[0].error == "thermal probe exploded"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_teardown_error_fails_completed_lane():
    class TeardownExplodingLane(FakeLane):
        async def _teardown(self) -> None:
            raise RuntimeError("teardown exploded")

    class DeviceLostTeardownLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            raise LaneError(LaneErrorCode.DEVICE_LOST, "device vanished")

        async def _teardown(self) -> None:
            raise RuntimeError("teardown exploded")

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec("udid-teardown", lambda: TeardownExplodingLane(), (_task(),)),
                    _spec("udid-lost-teardown", lambda: DeviceLostTeardownLane(), (_task(),)),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            lane = by_udid["udid-teardown"]
            assert lane.status is FleetLaneStatus.FAILED
            assert lane.error_code == "RA_ERROR"
            assert lane.error is not None
            assert "teardown exploded" in lane.error
            assert lane.tasks[0].status is FleetTaskStatus.COMPLETED
            lost = by_udid["udid-lost-teardown"]
            assert lost.status is FleetLaneStatus.FAILED
            assert lost.error_code == LaneErrorCode.DEVICE_LOST.value
            assert lost.error == "device vanished"
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_collect_and_reset_errors_do_not_mask_feed_failure():
    class RejectedCollectLaneErrorLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            return FeedResult(FeedStatus.REJECTED)

        async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
            raise LaneError(LaneErrorCode.FORMAT_FAIL, "collect rejected")

    class RejectedCollectExplodingLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            return FeedResult(FeedStatus.REJECTED)

        async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
            raise RuntimeError("collect exploded")

    class RejectedResetLaneErrorLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            return FeedResult(FeedStatus.REJECTED)

        async def _reset(self, handle: Handle) -> None:
            raise LaneError(LaneErrorCode.FORMAT_FAIL, "reset rejected")

    class RejectedResetExplodingLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            return FeedResult(FeedStatus.REJECTED)

        async def _reset(self, handle: Handle) -> None:
            raise RuntimeError("reset exploded")

    async def body():
        ledger = await _open_ledger()
        try:
            result = await FleetRunner(ledger).run(
                [
                    _spec(
                        "udid-rej-collect-lane", lambda: RejectedCollectLaneErrorLane(), (_task(),)
                    ),
                    _spec(
                        "udid-rej-collect-explode",
                        lambda: RejectedCollectExplodingLane(),
                        (_task(),),
                    ),
                    _spec("udid-rej-reset-lane", lambda: RejectedResetLaneErrorLane(), (_task(),)),
                    _spec(
                        "udid-rej-reset-explode", lambda: RejectedResetExplodingLane(), (_task(),)
                    ),
                ]
            )
            by_udid = {lane.udid: lane for lane in result.lanes}
            for udid in (
                "udid-rej-collect-lane",
                "udid-rej-collect-explode",
                "udid-rej-reset-lane",
                "udid-rej-reset-explode",
            ):
                task = by_udid[udid].tasks[0]
                assert task.status is FleetTaskStatus.FAILED
                assert task.error_code == LaneErrorCode.HARNESS_REJECTED.value
                assert task.error == "feed result REJECTED"
                assert task.feeds == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_crash_sink_errors_become_task_failures():
    class ExplodingSubmitSink(CrashLedgerSink):
        def __init__(self) -> None:
            super().__init__(SlowClaimLedger(), max_queue=2)  # type: ignore[arg-type]
            self.exc: Exception = RuntimeError("unused")

        async def submit(self, ingest: CrashIngest) -> None:
            raise self.exc

    async def body():
        ledger = await _open_ledger()
        sink = ExplodingSubmitSink()
        try:
            sink.exc = LaneError(LaneErrorCode.DEVICE_LOST, "sink lost device")
            lane_result = await FleetRunner(ledger, sink=sink).run(
                [_spec("udid-sink-lane", lambda: FakeLane(crash_every=1), (_task("sink"),))]
            )
            assert lane_result.lanes[0].status is FleetLaneStatus.FAILED
            assert lane_result.lanes[0].tasks[0].error_code == LaneErrorCode.DEVICE_LOST.value

            sink.exc = RuntimeError("sink exploded")
            generic_result = await FleetRunner(ledger, sink=sink).run(
                [_spec("udid-sink-generic", lambda: FakeLane(crash_every=1), (_task("sink"),))]
            )
            task = generic_result.lanes[0].tasks[0]
            assert task.status is FleetTaskStatus.FAILED
            assert task.error_code == "RA_ERROR"
            assert task.error == "sink exploded"
            assert generic_result.lanes[0].status is FleetLaneStatus.COMPLETED
        finally:
            await ledger.close()

    run(body())


def test_RA_FLEET_001_late_sink_errors_do_not_mask_feed_rejection():
    class RejectedCrashLane(FakeLane):
        async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedResult:
            return FeedResult(FeedStatus.REJECTED)

        async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
            return [
                CrashRef(
                    id=f"crash-{handle.handle_id}",
                    kind="rejected",
                    handle_id=handle.handle_id,
                    payload=b"rejected",
                )
            ]

    class ExplodingSubmitSink(CrashLedgerSink):
        def __init__(self, exc: Exception) -> None:
            super().__init__(SlowClaimLedger(), max_queue=2)  # type: ignore[arg-type]
            self.exc = exc

        async def submit(self, ingest: CrashIngest) -> None:
            raise self.exc

    async def body():
        ledger = await _open_ledger()
        try:
            for exc in (
                LaneError(LaneErrorCode.DEVICE_LOST, "sink lost device"),
                RuntimeError("sink exploded"),
            ):
                sink = ExplodingSubmitSink(exc)
                result = await FleetRunner(ledger, sink=sink).run(
                    [_spec("udid-late-sink", lambda: RejectedCrashLane(), (_task(),))]
                )
                task = result.lanes[0].tasks[0]
                assert task.status is FleetTaskStatus.FAILED
                assert task.error_code == LaneErrorCode.HARNESS_REJECTED.value
                assert task.error == "feed result REJECTED"
        finally:
            await ledger.close()

    run(body())
