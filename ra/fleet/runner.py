"""Concurrent fleet lane runner with budget, thermal, and backpressure control."""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..errors import DuplicateDedup, FormatFail, RaError
from ..lanes.base import (
    CrashRef,
    DeviceProfile,
    FeedStatus,
    HarnessRef,
    Lane,
    LaneError,
    LaneErrorCode,
    ProvisionState,
    Thermal,
    Tier,
)
from ..ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger, UlidFactory, dedup_key
from ..ledger.ids import now_ms, sha256_hex

LaneFactory = Callable[[], Lane]
Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]


def _require_int(
    name: str, value: int | None, *, minimum: int, allow_none: bool = False
) -> int | None:
    if value is None:
        if allow_none:
            return None
        raise FormatFail(f"{name} must be int")
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"{name} must be int")
    if value < minimum:
        raise FormatFail(f"{name} must be >= {minimum}")
    return value


def _require_positive_float(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{name} must be number")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise FormatFail(f"{name} must be > 0")
    return number


@dataclass(frozen=True)
class FleetBudget:
    """Resource caps enforced by the fleet runner.

    ``max_queued_crashes`` bounds the ledger sink and applies backpressure to
    lane workers when crash persistence falls behind. Crash and spend caps use
    integer counts and integer micro-USD; ``None`` means uncapped.
    """

    max_concurrent_lanes: int = 2
    max_queued_crashes: int = 64
    max_feeds_per_device: int = 10_000
    max_crashes_per_device: int = 400
    max_total_crashes: int | None = None
    spend_usd_micro: int | None = None
    thermal_poll_interval_s: float = 0.25
    thermal_pause_timeout_s: float = 300.0

    def __post_init__(self) -> None:
        _require_int("max_concurrent_lanes", self.max_concurrent_lanes, minimum=1)
        _require_int("max_queued_crashes", self.max_queued_crashes, minimum=1)
        _require_int("max_feeds_per_device", self.max_feeds_per_device, minimum=1)
        _require_int("max_crashes_per_device", self.max_crashes_per_device, minimum=0)
        _require_int("max_total_crashes", self.max_total_crashes, minimum=0, allow_none=True)
        _require_int("spend_usd_micro", self.spend_usd_micro, minimum=0, allow_none=True)
        object.__setattr__(
            self,
            "thermal_poll_interval_s",
            _require_positive_float("thermal_poll_interval_s", self.thermal_poll_interval_s),
        )
        object.__setattr__(
            self,
            "thermal_pause_timeout_s",
            _require_positive_float("thermal_pause_timeout_s", self.thermal_pause_timeout_s),
        )

    def ledger_payload(self) -> dict[str, Any]:
        """Budget JSON persisted on the ledger run row."""
        return {
            "max_concurrent_lanes": self.max_concurrent_lanes,
            "max_queued_crashes": self.max_queued_crashes,
            "max_feeds_per_device": self.max_feeds_per_device,
            "max_crashes_per_device": self.max_crashes_per_device,
            "max_total_crashes": self.max_total_crashes,
            "spend_usd_micro": self.spend_usd_micro,
            "thermal_poll_interval_s": self.thermal_poll_interval_s,
            "thermal_pause_timeout_s": self.thermal_pause_timeout_s,
        }


@dataclass(frozen=True)
class FleetTask:
    """One launch/feed/collect/reset unit of lane work."""

    target: str
    harness: HarnessRef
    inputs: tuple[bytes, ...] = (b"",)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    cost_usd_micro: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target:
            raise FormatFail("fleet task target must be non-empty str")
        if not isinstance(self.harness, HarnessRef) or not self.harness.name:
            raise FormatFail("fleet task harness must have a non-empty name")
        inputs = tuple(self.inputs)
        if any(not isinstance(item, bytes) for item in inputs):
            raise FormatFail("fleet task inputs must be bytes")
        object.__setattr__(self, "inputs", inputs)
        if not isinstance(self.metadata, Mapping):
            raise FormatFail("fleet task metadata must be a mapping")
        _require_int("cost_usd_micro", self.cost_usd_micro, minimum=0)


@dataclass(frozen=True)
class FleetLaneSpec:
    """A device profile plus the lane factory and task list for one worker."""

    profile: DeviceProfile
    lane_factory: LaneFactory
    tasks: tuple[FleetTask, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.profile, DeviceProfile):
            raise FormatFail("fleet lane profile must be DeviceProfile")
        if not isinstance(self.profile.udid, str) or not self.profile.udid:
            raise FormatFail("fleet lane profile udid must be non-empty str")
        if not isinstance(self.profile.ring_node, str) or not self.profile.ring_node:
            raise FormatFail("fleet lane profile ring_node must be non-empty str")
        if not isinstance(self.profile.state, str) or not self.profile.state:
            raise FormatFail("fleet lane profile state must be non-empty str")
        if not isinstance(self.profile.tier, Tier):
            raise FormatFail("fleet lane profile tier must be Tier")
        if self.profile.build is not None and not isinstance(self.profile.build, str):
            raise FormatFail("fleet lane profile build must be str or None")
        if self.profile.exclusion_window is not None and not isinstance(
            self.profile.exclusion_window, str
        ):
            raise FormatFail("fleet lane profile exclusion_window must be str or None")
        _require_int("fleet lane profile crashes", self.profile.crashes, minimum=0)
        if not callable(self.lane_factory):
            raise FormatFail("fleet lane_factory must be callable")
        tasks = tuple(self.tasks)
        if any(not isinstance(task, FleetTask) for task in tasks):
            raise FormatFail("fleet lane tasks must be FleetTask")
        object.__setattr__(self, "tasks", tasks)


class FleetLaneStatus(StrEnum):
    """Terminal status for one lane worker."""

    COMPLETED = "completed"
    NEEDS_HAND = "needs_hand"
    FAILED = "failed"
    DRAINED = "drained"
    BUDGET_EXHAUSTED = "budget_exhausted"


class FleetTaskStatus(StrEnum):
    """Terminal status for one task."""

    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED_BUDGET = "skipped_budget"


@dataclass(frozen=True)
class FleetTaskResult:
    """Outcome for one task on one lane."""

    lane_index: int
    task_index: int
    target: str
    status: FleetTaskStatus
    feeds: int
    crashes: int
    error_code: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class FleetLaneResult:
    """Outcome for one lane worker."""

    lane_index: int
    udid: str
    lane: str | None
    status: FleetLaneStatus
    tasks: tuple[FleetTaskResult, ...]
    feeds: int
    crashes: int
    spend_usd_micro: int
    error_code: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class FleetRunResult:
    """Aggregate outcome for one fleet run."""

    run_id: str
    mode: str
    state: str
    lanes: tuple[FleetLaneResult, ...]
    crashes_recorded: int
    crashes_duplicate: int
    crashes_dropped: int
    spend_usd_micro: int
    ledger_errors: int
    queued_crashes_peak: int


@dataclass(frozen=True)
class CrashIngest:
    """CrashRef plus the fleet context needed to persist it as a claim."""

    ref: CrashRef
    lane: str
    profile: DeviceProfile
    target: str
    harness: str
    run_id: str
    task_metadata: Mapping[str, Any]


class _FleetBudgetState:
    """Shared counters for spend/crash budgets across concurrent lane workers."""

    def __init__(self, budget: FleetBudget) -> None:
        self._budget = budget
        self._lock = asyncio.Lock()
        self._crashes_seen = 0
        self._crashes_dropped = 0
        self._spend_usd_micro = 0

    @property
    def crashes_dropped(self) -> int:
        return self._crashes_dropped

    @property
    def spend_usd_micro(self) -> int:
        return self._spend_usd_micro

    def crashes_exhausted(self) -> bool:
        cap = self._budget.max_total_crashes
        return cap is not None and self._crashes_seen >= cap

    async def reserve_spend(self, cost_usd_micro: int) -> bool:
        async with self._lock:
            cap = self._budget.spend_usd_micro
            if cap is not None and self._spend_usd_micro + cost_usd_micro > cap:
                return False
            self._spend_usd_micro += cost_usd_micro
            return True

    async def reserve_crashes(self, count: int) -> int:
        async with self._lock:
            cap = self._budget.max_total_crashes
            allowed = count if cap is None else max(0, min(count, cap - self._crashes_seen))
            self._crashes_seen += allowed
            return allowed

    async def release_crashes(self, count: int) -> None:
        async with self._lock:
            self._crashes_seen = max(0, self._crashes_seen - count)

    def note_dropped_crashes(self, count: int) -> None:
        if count > 0:
            self._crashes_dropped += count


class CrashLedgerSink:
    """Bounded async sink that persists CrashRefs as ledger crash claims.

    The sink is the fleet's backpressure point: lane workers await queue space
    when crash writes fall behind, and one writer task keeps dedup checks and
    claim creation ordered.
    """

    def __init__(
        self,
        ledger: Ledger,
        *,
        max_queue: int = 64,
        id_factory: UlidFactory | None = None,
    ) -> None:
        _require_int("max_queue", max_queue, minimum=1)
        self._ledger = ledger
        self._ids = id_factory or UlidFactory()
        self._queue: asyncio.Queue[CrashIngest | None] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None
        self._control_lock = asyncio.Lock()
        self._stop_lock = asyncio.Lock()
        self._accepting = False
        self.submitted = 0
        self.created = 0
        self.duplicates = 0
        self.errors = 0
        self.last_error: str | None = None
        self.queue_peak = 0

    async def start(self) -> None:
        async with self._control_lock:
            if self._task is not None:
                return
            self._accepting = True
            self.submitted = 0
            self.created = 0
            self.duplicates = 0
            self.errors = 0
            self.last_error = None
            self.queue_peak = 0
            self._task = asyncio.create_task(self._run(), name="ra-fleet-crash-sink")

    async def submit(self, ingest: CrashIngest) -> None:
        async with self._control_lock:
            if not self._accepting:
                raise RaError("crash ledger sink is not accepting", code="FLEET_SINK_CLOSED")
            await self._queue.put(ingest)
            self.submitted += 1
            self.queue_peak = max(self.queue_peak, self._queue.qsize())

    async def stop(self) -> None:
        async with self._stop_lock:
            async with self._control_lock:
                if self._task is None:
                    self._accepting = False
                    return
                self._accepting = False
                task = self._task
            try:
                await self._queue.put(None)
                await task
            except BaseException:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                raise
            finally:
                async with self._control_lock:
                    self._task = None
                    self._accepting = False

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item is None:
                    break
                await self._write(item)
            except Exception as exc:  # keep the writer alive; surfaced in stats
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
            finally:
                self._queue.task_done()

    async def _write(self, ingest: CrashIngest) -> None:
        value_json, dedup, artifacts = _claim_material(ingest)
        if self._ledger.claim_by_dedup(dedup) is not None:
            self.duplicates += 1
            return
        try:
            await self._ledger.create_claim(
                ClaimInput(
                    claim_id=self._ids.new("cl"),
                    type="crash",
                    value_json=value_json,
                    confidence=1.0,
                    dedup_key=dedup,
                    created=now_ms(),
                    run_id=ingest.run_id,
                    artifacts=artifacts,
                )
            )
        except DuplicateDedup:
            self.duplicates += 1
            return
        self.created += 1


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"sha256": sha256_hex(value), "bytes": len(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return str(value)


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"))


def _thermal_value(thermal: Thermal | str | None) -> str | None:
    if thermal is None:
        return None
    if isinstance(thermal, Thermal):
        return thermal.value
    return str(thermal)


def _claim_material(ingest: CrashIngest) -> tuple[str, str, tuple[ClaimArtifactInput, ...]]:
    ref = ingest.ref
    profile = ingest.profile
    payload_sha = sha256_hex(ref.payload) if ref.payload else None
    value: dict[str, Any] = {
        "schema": "ra.crash.v1",
        "crash_ref_id": ref.id,
        "kind": ref.kind,
        "handle_id": ref.handle_id,
        "path": ref.path,
        "digest": ref.digest,
        "context": ref.context,
        "created_ms": ref.created_ms,
        "lane": ingest.lane,
        "udid": profile.udid,
        "ring_node": profile.ring_node,
        "build": profile.build,
        "target": ingest.target,
        "harness": ingest.harness,
        "payload_sha256": payload_sha,
        "payload_bytes": len(ref.payload),
        "metadata": _jsonable(ref.metadata),
        "task_metadata": _jsonable(ingest.task_metadata),
    }
    value_json = _canonical_json(value)
    evidence = {
        key: value[key]
        for key in (
            "crash_ref_id",
            "kind",
            "handle_id",
            "path",
            "digest",
            "context",
            "lane",
            "udid",
            "ring_node",
            "build",
            "target",
            "harness",
            "payload_sha256",
            "payload_bytes",
            "metadata",
        )
    }
    evidence_sha = sha256_hex(_canonical_json(evidence).encode("utf-8"))
    site = "|".join(
        [ingest.lane, profile.udid, profile.ring_node, profile.build or "", ingest.target]
    )
    artifacts = [
        ClaimArtifactInput(
            artifact=ArtifactInput(
                kind="crash_ref", data=value_json.encode("utf-8"), ttl_class="run"
            ),
            role="evidence",
        )
    ]
    if ref.payload:
        artifacts.append(
            ClaimArtifactInput(
                artifact=ArtifactInput(kind="crash_payload", data=ref.payload, ttl_class="run"),
                role="payload",
            )
        )
    return value_json, dedup_key("crash", evidence_sha, site), tuple(artifacts)


class FleetRunner:
    """Run lane specs concurrently under fleet budgets."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        budget: FleetBudget | None = None,
        sink: CrashLedgerSink | None = None,
        id_factory: UlidFactory | None = None,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
    ) -> None:
        self._ledger = ledger
        self._budget = budget or FleetBudget()
        self._sink = sink
        self._id_factory = id_factory
        self._sleep = sleep
        self._clock = clock

    async def run(self, specs: Sequence[FleetLaneSpec], *, mode: str = "macos") -> FleetRunResult:
        """Provision lanes, run tasks, persist crashes, and end the ledger run."""
        specs = tuple(specs)
        _validate_specs(specs)
        run_id = await self._ledger.create_run(
            mode, budget=self._budget.ledger_payload(), state="running"
        )
        sink = self._sink
        if sink is None:
            sink = CrashLedgerSink(
                self._ledger,
                max_queue=self._budget.max_queued_crashes,
                id_factory=self._id_factory,
            )
        state = _FleetBudgetState(self._budget)
        run_state = "drained"
        lane_results: list[FleetLaneResult] = []
        try:
            await sink.start()
            semaphore = asyncio.Semaphore(self._budget.max_concurrent_lanes)

            async def guarded(index: int, spec: FleetLaneSpec) -> FleetLaneResult:
                async with semaphore:
                    return await self._run_lane(index, spec, run_id, state, sink)

            lane_tasks = [
                asyncio.create_task(guarded(index, spec))
                for index, spec in enumerate(specs)
            ]
            try:
                lane_results = await asyncio.gather(*lane_tasks)
            except BaseException:
                run_state = "aborted"
                for task in lane_tasks:
                    task.cancel()
                await asyncio.gather(*lane_tasks, return_exceptions=True)
                raise
        except BaseException:
            run_state = "aborted"
            raise
        finally:
            try:
                await sink.stop()
            finally:
                await self._ledger.end_run(run_id, run_state)
        return FleetRunResult(
            run_id=run_id,
            mode=mode,
            state=run_state,
            lanes=tuple(lane_results),
            crashes_recorded=sink.created,
            crashes_duplicate=sink.duplicates,
            crashes_dropped=state.crashes_dropped,
            spend_usd_micro=state.spend_usd_micro,
            ledger_errors=sink.errors,
            queued_crashes_peak=sink.queue_peak,
        )

    async def _run_lane(
        self,
        lane_index: int,
        spec: FleetLaneSpec,
        run_id: str,
        state: _FleetBudgetState,
        sink: CrashLedgerSink,
    ) -> FleetLaneResult:
        lane: Lane | None = None
        lane_name: str | None = None
        status = FleetLaneStatus.COMPLETED
        error_code: str | None = None
        error: str | None = None
        task_results: list[FleetTaskResult] = []
        feeds = 0
        crashes = 0
        spend = 0
        crashes_before = spec.profile.crashes
        lane_crashes = 0
        feeds_seen = 0
        try:
            lane = spec.lane_factory()
            lane_name = lane.name
            provision = await lane.provision(spec.profile)
            provision_state = (
                provision.state.value
                if provision.state is not None
                else ("ready" if provision.ready else "failed")
            )
            await self._upsert_profile(spec.profile, state=provision_state)
            if not provision.ready:
                status = (
                    FleetLaneStatus.NEEDS_HAND
                    if provision.state is ProvisionState.NEEDS_HAND
                    else FleetLaneStatus.FAILED
                )
                if provision.error_code is not None:
                    error_code = provision.error_code.value
                if provision.details:
                    error = _canonical_json(_jsonable(provision.details))
            else:
                for task_index, task in enumerate(spec.tasks):
                    if self._feed_budget_exhausted(feeds_seen):
                        status = FleetLaneStatus.BUDGET_EXHAUSTED
                        task_results.extend(self._skipped_tasks(lane_index, spec.tasks, task_index))
                        break
                    if self._crash_budget_exhausted(crashes_before + lane_crashes) or (
                        state.crashes_exhausted()
                    ):
                        status = FleetLaneStatus.BUDGET_EXHAUSTED
                        task_results.extend(self._skipped_tasks(lane_index, spec.tasks, task_index))
                        break
                    if not await self._ensure_available(lane, spec.profile):
                        status = FleetLaneStatus.DRAINED
                        break
                    if not await state.reserve_spend(task.cost_usd_micro):
                        status = FleetLaneStatus.BUDGET_EXHAUSTED
                        task_results.extend(self._skipped_tasks(lane_index, spec.tasks, task_index))
                        break
                    spend += task.cost_usd_micro
                    result = await self._run_task(
                        lane=lane,
                        lane_index=lane_index,
                        task_index=task_index,
                        task=task,
                        spec=spec,
                        run_id=run_id,
                        state=state,
                        feeds_seen=feeds_seen,
                        crashes_seen=crashes_before + lane_crashes,
                        sink=sink,
                    )
                    task_results.append(result)
                    feeds_seen += result.feeds
                    lane_crashes += result.crashes
                    feeds += result.feeds
                    crashes += result.crashes
                    if result.error_code == LaneErrorCode.THERMAL_DRAIN.value:
                        status = FleetLaneStatus.DRAINED
                        break
                    if result.error_code in {
                        LaneErrorCode.DEVICE_LOST.value,
                        LaneErrorCode.NOT_PROVISIONED.value,
                    }:
                        status = FleetLaneStatus.FAILED
                        error_code = result.error_code
                        error = result.error
                        break
                    if result.error_code == LaneErrorCode.BUDGET_EXHAUSTED.value:
                        status = FleetLaneStatus.BUDGET_EXHAUSTED
                        next_index = task_index + 1
                        task_results.extend(self._skipped_tasks(lane_index, spec.tasks, next_index))
                        break
                    if self._crash_budget_exhausted(crashes_before + lane_crashes) or (
                        state.crashes_exhausted()
                    ):
                        status = FleetLaneStatus.BUDGET_EXHAUSTED
                        next_index = task_index + 1
                        task_results.extend(self._skipped_tasks(lane_index, spec.tasks, next_index))
                        break
        except LaneError as exc:
            status = (
                FleetLaneStatus.DRAINED
                if exc.code is LaneErrorCode.THERMAL_DRAIN
                else FleetLaneStatus.FAILED
            )
            error_code = exc.code.value
            error = exc.message
        except Exception as exc:
            status = FleetLaneStatus.FAILED
            error_code = "RA_ERROR"
            error = str(exc)
        finally:
            teardown_error = await self._safe_teardown(lane)
            if teardown_error is not None:
                if error is None:
                    error = teardown_error
                    error_code = error_code or "RA_ERROR"
                if status is FleetLaneStatus.COMPLETED:
                    status = FleetLaneStatus.FAILED
            spec.profile.crashes = crashes_before + crashes
            await self._upsert_profile(spec.profile, state=status.value)
        return FleetLaneResult(
            lane_index=lane_index,
            udid=spec.profile.udid,
            lane=lane_name,
            status=status,
            tasks=tuple(task_results),
            feeds=feeds,
            crashes=crashes,
            spend_usd_micro=spend,
            error_code=error_code,
            error=error,
        )

    async def _run_task(
        self,
        *,
        lane: Lane,
        lane_index: int,
        task_index: int,
        task: FleetTask,
        spec: FleetLaneSpec,
        run_id: str,
        state: _FleetBudgetState,
        feeds_seen: int,
        crashes_seen: int,
        sink: CrashLedgerSink,
    ) -> FleetTaskResult:
        feeds = 0
        crashes = 0
        status = FleetTaskStatus.COMPLETED
        error_code: str | None = None
        error: str | None = None
        try:
            handle = await lane.launch(task.target, task.harness)
        except LaneError as exc:
            return FleetTaskResult(
                lane_index=lane_index,
                task_index=task_index,
                target=task.target,
                status=FleetTaskStatus.FAILED,
                feeds=0,
                crashes=0,
                error_code=exc.code.value,
                error=exc.message,
            )
        except Exception as exc:
            return FleetTaskResult(
                lane_index=lane_index,
                task_index=task_index,
                target=task.target,
                status=FleetTaskStatus.FAILED,
                feeds=0,
                crashes=0,
                error_code="RA_ERROR",
                error=str(exc),
            )
        collected = False
        try:
            for data in task.inputs:
                if feeds_seen + feeds >= self._budget.max_feeds_per_device:
                    status = FleetTaskStatus.FAILED
                    error_code = LaneErrorCode.BUDGET_EXHAUSTED.value
                    error = "max_feeds_per_device reached"
                    break
                try:
                    available = await self._ensure_available(lane, spec.profile)
                except LaneError as exc:
                    status = FleetTaskStatus.FAILED
                    error_code = exc.code.value
                    error = exc.message
                    break
                except Exception as exc:
                    status = FleetTaskStatus.FAILED
                    error_code = "RA_ERROR"
                    error = str(exc)
                    break
                if not available:
                    status = FleetTaskStatus.FAILED
                    error_code = LaneErrorCode.THERMAL_DRAIN.value
                    error = "thermal drain"
                    break
                try:
                    feed_result = await lane.feed(handle, data)
                except LaneError as exc:
                    status = FleetTaskStatus.FAILED
                    error_code = exc.code.value
                    error = exc.message
                    if exc.crash_ref is not None:
                        submitted, _dropped = await self._persist_crash_refs(
                            [exc.crash_ref],
                            lane=lane,
                            spec=spec,
                            task=task,
                            run_id=run_id,
                            state=state,
                            crashes_seen=crashes_seen + crashes,
                            sink=sink,
                        )
                        crashes += submitted
                    break
                except Exception as exc:
                    status = FleetTaskStatus.FAILED
                    error_code = "RA_ERROR"
                    error = str(exc)
                    break
                if feed_result.status is not FeedStatus.ACCEPTED:
                    status = FleetTaskStatus.FAILED
                    error_code = LaneErrorCode.HARNESS_REJECTED.value
                    error = f"feed result {feed_result.status.value}"
                    break
                feeds += 1
            refs: list[CrashRef] = []
            try:
                refs = await lane.collect_crashes(handle)
                collected = True
            except LaneError as exc:
                if error_code is None:
                    status = FleetTaskStatus.FAILED
                    error_code = exc.code.value
                    error = exc.message
            except Exception as exc:
                if error_code is None:
                    status = FleetTaskStatus.FAILED
                    error_code = "RA_ERROR"
                    error = str(exc)
            submitted, _dropped = await self._persist_crash_refs(
                refs,
                lane=lane,
                spec=spec,
                task=task,
                run_id=run_id,
                state=state,
                crashes_seen=crashes_seen + crashes,
                sink=sink,
            )
            crashes += submitted
            if collected:
                try:
                    await lane.reset(handle)
                except LaneError as exc:
                    if error_code is None:
                        status = FleetTaskStatus.FAILED
                        error_code = exc.code.value
                        error = exc.message
                except Exception as exc:
                    if error_code is None:
                        status = FleetTaskStatus.FAILED
                        error_code = "RA_ERROR"
                        error = str(exc)
        except LaneError as exc:
            if error_code is None:
                status = FleetTaskStatus.FAILED
                error_code = exc.code.value
                error = exc.message
        except Exception as exc:
            if error_code is None:
                status = FleetTaskStatus.FAILED
                error_code = "RA_ERROR"
                error = str(exc)
        return FleetTaskResult(
            lane_index=lane_index,
            task_index=task_index,
            target=task.target,
            status=status,
            feeds=feeds,
            crashes=crashes,
            error_code=error_code,
            error=error,
        )

    async def _persist_crash_refs(
        self,
        refs: Sequence[CrashRef],
        *,
        lane: Lane,
        spec: FleetLaneSpec,
        task: FleetTask,
        run_id: str,
        state: _FleetBudgetState,
        crashes_seen: int,
        sink: CrashLedgerSink,
    ) -> tuple[int, int]:
        if not refs:
            return 0, 0
        device_remaining = max(0, self._budget.max_crashes_per_device - crashes_seen)
        wanted = min(len(refs), device_remaining)
        allowed = await state.reserve_crashes(wanted)
        dropped = len(refs) - allowed
        state.note_dropped_crashes(dropped)
        submitted = 0
        try:
            for ref in refs[:allowed]:
                await sink.submit(
                    CrashIngest(
                        ref=ref,
                        lane=lane.name,
                        profile=spec.profile,
                        target=task.target,
                        harness=task.harness.name,
                        run_id=run_id,
                        task_metadata=task.metadata,
                    )
                )
                submitted += 1
        except BaseException:
            await state.release_crashes(allowed - submitted)
            raise
        return submitted, dropped

    def _feed_budget_exhausted(self, feeds_seen: int) -> bool:
        return feeds_seen >= self._budget.max_feeds_per_device

    def _crash_budget_exhausted(self, crashes_seen: int) -> bool:
        return crashes_seen >= self._budget.max_crashes_per_device

    def _skipped_tasks(
        self, lane_index: int, tasks: Sequence[FleetTask], start: int
    ) -> list[FleetTaskResult]:
        return [
            FleetTaskResult(
                lane_index=lane_index,
                task_index=index,
                target=task.target,
                status=FleetTaskStatus.SKIPPED_BUDGET,
                feeds=0,
                crashes=0,
            )
            for index, task in enumerate(tasks[start:], start=start)
        ]

    async def _ensure_available(self, lane: Lane, profile: DeviceProfile) -> bool:
        reading = Thermal(await lane.thermal())
        profile.thermal = reading
        if reading is Thermal.NOMINAL:
            return True
        if reading is Thermal.CRITICAL:
            await self._mark_drained(profile, reading)
            return False
        await self._upsert_profile(profile, state="thermal_pause")
        deadline = self._clock() + self._budget.thermal_pause_timeout_s
        while True:
            await self._sleep(self._budget.thermal_poll_interval_s)
            reading = Thermal(await lane.thermal())
            profile.thermal = reading
            if reading is Thermal.NOMINAL:
                return True
            if reading is Thermal.CRITICAL:
                await self._mark_drained(profile, reading)
                return False
            if self._clock() >= deadline:
                await self._mark_drained(profile, Thermal.CRITICAL)
                return False

    async def _mark_drained(self, profile: DeviceProfile, reading: Thermal) -> None:
        profile.state = "drained"
        profile.thermal = reading
        await self._upsert_profile(profile, state="drained")

    async def _upsert_profile(self, profile: DeviceProfile, *, state: str) -> None:
        payload = {
            "udid": profile.udid,
            "build": profile.build,
            "tier": profile.tier.value,
            "state": state,
            "thermal": _thermal_value(profile.thermal),
            "crashes": profile.crashes,
            "exclusion_window": profile.exclusion_window,
            "ring_node": profile.ring_node,
        }
        await self._ledger.upsert_device_profile(payload)

    async def _safe_teardown(self, lane: Lane | None) -> str | None:
        if lane is None:
            return None
        try:
            await lane.teardown()
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        return None


def _validate_specs(specs: Sequence[FleetLaneSpec]) -> None:
    seen: set[str] = set()
    for spec in specs:
        if not isinstance(spec, FleetLaneSpec):
            raise FormatFail("fleet lane spec must be FleetLaneSpec")
        udid = spec.profile.udid
        if not udid.strip():
            raise FormatFail("fleet lane profile udid must be non-empty str")
        if udid in seen:
            raise FormatFail(f"duplicate fleet lane udid: {udid}")
        seen.add(udid)


__all__ = [
    "CrashIngest",
    "CrashLedgerSink",
    "FleetBudget",
    "FleetLaneResult",
    "FleetLaneSpec",
    "FleetLaneStatus",
    "FleetRunResult",
    "FleetRunner",
    "FleetTask",
    "FleetTaskResult",
    "FleetTaskStatus",
]
