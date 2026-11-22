"""Fuzzing campaign orchestrator over the corpus scheduler and claim ledger.

The orchestrator consumes already-ranked surfaces (the surface ranker's output is
represented by ``CampaignSurface.score``), allocates a finite case/cost/wall-time
budget across lanes, drives each lane through the ledger-backed corpus scheduler,
and persists all durable campaign state as parked work orders plus ``bug_class``
claims. It has no side store: restarts rebuild from ledger rows only.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from .corpus import CorpusScheduler, CorpusSeedSpec, CorpusSeedView
from .errors import FormatFail
from .ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger
from .ledger.ids import dedup_key, now_ms, sha256_hex

STORE_KIND = "ra.campaign.orchestrator.v1"
WORK_ORDER_ACTION = "park"
WORK_ORDER_STATE = "parked"
_MAX_INT = 2**53 - 1
_MAX_SCORE = 1_000_000.0
_MAX_METADATA_BYTES = 8192
_MAX_ERROR_LEN = 256


class CampaignRunner(Protocol):
    """Lane executor protocol used by the orchestrator."""

    async def run_seed(
        self,
        lane: str,
        seed: CorpusSeedView,
        *,
        tick: int,
        case_index: int,
    ) -> LaneTickResult:
        """Run one scheduler-selected seed and return measured lane output."""
        raise NotImplementedError


@dataclass(frozen=True)
class CampaignSurface:
    """One ranked surface assigned to a lane."""

    surface_id: str
    lane: str
    score: float
    seeds: tuple[CorpusSeedSpec, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "surface_id", _require_str(self.surface_id, "surface_id", max_length=128))
        object.__setattr__(self, "lane", _require_lane(self.lane))
        object.__setattr__(self, "score", _require_finite_float(self.score, "score", minimum=0.0))
        if isinstance(self.seeds, (str, bytes)) or not isinstance(self.seeds, Iterable):
            raise FormatFail("surface seeds must be an iterable of CorpusSeedSpec")
        seeds = tuple(self.seeds)
        for seed in seeds:
            if not isinstance(seed, CorpusSeedSpec):
                raise FormatFail(f"surface {self.surface_id} seed is not a CorpusSeedSpec")
            if seed.lane != self.lane:
                raise FormatFail(f"surface {self.surface_id} seed lane {seed.lane!r} != {self.lane!r}")
        object.__setattr__(self, "seeds", seeds)
        object.__setattr__(self, "metadata", _validate_metadata(self.metadata, "surface_metadata"))


@dataclass(frozen=True)
class CampaignBudget:
    """Finite resource envelope for one campaign."""

    max_ticks: int = 1
    cases_per_tick: int = 8
    max_cases: int | None = None
    max_cost_usd_micro: int | None = None
    max_wall_ms: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_ticks", _require_int(self.max_ticks, "max_ticks", minimum=1, maximum=1_000_000))
        object.__setattr__(
            self,
            "cases_per_tick",
            _require_int(self.cases_per_tick, "cases_per_tick", minimum=1, maximum=4096),
        )
        object.__setattr__(self, "max_cases", _optional_int(self.max_cases, "max_cases"))
        object.__setattr__(
            self,
            "max_cost_usd_micro",
            _optional_int(self.max_cost_usd_micro, "max_cost_usd_micro"),
        )
        object.__setattr__(self, "max_wall_ms", _optional_int(self.max_wall_ms, "max_wall_ms"))
        if self.max_cases == 0:
            raise FormatFail("max_cases must be positive when set")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_ticks": self.max_ticks,
            "cases_per_tick": self.cases_per_tick,
            "max_cases": self.max_cases,
            "max_cost_usd_micro": self.max_cost_usd_micro,
            "max_wall_ms": self.max_wall_ms,
        }


@dataclass(frozen=True)
class RebalancePolicy:
    """Yield-responsive allocation controls."""

    alpha: float = 0.35
    yield_window: int = 4
    crash_weight: float = 2.0
    edge_scale: float = 1000.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "alpha", _require_finite_float(self.alpha, "alpha", minimum=0.0, maximum=1.0))
        object.__setattr__(
            self,
            "yield_window",
            _require_int(self.yield_window, "yield_window", minimum=1, maximum=1024),
        )
        object.__setattr__(
            self,
            "crash_weight",
            _require_finite_float(self.crash_weight, "crash_weight", minimum=0.0, maximum=_MAX_SCORE),
        )
        object.__setattr__(
            self,
            "edge_scale",
            _require_finite_float(self.edge_scale, "edge_scale", minimum=1.0, maximum=_MAX_SCORE),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "alpha": self.alpha,
            "yield_window": self.yield_window,
            "crash_weight": self.crash_weight,
            "edge_scale": self.edge_scale,
        }


@dataclass(frozen=True)
class LaneTickResult:
    """Measured output from one lane seed execution."""

    covered_edges: tuple[str, ...] = ()
    crashes: tuple[CampaignCrash, ...] = ()
    cost_usd_micro: int = 0
    elapsed_ms: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.covered_edges, (str, bytes)) or not isinstance(
            self.covered_edges, Iterable
        ):
            raise FormatFail("covered_edges must be an iterable of edge ids")
        if isinstance(self.crashes, (str, bytes)) or not isinstance(self.crashes, Iterable):
            raise FormatFail("crashes must be an iterable of CampaignCrash")
        edges = tuple(self.covered_edges)
        for edge in edges:
            _require_str(edge, "covered_edge", max_length=256)
        crashes = tuple(self.crashes)
        for crash in crashes:
            if not isinstance(crash, CampaignCrash):
                raise FormatFail("crashes must contain CampaignCrash values")
        object.__setattr__(self, "covered_edges", edges)
        object.__setattr__(self, "crashes", crashes)
        object.__setattr__(self, "cost_usd_micro", _require_int(self.cost_usd_micro, "cost_usd_micro", minimum=0))
        object.__setattr__(self, "elapsed_ms", _require_int(self.elapsed_ms, "elapsed_ms", minimum=0))


@dataclass(frozen=True)
class CampaignCrash:
    """Crash evidence emitted by a lane runner."""

    crash_id: str
    signature: str
    lane: str
    surface_id: str
    seed_id: str
    payload: bytes = b""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "crash_id", _require_str(self.crash_id, "crash_id", max_length=128))
        object.__setattr__(self, "signature", _require_str(self.signature, "signature", max_length=128))
        object.__setattr__(self, "lane", _require_lane(self.lane))
        object.__setattr__(self, "surface_id", _require_str(self.surface_id, "surface_id", max_length=128))
        object.__setattr__(self, "seed_id", _require_str(self.seed_id, "seed_id", max_length=128))
        if not isinstance(self.payload, bytes):
            raise FormatFail("crash payload must be bytes")
        object.__setattr__(self, "metadata", _validate_metadata(self.metadata, "crash_metadata"))


@dataclass(frozen=True)
class LaneTickRecord:
    """Per-lane progress snapshot for one executed tick."""

    tick: int
    cases: int
    crashes: int
    new_edges: int
    cost_usd_micro: int
    elapsed_ms: int
    errors: int

    def __post_init__(self) -> None:
        for name in ("tick", "cases", "crashes", "new_edges", "cost_usd_micro", "elapsed_ms", "errors"):
            object.__setattr__(self, name, _require_int(getattr(self, name), name, minimum=0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tick": self.tick,
            "cases": self.cases,
            "crashes": self.crashes,
            "new_edges": self.new_edges,
            "cost_usd_micro": self.cost_usd_micro,
            "elapsed_ms": self.elapsed_ms,
            "errors": self.errors,
        }


@dataclass
class LaneProgress:
    """Mutable per-lane progress accumulator."""

    lane: str
    score: float
    surface_ids: tuple[str, ...]
    cases: int = 0
    crashes: int = 0
    errors: int = 0
    cost_usd_micro: int = 0
    elapsed_ms: int = 0
    new_edges: int = 0
    last_new_edges: int = 0
    covered_edge_ids: set[str] = field(default_factory=set)
    recent: list[LaneTickRecord] = field(default_factory=list)
    last_error: str | None = None

    def to_dict(self, *, yield_window: int) -> dict[str, Any]:
        return {
            "lane": self.lane,
            "score": self.score,
            "surface_ids": list(self.surface_ids),
            "cases": self.cases,
            "crashes": self.crashes,
            "errors": self.errors,
            "cost_usd_micro": self.cost_usd_micro,
            "elapsed_ms": self.elapsed_ms,
            "coverage_edges": len(self.covered_edge_ids),
            "new_edges": self.new_edges,
            "last_new_edges": self.last_new_edges,
            "last_error": self.last_error,
            "recent": [record.to_dict() for record in self.recent[-yield_window:]],
        }


@dataclass(frozen=True)
class CrashAggregate:
    """Ledger-ready crash aggregate for one signature."""

    signature: str
    lane: str
    surface_id: str
    seed_id: str
    crash_id: str
    payload: bytes
    metadata: Mapping[str, Any]
    count: int
    first_tick: int
    last_tick: int

    def value_dict(self) -> dict[str, Any]:
        return {
            "record_kind": "campaign_crash",
            "campaign_id": None,
            "signature": self.signature,
            "lane": self.lane,
            "surface_id": self.surface_id,
            "seed_id": self.seed_id,
            "crash_id": self.crash_id,
            "count": self.count,
            "first_tick": self.first_tick,
            "last_tick": self.last_tick,
            "payload_sha256": sha256_hex(self.payload),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class CampaignResult:
    """Terminal campaign outcome."""

    campaign_id: str
    status: str
    stop_reason: str
    ticks: int
    cases: int
    crashes: int
    errors: int
    cost_usd_micro: int
    elapsed_ms: int
    coverage_edges: int
    new_edges: int
    lanes: tuple[LaneProgress, ...]
    claim_ids: tuple[str, ...]
    state_work_order_id: str
    created: int
    updated: int

    def summary_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "ticks": self.ticks,
            "cases": self.cases,
            "crashes": self.crashes,
            "errors": self.errors,
            "cost_usd_micro": self.cost_usd_micro,
            "elapsed_ms": self.elapsed_ms,
            "coverage_edges": self.coverage_edges,
            "new_edges": self.new_edges,
            "lane_count": len(self.lanes),
            "claim_count": len(self.claim_ids),
        }


@dataclass
class _CrashAccumulator:
    signature: str
    lane: str
    surface_id: str
    seed_id: str
    crash_id: str
    payload: bytes
    metadata: dict[str, Any]
    count: int = 0
    first_tick: int = 0
    last_tick: int = 0

    def observe(self, crash: CampaignCrash, tick: int) -> None:
        if self.count == 0:
            self.first_tick = tick
            self.payload = crash.payload
            self.metadata = dict(crash.metadata)
        self.count += 1
        self.last_tick = tick

    def aggregate(self) -> CrashAggregate:
        return CrashAggregate(
            signature=self.signature,
            lane=self.lane,
            surface_id=self.surface_id,
            seed_id=self.seed_id,
            crash_id=self.crash_id,
            payload=self.payload,
            metadata=self.metadata,
            count=self.count,
            first_tick=self.first_tick,
            last_tick=self.last_tick,
        )


@dataclass
class _TickDelta:
    cases: int = 0
    crashes: int = 0
    new_edges: int = 0
    cost_usd_micro: int = 0
    elapsed_ms: int = 0
    errors: int = 0

    def add(self, other: _TickDelta) -> None:
        self.cases += other.cases
        self.crashes += other.crashes
        self.new_edges += other.new_edges
        self.cost_usd_micro += other.cost_usd_micro
        self.elapsed_ms += other.elapsed_ms
        self.errors += other.errors


@dataclass(frozen=True)
class _SeedOutcome:
    delta: _TickDelta
    seed_id: str
    surface_id: str


class CampaignOrchestrator:
    """Coordinates ranked surfaces across lanes under one budget."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        namespace: str = "default",
        corpus: CorpusScheduler | None = None,
        policy: RebalancePolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        _require_str(namespace, "namespace", max_length=64)
        if not _NAMESPACE_RE.fullmatch(namespace):
            raise FormatFail("namespace must match [a-z0-9][a-z0-9._-]{0,63}")
        if corpus is not None and not isinstance(corpus, CorpusScheduler):
            raise FormatFail("corpus must be a CorpusScheduler")
        if policy is not None and not isinstance(policy, RebalancePolicy):
            raise FormatFail("policy must be a RebalancePolicy")
        if not callable(clock):
            raise FormatFail("clock must be callable")
        self._ledger = ledger
        self._namespace = namespace
        self._corpus = corpus or CorpusScheduler(ledger, namespace=namespace)
        self._policy = policy or RebalancePolicy()
        self._clock = clock
        self._unit = f"ra.campaign.{namespace}"

    @property
    def corpus(self) -> CorpusScheduler:
        return self._corpus

    @property
    def policy(self) -> RebalancePolicy:
        return self._policy

    async def run(
        self,
        campaign_id: str,
        surfaces: Iterable[CampaignSurface],
        budget: CampaignBudget,
        *,
        runner: CampaignRunner,
        run_id: str | None = None,
        created: int | None = None,
    ) -> CampaignResult:
        """Run one campaign to a budget/seed-exhaustion terminal state."""
        campaign_id = _require_campaign_id(campaign_id)
        if not isinstance(budget, CampaignBudget):
            raise FormatFail("budget must be a CampaignBudget")
        if runner is None:
            raise FormatFail("runner is required")
        surface_list = self._validate_surfaces(surfaces)
        created_ts = now_ms() if created is None else _require_int(created, "created", minimum=0)
        run_id = run_id or f"run_{campaign_id}"
        _require_str(run_id, "run_id", max_length=128)

        for surface in surface_list:
            for seed in surface.seeds:
                await self._corpus.register_seed(seed, created=created_ts)

        lanes = self._initial_lanes(surface_list)
        self._crash_accumulators: dict[str, _CrashAccumulator] = {}
        state_id, state_created, state_updated = await self._load_or_create_state(
            campaign_id=campaign_id,
            run_id=run_id,
            budget=budget,
            surfaces=surface_list,
            lanes=lanes,
            ticks=0,
            created=created_ts,
        )
        start = self._clock()
        spent_cost = sum(lane.cost_usd_micro for lane in lanes.values())
        stop_reason = "max_ticks"
        status = "complete"

        ticks_done = 0
        for tick in range(budget.max_ticks):
            if self._wall_exceeded(start, budget.max_wall_ms):
                stop_reason = "max_wall_ms"
                status = "budget_exhausted"
                break
            used_cases = sum(lane.cases for lane in lanes.values())
            cases_this_tick = self._cases_this_tick(used_cases, tick, budget)
            if cases_this_tick <= 0:
                stop_reason = "max_cases" if budget.max_cases is not None else "max_ticks"
                status = "budget_exhausted" if budget.max_cases is not None else "complete"
                break
            allocation = self._allocate(lanes, cases_this_tick)
            executed = 0
            tick_halted = False
            for lane_name in sorted(allocation):
                lane_cases = allocation[lane_name]
                progress = lanes[lane_name]
                batch = self._corpus.next_batch(
                    lane=lane_name,
                    batch_size=lane_cases,
                    schedule_seed=self._schedule_seed(tick, lane_name),
                )
                delta = _TickDelta()
                for case_index, seed_view in enumerate(batch[:lane_cases]):
                    if self._wall_exceeded(start, budget.max_wall_ms):
                        stop_reason = "max_wall_ms"
                        status = "budget_exhausted"
                        tick_halted = True
                        break
                    if budget.max_cost_usd_micro is not None and spent_cost >= budget.max_cost_usd_micro:
                        stop_reason = "max_cost_usd_micro"
                        status = "budget_exhausted"
                        tick_halted = True
                        break
                    outcome = await self._execute_seed(
                        runner, progress, lane_name, seed_view, tick, case_index, run_id=run_id
                    )
                    delta.add(outcome.delta)
                    spent_cost += outcome.delta.cost_usd_micro
                    executed += outcome.delta.cases
                if delta.cases or delta.errors:
                    self._append_tick_record(progress, tick, delta)
                if tick_halted:
                    break
            if executed == 0 and stop_reason == "max_ticks":
                stop_reason = "no_active_seeds"
                status = "no_work"
                break
            if executed > 0:
                ticks_done = tick + 1
            if tick_halted:
                break
            await self._save_state(
                campaign_id=campaign_id,
                run_id=run_id,
                status=status,
                stop_reason=stop_reason,
                ticks=ticks_done,
                budget=budget,
                surfaces=surface_list,
                lanes=lanes,
                claim_ids=(),
                created=created_ts,
                work_order_id=state_id,
            )

        # Persist terminal state before claims so a crash during claim emission can resume.
        terminal_status = status
        await self._save_state(
            campaign_id=campaign_id,
            run_id=run_id,
            status=terminal_status,
            stop_reason=stop_reason,
            ticks=ticks_done,
            budget=budget,
            surfaces=surface_list,
            lanes=lanes,
            claim_ids=(),
            created=created_ts,
            work_order_id=state_id,
        )
        claim_ids = await self._emit_claims(
            campaign_id=campaign_id,
            run_id=run_id,
            status=terminal_status,
            stop_reason=stop_reason,
            budget=budget,
            lanes=lanes,
            ticks=ticks_done,
            created=created_ts,
        )
        state_updated = await self._save_state(
            campaign_id=campaign_id,
            run_id=run_id,
            status=terminal_status,
            stop_reason=stop_reason,
            ticks=ticks_done,
            budget=budget,
            surfaces=surface_list,
            lanes=lanes,
            claim_ids=claim_ids,
            created=created_ts,
            work_order_id=state_id,
        )
        lanes_tuple = tuple(lanes[name] for name in sorted(lanes))
        totals = self._totals(lanes_tuple, ticks_done)
        return CampaignResult(
            campaign_id=campaign_id,
            status=terminal_status,
            stop_reason=stop_reason,
            ticks=ticks_done,
            cases=totals["cases"],
            crashes=totals["crashes"],
            errors=totals["errors"],
            cost_usd_micro=totals["cost_usd_micro"],
            elapsed_ms=totals["elapsed_ms"],
            coverage_edges=totals["coverage_edges"],
            new_edges=totals["new_edges"],
            lanes=lanes_tuple,
            claim_ids=claim_ids,
            state_work_order_id=state_id,
            created=state_created,
            updated=state_updated,
        )

    # ------------------------------------------------------------------ allocation

    def _validate_surfaces(self, surfaces: Iterable[CampaignSurface]) -> tuple[CampaignSurface, ...]:
        if isinstance(surfaces, (str, bytes)) or not isinstance(surfaces, Iterable):
            raise FormatFail("surfaces must be an iterable of CampaignSurface")
        result = tuple(surfaces)
        if not result:
            raise FormatFail("campaign requires at least one surface")
        seen_surfaces: set[str] = set()
        seen_seeds: set[str] = set()
        lanes: set[str] = set()
        for surface in result:
            if not isinstance(surface, CampaignSurface):
                raise FormatFail("surfaces must contain CampaignSurface values")
            if surface.surface_id in seen_surfaces:
                raise FormatFail(f"duplicate surface_id {surface.surface_id}")
            seen_surfaces.add(surface.surface_id)
            lanes.add(surface.lane)
            for seed in surface.seeds:
                if seed.seed_id in seen_seeds:
                    raise FormatFail(f"duplicate corpus seed_id {seed.seed_id}")
                seen_seeds.add(seed.seed_id)
        if len(result) > 256:
            raise FormatFail("campaign supports at most 256 surfaces")
        if len(lanes) > 64:
            raise FormatFail("campaign supports at most 64 lanes")
        return result

    def _initial_lanes(self, surfaces: tuple[CampaignSurface, ...]) -> dict[str, LaneProgress]:
        lanes: dict[str, LaneProgress] = {}
        for surface in surfaces:
            lane = lanes.get(surface.lane)
            if lane is None:
                lanes[surface.lane] = LaneProgress(
                    lane=surface.lane,
                    score=surface.score,
                    surface_ids=(surface.surface_id,),
                )
            else:
                lane.score += surface.score
                lane.surface_ids = tuple(sorted((*lane.surface_ids, surface.surface_id)))
        return lanes

    def _cases_this_tick(self, used_cases: int, tick: int, budget: CampaignBudget) -> int:
        if budget.max_cases is not None and used_cases >= budget.max_cases:
            return 0
        remaining = budget.cases_per_tick
        if budget.max_cases is not None:
            remaining = min(remaining, budget.max_cases - used_cases)
        remaining_ticks = budget.max_ticks - tick
        if remaining_ticks > 0 and budget.max_cases is not None:
            remaining = min(remaining, math.ceil((budget.max_cases - used_cases) / remaining_ticks))
        return max(0, remaining)

    def _allocate(self, lanes: Mapping[str, LaneProgress], cases: int) -> dict[str, int]:
        names = sorted(lanes)
        if cases <= 0 or not names:
            return {}
        base = {name: self._base_weight(lanes[name]) for name in names}
        total_base = sum(base.values())
        if total_base <= 0.0:
            weights = {name: 1.0 for name in names}
        else:
            weights = {name: base[name] / total_base for name in names}
        yields = {name: self._lane_yield(lanes[name]) for name in names}
        max_yield = max(yields.values())
        if max_yield <= 0.0:
            yield_weights = {name: 0.0 for name in names}
        else:
            yield_weights = {name: yields[name] / max_yield for name in names}
        alpha = self._policy.alpha
        combined = {
            name: (1.0 - alpha) * weights[name] + alpha * yield_weights[name]
            for name in names
        }
        total_combined = sum(combined.values())
        if total_combined <= 0.0:
            combined = weights
            total_combined = sum(combined.values())
        raw = {name: cases * combined[name] / total_combined for name in names}
        allocation = {name: int(math.floor(raw[name])) for name in names}
        leftover = cases - sum(allocation.values())
        order = sorted(names, key=lambda name: (-(raw[name] - allocation[name]), name))
        for name in order[:leftover]:
            allocation[name] += 1
        return {name: count for name, count in allocation.items() if count > 0}

    def _base_weight(self, progress: LaneProgress) -> float:
        return max(0.0, progress.score)

    def _lane_yield(self, progress: LaneProgress) -> float:
        window = progress.recent[-self._policy.yield_window :]
        if not window:
            return 0.0
        cases = sum(record.cases for record in window)
        if cases <= 0:
            return 0.0
        crashes = sum(record.crashes for record in window)
        new_edges = sum(record.new_edges for record in window)
        raw = (new_edges + self._policy.crash_weight * crashes) / cases
        coverage = len(progress.covered_edge_ids)
        diminishing = 1.0 / (1.0 + coverage / self._policy.edge_scale)
        return max(0.0, raw * diminishing)

    # ------------------------------------------------------------------ execution

    async def _execute_seed(
        self,
        runner: CampaignRunner,
        progress: LaneProgress,
        lane: str,
        seed: CorpusSeedView,
        tick: int,
        case_index: int,
        *,
        run_id: str,
    ) -> _SeedOutcome:
        progress.cases += 1
        try:
            result = await runner.run_seed(lane, seed, tick=tick, case_index=case_index)
            if not isinstance(result, LaneTickResult):
                raise FormatFail("runner must return LaneTickResult")
            await self._corpus.record_coverage(
                seed.seed_id,
                result.covered_edges,
                run_id=run_id,
                created=now_ms(),
            )
            delta = self._record_result(progress, result, seed, tick)
        except Exception as exc:  # lane failures are isolated and ledger-recorded
            progress.errors += 1
            progress.last_error = self._error_text(exc)
            delta = _TickDelta(cases=1, errors=1)
        return _SeedOutcome(delta=delta, seed_id=seed.seed_id, surface_id=self._surface_for_seed(progress, seed))

    def _record_result(
        self,
        progress: LaneProgress,
        result: LaneTickResult,
        seed: CorpusSeedView,
        tick: int,
    ) -> _TickDelta:
        for crash in result.crashes:
            if crash.lane != progress.lane:
                raise FormatFail(f"crash lane {crash.lane!r} does not match {progress.lane!r}")
        new_edges = 0
        for edge in result.covered_edges:
            edge_id = _require_str(edge, "covered_edge", max_length=256)
            if edge_id not in progress.covered_edge_ids:
                progress.covered_edge_ids.add(edge_id)
                new_edges += 1
        progress.new_edges += new_edges
        progress.last_new_edges = new_edges
        crash_count = len(result.crashes)
        progress.crashes += crash_count
        progress.cost_usd_micro += result.cost_usd_micro
        progress.elapsed_ms += result.elapsed_ms
        for crash in result.crashes:
            key = f"{crash.signature}:{crash.surface_id}:{crash.seed_id}:{crash.crash_id}"
            accumulator = self._crash_accumulators.get(key)
            if accumulator is None:
                accumulator = _CrashAccumulator(
                    signature=crash.signature,
                    lane=crash.lane,
                    surface_id=crash.surface_id,
                    seed_id=crash.seed_id,
                    crash_id=crash.crash_id,
                    payload=crash.payload,
                    metadata=dict(crash.metadata),
                )
                self._crash_accumulators[key] = accumulator
            accumulator.observe(crash, tick)
        return _TickDelta(
            cases=1,
            crashes=crash_count,
            new_edges=new_edges,
            cost_usd_micro=result.cost_usd_micro,
            elapsed_ms=result.elapsed_ms,
        )

    def _surface_for_seed(self, progress: LaneProgress, seed: CorpusSeedView) -> str:
        metadata = seed.metadata.get("surface_id")
        if isinstance(metadata, str) and metadata:
            return metadata
        if len(progress.surface_ids) == 1:
            return progress.surface_ids[0]
        return progress.lane

    def _append_tick_record(self, progress: LaneProgress, tick: int, delta: _TickDelta) -> None:
        progress.recent.append(
            LaneTickRecord(
                tick=tick,
                cases=delta.cases,
                crashes=delta.crashes,
                new_edges=delta.new_edges,
                cost_usd_micro=delta.cost_usd_micro,
                elapsed_ms=delta.elapsed_ms,
                errors=delta.errors,
            )
        )
        if len(progress.recent) > self._policy.yield_window:
            del progress.recent[: len(progress.recent) - self._policy.yield_window]

    def _schedule_seed(self, tick: int, lane: str) -> int:
        digest = sha256_hex(f"{self._namespace}:{lane}:{tick}".encode())
        return int(digest[:16], 16) % _MAX_INT

    def _wall_exceeded(self, start: float, max_wall_ms: int | None) -> bool:
        if max_wall_ms is None:
            return False
        return (self._clock() - start) * 1000.0 >= max_wall_ms

    # ------------------------------------------------------------------ ledger state

    async def _load_or_create_state(
        self,
        *,
        campaign_id: str,
        run_id: str,
        budget: CampaignBudget,
        surfaces: tuple[CampaignSurface, ...],
        lanes: dict[str, LaneProgress],
        ticks: int,
        created: int,
    ) -> tuple[str, int, int]:
        found = self._find_state(campaign_id)
        if found is None:
            work_order_id = self._work_order_id(campaign_id)
            initial_payload = self._state_payload(
                campaign_id=campaign_id,
                run_id=run_id,
                status="running",
                stop_reason="max_ticks",
                ticks=ticks,
                budget=budget,
                surfaces=surfaces,
                lanes=lanes,
                claim_ids=(),
            )
            await self._ledger.enqueue_work_order(
                action=WORK_ORDER_ACTION,
                unit=self._unit,
                ev_cost=0.0,
                state=WORK_ORDER_STATE,
                payload_json=initial_payload,
                work_order_id=work_order_id,
                created=created,
            )
            return work_order_id, created, created
        row, existing_payload = found
        # Resume only same-shape campaigns; a changed surface/budget plan starts fresh state.
        if existing_payload.get("run_id") != run_id or existing_payload.get("budget") != budget.to_dict():
            raise FormatFail("campaign_id already exists with different run_id or budget")
        created_value = row.get("created")
        if isinstance(created_value, bool) or not isinstance(created_value, int):
            raise FormatFail("work_order.created must be an integer")
        return str(row["id"]), created_value, created

    async def _save_state(
        self,
        *,
        campaign_id: str,
        run_id: str,
        status: str,
        stop_reason: str,
        ticks: int,
        budget: CampaignBudget,
        surfaces: tuple[CampaignSurface, ...],
        lanes: Mapping[str, LaneProgress],
        claim_ids: tuple[str, ...],
        created: int,
        work_order_id: str,
    ) -> int:
        payload = self._state_payload(
            campaign_id=campaign_id,
            run_id=run_id,
            status=status,
            stop_reason=stop_reason,
            ticks=ticks,
            budget=budget,
            surfaces=surfaces,
            lanes=lanes,
            claim_ids=claim_ids,
        )
        await self._ledger.update_work_order_state(
            work_order_id,
            WORK_ORDER_STATE,
            payload_json=payload,
        )
        updated = now_ms()
        if updated <= created:
            updated = created + 1
        return updated

    def _find_state(self, campaign_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        rows = self._ledger.work_orders_for_unit(self._unit)
        matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for row in rows:
            try:
                payload = json.loads(str(row.get("payload_json") or ""))
            except json.JSONDecodeError as exc:
                raise FormatFail(f"corrupt campaign state payload: {exc}") from exc
            if not isinstance(payload, dict):
                raise FormatFail("campaign state payload must be an object")
            data = cast(dict[str, Any], payload)
            if data.get("store") != STORE_KIND or data.get("campaign_id") != campaign_id:
                continue
            matches.append((row, data))
        if len(matches) > 1:
            raise FormatFail(f"multiple campaign state rows for {campaign_id}")
        return matches[0] if matches else None

    @staticmethod
    def _work_order_id(campaign_id: str) -> str:
        return f"campaign-state-{campaign_id}"

    def _state_payload(
        self,
        *,
        campaign_id: str,
        run_id: str,
        status: str,
        stop_reason: str,
        ticks: int,
        budget: CampaignBudget,
        surfaces: tuple[CampaignSurface, ...],
        lanes: Mapping[str, LaneProgress],
        claim_ids: tuple[str, ...],
    ) -> str:
        payload = {
            "store": STORE_KIND,
            "namespace": self._namespace,
            "campaign_id": campaign_id,
            "run_id": run_id,
            "status": status,
            "stop_reason": stop_reason,
            "ticks": ticks,
            "budget": budget.to_dict(),
            "policy": self._policy.to_dict(),
            "surfaces": [
                {
                    "surface_id": surface.surface_id,
                    "lane": surface.lane,
                    "score": surface.score,
                    "seed_ids": [seed.seed_id for seed in surface.seeds],
                    "metadata": dict(surface.metadata),
                }
                for surface in surfaces
            ],
            "lanes": [
                lanes[name].to_dict(yield_window=self._policy.yield_window)
                for name in sorted(lanes)
            ],
            "claim_ids": list(claim_ids),
        }
        return _json_dumps(payload, "campaign_state")

    # ------------------------------------------------------------------ claims

    async def _emit_claims(
        self,
        *,
        campaign_id: str,
        run_id: str,
        status: str,
        stop_reason: str,
        budget: CampaignBudget,
        lanes: Mapping[str, LaneProgress],
        ticks: int,
        created: int,
    ) -> tuple[str, ...]:
        claim_ids: list[str] = []
        aggregates = sorted(
            (accumulator.aggregate() for accumulator in self._crash_accumulators.values()),
            key=lambda item: item.signature,
        )
        crash_claim_ids: list[str] = []
        for aggregate in aggregates:
            value = aggregate.value_dict()
            value["campaign_id"] = campaign_id
            claim_id = await self._create_claim_once(
                claim_id_seed=f"crash:{campaign_id}:{aggregate.signature}",
                value=value,
                artifact_kind="campaign_crash",
                artifact_data=aggregate.payload or _json_dumps(value, "campaign_crash").encode("utf-8"),
                dedup_suffix=f"crash:{campaign_id}:{aggregate.signature}",
                created=created,
            )
            crash_claim_ids.append(claim_id)
            claim_ids.append(claim_id)
        summary_value = {
            "record_kind": "campaign_summary",
            "campaign_id": campaign_id,
            "namespace": self._namespace,
            "run_id": run_id,
            "status": status,
            "stop_reason": stop_reason,
            "ticks": ticks,
            "budget": budget.to_dict(),
            "policy": self._policy.to_dict(),
            "totals": self._totals(tuple(lanes[name] for name in sorted(lanes)), ticks),
            "lanes": [
                lanes[name].to_dict(yield_window=self._policy.yield_window)
                for name in sorted(lanes)
            ],
            "crash_claim_ids": crash_claim_ids,
            "crash_signatures": [aggregate.signature for aggregate in aggregates],
        }
        summary_id = await self._create_claim_once(
            claim_id_seed=f"summary:{campaign_id}",
            value=summary_value,
            artifact_kind="campaign_summary",
            artifact_data=_json_dumps(summary_value, "campaign_summary").encode("utf-8"),
            dedup_suffix=f"summary:{campaign_id}",
            created=created,
        )
        claim_ids.append(summary_id)
        return tuple(claim_ids)

    async def _create_claim_once(
        self,
        *,
        claim_id_seed: str,
        value: Mapping[str, Any],
        artifact_kind: str,
        artifact_data: bytes,
        dedup_suffix: str,
        created: int,
    ) -> str:
        value_json = _json_dumps(value, "claim_value")
        digest = sha256_hex(value_json.encode("utf-8"))[:24]
        claim_id = f"camp_{sha256_hex(claim_id_seed.encode('utf-8'))[:24]}_{digest}"
        dedup = dedup_key("campaign", self._namespace, dedup_suffix)
        existing = self._ledger.claim_by_dedup(dedup)
        if existing is not None:
            return str(existing["id"])
        artifact = ClaimArtifactInput(
            artifact=ArtifactInput(kind=artifact_kind, data=artifact_data, ttl_class="run"),
            role="evidence",
        )
        await self._ledger.create_claim(
            ClaimInput(
                claim_id=claim_id,
                type="bug_class",
                value_json=value_json,
                confidence=1.0,
                dedup_key=dedup,
                created=created,
                artifacts=(artifact,),
            )
        )
        return claim_id

    @staticmethod
    def _totals(lanes: tuple[LaneProgress, ...], ticks: int) -> dict[str, int]:
        return {
            "ticks": ticks,
            "cases": sum(lane.cases for lane in lanes),
            "crashes": sum(lane.crashes for lane in lanes),
            "errors": sum(lane.errors for lane in lanes),
            "cost_usd_micro": sum(lane.cost_usd_micro for lane in lanes),
            "elapsed_ms": sum(lane.elapsed_ms for lane in lanes),
            "coverage_edges": sum(len(lane.covered_edge_ids) for lane in lanes),
            "new_edges": sum(lane.new_edges for lane in lanes),
        }

    @staticmethod
    def _error_text(exc: BaseException) -> str:
        text = f"{type(exc).__name__}: {exc}"
        text = "".join(ch if ch == "\n" or ch == "\t" or ord(ch) >= 32 else "?" for ch in text)
        return text[:_MAX_ERROR_LEN]


_NAMESPACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _require_campaign_id(value: str) -> str:
    return _require_str(value, "campaign_id", max_length=64)


def _require_lane(value: str) -> str:
    return _require_str(value, "lane", max_length=128)


def _require_str(value: str, name: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str):
        raise FormatFail(f"{name} must be a string")
    if not value:
        raise FormatFail(f"{name} must be non-empty")
    if len(value) > max_length:
        raise FormatFail(f"{name} exceeds {max_length} chars")
    if _CONTROL_RE.search(value):
        raise FormatFail(f"{name} contains control characters")
    return value


def _require_int(value: int, name: str, *, minimum: int = 0, maximum: int = _MAX_INT) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise FormatFail(f"{name} must be in [{minimum}, {maximum}]")
    return value


def _optional_int(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    return _require_int(value, name, minimum=0)


def _require_finite_float(
    value: float,
    name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise FormatFail(f"{name} must be finite")
    if minimum is not None and result < minimum:
        raise FormatFail(f"{name} must be >= {minimum}")
    if maximum is not None and result > maximum:
        raise FormatFail(f"{name} must be <= {maximum}")
    return result


def _validate_metadata(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatFail(f"{name} must be a mapping")
    data = dict(value)
    try:
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise FormatFail(f"{name} must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
        raise FormatFail(f"{name} exceeds {_MAX_METADATA_BYTES} bytes")
    return data


def _json_dumps(payload: Mapping[str, Any], name: str) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise FormatFail(f"{name} must be JSON-serializable") from exc
