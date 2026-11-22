"""Tests for the fuzzing campaign orchestrator (ra.campaign)."""

from __future__ import annotations

import json
import math
import random
from collections import Counter
from collections.abc import Callable
from typing import Any

import pytest

import ra.campaign as campaign_module
from ra.campaign import (
    CampaignBudget,
    CampaignCrash,
    CampaignOrchestrator,
    CampaignResult,
    CampaignSurface,
    LaneProgress,
    LaneTickRecord,
    LaneTickResult,
    RebalancePolicy,
)
from ra.corpus import CorpusSeedSpec, CorpusSeedView
from ra.errors import FormatFail
from ra.ledger import Ledger
from ra.ledger.ids import now_ms
from tests.conftest import run


def make_spec(
    seed_id: str,
    lane: str,
    edges: Any = (),
    *,
    surface_id: str | None = None,
) -> CorpusSeedSpec:
    metadata: dict[str, Any] = {}
    if surface_id is not None:
        metadata["surface_id"] = surface_id
    return CorpusSeedSpec(seed_id=seed_id, lane=lane, edges=edges, metadata=metadata)


def make_surface(
    surface_id: str,
    lane: str,
    score: float,
    seed_ids: Any = (),
    *,
    edges: Any = (),
) -> CampaignSurface:
    seeds = tuple(make_spec(seed_id, lane, edges, surface_id=surface_id) for seed_id in seed_ids)
    return CampaignSurface(surface_id=surface_id, lane=lane, score=score, seeds=seeds)


class RecordingRunner:
    def __init__(
        self,
        result: LaneTickResult | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.result = result or LaneTickResult()
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def run_seed(
        self,
        lane: str,
        seed: CorpusSeedView,
        *,
        tick: int,
        case_index: int,
    ) -> LaneTickResult:
        self.calls.append(
            {"lane": lane, "seed_id": seed.seed_id, "tick": tick, "case_index": case_index}
        )
        if self.error is not None:
            raise self.error
        return self.result


class FunctionRunner:
    def __init__(self, fn: Callable[[str, CorpusSeedView, int, int], LaneTickResult]) -> None:
        self.fn = fn
        self.calls: list[dict[str, Any]] = []

    async def run_seed(
        self,
        lane: str,
        seed: CorpusSeedView,
        *,
        tick: int,
        case_index: int,
    ) -> LaneTickResult:
        self.calls.append(
            {"lane": lane, "seed_id": seed.seed_id, "tick": tick, "case_index": case_index}
        )
        return self.fn(lane, seed, tick, case_index)


def test_campaign_models_validate_inputs():
    make_spec("s1", "lane-a")
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="", lane="lane-a", score=1.0)
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="bad\x00lane", score=1.0)
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="lane-a", score=math.nan)
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="lane-a", score=1.0, seeds="bad")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="lane-a", score=1.0, seeds=(object(),))  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        CampaignSurface(
            surface_id="s", lane="lane-a", score=1.0, seeds=(make_spec("s1", "lane-b"),)
        )
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="lane-a", score=1.0, metadata={"x": object()})

    for kwargs in (
        {"max_ticks": 0},
        {"max_ticks": True},
        {"cases_per_tick": 0},
        {"max_cases": 0},
        {"max_cost_usd_micro": -1},
        {"max_wall_ms": "1"},
    ):
        with pytest.raises(FormatFail):
            CampaignBudget(**kwargs)  # type: ignore[arg-type]
    assert CampaignBudget(max_ticks=2, cases_per_tick=3).to_dict() == {
        "max_ticks": 2,
        "cases_per_tick": 3,
        "max_cases": None,
        "max_cost_usd_micro": None,
        "max_wall_ms": None,
    }

    for kwargs in (
        {"alpha": -0.1},
        {"alpha": 1.1},
        {"yield_window": 0},
        {"crash_weight": math.inf},
        {"edge_scale": 0.0},
    ):
        with pytest.raises(FormatFail):
            RebalancePolicy(**kwargs)  # type: ignore[arg-type]
    assert RebalancePolicy(alpha=0.25).to_dict()["alpha"] == 0.25

    with pytest.raises(FormatFail):
        LaneTickResult(covered_edges="e1")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        LaneTickResult(covered_edges=1)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        LaneTickResult(covered_edges=("",))
    with pytest.raises(FormatFail):
        LaneTickResult(crashes="bad")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        LaneTickResult(crashes=(object(),))  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        LaneTickResult(cost_usd_micro=-1)
    with pytest.raises(FormatFail):
        LaneTickResult(elapsed_ms=-1)

    crash = CampaignCrash(
        crash_id="c1",
        signature="sig",
        lane="lane-a",
        surface_id="surf-a",
        seed_id="s1",
    )
    assert crash.payload == b"" and crash.metadata == {}
    for kwargs in (
        {"crash_id": ""},
        {"signature": "x" * 129},
        {"lane": "bad\x00lane"},
        {"surface_id": ""},
        {"seed_id": ""},
        {"payload": "not-bytes"},
        {"metadata": {"x": object()}},
    ):
        base = {
            "crash_id": "c1",
            "signature": "sig",
            "lane": "lane-a",
            "surface_id": "surf-a",
            "seed_id": "s1",
        }
        base.update(kwargs)
        with pytest.raises(FormatFail):
            CampaignCrash(**base)  # type: ignore[arg-type]

    for kwargs in (
        {"tick": -1},
        {"cases": -1},
        {"crashes": -1},
        {"new_edges": -1},
        {"cost_usd_micro": -1},
        {"elapsed_ms": -1},
        {"errors": -1},
    ):
        base = {"tick": 0, "cases": 1, "crashes": 0, "new_edges": 0, "cost_usd_micro": 0, "elapsed_ms": 0, "errors": 0}
        base.update(kwargs)
        with pytest.raises(FormatFail):
            LaneTickRecord(**base)  # type: ignore[arg-type]
    assert LaneTickRecord(tick=1, cases=1, crashes=0, new_edges=2, cost_usd_micro=3, elapsed_ms=4, errors=0).to_dict()["new_edges"] == 2


def test_orchestrator_rejects_bad_construction():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            for bad in ("", "-lead", "a" * 64, "has space", 1, None):
                with pytest.raises(FormatFail):
                    CampaignOrchestrator(ledger, namespace=bad)  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                CampaignOrchestrator(ledger, corpus=object())  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                CampaignOrchestrator(ledger, policy=object())  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                CampaignOrchestrator(ledger, clock=1)  # type: ignore[arg-type]
            ok = CampaignOrchestrator(ledger, namespace="Campaign-1", clock=lambda: 0.0)
            assert ok.policy.alpha == RebalancePolicy().alpha
        finally:
            await ledger.close()

    run(body())


def test_run_allocates_proportional_to_rank_scores():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (
                make_surface("surf-a", "lane-a", 3.0, ["a1", "a2", "a3"]),
                make_surface("surf-b", "lane-b", 1.0, ["b1"]),
            )
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger, policy=RebalancePolicy(alpha=0.0))
            result = await orch.run(
                "camp-alloc",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=4, max_cases=4),
                runner=runner,
                created=1000,
            )
            counts = Counter(call["lane"] for call in runner.calls)
            assert counts == {"lane-a": 3, "lane-b": 1}
            assert result.cases == 4
            assert result.ticks == 1
            assert result.status == "complete"
            assert result.stop_reason == "max_ticks"
            assert result.crashes == 0 and result.errors == 0
            assert len(result.claim_ids) == 1
            claim = ledger.get_claim(result.claim_ids[0])
            assert claim is not None
            value = json.loads(str(claim["value_json"]))
            assert value["record_kind"] == "campaign_summary"
            assert value["totals"]["cases"] == 4
            work_order = ledger.get_work_order(result.state_work_order_id)
            assert work_order is not None
            payload = json.loads(str(work_order["payload_json"]))
            assert payload["store"] == "ra.campaign.orchestrator.v1"
            assert payload["campaign_id"] == "camp-alloc"
            assert payload["status"] == "complete"
            assert payload["claim_ids"] == list(result.claim_ids)
            assert orch.corpus.stats()["active"] == 4
        finally:
            await ledger.close()

    run(body())


def test_run_records_coverage_crashes_and_claims():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            def fn(lane: str, seed: CorpusSeedView, tick: int, case_index: int) -> LaneTickResult:
                crash = CampaignCrash(
                    crash_id="crash-1",
                    signature="sig-1",
                    lane=lane,
                    surface_id="surf-a" if lane == "lane-a" else "surf-b",
                    seed_id=seed.seed_id,
                    payload=b"payload",
                    metadata={"tick": tick},
                )
                return LaneTickResult(
                    covered_edges=[f"{seed.seed_id}-edge"],
                    crashes=(crash,),
                    cost_usd_micro=10,
                    elapsed_ms=2,
                )

            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = FunctionRunner(fn)
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-crash",
                surfaces,
                CampaignBudget(max_ticks=2, cases_per_tick=1),
                runner=runner,
                created=1000,
            )
            assert result.cases == 2
            assert result.crashes == 2
            assert result.coverage_edges == 1
            assert result.new_edges == 1
            assert result.cost_usd_micro == 20
            assert result.elapsed_ms == 4
            assert len(result.claim_ids) == 2
            crash_claim = ledger.get_claim(result.claim_ids[0])
            assert crash_claim is not None
            crash_value = json.loads(str(crash_claim["value_json"]))
            assert crash_value["record_kind"] == "campaign_crash"
            assert crash_value["count"] == 2
            assert crash_value["first_tick"] == 0
            assert crash_value["last_tick"] == 1
            assert crash_value["campaign_id"] == "camp-crash"
            summary_claim = ledger.get_claim(result.claim_ids[1])
            assert summary_claim is not None
            summary_value = json.loads(str(summary_claim["value_json"]))
            assert summary_value["record_kind"] == "campaign_summary"
            assert summary_value["totals"]["crashes"] == 2
            assert summary_value["crash_claim_ids"] == [result.claim_ids[0]]
            view = orch.corpus.active_seeds(lane="lane-a")[0]
            assert view.runs == 2
            assert view.covered_edges == 1
            assert view.last_run_id == "run_camp-crash"
        finally:
            await ledger.close()

    run(body())


def test_run_isolates_lane_failures_and_continues():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            def fn(lane: str, seed: CorpusSeedView, tick: int, case_index: int) -> LaneTickResult:
                if seed.seed_id == "bad":
                    raise RuntimeError("boom")
                return LaneTickResult(covered_edges=["good-edge"], cost_usd_micro=7)

            surfaces = (
                make_surface("surf-a", "lane-a", 1.0, ["bad", "good"]),
            )
            runner = FunctionRunner(fn)
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-fail",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=2, max_cases=2),
                runner=runner,
                created=1000,
            )
            assert result.cases == 2
            assert result.errors == 1
            assert result.crashes == 0
            assert result.coverage_edges == 1
            lane = result.lanes[0]
            assert lane.cases == 2
            assert lane.errors == 1
            assert lane.last_error is not None and lane.last_error.startswith("RuntimeError: boom")
            assert len(runner.calls) == 2
            work_order = ledger.get_work_order(result.state_work_order_id)
            assert work_order is not None
            payload = json.loads(str(work_order["payload_json"]))
            assert payload["lanes"][0]["errors"] == 1
            assert payload["lanes"][0]["last_error"].startswith("RuntimeError: boom")
            by_seed = {view.seed_id: view for view in orch.corpus.active_seeds(lane="lane-a")}
            assert by_seed["good"].runs == 1
            assert by_seed["bad"].runs == 0
        finally:
            await ledger.close()

    run(body())


def test_run_respects_max_cases_budget():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-cases",
                surfaces,
                CampaignBudget(max_ticks=5, cases_per_tick=2, max_cases=3),
                runner=runner,
                created=1000,
            )
            assert result.cases == 3
            assert result.ticks == 3
            assert result.status == "budget_exhausted"
            assert result.stop_reason == "max_cases"
            assert len(runner.calls) == 3
        finally:
            await ledger.close()

    run(body())


def test_run_respects_cost_budget():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1", "a2", "a3", "a4"]),)
            runner = RecordingRunner(LaneTickResult(cost_usd_micro=100))
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-cost",
                surfaces,
                CampaignBudget(
                    max_ticks=1,
                    cases_per_tick=4,
                    max_cases=4,
                    max_cost_usd_micro=200,
                ),
                runner=runner,
                created=1000,
            )
            assert result.cases == 2
            assert result.cost_usd_micro == 200
            assert result.status == "budget_exhausted"
            assert result.stop_reason == "max_cost_usd_micro"
            assert len(runner.calls) == 2
        finally:
            await ledger.close()

    run(body())


def test_run_respects_wall_budget():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            now = 0.0

            class Clock:
                def __call__(self) -> float:
                    return now

            def fn(lane: str, seed: CorpusSeedView, tick: int, case_index: int) -> LaneTickResult:
                nonlocal now
                now += 0.2
                return LaneTickResult()

            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1", "a2"]),)
            runner = FunctionRunner(fn)
            orch = CampaignOrchestrator(ledger, clock=Clock())
            result = await orch.run(
                "camp-wall",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=2, max_cases=2, max_wall_ms=100),
                runner=runner,
                created=1000,
            )
            assert result.cases == 1
            assert result.status == "budget_exhausted"
            assert result.stop_reason == "max_wall_ms"
            assert len(runner.calls) == 1
        finally:
            await ledger.close()

    run(body())


def test_run_rebalances_toward_high_yield_lane():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            def fn(lane: str, seed: CorpusSeedView, tick: int, case_index: int) -> LaneTickResult:
                if lane == "lane-b":
                    return LaneTickResult()
                crash = CampaignCrash(
                    crash_id="crash-1",
                    signature="sig-a",
                    lane=lane,
                    surface_id="surf-a",
                    seed_id=seed.seed_id,
                )
                return LaneTickResult(crashes=(crash,))

            surfaces = (
                make_surface("surf-a", "lane-a", 1.0, ["a1", "a2"]),
                make_surface("surf-b", "lane-b", 1.0, ["b1", "b2"]),
            )
            runner = FunctionRunner(fn)
            orch = CampaignOrchestrator(
                ledger,
                policy=RebalancePolicy(alpha=1.0, crash_weight=10.0),
            )
            result = await orch.run(
                "camp-rebalance",
                surfaces,
                CampaignBudget(max_ticks=2, cases_per_tick=2),
                runner=runner,
                created=1000,
            )
            by_tick: dict[int, Counter[str]] = {}
            for call in runner.calls:
                by_tick.setdefault(int(call["tick"]), Counter())[str(call["lane"])] += 1
            assert by_tick[0] == Counter({"lane-a": 1, "lane-b": 1})
            assert by_tick[1] == Counter({"lane-a": 2})
            assert result.cases == 4
            assert result.crashes == 3
            assert result.status == "complete"
        finally:
            await ledger.close()

    run(body())


def test_run_without_seeds_terminates_no_work():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (CampaignSurface(surface_id="surf-a", lane="lane-a", score=1.0),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-empty",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=1),
                runner=runner,
                created=1000,
            )
            assert result.cases == 0
            assert result.ticks == 0
            assert result.status == "no_work"
            assert result.stop_reason == "no_active_seeds"
            assert len(runner.calls) == 0
            assert len(result.claim_ids) == 1
            claim = ledger.get_claim(result.claim_ids[0])
            assert claim is not None
            value = json.loads(str(claim["value_json"]))
            assert value["totals"]["cases"] == 0
        finally:
            await ledger.close()

    run(body())


def test_run_rejects_invalid_campaign_inputs():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            orch = CampaignOrchestrator(ledger)
            surface = make_surface("surf-a", "lane-a", 1.0, ["a1"])
            budget = CampaignBudget(max_ticks=1, cases_per_tick=1)
            with pytest.raises(FormatFail):
                await orch.run("", [surface], budget, runner=RecordingRunner())
            with pytest.raises(FormatFail):
                await orch.run("camp", [], budget, runner=RecordingRunner())
            with pytest.raises(FormatFail):
                await orch.run("camp", "bad", budget, runner=RecordingRunner())  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                await orch.run("camp", [object()], budget, runner=RecordingRunner())  # type: ignore[list-item]
            with pytest.raises(FormatFail):
                await orch.run("camp", [surface], object(), runner=RecordingRunner())  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                await orch.run("camp", [surface], budget, runner=None)  # type: ignore[arg-type]
            duplicate_surface = make_surface("surf-a", "lane-b", 1.0, ["b1"])
            with pytest.raises(FormatFail):
                await orch.run("camp", [surface, duplicate_surface], budget, runner=RecordingRunner())
            duplicate_seed_surface = make_surface("surf-b", "lane-b", 1.0, ["a1"])
            with pytest.raises(FormatFail):
                await orch.run("camp", [surface, duplicate_seed_surface], budget, runner=RecordingRunner())
            with pytest.raises(FormatFail):
                await orch.run(
                    "camp",
                    [surface] * 257,
                    budget,
                    runner=RecordingRunner(),
                )
        finally:
            await ledger.close()

    run(body())


def test_allocation_properties_are_deterministic_and_bounded():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            rng = random.Random(20261122)
            orch = CampaignOrchestrator(ledger, policy=RebalancePolicy(alpha=0.5))
            for _ in range(200):
                lane_count = rng.randint(1, 5)
                lanes = {
                    f"lane-{index}": LaneProgress(
                        lane=f"lane-{index}",
                        score=rng.random() * 10.0,
                        surface_ids=(f"surf-{index}",),
                    )
                    for index in range(lane_count)
                }
                cases = rng.randint(1, 25)
                first = orch._allocate(lanes, cases)
                second = orch._allocate(lanes, cases)
                assert first == second
                assert sum(first.values()) == cases
                assert all(count >= 0 for count in first.values())
                assert set(first) <= set(lanes)
                assert all(lanes[name].cases == 0 for name in lanes)
            even = {
                "a": LaneProgress(lane="a", score=1.0, surface_ids=("s",)),
                "b": LaneProgress(lane="b", score=1.0, surface_ids=("s",)),
            }
            allocation = orch._allocate(even, 5)
            assert sorted(allocation.values()) == [2, 3]
        finally:
            await ledger.close()

    run(body())


def test_lane_yield_uses_window_and_diminishing_returns():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            orch = CampaignOrchestrator(
                ledger,
                policy=RebalancePolicy(alpha=1.0, yield_window=2, crash_weight=2.0, edge_scale=2.0),
            )
            lane = LaneProgress(lane="lane-a", score=1.0, surface_ids=("surf-a",))
            assert orch._lane_yield(lane) == 0.0
            lane.recent.extend(
                [
                    LaneTickRecord(tick=0, cases=1, crashes=0, new_edges=1, cost_usd_micro=0, elapsed_ms=0, errors=0),
                    LaneTickRecord(tick=1, cases=1, crashes=1, new_edges=0, cost_usd_micro=0, elapsed_ms=0, errors=0),
                    LaneTickRecord(tick=2, cases=1, crashes=0, new_edges=0, cost_usd_micro=0, elapsed_ms=0, errors=0),
                    LaneTickRecord(tick=3, cases=1, crashes=0, new_edges=0, cost_usd_micro=0, elapsed_ms=0, errors=0),
                ]
            )
            windowed = orch._lane_yield(lane)
            assert windowed == 0.0
            full_window = CampaignOrchestrator(
                ledger,
                policy=RebalancePolicy(alpha=1.0, yield_window=3, crash_weight=2.0, edge_scale=1000.0),
            )._lane_yield(lane)
            assert full_window > 0.0
            lane.recent.clear()
            lane.cases = 0
            lane.crashes = 0
            lane.errors = 0
            lane.cost_usd_micro = 0
            lane.elapsed_ms = 0
            lane.new_edges = 0
            lane.last_new_edges = 0
            lane.covered_edge_ids.clear()
            lane.last_error = "x" * 300
            lane.to_dict(yield_window=1)
        finally:
            await ledger.close()

    run(body())


def test_result_summary_and_lane_progress_dicts():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-summary",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=1, max_cases=1),
                runner=runner,
                created=1000,
            )
            summary = result.summary_dict()
            assert summary["campaign_id"] == "camp-summary"
            assert summary["cases"] == 1
            assert summary["lane_count"] == 1
            assert summary["claim_count"] == 1
            lane_dict = result.lanes[0].to_dict(yield_window=1)
            assert lane_dict["lane"] == "lane-a"
            assert lane_dict["cases"] == 1
            assert lane_dict["coverage_edges"] == 0
            assert isinstance(result, CampaignResult)
        finally:
            await ledger.close()

    run(body())


def test_run_wall_budget_zero_stops_before_first_tick():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-wall0",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=1, max_wall_ms=0),
                runner=runner,
                created=1000,
            )
            assert result.cases == 0 and result.ticks == 0
            assert result.status == "budget_exhausted"
            assert result.stop_reason == "max_wall_ms"
            assert runner.calls == []
        finally:
            await ledger.close()

    run(body())


def test_run_cost_budget_zero_stops_before_first_case():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-cost0",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=1, max_cases=1, max_cost_usd_micro=0),
                runner=runner,
                created=1000,
            )
            assert result.cases == 0 and result.cost_usd_micro == 0
            assert result.status == "budget_exhausted"
            assert result.stop_reason == "max_cost_usd_micro"
            assert runner.calls == []
        finally:
            await ledger.close()

    run(body())


def test_run_aggregates_multiple_surfaces_per_lane():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (
                make_surface("s1", "lane-a", 1.0, ["a1"]),
                make_surface("s2", "lane-a", 2.0, ["a2"]),
                make_surface("s3", "lane-b", 1.0, ["b1"]),
            )
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger, policy=RebalancePolicy(alpha=0.0))
            result = await orch.run(
                "camp-multi",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=3, max_cases=3),
                runner=runner,
                created=1000,
            )
            counts = Counter(call["lane"] for call in runner.calls)
            assert counts == {"lane-a": 2, "lane-b": 1}
            lane_a = next(lane for lane in result.lanes if lane.lane == "lane-a")
            assert lane_a.score == 3.0
            assert lane_a.surface_ids == ("s1", "s2")
        finally:
            await ledger.close()

    run(body())


def test_run_trims_recent_window():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger, policy=RebalancePolicy(yield_window=1))
            result = await orch.run(
                "camp-window",
                surfaces,
                CampaignBudget(max_ticks=3, cases_per_tick=1, max_cases=3),
                runner=runner,
                created=1000,
            )
            assert result.cases == 3
            assert len(result.lanes[0].recent) == 1
            work_order = ledger.get_work_order(result.state_work_order_id)
            assert work_order is not None
            payload = json.loads(str(work_order["payload_json"]))
            assert len(payload["lanes"][0]["recent"]) == 1
        finally:
            await ledger.close()

    run(body())


def test_run_reuses_existing_campaign_state_and_rejects_mismatched_budget():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            await ledger.enqueue_work_order(
                action="park",
                unit="ra.campaign.default",
                ev_cost=0.0,
                state="parked",
                payload_json=json.dumps({"store": "other.store", "campaign_id": "camp-reuse"}),
                work_order_id="other-state",
                created=1,
            )
            budget = CampaignBudget(max_ticks=1, cases_per_tick=1, max_cases=1)
            first = await orch.run("camp-reuse", surfaces, budget, runner=runner, created=1000)
            second = await orch.run("camp-reuse", surfaces, budget, runner=runner, created=1000)
            assert second.state_work_order_id == first.state_work_order_id
            assert second.claim_ids == first.claim_ids
            assert len(ledger.claims_by_type("bug_class", limit=10)) == 1
            with pytest.raises(FormatFail, match="already exists"):
                await orch.run(
                    "camp-reuse",
                    surfaces,
                    CampaignBudget(max_ticks=1, cases_per_tick=1, max_cases=2),
                    runner=runner,
                    created=1000,
                )
        finally:
            await ledger.close()

    run(body())


def test_campaign_state_payload_validation():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            budget = CampaignBudget(max_ticks=1, cases_per_tick=1)
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)

            async def expect_failure(namespace: str, payload_json: str, match: str) -> None:
                await ledger.enqueue_work_order(
                    action="park",
                    unit=f"ra.campaign.{namespace}",
                    ev_cost=0.0,
                    state="parked",
                    payload_json=payload_json,
                    work_order_id=f"bad-{namespace}",
                    created=1,
                )
                orch = CampaignOrchestrator(ledger, namespace=namespace)
                with pytest.raises(FormatFail, match=match):
                    await orch.run(
                        "camp-x", surfaces, budget, runner=RecordingRunner(), created=1000
                    )

            await expect_failure("badjson", "not-json", "corrupt campaign state payload")
            await expect_failure("baddict", "[]", "must be an object")
            for index in range(2):
                await ledger.enqueue_work_order(
                    action="park",
                    unit="ra.campaign.multi",
                    ev_cost=0.0,
                    state="parked",
                    payload_json=json.dumps(
                        {"store": "ra.campaign.orchestrator.v1", "campaign_id": "camp-dup"}
                    ),
                    work_order_id=f"dup-{index}",
                    created=1,
                )
            orch = CampaignOrchestrator(ledger, namespace="multi")
            with pytest.raises(FormatFail, match="multiple campaign state rows"):
                await orch.run(
                    "camp-dup", surfaces, budget, runner=RecordingRunner(), created=1000
                )
        finally:
            await ledger.close()

    run(body())


def test_run_isolates_bad_runner_result_and_crash_lane_mismatch():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (
                make_surface("surf-a", "lane-a", 1.0, ["a1"]),
                make_surface("surf-b", "lane-b", 1.0, ["b1"]),
            )

            def fn(lane: str, seed: CorpusSeedView, tick: int, case_index: int) -> LaneTickResult:
                if lane == "lane-a":
                    return object()  # type: ignore[return-value]
                return LaneTickResult(
                    crashes=(
                        CampaignCrash(
                            lane="lane-a",
                            signature="sig",
                            surface_id="surf-b",
                            seed_id=seed.seed_id,
                            crash_id="crash-1",
                        ),
                    )
                )

            runner = FunctionRunner(fn)
            orch = CampaignOrchestrator(ledger)
            result = await orch.run(
                "camp-bad",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=2, max_cases=2),
                runner=runner,
                created=1000,
            )
            assert result.cases == 2 and result.errors == 2
            errors = {lane.lane: lane.last_error for lane in result.lanes}
            assert "runner must return LaneTickResult" in str(errors["lane-a"])
            assert "does not match" in str(errors["lane-b"])
        finally:
            await ledger.close()

    run(body())


def test_campaign_validation_edges():
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="lane-a", score=True)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        RebalancePolicy(alpha="bad")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        CampaignSurface(surface_id="s", lane="lane-a", score=1.0, metadata=[])  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        CampaignSurface(
            surface_id="s",
            lane="lane-a",
            score=1.0,
            metadata={"blob": "x" * 9000},
        )
    with pytest.raises(FormatFail):
        CampaignCrash(
            lane="lane-a",
            signature="sig",
            surface_id="s",
            seed_id="seed",
            crash_id="c",
            metadata="bad",  # type: ignore[arg-type]
        )
    assert campaign_module._json_dumps({"ok": 1}, "ok") == '{"ok":1}'
    with pytest.raises(FormatFail, match="JSON-serializable"):
        campaign_module._json_dumps({"x": object()}, "bad")


def test_run_rejects_surface_and_lane_limits():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            orch = CampaignOrchestrator(ledger)
            budget = CampaignBudget(max_ticks=1, cases_per_tick=1)
            many_surfaces = [
                CampaignSurface(surface_id=f"s{i}", lane="lane-a", score=1.0) for i in range(257)
            ]
            with pytest.raises(FormatFail, match="256 surfaces"):
                await orch.run("camp-many", many_surfaces, budget, runner=RecordingRunner())
            lane_surfaces = [
                CampaignSurface(surface_id=f"s{i}", lane=f"lane-{i}", score=1.0)
                for i in range(65)
            ]
            with pytest.raises(FormatFail, match="64 lanes"):
                await orch.run("camp-lanes", lane_surfaces, budget, runner=RecordingRunner())
        finally:
            await ledger.close()

    run(body())


def test_allocation_zero_score_fallback():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            orch = CampaignOrchestrator(ledger, policy=RebalancePolicy(alpha=1.0))
            lanes = {
                "lane-a": LaneProgress(lane="lane-a", score=0.0, surface_ids=()),
                "lane-b": LaneProgress(lane="lane-b", score=0.0, surface_ids=()),
            }
            assert orch._allocate({}, 1) == {}
            assert orch._allocate(lanes, 0) == {}
            allocation = orch._allocate(lanes, 3)
            assert sum(allocation.values()) == 3
        finally:
            await ledger.close()

    run(body())


def test_lane_yield_zero_case_window():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            orch = CampaignOrchestrator(ledger)
            lane = LaneProgress(lane="lane-a", score=1.0, surface_ids=("surf-a",))
            lane.recent.append(
                LaneTickRecord(tick=0, cases=0, crashes=0, new_edges=0, cost_usd_micro=0, elapsed_ms=0, errors=0)
            )
            assert orch._lane_yield(lane) == 0.0
        finally:
            await ledger.close()

    run(body())


def test_surface_for_seed_fallbacks():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            orch = CampaignOrchestrator(ledger)
            await orch.corpus.register_seed(CorpusSeedSpec(seed_id="raw", lane="lane-a"))
            seed = next(
                view for view in orch.corpus.active_seeds(lane="lane-a") if view.seed_id == "raw"
            )
            single = LaneProgress(lane="lane-a", score=1.0, surface_ids=("only",))
            assert orch._surface_for_seed(single, seed) == "only"
            multi = LaneProgress(lane="lane-a", score=1.0, surface_ids=("s1", "s2"))
            assert orch._surface_for_seed(multi, seed) == "lane-a"
            await orch.corpus.register_seed(
                CorpusSeedSpec(seed_id="meta", lane="lane-a", metadata={"surface_id": "surf-meta"})
            )
            meta_seed = next(
                view for view in orch.corpus.active_seeds(lane="lane-a") if view.seed_id == "meta"
            )
            assert orch._surface_for_seed(multi, meta_seed) == "surf-meta"
        finally:
            await ledger.close()

    run(body())


def test_run_uses_created_floor_for_state_updates():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            surfaces = (make_surface("surf-a", "lane-a", 1.0, ["a1"]),)
            runner = RecordingRunner()
            orch = CampaignOrchestrator(ledger)
            created = now_ms() + 60_000
            result = await orch.run(
                "camp-floor",
                surfaces,
                CampaignBudget(max_ticks=1, cases_per_tick=1, max_cases=1),
                runner=runner,
                created=created,
            )
            assert result.updated == created + 1
        finally:
            await ledger.close()

    run(body())
