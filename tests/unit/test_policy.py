import asyncio
import json
import math
import random
import sys

import pytest

from ra.errors import BudgetGate, FormatFail
from ra.ledger import Ledger
from ra.ledger.operations import LedgerOperation
from ra.policy import (
    ACTION_COST_USD_MICRO,
    SQLITE_INT_MAX,
    Action,
    ActionOutcome,
    ActionResult,
    EVInputs,
    Executor,
    ExecutorCaps,
    LaneAvailability,
    NullActionHandler,
    PolicyEngine,
    StaticEVInputProvider,
    StaticLaneStateProvider,
    WorkOrderCandidate,
    candidates_from_rows,
    ev_score,
    rank,
    shed,
    shed_budget,
)
from ra.policy.actions import parse_action
from tests.conftest import run


def candidate(cid: str, ev: float, created: int = 0, join_live: bool = False) -> WorkOrderCandidate:
    return WorkOrderCandidate(
        id=cid, action="park", unit="u", ev_cost=ev, created=created, join_live=join_live
    )


def payload_of(row: dict) -> dict:
    return json.loads(row["payload_json"] or "{}")


def test_RA_POL_001_closed_action_vocabulary_and_costs():
    assert Action("retarget") is Action.RETARGET
    assert ACTION_COST_USD_MICRO[Action.SPAWN_SUBFACTORY] == 300_000
    with pytest.raises(FormatFail):
        parse_action("rm_rf")


def test_RA_POL_001_plan_rejects_off_vocabulary_before_ledger_write():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            with pytest.raises(FormatFail):
                await engine.plan_action("rm_rf", "u", probability_join=1.0)
            assert ledger.counts()["work_order"] == 0
            assert ledger.counts()["decision"] == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_002_ev_ranking_total_order():
    assert ev_score(0.5, 2.0, 3.0, 1000) == pytest.approx(0.003)
    assert ev_score(0.5, 2.0, 3.0, 0) == pytest.approx(3.0)
    ranked = rank([candidate("b", 1.0, 2), candidate("a", 1.0, 1), candidate("c", 2.0, 3)])
    assert [row.id for row in ranked] == ["c", "a", "b"]


def test_RA_POL_006_shed_never_drops_live_join():
    rows = [candidate("low", 1.0), candidate("live", 0.1, join_live=True), candidate("high", 3.0)]
    kept, dropped = shed(rows, backlog_limit=2)
    assert {row.id for row in dropped} == {"low"}
    assert all(row.id != "live" for row in dropped)
    assert len(kept) == 2


def test_RA_POL_006_shed_budget_validates_limits():
    with pytest.raises(FormatFail):
        shed_budget([], backlog_limit=-1)
    with pytest.raises(FormatFail):
        shed_budget([], cas_bytes_limit=-1)


def test_RA_POL_003_executor_caps_before_side_effect():
    executor = Executor(ExecutorCaps(spend_usd_micro=30_000))
    assert executor.admits(Action.REWEIGHT) is True
    assert executor.record_spend(Action.REWEIGHT) == 10_000
    assert executor.admits(Action.RETARGET) is True
    executor.record_spend(Action.RETARGET)
    assert executor.admits(Action.REWEIGHT) is False
    with pytest.raises(BudgetGate):
        executor.gate(Action.REWEIGHT)
    executor.corpus_rows = executor.caps.corpus_max
    assert executor.admits(Action.SPAWN_SUBFACTORY) is False
    executor.escalations = executor.caps.escalations
    assert executor.admits(Action.ESCALATE_MODEL) is False


def test_RA_POL_003_dispatch_budget_gate_has_no_side_effects():
    async def body():
        ledger = await Ledger.open(":memory:")
        calls = []

        async def handler(order):
            calls.append(order)
            return ActionResult()

        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=10_000),
                handlers={Action.RETARGET: handler},
            )
            wid = await engine.plan_action("retarget", "unit", probability_join=0.5)
            report = await engine.dispatch_tick(limit=10)
            assert report.dispatched == 0
            assert report.refusals == (wid,)
            assert calls == []
            row = ledger.get_work_order(wid)
            assert row is not None and row["state"] == "ready"
            assert "spend_cap" in payload_of(row)["last_budget_gate"]
            decisions = ledger.decision_rows(wo_id=wid)
            assert [row_["trigger_metric"] for row_ in decisions] == ["policy", "budget_gate"]
            gate = decisions[-1]
            assert gate["expected"] == "BUDGET_GATE"
            assert gate["spent_usd_micro"] == 0
            assert gate["unit"] == "unit"
            assert ledger.spent_usd_micro() == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_004_policy_engine_plan_dispatch_and_park():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            wid = await engine.plan_action(
                "retarget", "unit", probability_join=0.5, chain_bonus=2.0, ingress_weight=1.0
            )
            assert ledger.get_work_order(wid)["state"] == "ready"
            dispatched, refusals = await engine.dispatch_ready()
            assert dispatched == 1 and refusals == []
            assert ledger.spent_usd_micro() == ACTION_COST_USD_MICRO[Action.RETARGET]
            for _ in range(3):
                await engine.record_failure("unit")
            wid2 = await engine.plan_action("reweight", "unit", probability_join=0.9)
            assert ledger.get_work_order(wid2)["action"] == "park"
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_004_triple_failure_state_is_persisted(tmp_path):
    async def body():
        path = tmp_path / "ledger.sqlite"
        ledger = await Ledger.open(path)
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            for _ in range(3):
                await engine.record_failure("unit")
        finally:
            await ledger.close()

        again = await Ledger.open(path)
        try:
            engine = PolicyEngine(again, ExecutorCaps(spend_usd_micro=100_000))
            assert await engine.unit_failure_count("unit") == 3
            wid = await engine.plan_action("reweight", "unit", probability_join=0.9)
            row = again.get_work_order(wid)
            assert row is not None
            assert row["action"] == "park"
            assert row["state"] == "parked"
            assert await engine.unit_failure_count("unit") == 3
        finally:
            await again.close()

    run(body())


def test_RA_POL_004_dispatch_handler_failure_isolated_and_counted():
    async def body():
        ledger = await Ledger.open(":memory:")

        async def handler(order):
            raise RuntimeError("boom")

        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=100_000),
                handlers={Action.RETARGET: handler},
            )
            wids = [
                await engine.plan_action("retarget", "unit", probability_join=0.5)
                for _ in range(3)
            ]
            report = await engine.dispatch_tick(limit=10)
            assert report.dispatched == 0
            assert report.refusals == ()
            assert [ledger.get_work_order(wid)["state"] for wid in wids] == ["failed"] * 3
            assert await engine.unit_failure_count("unit") == 3
            wid2 = await engine.plan_action("reweight", "unit", probability_join=0.9)
            row = ledger.get_work_order(wid2)
            assert row is not None and row["action"] == "park" and row["state"] == "parked"
            failures = [
                row
                for row in ledger.decision_rows(unit="unit", limit=20)
                if row["trigger_metric"] == "remedy_failure"
            ]
            assert len(failures) == 3
            assert all(row["expected"] == "retarget" for row in failures)
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_005_budget_gate_zero_ev_rejected():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=1))
            with pytest.raises(FormatFail):
                await engine.plan_action("retarget", "u", probability_join=0.0)
            assert ledger.counts()["work_order"] == 0
            assert ledger.counts()["decision"] == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_006_shed_backlog_drops_lowest_ev_and_keeps_live_join():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=1_000_000, backlog_limit=2, cas_bytes=1 << 40),
            )
            high = await engine.plan_action("park", "unit", probability_join=0.9)
            live = await engine.plan_action(
                "park", "unit", probability_join=0.05, join_live=True
            )
            low = await engine.plan_action("park", "unit", probability_join=0.1)
            lower = await engine.plan_action("park", "unit", probability_join=0.2)
            assert await engine.shed_backlog() == 2
            assert ledger.get_work_order(high)["state"] == "ready"
            assert ledger.get_work_order(live)["state"] == "ready"
            for wid in (low, lower):
                row = ledger.get_work_order(wid)
                assert row is not None and row["state"] == "shed"
                assert payload_of(row)["shed_reason"] == "backlog_budget"
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_006_cas_budget_triggers_shedding():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=1_000_000, backlog_limit=10, cas_bytes=100),
            )
            keep = await engine.plan_action(
                "park", "unit", probability_join=0.9, cas_bytes=80
            )
            drop = await engine.plan_action(
                "park", "unit", probability_join=0.1, cas_bytes=30
            )
            assert await engine.shed_backlog() == 1
            assert ledger.get_work_order(keep)["state"] == "ready"
            assert ledger.get_work_order(drop)["state"] == "shed"
            assert ledger.ready_work_order_cas_bytes() == 80
        finally:
            await ledger.close()

    run(body())


def test_policy_dispatch_lane_busy_requeues_then_dispatches():
    class LaneProvider:
        def __init__(self):
            self.busy = True

        async def availability(self, lane_id):
            return LaneAvailability(
                lane_id=lane_id,
                busy=self.busy,
                reason="device busy" if self.busy else "",
                retry_after_ms=7 if self.busy else 0,
            )

    async def body():
        ledger = await Ledger.open(":memory:")
        provider = LaneProvider()
        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=100_000),
                lane_provider=provider,
            )
            wid = await engine.plan_action(
                "retarget",
                "unit",
                probability_join=0.5,
                lane_id="lane-1",
                requires_lane=True,
            )
            report = await engine.dispatch_tick(limit=5)
            assert report.dispatched == 0
            assert report.requeued == (wid,)
            row = ledger.get_work_order(wid)
            assert row is not None and row["state"] == "ready"
            assert payload_of(row)["requeue_count"] == 1
            assert payload_of(row)["last_lane_reason"] == "device busy"
            provider.busy = False
            report = await engine.dispatch_tick(limit=5)
            assert report.dispatched == 1
            assert ledger.get_work_order(wid)["state"] == "done"
        finally:
            await ledger.close()

    run(body())


def test_policy_decision_records_are_complete():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            wid = await engine.plan_action(
                "retarget",
                "unit",
                probability_join=0.5,
                chain_bonus=2.0,
                ingress_weight=3.0,
                trigger_metric="plan_metric",
                observed=0.25,
                expected="join",
            )
            report = await engine.dispatch_tick(limit=5)
            assert report.dispatched == 1
            rows = ledger.decision_rows(wo_id=wid)
            assert len(rows) == 2
            plan, dispatch = rows
            assert plan["trigger_metric"] == "plan_metric"
            assert plan["observed"] == pytest.approx(0.25)
            assert plan["expected"] == "join"
            assert plan["spent_usd_micro"] == 0
            assert plan["unit"] == "unit"
            assert plan["wo_id"] == wid
            work = ledger.get_work_order(wid)
            assert work is not None
            assert dispatch["trigger_metric"] == "remedy_success"
            assert dispatch["expected"] == "join"
            assert dispatch["spent_usd_micro"] == ACTION_COST_USD_MICRO[Action.RETARGET]
            assert dispatch["observed"] == pytest.approx(float(work["ev_cost"]))
            assert dispatch["unit"] == "unit"
            assert dispatch["wo_id"] == wid
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_dispatch_format_fail_isolated():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ledger.store.apply_batch(
                [
                    LedgerOperation(
                        "enqueue_work_order",
                        {
                            "work_order_id": "wo_bad",
                            "run_id": None,
                            "action": "park",
                            "unit": "unit",
                            "payload_json": "{bad",
                            "ev_cost": 1.0,
                            "state": "ready",
                            "created": 1,
                        },
                        rows=1,
                    )
                ]
            )
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            report = await engine.dispatch_tick(limit=1)
            assert report.dispatched == 0
            assert report.refusals == ("wo_bad",)
            row = ledger.get_work_order("wo_bad")
            assert row is not None and row["state"] == "failed"
            decision = ledger.decision_rows(wo_id="wo_bad")[-1]
            assert decision["trigger_metric"] == "format_fail"
            assert decision["expected"] == "FORMAT_FAIL"
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_dispatch_tick_budget_at_5000_backlog():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            operations = [
                LedgerOperation(
                    "enqueue_work_order",
                    {
                        "work_order_id": f"wo_{index:05d}",
                        "run_id": None,
                        "action": "park",
                        "unit": "load",
                        "payload_json": "{}",
                        "ev_cost": float(5000 - index),
                        "state": "ready",
                        "created": index,
                    },
                    rows=1,
                )
                for index in range(5000)
            ]
            ledger.store.apply_batch(operations)
            # Coverage tracing inflates wall-clock tick cost; keep the budget
            # validation but scale it to the instrumentation overhead.
            tick_budget_ms = 5.0 * (4 if "coverage" in sys.modules else 1)
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=1_000_000),
                tick_budget_ms=tick_budget_ms,
            )
            for _ in range(2):
                await engine.dispatch_tick(limit=64)
            ticks = []
            for _ in range(16):
                report = await engine.dispatch_tick(limit=64)
                ticks.append(report.tick_ms)
                assert report.within_budget
            assert max(ticks) <= engine.tick_budget_ms
            assert ledger.ready_work_order_count() == 5000 - 18 * 64
        finally:
            await ledger.close()

    run(body())


def test_policy_engine_uses_ev_provider_and_success_reset():
    async def body():
        ledger = await Ledger.open(":memory:")
        provider = StaticEVInputProvider(
            EVInputs(probability_join=0.4, chain_bonus=2.0, ingress_weight=1.0)
        )
        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=100_000),
                ev_provider=provider,
            )
            inputs = await engine.inputs_for(Action.RETARGET, "unit", run_id=None)
            assert inputs.probability_join == 0.4
            wid = await engine.plan_action("retarget", "unit")
            row = ledger.get_work_order(wid)
            assert row is not None
            assert payload_of(row)["probability_join"] == 0.4
            assert payload_of(row)["chain_bonus"] == 2.0
            await engine.record_failure("unit")
            await engine.record_failure("unit")
            assert await engine.unit_failure_count("unit") == 2
            await engine.record_success("unit")
            assert await engine.unit_failure_count("unit") == 0
        finally:
            await ledger.close()

    run(body())


def test_policy_static_providers_and_null_handler():
    async def body():
        ev_provider = StaticEVInputProvider(by_unit={"u": EVInputs(probability_join=0.25)})
        assert (await ev_provider.inputs_for(action=Action.RETARGET, unit="u", run_id=None)).probability_join == 0.25
        assert (await ev_provider.inputs_for(action=Action.RETARGET, unit="other", run_id=None)).probability_join == 0.0

        lanes = StaticLaneStateProvider({"busy": LaneAvailability(lane_id="busy", busy=True)})
        assert (await lanes.availability("busy")).busy is True
        assert (await lanes.availability("free")).busy is False

        result = await NullActionHandler()({"ev_cost": 1.5})
        assert result.outcome is ActionOutcome.SUCCESS
        assert result.observed == 1.5
        assert result.expected == ""

    run(body())


def test_policy_models_validate_inputs():
    with pytest.raises(FormatFail):
        EVInputs(probability_join=float("nan")).validate()
    with pytest.raises(FormatFail):
        EVInputs(probability_join=1.1).validate()
    with pytest.raises(FormatFail):
        EVInputs(probability_join=0.5, cas_bytes=-1).validate()
    with pytest.raises(FormatFail):
        EVInputs(probability_join=0.5, lane_id="").validate()
    with pytest.raises(FormatFail):
        LaneAvailability(lane_id="").validate()
    with pytest.raises(FormatFail):
        LaneAvailability(lane_id="lane", busy=1).validate()
    with pytest.raises(FormatFail):
        LaneAvailability(lane_id="lane", retry_after_ms=-1).validate()


def test_policy_executor_action_cap_branches():
    executor = Executor(
        ExecutorCaps(
            spend_usd_micro=10_000_000,
            corpus_max=1,
            crashes_per_device=1,
            escalations=1,
        )
    )
    executor.record_spend(Action.SPAWN_SUBFACTORY)
    executor.record_spend(Action.FORCE_GROOM)
    executor.record_spend(Action.ESCALATE_MODEL)
    assert executor.admits(Action.SPAWN_SUBFACTORY) is False
    assert executor.admits(Action.FORCE_GROOM) is False
    assert executor.admits(Action.ESCALATE_MODEL) is False
    for action, reason in (
        (Action.SPAWN_SUBFACTORY, "corpus_cap"),
        (Action.FORCE_GROOM, "crash_cap"),
        (Action.ESCALATE_MODEL, "escalation_cap"),
    ):
        with pytest.raises(BudgetGate, match=reason):
            executor.gate(action)


def test_policy_engine_validation_and_pure_helpers():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail):
                PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=1), tick_budget_ms=0)
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000, backlog_limit=1))
            with pytest.raises(FormatFail):
                await engine.dispatch_tick(limit=-1)
            rows = [candidate("a", 2.0), candidate("b", 1.0)]
            assert [row.id for row in engine.rank_candidates(rows)] == ["a", "b"]
            kept, dropped = engine.shed_candidates(rows, backlog_limit=1, cas_bytes_limit=None)
            assert [row.id for row in kept] == ["a"]
            assert [row.id for row in dropped] == ["b"]
        finally:
            await ledger.close()

    run(body())


def candidate_row(payload):
    return {
        "id": "wo_payload",
        "action": "park",
        "unit": "u",
        "ev_cost": 1.0,
        "created": 1,
        "payload_json": payload,
    }


def test_policy_candidate_helpers_validate_payloads():
    assert candidates_from_rows([candidate_row(None)])[0].id == "wo_payload"
    assert candidates_from_rows([candidate_row("")])[0].id == "wo_payload"
    with pytest.raises(FormatFail):
        candidates_from_rows([candidate_row(123)])
    with pytest.raises(FormatFail):
        candidates_from_rows([candidate_row("[]")])
    with pytest.raises(FormatFail):
        candidates_from_rows([candidate_row('{"cas_bytes": -1}')])


def test_policy_park_unit_persists_reason():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            wids = [
                await engine.plan_action("reweight", "unit", probability_join=0.5),
                await engine.plan_action("retarget", "unit", probability_join=0.4),
            ]
            assert await engine.park_unit("unit", reason="manual") == 2
            for wid in wids:
                row = ledger.get_work_order(wid)
                assert row is not None and row["state"] == "parked"
                assert payload_of(row)["park_reason"] == "manual"
            assert ledger.ready_work_order_count() == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_dispatch_invalid_inputs_format_fail():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ledger.store.apply_batch(
                [
                    LedgerOperation(
                        "enqueue_work_order",
                        {
                            "work_order_id": "wo_bad_inputs",
                            "run_id": None,
                            "action": "park",
                            "unit": "unit",
                            "payload_json": '{"probability_join":"bad"}',
                            "ev_cost": 1.0,
                            "state": "ready",
                            "created": 1,
                        },
                        rows=1,
                    )
                ]
            )
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            report = await engine.dispatch_tick(limit=1)
            assert report.refusals == ("wo_bad_inputs",)
            assert ledger.get_work_order("wo_bad_inputs")["state"] == "failed"
        finally:
            await ledger.close()

    run(body())


def test_RA_POL_006_live_join_over_budget_is_kept():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=100_000, backlog_limit=0, cas_bytes=1 << 40),
            )
            wid = await engine.plan_action(
                "park", "unit", probability_join=0.1, join_live=True
            )
            assert await engine.shed_backlog() == 0
            row = ledger.get_work_order(wid)
            assert row is not None and row["state"] == "ready"
        finally:
            await ledger.close()

    run(body())


def test_policy_plan_action_rejects_bad_probability_and_bonus():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=1_000_000))
            with pytest.raises(FormatFail):
                await engine.plan_action("retarget", "bad", probability_join=2.0)
            with pytest.raises(FormatFail):
                await engine.plan_action("retarget", "bad", probability_join=float("nan"))
            with pytest.raises(FormatFail):
                await engine.plan_action("retarget", "bad", probability_join=-0.1)
            with pytest.raises(FormatFail):
                await engine.plan_action(
                    "retarget", "bad", probability_join=0.5, chain_bonus=-1.0
                )
            with pytest.raises(FormatFail):
                await engine.plan_action(
                    "retarget", "bad", probability_join=0.5, ingress_weight=float("inf")
                )
            assert ledger.ready_work_orders() == []
        finally:
            await ledger.close()

    run(body())


def test_policy_parse_action_roundtrip():
    for action in Action:
        assert parse_action(action.value) is action
    with pytest.raises(FormatFail, match="off-vocabulary"):
        parse_action("park; rm")


def test_policy_ev_inputs_validate_boundaries_and_types():
    for kwargs in (
        {"probability_join": 0.0},
        {"probability_join": 1.0},
        {
            "probability_join": 0.5,
            "chain_bonus": 0.0,
            "ingress_weight": 0.0,
            "cas_bytes": 0,
        },
        {"probability_join": 0.5, "lane_id": "lane"},
    ):
        EVInputs(**kwargs).validate()

    invalid = (
        {"probability_join": True},
        {"probability_join": "0.5"},
        {"probability_join": float("nan")},
        {"probability_join": float("inf")},
        {"probability_join": -0.1},
        {"probability_join": 1.1},
        {"probability_join": 0.5, "chain_bonus": float("nan")},
        {"probability_join": 0.5, "chain_bonus": -1.0},
        {"probability_join": 0.5, "ingress_weight": -1.0},
        {"probability_join": 0.5, "observed": float("nan")},
        {"probability_join": 0.5, "cas_bytes": True},
        {"probability_join": 0.5, "cas_bytes": 1.0},
        {"probability_join": 0.5, "cas_bytes": "1"},
        {"probability_join": 0.5, "cas_bytes": -1},
        {"probability_join": 0.5, "lane_id": ""},
    )
    for kwargs in invalid:
        with pytest.raises(FormatFail):
            EVInputs(**kwargs).validate()


def test_policy_lane_availability_validate():
    LaneAvailability(lane_id="lane").validate()
    LaneAvailability(lane_id="lane", busy=True, retry_after_ms=5).validate()
    for kwargs in (
        {"lane_id": ""},
        {"lane_id": "lane", "busy": 1},
        {"lane_id": "lane", "busy": "true"},
        {"lane_id": "lane", "retry_after_ms": True},
        {"lane_id": "lane", "retry_after_ms": 1.0},
        {"lane_id": "lane", "retry_after_ms": "1"},
        {"lane_id": "lane", "retry_after_ms": -1},
    ):
        with pytest.raises(FormatFail):
            LaneAvailability(**kwargs).validate()


def test_RA_POL_006_shed_budget_cas_and_live_edges():
    def row(cid, ev, *, cas_bytes=0, join_live=False, created=0):
        return WorkOrderCandidate(
            id=cid,
            action="park",
            unit="u",
            ev_cost=ev,
            created=created,
            join_live=join_live,
            cas_bytes=cas_bytes,
        )

    kept, dropped = shed_budget(
        [
            row("a", 3.0, cas_bytes=10),
            row("b", 2.0, cas_bytes=10),
            row("c", 1.0, cas_bytes=10),
        ],
        backlog_limit=10,
        cas_bytes_limit=15,
    )
    assert [item.id for item in kept] == ["a"]
    assert {item.id for item in dropped} == {"b", "c"}

    kept, dropped = shed_budget(
        [
            row("live", 0.1, cas_bytes=100, join_live=True),
            row("high", 3.0, cas_bytes=1),
        ],
        backlog_limit=10,
        cas_bytes_limit=1,
    )
    assert [item.id for item in kept] == ["live"]
    assert [item.id for item in dropped] == ["high"]

    kept, dropped = shed_budget(
        [row("a", 1.0), row("live", 0.5, join_live=True)], backlog_limit=0
    )
    assert [item.id for item in kept] == ["live"]
    assert [item.id for item in dropped] == ["a"]
    with pytest.raises(FormatFail, match="cost_usd_micro"):
        ev_score(0.5, 2.0, 3.0, -1)


def test_policy_candidate_helpers_edge_payloads():
    valid = candidates_from_rows(
        [
            candidate_row(
                '{"cas_bytes": 2, "lane_id": "lane", '
                '"join_live": true, "requires_lane": true}'
            )
        ]
    )[0]
    assert valid.cas_bytes == 2
    assert valid.lane_id == "lane"
    assert valid.join_live is True
    assert valid.requires_lane is True

    parsed = candidates_from_rows(
        [candidate_row('{"lane_id": 123, "join_live": 1, "requires_lane": "yes"}')]
    )[0]
    assert parsed.lane_id is None
    assert parsed.join_live is False
    assert parsed.requires_lane is False

    for payload in (
        "{",
        "1",
        '"x"',
        '{"cas_bytes": true}',
        '{"cas_bytes": "1"}',
        '{"cas_bytes": 1.0}',
        '{"cas_bytes": null}',
    ):
        with pytest.raises(FormatFail):
            candidates_from_rows([candidate_row(payload)])


def test_policy_inputs_from_payload_maps_fields():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            row = {"id": "wo_inputs", "action": "retarget", "unit": "u"}
            inputs = engine._inputs_from_payload(
                row,
                {
                    "probability_join": "0.5",
                    "chain_bonus": "2",
                    "ingress_weight": "3",
                    "lane_id": "lane",
                    "requires_lane": True,
                    "join_live": True,
                    "cas_bytes": "4",
                    "trigger_metric": "t",
                    "observed": "1.5",
                    "expected": "e",
                },
            )
            assert inputs.probability_join == pytest.approx(0.5)
            assert inputs.chain_bonus == pytest.approx(2.0)
            assert inputs.ingress_weight == pytest.approx(3.0)
            assert inputs.lane_id == "lane"
            assert inputs.requires_lane is True
            assert inputs.join_live is True
            assert inputs.cas_bytes == 4
            assert inputs.trigger_metric == "t"
            assert inputs.observed == pytest.approx(1.5)
            assert inputs.expected == "e"

            default = engine._inputs_from_payload(row, {})
            assert default.probability_join == 0.0
            assert default.chain_bonus == 1.0
            assert default.ingress_weight == 1.0
            assert default.lane_id is None
            assert default.requires_lane is False
            assert default.join_live is False
            assert default.cas_bytes == 0
            assert default.trigger_metric == "dispatch"
            assert default.observed == 0.0
            assert default.expected == "retarget"

            coerced = engine._inputs_from_payload(
                row, {"lane_id": 123, "requires_lane": "yes", "join_live": 1}
            )
            assert coerced.lane_id is None
            assert coerced.requires_lane is False
            assert coerced.join_live is False

            for payload in (
                {"probability_join": "bad"},
                {"chain_bonus": {}},
                {"cas_bytes": "bad"},
                {"observed": "bad"},
                {"probability_join": 2.0},
                {"cas_bytes": -1},
            ):
                with pytest.raises(FormatFail):
                    engine._inputs_from_payload(row, payload)
        finally:
            await ledger.close()

    run(body())


def test_policy_provider_and_handler_edges():
    async def body():
        ev_provider = StaticEVInputProvider(
            default=EVInputs(probability_join=0.75),
            by_unit={"u": EVInputs(probability_join=0.25)},
        )
        assert (await ev_provider.inputs_for(action=Action.RETARGET, unit="u", run_id=None)).probability_join == 0.25
        assert (await ev_provider.inputs_for(action=Action.RETARGET, unit="v", run_id=None)).probability_join == 0.75

        lanes = StaticLaneStateProvider(
            {"busy": LaneAvailability(lane_id="busy", busy=True, reason="r", retry_after_ms=3)}
        )
        known = await lanes.availability("busy")
        assert known.lane_id == "busy" and known.busy is True and known.reason == "r"
        assert known.retry_after_ms == 3
        unknown = await lanes.availability("missing")
        assert unknown.lane_id == "missing"
        assert unknown.busy is False
        assert unknown.reason == ""
        assert unknown.retry_after_ms == 0

        handler = NullActionHandler()
        empty = await handler({})
        assert empty.outcome is ActionOutcome.SUCCESS
        assert empty.observed == 0.0
        assert empty.expected == ""
        assert empty.detail == "stub"
        with_ev = await handler({"ev_cost": "2.5"})
        assert with_ev.observed == 2.5

    run(body())


def test_policy_adversarial_plan_inputs_rejected_before_ledger_write():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=1_000_000))
            for probability in (float("nan"), float("inf"), -0.1, 1.1, True, "0.5"):
                with pytest.raises(FormatFail):
                    await engine.plan_action("retarget", "u", probability_join=probability)
            invalid = (
                {"chain_bonus": float("nan")},
                {"chain_bonus": -1.0},
                {"chain_bonus": True},
                {"ingress_weight": float("inf")},
                {"ingress_weight": -1.0},
                {"cas_bytes": -1},
                {"cas_bytes": True},
                {"cas_bytes": 1.0},
                {"cas_bytes": SQLITE_INT_MAX + 1},
                {"lane_id": ""},
                {"requires_lane": 1},
                {"join_live": "yes"},
                {"trigger_metric": ""},
                {"observed": float("inf")},
                {"expected": None},
            )
            for kwargs in invalid:
                with pytest.raises(FormatFail):
                    await engine.plan_action("retarget", "u", probability_join=0.5, **kwargs)

            class BadEVProvider:
                async def inputs_for(self, *, action, unit, run_id):
                    return {"probability_join": 0.5}

            bad_provider_engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=1_000_000),
                ev_provider=BadEVProvider(),
            )
            with pytest.raises(FormatFail):
                await bad_provider_engine.plan_action("retarget", "u")
            assert ledger.counts()["work_order"] == 0
            assert ledger.counts()["decision"] == 0
        finally:
            await ledger.close()

    run(body())


def test_policy_ev_score_properties_and_invalid_inputs():
    rng = random.Random(0x52A)
    for _ in range(300):
        probability = rng.random()
        chain_bonus = rng.random() * 10.0
        ingress_weight = rng.random() * 5.0
        cost = rng.choice([0, 1, 7, 1000, 2**31])
        score = ev_score(probability, chain_bonus, ingress_weight, cost)
        assert math.isfinite(score)
        assert score >= 0.0
        numerator = probability * chain_bonus * ingress_weight
        expected = numerator if cost == 0 else numerator / cost
        assert score == pytest.approx(expected)

    invalid = (
        {"probability_join": float("nan"), "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": 1},
        {"probability_join": 1.1, "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": 1},
        {"probability_join": 0.5, "chain_bonus": -1.0, "ingress_weight": 1.0, "cost_usd_micro": 1},
        {"probability_join": 0.5, "chain_bonus": 1.0, "ingress_weight": float("inf"), "cost_usd_micro": 1},
        {"probability_join": 0.5, "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": -1},
        {"probability_join": 0.5, "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": True},
        {"probability_join": 0.5, "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": 1.5},
        {"probability_join": 0.5, "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": SQLITE_INT_MAX + 1},
    )
    for case in invalid:
        with pytest.raises(FormatFail):
            ev_score(**case)


def test_policy_executor_caps_reject_invalid_bounds_and_release_is_safe():
    with pytest.raises(FormatFail):
        ExecutorCaps(spend_usd_micro=-1)
    with pytest.raises(FormatFail):
        ExecutorCaps(spend_usd_micro=True)
    with pytest.raises(FormatFail):
        ExecutorCaps(spend_usd_micro=1.5)
    with pytest.raises(FormatFail):
        ExecutorCaps(spend_usd_micro=SQLITE_INT_MAX + 1)
    with pytest.raises(FormatFail):
        ExecutorCaps(spend_usd_micro=1, backlog_limit=-1)
    with pytest.raises(FormatFail):
        ExecutorCaps(spend_usd_micro=1, cas_bytes=SQLITE_INT_MAX + 1)
    with pytest.raises(FormatFail):
        Executor(ExecutorCaps(spend_usd_micro=1), spent_usd_micro=-1)

    executor = Executor(
        ExecutorCaps(
            spend_usd_micro=1_000_000,
            corpus_max=1,
            crashes_per_device=1,
            escalations=1,
        )
    )
    cost = executor.reserve(Action.REWEIGHT)
    assert executor.spent_usd_micro == cost
    with pytest.raises(FormatFail):
        executor.release(Action.REWEIGHT, cost + 1)
    executor.release(Action.REWEIGHT, cost)
    assert executor.spent_usd_micro == 0

    executor.spent_usd_micro = ACTION_COST_USD_MICRO[Action.FORCE_GROOM]
    with pytest.raises(FormatFail, match="crash"):
        executor.release(Action.FORCE_GROOM, ACTION_COST_USD_MICRO[Action.FORCE_GROOM])
    assert executor.crashes == 0
    with pytest.raises(FormatFail):
        executor.sync_spent(SQLITE_INT_MAX + 1)
    with pytest.raises(FormatFail):
        executor.sync_spent(True)


def test_policy_dispatch_malformed_work_orders_are_failed_before_spend():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cases = (
                ("wo_bad_json", "park", "{", 1.0),
                ("wo_bad_cas", "park", '{"cas_bytes": -1}', 1.0),
                ("wo_bad_inputs", "park", '{"probability_join": 2.0}', 1.0),
                ("wo_trigger_empty", "park", '{"trigger_metric": ""}', 1.0),
                ("wo_expected_null", "park", '{"expected": null}', 1.0),
            )
            ledger.store.apply_batch(
                [
                    LedgerOperation(
                        "enqueue_work_order",
                        {
                            "work_order_id": wo_id,
                            "run_id": None,
                            "action": action,
                            "unit": "unit",
                            "payload_json": payload_json,
                            "ev_cost": ev_cost,
                            "state": "ready",
                            "created": 1,
                        },
                        rows=1,
                    )
                    for wo_id, action, payload_json, ev_cost in cases
                ]
            )
            with pytest.raises(FormatFail):
                await ledger.enqueue_work_order(action="park", unit="unit", ev_cost=-1.0)
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=100_000))
            report = await engine.dispatch_tick(limit=10)
            ids = [case[0] for case in cases]
            assert report.dispatched == 0
            assert report.shed == 0
            assert set(report.refusals) == set(ids)
            assert all(ledger.get_work_order(wid)["state"] == "failed" for wid in ids)
            format_fails = [
                row for row in ledger.decision_rows(limit=100) if row["trigger_metric"] == "format_fail"
            ]
            assert len(format_fails) == len(ids)
            assert ledger.spent_usd_micro() == 0
            assert engine.executor.spent_usd_micro == 0
        finally:
            await ledger.close()

    run(body())


def test_policy_dispatch_handler_failure_injection_is_sanitized():
    async def body():
        ledger = await Ledger.open(":memory:")

        async def handler(order):
            marker = order["payload"].get("expected")
            if marker == "raise":
                raise RuntimeError("boom")
            if marker == "nan":
                return ActionResult(observed=float("nan"))
            return {"not": "an ActionResult"}

        try:
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=100_000),
                handlers={Action.RETARGET: handler},
            )
            wids = [
                await engine.plan_action("retarget", "unit", probability_join=0.5, expected=marker)
                for marker in ("raise", "nan", "dict")
            ]
            report = await engine.dispatch_tick(limit=10)
            assert report.dispatched == 0
            assert report.refusals == ()
            assert [ledger.get_work_order(wid)["state"] for wid in wids] == ["failed"] * 3
            failures = [
                row for row in ledger.decision_rows(unit="unit", limit=20) if row["trigger_metric"] == "remedy_failure"
            ]
            assert len(failures) == 3
            assert all(row["spent_usd_micro"] == 0 for row in failures)
            assert all(math.isfinite(float(row["observed"])) for row in failures)
            assert ledger.spent_usd_micro() == 0
            assert engine.executor.spent_usd_micro == 0
            assert await engine.unit_failure_count("unit") == 3
        finally:
            await ledger.close()

    run(body())


def test_policy_dispatch_concurrent_ticks_respect_spend_cap():
    async def body():
        ledger = await Ledger.open(":memory:")
        calls = 0

        async def handler(order):
            nonlocal calls
            calls += 1
            return ActionResult()

        try:
            cap = ACTION_COST_USD_MICRO[Action.RETARGET]
            engine = PolicyEngine(
                ledger,
                ExecutorCaps(spend_usd_micro=cap),
                handlers={Action.RETARGET: handler},
            )
            wids = [
                await engine.plan_action("retarget", "unit", probability_join=0.5, expected=marker)
                for marker in ("first", "second")
            ]
            reports = await asyncio.gather(engine.dispatch_tick(limit=10), engine.dispatch_tick(limit=10))
            assert sum(report.dispatched for report in reports) == 1
            assert sum(len(report.refusals) for report in reports) == 2
            assert calls == 1
            assert ledger.spent_usd_micro() == cap
            assert engine.executor.spent_usd_micro == cap
            states = [ledger.get_work_order(wid)["state"] for wid in wids]
            assert states.count("done") == 1
            assert states.count("ready") == 1
        finally:
            await ledger.close()

    run(body())


def test_policy_work_order_candidate_and_ev_score_reject_invalid_fields():
    base = {"id": "w", "action": "park", "unit": "u", "ev_cost": 1.0, "created": 1}
    WorkOrderCandidate(**base, state="shed", cas_bytes=SQLITE_INT_MAX, lane_id="lane", requires_lane=True, join_live=True)
    invalid = (
        {"id": ""},
        {"unit": ""},
        {"action": "rm_rf"},
        {"ev_cost": True},
        {"ev_cost": "1"},
        {"ev_cost": float("nan")},
        {"ev_cost": -1.0},
        {"created": True},
        {"created": "1"},
        {"created": -1},
        {"state": "bogus"},
        {"join_live": 1},
        {"cas_bytes": True},
        {"cas_bytes": 1.0},
        {"cas_bytes": -1},
        {"cas_bytes": SQLITE_INT_MAX + 1},
        {"lane_id": ""},
        {"requires_lane": "yes"},
    )
    for override in invalid:
        with pytest.raises(FormatFail):
            WorkOrderCandidate(**{**base, **override})

    for case in (
        {"probability_join": True, "chain_bonus": 1.0, "ingress_weight": 1.0, "cost_usd_micro": 1},
        {"probability_join": 0.5, "chain_bonus": "2", "ingress_weight": 1.0, "cost_usd_micro": 1},
        {"probability_join": 0.5, "chain_bonus": 1.0, "ingress_weight": True, "cost_usd_micro": 1},
    ):
        with pytest.raises(FormatFail):
            ev_score(**case)
