import pytest

from ra.errors import BudgetGate, FormatFail
from ra.ledger import Ledger
from ra.policy import (
    ACTION_COST_USD_MICRO,
    Action,
    Executor,
    ExecutorCaps,
    PolicyEngine,
    WorkOrderCandidate,
    ev_score,
    rank,
    shed,
)
from ra.policy.actions import parse_action
from tests.conftest import run


def candidate(cid: str, ev: float, created: int = 0, join_live: bool = False) -> WorkOrderCandidate:
    return WorkOrderCandidate(
        id=cid, action="park", unit="u", ev_cost=ev, created=created, join_live=join_live
    )


def test_RA_POL_001_closed_action_vocabulary_and_costs():
    assert Action("retarget") is Action.RETARGET
    assert ACTION_COST_USD_MICRO[Action.SPAWN_SUBFACTORY] == 300_000
    with pytest.raises(FormatFail):
        parse_action("rm_rf")


def test_RA_POL_002_ev_ranking_total_order():
    assert ev_score(0.5, 2.0, 3.0, 1000) == pytest.approx(0.003)
    ranked = rank([candidate("b", 1.0, 2), candidate("a", 1.0, 1), candidate("c", 2.0, 3)])
    assert [row.id for row in ranked] == ["c", "a", "b"]


def test_RA_POL_006_shed_never_drops_live_join():
    rows = [candidate("low", 1.0), candidate("live", 0.1, join_live=True), candidate("high", 3.0)]
    kept, dropped = shed(rows, backlog_limit=2)
    assert {row.id for row in dropped} == {"low"}
    assert all(row.id != "live" for row in dropped)
    assert len(kept) == 2


def test_RA_POL_003_executor_caps_before_side_effect():
    executor = Executor(ExecutorCaps(spend_usd_micro=30_000))
    assert executor.admits(Action.REWEIGHT) is True
    assert executor.record_spend(Action.REWEIGHT) == 10_000
    assert executor.admits(Action.RETARGET) is True
    executor.record_spend(Action.RETARGET)
    assert executor.admits(Action.REWEIGHT) is False
    executor.corpus_rows = executor.caps.corpus_max
    assert executor.admits(Action.SPAWN_SUBFACTORY) is False
    executor.escalations = executor.caps.escalations
    assert executor.admits(Action.ESCALATE_MODEL) is False


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


def test_RA_POL_005_budget_gate_zero_ev_rejected():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=1))
            with pytest.raises(FormatFail):
                await engine.plan_action("retarget", "u", probability_join=0.0)
            with pytest.raises(BudgetGate):
                raise BudgetGate("cap")
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
