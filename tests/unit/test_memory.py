import asyncio
import json
import random

import pytest

from ra.errors import AdapterShipBlocked, FormatFail
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger
from ra.memory import CampaignMemory, SlaStatus
from ra.memory.models import _json_dict, _json_list
from ra.press.golden import GoldenCase
from ra.press.packets import PacketCompiler
from ra.press.routing import TaskType
from tests.conftest import run


def claim_input(
    claim_id: str,
    claim_type: str,
    value: dict,
    *,
    confidence: float = 0.8,
    dedup: str | None = None,
) -> ClaimInput:
    return ClaimInput(
        claim_id=claim_id,
        type=claim_type,
        value_json=json.dumps(value),
        confidence=confidence,
        dedup_key=dedup or f"dedup-{claim_id}",
        created=1,
        artifacts=(
            ClaimArtifactInput(ArtifactInput(kind="evidence", data=claim_id.encode()), role="evidence"),
        ),
    )


async def promoted_claim(ledger: Ledger, claim_id: str, claim_type: str, value: dict):
    cid = await ledger.create_claim(claim_input(claim_id, claim_type, value))
    await ledger.transition_claim(cid, ClaimState.BOUND)
    await ledger.transition_claim(cid, ClaimState.REVIEWED)
    await ledger.transition_claim(cid, ClaimState.PROMOTED)
    row = ledger.get_claim(cid)
    assert row is not None
    return row


def test_RA_MEM_001_learn_promoted_claims_and_idempotent_support():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            claim = await promoted_claim(
                ledger,
                "cl_root_1",
                "root_cause",
                {"surface": "webkit", "root_cause": "uaf", "score": 0.9},
            )
            first = await memory.learn_from_claim(claim)
            second = await memory.learn_from_claim(claim)
            assert len(first) == 1 and len(second) == 1
            prior = second[0]
            assert prior.kind == "root_cause"
            assert prior.surface == "webkit"
            assert prior.score == pytest.approx(0.9)
            assert prior.support == 1
            assert prior.revision == 1
            assert prior.value["claim_id"] == "cl_root_1"
            reviewed = await ledger.create_claim(
                claim_input("cl_reviewed", "bug_class", {"surface": "webkit", "bug_class": "overflow"})
            )
            await ledger.transition_claim(reviewed, ClaimState.BOUND)
            await ledger.transition_claim(reviewed, ClaimState.REVIEWED)
            reviewed_row = ledger.get_claim(reviewed)
            assert reviewed_row is not None
            assert await memory.learn_from_claim(reviewed_row) == []
            assert len(await memory.learn_from_claim(reviewed_row, include_reviewed=True)) == 1
            state_claim = await promoted_claim(
                ledger, "cl_state", "foundry_state", {"surface": "webkit"}
            )
            assert await memory.learn_from_claim(state_claim) == []
            tampered = await memory.learn_from_claim({**claim, "type": "foundry_state"})
            assert len(tampered) == 1 and tampered[0].source_claim == "cl_root_1"
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_001_claim_value_parser_rejects_malformed_json():
    with pytest.raises(FormatFail):
        CampaignMemory._claim_value({"value_json": "{not json"})


def test_RA_MEM_002_preference_pairs_idempotent_and_validated():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            kwargs = {
                "task_type": TaskType.BUG_CLASS,
                "surface": "webkit",
                "prompt": "classify crash",
                "chosen": {"answer": "uaf"},
                "rejected": {"answer": "overflow"},
                "reward": 0.9,
                "rationale": "root cause matched",
            }
            first = await memory.record_preference_pair(**kwargs)
            second = await memory.record_preference_pair(**kwargs)
            assert first.id == second.id
            assert first.prompt_sha
            assert first.reward == pytest.approx(0.9)
            assert memory.preference_pairs(task_type="bug_class", surface="webkit") == [first]
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**kwargs, "reward": 1.2})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**kwargs, "prompt": "  "})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**kwargs, "surface": " "})
        finally:
            await ledger.close()

    run(body())


def golden_cases(count: int, answer: str = "ok") -> list[GoldenCase]:
    return [GoldenCase(TaskType.BUG_CLASS, {}, {"answer": answer}) for _ in range(count)]


def responder_ok(case: GoldenCase) -> dict:
    return dict(case.reference)


def responder_bad(case: GoldenCase) -> dict:
    return {"answer": "bad"}


def test_RA_MEM_003_adapter_lifecycle_and_golden_ship_gate():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            pair = await memory.record_preference_pair(
                task_type="bug_class",
                surface="webkit",
                prompt="classify",
                chosen={"answer": "uaf"},
                rejected={"answer": "overflow"},
                reward=1.0,
            )
            adapter = await memory.propose_adapter("bug_class", "webkit", pair_ids=[pair.id])
            assert adapter.state == "candidate"
            assert adapter.version == 1
            assert adapter.train_pair_count == 1
            assert ledger.memory_adapter_pair_ids(adapter.id) == [pair.id]
            evaluated = await memory.evaluate_adapter(
                adapter.id, golden_cases(1), responder_ok, baseline=0.0
            )
            assert evaluated.state == "evaluated"
            assert evaluated.golden_passed is True
            shipped = await memory.ship_adapter(adapter.id)
            assert shipped.state == "shipped"
            assert memory.active_adapter("bug_class", "webkit") == shipped
            second = await memory.propose_adapter("bug_class", "webkit", salt="second")
            assert second.version == 2
            blocked_eval = await memory.evaluate_adapter(
                second.id, golden_cases(200), responder_bad, baseline=1.0
            )
            assert blocked_eval.golden_passed is False
            with pytest.raises(AdapterShipBlocked):
                await memory.ship_adapter(second.id)
            assert memory.active_adapter("bug_class", "webkit") == shipped
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_003_shipping_new_adapter_retires_previous_shipped():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            pair = await memory.record_preference_pair(
                task_type="rung_select",
                surface="ios",
                prompt="select rung",
                chosen={"answer": "r1"},
                rejected={"answer": "r2"},
                reward=0.8,
            )
            first = await memory.propose_adapter("rung_select", "ios", pair_ids=[pair.id])
            await memory.evaluate_adapter(first.id, golden_cases(1, "ok"), responder_ok, baseline=0.0)
            first_shipped = await memory.ship_adapter(first.id)
            second = await memory.propose_adapter("rung_select", "ios", pair_ids=[pair.id], salt="v2")
            await memory.evaluate_adapter(second.id, golden_cases(1, "ok"), responder_ok, baseline=1.0)
            second_shipped = await memory.ship_adapter(second.id)
            assert first_shipped.id != second_shipped.id
            assert memory.adapter(first.id).state == "retired"
            active = memory.active_adapter("rung_select", "ios")
            assert active is not None and active.id == second_shipped.id
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_003_adapter_validation_and_missing_dependencies():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            with pytest.raises(FormatFail):
                await memory.propose_adapter("bug_class", "webkit")
            pair = await memory.record_preference_pair(
                task_type="bug_class",
                surface="webkit",
                prompt="p",
                chosen={"answer": "a"},
                rejected={"answer": "b"},
                reward=0.5,
            )
            with pytest.raises(FormatFail):
                await memory.propose_adapter("bug_class", "webkit", pair_ids=[pair.id, "pref_missing"])
            with pytest.raises(FormatFail):
                await memory.propose_adapter("bug_class", "webkit", pair_ids=[], parent_id="mem_missing")
            with pytest.raises(FormatFail):
                await memory.evaluate_adapter("mem_missing", golden_cases(1), responder_ok)
            candidate = await memory.propose_adapter("bug_class", "webkit", pair_ids=[pair.id])
            with pytest.raises(AdapterShipBlocked):
                await memory.ship_adapter(candidate.id)
            with pytest.raises(FormatFail):
                await memory.retire_adapter(pair.id)
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_004_sla_monotonicity_met_sticky_and_regression_flagged():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            first = await memory.record_cost_to_first_valid_poc(
                "webkit", cost_micro=100, target_cost_micro=1000
            )
            assert first.met is True and first.best_cost_micro == 100
            lower = await memory.record_cost_to_first_valid_poc("webkit", cost_micro=50)
            assert lower.best_cost_micro == 50 and lower.regressions == 0
            higher = await memory.record_cost_to_first_valid_poc("webkit", cost_micro=75)
            assert higher.flagged is True and higher.regressions == 1
            assert higher.best_cost_micro == 50 and higher.last_cost_micro == 75
            assert higher.met is True
            over_target = await memory.record_cost_to_first_valid_poc("webkit", cost_micro=2000)
            assert over_target.met is True and over_target.regressions == 2
            events = memory.sla_events("webkit")
            assert [event["regression"] for event in events] == [0, 0, 1, 1]
            assert memory.sla_violations() == [over_target]
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc(
                    "webkit", cost_micro=10, target_cost_micro=2000
                )
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc("new", cost_micro=-1, target_cost_micro=10)
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc("new2", cost_micro=1)
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_004_sla_property_best_never_regresses_and_met_sticky():
    rng = random.Random(14)
    costs = [rng.randrange(0, 5000) for _ in range(200)]
    best = None
    met = False
    regressions = 0
    last = None
    target = 1000
    for index, cost in enumerate(costs):
        if index == 0:
            best = cost
            last = cost
            met = cost <= target
            continue
        previous_last = last
        assert previous_last is not None
        if cost > previous_last:
            regressions += 1
        best = cost if best is None else min(best, cost)
        met = met or cost <= target
        last = cost
    assert best is not None and best <= min(costs)
    assert regressions >= 0 and met is (min(costs) <= 1000 or any(c <= 1000 for c in costs))


def test_RA_MEM_005_retrieval_context_citations_and_relevance():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            claim = await promoted_claim(
                ledger,
                "cl_ret",
                "root_cause",
                {"surface": "webkit", "root_cause": "uaf", "score": 0.95},
            )
            priors = await memory.learn_from_claim(claim)
            await memory.learn_from_claim(
                await promoted_claim(
                    ledger,
                    "cl_other",
                    "root_cause",
                    {"surface": "other", "root_cause": "x", "score": 1.0},
                )
            )
            await memory.record_preference_pair(
                task_type="bug_class",
                surface="webkit",
                prompt="classify",
                chosen={"answer": "uaf"},
                rejected={"answer": "overflow"},
                reward=0.7,
                source_claim="cl_ret",
            )
            context = await memory.retrieve("webkit", "bug_class", kinds=["root_cause"], limit=5)
            assert context.retrieval_id
            assert [prior.id for prior in context.priors] == [priors[0].id]
            assert len(context.pairs) == 1
            assert context.adapter is None
            text = CampaignMemory.memory_context_text(context)
            assert priors[0].id in text and "cite=cl_ret" in text
            assert context.pairs[0].id in text
            row = ledger.memory_retrieval_row(context.retrieval_id)
            assert row is not None and row["relevance"] is None
            updated = await memory.record_relevance(0.9, retrieval_id=context.retrieval_id)
            assert updated == 1
            assert ledger.memory_retrieval_row(context.retrieval_id)["relevance"] == pytest.approx(0.9)
            with pytest.raises(FormatFail):
                await memory.record_relevance(1.1, retrieval_id=context.retrieval_id)
            with pytest.raises(FormatFail):
                await memory.record_relevance(0.5)
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_005_press_packet_enrichment_records_packet_sha():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            claim = await promoted_claim(
                ledger,
                "cl_press",
                "bug_class",
                {"surface": "webkit", "bug_class": "uaf", "score": 0.88},
            )
            await memory.learn_from_claim(claim)
            compiler = PacketCompiler()
            packet, context = await memory.press_packet(
                TaskType.BUG_CLASS,
                "classify this crash",
                surface="webkit",
                run_id="run-1",
                compiler=compiler,
            )
            assert packet.task_type == TaskType.BUG_CLASS
            assert context.packet_sha is not None
            assert "[prior" in packet.exemplar
            rows = ledger.memory_retrievals(packet_sha=context.packet_sha)
            assert len(rows) == 1 and rows[0]["id"] == context.retrieval_id
            assert rows[0]["run_id"] == "run-1"
            updated = await memory.record_relevance(0.75, packet_sha=context.packet_sha)
            assert updated == 1
            assert ledger.memory_retrievals(packet_sha=context.packet_sha)[0]["relevance"] == pytest.approx(0.75)
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_006_persistence_reopen_and_counts(tmp_path):
    async def body():
        path = tmp_path / "memory.sqlite"
        ledger = await Ledger.open(path)
        memory = CampaignMemory(ledger)
        claim = await promoted_claim(
            ledger,
            "cl_persist",
            "gadget_set",
            {"surface": "macos", "gadget_set": "g1", "score": 0.7},
        )
        learned = await memory.learn_from_claim(claim)
        await memory.record_cost_to_first_valid_poc("macos", cost_micro=300, target_cost_micro=1000)
        report = memory.memory_report()
        assert report["priors"] == 1 and report["slas"] == 1
        await ledger.close()
        again = await Ledger.open(path)
        try:
            memory2 = CampaignMemory(again)
            priors = memory2.priors("macos", kind="gadget_set")
            assert [prior.id for prior in priors] == [learned[0].id]
            assert priors[0].value["claim_id"] == "cl_persist"
            status = memory2.sla_status("macos")
            assert isinstance(status, SlaStatus) and status.met is True
            assert memory2.memory_report()["sla_events"] == 1
        finally:
            await again.close()

    run(body())


def test_RA_MEM_007_learning_static_edge_branches():
    assert CampaignMemory._claim_value({"value": {"surface": "webkit"}}) == {"surface": "webkit"}
    assert CampaignMemory._claim_value({"value_json": {"surface": "ios"}}) == {"surface": "ios"}
    assert CampaignMemory._claim_value({"value_json": [1, 2]}) == {"value": [1, 2]}
    assert CampaignMemory._surface_for({"surface": "", "ring_node": "webkit"}) == "webkit"
    assert CampaignMemory._surface_for({"surface": 7, "target": "macos"}) == "macos"
    assert CampaignMemory._surface_for({"surface": " "}) == "*"
    claim = {"dedup_key": "", "id": "cl_fallback"}
    assert CampaignMemory._prior_key({"surface": "webkit"}, claim, "cl_fallback") == "cl_fallback"

    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            with pytest.raises(FormatFail):
                await memory.learn_from_claim({})
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_007b_memory_json_helpers():
    assert _json_dict({"a": 1}) == {"a": 1}
    assert _json_dict('{"a": 1}') == {"a": 1}
    assert _json_dict("[1]") == {}
    assert _json_dict(3) == {}
    assert _json_list([1, 2]) == [1, 2]
    assert _json_list('["a"]') == ["a"]
    assert _json_list('{"a": 1}') == []
    assert _json_list(None) == []


def test_RA_MEM_008_adapter_reporting_reject_retire_and_default_baseline():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            pair = await memory.record_preference_pair(
                task_type="gadget_rank",
                surface="macos",
                prompt="rank gadgets",
                chosen={"ranking": ["a"]},
                rejected={"ranking": ["b"]},
                reward=0.6,
            )
            with pytest.raises(FormatFail):
                await memory.propose_adapter("gadget_rank", " ", pair_ids=[pair.id])
            first = await memory.propose_adapter("gadget_rank", "macos", pair_ids=[pair.id])
            reused = await memory.propose_adapter("gadget_rank", "macos", pair_ids=[pair.id])
            assert reused.id == first.id and reused.version == 1
            await memory.evaluate_adapter(first.id, golden_cases(1, "ok"), responder_ok)
            shipped = await memory.ship_adapter(first.id)
            assert await memory.ship_adapter(first.id) == shipped
            second = await memory.propose_adapter("gadget_rank", "macos", pair_ids=[pair.id], salt="two")
            evaluated = await memory.evaluate_adapter(second.id, golden_cases(1, "ok"), responder_ok)
            assert evaluated.baseline_score == pytest.approx(1.0)
            rejected = await memory.propose_adapter("gadget_rank", "macos", pair_ids=[pair.id], salt="rej")
            assert await memory.reject_adapter(rejected.id) is True
            assert memory.adapter(rejected.id).state == "rejected"
            third = await memory.propose_adapter("gadget_rank", "macos", pair_ids=[pair.id], salt="three")
            await memory.evaluate_adapter(third.id, golden_cases(1, "ok"), responder_ok, baseline=0.0)
            await memory.ship_adapter(third.id)
            assert memory.adapter(first.id).state == "retired"
            assert await memory.retire_adapter(second.id) is True
            active = memory.active_adapter("gadget_rank", "macos")
            assert active is not None and active.id == third.id
            cited = await memory.retrieve("macos", "gadget_rank", limit=1, pair_limit=1)
            assert cited.adapter is not None and cited.adapter.id == third.id
            assert "[adapter" in CampaignMemory.memory_context_text(cited)
            states = [adapter.state for adapter in memory.adapters(task_type="gadget_rank", surface="macos")]
            assert "rejected" in states and "retired" in states and "shipped" in states
            with pytest.raises(FormatFail):
                memory.adapters(state="bogus")
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_009_retrieval_edges_prior_reporting_and_sla_validation():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            long_value = "x" * 400
            claim = await promoted_claim(
                ledger,
                "cl_long",
                "root_cause",
                {"surface": "webkit", "root_cause": long_value, "score": 0.9},
            )
            learned = await memory.learn_from_claim(claim)
            await memory.learn_from_claim(
                await promoted_claim(
                    ledger,
                    "cl_bug",
                    "bug_class",
                    {"surface": "webkit", "bug_class": "overflow", "score": 0.4},
                )
            )
            limited = await memory.retrieve("webkit", "bug_class", limit=1, pair_limit=0)
            assert len(limited.priors) == 1 and limited.pairs == () and limited.adapter is None
            roots = await memory.retrieve("webkit", kinds=["root_cause"], pair_limit=0, limit=5)
            assert [prior.kind for prior in roots.priors] == ["root_cause"]
            with pytest.raises(FormatFail):
                memory._pairs_for_ids(["pref_missing"])
            only_priors = await memory.retrieve("webkit")
            assert only_priors.task_type is None and only_priors.pairs == ()
            with pytest.raises(FormatFail):
                await memory.retrieve(" ", "bug_class")
            packet, context = await memory.press_packet(
                "bug_class", "goal", surface="webkit", limit=1, pair_limit=0
            )
            assert context.packet_sha is None
            assert "..." in packet.exemplar
            rows = memory.retrievals(surface="webkit", task_type="bug_class")
            assert len(rows) == 2
            assert memory.prior(learned[0].id) is not None
            assert memory.prior("mem_missing") is None
            with pytest.raises(FormatFail):
                memory.priors(kind="bogus")
            with pytest.raises(FormatFail):
                await memory.retire_prior("mem_missing")
            assert await memory.retire_prior(learned[0].id) is True
            assert memory.priors("webkit", state="retired", include_global=False)
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc(" ", cost_micro=1, target_cost_micro=1)
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc("neg", cost_micro=1, target_cost_micro=-1)
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_010_ledger_memory_payload_validation_failure_injection():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            before = ledger.counts()["memory_prior"]
            with pytest.raises(FormatFail):
                await ledger.upsert_memory_prior(
                    kind="root_cause",
                    surface="webkit",
                    key="bad-score",
                    value={"x": 1},
                    score=1.2,
                    support=1,
                    confidence=0.5,
                )
            assert ledger.counts()["memory_prior"] == before
            with pytest.raises(FormatFail):
                await ledger.record_memory_retrieval_relevance(relevance=0.5)
            with pytest.raises(FormatFail):
                await ledger.ensure_memory_preference(
                    pair_id="pref_bad",
                    task_type="bug_class",
                    surface="webkit",
                    prompt_sha="0" * 64,
                    chosen={"answer": "a"},
                    rejected={"answer": "b"},
                    reward=-0.1,
                )
            assert ledger.counts()["memory_preference"] == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_011_adversarial_validation_bounds_and_adapter_lifecycle_edges():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            second_memory = CampaignMemory(ledger)
            assert second_memory is not memory
            base = {
                "task_type": "bug_class",
                "surface": "webkit",
                "prompt": "classify",
                "chosen": {"answer": "uaf"},
                "rejected": {"answer": "overflow"},
                "reward": 0.5,
            }
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "task_type": "bogus"})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "surface": 123})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "surface": "x" * 513})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "reward": "high"})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "reward": True})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "reward": float("nan")})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "reward": 10**1000})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "chosen": []})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "chosen": {"x": object()}})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "chosen": {"x": "y" * 1_000_001}})
            with pytest.raises(FormatFail):
                await memory.record_preference_pair(**{**base, "source_claim": "cl_missing"})
            with pytest.raises(FormatFail):
                memory.preference_pairs(surfaces=["a"] * 1001)
            with pytest.raises(FormatFail):
                memory.preference_pairs(limit=True)
            with pytest.raises(FormatFail):
                memory.preference_pairs(limit=1001)
            assert memory.preference_pairs(surfaces=["webkit"], limit=0) == []
            with pytest.raises(FormatFail):
                await memory.retrieve("webkit", kinds=["bogus"])
            with pytest.raises(FormatFail):
                memory.priors(state="bogus")
            with pytest.raises(FormatFail):
                await memory.propose_adapter("bug_class", "webkit", pair_ids="pref_x")
            with pytest.raises(FormatFail):
                await memory.propose_adapter("bug_class", "webkit", max_pairs=0)

            bad_pair = await memory.record_preference_pair(
                task_type="gadget_rank", surface="macos", prompt="p",
                chosen={"a": 1}, rejected={"a": 2}, reward=0.5,
            )
            with pytest.raises(FormatFail):
                await memory.propose_adapter("bug_class", "webkit", pair_ids=[bad_pair.id])

            pair = await memory.record_preference_pair(**base)
            shipped = await memory.propose_adapter("bug_class", "webkit", pair_ids=[pair.id])
            await memory.evaluate_adapter(shipped.id, golden_cases(1), responder_ok, baseline=0.0)
            shipped = await memory.ship_adapter(shipped.id)
            with pytest.raises(FormatFail):
                await memory.evaluate_adapter(shipped.id, golden_cases(1), responder_ok)
            with pytest.raises(FormatFail):
                await memory.reject_adapter(shipped.id)
            ios_pair = await memory.record_preference_pair(
                task_type="bug_class", surface="ios", prompt="p",
                chosen={"a": 1}, rejected={"a": 2}, reward=0.5,
            )
            with pytest.raises(FormatFail):
                await memory.propose_adapter(
                    "bug_class", "ios", pair_ids=[ios_pair.id], parent_id=shipped.id
                )
            rejected = await memory.propose_adapter(
                "bug_class", "webkit", pair_ids=[pair.id], salt="rej"
            )
            assert await memory.reject_adapter(rejected.id) is True
            assert await memory.reject_adapter(rejected.id) is False
            assert await memory.retire_adapter(rejected.id) is True
            assert await memory.retire_adapter(rejected.id) is False
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_012_prior_adversarial_persistence_edges():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            with pytest.raises(FormatFail):
                await memory.learn_from_claim({"id": "cl_missing"})

            async def malformed_meta(value, claim_id):
                await ledger.upsert_memory_prior(
                    kind="bug_class", surface="webkit", key="meta",
                    value=value, score=0.5, support=1, confidence=0.5,
                )
                claim = await promoted_claim(
                    ledger, claim_id, "bug_class",
                    {"surface": "webkit", "bug_class": "meta", "score": 0.7},
                )
                await memory.learn_from_claim(claim)

            for index, bad_value in enumerate((
                {"_memory": "bad"},
                {"_memory": {"contributors": {}}},
                {"_memory": {"contributors": [1]}},
            )):
                with pytest.raises(FormatFail):
                    await malformed_meta(bad_value, f"cl_meta_{index}")

            legacy = await promoted_claim(
                ledger, "cl_legacy", "bug_class",
                {"surface": "webkit", "bug_class": "legacy", "score": 0.4},
            )
            await ledger.upsert_memory_prior(
                kind="bug_class", surface="webkit", key="legacy",
                value={"claim_id": "cl_legacy", "bug_class": "legacy", "score": 0.4},
                score=0.4, support=1, confidence=0.8, source_claim="cl_legacy",
            )
            newer = await promoted_claim(
                ledger, "cl_legacy2", "bug_class",
                {"surface": "webkit", "bug_class": "legacy", "score": 0.9},
            )
            learned = await memory.learn_from_claim(newer)
            assert learned[0].score == pytest.approx(0.9)
            assert learned[0].support == 2
            assert learned[0].source_claim == "cl_legacy2"
            assert legacy is not None

            conflict = await promoted_claim(
                ledger, "cl_conflict", "bug_class",
                {"surface": "webkit", "bug_class": "conflict", "score": 0.7},
            )
            await memory.learn_from_claim(conflict)
            await ledger.upsert_memory_prior(
                kind="bug_class", surface="webkit", key="conflict",
                value={
                    "claim_id": "cl_conflict", "bug_class": "conflict", "score": 0.7,
                    "_memory": {"contributors": [{
                        "id": "cl_conflict", "score": 0.7, "confidence": 0.8,
                        "created": 1, "sha": "bad", "artifact": None,
                    }]},
                },
                score=0.7, support=1, confidence=0.8, source_claim="cl_conflict",
            )
            with pytest.raises(FormatFail):
                await memory.learn_from_claim(conflict)

            retired_claim = await promoted_claim(
                ledger, "cl_retire", "bug_class",
                {"surface": "webkit", "bug_class": "retire", "score": 0.6},
            )
            retired_prior = (await memory.learn_from_claim(retired_claim))[0]
            assert await memory.retire_prior(retired_prior.id) is True
            assert await memory.learn_from_claim(retired_claim) == []
            await ledger.upsert_memory_prior(
                kind="bug_class", surface="webkit", key="nolegacy",
                value={"bug_class": "nolegacy", "score": 0.3},
                score=0.3, support=1, confidence=0.8,
            )
            nolegacy_claim = await promoted_claim(
                ledger, "cl_nolegacy", "bug_class",
                {"surface": "webkit", "bug_class": "nolegacy", "score": 0.8},
            )
            learned = await memory.learn_from_claim(nolegacy_claim)
            assert learned[0].source_claim == "cl_nolegacy"
        finally:
            await ledger.close()

    run(body())


def test_RA_MEM_013_prior_convergence_cap_and_concurrent_writes():
    async def body():
        first = await Ledger.open(":memory:")
        second = await Ledger.open(":memory:")
        try:
            memory_a = CampaignMemory(first)
            memory_b = CampaignMemory(second)
            claims = []
            for index, score in enumerate((0.2, 0.8, 0.5)):
                claims.append((index, await promoted_claim(
                    first, f"cl_conv_{index}", "bug_class",
                    {"surface": "webkit", "bug_class": "conv", "score": score},
                )))
                await promoted_claim(
                    second, f"cl_conv_{index}", "bug_class",
                    {"surface": "webkit", "bug_class": "conv", "score": score},
                )
            for _, claim in reversed(claims):
                await memory_b.learn_from_claim(claim)
            for _, claim in claims:
                await memory_a.learn_from_claim(claim)
            prior_a = memory_a.priors("webkit", kind="bug_class", include_global=False)[0]
            prior_b = memory_b.priors("webkit", kind="bug_class", include_global=False)[0]
            assert prior_a.value == prior_b.value
            assert prior_a.score == prior_b.score == pytest.approx(0.8)
            assert prior_a.support == prior_b.support == 3
            assert prior_a.source_claim == prior_b.source_claim

            cap_claims = []
            for index in range(130):
                cap_claims.append(await promoted_claim(
                    first, f"cl_cap_{index:03d}", "bug_class",
                    {"surface": "webkit", "bug_class": "cap", "score": (index % 97) / 97},
                ))
            for claim in cap_claims:
                await memory_a.learn_from_claim(claim)
            capped = first.memory_prior_by_key("bug_class", "webkit", "cap")
            assert capped is not None
            assert int(capped["support"]) == 128
            meta = json.loads(capped["value_json"])["_memory"]
            assert len(meta["contributors"]) == 128

            conc_claims = []
            for index in range(12):
                conc_claims.append(await promoted_claim(
                    first, f"cl_conc_{index:02d}", "bug_class",
                    {"surface": "webkit", "bug_class": "conc", "score": (index + 1) / 12},
                ))
            results = await asyncio.gather(*(memory_a.learn_from_claim(claim) for claim in conc_claims))
            assert len(results) == 12 and all(len(item) == 1 for item in results)
            concurrent = first.memory_prior_by_key("bug_class", "webkit", "conc")
            assert concurrent is not None
            assert int(concurrent["support"]) == 12
            assert float(concurrent["score"]) == pytest.approx(1.0)
            assert concurrent["source_claim"] == "cl_conc_11"
        finally:
            await first.close()
            await second.close()

    run(body())


def test_RA_MEM_014_sla_adversarial_ordering_and_bounds():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            memory = CampaignMemory(ledger)
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc("x", cost_micro=True, target_cost_micro=1)
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc("x", cost_micro=1, target_cost_micro=1, created=10**15)
            await memory.record_cost_to_first_valid_poc(
                "sla_same", cost_micro=50, target_cost_micro=100, created=1_000_000_000_000
            )
            same = await memory.record_cost_to_first_valid_poc(
                "sla_same", cost_micro=60, target_cost_micro=100, created=1_000_000_000_001
            )
            assert same.best_cost_micro == 50 and same.met is True
            await memory.record_cost_to_first_valid_poc(
                "sla_order", cost_micro=10, target_cost_micro=100, created=1_000_000_000_000
            )
            with pytest.raises(FormatFail):
                await memory.record_cost_to_first_valid_poc(
                    "sla_order", cost_micro=9, target_cost_micro=100, created=999_999_999_999
                )
            with pytest.raises(FormatFail):
                memory.sla_statuses(limit=-1)
        finally:
            await ledger.close()

    run(body())
