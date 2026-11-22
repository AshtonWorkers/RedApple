"""RA-PROM promotion gate acceptance tests."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from ra.errors import FormatFail
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger
from ra.promote import (
    DupeResult,
    DupeStatus,
    EvidenceArtifact,
    GroomResult,
    GroomStatus,
    LadderResult,
    LadderStatus,
    LedgerPolicyGate,
    PromotionGate,
    PromotionRequest,
    PromotionResult,
    PromotionStage,
    PromotionStatus,
    ReviewResult,
    ReviewStatus,
    ReviewVerdict,
    StubDupe,
    StubGroom,
    StubLadder,
    StubReviewer,
    StubTriage,
    SubmissionEntry,
    TriageResult,
    TriageStatus,
)
from ra.promote.models import json_loads, sorted_artifact_views


def triage_ok(dedup: str = "dedup-1", **overrides) -> SimpleNamespace:
    values = {
        "status": TriageStatus.CLASSIFIED,
        "bug_class": "uaf",
        "primitive": "rel_rw",
        "confidence": 0.9,
        "dedup_key": dedup,
    }
    values.update(overrides)
    return SimpleNamespace(classify=AsyncMock(return_value=TriageResult(**values)))


def ladder_ok(**overrides) -> SimpleNamespace:
    values = {
        "status": LadderStatus.PASSED,
        "rung": "rel_rw",
        "assertions": ("assert-a",),
        "consecutive_passes": 3,
        "required_passes": 3,
    }
    values.update(overrides)
    return SimpleNamespace(climb=AsyncMock(return_value=LadderResult(**values)))


def groom_ok(**overrides) -> SimpleNamespace:
    values = {"status": GroomStatus.VALID, "validator": "heap_diff.class_stable"}
    values.update(overrides)
    return SimpleNamespace(validate=AsyncMock(return_value=GroomResult(**values)))


def dupe_ok(score: float = 0.7, **overrides) -> SimpleNamespace:
    values = {
        "status": DupeStatus.SCORED,
        "saturation": 0.5,
        "patch_proximity": 0.5,
        "shipped_coverage": 0.2,
        "score": score,
    }
    values.update(overrides)
    return SimpleNamespace(score=AsyncMock(return_value=DupeResult(**values)))


def verdict(**overrides) -> ReviewVerdict:
    values = {
        "reviewer": "rev-b",
        "bug_class": "uaf",
        "primitive": "rel_rw",
        "reviewer_family": "family-b",
        "artifact": EvidenceArtifact(kind="review", data=b"review", role="reviewer"),
    }
    values.update(overrides)
    return ReviewVerdict(**values)


def reviewer_ok(review_verdict: ReviewVerdict | None = None, **overrides) -> SimpleNamespace:
    values = {"status": ReviewStatus.OK, "verdict": review_verdict or verdict()}
    values.update(overrides)
    return SimpleNamespace(review=AsyncMock(return_value=ReviewResult(**values)))


class PromotionGateTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = await Ledger.open(self.root / "ledger.sqlite")

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def request(self, case_id: str = "case-1", data: bytes = b"crash", **overrides) -> PromotionRequest:
        values = {
            "case_id": case_id,
            "artifacts": (EvidenceArtifact(kind="crash", data=data, role="crash"),),
        }
        values.update(overrides)
        return PromotionRequest(**values)

    def gate(self, **overrides) -> PromotionGate:
        values = {
            "triage": triage_ok(),
            "ladder": ladder_ok(),
            "groom": groom_ok(),
            "dupe": dupe_ok(),
            "reviewer": reviewer_ok(),
        }
        values.update(overrides)
        return PromotionGate(self.ledger, **values)

    async def test_promote_happy_path_is_idempotent(self) -> None:
        gate = self.gate()
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.PROMOTED)
        self.assertIsNotNone(result.claim_id)
        self.assertIsNotNone(result.verdict_id)
        self.assertIsNotNone(result.submission)
        assert result.claim_id is not None
        assert result.submission is not None
        self.assertEqual(result.submission.dupe_score, 0.7)
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "promoted")
        self.assertEqual(len(self.ledger.claims_by_type("rung")), 1)
        self.assertEqual(len(self.ledger.claims_by_type("groom")), 1)
        self.assertEqual(len(self.ledger.claims_by_type("dupe_score")), 1)
        verdicts = self.ledger.verdicts_for_claim(result.claim_id)
        self.assertEqual(len(verdicts), 1)
        self.assertEqual(int(verdicts[0]["agree"]), 1)

        again = await gate.evaluate(self.request())
        self.assertEqual(again.status, PromotionStatus.ALREADY_PROMOTED)
        self.assertEqual(again.claim_id, result.claim_id)
        self.assertEqual(len(self.ledger.verdicts_for_claim(result.claim_id)), 1)
        self.assertEqual(len(self.ledger.claims_by_type("rung")), 1)

    async def test_submission_queue_orders_by_dupe_score(self) -> None:
        low = self.gate(triage=triage_ok("dedup-low"), dupe=dupe_ok(0.2))
        high = self.gate(triage=triage_ok("dedup-high"), dupe=dupe_ok(0.9))
        await low.evaluate(self.request("case-low", b"low"))
        await high.evaluate(self.request("case-high", b"high"))
        queue = low.submission_queue()
        self.assertEqual([entry.bug_class for entry in queue], ["uaf", "uaf"])
        self.assertEqual([entry.dupe_score for entry in queue], [0.9, 0.2])

    async def test_triage_insufficient_requeues_with_retarget(self) -> None:
        triage = SimpleNamespace(
            classify=AsyncMock(
                return_value=TriageResult(
                    status=TriageStatus.INSUFFICIENT, reason="need more evidence"
                )
            )
        )
        result = await PromotionGate(self.ledger, triage=triage).evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.stage, PromotionStage.TRIAGE)
        self.assertIsNotNone(result.work_order_id)
        order = self.ledger.get_work_order(result.work_order_id or "")
        assert order is not None
        self.assertEqual(order["action"], "retarget")
        self.assertEqual(self.ledger.counts()["claim"], 0)

    async def test_triage_split_escalates_model(self) -> None:
        triage = SimpleNamespace(
            classify=AsyncMock(return_value=TriageResult(status=TriageStatus.SPLIT, reason="ambiguous"))
        )
        result = await PromotionGate(self.ledger, triage=triage).evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.ESCALATED)
        self.assertIsNotNone(result.work_order_id)
        order = self.ledger.get_work_order(result.work_order_id or "")
        assert order is not None
        self.assertEqual(order["action"], "escalate_model")

    async def test_triage_duplicate_stops_gate(self) -> None:
        triage = SimpleNamespace(
            classify=AsyncMock(return_value=TriageResult(status=TriageStatus.DUPLICATE, reason="known"))
        )
        result = await PromotionGate(self.ledger, triage=triage).evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.DUPLICATE)
        self.assertEqual(result.stage, PromotionStage.TRIAGE)
        self.assertIsNone(result.claim_id)

    async def test_triage_unavailable_requeues_then_parks_at_limit(self) -> None:
        triage = SimpleNamespace(
            classify=AsyncMock(return_value=TriageResult(status=TriageStatus.UNAVAILABLE, reason="down"))
        )
        gate = PromotionGate(self.ledger, triage=triage, max_attempts=3)
        first = await gate.evaluate(self.request(attempt=0))
        self.assertEqual(first.status, PromotionStatus.REQUEUED)
        last = await gate.evaluate(self.request(attempt=2))
        self.assertEqual(last.status, PromotionStatus.PARKED)
        order = self.ledger.get_work_order(last.work_order_id or "")
        assert order is not None
        self.assertEqual(order["action"], "park")

    async def test_ladder_exhausted_demotes_claim(self) -> None:
        gate = self.gate(ladder=ladder_ok(status=LadderStatus.EXHAUSTED, reason="no primitive"))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.DEMOTED)
        self.assertEqual(result.stage, PromotionStage.LADDER)
        assert result.claim_id is not None
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "demoted")
        order = self.ledger.get_work_order(result.work_order_id or "")
        assert order is not None
        self.assertEqual(order["action"], "demote")
        self.assertEqual(len(self.ledger.claims_by_type("rung")), 1)

    async def test_ladder_retry_parks_at_max_attempts(self) -> None:
        gate = self.gate(ladder=ladder_ok(status=LadderStatus.RETRY, reason="flaky"), max_attempts=1)
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.PARKED)
        self.assertEqual(result.stage, PromotionStage.LADDER)
        assert result.claim_id is not None
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "parked")

    async def test_ladder_pass_without_assertions_requeues(self) -> None:
        gate = self.gate(ladder=ladder_ok(assertions=()))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.reason, "ladder_assertions_missing")
        assert result.claim_id is not None
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "bound")

    async def test_groom_invalid_demotes_claim(self) -> None:
        gate = self.gate(groom=groom_ok(status=GroomStatus.INVALID, reason="layout changed"))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.DEMOTED)
        self.assertEqual(result.stage, PromotionStage.GROOM)
        assert result.claim_id is not None
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "demoted")

    async def test_groom_defect_escalates_force_groom(self) -> None:
        gate = self.gate(groom=groom_ok(status=GroomStatus.DEFECT, reason="dialect gap"))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.ESCALATED)
        self.assertEqual(result.stage, PromotionStage.GROOM)
        order = self.ledger.get_work_order(result.work_order_id or "")
        assert order is not None
        self.assertEqual(order["action"], "force_groom")
        assert result.claim_id is not None
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "bound")

    async def test_dupe_unavailable_requeues(self) -> None:
        dupe = SimpleNamespace(
            score=AsyncMock(return_value=DupeResult(status=DupeStatus.UNAVAILABLE, reason="oracle down"))
        )
        gate = self.gate(dupe=dupe)
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.stage, PromotionStage.DUPE)
        self.assertEqual(len(self.ledger.claims_by_type("dupe_score")), 1)

    async def test_reviewer_disagreement_escalates_and_verdict_is_idempotent(self) -> None:
        reviewer = reviewer_ok(verdict=verdict(reviewer_family="family-a"))
        gate = self.gate(reviewer=reviewer, policy=LedgerPolicyGate(self.ledger))
        req = self.request(proposer_family="family-a")
        first = await gate.evaluate(req)
        self.assertEqual(first.status, PromotionStatus.ESCALATED)
        self.assertEqual(first.reason, "reviewer_family_not_independent")
        self.assertEqual(first.stage, PromotionStage.REVIEWER)
        assert first.claim_id is not None
        assert first.verdict_id is not None
        self.assertEqual(self.ledger.get_claim(first.claim_id)["state"], "reviewed")
        self.assertEqual(len(self.ledger.verdicts_for_claim(first.claim_id)), 1)

        second = await gate.evaluate(req)
        self.assertEqual(second.status, PromotionStatus.ESCALATED)
        self.assertEqual(second.verdict_id, first.verdict_id)
        self.assertEqual(len(self.ledger.verdicts_for_claim(first.claim_id)), 1)

    async def test_policy_budget_gate_holds_at_reviewed(self) -> None:
        policy = LedgerPolicyGate(self.ledger, spend_cap_usd_micro=0)
        gate = self.gate(policy=policy)
        result = await gate.evaluate(self.request(estimated_cost_usd_micro=1))
        self.assertEqual(result.status, PromotionStatus.BUDGET_GATE)
        self.assertEqual(result.stage, PromotionStage.POLICY)
        assert result.claim_id is not None
        self.assertEqual(self.ledger.get_claim(result.claim_id)["state"], "reviewed")
        self.assertEqual(result.details["policy"]["reason"], "BUDGET_GATE")

    async def test_unbound_claim_requeues(self) -> None:
        req = self.request()
        artifact_id = req.artifact_views()[0].artifact_id
        gate = self.gate(
            triage=triage_ok("dedup-unbound"),
            ladder=ladder_ok(status=LadderStatus.RETRY, reason="wait"),
        )
        first = await gate.evaluate(req)
        self.assertEqual(first.status, PromotionStatus.REQUEUED)
        assert first.claim_id is not None
        await self.ledger.delete_artifacts([artifact_id])
        self.assertEqual(self.ledger.claim_artifact_count(first.claim_id), 0)

        second = await gate.evaluate(req)
        self.assertEqual(second.status, PromotionStatus.REQUEUED)
        self.assertEqual(second.reason, "unbound_claim")
        self.assertEqual(second.claim_id, first.claim_id)

    async def test_malformed_ladder_rung_requeues(self) -> None:
        gate = self.gate(ladder=ladder_ok(rung="bogus"))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.reason, "ladder_rung_unknown")

    async def test_ladder_insufficient_passes_requeues(self) -> None:
        gate = self.gate(ladder=ladder_ok(consecutive_passes=2))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.reason, "ladder_passes_insufficient")

    async def test_groom_missing_validator_requeues(self) -> None:
        gate = self.gate(groom=groom_ok(validator=None))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.reason, "groom_validator_missing")

    async def test_dupe_invalid_score_requeues(self) -> None:
        gate = self.gate(dupe=dupe_ok(score=-0.1))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.reason, "dupe_score_invalid")

    async def test_reviewer_ok_without_verdict_is_rejected(self) -> None:
        reviewer = SimpleNamespace(
            review=AsyncMock(return_value=ReviewResult(status=ReviewStatus.OK, verdict=None))
        )
        gate = self.gate(reviewer=reviewer)
        with self.assertRaises(FormatFail):
            await gate.evaluate(self.request())

    async def test_triage_confidence_out_of_range_is_rejected(self) -> None:
        gate = self.gate(triage=triage_ok(confidence=1.2))
        with self.assertRaises(FormatFail):
            await gate.evaluate(self.request())

    def test_submission_queue_rejects_bad_limit(self) -> None:
        gate = self.gate()
        with self.assertRaises(ValueError):
            gate.submission_queue(limit=0)

    async def test_default_stubs_requeue_at_triage(self) -> None:
        result = await PromotionGate(self.ledger).evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.stage, PromotionStage.TRIAGE)
        self.assertEqual(result.reason, "triage component is not implemented")

    async def test_component_stubs_report_unavailable(self) -> None:
        self.assertEqual(
            (await StubTriage().classify(SimpleNamespace())).status, TriageStatus.UNAVAILABLE
        )
        self.assertEqual(
            (await StubLadder().climb(SimpleNamespace())).status, LadderStatus.UNAVAILABLE
        )
        self.assertEqual(
            (await StubGroom().validate(SimpleNamespace())).status, GroomStatus.UNAVAILABLE
        )
        self.assertEqual(
            (await StubDupe().score(SimpleNamespace())).status, DupeStatus.UNAVAILABLE
        )
        self.assertEqual(
            (await StubReviewer().review(SimpleNamespace())).status, ReviewStatus.UNAVAILABLE
        )

    def test_request_validation_rejects_bad_gate_inputs(self) -> None:
        bad_artifacts = [
            EvidenceArtifact(kind="crash", data=b"", role="crash"),
            EvidenceArtifact(kind="crash", data=b"x", role=" "),
            EvidenceArtifact(kind="crash", data=b"x", role="crash", ttl_class="forever"),
        ]
        for artifact in bad_artifacts:
            with self.subTest(artifact=artifact), self.assertRaises(ValueError):
                PromotionRequest(case_id="case-1", artifacts=(artifact,)).validated()
        with self.assertRaises(ValueError):
            self.request(probability_join=True).validated()
        with self.assertRaises(ValueError):
            self.request(chain_bonus=float("nan")).validated()

    async def test_classified_triage_with_duplicate_of_is_duplicate(self) -> None:
        gate = self.gate(triage=triage_ok("dedup-dupe", duplicate_of="cl-existing"))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.DUPLICATE)
        self.assertIsNone(result.claim_id)
        self.assertEqual(self.ledger.counts()["claim"], 0)

    async def test_dedup_identity_mismatch_is_rejected(self) -> None:
        await self.gate().evaluate(self.request())
        mismatched = self.gate(triage=triage_ok("dedup-1", bug_class="oob"))
        with self.assertRaises(FormatFail):
            await mismatched.evaluate(self.request())
        self.assertEqual(len(self.ledger.claims_by_type("bug_class")), 1)

    async def test_component_errors_are_contained(self) -> None:
        cases = {
            "triage": SimpleNamespace(classify=AsyncMock(side_effect=RuntimeError("boom"))),
            "ladder": SimpleNamespace(climb=AsyncMock(side_effect=RuntimeError("boom"))),
            "groom": SimpleNamespace(validate=AsyncMock(side_effect=RuntimeError("boom"))),
            "dupe": SimpleNamespace(score=AsyncMock(side_effect=RuntimeError("boom"))),
            "reviewer": SimpleNamespace(review=AsyncMock(side_effect=RuntimeError("boom"))),
        }
        for name, component in cases.items():
            with self.subTest(component=name):
                overrides = {name: component}
                if name != "triage":
                    overrides["triage"] = triage_ok(f"dedup-error-{name}")
                gate = self.gate(**overrides, max_attempts=1)
                result = await gate.evaluate(self.request(case_id=f"case-{name}"))
                self.assertEqual(result.status, PromotionStatus.PARKED)
                self.assertTrue(result.reason.startswith(f"{name}_error:RuntimeError"))

    async def test_component_invalid_results_are_contained(self) -> None:
        cases = {
            "triage": (
                "triage",
                SimpleNamespace(classify=AsyncMock(return_value="bad")),
                "triage_result_invalid",
            ),
            "ladder": (
                "ladder",
                SimpleNamespace(climb=AsyncMock(return_value="bad")),
                "ladder_result_invalid",
            ),
            "groom": (
                "groom",
                SimpleNamespace(validate=AsyncMock(return_value="bad")),
                "groom_result_invalid",
            ),
            "dupe": (
                "dupe",
                SimpleNamespace(score=AsyncMock(return_value="bad")),
                "dupe_result_invalid",
            ),
            "reviewer": (
                "reviewer",
                SimpleNamespace(review=AsyncMock(return_value="bad")),
                "reviewer_result_invalid",
            ),
        }
        for name, (gate_key, component, reason) in cases.items():
            with self.subTest(component=name):
                overrides = {gate_key: component}
                if gate_key != "triage":
                    overrides["triage"] = triage_ok(f"dedup-invalid-{name}")
                gate = self.gate(**overrides, max_attempts=1)
                result = await gate.evaluate(self.request(case_id=f"case-invalid-{name}"))
                self.assertEqual(result.status, PromotionStatus.PARKED)
                self.assertEqual(result.reason, reason)

    async def test_concurrent_identical_evaluations_promote_once(self) -> None:
        gate = self.gate()
        req = self.request()
        results = await asyncio.gather(*(gate.evaluate(req) for _ in range(3)))
        self.assertEqual(sum(result.status is PromotionStatus.PROMOTED for result in results), 1)
        self.assertEqual(
            sum(result.status is PromotionStatus.ALREADY_PROMOTED for result in results), 2
        )
        claim_ids = {result.claim_id for result in results}
        self.assertEqual(len(claim_ids), 1)
        claim_id = next(iter(claim_ids))
        assert claim_id is not None
        self.assertEqual(self.ledger.get_claim(claim_id)["state"], "promoted")
        self.assertEqual(len(self.ledger.verdicts_for_claim(claim_id)), 1)
        self.assertEqual(len(self.ledger.claims_by_type("bug_class")), 1)
        self.assertEqual(len(self.ledger.claims_by_type("rung")), 1)
        self.assertEqual(len(self.ledger.claims_by_type("groom")), 1)
        self.assertEqual(len(self.ledger.claims_by_type("dupe_score")), 1)

    def test_constructor_and_request_validation_edges(self) -> None:
        with self.assertRaises(ValueError):
            PromotionGate(self.ledger, max_attempts=0)
        with self.assertRaises(ValueError):
            LedgerPolicyGate(self.ledger, spend_cap_usd_micro=-1)
        requests = [
            PromotionRequest(
                case_id=" ", artifacts=(EvidenceArtifact(kind="k", data=b"x"),)
            ),
            self.request(attempt=-1),
            PromotionRequest(case_id="case-1", artifacts=()),
            PromotionRequest(
                case_id="case-1", artifacts=(EvidenceArtifact(kind=" ", data=b"x"),)
            ),
            self.request(estimated_cost_usd_micro=True),
            self.request(estimated_cost_usd_micro=-1),
        ]
        for req in requests:
            with self.subTest(req=req), self.assertRaises(ValueError):
                req.validated()

    def test_json_submission_and_view_helpers(self) -> None:
        self.assertEqual(json_loads('{"a": 1}'), {"a": 1})
        views = self.request().artifact_views()
        self.assertEqual(sorted_artifact_views(views), views)
        entry = SubmissionEntry(
            claim_id="cl_1", bug_class="uaf", primitive="rel_rw", dupe_score=0.5, created=0
        )
        with_submission = PromotionResult(
            status=PromotionStatus.PROMOTED,
            reason="ok",
            claim_id="cl_1",
            stage=PromotionStage.PROMOTE,
            submission=entry,
        ).to_dict()
        self.assertEqual(with_submission["submission"]["claim_id"], "cl_1")
        without_submission = PromotionResult(status=PromotionStatus.PROMOTED, reason="ok").to_dict()
        self.assertIsNone(without_submission["submission"])

    async def test_private_guard_paths(self) -> None:
        gate = self.gate()
        req = self.request()
        with self.assertRaises(FormatFail):
            await gate._ensure_state("cl_missing", ClaimState.BOUND)
        self.assertIsNone(gate._submission_for("cl_missing"))
        self.assertIsNone(
            gate._entry_for_row(
                {
                    "type": "rung",
                    "state": "promoted",
                    "id": "cl_1",
                    "value_json": "{}",
                    "created": 0,
                },
                0.0,
            )
        )
        with self.assertRaises(FormatFail):
            await gate._record_stage_claim("bogus", "cl_x", req, {}, None)
        with self.assertRaises(FormatFail):
            PromotionGate._verify_main_claim_identity(
                {"id": "cl_x", "value_json": "{}"}, "cl_y", "uaf", "rel_rw"
            )
        with self.assertRaises(FormatFail):
            PromotionGate._verify_main_claim_identity(
                {"id": "cl_1", "value_json": "{"}, "cl_1", "uaf", "rel_rw"
            )
        with self.assertRaises(FormatFail):
            PromotionGate._verify_main_claim_identity(
                {"id": "cl_1", "value_json": json.dumps({"gate": "other"})},
                "cl_1",
                "uaf",
                "rel_rw",
            )

    async def test_component_result_type_edges(self) -> None:
        with self.assertRaises(FormatFail):
            await self.gate(triage=triage_ok(bug_class=123)).evaluate(self.request())
        with self.assertRaises(FormatFail):
            await self.gate(triage=triage_ok(confidence=True)).evaluate(self.request())
        gate = self.gate(dupe=dupe_ok(saturation=1.2))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.REQUEUED)
        self.assertEqual(result.reason, "dupe_term_invalid")

    def test_review_verdict_and_helper_edges(self) -> None:
        bad_verdicts = [
            verdict(reviewer=" "),
            verdict(bug_class=" "),
            verdict(reviewer_family=" "),
            verdict(reason=123),
            verdict(confidence=2.0),
            verdict(artifact=object()),
        ]
        for item in bad_verdicts:
            with self.subTest(item=item), self.assertRaises(FormatFail):
                PromotionGate._validate_review_verdict(item)
        disagreement = PromotionGate._agreement(
            self.request(), verdict(bug_class="oob"), "uaf", "rel_rw"
        )
        self.assertEqual(disagreement[1], "reviewer_disagreement")
        family_req = self.request(proposer_family="family-a")
        unknown_family = PromotionGate._agreement(
            family_req, verdict(reviewer_family=None), "uaf", "rel_rw"
        )
        self.assertEqual(unknown_family[1], "reviewer_family_unknown")
        bad_assertions = LadderResult(
            status=LadderStatus.PASSED,
            rung="rel_rw",
            assertions=(123,),
            consecutive_passes=3,
            required_passes=3,
        )
        self.assertEqual(PromotionGate._ladder_proof_error(bad_assertions), "ladder_assertions_missing")
        bad_passes = LadderResult(
            status=LadderStatus.PASSED,
            rung="rel_rw",
            assertions=("assert-a",),
            consecutive_passes=3,
            required_passes=True,
        )
        self.assertEqual(PromotionGate._ladder_proof_error(bad_passes), "ladder_passes_insufficient")

    async def test_dupe_score_parser_ignores_malformed_rows(self) -> None:
        artifact = ArtifactInput(kind="result", data=b"{}")
        rows = [
            "[]",
            json.dumps({"claim_id": 1, "result": {}}),
            json.dumps({"claim_id": "cl_x", "result": {"status": "retry", "score": 1.0}}),
            json.dumps({"claim_id": "cl_y", "result": {"status": "scored", "score": float("nan")}}),
        ]
        for index, value_json in enumerate(rows):
            await self.ledger.create_claim(
                ClaimInput(
                    claim_id=f"cl_bad_{index}",
                    type="dupe_score",
                    value_json=value_json,
                    confidence=1.0,
                    dedup_key=f"bad-dupe-{index}",
                    created=0,
                    artifacts=(ClaimArtifactInput(artifact=artifact, role="result"),),
                )
            )
        self.assertEqual(self.gate()._dupe_scores(), {})
        self.assertEqual(self.gate().submission_queue(), [])

    async def test_fallback_dedup_and_triage_artifact_are_bound(self) -> None:
        triage_artifact = EvidenceArtifact(kind="triage", data=b"triage", role="triage")
        gate = self.gate(triage=triage_ok(dedup=None, artifact=triage_artifact))
        result = await gate.evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.PROMOTED)
        assert result.claim_id is not None
        roles = {str(row["role"]) for row in self.ledger.claim_artifacts(result.claim_id)}
        self.assertIn("triage", roles)

    async def test_existing_claim_binds_new_evidence_artifacts(self) -> None:
        triage = triage_ok("dedup-bind")
        gate = self.gate(
            triage=triage,
            ladder=ladder_ok(status=LadderStatus.RETRY, reason="wait"),
        )
        first = await gate.evaluate(self.request("case-bind", b"crash"))
        self.assertEqual(first.status, PromotionStatus.REQUEUED)
        assert first.claim_id is not None
        before = self.ledger.claim_artifact_count(first.claim_id)
        second_req = self.request(
            "case-bind",
            b"crash",
            artifacts=(
                EvidenceArtifact(kind="crash", data=b"crash", role="crash"),
                EvidenceArtifact(kind="note", data=b"extra", role="note"),
            ),
        )
        second = await gate.evaluate(second_req)
        self.assertEqual(second.claim_id, first.claim_id)
        self.assertEqual(second.reason, "wait")
        self.assertGreater(self.ledger.claim_artifact_count(first.claim_id), before)

    async def test_stage_proof_artifacts_are_recorded(self) -> None:
        proof = EvidenceArtifact(kind="proof", data=b"proof", role="proof")
        result = await self.gate(ladder=ladder_ok(artifact=proof)).evaluate(self.request())
        self.assertEqual(result.status, PromotionStatus.PROMOTED)
        rung_claim_id = result.details["ladder_claim_id"]
        assert isinstance(rung_claim_id, str)
        roles = {str(row["role"]) for row in self.ledger.claim_artifacts(rung_claim_id)}
        self.assertIn("proof", roles)


if __name__ == "__main__":
    unittest.main()
