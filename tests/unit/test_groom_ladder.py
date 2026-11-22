"""RA-LAD primitive ladder acceptance tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from ra.groom import (
    LADDER_ORDER,
    RUNG_ASSERTIONS,
    AttemptEvidence,
    CrashCase,
    GroomCandidate,
    GroomPlan,
    HeapObject,
    HeapSnapshot,
    LadderRung,
    LadderRunner,
    TriageResult,
    validate_heap_diff,
)
from ra.ledger import Ledger


def dialect(size_class: str = "kalloc_2048") -> dict[str, Any]:
    return {
        "format": "heif",
        "pre_seed": [{"box": "meta", "pad_to_class": "kalloc_1024", "count": 2}],
        "victim_pad": "align_to_class",
        "victim_class": size_class,
        "post": {"free": "ipco_before_victim"},
        "validator": "heap_diff.class_stable",
    }


def candidate(candidate_id: str = "groom_a", size_class: str = "kalloc_2048") -> GroomCandidate:
    return GroomCandidate(
        candidate_id=candidate_id,
        depth=1,
        score=1.0,
        dialect=dialect(size_class),
        size_class=size_class,
        provenance={"libpas_size_classes": "https://example.com/libpas"},
        rationale="test candidate",
    )


def passing_evidence(rung: LadderRung, *, consecutive: int = 3) -> AttemptEvidence:
    assertion = RUNG_ASSERTIONS[rung]
    before = HeapSnapshot.from_objects("before", (HeapObject("kalloc_1024", role="seed"),))
    after = HeapSnapshot.from_objects(
        "after",
        (*before.objects, HeapObject("kalloc_2048", role="victim")),
    )
    return AttemptEvidence(
        rung=rung,
        passed=True,
        consecutive_passes=consecutive,
        assertion=assertion,
        assertion_results={assertion: True},
        heap_before=before,
        heap_after=after,
        artifact_payload=f"artifact-{rung.value}".encode(),
        details={"ok": True},
    )


def failing_evidence(rung: LadderRung) -> AttemptEvidence:
    return AttemptEvidence(rung=rung, passed=False, consecutive_passes=0, details={"reason": "no"})


class ScriptedAttemptPort:
    def __init__(self, outcomes: dict[LadderRung, Any]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[LadderRung, str]] = []

    async def attempt(self, *, rung: LadderRung, candidate: GroomCandidate, case: CrashCase) -> AttemptEvidence:
        self.calls.append((rung, candidate.candidate_id))
        outcome = self.outcomes.get(rung, failing_evidence(rung))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class RecordingDefectSink:
    def __init__(self) -> None:
        self.defects: list[tuple[str, str]] = []

    async def report_dialect_defect(self, *, candidate: GroomCandidate, case: CrashCase, error: str) -> None:
        self.defects.append((candidate.candidate_id, error))


class SelectAdvisor:
    def __init__(self, candidate_id: str, rung: LadderRung) -> None:
        self.candidate_id = candidate_id
        self.rung = rung
        self.rung_calls: list[LadderRung] = []

    async def advise_rung(self, *, case: CrashCase, triage: TriageResult, rung: LadderRung) -> str | None:
        self.rung_calls.append(rung)
        if rung == self.rung:
            return self.candidate_id
        return None

    async def advise_groom(self, *, case: CrashCase, triage: TriageResult) -> dict[str, Any] | None:
        return None


def plan(candidates: tuple[GroomCandidate, ...] = (candidate(),)) -> GroomPlan:
    return GroomPlan(plan_id="gplan_test", crash_id="crash_1", candidates=candidates)


class LadderRunnerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = await Ledger.open(Path(self._tmp.name) / "ledger.sqlite")
        await self.ledger.create_run("macos", run_id="run_1")
        self.case = CrashCase(id="crash_1", payload=b"crash", run_id="run_1")

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    async def test_RA_LAD_001_002_003_rungs_once_assertions_and_exhaustion(self) -> None:
        port = ScriptedAttemptPort({})
        runner = LadderRunner(self.ledger, attempt_port=port)
        outcome = await runner.run(self.case, plan())
        self.assertEqual([rung for rung, _ in port.calls], list(LADDER_ORDER))
        self.assertEqual(len(port.calls), 3)
        self.assertEqual(outcome.status, "exhausted")
        self.assertEqual(outcome.error_code, "LADDER_EXHAUSTED")
        self.assertEqual([result.rung for result in outcome.results], list(LADDER_ORDER))
        for result in outcome.results:
            self.assertEqual(result.assertion, RUNG_ASSERTIONS[result.rung])
            self.assertFalse(result.passed)
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "attempt_failed")
        claim = self.ledger.get_claim(str(outcome.claim_id))
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim["type"], "rung")
        self.assertEqual(claim["state"], "demoted")

    async def test_RA_LAD_004_promotion_requires_three_consecutive_passes(self) -> None:
        outcomes = {rung: passing_evidence(rung, consecutive=2) for rung in LADDER_ORDER}
        runner = LadderRunner(self.ledger, attempt_port=ScriptedAttemptPort(outcomes))
        outcome = await runner.run(self.case, plan())
        self.assertEqual(outcome.status, "rejected")
        self.assertTrue(all(result.passed for result in outcome.results))
        self.assertTrue(all(not result.promoted for result in outcome.results))
        claim = self.ledger.get_claim(str(outcome.claim_id))
        assert claim is not None
        self.assertEqual(claim["state"], "demoted")

        promoted_outcomes = {rung: passing_evidence(rung, consecutive=3) for rung in LADDER_ORDER}
        promoted_runner = LadderRunner(self.ledger, attempt_port=ScriptedAttemptPort(promoted_outcomes))
        promoted = await promoted_runner.run(self.case, plan())
        self.assertEqual(promoted.status, "promoted")
        self.assertEqual(promoted.highest_promoted, LadderRung.REL_RW)
        self.assertTrue(all(result.promoted for result in promoted.results))
        promoted_claim = self.ledger.get_claim(str(promoted.claim_id))
        assert promoted_claim is not None
        self.assertEqual(promoted_claim["state"], "promoted")

    async def test_partial_promotion_stays_reviewed(self) -> None:
        outcomes = {
            LadderRung.INFO_LEAK: passing_evidence(LadderRung.INFO_LEAK, consecutive=3),
            LadderRung.OOB_READ: failing_evidence(LadderRung.OOB_READ),
            LadderRung.REL_RW: failing_evidence(LadderRung.REL_RW),
        }
        runner = LadderRunner(self.ledger, attempt_port=ScriptedAttemptPort(outcomes))
        outcome = await runner.run(self.case, plan())
        self.assertEqual(outcome.status, "partial")
        self.assertEqual(outcome.highest_promoted, LadderRung.INFO_LEAK)
        claim = self.ledger.get_claim(str(outcome.claim_id))
        assert claim is not None
        self.assertEqual(claim["state"], "reviewed")

    async def test_evaluate_failure_modes(self) -> None:
        bad_assertion = passing_evidence(LadderRung.INFO_LEAK, consecutive=3)
        bad_assertion = AttemptEvidence(
            rung=bad_assertion.rung,
            passed=bad_assertion.passed,
            consecutive_passes=bad_assertion.consecutive_passes,
            assertion="wrong.assertion",
            assertion_results=bad_assertion.assertion_results,
            heap_before=bad_assertion.heap_before,
            heap_after=bad_assertion.heap_after,
        )
        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort(
                {
                    LadderRung.INFO_LEAK: bad_assertion,
                    LadderRung.OOB_READ: failing_evidence(LadderRung.OOB_READ),
                    LadderRung.REL_RW: failing_evidence(LadderRung.REL_RW),
                }
            ),
        ).run(self.case, plan())
        self.assertEqual(outcome.results[0].reason, "assertion_mismatch")

        missing = AttemptEvidence(
            rung=LadderRung.INFO_LEAK,
            passed=True,
            consecutive_passes=3,
            assertion=RUNG_ASSERTIONS[LadderRung.INFO_LEAK],
            assertion_results={},
            heap_before=passing_evidence(LadderRung.INFO_LEAK).heap_before,
            heap_after=passing_evidence(LadderRung.INFO_LEAK).heap_after,
        )
        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort(
                {
                    LadderRung.INFO_LEAK: missing,
                    LadderRung.OOB_READ: failing_evidence(LadderRung.OOB_READ),
                    LadderRung.REL_RW: failing_evidence(LadderRung.REL_RW),
                }
            ),
        ).run(self.case, plan())
        self.assertEqual(outcome.results[0].reason, "assertion_missing")

        escaped = passing_evidence(LadderRung.INFO_LEAK, consecutive=3)
        escaped_after = HeapSnapshot.from_objects(
            "after",
            (
                HeapObject("kalloc_1024", role="seed"),
                HeapObject("kalloc_2048", role="victim"),
                HeapObject("kalloc_512", role="escape"),
            ),
        )
        escaped = AttemptEvidence(
            rung=escaped.rung,
            passed=escaped.passed,
            consecutive_passes=escaped.consecutive_passes,
            assertion=escaped.assertion,
            assertion_results=escaped.assertion_results,
            heap_before=escaped.heap_before,
            heap_after=escaped_after,
        )
        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort(
                {
                    LadderRung.INFO_LEAK: escaped,
                    LadderRung.OOB_READ: failing_evidence(LadderRung.OOB_READ),
                    LadderRung.REL_RW: failing_evidence(LadderRung.REL_RW),
                }
            ),
        ).run(self.case, plan())
        self.assertEqual(outcome.results[0].reason, "heap_diff_failed")

        no_heap = AttemptEvidence(
            rung=LadderRung.INFO_LEAK,
            passed=True,
            consecutive_passes=3,
            assertion=RUNG_ASSERTIONS[LadderRung.INFO_LEAK],
            assertion_results={RUNG_ASSERTIONS[LadderRung.INFO_LEAK]: True},
        )
        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort(
                {
                    LadderRung.INFO_LEAK: no_heap,
                    LadderRung.OOB_READ: failing_evidence(LadderRung.OOB_READ),
                    LadderRung.REL_RW: failing_evidence(LadderRung.REL_RW),
                }
            ),
        ).run(self.case, plan())
        self.assertEqual(outcome.results[0].reason, "heap_evidence_missing")

    async def test_rung_mismatch_dialect_defect_attempt_error_and_no_candidates(self) -> None:
        mismatched = passing_evidence(LadderRung.REL_RW, consecutive=3)
        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort(
                {
                    LadderRung.INFO_LEAK: mismatched,
                    LadderRung.OOB_READ: mismatched,
                    LadderRung.REL_RW: mismatched,
                }
            ),
        ).run(self.case, plan())
        self.assertTrue(all(result.reason == "rung_mismatch" for result in outcome.results[:2]))
        self.assertEqual(outcome.results[2].reason, "promoted")
        self.assertEqual(outcome.status, "promoted")

        invalid = GroomCandidate(
            candidate_id="groom_bad",
            depth=0,
            score=0.0,
            dialect={"format": "heif"},
            size_class="kalloc_1024",
        )
        sink = RecordingDefectSink()
        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort({}),
            defect_sink=sink,
        ).run(self.case, plan((invalid,)))
        self.assertTrue(all(result.reason == "DIALECT_DEFECT" for result in outcome.results))
        self.assertEqual(len(sink.defects), 3)

        outcome = await LadderRunner(
            self.ledger,
            attempt_port=ScriptedAttemptPort({rung: RuntimeError("boom") for rung in LADDER_ORDER}),
        ).run(self.case, plan())
        self.assertTrue(all(result.reason == "attempt_error:RuntimeError" for result in outcome.results))

        outcome = await LadderRunner(self.ledger, attempt_port=ScriptedAttemptPort({})).run(self.case, None)
        self.assertTrue(all(result.reason == "no_groom_candidates" for result in outcome.results))
        self.assertEqual(outcome.status, "exhausted")

    async def test_press_advisor_can_select_candidate(self) -> None:
        first = candidate("groom_a")
        second = candidate("groom_b", size_class="kalloc_1024")
        advisor = SelectAdvisor("groom_b", LadderRung.REL_RW)
        port = ScriptedAttemptPort({})
        runner = LadderRunner(self.ledger, attempt_port=port, advisor=advisor)
        await runner.run(self.case, plan((first, second)))
        rel_rw_candidate = port.calls[2][1]
        self.assertEqual(rel_rw_candidate, "groom_b")
        self.assertEqual(advisor.rung_calls, list(LADDER_ORDER))

    async def test_heap_diff_fixture_matches_ladder_evidence(self) -> None:
        evidence = passing_evidence(LadderRung.INFO_LEAK, consecutive=3)
        assert evidence.heap_before is not None and evidence.heap_after is not None
        result = validate_heap_diff(dialect(), evidence.heap_before, evidence.heap_after)
        self.assertTrue(result.passed)


if __name__ == "__main__":
    unittest.main()
