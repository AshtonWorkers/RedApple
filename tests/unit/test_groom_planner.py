"""RA-GRM groom planner acceptance tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from ra.errors import DialectDefect
from ra.groom import (
    AllocatorModelSet,
    CrashCase,
    FoundryDialectValidator,
    GroomCandidate,
    GroomPlanner,
    GroomService,
    LedgerFoundryDefectSink,
    TriageResult,
    load_allocator_models,
)
from ra.ledger import Ledger


class RecordingDefectSink:
    def __init__(self) -> None:
        self.defects: list[dict[str, Any]] = []

    async def report_dialect_defect(self, *, candidate: GroomCandidate, case: CrashCase, error: str) -> None:
        self.defects.append({"candidate_id": candidate.candidate_id, "crash_id": case.id, "error": error})


class RejectingGate:
    def validate(self, dialect: Any) -> None:
        raise DialectDefect("injected dialect defect")


class HintTriage:
    async def classify(self, case: CrashCase) -> TriageResult:
        return TriageResult(
            bug_class="heap_overflow",
            primitive_hint="oob_read kalloc_2048",
            confidence=0.9,
            rationale="hinted",
            artifacts=(b"triage-bytes",),
        )


class GroomPlannerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = await Ledger.open(Path(self._tmp.name) / "ledger.sqlite")
        await self.ledger.create_run("macos", run_id="run_1")
        self.models: AllocatorModelSet = load_allocator_models()

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def case(self, **overrides: Any) -> CrashCase:
        values: dict[str, Any] = {
            "id": "crash_1",
            "target": "jsc",
            "ring_node": "macos_15_0",
            "payload": b"crash-bytes",
            "bug_class": "heap_overflow kalloc_2048",
            "primitive_hint": "oob_read",
            "format": "heif",
            "run_id": "run_1",
            "metadata": {"size_kb": 1500},
        }
        values.update(overrides)
        return CrashCase(**values)

    async def test_RA_GRM_003_planner_candidates_caps_ledger_and_idempotency(self) -> None:
        planner = GroomPlanner(self.ledger, models=self.models, triage=HintTriage())
        outcome = await planner.plan(self.case())
        self.assertEqual(outcome.status, "planned")
        self.assertEqual(outcome.triage.bug_class, "heap_overflow")
        self.assertGreater(len(outcome.plan.candidates), 0)
        self.assertLessEqual(len(outcome.plan.candidates), 64)
        self.assertTrue(all(candidate.depth <= 3 for candidate in outcome.plan.candidates))
        self.assertEqual(
            len({candidate.candidate_id for candidate in outcome.plan.candidates}),
            len(outcome.plan.candidates),
        )
        self.assertTrue(
            all(
                candidate.dialect["validator"] == "heap_diff.class_stable"
                for candidate in outcome.plan.candidates
            )
        )
        self.assertIn("libpas_size_classes", outcome.plan.candidates[0].provenance)
        claim = self.ledger.get_claim(str(outcome.claim_id))
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim["type"], "groom")
        self.assertEqual(claim["state"], "reviewed")
        self.assertGreater(self.ledger.claim_artifact_count(str(outcome.claim_id)), 0)

        replay = await planner.plan(self.case())
        self.assertEqual(replay.plan.plan_id, outcome.plan.plan_id)
        self.assertEqual(replay.claim_id, outcome.claim_id)

    async def test_RA_GRM_003_search_respects_depth_and_candidate_caps(self) -> None:
        planner = GroomPlanner(self.ledger, models=self.models)
        for index in range(6):
            outcome = await planner.plan(self.case(id=f"crash_cap_{index}", metadata={"size_kb": 100 * (index + 1)}))
            self.assertLessEqual(len(outcome.plan.candidates), 64)
            self.assertTrue(all(candidate.depth <= 3 for candidate in outcome.plan.candidates))
            self.assertGreaterEqual(outcome.plan.stats["memo_hits"], 0)

    async def test_RA_GRM_004_invalid_groom_returns_dialect_defect_to_foundry(self) -> None:
        gate: FoundryDialectValidator = RejectingGate()
        sink = RecordingDefectSink()
        planner = GroomPlanner(self.ledger, models=self.models, gate=gate, defect_sink=sink)
        outcome = await planner.plan(self.case())
        self.assertEqual(outcome.status, "defect")
        self.assertEqual(outcome.plan.candidates, ())
        self.assertTrue(outcome.defects)
        self.assertGreater(len(sink.defects), 0)
        claim = self.ledger.get_claim(str(outcome.claim_id))
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertIn('"status":"defect"', str(claim["value_json"]))

    async def test_foundry_defect_sink_persists_ledger_work_order(self) -> None:
        sink = LedgerFoundryDefectSink(self.ledger)
        candidate = GroomCandidate(
            candidate_id="groom_test",
            depth=1,
            score=1.0,
            dialect={"validator": "heap_diff.class_stable"},
            size_class="kalloc_1024",
        )
        await sink.report_dialect_defect(candidate=candidate, case=self.case(), error="bad dialect")
        rows = self.ledger.work_orders_for_unit("groom:groom_test")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "widen_dialect")
        self.assertEqual(rows[0]["state"], "dialect_defect")
        self.assertIn("bad dialect", str(rows[0]["payload_json"]))

    async def test_planner_uses_mapping_and_static_triage(self) -> None:
        service = GroomService.create(self.ledger, models=self.models)
        result = await service.process_mapping(
            {
                "crash_id": "crash_mapping",
                "handle_id": "handle_1",
                "build": "macos_15_1",
                "payload": "bytes",
                "bug_class": "uaf",
                "metadata": {"size_kb": 20, "primitive_hint": "info_leak kalloc_1024"},
            }
        )
        self.assertEqual(result.case.id, "crash_mapping")
        self.assertEqual(result.case.payload, b"bytes")
        self.assertEqual(result.plan.triage.bug_class, "uaf")
        self.assertEqual(result.plan.triage.primitive_hint, "info_leak kalloc_1024")
        self.assertEqual(result.ladder.status, "exhausted")
        self.assertEqual(result.ladder.error_code, "LADDER_EXHAUSTED")
        payload = result.to_dict()
        self.assertEqual(payload["plan"]["status"], "planned")
        self.assertEqual(payload["ladder"]["status"], "exhausted")


if __name__ == "__main__":
    unittest.main()
