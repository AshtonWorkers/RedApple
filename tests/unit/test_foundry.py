"""RA-FND Foundry acceptance tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ra.foundry import (
    AcceptanceMeasurements,
    ContentAddressedStore,
    DialectDefect,
    Foundry,
    HarnessSpec,
    JsonFoundryStore,
    evaluate_acceptance,
    load_dialect_file,
)

GOOD_COVERAGE = (
    "COVERAGE:\n"
    "COVERED_FUNC: hits: 10 edges: 2/2 parser_malloc(unsigned long) harness.cc:10\n"
)
BAD_COVERAGE = "COVERAGE:\nCOVERED_FUNC: hits: 10 edges: 2/2 LLVMFuzzerTestOneInput harness.cc:20\n"

VALID_DIALECT = {
    "format": "heif",
    "pre_seed": [{"box": "meta", "pad_to_class": "kalloc_1024"}, {"box": "iprp", "count": 8}],
    "victim_pad": "align_to_class",
    "victim_class": "kalloc_2048",
    "post": {"free": "ipco_before_victim"},
    "validator": "heap_diff.class_stable",
}


def measurements(**overrides) -> AcceptanceMeasurements:
    values = {
        "compiled": True,
        "edges_per_sec": 1000.0,
        "surface_median_edges_per_sec": 1000.0,
        "coverage_map": GOOD_COVERAGE,
        "dry_run_seconds": 600.0,
    }
    values.update(overrides)
    return AcceptanceMeasurements(**values)


class FoundryTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.store = JsonFoundryStore(self.root / "store")
        self.cas = ContentAddressedStore(self.root / "cas")
        self.foundry = Foundry(self.store, self.cas)

    async def asyncTearDown(self) -> None:
        self._tmp.cleanup()

    def make_harness(self, dialect=None) -> HarnessSpec:
        directory = self.root / "harness"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "harness.cc").write_text("int LLVMFuzzerTestOneInput() { return 0; }\n")
        (directory / "heif.dialect.json").write_text(
            json.dumps(VALID_DIALECT if dialect is None else dialect)
        )
        return HarnessSpec(
            id="test_heif",
            format="heif",
            directory=directory,
            source="harness.cc",
            dialect="heif.dialect.json",
            manifest=None,
        )

    async def test_RA_FND_001(self) -> None:
        accepted = evaluate_acceptance(measurements())
        self.assertTrue(accepted.accepted)
        self.assertEqual(
            accepted.checks,
            {
                "compiles": True,
                "edges_sec_ge_60pct_surface_median": True,
                "parser_malloc_in_coverage": True,
            },
        )

        for bad in (
            measurements(compiled=False),
            measurements(edges_per_sec=599.0),
            measurements(coverage_map=BAD_COVERAGE),
        ):
            decision = evaluate_acceptance(bad)
            self.assertFalse(decision.accepted)
            self.assertTrue(decision.reasons)

    async def test_RA_FND_002(self) -> None:
        spec = self.make_harness()
        dialect = await self.foundry.load_dialect(spec)
        self.assertEqual(dialect.validator, "heap_diff.class_stable")
        self.assertEqual(dialect.validator_requirement, "RA-GRM-002")

        bad = dict(VALID_DIALECT)
        bad["validator"] = "heap_diff.not_a_section_11_assertion"
        bad_spec = self.make_harness(dialect=bad)
        with self.assertRaises(DialectDefect):
            await self.foundry.submit(bad_spec, measurements())
        self.assertEqual(await self.store.list_ids(), [])

        schema_bad = dict(VALID_DIALECT)
        schema_bad["unexpected"] = True
        with self.assertRaises(DialectDefect):
            load_dialect_file(
                self.make_harness(dialect=schema_bad).dialect_path()
            )

    async def test_RA_FND_003(self) -> None:
        spec = self.make_harness()
        outcome = await self.foundry.submit(
            spec, measurements(coverage_map=BAD_COVERAGE)
        )
        self.assertEqual(outcome.status, "reprompt")
        self.assertEqual(outcome.state.foundry_defect, 1)
        self.assertIsNotNone(outcome.reprompt)
        assert outcome.reprompt is not None
        self.assertEqual(outcome.reprompt["task_type"], "harness_synth")
        self.assertEqual(
            outcome.reprompt["failing_artifact_id"], outcome.artifact_ids[0]
        )
        self.assertTrue(
            any(
                "parser_malloc_in_coverage" in reason
                for reason in outcome.reprompt["decision"]["reasons"]
            )
        )

        stored = await self.cas.get(outcome.artifact_ids[0])
        payload = json.loads(stored.decode("utf-8"))
        self.assertFalse(payload["decision"]["accepted"])
        self.assertEqual(payload["measurements"]["coverage_map"], BAD_COVERAGE)

    async def test_RA_FND_004(self) -> None:
        spec = self.make_harness()
        outcome = await self.foundry.submit(spec, measurements())
        self.assertEqual(outcome.status, "accepted")
        self.assertIsNotNone(outcome.state.last_good_artifact_id)

        original = spec.source_path().read_bytes()
        spec.source_path().write_text("// broken candidate\n")
        target = self.root / "rollback"
        result = await self.foundry.rollback(spec.id, target)
        self.assertLess(result.elapsed_ms, 10_000)
        self.assertEqual((target / spec.source).read_bytes(), original)
        self.assertEqual((target / spec.dialect).read_bytes(), spec.dialect_path().read_bytes())

    async def test_RA_FND_005(self) -> None:
        spec = self.make_harness()
        outcomes = [
            await self.foundry.submit(spec, measurements(coverage_map=BAD_COVERAGE))
            for _ in range(3)
        ]
        self.assertEqual([o.status for o in outcomes], ["reprompt", "reprompt", "parked"])
        self.assertEqual(outcomes[-1].state.state, "parked")
        self.assertEqual(outcomes[-1].state.foundry_defect, 3)
        self.assertEqual(len(outcomes[-1].state.attempts), 3)
        self.assertTrue(all(not a.accepted for a in outcomes[-1].state.attempts))


if __name__ == "__main__":
    unittest.main()
