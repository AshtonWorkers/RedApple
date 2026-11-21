"""RA-FND Foundry orchestration tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ra.foundry import (
    AcceptanceMeasurements,
    ContentAddressedStore,
    DialectDefect,
    Foundry,
    FoundryError,
    FoundryState,
    HarnessSpec,
    JsonFoundryStore,
    SynthesisRequest,
    SynthesizedHarness,
    TemplateHarnessSynthesizer,
)

from .helpers import BAD_COVERAGE, VALID_DIALECT, measurements, write_harness


class FakeMeasurer:
    def __init__(self, results: list[AcceptanceMeasurements]) -> None:
        self.results = list(results)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        spec: HarnessSpec,
        manifest: dict[str, object],
        workdir: Path,
        corpus_dir: Path,
        surface_median_edges_per_sec: float | None = None,
        *,
        clangxx: str | None = None,
        dry_run_seconds: float | None = None,
        run_baseline: bool = True,
    ) -> AcceptanceMeasurements:
        self.calls.append(
            {
                "spec": spec,
                "manifest": manifest,
                "workdir": workdir,
                "corpus_dir": corpus_dir,
                "surface_median_edges_per_sec": surface_median_edges_per_sec,
                "clangxx": clangxx,
                "dry_run_seconds": dry_run_seconds,
                "run_baseline": run_baseline,
            }
        )
        if not self.results:
            raise AssertionError("FakeMeasurer ran out of results")
        return self.results.pop(0)


class RecordingSynthesizer:
    def __init__(self) -> None:
        self.requests: list[SynthesisRequest] = []
        self._inner = TemplateHarnessSynthesizer()

    def synthesize(self, request: SynthesisRequest) -> SynthesizedHarness:
        self.requests.append(request)
        return self._inner.synthesize(request)


class UnsafeSynthesizer:
    def synthesize(self, request: SynthesisRequest) -> SynthesizedHarness:
        return SynthesizedHarness(files={"../evil": b"x"}, manifest={})


class FoundryTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.store = JsonFoundryStore(self.root / "store")
        self.cas = ContentAddressedStore(self.root / "cas")
        self.foundry = Foundry(self.store, self.cas, workroot=self.root / "work")

    async def asyncTearDown(self) -> None:
        self._tmp.cleanup()

    async def test_submit_measurements_accepts_and_stores_artifacts(self) -> None:
        spec = write_harness(self.root)
        outcome = await self.foundry.submit_measurements(spec, measurements())
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.to_dict()["state"], "accepted")
        self.assertFalse(outcome.parked)
        self.assertEqual(outcome.state.state, "accepted")
        self.assertIsNotNone(outcome.bundle_artifact_id)
        self.assertEqual(outcome.state.last_good_artifact_id, outcome.bundle_artifact_id)
        self.assertIsNone(outcome.reprompt)

        stored = await self.store.load(spec.id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.state, "accepted")
        self.assertEqual(len(stored.attempts), 1)
        self.assertEqual(stored.attempts[0].measurement_artifact_id, outcome.measurement_artifact_id)

        payload = json.loads((await self.cas.get(outcome.measurement_artifact_id)).decode())
        self.assertTrue(payload["decision"]["accepted"])
        self.assertEqual(payload["measurements"]["throughput_metric"], "coverage_edges_per_sec")
        target = self.root / "bundle"
        await self.cas.extract_harness(outcome.bundle_artifact_id, target)  # type: ignore[arg-type]
        self.assertTrue((target / "harness.cc").exists())
        self.assertTrue((target / "heif.dialect.json").exists())
        states = await self.foundry.list_states()
        self.assertEqual(len(states), 1)

    async def test_reprompt_then_park_after_three_failures(self) -> None:
        spec = write_harness(self.root)
        bad = measurements(coverage_map=BAD_COVERAGE)
        first = await self.foundry.submit_measurements(spec, bad)
        self.assertFalse(first.accepted)
        self.assertEqual(first.state.state, "reprompt")
        self.assertFalse(first.parked)
        self.assertIsNotNone(first.reprompt)
        assert first.reprompt is not None
        self.assertEqual(first.reprompt["task_type"], "harness_synth")
        self.assertEqual(first.reprompt["harness_id"], spec.id)
        self.assertIn("parser_malloc_in_coverage", first.reprompt["decision"]["reasons"])
        self.assertEqual(first.reprompt["failing_measurement"]["coverage_map"], BAD_COVERAGE)

        second = await self.foundry.submit_measurements(spec, bad)
        self.assertEqual(second.state.state, "reprompt")
        self.assertEqual(second.state.reprompt_count, 2)

        third = await self.foundry.submit_measurements(spec, bad)
        self.assertTrue(third.parked)
        self.assertIsNone(third.reprompt)
        self.assertEqual(third.state.state, "parked")
        self.assertEqual(third.state.foundry_defect_count, 3)
        self.assertEqual(third.state.reprompt_count, 2)
        self.assertEqual(len(third.state.attempts), 3)
        self.assertTrue(all(not attempt.decision.accepted for attempt in third.state.attempts))

        with self.assertRaises(FoundryError):
            await self.foundry.submit_measurements(spec, measurements())

    async def test_dialect_defect_blocks_before_side_effects(self) -> None:
        bad = dict(VALID_DIALECT)
        bad["validator"] = "heap_diff.not_a_section_11_assertion"
        spec = write_harness(self.root, dialect=bad)
        with self.assertRaises(DialectDefect):
            await self.foundry.submit_measurements(spec, measurements())
        self.assertEqual(await self.store.list_ids(), [])
        with self.assertRaises(DialectDefect):
            await self.foundry.submit_candidate(spec)
        self.assertEqual(await self.store.list_ids(), [])

    async def test_submit_alias(self) -> None:
        spec = write_harness(self.root)
        outcome = await self.foundry.submit(spec, measurements())
        self.assertTrue(outcome.accepted)

    async def test_rollback_restores_last_good_bundle(self) -> None:
        spec = write_harness(self.root)
        original = spec.source_path.read_bytes()
        await self.foundry.submit_measurements(spec, measurements())
        spec.source_path.write_text("// broken candidate\n", encoding="utf-8")
        target = self.root / "restored"
        state = await self.foundry.rollback(spec.id, target)
        self.assertEqual(state.state, "candidate")
        self.assertEqual((target / "harness.cc").read_bytes(), original)
        self.assertEqual((target / "heif.dialect.json").read_bytes(), spec.dialect_path.read_bytes())

    async def test_rollback_errors(self) -> None:
        with self.assertRaises(FoundryError):
            await self.foundry.rollback("missing")
        await self.store.save(FoundryState(harness_id="no_good", format="heif"))
        with self.assertRaises(FoundryError):
            await self.foundry.rollback("no_good")

    async def test_rollback_budget_enforced(self) -> None:
        spec = write_harness(self.root)
        await self.foundry.submit_measurements(spec, measurements())
        with (
            mock.patch("ra.foundry.foundry.now_ms", side_effect=[1000, 11000, 11000]),
            self.assertRaises(FoundryError),
        ):
            await self.foundry.rollback(spec.id)

    async def test_submit_candidate_synthesizes_measures_and_stores_bundle(self) -> None:
        spec = write_harness(self.root, harness_id="synth")
        measurer = FakeMeasurer([measurements()])
        synthesizer = RecordingSynthesizer()
        foundry = Foundry(
            self.store,
            self.cas,
            synthesizer=synthesizer,
            measurer=measurer,
            workroot=self.root / "work",
        )
        outcome = await foundry.submit_candidate(
            spec,
            surface_median_edges_per_sec=1000.0,
            dry_run_seconds=1.0,
            run_baseline=False,
        )
        self.assertTrue(outcome.accepted)
        self.assertEqual(len(measurer.calls), 1)
        call = measurer.calls[0]
        candidate = call["spec"]
        assert isinstance(candidate, HarnessSpec)
        self.assertEqual(candidate.source, "LLVMFuzzerTestOneInput.cc")
        self.assertEqual(candidate.dialect, "groom-dialect.json")
        self.assertEqual(candidate.manifest, "harness.json")
        self.assertEqual(call["run_baseline"], False)
        self.assertEqual(call["dry_run_seconds"], 1.0)
        self.assertTrue(candidate.source_path.exists())
        self.assertTrue(candidate.dialect_path.exists())
        assert candidate.manifest_path is not None
        self.assertTrue(candidate.manifest_path.exists())
        corpus_dir = call["corpus_dir"]
        assert isinstance(corpus_dir, Path)
        self.assertTrue((corpus_dir / "seed_000").exists())

        self.assertEqual(len(synthesizer.requests), 1)
        request = synthesizer.requests[0]
        self.assertEqual(request.attempt, 1)
        self.assertIsNone(request.feedback)
        self.assertEqual(request.dialect_bytes, spec.dialect_path.read_bytes())

        target = self.root / "synth-bundle"
        await self.cas.extract_harness(outcome.bundle_artifact_id, target)  # type: ignore[arg-type]
        self.assertTrue((target / "LLVMFuzzerTestOneInput.cc").exists())
        self.assertTrue(any(path.name.startswith("seed_") for path in (target / "corpus").iterdir()))

    async def test_submit_candidate_passes_feedback_on_retry(self) -> None:
        spec = write_harness(self.root, harness_id="retry")
        measurer = FakeMeasurer([measurements(coverage_map=BAD_COVERAGE), measurements()])
        synthesizer = RecordingSynthesizer()
        foundry = Foundry(self.store, self.cas, synthesizer=synthesizer, measurer=measurer)
        first = await foundry.submit_candidate(spec, surface_median_edges_per_sec=1000.0)
        self.assertFalse(first.accepted)
        second = await foundry.submit_candidate(spec, surface_median_edges_per_sec=1000.0)
        self.assertTrue(second.accepted)
        self.assertEqual(len(synthesizer.requests), 2)
        feedback = synthesizer.requests[1].feedback
        self.assertIsNotNone(feedback)
        assert feedback is not None
        self.assertEqual(feedback["attempt"], 1)
        self.assertIn("parser_malloc_in_coverage", feedback["reasons"])
        self.assertEqual(synthesizer.requests[1].attempt, 2)

    async def test_submit_candidate_parked_raises_before_work(self) -> None:
        spec = write_harness(self.root, harness_id="parked")
        await self.store.save(FoundryState(harness_id=spec.id, format=spec.format, state="parked"))
        measurer = FakeMeasurer([])
        synthesizer = RecordingSynthesizer()
        foundry = Foundry(self.store, self.cas, synthesizer=synthesizer, measurer=measurer)
        with self.assertRaises(FoundryError):
            await foundry.submit_candidate(spec)
        self.assertEqual(measurer.calls, [])
        self.assertEqual(synthesizer.requests, [])

    async def test_submit_candidate_manifest_validation(self) -> None:
        for index, manifest in enumerate(
            [
                {"compile_args": "-O2"},
                {"surface_median_edges_per_sec": "high"},
                {"surface_median_edges_per_sec": True},
                {"dry_run_seconds": "soon"},
                {"dry_run_seconds": True},
            ]
        ):
            spec = write_harness(self.root, harness_id=f"badmanifest{index}", manifest=manifest)
            measurer = FakeMeasurer([])
            synthesizer = RecordingSynthesizer()
            foundry = Foundry(self.store, self.cas, synthesizer=synthesizer, measurer=measurer)
            with self.subTest(manifest=manifest), self.assertRaises(FoundryError):
                await foundry.submit_candidate(spec)
            self.assertEqual(synthesizer.requests, [])
            self.assertEqual(measurer.calls, [])

    async def test_list_states_skips_missing_state(self) -> None:
        class GhostStore:
            async def load(self, harness_id: str) -> FoundryState | None:
                return None

            async def save(self, state: FoundryState) -> None:
                return None

            async def list_ids(self) -> list[str]:
                return ["ghost"]

        foundry = Foundry(GhostStore(), self.cas)  # type: ignore[arg-type]
        self.assertEqual(await foundry.list_states(), [])

    async def test_submit_candidate_rejects_unsafe_synthesized_path(self) -> None:
        spec = write_harness(self.root, harness_id="unsafe")
        foundry = Foundry(self.store, self.cas, synthesizer=UnsafeSynthesizer(), measurer=FakeMeasurer([]))
        with self.assertRaises(FoundryError):
            await foundry.submit_candidate(spec)


if __name__ == "__main__":
    unittest.main()
