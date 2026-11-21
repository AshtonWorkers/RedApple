"""Foundry model serialization and path safety tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ra.foundry import (
    AcceptanceDecision,
    AcceptanceMeasurements,
    AttemptRecord,
    FoundryState,
    HarnessSpec,
    now_ms,
)

from .helpers import measurements, write_harness


class ModelsTest(unittest.TestCase):
    def test_harness_spec_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = write_harness(root)
            self.assertEqual(good.id, "test_heif")
            self.assertTrue(good.source_path.exists())
            self.assertEqual(good.to_dict()["source"], "harness.cc")
            self.assertEqual(HarnessSpec.from_dict(good.to_dict()), good)

            bad_specs = [
                {"id": "bad id", "format": "heif", "directory": root, "source": "a", "dialect": "b"},
                {"id": "ok", "format": "", "directory": root, "source": "a", "dialect": "b"},
                {"id": "ok", "format": "heif", "directory": root, "source": "/tmp/a", "dialect": "b"},
                {"id": "ok", "format": "heif", "directory": root, "source": "../a", "dialect": "b"},
                {"id": "ok", "format": "heif\n", "directory": root, "source": "a", "dialect": "b"},
                {"id": "ok", "format": "heif", "directory": root, "source": "", "dialect": "b"},
                {"id": "ok", "format": "heif", "directory": root, "source": "bad\nsource", "dialect": "b"},
            ]
            for kwargs in bad_specs:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    HarnessSpec(**kwargs)  # type: ignore[arg-type]

    def test_harness_spec_symlink_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside.cc"
            outside.write_text("int x;\n", encoding="utf-8")
            directory = root / "harness"
            directory.mkdir()
            (directory / "link.cc").symlink_to(outside)
            (directory / "dialect.json").write_text("{}", encoding="utf-8")
            spec = HarnessSpec(
                id="link",
                format="heif",
                directory=directory,
                source="link.cc",
                dialect="dialect.json",
            )
            with self.assertRaises(ValueError):
                _ = spec.source_path

    def test_bundle_files_include_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = write_harness(Path(tmp), manifest={"id": "test_heif", "format": "heif"})
            files = spec.bundle_files()
            self.assertEqual(set(files), {"harness.cc", "heif.dialect.json", "harness.json"})
            self.assertIn(b"LLVMFuzzerTestOneInput", files["harness.cc"])
            payload = spec.to_dict()
            self.assertEqual(payload["manifest"], "harness.json")
            self.assertEqual(HarnessSpec.from_dict(payload), spec)

    def test_measurement_decision_attempt_state_roundtrip(self) -> None:
        meas = measurements()
        decision = AcceptanceDecision(accepted=True, checks={"compiles": True}, reasons=())
        attempt = AttemptRecord(
            attempt_id="h:a001",
            harness_id="h",
            measurements=meas,
            decision=decision,
            measurement_artifact_id="m" * 64,
            created_at=now_ms(),
            bundle_artifact_id="b" * 64,
        )
        state = FoundryState(
            harness_id="h",
            format="heif",
            state="accepted",
            attempts=[attempt],
            last_good_artifact_id="b" * 64,
            reprompt_count=1,
            foundry_defect_count=2,
            updated_at=now_ms(),
        )
        restored = FoundryState.from_dict(state.to_dict())
        self.assertEqual(restored, state)
        self.assertEqual(restored.attempts[0].measurements, meas)
        self.assertEqual(restored.attempts[0].decision, decision)
        self.assertEqual(restored.attempt_count, 1)

    def test_state_defaults_and_dict_optional_fields(self) -> None:
        state = FoundryState(harness_id="h", format="heif")
        self.assertEqual(state.attempt_count, 0)
        payload = state.to_dict()
        self.assertNotIn("bundle_artifact_id", payload["attempts"])
        self.assertIsNone(payload["last_good_artifact_id"])
        restored = FoundryState.from_dict(payload)
        self.assertEqual(restored.state, "candidate")
        meas = AcceptanceMeasurements.from_dict(measurements().to_dict())
        self.assertEqual(meas.throughput_metric, "coverage_edges_per_sec")


if __name__ == "__main__":
    unittest.main()
