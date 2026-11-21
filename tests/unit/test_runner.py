"""Runner compile/dry-run measurement tests."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ra.foundry import (
    CompileResult,
    DryRunResult,
    FoundryError,
    compile_harness,
    harness_spec_from_manifest,
    load_manifest,
    measure_harness,
    resolve_clangxx,
    run_dry_run,
    run_seed_coverage,
)

from .helpers import write_harness

COVERAGE_OUTPUT = (
    "COVERED_FUNC: hits: 10 edges: 10/20 parser_malloc(unsigned long) harness.cc:10\n"
    "UNCOVERED_FUNC: hits: 0 edges: 0/5 parser_free harness.cc:20\n"
)


def dry_result(**overrides: object) -> DryRunResult:
    values = {
        "completed": True,
        "returncode": 0,
        "seconds": 2.0,
        "covered_edges": 10,
        "total_edges": 25,
        "baseline_covered_edges": 4,
        "new_covered_edges": 6,
        "edges_per_sec": 3.0,
        "output": "cov",
    }
    values.update(overrides)
    return DryRunResult(**values)  # type: ignore[arg-type]


class RunnerTest(unittest.TestCase):
    def test_resolve_clangxx(self) -> None:
        self.assertEqual(resolve_clangxx("explicit"), "explicit")
        self.assertEqual(resolve_clangxx(None, {"clangxx": "manifest-clang"}), "manifest-clang")
        with mock.patch.dict(os.environ, {"REDAPPLE_CLANGXX": "env-clang"}, clear=True):
            self.assertEqual(resolve_clangxx(), "env-clang")
        with mock.patch.dict(os.environ, {"CXX": "cxx-clang"}, clear=True):
            self.assertEqual(resolve_clangxx(), "cxx-clang")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_clangxx(), "clang++")

    def test_load_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.json"
            path.write_text(json.dumps({"id": "demo", "format": "heif"}), encoding="utf-8")
            self.assertEqual(load_manifest(path)["id"], "demo")
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(FoundryError):
                load_manifest(path)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(FoundryError):
                load_manifest(path)

    def test_harness_spec_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "harness.json").write_text(
                json.dumps(
                    {
                        "id": "demo",
                        "format": "heif",
                        "source": "LLVMFuzzerTestOneInput.cc",
                        "dialect": "demo.dialect.json",
                    }
                ),
                encoding="utf-8",
            )
            spec = harness_spec_from_manifest(root / "harness.json")
            self.assertEqual(spec.id, "demo")
            self.assertEqual(spec.manifest, "harness.json")
            self.assertEqual(spec.directory, root)

    def test_harness_spec_from_manifest_requires_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.json"
            path.write_text(json.dumps({"id": "demo"}), encoding="utf-8")
            with self.assertRaises(FoundryError):
                harness_spec_from_manifest(path)
            path.write_text(json.dumps({"format": "heif", "source": "a", "dialect": "b"}), encoding="utf-8")
            with self.assertRaises(FoundryError):
                harness_spec_from_manifest(path)
            path.write_text(
                json.dumps({"id": "bad id", "format": "heif", "source": "a", "dialect": "b"}),
                encoding="utf-8",
            )
            with self.assertRaises(FoundryError):
                harness_spec_from_manifest(path)

    def test_compile_harness_missing_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "h"
            directory.mkdir()
            (directory / "dialect.json").write_text("{}", encoding="utf-8")
            spec = write_harness(root, harness_id="h", source="missing.cc")
            # write_harness creates the source; remove it for this case.
            spec.source_path.unlink()
            with self.assertRaises(FoundryError):
                compile_harness(spec, root / "build")

    def test_compile_harness_success_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = write_harness(root)
            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="ok")
            with mock.patch("ra.foundry.runner._run_process", return_value=completed) as run:
                result = compile_harness(spec, root / "build", clangxx="clang++", extra_args=("-O2",))
            self.assertTrue(result.ok)
            self.assertEqual(result.binary_path.name, "test_heif_fuzzer")
            command = run.call_args.args[0]
            self.assertIn("-fsanitize=fuzzer,address,undefined", command)
            self.assertIn("-O2", command)
            self.assertIn(str(spec.source_path), command)

            failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="bad")
            with mock.patch("ra.foundry.runner._run_process", return_value=failed):
                result = compile_harness(spec, root / "build")
            self.assertFalse(result.ok)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.output, "bad")

    def test_run_process_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = write_harness(Path(tmp))
            with mock.patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="clang++", timeout=1)
            ), self.assertRaises(FoundryError):
                compile_harness(spec, Path(tmp) / "build", timeout_seconds=0.1)
            with (
                mock.patch("subprocess.run", side_effect=OSError("no exec")),
                self.assertRaises(FoundryError),
            ):
                compile_harness(spec, Path(tmp) / "build")

    def test_run_dry_run_edges_per_sec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=COVERAGE_OUTPUT, stderr="")
            with mock.patch("ra.foundry.runner._run_process", return_value=completed):
                result = run_dry_run(root / "bin", root / "corpus", 1.0, baseline_covered_edges=5)
            self.assertTrue(result.completed)
            self.assertEqual(result.covered_edges, 10)
            self.assertEqual(result.total_edges, 25)
            self.assertEqual(result.baseline_covered_edges, 5)
            self.assertEqual(result.new_covered_edges, 5)
            self.assertGreater(result.edges_per_sec, 0.0)

            failed = subprocess.CompletedProcess(args=[], returncode=1, stdout=COVERAGE_OUTPUT, stderr="")
            with mock.patch("ra.foundry.runner._run_process", return_value=failed):
                result = run_dry_run(root / "bin", root / "corpus", 1.0)
            self.assertFalse(result.completed)
            self.assertEqual(result.returncode, 1)

    def test_run_dry_run_invalid_and_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(FoundryError):
                run_dry_run(root / "bin", root / "corpus", 0.0)
            with mock.patch("ra.foundry.runner._run_process", side_effect=FoundryError("boom")):
                result = run_dry_run(root / "bin", root / "corpus", 1.0, timeout_seconds=2.0)
            self.assertFalse(result.completed)
            self.assertEqual(result.returncode, -1)
            self.assertIn("boom", result.output)

    def test_run_seed_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=COVERAGE_OUTPUT, stderr="")
            with mock.patch("ra.foundry.runner._run_process", return_value=completed):
                self.assertEqual(run_seed_coverage(root / "bin", root / "corpus"), 10)
            failed = subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="bad")
            with (
                mock.patch("ra.foundry.runner._run_process", return_value=failed),
                self.assertRaises(FoundryError),
            ):
                run_seed_coverage(root / "bin", root / "corpus")

    def test_measure_harness_compile_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = write_harness(root)
            with mock.patch(
                "ra.foundry.runner.compile_harness",
                return_value=CompileResult(ok=False, returncode=1, output="compile bad", binary_path=root / "bin"),
            ), mock.patch("ra.foundry.runner.run_seed_coverage") as seed, mock.patch(
                "ra.foundry.runner.run_dry_run"
            ) as dry:
                result = measure_harness(spec, {}, root / "work", root / "corpus")
            self.assertFalse(result.compiled)
            self.assertFalse(result.dry_run_completed)
            self.assertEqual(result.coverage_map, "compile bad")
            self.assertEqual(result.throughput_metric, "coverage_edges_per_sec")
            seed.assert_not_called()
            dry.assert_not_called()

    def test_measure_harness_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "clangxx": "clang++",
                "compile_args": ["-O2"],
                "dry_run_seconds": 1.0,
                "surface_median_edges_per_sec": 100.0,
                "parser_malloc_symbol": "parser_malloc",
                "baseline_coverage": True,
            }
            spec = write_harness(root, manifest=manifest)
            binary = root / "bin"
            with mock.patch(
                "ra.foundry.runner.compile_harness",
                return_value=CompileResult(ok=True, returncode=0, output="", binary_path=binary),
            ) as compile_mock, mock.patch(
                "ra.foundry.runner.run_seed_coverage", return_value=4
            ) as seed_mock, mock.patch(
                "ra.foundry.runner.run_dry_run", return_value=dry_result()
            ) as dry_mock:
                result = measure_harness(
                    spec,
                    manifest,
                    root / "work",
                    root / "corpus",
                    surface_median_edges_per_sec=50.0,
                    dry_run_seconds=0.5,
                )
            self.assertTrue(result.compiled)
            self.assertTrue(result.dry_run_completed)
            self.assertEqual(result.edges_per_sec, 3.0)
            self.assertEqual(result.surface_median_edges_per_sec, 50.0)
            self.assertEqual(result.covered_edges, 10)
            self.assertEqual(result.baseline_covered_edges, 4)
            self.assertEqual(result.new_covered_edges, 6)
            self.assertEqual(result.dry_run_seconds, 2.0)
            self.assertGreaterEqual(result.compile_seconds, 0.0)
            self.assertEqual(compile_mock.call_args.kwargs["extra_args"], ("-O2",))
            seed_mock.assert_called_once_with(binary, root / "corpus")
            dry_mock.assert_called_once_with(binary, root / "corpus", 0.5, baseline_covered_edges=4)

            with mock.patch(
                "ra.foundry.runner.compile_harness",
                return_value=CompileResult(ok=True, returncode=0, output="", binary_path=binary),
            ), mock.patch("ra.foundry.runner.run_seed_coverage") as seed_mock, mock.patch(
                "ra.foundry.runner.run_dry_run", return_value=dry_result()
            ) as dry_mock:
                result = measure_harness(spec, {**manifest, "baseline_coverage": False}, root / "work", root / "corpus")
            seed_mock.assert_not_called()
            self.assertEqual(dry_mock.call_args.kwargs["baseline_covered_edges"], 0)
            self.assertEqual(result.surface_median_edges_per_sec, 100.0)

    def test_measure_harness_manifest_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = write_harness(root)
            binary = root / "bin"
            bad_manifests = [
                {"compile_args": "-O2"},
                {"compile_args": ["-O2", 1]},
                {"surface_median_edges_per_sec": "high"},
                {"surface_median_edges_per_sec": True},
                {"dry_run_seconds": "soon"},
                {"dry_run_seconds": True},
            ]
            for manifest in bad_manifests:
                with self.subTest(manifest=manifest), mock.patch(
                    "ra.foundry.runner.compile_harness",
                    return_value=CompileResult(ok=True, returncode=0, output="", binary_path=binary),
                ), mock.patch("ra.foundry.runner.run_seed_coverage", return_value=0), mock.patch(
                    "ra.foundry.runner.run_dry_run", return_value=dry_result()
                ), self.assertRaises(FoundryError):
                    measure_harness(spec, manifest, root / "work", root / "corpus")

    def test_measure_harness_compile_args_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = write_harness(root)
            binary = root / "bin"
            with mock.patch(
                "ra.foundry.runner.compile_harness",
                return_value=CompileResult(ok=True, returncode=0, output="", binary_path=binary),
            ) as compile_mock, mock.patch("ra.foundry.runner.run_seed_coverage", return_value=0), mock.patch(
                "ra.foundry.runner.run_dry_run", return_value=dry_result()
            ):
                result = measure_harness(spec, {"compile_args": None}, root / "work", root / "corpus")
            self.assertTrue(result.compiled)
            self.assertEqual(compile_mock.call_args.kwargs["extra_args"], ())


if __name__ == "__main__":
    unittest.main()
