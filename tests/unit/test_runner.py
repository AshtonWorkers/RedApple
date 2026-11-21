"""Runner parsing tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ra.foundry import (
    FoundryError,
    harness_spec_from_manifest,
    load_manifest,
    parse_average_exec_per_sec,
)


class RunnerTest(unittest.TestCase):
    def test_parse_average_exec_per_sec(self) -> None:
        output = "noise\nstat::average_exec_per_sec: 12345\nmore noise\n"
        self.assertEqual(parse_average_exec_per_sec(output), 12345.0)
        self.assertEqual(parse_average_exec_per_sec("no stats"), 0.0)

    def test_harness_spec_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "harness.json").write_text(
                json.dumps(
                    {
                        "id": "demo",
                        "format": "heif",
                        "source": "LLVMFuzzerTestOneInput.cc",
                        "dialect": "demo.dialect.json",
                    }
                )
            )
            spec = harness_spec_from_manifest(directory)
            self.assertEqual(spec.id, "demo")
            self.assertEqual(spec.manifest, "harness.json")
            self.assertEqual(load_manifest(directory / "harness.json")["format"], "heif")

    def test_manifest_requires_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "harness.json").write_text(json.dumps({"id": "demo"}))
            with self.assertRaises(FoundryError):
                harness_spec_from_manifest(directory)


if __name__ == "__main__":
    unittest.main()
