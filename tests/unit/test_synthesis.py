"""Deterministic harness synthesis tests."""

from __future__ import annotations

import unittest

from ra.foundry import Dialect, SynthesisRequest, TemplateHarnessSynthesizer


class SynthesisTest(unittest.TestCase):
    def request(self, fmt: str = "bin", attempt: int = 1, symbol: str = "parser_malloc") -> SynthesisRequest:
        return SynthesisRequest(
            harness_id="demo",
            format=fmt,
            dialect=Dialect(format=fmt, data={}, validator="heap_diff.class_stable", validator_requirement="RA-GRM-002"),
            dialect_bytes=b'{"format":"heif"}',
            attempt=attempt,
            feedback={"reasons": ["parser_malloc_in_coverage"]},
            surface="imageio.heif",
            surface_median_edges_per_sec=12.5,
            parser_malloc_symbol=symbol,
            dry_run_seconds=30.0,
            clangxx="clang++",
            compile_args=("-O2",),
        )

    def test_generic_synthesis(self) -> None:
        synth = TemplateHarnessSynthesizer()
        out = synth.synthesize(self.request())
        self.assertIn("LLVMFuzzerTestOneInput.cc", out.files)
        self.assertIn("groom-dialect.json", out.files)
        self.assertIn("harness.json", out.files)
        self.assertTrue(any(name.startswith("corpus/seed_") for name in out.files))
        source = out.files["LLVMFuzzerTestOneInput.cc"].decode()
        self.assertIn("parser_malloc", source)
        self.assertNotIn("ImageIO", source)
        self.assertEqual(out.manifest["throughput_metric"], "coverage_edges_per_sec")
        self.assertEqual(out.manifest["attempt"], 1)

    def test_heif_synthesis_uses_imageio_template(self) -> None:
        synth = TemplateHarnessSynthesizer()
        out = synth.synthesize(self.request(fmt="heif"))
        source = out.files["LLVMFuzzerTestOneInput.cc"].decode()
        self.assertIn("ImageIO", source)
        self.assertIn("parser_malloc", source)
        seeds = [name for name in out.files if name.startswith("corpus/seed_")]
        first = sorted(seeds)[0]
        self.assertIn(b"ftypheic", out.files[first])

    def test_attempt_and_feedback_change_outputs(self) -> None:
        synth = TemplateHarnessSynthesizer()
        first = synth.synthesize(self.request(attempt=1))
        second = synth.synthesize(self.request(attempt=2))
        self.assertNotEqual(first.files["LLVMFuzzerTestOneInput.cc"], second.files["LLVMFuzzerTestOneInput.cc"])
        self.assertEqual(first.manifest["attempt"], 1)
        self.assertEqual(second.manifest["attempt"], 2)

    def test_invalid_parser_symbol_falls_back(self) -> None:
        synth = TemplateHarnessSynthesizer()
        out = synth.synthesize(self.request(symbol="not a c symbol"))
        source = out.files["LLVMFuzzerTestOneInput.cc"].decode()
        self.assertIn("parser_malloc(size_t size)", source)


if __name__ == "__main__":
    unittest.main()
