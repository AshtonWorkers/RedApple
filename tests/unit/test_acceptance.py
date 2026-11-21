"""RA-FND-001 acceptance gate tests."""

from __future__ import annotations

import unittest

from ra.foundry import (
    coverage_edge_counts,
    covered_functions,
    evaluate_acceptance,
    parser_malloc_reachable,
)

from .helpers import BAD_COVERAGE, GOOD_COVERAGE, measurements


class AcceptanceTest(unittest.TestCase):
    def test_coverage_parsing(self) -> None:
        self.assertEqual(
            covered_functions(GOOD_COVERAGE),
            {"parser_malloc(unsigned long)"},
        )
        self.assertTrue(parser_malloc_reachable(GOOD_COVERAGE, "parser_malloc"))
        self.assertFalse(parser_malloc_reachable(BAD_COVERAGE, "parser_malloc"))
        self.assertEqual(coverage_edge_counts(GOOD_COVERAGE), (3, 6))
        self.assertEqual(coverage_edge_counts("no coverage here"), (0, 0))

    def test_coverage_parsing_tolerates_malformed_function_lines(self) -> None:
        self.assertEqual(covered_functions("COVERED_FUNC: hits: 1 edges: 1/1 \n"), set())
        self.assertEqual(
            covered_functions("COVERED_FUNC: hits: 1 edges: 2/2 no_location_here\n"),
            {"no_location_here"},
        )

    def test_parser_malloc_symbol_matching(self) -> None:
        coverage = "COVERED_FUNC: hits: 1 edges: 1/1 custom_alloc(int) x.cc:1\n"
        self.assertTrue(parser_malloc_reachable(coverage, "custom_alloc"))
        self.assertTrue(parser_malloc_reachable(coverage, "custom_alloc(int)"))
        self.assertFalse(parser_malloc_reachable(coverage, "custom"))

    def test_acceptance_accepts_good_measurements(self) -> None:
        decision = evaluate_acceptance(measurements())
        self.assertTrue(decision.accepted)
        self.assertTrue(all(decision.checks.values()))
        self.assertEqual(decision.reasons, ())

    def test_acceptance_boundary_60_percent(self) -> None:
        decision = evaluate_acceptance(measurements(edges_per_sec=600.0))
        self.assertTrue(decision.accepted)
        decision = evaluate_acceptance(measurements(edges_per_sec=599.9))
        self.assertFalse(decision.accepted)
        self.assertIn("edges_sec_ge_60pct_surface_median", decision.reasons)

    def test_acceptance_rejects_each_failed_check(self) -> None:
        cases = [
            (measurements(compiled=False), "compiles"),
            (measurements(dry_run_completed=False), "compiles"),
            (measurements(edges_per_sec=0.0), "edges_sec_ge_60pct_surface_median"),
            (measurements(surface_median_edges_per_sec=0.0), "edges_sec_ge_60pct_surface_median"),
            (measurements(coverage_map=BAD_COVERAGE), "parser_malloc_in_coverage"),
            (measurements(throughput_metric="exec_per_sec_proxy"), "throughput_metric_is_coverage_edges_per_sec"),
        ]
        for bad, reason in cases:
            with self.subTest(reason=reason):
                decision = evaluate_acceptance(bad)
                self.assertFalse(decision.accepted)
                self.assertIn(reason, decision.reasons)


if __name__ == "__main__":
    unittest.main()
