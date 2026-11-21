"""Mechanical RA-FND-001 acceptance gate.

Pure logic only: no I/O, no imports from other ra/ modules.
"""

from __future__ import annotations

import re
from typing import Iterator, List

from .models import AcceptanceDecision, AcceptanceMeasurements

_COVERED_FUNC_RE = re.compile(
    r"^COVERED_FUNC:\s+hits:\s+\d+\s+edges:\s+\S+\s+(?P<func>.*)$"
)


def covered_functions(coverage_map: str) -> Iterator[str]:
    """Yield function entries from a libFuzzer ``-print_coverage=1`` map."""
    for line in coverage_map.splitlines():
        match = _COVERED_FUNC_RE.match(line.strip())
        if match is not None:
            yield match.group("func")


def parser_malloc_reachable(
    coverage_map: str, symbol: str = "parser_malloc"
) -> bool:
    """Return True when a covered parser allocation symbol is in the map."""
    return any(symbol in func for func in covered_functions(coverage_map))


def evaluate_acceptance(measurements: AcceptanceMeasurements) -> AcceptanceDecision:
    """Evaluate the three mechanical RA-FND-001 checks.

    Invariants touched: I5 (checks are a fixed ordered mapping), I8 (the gate is
    evaluated before any side effect by the caller).
    """
    checks = {
        "compiles": (
            bool(measurements.compiled) and bool(measurements.dry_run_completed)
        ),
        "edges_sec_ge_60pct_surface_median": (
            measurements.surface_median_edges_per_sec > 0
            and measurements.edges_per_sec
            >= 0.6 * measurements.surface_median_edges_per_sec
        ),
        "parser_malloc_in_coverage": parser_malloc_reachable(
            measurements.coverage_map, measurements.parser_malloc_symbol
        ),
    }

    reasons: List[str] = []
    if not checks["compiles"]:
        reasons.append("compiles: harness did not compile or dry run did not complete")
    if not checks["edges_sec_ge_60pct_surface_median"]:
        reasons.append(
            "edges_sec_ge_60pct_surface_median "
            f"[{measurements.throughput_metric}]: "
            f"{measurements.edges_per_sec} < "
            f"{0.6 * measurements.surface_median_edges_per_sec} "
            f"(median {measurements.surface_median_edges_per_sec}; "
            f"{measurements.throughput_caveat})"
        )
    if not checks["parser_malloc_in_coverage"]:
        reasons.append(
            "parser_malloc_in_coverage: "
            f"{measurements.parser_malloc_symbol} not covered"
        )

    return AcceptanceDecision(
        accepted=all(checks.values()), checks=checks, reasons=reasons
    )
