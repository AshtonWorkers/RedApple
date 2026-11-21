"""Pure RA-FND-001 acceptance gate."""

from __future__ import annotations

import re

from .models import AcceptanceDecision, AcceptanceMeasurements

_FUNC_EDGE_RE = re.compile(
    r"^(?P<uncovered>UN)?COVERED_FUNC:\s+hits:\s+\d+\s+edges:\s+"
    r"(?P<covered>\d+)/(?P<total>\d+)\s+(?P<rest>.*)$",
    re.MULTILINE,
)
_LOCATION_RE = re.compile(r"^(?P<name>.*)\s+\S+:\d+\s*$")


def _function_name(rest: str) -> str:
    match = _LOCATION_RE.match(rest.strip())
    if match is None:
        return rest.strip()
    return match.group("name").strip()


def covered_functions(coverage_map: str) -> set[str]:
    """Return function names present in covered libFuzzer output."""
    names: set[str] = set()
    for match in _FUNC_EDGE_RE.finditer(coverage_map):
        if match.group("uncovered"):
            continue
        name = _function_name(match.group("rest"))
        if name:
            names.add(name)
    return names


def parser_malloc_reachable(coverage_map: str, symbol: str) -> bool:
    """Return whether ``symbol`` appears in covered functions."""
    for name in covered_functions(coverage_map):
        if name == symbol or name.startswith(f"{symbol}(") or name.startswith(f"{symbol}::"):
            return True
    return False


def coverage_edge_counts(coverage_map: str) -> tuple[int, int]:
    """Return ``(covered_edges, total_edges)`` from libFuzzer coverage output."""
    covered = 0
    total = 0
    for match in _FUNC_EDGE_RE.finditer(coverage_map):
        covered_edges = int(match.group("covered"))
        total_edges = int(match.group("total"))
        if not match.group("uncovered"):
            covered += covered_edges
        total += total_edges
    return covered, total


def evaluate_acceptance(measurements: AcceptanceMeasurements) -> AcceptanceDecision:
    """Evaluate the mechanical RA-FND-001 checks."""
    checks = {
        "compiles": bool(measurements.compiled) and bool(measurements.dry_run_completed),
        "edges_sec_ge_60pct_surface_median": (
            measurements.surface_median_edges_per_sec > 0
            and measurements.edges_per_sec
            >= 0.6 * measurements.surface_median_edges_per_sec
        ),
        "parser_malloc_in_coverage": parser_malloc_reachable(
            measurements.coverage_map, measurements.parser_malloc_symbol
        ),
        "throughput_metric_is_coverage_edges_per_sec": (
            measurements.throughput_metric == "coverage_edges_per_sec"
        ),
    }
    reasons = [name for name, ok in checks.items() if not ok]
    return AcceptanceDecision(accepted=not reasons, checks=checks, reasons=tuple(reasons))
