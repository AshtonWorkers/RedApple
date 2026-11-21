"""Golden-set runner and gate (RA-MDL-007)."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import FormatFail
from .routing import TaskType

GOLDEN_ROWS_REQUIRED = 200
TOLERANCE = 0.02


@dataclass(frozen=True)
class GoldenCase:
    """One immutable golden row."""

    task_type: TaskType
    packet: Mapping[str, Any]
    reference: Mapping[str, Any]


@dataclass(frozen=True)
class GoldenReport:
    """Golden-set evaluation result."""

    task_type: TaskType
    rows: int
    score: float
    baseline: float | None
    passed: bool
    route_large_model: bool
    drop: float | None


def load_golden(path: str | Path, task_type: TaskType | str | None = None) -> list[GoldenCase]:
    """Load JSONL golden rows; rows are immutable once released."""
    tt = TaskType(task_type) if task_type is not None else None
    cases: list[GoldenCase] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise FormatFail(f"golden row {line_no} is not an object")
        row_type = TaskType(str(value.get("task_type")))
        if tt is not None and row_type is not tt:
            continue
        packet = value.get("packet")
        reference = value.get("reference")
        if not isinstance(packet, dict) or not isinstance(reference, dict):
            raise FormatFail(f"golden row {line_no} requires packet and reference objects")
        cases.append(GoldenCase(row_type, packet, reference))
    return cases


def score_output(reference: Mapping[str, Any], output: Mapping[str, Any]) -> float:
    """Score one output; insufficient_evidence beats a wrong answer (RA-MDL-004)."""
    if dict(output) == dict(reference):
        return 1.0
    ref_answer = reference.get("answer") or reference.get("text")
    out_answer = output.get("answer") or output.get("text")
    if out_answer == "insufficient_evidence" and ref_answer != "insufficient_evidence":
        return 0.5
    return 0.0


def evaluate_cases(
    cases: list[GoldenCase], responder: Callable[[GoldenCase], Mapping[str, Any]]
) -> float:
    """Mean golden score for a responder."""
    if not cases:
        return 0.0
    return sum(score_output(case.reference, responder(case)) for case in cases) / len(cases)


def check_golden(
    cases: list[GoldenCase],
    responder: Callable[[GoldenCase], Mapping[str, Any]],
    *,
    baseline: float | None = None,
) -> GoldenReport:
    """Evaluate a golden set and apply the <=2-point gate."""
    if not cases:
        raise FormatFail("golden set is empty")
    task_type = cases[0].task_type
    rows = len(cases)
    route_large = rows < GOLDEN_ROWS_REQUIRED
    score = evaluate_cases(cases, responder)
    drop = None if baseline is None else max(0.0, baseline - score)
    passed = route_large or drop is None or drop <= TOLERANCE
    return GoldenReport(task_type, rows, score, baseline, passed, route_large, drop)
