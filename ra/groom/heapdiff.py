"""Exact before/after heap-state diff validators for groom dialects."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..errors import DialectDefect, FormatFail
from .models import HeapDiff, HeapDiffExpectation, HeapObject, HeapSnapshot

HEAP_DIFF_CLASS_STABLE = "heap_diff.class_stable"


@dataclass(frozen=True)
class HeapDiffResult:
    """Outcome of one heap-diff validator run."""

    passed: bool
    validator: str
    reasons: tuple[str, ...] = ()
    diff: HeapDiff | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "validator": self.validator,
            "reasons": list(self.reasons),
            "diff": None if self.diff is None else self.diff.to_dict(),
        }


def diff_heap_states(before: HeapSnapshot, after: HeapSnapshot) -> HeapDiff:
    """Return the exact multiset difference between two snapshots."""
    before_counts = Counter(before.objects)
    after_counts = Counter(after.objects)
    added: list[HeapObject] = []
    removed: list[HeapObject] = []
    for obj, count in after_counts.items():
        delta = count - before_counts.get(obj, 0)
        if delta > 0:
            added.extend([obj] * delta)
    for obj, count in before_counts.items():
        delta = count - after_counts.get(obj, 0)
        if delta > 0:
            removed.extend([obj] * delta)
    return HeapDiff(
        added=tuple(sorted(added, key=HeapObject.key)),
        removed=tuple(sorted(removed, key=HeapObject.key)),
    )


def validate_heap_diff(
    dialect: Mapping[str, Any],
    before: HeapSnapshot,
    after: HeapSnapshot,
    *,
    expectation: HeapDiffExpectation | None = None,
) -> HeapDiffResult:
    """Validate ``heap_diff.class_stable`` against exact heap-state diffs."""
    validator = dialect.get("validator")
    if validator != HEAP_DIFF_CLASS_STABLE:
        raise DialectDefect(f"unsupported heap diff validator {validator!r}")
    victim_class = dialect.get("victim_class")
    if not isinstance(victim_class, str) or not victim_class:
        raise FormatFail("groom dialect missing victim_class")
    pre_seed = dialect.get("pre_seed", [])
    allowed_classes = {victim_class}
    if isinstance(pre_seed, list):
        for item in pre_seed:
            if isinstance(item, Mapping):
                pad_to_class = item.get("pad_to_class")
                if isinstance(pad_to_class, str) and pad_to_class:
                    allowed_classes.add(pad_to_class)
    diff = diff_heap_states(before, after)
    reasons: list[str] = []
    if expectation is not None and not expectation.matches(diff):
        reasons.append("heap diff does not match expected before/after delta")
    for obj in (*diff.added, *diff.removed):
        if obj.size_class not in allowed_classes:
            reasons.append(
                f"heap object escaped declared size classes: {obj.size_class} not in {sorted(allowed_classes)}"
            )
            break
    if not reasons and diff.is_empty:
        reasons.append("heap state did not change")
    return HeapDiffResult(
        passed=not reasons,
        validator=HEAP_DIFF_CLASS_STABLE,
        reasons=tuple(reasons),
        diff=diff,
    )
