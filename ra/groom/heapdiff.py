"""Exact before/after heap-state diff validators for groom dialects."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from ..errors import DialectDefect, FormatFail
from .allocators import AllocatorModelSet, load_allocator_models
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


@lru_cache(maxsize=1)
def _default_allocator_models() -> AllocatorModelSet:
    """Return the repo allocator models, loaded once per process."""
    return load_allocator_models()


def _allocator_models(allocator_models: AllocatorModelSet | None) -> AllocatorModelSet:
    if allocator_models is not None:
        return allocator_models
    return _default_allocator_models()


def _allowed_size_classes(dialect: Mapping[str, Any], models: AllocatorModelSet) -> set[str]:
    """Return dialect-declared libpas classes or raise ``DialectDefect``."""
    validator = dialect.get("validator")
    if validator != HEAP_DIFF_CLASS_STABLE:
        raise DialectDefect(f"unsupported heap diff validator {validator!r}")
    victim_class = dialect.get("victim_class")
    if not isinstance(victim_class, str) or not models.is_libpas_size_class(victim_class):
        raise DialectDefect(f"groom dialect has unknown victim size class {victim_class!r}")
    pre_seed = dialect.get("pre_seed", [])
    if not isinstance(pre_seed, list):
        raise DialectDefect("groom dialect pre_seed must be a list")
    allowed = {victim_class}
    for item in pre_seed:
        if not isinstance(item, Mapping):
            raise DialectDefect("groom dialect pre_seed entries must be mappings")
        pad_to_class = item.get("pad_to_class")
        if pad_to_class is None:
            continue
        if not isinstance(pad_to_class, str) or not models.is_libpas_size_class(pad_to_class):
            raise DialectDefect(f"groom dialect has unknown pad size class {pad_to_class!r}")
        allowed.add(pad_to_class)
    return allowed


def _heap_state_reasons(
    diff: HeapDiff,
    allowed_classes: set[str],
    models: AllocatorModelSet,
) -> list[str]:
    """Check changed heap objects against allocator-model invariants."""
    reasons: list[str] = []
    changed = (*diff.added, *diff.removed)
    for obj in changed:
        if obj.size_class not in allowed_classes or not models.is_libpas_size_class(obj.size_class):
            reasons.append(
                f"heap object escaped declared size classes: {obj.size_class} not in {sorted(allowed_classes)}"
            )
            break
    for obj in changed:
        if obj.cage and not models.is_known_cage(obj.cage):
            reasons.append(f"heap object used unknown Gigacage {obj.cage!r}")
            break
    for obj in changed:
        if obj.isoheap and not models.is_known_isoheap(obj.isoheap):
            reasons.append(f"heap object used unknown IsoHeap {obj.isoheap!r}")
            break
    for obj in changed:
        if obj.structure_id and not models.is_known_structure_id(obj.structure_id):
            reasons.append(f"heap object used unknown StructureID {obj.structure_id!r}")
            break
    return reasons


def validate_heap_diff(
    dialect: Mapping[str, Any],
    before: HeapSnapshot,
    after: HeapSnapshot,
    *,
    expectation: HeapDiffExpectation | None = None,
    allocator_models: AllocatorModelSet | None = None,
) -> HeapDiffResult:
    """Validate ``heap_diff.class_stable`` against exact heap-state diffs."""
    if not isinstance(dialect, Mapping):
        raise DialectDefect("groom dialect must be a mapping")
    if not isinstance(before, HeapSnapshot) or not isinstance(after, HeapSnapshot):
        raise FormatFail("heap snapshots must be HeapSnapshot values")
    models = _allocator_models(allocator_models)
    allowed_classes = _allowed_size_classes(dialect, models)
    diff = diff_heap_states(before, after)
    reasons: list[str] = []
    if expectation is not None and not expectation.matches(diff):
        reasons.append("heap diff does not match expected before/after delta")
    reasons.extend(_heap_state_reasons(diff, allowed_classes, models))
    if not reasons and diff.is_empty:
        reasons.append("heap state did not change")
    return HeapDiffResult(
        passed=not reasons,
        validator=HEAP_DIFF_CLASS_STABLE,
        reasons=tuple(reasons),
        diff=diff,
    )
