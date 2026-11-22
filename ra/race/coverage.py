"""Interleaving and schedule coverage accounting for race exploration."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .models import RaceSchedule


@dataclass(frozen=True)
class CoverageGap:
    """One missing coverage cell observed by :class:`InterleavingCoverage`."""

    kind: str
    label: str
    observed: int
    expected: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "kind": self.kind,
            "label": self.label,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class InterleavingCoverage:
    """Deterministic coverage summary over a set of race schedules.

    The summary is derived only from schedule contents, so it is stable across
    processes and hosts and can be compared between exploration strategies.
    """

    schedule_count: int
    step_count: int
    schedule_digests: tuple[str, ...]
    worker_op_counts: Mapping[tuple[int, str], int]
    worker_transition_counts: Mapping[tuple[int, int], int]
    op_transition_counts: Mapping[tuple[str, str], int]
    delay_buckets: Mapping[str, int]

    @classmethod
    def from_schedules(cls, schedules: Iterable[RaceSchedule]) -> InterleavingCoverage:
        schedule_count = 0
        step_count = 0
        digests: list[str] = []
        worker_op: Counter[tuple[int, str]] = Counter()
        worker_transitions: Counter[tuple[int, int]] = Counter()
        op_transitions: Counter[tuple[str, str]] = Counter()
        delay_buckets: Counter[str] = Counter()
        for schedule in schedules:
            schedule_count += 1
            step_count += len(schedule.steps)
            digests.append(schedule.digest)
            previous_worker: int | None = None
            previous_op: str | None = None
            for step in schedule.steps:
                worker_op[(step.worker, step.op)] += 1
                if previous_worker is not None:
                    worker_transitions[(previous_worker, step.worker)] += 1
                if previous_op is not None:
                    op_transitions[(previous_op, step.op)] += 1
                delay_buckets[_delay_bucket(step.delay_us, schedule.target.max_delay_us)] += 1
                previous_worker = step.worker
                previous_op = step.op
        return cls(
            delay_buckets=dict(sorted(delay_buckets.items())),
            op_transition_counts=dict(sorted(op_transitions.items())),
            schedule_count=schedule_count,
            schedule_digests=tuple(sorted(digests)),
            step_count=step_count,
            worker_op_counts=dict(sorted(worker_op.items())),
            worker_transition_counts=dict(sorted(worker_transitions.items())),
        )

    def gaps(
        self,
        *,
        workers: int,
        ops: tuple[str, ...],
        require_worker_transitions: bool = False,
    ) -> tuple[CoverageGap, ...]:
        """Return worker/op cells (and optional worker transitions) never observed."""
        gaps: list[CoverageGap] = []
        for worker in range(workers):
            for op in ops:
                observed = self.worker_op_counts.get((worker, op), 0)
                if observed == 0:
                    gaps.append(CoverageGap("worker_op", f"{worker}:{op}", observed))
        if require_worker_transitions and workers > 1:
            for previous in range(workers):
                for current in range(workers):
                    if previous == current:
                        continue
                    observed = self.worker_transition_counts.get((previous, current), 0)
                    if observed == 0:
                        gaps.append(
                            CoverageGap("worker_transition", f"{previous}->{current}", observed)
                        )
        return tuple(gaps)

    def merge(self, other: InterleavingCoverage) -> InterleavingCoverage:
        """Merge two coverage summaries deterministically."""
        return _merge_coverages(self, other)

    def to_dict(self) -> dict[str, Any]:
        return {
            "delay_buckets": dict(self.delay_buckets),
            "op_transition_counts": {f"{a}->{b}": n for (a, b), n in sorted(self.op_transition_counts.items())},
            "schedule_count": self.schedule_count,
            "schedule_digests": list(self.schedule_digests),
            "step_count": self.step_count,
            "worker_op_counts": {
                f"{worker}:{op}": n for (worker, op), n in sorted(self.worker_op_counts.items())
            },
            "worker_transition_counts": {
                f"{a}->{b}": n for (a, b), n in sorted(self.worker_transition_counts.items())
            },
        }


def _delay_bucket(delay_us: int, max_delay_us: int) -> str:
    if delay_us == 0:
        return "zero"
    if max_delay_us <= 0:
        return "positive"
    if delay_us <= max_delay_us // 4:
        return "short"
    if delay_us <= max_delay_us // 2:
        return "medium"
    return "long"


def _merge_coverages(
    left: InterleavingCoverage, right: InterleavingCoverage
) -> InterleavingCoverage:
    def merged_counts(
        a: Mapping[tuple[Any, ...], int], b: Mapping[tuple[Any, ...], int]
    ) -> dict[tuple[Any, ...], int]:
        merged: dict[tuple[Any, ...], int] = dict(a)
        for key, value in b.items():
            merged[key] = merged.get(key, 0) + value
        return dict(sorted(merged.items()))

    return InterleavingCoverage(
        delay_buckets=dict(
            sorted(
                Counter({**left.delay_buckets, **{k: v + left.delay_buckets.get(k, 0) for k, v in right.delay_buckets.items()}}).items()
            )
        ),
        op_transition_counts=merged_counts(left.op_transition_counts, right.op_transition_counts),
        schedule_count=left.schedule_count + right.schedule_count,
        schedule_digests=tuple(sorted(set(left.schedule_digests) | set(right.schedule_digests))),
        step_count=left.step_count + right.step_count,
        worker_op_counts=merged_counts(left.worker_op_counts, right.worker_op_counts),
        worker_transition_counts=merged_counts(
            left.worker_transition_counts, right.worker_transition_counts
        ),
    )
