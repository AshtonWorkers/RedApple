"""Coverage-guided scheduling hooks for JSC discovery campaigns.

The scheduler is intentionally provider-agnostic: a real JSC coverage runner
can implement :class:`CoverageProvider`, while tests and Linux CI can use the
built-in crash/exec-error bandit signal. All scheduling state is in memory for
one campaign; durable campaign state still goes through the ledger store.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from .harness import CrashResult


@dataclass(frozen=True)
class CoverageSample:
    """One coverage observation for a candidate input."""

    edges: frozenset[str] = frozenset()
    features: dict[str, int] = field(default_factory=dict)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def novelty(self, seen: set[str]) -> int:
        return len(self.edges - seen)


class CoverageProvider(Protocol):
    """Optional async hook that measures candidate coverage."""

    async def coverage_for(self, content: str) -> CoverageSample | None: ...


@dataclass
class CoverageStats:
    """Mutable counters for coverage-guided scheduling."""

    executions: int = 0
    samples: int = 0
    edges: int = 0
    new_edges: int = 0
    crashes: int = 0
    timeouts: int = 0
    exec_errors: int = 0


@dataclass
class _SeedEnergy:
    energy: float
    executions: int = 0
    crashes: int = 0
    last_coverage: int = 0


class CoverageScheduler:
    """Weighted seed scheduler driven by coverage novelty and crash yield."""

    def __init__(
        self,
        provider: CoverageProvider | None = None,
        *,
        seed_energy: float = 1.0,
        new_edge_bonus: float = 6.0,
        crash_bonus: float = 2.0,
        timeout_bonus: float = 0.25,
        exec_error_penalty: float = 0.75,
        decay: float = 0.98,
        min_energy: float = 0.05,
    ) -> None:
        if seed_energy <= 0 or min_energy <= 0 or decay < 0 or decay > 1:
            raise ValueError("invalid coverage scheduler energy parameters")
        self._provider = provider
        self._seed_energy = seed_energy
        self._new_edge_bonus = new_edge_bonus
        self._crash_bonus = crash_bonus
        self._timeout_bonus = timeout_bonus
        self._exec_error_penalty = exec_error_penalty
        self._decay = decay
        self._min_energy = min_energy
        self._global_edges: set[str] = set()
        self._energies: dict[str, _SeedEnergy] = {}
        self.stats = CoverageStats()

    async def observe(
        self,
        seed: str,
        content: str,
        result: CrashResult,
        sample: CoverageSample | None = None,
    ) -> CoverageSample | None:
        """Record one execution and update seed energy for ``seed``."""
        if sample is None and self._provider is not None:
            try:
                sample = await self._provider.coverage_for(content)
            except Exception:
                sample = None
        self.stats.executions += 1
        if result.exec_error:
            self.stats.exec_errors += 1
        elif result.timed_out:
            self.stats.timeouts += 1
        if result.is_crash:
            self.stats.crashes += 1

        new_edges = 0
        if sample is not None:
            self.stats.samples += 1
            new_edges = sample.novelty(self._global_edges)
            self._global_edges.update(sample.edges)
            self.stats.new_edges += new_edges
            self.stats.edges = len(self._global_edges)
        elif not self._global_edges:
            self.stats.edges = 0

        state = self._energies.setdefault(seed, _SeedEnergy(energy=self._seed_energy))
        state.executions += 1
        state.last_coverage = sample.edge_count if sample is not None else 0
        if result.is_crash:
            state.crashes += 1
        delta = self._new_edge_bonus * new_edges
        if result.is_crash:
            delta += self._crash_bonus
        elif result.timed_out:
            delta += self._timeout_bonus
        elif result.exec_error:
            delta -= self._exec_error_penalty
        state.energy = max(self._min_energy, state.energy * self._decay + delta)
        return sample

    def choose(self, rng: random.Random, corpus: Sequence[str]) -> str:
        """Choose a corpus seed with probability proportional to energy."""
        if not corpus:
            raise ValueError("coverage scheduler corpus must not be empty")
        weights = [self._energies.get(content, _SeedEnergy(self._seed_energy)).energy for content in corpus]
        total = sum(weights)
        pick = rng.random() * total
        upto = 0.0
        for content, weight in zip(corpus, weights, strict=True):
            upto += weight
            if pick < upto:
                return content
        return corpus[-1]

    def energy_for(self, content: str) -> float:
        return self._energies.get(content, _SeedEnergy(self._seed_energy)).energy

    def reset(self) -> None:
        self._global_edges.clear()
        self._energies.clear()
        self.stats = CoverageStats()
