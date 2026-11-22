"""Seed distributions for stochastic probing (RA-RACE-002).

Seeds are drawn from a distribution, never hard-coded, so crash signals are
scored statistically across the seed space rather than from a single input.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from ..errors import FormatFail
from .models import MAX_SEED_SCORES, SeedScore
from .prng import MAX_SEED, RaceRng, normalize_seed, seed_hex


class SeedDistribution(Protocol):
    """A distribution over race seeds."""

    def sample(self, rng: RaceRng) -> int:
        """Draw one seed from the distribution."""
        ...

    def describe(self) -> dict[str, Any]:
        """JSON-safe descriptor persisted in race state."""
        ...


@dataclass(frozen=True)
class UniformSeedDistribution:
    """Uniform distribution over the inclusive range ``[lo, hi]``."""

    lo: int = 0
    hi: int = MAX_SEED

    def __post_init__(self) -> None:
        object.__setattr__(self, "lo", normalize_seed(self.lo))
        object.__setattr__(self, "hi", normalize_seed(self.hi))
        if self.lo > self.hi:
            raise FormatFail("uniform seed distribution lo must be <= hi")

    def sample(self, rng: RaceRng) -> int:
        return self.lo + rng.randbelow(self.hi - self.lo + 1)

    def describe(self) -> dict[str, Any]:
        return {"hi": self.hi, "kind": "uniform", "lo": self.lo}


@dataclass(frozen=True)
class WeightedSeedDistribution:
    """Weighted distribution over an explicit seed support.

    Weights are positive integers (no floats in any budget/score path), and
    sampling is deterministic for a given RNG stream.
    """

    weights: tuple[tuple[int, int], ...]
    _cumulative: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if not self.weights:
            raise FormatFail("weighted seed distribution requires at least one seed")
        seen: set[int] = set()
        total = 0
        cumulative: list[int] = []
        for seed, weight in self.weights:
            canonical = normalize_seed(seed)
            if canonical in seen:
                raise FormatFail(f"weighted seed distribution duplicates seed {seed_hex(seed)}")
            seen.add(canonical)
            if isinstance(weight, bool) or not isinstance(weight, int) or weight <= 0:
                raise FormatFail("weighted seed distribution weights must be positive ints")
            total += weight
            cumulative.append(total)
        object.__setattr__(self, "_cumulative", tuple(cumulative))
        object.__setattr__(self, "weights", tuple((normalize_seed(s), w) for s, w in self.weights))

    def sample(self, rng: RaceRng) -> int:
        total = self._cumulative[-1]
        draw = rng.randbelow(total)
        index = bisect_right(self._cumulative, draw)
        seed, _weight = self.weights[index]
        return seed

    def describe(self) -> dict[str, Any]:
        return {
            "kind": "weighted",
            "seeds": [
                {"seed": seed_hex(seed), "weight": weight}
                for seed, weight in self.weights
            ],
        }


@dataclass(frozen=True)
class FixedSeedDistribution:
    """Single-seed distribution for replay and tests."""

    seed: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "seed", normalize_seed(self.seed))

    def sample(self, rng: RaceRng) -> int:
        return self.seed

    def describe(self) -> dict[str, Any]:
        return {"kind": "fixed", "seed": seed_hex(self.seed)}


def index_seed(master_seed: int | str, index: int, *, salt: str = "") -> int:
    """Derive a deterministic seed for ``index`` under ``master_seed``."""
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise FormatFail("seed index must be a non-negative int")
    if not isinstance(salt, str):
        raise FormatFail("seed salt must be str")
    key = f"ra.race.seed.v1|{seed_hex(normalize_seed(master_seed))}|{index}|{salt}"
    return RaceRng(key).next_u64()


def seed_sequence(
    master_seed: int | str,
    count: int,
    *,
    salt: str = "",
    start: int = 0,
) -> tuple[int, ...]:
    """Return ``count`` deterministic seeds starting at ``start``."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise FormatFail("seed count must be a non-negative int")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise FormatFail("seed start must be a non-negative int")
    return tuple(index_seed(master_seed, start + offset, salt=salt) for offset in range(count))


def score_seed_outcomes(
    outcomes: Iterable[tuple[int | str, bool]],
    *,
    max_seeds: int = MAX_SEED_SCORES,
) -> tuple[SeedScore, ...]:
    """Score seeds from ``(seed, crashed)`` probe outcomes.

    The result is sorted by crash rate descending with deterministic tie-breaks,
    so the same outcome stream always yields the same ranking.
    """
    if isinstance(max_seeds, bool) or not isinstance(max_seeds, int) or max_seeds < 1:
        raise FormatFail("max_seeds must be a positive int")
    probes: dict[int, int] = {}
    crashes: dict[int, int] = {}
    for seed, crashed in outcomes:
        canonical = normalize_seed(seed)
        if not isinstance(crashed, bool):
            raise FormatFail("seed outcome crashed flag must be bool")
        probes[canonical] = probes.get(canonical, 0) + 1
        if crashed:
            crashes[canonical] = crashes.get(canonical, 0) + 1
    scores = [
        SeedScore(
            seed=seed,
            seed_hex=seed_hex(seed),
            probes=probes[seed],
            crashes=crashes.get(seed, 0),
        )
        for seed in probes
    ]
    scores.sort(key=lambda score: (-score.rate, -score.crashes, -score.probes, score.seed_hex))
    return tuple(scores[:max_seeds])
