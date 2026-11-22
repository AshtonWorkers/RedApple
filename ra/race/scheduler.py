"""Deterministic interleaving schedule construction (RA-RACE-001)."""

from __future__ import annotations

from .models import RaceSchedule, RaceTarget
from .prng import RaceRng, normalize_seed, seed_hex
from .strategies import ScheduleStrategy, build_strategy_steps, normalize_strategy


def schedule_rng_key(
    target: RaceTarget,
    seed: int,
    iteration: int,
    *,
    strategy: ScheduleStrategy = "random",
) -> str:
    """Canonical DRBG key binding schedule to target identity, seed, iteration."""
    base = f"ra.race.schedule.v1|{target.target_digest}|{seed_hex(seed)}|{iteration}"
    if strategy == "random":
        return base
    return f"{base}|{strategy}"


def build_schedule(
    target: RaceTarget,
    seed: int | str,
    *,
    iteration: int,
    strategy: str = "random",
) -> RaceSchedule:
    """Build the deterministic schedule for (target, seed, iteration, strategy).

    The same arguments always produce byte-identical schedule bytes and digest,
    in any process, on any host (RA-RACE-001, RA-RACE-004).
    """
    canonical_seed = normalize_seed(seed)
    strategy_name = normalize_strategy(strategy)
    rng = RaceRng(schedule_rng_key(target, canonical_seed, iteration, strategy=strategy_name))
    steps = build_strategy_steps(target, rng, strategy_name, iteration=iteration)
    return RaceSchedule(seed=canonical_seed, iteration=iteration, target=target, steps=steps)
