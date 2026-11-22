"""Deterministic schedule-exploration strategies for race probing."""

from __future__ import annotations

from typing import Literal

from ..errors import FormatFail
from .models import RaceStep, RaceTarget
from .prng import RaceRng

ScheduleStrategy = Literal["random", "pairwise", "op_focus", "delay_pulse", "round_robin"]

SCHEDULE_STRATEGIES: tuple[ScheduleStrategy, ...] = (
    "random",
    "pairwise",
    "op_focus",
    "delay_pulse",
    "round_robin",
)


def normalize_strategy(strategy: str) -> ScheduleStrategy:
    if strategy not in SCHEDULE_STRATEGIES:
        raise FormatFail(f"unknown race schedule strategy {strategy!r}")
    return strategy


def build_strategy_steps(
    target: RaceTarget,
    rng: RaceRng,
    strategy: ScheduleStrategy,
    *,
    iteration: int,
) -> tuple[RaceStep, ...]:
    """Build one deterministic step sequence for ``strategy``."""
    if strategy == "random":
        return _random_steps(target, rng)
    if strategy == "pairwise":
        return _pairwise_steps(target, rng)
    if strategy == "op_focus":
        return _op_focus_steps(target, rng, iteration)
    if strategy == "delay_pulse":
        return _delay_pulse_steps(target, rng)
    if strategy == "round_robin":
        return _round_robin_steps(target, rng)
    raise FormatFail(f"unknown race schedule strategy {strategy!r}")


def _random_steps(target: RaceTarget, rng: RaceRng) -> tuple[RaceStep, ...]:
    return tuple(
        RaceStep(
            worker=rng.randbelow(target.workers),
            op=rng.choice(target.ops),
            delay_us=rng.jitter_us(target.max_delay_us),
        )
        for _ in range(target.steps)
    )


def _pairwise_steps(target: RaceTarget, rng: RaceRng) -> tuple[RaceStep, ...]:
    workers = target.workers
    steps: list[RaceStep] = []
    for index in range(target.steps):
        base = (index // 2) % workers
        worker = base if index % 2 == 0 else (base + 1) % workers
        steps.append(
            RaceStep(
                worker=worker,
                op=rng.choice(target.ops),
                delay_us=rng.jitter_us(target.max_delay_us),
            )
        )
    return tuple(steps)


def _op_focus_steps(target: RaceTarget, rng: RaceRng, iteration: int) -> tuple[RaceStep, ...]:
    focus = target.ops[iteration % len(target.ops)]
    steps: list[RaceStep] = []
    for _ in range(target.steps):
        op = focus if rng.randbelow(4) != 0 else rng.choice(target.ops)
        steps.append(
            RaceStep(
                worker=rng.randbelow(target.workers),
                op=op,
                delay_us=rng.jitter_us(target.max_delay_us),
            )
        )
    return tuple(steps)


def _delay_pulse_steps(target: RaceTarget, rng: RaceRng) -> tuple[RaceStep, ...]:
    steps: list[RaceStep] = []
    for index in range(target.steps):
        phase = index % 4
        if phase == 0:
            delay_us = 0
        elif phase == 2:
            delay_us = target.max_delay_us
        else:
            delay_us = rng.jitter_us(target.max_delay_us)
        steps.append(
            RaceStep(
                worker=rng.randbelow(target.workers),
                op=rng.choice(target.ops),
                delay_us=delay_us,
            )
        )
    return tuple(steps)


def _round_robin_steps(target: RaceTarget, rng: RaceRng) -> tuple[RaceStep, ...]:
    steps: list[RaceStep] = []
    for index in range(target.steps):
        cycle = index // target.workers
        steps.append(
            RaceStep(
                worker=index % target.workers,
                op=target.ops[cycle % len(target.ops)],
                delay_us=rng.jitter_us(target.max_delay_us),
            )
        )
    return tuple(steps)
