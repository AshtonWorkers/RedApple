"""Race execution backends (RA-RACE-003).

A backend executes one deterministic schedule and reports observed crashes.
Backends are pure with respect to the schedule when ``deterministic`` is true;
lane-backed hardware is not, and the harness measures that as flakiness.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from ..errors import FormatFail
from ..ledger.ids import sha256_hex
from .models import RaceCrash, RaceRunResult, RaceSchedule


class RaceBackend(Protocol):
    """Execution surface used by the stochastic race harness."""

    name: str
    deterministic: bool

    async def run_schedule(self, schedule: RaceSchedule) -> RaceRunResult:
        """Execute ``schedule`` once and return observed crashes."""
        ...


class ScriptExhaustedError(RuntimeError):
    """Scripted backend ran out of scripted outcomes."""


class DeterministicRaceBackend:
    """Hardware-free backend whose crash decision is a pure function of the schedule.

    This models an idealized race target: replaying the same schedule always
    yields the same crashes, which is what deterministic replay (RA-RACE-004)
    verifies end to end without devices.
    """

    name = "deterministic"
    deterministic = True

    def __init__(
        self,
        *,
        crash_threshold: int = 0,
        crash_kind: str = "race_toctou",
        crash_rule: Callable[[RaceSchedule], Sequence[RaceCrash]] | None = None,
    ) -> None:
        if crash_threshold < 0 or crash_threshold > 256:
            raise FormatFail("crash_threshold must be in [0, 256]")
        if crash_rule is not None and not callable(crash_rule):
            raise FormatFail("crash_rule must be callable")
        self._crash_threshold = crash_threshold
        self._crash_kind = crash_kind
        self._crash_rule = crash_rule

    def _default_crashes(self, schedule: RaceSchedule) -> tuple[RaceCrash, ...]:
        if int(schedule.digest[:2], 16) >= self._crash_threshold:
            return ()
        crash = RaceCrash(
            id=f"racecrash_{schedule.digest[:24]}",
            kind=self._crash_kind,
            context="kernel",
            digest=sha256_hex(b"race-crash|" + schedule.digest.encode("ascii")),
            payload=b"race-crash\x00" + schedule.digest.encode("ascii"),
            metadata={
                "iteration": schedule.iteration,
                "schedule_digest": schedule.digest,
                "seed": schedule.seed_hex,
            },
        )
        return (crash,)

    async def run_schedule(self, schedule: RaceSchedule) -> RaceRunResult:
        crashes = (
            tuple(self._crash_rule(schedule))
            if self._crash_rule is not None
            else self._default_crashes(schedule)
        )
        duration_ms = (sum(step.delay_us for step in schedule.steps) // 1000) + len(
            schedule.steps
        )
        return RaceRunResult.for_schedule(
            schedule,
            crashes=crashes,
            duration_ms=duration_ms,
        )


class ScriptedRaceBackend:
    """Outcome-scripted backend for unit, property, and failure-injection tests.

    Outcomes are consumed in FIFO order per ``run_schedule`` call; an
    ``Exception`` instance is raised instead of returning a result. Results are
    validated against the schedule digest so scripted tests cannot drift from
    the schedule under test.
    """

    def __init__(
        self,
        outcomes: Sequence[RaceRunResult | Exception] = (),
        *,
        name: str = "scripted",
        deterministic: bool = True,
    ) -> None:
        self._outcomes = list(outcomes)
        self.name = name
        self.deterministic = deterministic
        self.calls: list[str] = []

    def push(self, outcome: RaceRunResult | Exception) -> None:
        """Append one scripted outcome."""
        self._outcomes.append(outcome)

    async def run_schedule(self, schedule: RaceSchedule) -> RaceRunResult:
        self.calls.append(schedule.digest)
        if not self._outcomes:
            raise ScriptExhaustedError("scripted race backend has no outcome queued")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome.schedule_digest != schedule.digest:
            raise FormatFail("scripted race outcome schedule_digest mismatch")
        return outcome
