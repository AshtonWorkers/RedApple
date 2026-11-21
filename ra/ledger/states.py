"""Claim state machine (RA-LED-003)."""

from __future__ import annotations

from enum import StrEnum


class ClaimState(StrEnum):
    LIMBO = "limbo"
    BOUND = "bound"
    REVIEWED = "reviewed"
    PROMOTED = "promoted"
    DEMOTED = "demoted"
    PARKED = "parked"


TRANSITIONS: dict[ClaimState, frozenset[ClaimState]] = {
    ClaimState.LIMBO: frozenset({ClaimState.BOUND}),
    ClaimState.BOUND: frozenset({ClaimState.REVIEWED}),
    ClaimState.REVIEWED: frozenset({ClaimState.PROMOTED, ClaimState.DEMOTED, ClaimState.PARKED}),
    ClaimState.PROMOTED: frozenset(),
    ClaimState.DEMOTED: frozenset(),
    ClaimState.PARKED: frozenset(),
}

TERMINAL_STATES = frozenset({ClaimState.PROMOTED, ClaimState.DEMOTED, ClaimState.PARKED})


def can_transition(current: ClaimState, target: ClaimState) -> bool:
    """Return whether ``current -> target`` is legal."""
    return target in TRANSITIONS[current]
