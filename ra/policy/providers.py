"""Pluggable EV and lane-state providers for the policy engine.

Chain search, the dupe oracle, and lane adapters are separate components. The
policy engine depends only on these protocols; the defaults are deterministic
stubs that keep the engine honest until those components land.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .actions import Action
from .models import EVInputs, LaneAvailability


class EVInputProvider(Protocol):
    """Supply chain/dupe EV inputs for a unit."""

    async def inputs_for(
        self, *, action: Action, unit: str, run_id: str | None
    ) -> EVInputs: ...


class StaticEVInputProvider:
    """Deterministic EV provider for tests and offline runs."""

    def __init__(
        self,
        default: EVInputs | None = None,
        *,
        by_unit: Mapping[str, EVInputs] | None = None,
    ) -> None:
        self._default = default or EVInputs(probability_join=0.0)
        self._by_unit = dict(by_unit or {})

    async def inputs_for(
        self, *, action: Action, unit: str, run_id: str | None
    ) -> EVInputs:
        return self._by_unit.get(unit, self._default)


class LaneStateProvider(Protocol):
    """Report whether a lane can accept work right now."""

    async def availability(self, lane_id: str) -> LaneAvailability: ...


class StaticLaneStateProvider:
    """Deterministic lane provider; unknown lanes are free."""

    def __init__(self, states: Mapping[str, LaneAvailability] | None = None) -> None:
        self._states = dict(states or {})

    async def availability(self, lane_id: str) -> LaneAvailability:
        return self._states.get(lane_id, LaneAvailability(lane_id=lane_id))
