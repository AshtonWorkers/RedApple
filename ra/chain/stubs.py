"""Deterministic stubs for ladder/groom, dupe, and policy dependencies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..errors import FormatFail
from ..policy.actions import ACTION_COST_USD_MICRO, Action
from .models import RESEARCH_LOWER_BOUND, PrimitiveProfile


class NullPrimitiveProvider:
    """Stub used until the ladder/groom component lands."""

    def profile(
        self, claim_id: str, claim_type: str, value: Mapping[str, Any]
    ) -> PrimitiveProfile | None:
        return None


class StaticPrimitiveProvider:
    """Test/integration stub backed by an explicit claim-id profile map."""

    def __init__(self, profiles: Mapping[str, PrimitiveProfile] | None = None) -> None:
        self._profiles = dict(profiles or {})

    def profile(
        self, claim_id: str, claim_type: str, value: Mapping[str, Any]
    ) -> PrimitiveProfile | None:
        return self._profiles.get(claim_id)


class StaticDupeOracle:
    """Test/integration stub backed by an explicit score map."""

    def __init__(self, scores: Mapping[str, float] | None = None, *, default: float = 1.0) -> None:
        self._scores = dict(scores or {})
        self._default = default

    def score(self, claim_id: str) -> float:
        value = self._scores.get(claim_id, self._default)
        if not 0.0 <= value <= 1.0:
            raise FormatFail("dupe score must be in [0, 1]")
        return value


class DefaultPolicyAdvisor:
    """Policy stub using the M0 Appendix D action costs."""

    def join_cost_usd_micro(self) -> int:
        return ACTION_COST_USD_MICRO[Action.TRY_GADGET_SET]

    def subfactory_cost_usd_micro(self) -> int:
        return ACTION_COST_USD_MICRO[Action.SPAWN_SUBFACTORY]

    def subfactory_floor(self) -> float:
        return RESEARCH_LOWER_BOUND
