"""Clean interfaces for chain dependencies that are implemented elsewhere."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .models import PrimitiveProfile


class PrimitiveProvider(Protocol):
    """Ladder/groom facts for primitive claims."""

    def profile(
        self, claim_id: str, claim_type: str, value: Mapping[str, Any]
    ) -> PrimitiveProfile | None:
        """Return ladder/groom facts for one claim, or None when unknown."""
        ...


class DupeOracle(Protocol):
    """Dupe score oracle for claim novelty/submission value."""

    def score(self, claim_id: str) -> float:
        """Return a novelty score in [0, 1]; higher is more valuable."""
        ...


class PolicyAdvisor(Protocol):
    """Policy-facing cost/floor advice for joins and subfactories."""

    def join_cost_usd_micro(self) -> int:
        """Integer micro-USD cost to prove one join."""
        ...

    def subfactory_cost_usd_micro(self) -> int:
        """Integer micro-USD cost to spawn one subfactory."""
        ...

    def subfactory_floor(self) -> float:
        """Minimum join lower bound considered proven enough to skip subfactory."""
        ...
