"""Clean interfaces to components groom depends on.

``ra.groom`` deliberately does not import ``ra.lanes``; lane code adapts
``CrashRef``/heap evidence into these DTOs at the fleet edge.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .models import (
    AttemptEvidence,
    CrashCase,
    GroomCandidate,
    LadderRung,
    TriageResult,
)


class TriageService(Protocol):
    """Crash triage service producing the groom planner's input."""

    async def classify(self, case: CrashCase) -> TriageResult:
        """Classify one retained crash."""
        raise NotImplementedError


class FoundryDialectValidator(Protocol):
    """Foundry-side groom dialect validator."""

    def validate(self, dialect: Mapping[str, Any]) -> None:
        """Raise ``DialectDefect`` when a dialect is invalid."""
        raise NotImplementedError


class FoundryDefectSink(Protocol):
    """Sink for reporting invalid groom dialects back to foundry."""

    async def report_dialect_defect(
        self,
        *,
        candidate: GroomCandidate,
        case: CrashCase,
        error: str,
    ) -> None:
        """Persist one dialect defect report."""
        raise NotImplementedError


class PrimitiveAttemptPort(Protocol):
    """Lane/foundry port that attempts one ladder rung for one candidate."""

    async def attempt(
        self,
        *,
        rung: LadderRung,
        candidate: GroomCandidate,
        case: CrashCase,
    ) -> AttemptEvidence:
        """Run one rung attempt and return evidence."""
        raise NotImplementedError


class PressAdvisor(Protocol):
    """Optional PRESS advisor for ``rung_select`` and ``groom_fill`` packets."""

    async def advise_rung(
        self,
        *,
        case: CrashCase,
        triage: TriageResult,
        rung: LadderRung,
    ) -> str | None:
        """Return optional PRESS advice for a rung, or ``None`` when unavailable."""
        raise NotImplementedError

    async def advise_groom(
        self,
        *,
        case: CrashCase,
        triage: TriageResult,
    ) -> Mapping[str, Any] | None:
        """Return optional PRESS advice for groom planning, or ``None``."""
        raise NotImplementedError
