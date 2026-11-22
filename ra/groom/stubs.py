"""Stub dependencies for groom planning when triage/lanes/PRESS are absent."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import (
    AttemptEvidence,
    CrashCase,
    GroomCandidate,
    LadderRung,
    TriageResult,
)


class StaticTriage:
    """Deterministic triage stub using only fields already present on a crash."""

    async def classify(self, case: CrashCase) -> TriageResult:
        """Return a low-confidence triage result from crash metadata."""
        bug_class = case.bug_class or str(case.metadata.get("bug_class") or "unclassified")
        primitive_hint = case.primitive_hint or _opt_str(case.metadata.get("primitive_hint"))
        return TriageResult(
            bug_class=bug_class,
            primitive_hint=primitive_hint,
            confidence=0.25,
            rationale="static triage stub; no model verdict available",
        )


class NullAttemptPort:
    """Attempt port used until lane/foundry attempt executors are wired."""

    async def attempt(
        self,
        *,
        rung: LadderRung,
        candidate: GroomCandidate,
        case: CrashCase,
    ) -> AttemptEvidence:
        """Return a non-passing evidence record for every rung."""
        return AttemptEvidence(
            rung=rung,
            passed=False,
            consecutive_passes=0,
            assertion="",
            details={"stub": True, "reason": "no primitive attempt port configured"},
        )


class NullPressAdvisor:
    """PRESS advisor stub; no packets are emitted until PRESS is wired."""

    async def advise_rung(
        self,
        *,
        case: CrashCase,
        triage: TriageResult,
        rung: LadderRung,
    ) -> str | None:
        """No advice."""
        return None

    async def advise_groom(
        self,
        *,
        case: CrashCase,
        triage: TriageResult,
    ) -> Mapping[str, Any] | None:
        """No advice."""
        return None


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None
