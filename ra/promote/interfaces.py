"""Component interfaces for the promotion gate.

Triage, ladder/groom, dupe oracle, and adversarial reviewer are separate
workstreams. The gate depends only on these protocols so those components can
land independently.
"""

from __future__ import annotations

from typing import Protocol

from .models import (
    DupeEvidence,
    DupeResult,
    GroomEvidence,
    GroomResult,
    LadderEvidence,
    LadderResult,
    PolicyAuthorization,
    PolicyRequest,
    RemedyRequest,
    RemedyResult,
    ReviewEvidence,
    ReviewResult,
    TriageEvidence,
    TriageResult,
)


class TriageEngine(Protocol):
    async def classify(self, evidence: TriageEvidence) -> TriageResult:
        """Classify crash evidence into bug class, primitive, and dedup identity."""
        ...


class LadderEngine(Protocol):
    async def climb(self, evidence: LadderEvidence) -> LadderResult:
        """Attempt retained-crash primitive rungs and report the highest proof."""
        ...


class GroomEngine(Protocol):
    async def validate(self, evidence: GroomEvidence) -> GroomResult:
        """Validate a groom by exact before/after heap-state diff."""
        ...


class DupeOracle(Protocol):
    async def score(self, evidence: DupeEvidence) -> DupeResult:
        """Score submission order; scoring never suppresses a finding."""
        ...


class Reviewer(Protocol):
    async def review(self, evidence: ReviewEvidence) -> ReviewResult:
        """Independently derive bug class and primitive from artifacts only."""
        ...


class PolicyGate(Protocol):
    async def authorize_promotion(self, request: PolicyRequest) -> PolicyAuthorization:
        """Authorize the final promote side effect under policy caps."""
        ...

    async def plan_remedy(self, request: RemedyRequest) -> RemedyResult:
        """Enqueue a policy remedy for a paused or failed gate."""
        ...
