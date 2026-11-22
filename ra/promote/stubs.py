"""Unavailable stubs for promotion-gate dependencies that are not built yet."""

from __future__ import annotations

from .models import (
    DupeEvidence,
    DupeResult,
    DupeStatus,
    GroomEvidence,
    GroomResult,
    GroomStatus,
    LadderEvidence,
    LadderResult,
    LadderStatus,
    ReviewEvidence,
    ReviewResult,
    ReviewStatus,
    TriageEvidence,
    TriageResult,
    TriageStatus,
)


class StubTriage:
    async def classify(self, evidence: TriageEvidence) -> TriageResult:
        del evidence
        return TriageResult(
            status=TriageStatus.UNAVAILABLE,
            reason="triage component is not implemented",
        )


class StubLadder:
    async def climb(self, evidence: LadderEvidence) -> LadderResult:
        del evidence
        return LadderResult(
            status=LadderStatus.UNAVAILABLE,
            reason="ladder component is not implemented",
        )


class StubGroom:
    async def validate(self, evidence: GroomEvidence) -> GroomResult:
        del evidence
        return GroomResult(
            status=GroomStatus.UNAVAILABLE,
            reason="groom component is not implemented",
        )


class StubDupe:
    async def score(self, evidence: DupeEvidence) -> DupeResult:
        del evidence
        return DupeResult(
            status=DupeStatus.UNAVAILABLE,
            reason="dupe oracle is not implemented",
        )


class StubReviewer:
    async def review(self, evidence: ReviewEvidence) -> ReviewResult:
        del evidence
        return ReviewResult(
            status=ReviewStatus.UNAVAILABLE,
            reason="adversarial reviewer is not implemented",
        )
