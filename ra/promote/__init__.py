"""Promotion gate package.

The gate orchestrates crash promotion over the claim ledger while the
triage, ladder/groom, dupe, and reviewer components remain behind interfaces.
"""

from .gate import PromotionGate
from .interfaces import (
    DupeOracle,
    GroomEngine,
    LadderEngine,
    PolicyGate,
    Reviewer,
    TriageEngine,
)
from .models import (
    DupeResult,
    DupeStatus,
    EvidenceArtifact,
    GroomResult,
    GroomStatus,
    LadderResult,
    LadderStatus,
    PolicyAuthorization,
    PolicyRequest,
    PromotionRequest,
    PromotionResult,
    PromotionStage,
    PromotionStatus,
    RemedyRequest,
    RemedyResult,
    ReviewResult,
    ReviewStatus,
    ReviewVerdict,
    SubmissionEntry,
    TriageResult,
    TriageStatus,
)
from .policy import LedgerPolicyGate
from .stubs import StubDupe, StubGroom, StubLadder, StubReviewer, StubTriage

__all__ = [
    "DupeOracle",
    "DupeResult",
    "DupeStatus",
    "EvidenceArtifact",
    "GroomEngine",
    "GroomResult",
    "GroomStatus",
    "LadderEngine",
    "LadderResult",
    "LadderStatus",
    "LedgerPolicyGate",
    "PolicyAuthorization",
    "PolicyGate",
    "PolicyRequest",
    "PromotionGate",
    "PromotionRequest",
    "PromotionResult",
    "PromotionStage",
    "PromotionStatus",
    "RemedyRequest",
    "RemedyResult",
    "ReviewResult",
    "ReviewStatus",
    "ReviewVerdict",
    "Reviewer",
    "StubDupe",
    "StubGroom",
    "StubLadder",
    "StubReviewer",
    "StubTriage",
    "SubmissionEntry",
    "TriageEngine",
    "TriageResult",
    "TriageStatus",
]
