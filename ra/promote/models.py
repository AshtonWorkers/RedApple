"""Data model for the promotion gate."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..ledger.ids import artifact_id, sha256_hex


class PromotionStage(StrEnum):
    """Gate stages in evaluation order."""

    TRIAGE = "triage"
    LADDER = "ladder"
    GROOM = "groom"
    DUPE = "dupe"
    REVIEWER = "reviewer"
    POLICY = "policy"
    PROMOTE = "promote"


class PromotionStatus(StrEnum):
    """Terminal or paused outcome of one gate evaluation."""

    PROMOTED = "promoted"
    ALREADY_PROMOTED = "already_promoted"
    DUPLICATE = "duplicate"
    REQUEUED = "requeued"
    ESCALATED = "escalated"
    DEMOTED = "demoted"
    PARKED = "parked"
    BUDGET_GATE = "budget_gate"


class TriageStatus(StrEnum):
    CLASSIFIED = "classified"
    INSUFFICIENT = "insufficient"
    SPLIT = "split"
    DUPLICATE = "duplicate"
    UNAVAILABLE = "unavailable"
    RETRY = "retry"


class LadderStatus(StrEnum):
    PASSED = "passed"
    RETRY = "retry"
    EXHAUSTED = "exhausted"
    UNAVAILABLE = "unavailable"


class GroomStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    DEFECT = "defect"
    RETRY = "retry"
    UNAVAILABLE = "unavailable"


class DupeStatus(StrEnum):
    SCORED = "scored"
    RETRY = "retry"
    UNAVAILABLE = "unavailable"


class ReviewStatus(StrEnum):
    OK = "ok"
    RETRY = "retry"
    UNAVAILABLE = "unavailable"


LADDER_RUNGS = ("info_leak", "oob_read", "rel_rw")
ARTIFACT_TTL_CLASSES = frozenset({"ephemeral", "run", "pinned"})


@dataclass(frozen=True)
class EvidenceArtifact:
    """Artifact bytes offered to the gate; the ledger stores only the CAS metadata."""

    kind: str
    data: bytes
    role: str = "evidence"
    ttl_class: str = "run"

    def to_view(self, *, data: bool = True) -> ArtifactView:
        """Return the ledger-shaped artifact view, optionally carrying bytes."""
        return ArtifactView(
            artifact_id=artifact_id(self.data),
            kind=self.kind,
            sha256=sha256_hex(self.data),
            size=len(self.data),
            role=self.role,
            ttl_class=self.ttl_class,
            data=self.data if data else None,
        )


@dataclass(frozen=True)
class ArtifactView:
    """Artifact metadata visible to gate components.

    ``data`` is present only when the bytes are already in memory; reviewers that
    need bytes should be constructed with their own artifact reader.
    """

    artifact_id: str
    kind: str
    sha256: str
    size: int
    role: str
    ttl_class: str = "run"
    data: bytes | None = None

    @classmethod
    def from_ledger_row(cls, row: Mapping[str, Any], *, data: bytes | None = None) -> ArtifactView:
        return cls(
            artifact_id=str(row["artifact_id"]),
            kind=str(row["kind"]),
            sha256=str(row["sha256"]),
            size=int(row["bytes"]),
            role=str(row["role"]),
            ttl_class=str(row["ttl_class"]),
            data=data,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
            "ttl_class": self.ttl_class,
        }


@dataclass(frozen=True)
class TriageEvidence:
    case_id: str
    artifacts: tuple[ArtifactView, ...]
    run_id: str | None = None
    attempt: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LadderEvidence:
    case_id: str
    claim_id: str
    bug_class: str
    primitive: str
    artifacts: tuple[ArtifactView, ...]
    run_id: str | None = None
    attempt: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GroomEvidence:
    case_id: str
    claim_id: str
    bug_class: str
    primitive: str
    rung: str
    assertions: tuple[str, ...]
    artifacts: tuple[ArtifactView, ...]
    run_id: str | None = None
    attempt: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DupeEvidence:
    case_id: str
    claim_id: str
    bug_class: str
    primitive: str
    rung: str
    groom_validator: str
    artifacts: tuple[ArtifactView, ...]
    run_id: str | None = None
    attempt: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReviewEvidence:
    """Reviewer input. Deliberately excludes proposer prose such as value_json."""

    case_id: str
    claim_id: str
    artifacts: tuple[ArtifactView, ...]
    run_id: str | None = None
    attempt: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyRequest:
    claim_id: str
    dupe_score: float
    run_id: str | None = None
    ingress_weight: float = 1.0
    chain_bonus: float = 1.0
    probability_join: float = 1.0
    estimated_cost_usd_micro: int = 0
    attempt: int = 0


@dataclass(frozen=True)
class RemedyRequest:
    claim_id: str
    stage: PromotionStage
    reason: str
    action: str
    run_id: str | None = None
    probability_join: float = 1.0
    chain_bonus: float = 1.0
    ingress_weight: float = 1.0
    attempt: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TriageResult:
    status: TriageStatus
    bug_class: str | None = None
    primitive: str | None = None
    confidence: float = 0.0
    dedup_key: str | None = None
    duplicate_of: str | None = None
    reason: str = ""
    artifact: EvidenceArtifact | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "bug_class": self.bug_class,
            "primitive": self.primitive,
            "confidence": self.confidence,
            "dedup_key": self.dedup_key,
            "duplicate_of": self.duplicate_of,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LadderResult:
    status: LadderStatus
    rung: str | None = None
    assertions: tuple[str, ...] = ()
    consecutive_passes: int = 0
    required_passes: int = 3
    reason: str = ""
    artifact: EvidenceArtifact | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "rung": self.rung,
            "assertions": list(self.assertions),
            "consecutive_passes": self.consecutive_passes,
            "required_passes": self.required_passes,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class GroomResult:
    status: GroomStatus
    validator: str | None = None
    reason: str = ""
    artifact: EvidenceArtifact | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "validator": self.validator,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DupeResult:
    status: DupeStatus
    saturation: float = 0.0
    patch_proximity: float = 0.0
    shipped_coverage: float = 0.0
    score: float = 0.0
    reason: str = ""
    artifact: EvidenceArtifact | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "saturation": self.saturation,
            "patch_proximity": self.patch_proximity,
            "shipped_coverage": self.shipped_coverage,
            "score": self.score,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ReviewVerdict:
    reviewer: str
    bug_class: str
    primitive: str
    confidence: float = 1.0
    reviewer_family: str | None = None
    reason: str = ""
    artifact: EvidenceArtifact | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reviewer": self.reviewer,
            "bug_class": self.bug_class,
            "primitive": self.primitive,
            "confidence": self.confidence,
            "reviewer_family": self.reviewer_family,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ReviewResult:
    status: ReviewStatus
    verdict: ReviewVerdict | None = None
    reason: str = ""


@dataclass(frozen=True)
class PolicyAuthorization:
    allowed: bool
    reason: str = "ok"
    spent_usd_micro: int = 0
    decision_id: int | None = None


@dataclass(frozen=True)
class RemedyResult:
    work_order_id: str | None
    action: str
    state: str = "ready"
    reason: str = ""


@dataclass(frozen=True)
class PromotionRequest:
    case_id: str
    artifacts: tuple[EvidenceArtifact, ...]
    run_id: str | None = None
    attempt: int = 0
    proposer_family: str | None = None
    probability_join: float = 1.0
    chain_bonus: float = 1.0
    ingress_weight: float = 1.0
    estimated_cost_usd_micro: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def validated(self) -> PromotionRequest:
        """Return this request after enforcing gate input invariants."""
        if not self.case_id.strip():
            raise ValueError("case_id must be non-empty")
        if self.attempt < 0:
            raise ValueError("attempt must be >= 0")
        if not self.artifacts:
            raise ValueError("at least one evidence artifact is required")
        for artifact in self.artifacts:
            if not artifact.kind.strip():
                raise ValueError("artifact kind must be non-empty")
            if not artifact.role.strip():
                raise ValueError("artifact role must be non-empty")
            if artifact.ttl_class not in ARTIFACT_TTL_CLASSES:
                raise ValueError("artifact ttl_class must be ephemeral, run, or pinned")
            if not artifact.data:
                raise ValueError("artifact data must be non-empty")
        for name, value in (
            ("probability_join", self.probability_join),
            ("chain_bonus", self.chain_bonus),
            ("ingress_weight", self.ingress_weight),
        ):
            if isinstance(value, bool) or not math.isfinite(value) or value < 0.0:
                raise ValueError(f"{name} must be a finite non-negative number")
        if isinstance(self.estimated_cost_usd_micro, bool) or self.estimated_cost_usd_micro < 0:
            raise ValueError("estimated_cost_usd_micro must be a non-negative int")
        return self

    def artifact_views(self) -> tuple[ArtifactView, ...]:
        views = [artifact.to_view() for artifact in self.artifacts]
        return tuple(sorted(views, key=lambda item: (item.artifact_id, item.role)))


@dataclass(frozen=True)
class SubmissionEntry:
    claim_id: str
    bug_class: str
    primitive: str
    dupe_score: float
    created: int
    state: str = "promoted"
    artifact_count: int = 0

    def sort_key(self) -> tuple[float, int, str]:
        """Total order: dupe score desc, created asc, id asc (I5)."""
        return (-self.dupe_score, self.created, self.claim_id)


@dataclass(frozen=True)
class PromotionResult:
    status: PromotionStatus
    reason: str
    claim_id: str | None = None
    stage: PromotionStage | None = None
    work_order_id: str | None = None
    verdict_id: int | None = None
    submission: SubmissionEntry | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "claim_id": self.claim_id,
            "stage": None if self.stage is None else self.stage.value,
            "work_order_id": self.work_order_id,
            "verdict_id": self.verdict_id,
            "submission": None if self.submission is None else self.submission.__dict__,
            "details": dict(self.details),
        }


def json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes for ledger artifacts."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def json_loads(raw: bytes | str) -> Any:
    """Parse JSON produced by :func:`json_bytes`."""
    return json.loads(raw)


def sorted_artifact_views(views: Sequence[ArtifactView]) -> tuple[ArtifactView, ...]:
    """Return artifact views in deterministic order."""
    return tuple(sorted(views, key=lambda item: (item.artifact_id, item.role)))
