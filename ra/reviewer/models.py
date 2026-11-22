"""Adversarial reviewer data model (RA-REV)."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..ledger.ids import sha256_hex

BUG_CLASSES = ("oob_read", "oob_write", "uaf", "type_confusion", "info_leak")
PRIMITIVES = (
    "none",
    "crash",
    "info_leak",
    "oob_read",
    "oob_write",
    "uaf",
    "type_confusion",
    "arbitrary_read",
    "arbitrary_write",
    "code_execution",
)
INSUFFICIENT_EVIDENCE = "insufficient_evidence"
NO_PRIMITIVE = "none"
REVIEW_GOAL = "Independently derive the bug class and weakest primitive from artifacts only."
REVIEW_CLAIM_TYPE = "review"
CANDIDATE_TYPES = frozenset(
    {"bug_class", "rung", "groom", "join", "gadget_set", "root_cause", "dupe_score"}
)


def now_ms() -> int:
    """Current Unix time in integer milliseconds."""
    return time.time_ns() // 1_000_000


def _token(value: object) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def normalize_bug_class(value: object) -> str:
    """Normalize a bug-class token to the PRESS bug_class vocabulary."""
    token = _token(value)
    if token in BUG_CLASSES:
        return token
    aliases = {
        "use_after_free": "uaf",
        "useafterfree": "uaf",
        "uaf_write": "uaf",
        "out_of_bounds_read": "oob_read",
        "oob_read_vuln": "oob_read",
        "out_of_bounds_write": "oob_write",
        "oob_write_vuln": "oob_write",
        "type_confusion_vuln": "type_confusion",
        "information_leak": "info_leak",
        "information_disclosure": "info_leak",
        "infoleak": "info_leak",
    }
    return aliases.get(token, INSUFFICIENT_EVIDENCE)


def normalize_primitive(value: object) -> str:
    """Normalize a primitive token to the reviewer primitive vocabulary."""
    token = _token(value)
    if token in PRIMITIVES:
        return token
    aliases = {
        "read_write": "oob_write",
        "relative_read_write": "oob_write",
        "rel_rw": "oob_write",
        "arbitrary_read_write": "arbitrary_write",
        "arbitrary_rw": "arbitrary_write",
        "code_exec": "code_execution",
        "rce": "code_execution",
        "none_proven": NO_PRIMITIVE,
    }
    return aliases.get(token, NO_PRIMITIVE)


_PRIMITIVE_RANK = {
    "none": 0,
    "crash": 1,
    "info_leak": 2,
    "oob_read": 3,
    "oob_write": 4,
    "uaf": 5,
    "type_confusion": 6,
    "arbitrary_read": 7,
    "arbitrary_write": 8,
    "code_execution": 9,
}


def primitive_rank(value: object) -> int:
    """Return the exploitability rank for a normalized primitive."""
    return _PRIMITIVE_RANK[normalize_primitive(value)]


def candidate_claim_fields(value_json: str) -> tuple[str, str]:
    """Extract the structured candidate bug class and primitive from claim JSON."""
    try:
        data = json.loads(value_json)
    except (TypeError, ValueError):
        return INSUFFICIENT_EVIDENCE, NO_PRIMITIVE
    if not isinstance(data, dict):
        return INSUFFICIENT_EVIDENCE, NO_PRIMITIVE
    bug_value = (
        data.get("bug_class")
        or data.get("bugClass")
        or data.get("answer")
        or data.get("class")
        or INSUFFICIENT_EVIDENCE
    )
    primitive_value = data.get("primitive") or data.get("weakest_primitive")
    bug_class = normalize_bug_class(str(bug_value))
    if primitive_value is None:
        primitive = bug_class if bug_class in PRIMITIVES else NO_PRIMITIVE
    else:
        primitive = normalize_primitive(str(primitive_value))
    return bug_class, primitive


@dataclass(frozen=True)
class ArtifactLink:
    """Ledger artifact link metadata for one claim artifact."""

    artifact_id: str
    kind: str
    role: str
    sha256: str
    byte_count: int
    ttl_class: str = "run"

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> ArtifactLink:
        return cls(
            artifact_id=str(row["artifact_id"]),
            kind=str(row["kind"]),
            role=str(row["role"]),
            sha256=str(row["sha256"]),
            byte_count=int(row["bytes"]),
            ttl_class=str(row["ttl_class"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "role": self.role,
            "sha256": self.sha256,
            "byte_count": self.byte_count,
            "ttl_class": self.ttl_class,
        }


@dataclass(frozen=True)
class ArtifactEvidence:
    """One artifact with optionally resolved bytes and a bounded excerpt."""

    link: ArtifactLink
    data: bytes | None = None
    excerpt: str = ""
    error: str | None = None

    @property
    def artifact_id(self) -> str:
        return self.link.artifact_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "link": self.link.to_dict(),
            "byte_count": self.link.byte_count,
            "resolved": self.data is not None,
            "excerpt": self.excerpt,
            "error": self.error,
        }


@dataclass(frozen=True)
class CheckResult:
    """One deterministic false-positive or rebuttal check."""

    name: str
    passed: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "reason": self.reason}


@dataclass(frozen=True)
class ReviewPacket:
    """Artifact-only packet sent to the independent reviewer model."""

    claim_id: str
    claim_type: str
    artifacts: tuple[ArtifactEvidence, ...] = field(default_factory=tuple)
    goal: str = REVIEW_GOAL

    def artifact_strings(self, *, max_artifacts: int = 3, max_chars: int = 1200) -> tuple[str, ...]:
        """Render bounded artifact excerpts; never includes claim prose."""
        out: list[str] = []
        for evidence in self.artifacts[:max_artifacts]:
            link = evidence.link
            body = evidence.excerpt if evidence.excerpt else f"error={evidence.error or 'empty'}"
            if len(body) > max_chars:
                body = body[:max_chars]
            out.append(
                "ARTIFACT "
                f"{link.artifact_id} kind={link.kind} role={link.role} "
                f"sha256={link.sha256} bytes={link.byte_count}\n{body}"
            )
        return tuple(out)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "goal": self.goal,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }

    def canonical_json(self) -> str:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return sha256_hex(self.canonical_json().encode("utf-8"))


@dataclass(frozen=True)
class IndependentDerivation:
    """Bug class and weakest primitive derived without proposer prose."""

    bug_class: str
    primitive: str
    confidence: float
    reasons: tuple[str, ...] = ()
    model_family: str = "unknown"
    error: bool = False

    def normalized(self) -> IndependentDerivation:
        try:
            confidence = float(self.confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        if not math.isfinite(confidence):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        try:
            if isinstance(self.reasons, str):
                reasons = (self.reasons,)
            else:
                reasons = tuple(str(item) for item in self.reasons)
        except TypeError:
            reasons = ()
        model_family = str(self.model_family) if self.model_family else "unknown"
        return IndependentDerivation(
            bug_class=normalize_bug_class(self.bug_class),
            primitive=normalize_primitive(self.primitive),
            confidence=confidence,
            reasons=reasons,
            model_family=model_family,
            error=bool(self.error),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bug_class": self.bug_class,
            "primitive": self.primitive,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "model_family": self.model_family,
            "error": self.error,
        }


@dataclass(frozen=True)
class ReviewDecision:
    """Ledger-bound review decision for one candidate claim."""

    agree: bool
    status: str
    candidate_bug_class: str
    candidate_primitive: str
    bug_class: str
    primitive: str
    checks: tuple[CheckResult, ...]
    reasons: tuple[str, ...]
    model_family: str
    packet_sha: str
    escalate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "agree": self.agree,
            "status": self.status,
            "candidate_bug_class": self.candidate_bug_class,
            "candidate_primitive": self.candidate_primitive,
            "bug_class": self.bug_class,
            "primitive": self.primitive,
            "checks": [check.to_dict() for check in self.checks],
            "reasons": list(self.reasons),
            "model_family": self.model_family,
            "packet_sha": self.packet_sha,
            "escalate": self.escalate,
        }


@dataclass(frozen=True)
class ReviewOutcome:
    """Result of reviewing one candidate claim."""

    status: str
    claim_id: str
    decision: ReviewDecision
    review_claim_id: str | None = None
    verdict_id: int | None = None
    work_order_id: str | None = None
    promoted: bool = False


class ArtifactResolver(Protocol):
    """Resolve ledger artifact metadata to bytes; CAS/lane stores own this."""

    async def resolve(self, link: ArtifactLink) -> bytes | None:
        """Return artifact bytes, or None when the store cannot resolve them."""
        ...


class ReviewModel(Protocol):
    """Independent reviewer model family."""

    family: str

    async def derive(self, packet: ReviewPacket) -> IndependentDerivation:
        """Derive bug class and weakest primitive from artifact-only packet."""
        ...


class EscalationSink(Protocol):
    """Sink for larger-model escalation work orders."""

    async def escalate(
        self,
        claim_id: str,
        review_claim_id: str,
        decision: ReviewDecision,
        *,
        run_id: str | None = None,
    ) -> str:
        """Escalate a frozen review and return the work-order id."""
        ...


class PromotionGate(Protocol):
    """Promotion gate interface; M3 owns the full gate."""

    async def promote(self, claim_id: str, *, review_claim_id: str) -> None:
        """Promote an agreed candidate claim."""
        ...
