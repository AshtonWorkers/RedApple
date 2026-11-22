"""Data model for the RedApple groom planner and primitive ladder."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

MAX_GROOM_DEPTH = 3
MAX_GROOM_CANDIDATES = 64
PROMOTION_CONSECUTIVE_PASSES = 3

_SIZE_CLASS_RE = re.compile(r"^kalloc_[0-9]+$")


class LadderRung(StrEnum):
    """Primitive ladder rungs in escalation order (RA-LAD-001)."""

    INFO_LEAK = "info_leak"
    OOB_READ = "oob_read"
    REL_RW = "rel_rw"


LADDER_ORDER: tuple[LadderRung, ...] = (
    LadderRung.INFO_LEAK,
    LadderRung.OOB_READ,
    LadderRung.REL_RW,
)

RUNG_ASSERTIONS: Mapping[LadderRung, str] = {
    LadderRung.INFO_LEAK: "info_leak.stable",
    LadderRung.OOB_READ: "oob_read.bounds",
    LadderRung.REL_RW: "rel_rw.readback",
}


def now_ms() -> int:
    """Current Unix time in integer milliseconds."""
    return time.time_ns() // 1_000_000


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for ledger artifacts and digests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    """SHA-256 hex digest for a UTF-8 string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CrashCase:
    """One retained crash presented to groom/ladder planning.

    This is intentionally structural so ``ra.groom`` does not import the lane
    package; lane adapters can map ``CrashRef`` into this DTO at the fleet edge.
    """

    id: str
    target: str = "unknown"
    ring_node: str = "unknown"
    payload: bytes = b""
    bug_class: str | None = None
    primitive_hint: str | None = None
    format: str | None = None
    run_id: str | None = None
    created_ms: int = field(default_factory=now_ms)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CrashCase:
        """Build a case from a lane/triage-shaped mapping without lane imports."""
        metadata = value.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}
        payload = value.get("payload", b"")
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            payload_bytes = payload
        else:
            payload_bytes = b""
        return cls(
            id=str(value.get("id") or value.get("crash_id") or "crash_unknown"),
            target=str(value.get("target") or value.get("handle_id") or "unknown"),
            ring_node=str(value.get("ring_node") or value.get("build") or "unknown"),
            payload=payload_bytes,
            bug_class=_opt_str(value.get("bug_class")),
            primitive_hint=_opt_str(value.get("primitive_hint") or value.get("primitive")),
            format=_opt_str(value.get("format")),
            run_id=_opt_str(value.get("run_id")),
            created_ms=int(value.get("created_ms") or now_ms()),
            metadata=dict(metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "id": self.id,
            "target": self.target,
            "ring_node": self.ring_node,
            "payload_sha256": hashlib.sha256(self.payload).hexdigest(),
            "payload_bytes": len(self.payload),
            "bug_class": self.bug_class,
            "primitive_hint": self.primitive_hint,
            "format": self.format,
            "run_id": self.run_id,
            "created_ms": self.created_ms,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class TriageResult:
    """Triage output consumed by the groom planner."""

    bug_class: str
    primitive_hint: str | None = None
    confidence: float = 0.0
    rationale: str = ""
    artifacts: tuple[bytes, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "bug_class": self.bug_class,
            "primitive_hint": self.primitive_hint,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "artifact_count": len(self.artifacts),
        }


@dataclass(frozen=True)
class HeapObject:
    """Allocator-model heap object identity, excluding absolute addresses."""

    size_class: str
    cage: str = ""
    isoheap: str = ""
    structure_id: str = ""
    role: str = "object"
    state: str = "allocated"

    def __post_init__(self) -> None:
        if _SIZE_CLASS_RE.match(self.size_class) is None:
            raise ValueError(f"invalid size class {self.size_class!r}")

    def key(self) -> tuple[str, str, str, str, str, str]:
        """Canonical identity used by exact heap diffs."""
        return (
            self.size_class,
            self.cage,
            self.isoheap,
            self.structure_id,
            self.role,
            self.state,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "size_class": self.size_class,
            "cage": self.cage,
            "isoheap": self.isoheap,
            "structure_id": self.structure_id,
            "role": self.role,
            "state": self.state,
        }


@dataclass(frozen=True)
class HeapSnapshot:
    """Exact heap-state snapshot for before/after grooming validation."""

    label: str
    objects: tuple[HeapObject, ...] = ()

    @classmethod
    def from_objects(cls, label: str, objects: tuple[HeapObject, ...]) -> HeapSnapshot:
        """Create a snapshot with deterministic object ordering."""
        return cls(label=label, objects=tuple(sorted(objects, key=HeapObject.key)))

    def digest(self) -> str:
        """Content digest of the canonical snapshot."""
        payload = canonical_json({"label": self.label, "objects": [o.key() for o in self.objects]})
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "digest": self.digest(),
            "objects": [obj.to_dict() for obj in self.objects],
        }


@dataclass(frozen=True)
class HeapDiff:
    """Exact multiset difference between two heap snapshots."""

    added: tuple[HeapObject, ...] = ()
    removed: tuple[HeapObject, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.added and not self.removed

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": [obj.to_dict() for obj in self.added],
            "removed": [obj.to_dict() for obj in self.removed],
        }


@dataclass(frozen=True)
class HeapDiffExpectation:
    """Expected exact before/after delta for a groom validation."""

    added: tuple[HeapObject, ...] = ()
    removed: tuple[HeapObject, ...] = ()

    def matches(self, diff: HeapDiff) -> bool:
        return diff.added == self.added and diff.removed == self.removed

    def to_dict(self) -> dict[str, Any]:
        return {"added": [obj.to_dict() for obj in self.added], "removed": [obj.to_dict() for obj in self.removed]}


@dataclass(frozen=True)
class GroomCandidate:
    """One allocator-aware groom dialect candidate."""

    candidate_id: str
    depth: int
    score: float
    dialect: Mapping[str, Any]
    size_class: str
    cage: str = ""
    isoheap: str = ""
    structure_id: str = ""
    provenance: Mapping[str, str] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "depth": self.depth,
            "score": self.score,
            "dialect": dict(self.dialect),
            "size_class": self.size_class,
            "cage": self.cage,
            "isoheap": self.isoheap,
            "structure_id": self.structure_id,
            "provenance": dict(self.provenance),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class GroomPlan:
    """Ledger-persisted groom plan for one retained crash."""

    plan_id: str
    crash_id: str
    candidates: tuple[GroomCandidate, ...]
    created_ms: int = field(default_factory=now_ms)
    stats: Mapping[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "crash_id": self.crash_id,
            "created_ms": self.created_ms,
            "stats": dict(self.stats),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass(frozen=True)
class AttemptEvidence:
    """Lane/foundry evidence for one ladder rung attempt."""

    rung: LadderRung
    passed: bool
    consecutive_passes: int = 0
    assertion: str = ""
    assertion_results: Mapping[str, bool] = field(default_factory=dict)
    heap_before: HeapSnapshot | None = None
    heap_after: HeapSnapshot | None = None
    heap_expectation: HeapDiffExpectation | None = None
    artifact_payload: bytes = b""
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rung": self.rung.value,
            "passed": self.passed,
            "consecutive_passes": self.consecutive_passes,
            "assertion": self.assertion,
            "assertion_results": dict(self.assertion_results),
            "heap_before": None if self.heap_before is None else self.heap_before.to_dict(),
            "heap_after": None if self.heap_after is None else self.heap_after.to_dict(),
            "heap_expectation": (
                None if self.heap_expectation is None else self.heap_expectation.to_dict()
            ),
            "artifact_payload_sha256": hashlib.sha256(self.artifact_payload).hexdigest(),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class RungResult:
    """Outcome of one ladder rung attempt."""

    rung: LadderRung
    candidate_id: str
    passed: bool
    promoted: bool
    consecutive_passes: int
    assertion: str
    reason: str
    evidence: AttemptEvidence | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rung": self.rung.value,
            "candidate_id": self.candidate_id,
            "passed": self.passed,
            "promoted": self.promoted,
            "consecutive_passes": self.consecutive_passes,
            "assertion": self.assertion,
            "reason": self.reason,
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class GroomPlanOutcome:
    """Result of planning grooms for one crash."""

    case: CrashCase
    triage: TriageResult
    plan: GroomPlan
    claim_id: str | None
    defects: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if self.plan.candidates:
            return "planned"
        return "defect" if self.defects else "no_candidates"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "case": self.case.to_dict(),
            "triage": self.triage.to_dict(),
            "plan": self.plan.to_dict(),
            "claim_id": self.claim_id,
            "defects": list(self.defects),
        }


@dataclass(frozen=True)
class LadderOutcome:
    """Ledger-backed result of running the primitive ladder."""

    case: CrashCase
    plan_id: str | None
    results: tuple[RungResult, ...]
    claim_id: str | None
    status: str
    error_code: str | None = None

    @property
    def highest_promoted(self) -> LadderRung | None:
        promoted = [result.rung for result in self.results if result.promoted]
        if not promoted:
            return None
        return LADDER_ORDER[max(LADDER_ORDER.index(rung) for rung in promoted)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "error_code": self.error_code,
            "case": self.case.to_dict(),
            "plan_id": self.plan_id,
            "claim_id": self.claim_id,
            "highest_promoted": (
                None if self.highest_promoted is None else self.highest_promoted.value
            ),
            "results": [result.to_dict() for result in self.results],
        }


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None
