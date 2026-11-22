"""Typed records shared by the triage classifier and ledger writer."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .sanitize import clean_text, safe_int


def now_ms() -> int:
    return int(time.time() * 1000)


class TriageStatus(StrEnum):
    BOUND = "bound"
    PARKED = "parked"
    DUPLICATE = "duplicate"


class BugClass(StrEnum):
    UAF = "uaf"
    TYPE_CONFUSION = "type_confusion"
    OOB_WRITE = "oob_write"
    INFO_LEAK = "info_leak"
    OOB_READ = "oob_read"
    OTHER = "other"


class ClassifyStatus(StrEnum):
    BOUND = "bound"
    ESCALATED = "escalated"
    SPLIT = "split"
    ERROR = "error"


BUG_CLASS_VOCAB: tuple[str, ...] = tuple(item.value for item in BugClass)
CRASH_CLASS_VOCAB: tuple[str, ...] = (
    "use-after-free",
    "double-free",
    "out-of-bounds",
    "type-confusion",
    "assertion",
    "stack-exhaustion",
    "null-deref",
    "integer-overflow",
    "uninitialized-memory",
    "use-after-poison",
    "timeout",
    "out-of-memory",
    "other",
)
KERNEL_RUBRIC_ORDER: tuple[str, ...] = (
    BugClass.UAF.value,
    BugClass.TYPE_CONFUSION.value,
    BugClass.OOB_WRITE.value,
    BugClass.INFO_LEAK.value,
    BugClass.OOB_READ.value,
    BugClass.OTHER.value,
)


@dataclass(frozen=True, slots=True)
class CrashEvidence:
    """Crash payload/metadata normalized away from any lane type."""

    id: str
    kind: str
    payload: bytes = b""
    path: str | None = None
    handle_id: str | None = None
    context: str = "app"
    created_ms: int = field(default_factory=now_ms)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SymbolizedCrash:
    crash_id: str
    crash_type: str
    frames: tuple[str, ...] = ()
    signal: str | None = None
    returncode: int | None = None
    stderr: str = ""
    repro: str = ""
    target: Mapping[str, Any] = field(default_factory=dict)
    symbolicated: bool = False
    source: str = "none"


@dataclass(frozen=True, slots=True)
class PacketRef:
    task_type: str
    sha: str
    offline: bool = False


@dataclass(frozen=True, slots=True)
class DedupSignature:
    dedup_key: str
    stack_hash: str
    alloc_site: str
    bug_class: str
    frames: tuple[str, ...]
    signature: tuple[int, ...]
    created_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "dedup_key": self.dedup_key,
            "stack_hash": self.stack_hash,
            "alloc_site": self.alloc_site,
            "bug_class": self.bug_class,
            "frames": list(self.frames),
            "signature": list(self.signature),
            "created_ms": self.created_ms,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DedupSignature:
        frames_raw = raw.get("frames", ())
        frames: tuple[str, ...] = ()
        if isinstance(frames_raw, (list, tuple)):
            cleaned_frames: list[str] = []
            for item in list(frames_raw)[:32]:
                text = clean_text(item, limit=240, keep_newlines=False)
                if text:
                    cleaned_frames.append(text)
            frames = tuple(cleaned_frames)
        signature_raw = raw.get("signature", ())
        signature: tuple[int, ...] = ()
        if isinstance(signature_raw, (list, tuple)):
            values: list[int] = []
            for item in list(signature_raw)[:256]:
                try:
                    values.append(int(item))
                except (TypeError, ValueError, OverflowError):
                    continue
            signature = tuple(values)
        return cls(
            dedup_key=clean_text(raw.get("dedup_key", ""), limit=128, keep_newlines=False),
            stack_hash=clean_text(raw.get("stack_hash", ""), limit=128, keep_newlines=False),
            alloc_site=clean_text(raw.get("alloc_site", ""), limit=256, keep_newlines=False),
            bug_class=clean_text(raw.get("bug_class", ""), limit=64, keep_newlines=False),
            frames=frames,
            signature=signature,
            created_ms=safe_int(raw.get("created_ms"), 0),
        )


@dataclass(frozen=True, slots=True)
class ClassifyResult:
    answer: str | None
    status: ClassifyStatus
    confidence: float
    packets: tuple[PacketRef, ...] = ()
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    data: Mapping[str, Any]
    packets: tuple[PacketRef, ...] = ()
    source: str = "fallback"
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class PocResult:
    markdown: str
    packets: tuple[PacketRef, ...] = ()
    source: str = "fallback"
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class TriageClaimResult:
    claim_id: str
    status: TriageStatus
    bug_class: str
    confidence: float
    claim_state: str
    duplicate_of: str | None = None
    error_code: str | None = None
    value: Mapping[str, Any] = field(default_factory=dict)
    artifacts: tuple[str, ...] = ()
    packets: tuple[PacketRef, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status.value,
            "bug_class": self.bug_class,
            "confidence": self.confidence,
            "claim_state": self.claim_state,
            "duplicate_of": self.duplicate_of,
            "error_code": self.error_code,
            "value": dict(self.value),
            "artifacts": list(self.artifacts),
            "packets": [
                {"task_type": item.task_type, "sha": item.sha, "offline": item.offline}
                for item in self.packets
            ],
        }
