"""Deterministic false-positive checks and rebuttal heuristics for adversarial review."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ra.ledger.ids import sha256_hex
from ra.reviewer.models import (
    BUG_CLASSES,
    INSUFFICIENT_EVIDENCE,
    NO_PRIMITIVE,
    ArtifactEvidence,
    CheckResult,
    primitive_rank,
)

_CRASH_KIND_TOKENS = (
    "crash",
    "repro",
    "ips",
    "hang",
    "panic",
    "asan",
    "sanitizer",
    "leak",
    "info_leak",
    "disclosure",
)
_CRASH_TEXT_TOKENS = (
    "exc_bad_access",
    "exc_breakpoint",
    "exc_crash",
    "sigsegv",
    "sigabrt",
    "sigbus",
    "sigill",
    "sigtrap",
    "sigfpe",
    "addresssanitizer",
    "asan",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "use after free",
    "double-free",
    "double free",
    "type confusion",
    "null pointer",
    "bad access",
    "out of bounds",
    "out-of-bounds",
    "oob read",
    "oob write",
    "write of size",
    "read of size",
    "crash",
    "panic",
    "fault",
)

_UAF_TOKENS = (
    "use-after-free",
    "use after free",
    "use_after_free",
    "uaf",
    "freed object",
    "double free",
    "double-free",
    "object is freed",
    "attempting free",
    "deallocated",
)
_TYPE_CONFUSION_TOKENS = (
    "type confusion",
    "type-confusion",
    "type_confusion",
    "bad cast",
    "invalid cast",
    "vtable",
    "structure id",
    "jsvalue",
    "jsobject",
    "jsarray",
)
_OOB_WRITE_TOKENS = (
    "out-of-bounds write",
    "out of bounds write",
    "oob write",
    "oob_write",
    "heap-buffer-overflow write",
    "buffer overflow write",
    "write past",
    "write overflow",
)
_OOB_READ_TOKENS = (
    "out-of-bounds read",
    "out of bounds read",
    "oob read",
    "oob_read",
    "heap-buffer-overflow read",
    "buffer overflow read",
    "read past",
    "read overflow",
)
_GENERIC_OVERFLOW_TOKENS = ("heap-buffer-overflow", "stack-buffer-overflow", "buffer-overflow")
_INFO_LEAK_TOKENS = (
    "info leak",
    "information leak",
    "information disclosure",
    "disclosure",
    "uninitialized",
    "heap metadata",
    "address leak",
    "leak",
)
_CODE_EXEC_TOKENS = (
    "code execution",
    "arbitrary code",
    "rip control",
    "control flow",
    "ret2",
    "shellcode",
    "pc control",
    "instruction pointer control",
    "control flow hijack",
)
_ARBITRARY_WRITE_TOKENS = (
    "arbitrary write",
    "arbitrary_write",
    "arbitrary address write",
    "write-what-where",
    "write what where",
    "controlled write",
)
_ARBITRARY_READ_TOKENS = (
    "arbitrary read",
    "arbitrary_read",
    "arbitrary address read",
    "read-what-where",
    "read what where",
    "controlled read",
)

_ADDRESS_RE = re.compile(r"0x[0-9a-f]+")
_NUMBER_RE = re.compile(r"\b\d+\b")
_NON_TOKEN_RE = re.compile(r"[^a-z0-9_#]+")


@dataclass(frozen=True)
class EvidenceAssessment:
    """Deterministic reading of what the artifacts can prove."""

    supported_bug_class: str
    supported_primitive: str
    primary_evidence_substantiated: bool
    signatures: tuple[str, ...]


def excerpt_bytes(data: bytes, *, max_chars: int = 1200) -> str:
    """Decode bytes to a bounded text excerpt for review packets."""
    if max_chars <= 0:
        return ""
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    head = max_chars // 2
    tail = max_chars - head
    return f"{text[:head]}\n...[truncated {len(text) - max_chars} chars]...\n{text[-tail:]}"


def _has_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def looks_like_crash(evidence: ArtifactEvidence) -> bool:
    """Return True when artifact metadata or excerpt looks like crash evidence."""
    kind_role = f"{evidence.link.kind} {evidence.link.role}".lower()
    if any(token in kind_role for token in _CRASH_KIND_TOKENS):
        return True
    excerpt = evidence.excerpt.lower()
    return _has_any(excerpt, _CRASH_TEXT_TOKENS)


def looks_like_crash_text(lowered_text: str) -> bool:
    """Return True when already-lowercased text has crash markers."""
    return _has_any(lowered_text, _CRASH_TEXT_TOKENS)


def detect_bug_class(text: str) -> str:
    """Conservative keyword classifier used as a deterministic cross-check."""
    lowered = text.lower()
    if _has_any(lowered, _UAF_TOKENS):
        return "uaf"
    if _has_any(lowered, _TYPE_CONFUSION_TOKENS):
        return "type_confusion"
    if _has_any(lowered, _OOB_WRITE_TOKENS):
        return "oob_write"
    if _has_any(lowered, _GENERIC_OVERFLOW_TOKENS):
        if "write" in lowered:
            return "oob_write"
        if "read" in lowered:
            return "oob_read"
    if _has_any(lowered, _OOB_READ_TOKENS):
        return "oob_read"
    if _has_any(lowered, _INFO_LEAK_TOKENS):
        return "info_leak"
    return INSUFFICIENT_EVIDENCE


def detect_primitive(text: str, bug_class: str) -> str:
    """Detect the strongest primitive hinted by text, bounded by bug class."""
    lowered = text.lower()
    if _has_any(lowered, _CODE_EXEC_TOKENS):
        return "code_execution"
    if _has_any(lowered, _ARBITRARY_WRITE_TOKENS):
        return "arbitrary_write"
    if _has_any(lowered, _ARBITRARY_READ_TOKENS):
        return "arbitrary_read"
    if bug_class in BUG_CLASSES:
        return bug_class
    if looks_like_crash_text(lowered):
        return "crash"
    return NO_PRIMITIVE


def is_substantiated_evidence(evidence: ArtifactEvidence) -> bool:
    """Return True when an artifact excerpt carries checkable vulnerability evidence."""
    excerpt = evidence.excerpt
    if not excerpt:
        return False
    lowered = excerpt.lower()
    return looks_like_crash_text(lowered) or detect_bug_class(excerpt) != INSUFFICIENT_EVIDENCE


def _looks_like_stack_line(line: str) -> bool:
    stripped = line.strip().lower()
    if not stripped:
        return False
    if stripped.startswith("#") or " at " in stripped or "backtrace" in stripped:
        return True
    return any(
        marker in stripped
        for marker in (".cc:", ".cpp:", ".c:", ".mm:", ".h:", ".hpp:", ".js:", ".ts:")
    )


def _crash_salient_lines(text: str) -> list[str]:
    salient: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if looks_like_crash_text(lowered) or _looks_like_stack_line(line):
            salient.append(line)
    return salient


def normalize_crash_text(text: str) -> str:
    """Normalize stable crash lines so volatile fields do not hide duplicate evidence."""
    normalized_lines: list[str] = []
    for line in _crash_salient_lines(text):
        lowered = line.lower()
        lowered = _ADDRESS_RE.sub("0x", lowered)
        lowered = _NUMBER_RE.sub("#", lowered)
        lowered = _NON_TOKEN_RE.sub(" ", lowered)
        normalized = " ".join(lowered.split())
        if normalized:
            normalized_lines.append(normalized)
    return "\n".join(normalized_lines)


def evidence_signature(evidence: ArtifactEvidence) -> str | None:
    """Return a stable signature for crash-like evidence, or None when absent."""
    excerpt = evidence.excerpt
    if not excerpt or not looks_like_crash_text(excerpt.lower()):
        return None
    normalized = normalize_crash_text(excerpt)
    if not normalized:
        return None
    return sha256_hex(normalized.encode("utf-8"))


def evidence_signatures(evidence: Iterable[ArtifactEvidence]) -> tuple[str, ...]:
    """Return sorted unique crash signatures for substantiated artifacts."""
    signatures = {
        signature
        for item in evidence
        if (signature := evidence_signature(item)) is not None
    }
    return tuple(sorted(signatures))


def assess_evidence(evidence: tuple[ArtifactEvidence, ...]) -> EvidenceAssessment:
    """Assess the strongest bug class and primitive the artifacts can prove."""
    primary_items = tuple(item for item in evidence if is_substantiated_evidence(item))
    crash_items = tuple(
        item for item in evidence if looks_like_crash_text(item.excerpt.lower())
    )
    votes = {
        bug_class
        for item in primary_items
        if (bug_class := detect_bug_class(item.excerpt)) != INSUFFICIENT_EVIDENCE
    }
    supported_bug_class = next(iter(votes)) if len(votes) == 1 else INSUFFICIENT_EVIDENCE
    supported_primitive = NO_PRIMITIVE
    supported_rank = primitive_rank(NO_PRIMITIVE)
    for item in primary_items:
        item_bug_class = detect_bug_class(item.excerpt)
        primitive = detect_primitive(item.excerpt, item_bug_class)
        rank = primitive_rank(primitive)
        if rank > supported_rank:
            supported_rank = rank
            supported_primitive = primitive
    signatures = evidence_signatures(crash_items)
    return EvidenceAssessment(
        supported_bug_class=supported_bug_class,
        supported_primitive=supported_primitive,
        primary_evidence_substantiated=bool(primary_items),
        signatures=signatures,
    )


def run_checks(
    evidence: tuple[ArtifactEvidence, ...], *, max_artifacts: int = 8
) -> tuple[CheckResult, ...]:
    """Run deterministic checks that must pass before model agreement promotes."""
    checks: list[CheckResult] = []
    checks.append(
        CheckResult(
            "artifact_links_present",
            bool(evidence),
            "" if evidence else "claim has no artifact links",
        )
    )
    unresolved = [item for item in evidence if item.error is not None or item.data is None]
    checks.append(
        CheckResult(
            "artifact_bytes_resolved",
            bool(evidence) and not unresolved,
            ""
            if not unresolved
            else f"unresolved artifacts: {', '.join(item.artifact_id for item in unresolved)}",
        )
    )
    crash_evidence = [item for item in evidence if looks_like_crash(item)]
    checks.append(
        CheckResult(
            "crash_evidence_present",
            bool(crash_evidence),
            "" if crash_evidence else "no crash/repro/evidence artifact found",
        )
    )
    substantiated = [item for item in evidence if is_substantiated_evidence(item)]
    checks.append(
        CheckResult(
            "crash_evidence_substantiated",
            bool(substantiated),
            "" if substantiated else "no substantiated crash/repro/evidence artifact found",
        )
    )
    corpus = [
        item
        for item in evidence
        if "corpus" in item.link.kind.lower() or "corpus" in item.link.role.lower()
    ]
    checks.append(
        CheckResult(
            "no_host_corpus_parse",
            not corpus,
            "" if not corpus else f"corpus artifact refused on host: {corpus[0].artifact_id}",
        )
    )
    checks.append(
        CheckResult(
            "artifact_count_bounded",
            len(evidence) <= max_artifacts,
            "" if len(evidence) <= max_artifacts else f"{len(evidence)} artifacts exceeds {max_artifacts}",
        )
    )
    return tuple(checks)


def run_rebuttals(
    evidence: tuple[ArtifactEvidence, ...],
    *,
    candidate_bug_class: str,
    candidate_primitive: str,
    duplicate_matches: tuple[str, ...] = (),
) -> tuple[CheckResult, ...]:
    """Challenge candidate bug class, primitive label, and duplicate evidence."""
    assessment = assess_evidence(evidence)
    bug_ok = (
        candidate_bug_class != INSUFFICIENT_EVIDENCE
        and candidate_bug_class == assessment.supported_bug_class
    )
    bug_reason = (
        ""
        if bug_ok
        else f"supported={assessment.supported_bug_class} candidate={candidate_bug_class}"
    )
    candidate_rank = primitive_rank(candidate_primitive)
    supported_rank = primitive_rank(assessment.supported_primitive)
    primitive_ok = candidate_rank == supported_rank
    primitive_reason = (
        ""
        if primitive_ok
        else f"supported={assessment.supported_primitive} candidate={candidate_primitive}"
    )
    duplicate_ok = not duplicate_matches
    duplicate_reason = ""
    if not duplicate_ok:
        shown = ", ".join(duplicate_matches[:3])
        extra = f" (+{len(duplicate_matches) - 3} more)" if len(duplicate_matches) > 3 else ""
        duplicate_reason = f"duplicate evidence: {shown}{extra}"
    return (
        CheckResult("candidate_bug_class_supported", bug_ok, bug_reason),
        CheckResult("candidate_primitive_supported", primitive_ok, primitive_reason),
        CheckResult("evidence_not_duplicate", duplicate_ok, duplicate_reason),
    )
