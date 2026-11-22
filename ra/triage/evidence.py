"""Crash evidence normalization, stack extraction and deterministic hints."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from itertools import islice
from typing import Any, cast

from .models import BUG_CLASS_VOCAB, CRASH_CLASS_VOCAB, BugClass, CrashEvidence
from .sanitize import clean_multiline, clean_text, json_safe

_TEXT_LIMIT = 16_000
_FRAME_LIMIT = 12
_DEDUP_DEPTH = 5
_MAX_FRAME_CHARS = 240
_MAX_METADATA_FIELD_CHARS = 8_000
_MAX_TARGET_ITEMS = 32
_MAX_HINT_FRAMES = 32

_ASAN_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+(?:\S+\s+)?in\s+(.+?)\s+([^:\s]+):(\d+)",
    re.IGNORECASE,
)
_HASH_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+(.+?)(?:\s+\(([^)]+)\))?\s*$",
    re.IGNORECASE,
)
_APPLE_FRAME_RE = re.compile(
    r"^\s*\d+\s+\S+\s+(?:0x[0-9a-f]+\s+)+(.+?)(?:\s+\+\s*\d+)?\s*$",
    re.IGNORECASE,
)
_FRAME_PREFIX_RE = re.compile(r"^\s*frame\s+#?\d+\s*:?\s*(.+?)\s*$", re.IGNORECASE)
_ADDR_RE = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")
_MAIN_FRAME_RE = re.compile(r"(^|[^a-z0-9])main([^a-z0-9]|$)")

_NOISE_FRAGMENTS = (
    "libsystem",
    "libdispatch",
    "libdyld",
    "dyld",
    "corefoundation",
    "libobjc",
    "libc++",
    "start_",
    "_pthread",
    "__workq",
    "js::drain",
)

_BUG_CLASS_ALIASES = {
    "uaf": "uaf",
    "use_after_free": "uaf",
    "use-after-free": "uaf",
    "heap-use-after-free": "uaf",
    "type_confusion": "type_confusion",
    "type-confusion": "type_confusion",
    "oob_write": "oob_write",
    "oob-write": "oob_write",
    "out_of_bounds_write": "oob_write",
    "info_leak": "info_leak",
    "info-leak": "info_leak",
    "information_leak": "info_leak",
    "oob_read": "oob_read",
    "oob-read": "oob_read",
    "out_of_bounds_read": "oob_read",
    "other": "other",
}

_KEYWORD_SCORES: tuple[tuple[BugClass, tuple[str, ...]], ...] = (
    (
        BugClass.UAF,
        (
            "use-after-free",
            "heap-use-after-free",
            "uaf",
            "freed",
            "double free",
            "double-free",
            "dealloc",
        ),
    ),
    (
        BugClass.TYPE_CONFUSION,
        ("type confusion", "type_confusion", "structureid", "classinfo", "wrong vtable"),
    ),
    (
        BugClass.OOB_WRITE,
        (
            "out-of-bounds write",
            "oob write",
            "heap-buffer-overflow write",
            "stack-buffer-overflow write",
            "buffer-overflow write",
            "oob_write",
            "write of size",
        ),
    ),
    (
        BugClass.INFO_LEAK,
        ("info leak", "information leak", "uninitialized", "info_leak", "disclosure"),
    ),
    (
        BugClass.OOB_READ,
        (
            "out-of-bounds read",
            "oob read",
            "heap-buffer-overflow read",
            "stack-buffer-overflow read",
            "buffer-overflow read",
            "oob_read",
            "read of size",
        ),
    ),
)

_CRASH_CLASS_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("stack-exhaustion", ("stack exhaustion", "stack-exhaustion", "stack overflow", "stack-overflow")),
    ("double-free", ("double free", "double-free", "doublefree")),
    ("use-after-poison", ("use-after-poison", "use after poison", "heap-use-after-poison")),
    ("use-after-free", ("use-after-free", "heap-use-after-free", "use after free", "uaf")),
    ("type-confusion", ("type confusion", "type_confusion", "wrong vtable", "structureid")),
    ("null-deref", ("null-deref", "null deref", "null pointer", "nullptr", "address 0x0")),
    ("integer-overflow", ("integer-overflow", "integer overflow", "signed integer overflow")),
    ("uninitialized-memory", ("uninitialized", "uninitialised", "msan", "memory sanitizer")),
    ("timeout", ("timeout", "timed out", "watchdog", "hang")),
    ("out-of-memory", ("out-of-memory", "out of memory", "oom", "memory pressure")),
    ("out-of-bounds", ("out-of-bounds", "oob ", "buffer-overflow", "heap-buffer-overflow", "stack-buffer-overflow", "read of size", "write of size")),
    ("assertion", ("assertion", "assert", "abort", "sigabrt", "fatal error")),
)


def decode_bytes(data: bytes, limit: int = _TEXT_LIMIT) -> str:
    return clean_multiline(data, limit=limit)


def _metadata(crash: CrashEvidence) -> Mapping[str, Any]:
    metadata = crash.metadata
    return metadata if isinstance(metadata, Mapping) else {}


def metadata_text(crash: CrashEvidence, limit: int = _TEXT_LIMIT) -> str:
    limit = max(0, limit)
    if limit == 0:
        return ""
    metadata = _metadata(crash)
    parts: list[str] = []
    total = 0
    keys = ("report", "stderr", "text", "crash_log", "log", "stdout", "exception", "message", "termination_reason")
    for key in keys:
        value = metadata.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        cleaned = clean_multiline(value, limit=min(_MAX_METADATA_FIELD_CHARS, limit))
        if not cleaned:
            continue
        parts.append(cleaned)
        total += len(cleaned) + 1
        if total >= limit:
            break
    return "\n".join(parts)[:limit]


def evidence_text(crash: CrashEvidence, limit: int = _TEXT_LIMIT) -> str:
    if crash.payload:
        return decode_bytes(crash.payload, limit)
    return metadata_text(crash, limit=limit)


def _frame_from_line(line: str) -> str | None:
    match = _ASAN_FRAME_RE.match(line)
    if match:
        return f"{match.group(1)} ({match.group(2)}:{match.group(3)})"
    match = _HASH_FRAME_RE.match(line)
    if match and " in " not in line.lower():
        func = match.group(1).strip()
        loc = match.group(2)
        if loc:
            return f"{func} ({loc.strip()})"
        return func or None
    match = _APPLE_FRAME_RE.match(line)
    if match:
        frame = match.group(1).strip()
        frame = re.sub(r"\s+\+\s*\d+$", "", frame).strip()
        return frame or None
    match = _FRAME_PREFIX_RE.match(line)
    if match:
        return match.group(1).strip() or None
    return None


def extract_frames(text: str, limit: int = _FRAME_LIMIT) -> tuple[str, ...]:
    limit = max(0, limit)
    if not text or limit == 0:
        return ()
    frames: list[str] = []
    for raw_line in text.splitlines():
        line = clean_text(raw_line, limit=_MAX_FRAME_CHARS * 4, keep_newlines=False)
        if not line:
            continue
        frame = _frame_from_line(line)
        if frame is None:
            continue
        cleaned = _clean_frame(frame)
        if cleaned is None:
            continue
        frames.append(cleaned)
        if len(frames) >= limit:
            break
    return tuple(frames[:limit])


def _is_noise_frame(lowered: str) -> bool:
    if any(fragment in lowered for fragment in _NOISE_FRAGMENTS):
        return True
    return _MAIN_FRAME_RE.search(lowered) is not None


def _clean_frame(frame: str) -> str | None:
    cleaned = clean_text(frame, limit=_MAX_FRAME_CHARS, keep_newlines=False)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if _is_noise_frame(lowered):
        return None
    return cleaned


def _frame_candidates(frames: Any) -> Iterable[Any]:
    if frames is None or isinstance(frames, Mapping):
        return ()
    if isinstance(frames, (str, bytes, bytearray)):
        return (frames,)
    try:
        return cast(Iterable[Any], iter(frames))
    except TypeError:
        return ()


def normalize_frame(frame: Any) -> str:
    cleaned = clean_text(frame, limit=_MAX_FRAME_CHARS * 2, keep_newlines=False).lower()
    cleaned = _ADDR_RE.sub("0x", cleaned)
    cleaned = re.sub(r"\(x?\d+\)", "", cleaned)
    cleaned = re.sub(r"\+0x[0-9a-f]+", "", cleaned)
    cleaned = _WS_RE.sub(" ", cleaned).strip()
    return cleaned[:_MAX_FRAME_CHARS]


def normalized_frames(frames: Sequence[str], depth: int = _DEDUP_DEPTH) -> tuple[str, ...]:
    normalized: list[str] = []
    depth = max(0, depth)
    for frame in islice(_frame_candidates(frames), 64):
        item = normalize_frame(frame)
        if item:
            normalized.append(item)
        if len(normalized) >= depth:
            break
    return tuple(normalized)


def normalize_stack_text(text: str) -> str:
    cleaned = clean_multiline(text, limit=1_200).lower()
    cleaned = _WS_RE.sub(" ", cleaned).strip()
    cleaned = _ADDR_RE.sub("0x", cleaned)
    cleaned = re.sub(r"0x[0-9a-f]+", "0x", cleaned)
    return cleaned[:600]


def stack_hash(frames: Sequence[str], fallback_text: str = "") -> str:
    normalized = normalized_frames(frames, depth=12)
    basis = "|".join(normalized) if normalized else normalize_stack_text(fallback_text)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _safe_target_value(value: Any) -> Any:
    safe = json_safe(value)
    return safe


def target_dict(crash: CrashEvidence, symbolized_target: Mapping[str, Any] | None = None) -> dict[str, Any]:
    target: dict[str, Any] = {}
    metadata = _metadata(crash)
    metadata_target = metadata.get("target")
    if isinstance(metadata_target, Mapping):
        for key, value in list(metadata_target.items())[:_MAX_TARGET_ITEMS]:
            name = clean_text(key, limit=64, keep_newlines=False)
            if not name:
                continue
            safe = _safe_target_value(value)
            if safe is not None:
                target[name] = safe
    for key in ("revision", "build_type", "sanitizers"):
        if key in metadata and key not in target:
            safe = _safe_target_value(metadata.get(key))
            if safe is not None:
                target[key] = safe
    if symbolized_target:
        for key in ("revision", "build_type", "sanitizers"):
            if key in symbolized_target and key not in target:
                safe = _safe_target_value(symbolized_target.get(key))
                if safe is not None:
                    target[key] = safe
    return target


def _canonical_bug_class(value: str) -> str | None:
    cleaned = clean_text(value, limit=64, keep_newlines=False).lower().replace("-", "_")
    canonical = _BUG_CLASS_ALIASES.get(cleaned, cleaned)
    return canonical if canonical in BUG_CLASS_VOCAB else None


def _hint_text(crash: CrashEvidence, frames: Sequence[str]) -> str:
    frame_items: list[str] = []
    for frame in islice(_frame_candidates(frames), _MAX_HINT_FRAMES):
        item = clean_text(frame, limit=_MAX_FRAME_CHARS, keep_newlines=False)
        if item:
            frame_items.append(item)
    frame_text = " ".join(frame_items)
    return f"{evidence_text(crash)}\n{frame_text}".lower()


def bug_class_hint(
    crash: CrashEvidence,
    frames: Sequence[str] = (),
    *,
    symbolized: bool = False,
) -> str:
    explicit = _metadata(crash).get("bug_class")
    if isinstance(explicit, str):
        canonical = _canonical_bug_class(explicit)
        if canonical is not None:
            return canonical
    haystack = _hint_text(crash, frames)
    best = BugClass.OTHER
    best_score = 0
    for bug_class, needles in _KEYWORD_SCORES:
        score = sum(1 for needle in needles if needle in haystack)
        if score > best_score:
            best = bug_class
            best_score = score
    if symbolized and best_score == 0 and frames:
        return BugClass.OOB_READ.value
    return best.value


def crash_class_hint(
    crash: CrashEvidence,
    frames: Sequence[str] = (),
    *,
    symbolized: bool = False,
) -> str:
    explicit = _metadata(crash).get("crash_class")
    if isinstance(explicit, str):
        candidate = clean_text(explicit, limit=64, keep_newlines=False).lower()
        if candidate in CRASH_CLASS_VOCAB:
            return candidate
    haystack = _hint_text(crash, frames)
    if symbolized and not haystack.strip():
        return "other"
    for crash_class, needles in _CRASH_CLASS_KEYWORDS:
        if any(needle in haystack for needle in needles):
            return crash_class
    return "other"


def symbolized_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    safe = json_safe(payload)
    return json.dumps(safe, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = [
    "bug_class_hint",
    "crash_class_hint",
    "decode_bytes",
    "evidence_text",
    "extract_frames",
    "metadata_text",
    "normalize_frame",
    "normalize_stack_text",
    "normalized_frames",
    "stack_hash",
    "symbolized_payload_bytes",
    "target_dict",
]
