"""Crash payload parsing, stack normalization, and signature similarity (RA-DUP)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..ledger.ids import sha256_hex
from .models import (
    CrashInput,
    CrashSignature,
    Finding,
    NormalizedFrame,
    PatchDiff,
    _first_present,
)
from .patch import max_patch_proximity, max_patch_similarity, parse_unified_diff

_MAX_STORE_FRAMES = 64
_STACK_HASH_FRAMES = 12
_SIMILARITY_FRAMES = 8
_UNKNOWN = "unknown"

_TEXT_FRAME_RES = (
    re.compile(r"^\s*(?:#?\d+|0x[0-9a-fA-F]+)\s+(?P<rest>.+?)\s*$"),
    re.compile(r"^\s*(?P<rest>\S+!\S+(?:\s+.*)?)\s*$"),
)
_EXCEPTION_TYPE_RE = re.compile(r"Exception Type:\s*([^\n]+)", re.IGNORECASE)
_EXCEPTION_CODE_RE = re.compile(r"Exception Codes?:\s*([^\n]+)", re.IGNORECASE)
_TERMINATION_RE = re.compile(r"Termination Reason:\s*([^\n]+)", re.IGNORECASE)
_SIGNAL_RE = re.compile(r"^\s*Signal:\s*([^\n]+)", re.IGNORECASE | re.MULTILINE)
_PROCESS_RE = re.compile(r"^\s*(?:Process|Name):\s*([^\n]+)", re.IGNORECASE | re.MULTILINE)
_CRASHED_THREAD_RE = re.compile(r"Thread\s+(?P<index>\d+).*Crashed", re.IGNORECASE)
_THREAD_HEADER_RE = re.compile(r"^\s*Thread\s+\d+", re.IGNORECASE)


@dataclass(frozen=True)
class _ParsedCrash:
    exception_type: str = ""
    exception_code: str = ""
    signal: str = ""
    process: str = ""
    frames: tuple[NormalizedFrame, ...] = ()


@dataclass(frozen=True)
class SignatureSimilarity:
    """Weighted similarity breakdown for fuzzy duplicate detection."""

    score: float
    stack: float
    exception: float
    bug_class: float
    alloc_site: float
    context: float
    patch: float | None = None


def signature_for_finding(finding: Finding, *, bug_class: str) -> CrashSignature:
    """Build the normalized signature for a crash/finding."""
    crash = finding.crash
    parsed = _parse_crash(crash)
    frames = _cap_frames(parsed.frames if parsed is not None else ())
    exception_type = _first_text(
        parsed.exception_type if parsed else "",
        _metadata_text(crash.metadata, "exception_type", "exceptionType", "exception"),
    )
    exception_code = _first_text(
        parsed.exception_code if parsed else "",
        _metadata_text(crash.metadata, "exception_code", "exceptionCode", "code"),
    )
    signal = _first_text(
        parsed.signal if parsed else "",
        _metadata_text(crash.metadata, "signal"),
    )
    process = _first_text(
        parsed.process if parsed else "",
        _metadata_text(crash.metadata, "process", "proc", "process_name", "app_name"),
        crash.kind,
    )
    alloc_site = _first_text(
        finding.alloc_site or "",
        _metadata_text(crash.metadata, "alloc_site", "allocation_site", "malloc_site", "site"),
        _UNKNOWN,
    )
    context = _first_text(crash.context, _UNKNOWN)
    source_digest = _first_text(
        crash.digest or "",
        sha256_hex(crash.payload) if crash.payload else "",
    )
    stack_hash = _stack_hash(frames)
    signature_hash = _signature_hash(
        bug_class=bug_class,
        exception_type=exception_type,
        exception_code=exception_code,
        signal=signal,
        process=process,
        context=context,
        alloc_site=alloc_site,
        stack_hash=stack_hash,
        frames=frames,
    )
    return CrashSignature(
        signature_hash=signature_hash,
        stack_hash=stack_hash,
        bug_class=bug_class,
        exception_type=exception_type,
        exception_code=exception_code,
        signal=signal,
        process=process,
        context=context,
        alloc_site=alloc_site,
        frames=frames,
        source_kind=crash.kind,
        source_id=crash.id,
        source_path=crash.path or "",
        source_digest=source_digest,
        created_ms=finding.created_ms or crash.created_ms,
    )


def stack_similarity(a: CrashSignature, b: CrashSignature) -> float:
    """Position-weighted top-frame similarity with a Jaccard tail check."""
    if not a.frames and not b.frames:
        return 0.5
    if not a.frames or not b.frames:
        return 0.0
    left = [_frame_match_key(frame) for frame in a.frames[:_SIMILARITY_FRAMES]]
    right = [_frame_match_key(frame) for frame in b.frames[:_SIMILARITY_FRAMES]]
    common = 0.0
    total = 0.0
    for index in range(min(len(left), len(right))):
        weight = 1.0 / (index + 1)
        total += weight
        if left[index] == right[index]:
            common += weight
        elif _frame_relaxed_key(a.frames[index]) == _frame_relaxed_key(b.frames[index]):
            common += 0.75 * weight
    prefix = common / total if total else 0.0
    left_set = {_frame_relaxed_key(frame) for frame in a.frames[:_STACK_HASH_FRAMES]}
    right_set = {_frame_relaxed_key(frame) for frame in b.frames[:_STACK_HASH_FRAMES]}
    union = left_set | right_set
    jaccard = len(left_set & right_set) / len(union) if union else 0.0
    return min(1.0, 0.75 * prefix + 0.25 * jaccard)


def signature_similarity(
    a: CrashSignature,
    b: CrashSignature,
    *,
    patch_similarity: float | None = None,
) -> SignatureSimilarity:
    """Compute fuzzy duplicate similarity in [0, 1]."""
    stack = stack_similarity(a, b)
    exception = _exception_similarity(a, b)
    bug_class = _bug_class_similarity(a.bug_class, b.bug_class)
    alloc_site = _alloc_site_similarity(a.alloc_site, b.alloc_site)
    context = 1.0 if a.context == b.context else 0.4
    patch = patch_similarity
    if patch is None:
        score = (
            0.50 * stack
            + 0.15 * exception
            + 0.15 * bug_class
            + 0.10 * alloc_site
            + 0.10 * context
        )
    else:
        score = (
            0.40 * stack
            + 0.12 * exception
            + 0.12 * bug_class
            + 0.08 * alloc_site
            + 0.08 * context
            + 0.20 * patch
        )
    score = min(1.0, max(0.0, score))
    if bug_class == 0.0:
        # A confident bug-class contradiction is strong evidence against a dupe.
        score = min(score, 0.49)
    return SignatureSimilarity(
        score=score,
        stack=stack,
        exception=exception,
        bug_class=bug_class,
        alloc_site=alloc_site,
        context=context,
        patch=patch,
    )


def finding_patches(finding: Finding) -> tuple[PatchDiff, ...]:
    """Return normalized patch evidence, parsing unified-diff text when needed."""
    patches = list(finding.patches)
    for text in finding.patch_texts:
        patches.append(parse_unified_diff(text, source="finding.patch_text"))
    return tuple(patches)


def patch_similarity_for_findings(a: Finding, b: Finding) -> float | None:
    """Best patch-diff similarity between two findings, if both have evidence."""
    return max_patch_similarity(finding_patches(a), finding_patches(b))


def patch_proximity_for_finding(finding: Finding, signature: CrashSignature) -> float | None:
    """Best patch-to-crash proximity for a finding, if patch evidence exists."""
    return max_patch_proximity(finding_patches(finding), signature)


def _parse_crash(crash: CrashInput) -> _ParsedCrash | None:
    parsed: _ParsedCrash | None = None
    if crash.payload:
        parsed = _parse_payload(crash.payload)
    if parsed is not None and _has_crash_content(parsed):
        return parsed
    metadata = _parse_metadata(crash.metadata)
    if metadata is not None:
        return metadata
    return parsed


def _has_crash_content(parsed: _ParsedCrash) -> bool:
    return bool(
        parsed.frames
        or parsed.exception_type
        or parsed.exception_code
        or parsed.signal
        or parsed.process
    )


def _parse_payload(payload: bytes) -> _ParsedCrash | None:
    text = payload.decode("utf-8", errors="replace")
    document = _json_document(text)
    if document is not None:
        return _parse_json_crash(document)
    return _parse_text_crash(text)


def _json_document(text: str) -> Mapping[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, Mapping):
        return value
    for line in stripped.splitlines():
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, Mapping):
            return parsed
    return None


def _parse_json_crash(data: Mapping[str, Any]) -> _ParsedCrash:
    exception_type, exception_code = _json_exception(data)
    signal = _json_signal(data, exception_type, exception_code)
    process = _first_text(
        _json_text(data.get("procName")),
        _json_text(data.get("app_name")),
        _json_text(data.get("process")),
        _json_text(data.get("name")),
        _json_text(data.get("target")),
    )
    frames = _json_frames(data)
    return _ParsedCrash(
        exception_type=exception_type,
        exception_code=exception_code,
        signal=signal,
        process=process,
        frames=frames,
    )


def _json_exception(data: Mapping[str, Any]) -> tuple[str, str]:
    exception = data.get("exception")
    exc_type = ""
    exc_code = ""
    if isinstance(exception, Mapping):
        exc_type = _json_text(exception.get("type")) or _json_text(exception.get("name"))
        exc_code = _json_text(exception.get("code")) or _json_text(exception.get("subtype"))
        if exc_type or exc_code:
            return exc_type, exc_code
    elif isinstance(exception, str):
        return exception, ""
    termination = data.get("termination")
    if isinstance(termination, Mapping):
        reason = _json_text(termination.get("reason"))
        namespace = _json_text(termination.get("namespace"))
        code = _json_text(termination.get("code"))
        joined = " ".join(part for part in (namespace, reason, code) if part)
        if joined:
            return joined, ""
    elif isinstance(termination, str):
        return termination, ""
    return exc_type, exc_code


def _json_signal(data: Mapping[str, Any], exception_type: str, exception_code: str) -> str:
    for value in (data.get("signal"), data.get("siginfo")):
        text = _json_text(value)
        if text:
            return text
    exception = data.get("exception")
    if isinstance(exception, Mapping):
        text = _json_text(exception.get("signal"))
        if text:
            return text
    for candidate in (exception_code, exception_type):
        if candidate.upper().startswith("SIG"):
            return candidate.upper()
    return ""


def _json_frames(data: Mapping[str, Any]) -> tuple[NormalizedFrame, ...]:
    threads = data.get("threads")
    if not isinstance(threads, Sequence) or isinstance(threads, (str, bytes, bytearray)):
        return ()
    thread = _faulting_thread(threads, data.get("faultingThread"))
    if not isinstance(thread, Mapping):
        return ()
    frames_raw = thread.get("frames")
    if not isinstance(frames_raw, Sequence) or isinstance(frames_raw, (str, bytes, bytearray)):
        return ()
    used_images = _used_images(data)
    frames: list[NormalizedFrame] = []
    for item in frames_raw[:_MAX_STORE_FRAMES]:
        if isinstance(item, Mapping):
            frame = _frame_from_json(item, used_images)
            if frame is not None:
                frames.append(frame)
    return tuple(frames)


def _faulting_thread(threads: Sequence[Any], faulting: Any) -> Mapping[str, Any] | None:
    index = _as_int(faulting)
    if index is not None and 0 <= index < len(threads):
        candidate = threads[index]
        if isinstance(candidate, Mapping):
            return candidate
    for item in threads:
        if isinstance(item, Mapping) and isinstance(item.get("frames"), Sequence):
            return item
    return None


def _used_images(data: Mapping[str, Any]) -> list[str]:
    images = data.get("usedImages", data.get("used_images", ()))
    names: list[str] = []
    if isinstance(images, Sequence) and not isinstance(images, (str, bytes, bytearray)):
        for item in images:
            if isinstance(item, Mapping):
                name = _json_text(item.get("name")) or _json_text(item.get("path"))
                if name:
                    names.append(name)
            elif isinstance(item, str):
                names.append(item)
    return names


def _frame_from_json(frame: Mapping[str, Any], used_images: list[str]) -> NormalizedFrame | None:
    symbol = _json_text(frame.get("symbol")) or _json_text(frame.get("function"))
    name = _json_text(frame.get("name"))
    function = _normalize_symbol(symbol or name or "")
    module = ""
    image_name = _json_text(frame.get("imageName")) or _json_text(frame.get("module"))
    image_index = _as_int(frame.get("imageIndex", frame.get("image_index")))
    if image_name:
        module = image_name
    elif image_index is not None and 0 <= image_index < len(used_images):
        module = used_images[image_index]
    module = _normalize_module(module)
    detail = ""
    line = _as_int(frame.get("line", frame.get("lineNumber", frame.get("line_number"))))
    if line is not None and line > 0:
        detail = f"line:{line}"
    if not function and not module:
        return None
    return NormalizedFrame(module=module or _UNKNOWN, function=function or _UNKNOWN, detail=detail)


def _parse_text_crash(text: str) -> _ParsedCrash:
    exception_type = _regex_text(_EXCEPTION_TYPE_RE, text)
    exception_code = _regex_text(_EXCEPTION_CODE_RE, text)
    signal_match = _SIGNAL_RE.search(text)
    signal = signal_match.group(1).strip() if signal_match else ""
    process_match = _PROCESS_RE.search(text)
    process = process_match.group(1).strip() if process_match else ""
    frames = _text_frames(text)
    return _ParsedCrash(
        exception_type=exception_type,
        exception_code=exception_code,
        signal=signal,
        process=process,
        frames=frames,
    )


def _text_frames(text: str) -> tuple[NormalizedFrame, ...]:
    lines = text.splitlines()
    crashed = _crashed_thread_index(lines)
    frames: list[NormalizedFrame] = []
    if crashed is not None:
        for line in lines[crashed:]:
            if frames and _THREAD_HEADER_RE.match(line):
                break
            frame = _frame_from_text_line(line)
            if frame is not None:
                frames.append(frame)
            if len(frames) >= _MAX_STORE_FRAMES:
                break
    if not frames:
        for line in lines:
            frame = _frame_from_text_line(line)
            if frame is not None:
                frames.append(frame)
            if len(frames) >= _MAX_STORE_FRAMES:
                break
    return tuple(frames)


def _crashed_thread_index(lines: Sequence[str]) -> int | None:
    for index, line in enumerate(lines):
        if _CRASHED_THREAD_RE.search(line):
            return index + 1
    return None


def _frame_from_text_line(line: str) -> NormalizedFrame | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("Thread", "Crashed", "Exception", "Termination")):
        return None
    rest = stripped
    for pattern in _TEXT_FRAME_RES:
        match = pattern.match(rest)
        if match:
            rest = match.group("rest").strip()
            break
    else:
        return None
    rest = _strip_trailing_offset(rest)
    if not rest or rest.startswith(("Binary Images", "OS Version", "Kernel")):
        return None
    module, function, detail = _split_frame_text(rest)
    if not module and not function:
        return None
    if module and not function and not _looks_like_module(module):
        return None
    return NormalizedFrame(
        module=_normalize_module(module) or _UNKNOWN,
        function=_normalize_symbol(function) or _UNKNOWN,
        detail=detail,
    )


def _strip_trailing_offset(text: str) -> str:
    previous = None
    current = text.strip()
    while current != previous:
        previous = current
        current = re.sub(r"\s+\+\s*(?:0x)?[0-9a-fA-F]+\s*$", "", current).strip()
        current = re.sub(r"\s+-\s*\d+\s*$", "", current).strip()
    return current


def _split_frame_text(text: str) -> tuple[str, str, str]:
    tokens = [token for token in text.split() if token]
    if tokens and tokens[0].lower().startswith("0x"):
        tokens = tokens[1:]
    if not tokens:
        return "", "", ""
    detail = ""
    if "!" in tokens[0]:
        module, function = tokens[0].split("!", 1)
        extra = " ".join(tokens[1:])
        function = " ".join(part for part in (function, extra) if part)
        return module, function, detail
    if len(tokens) >= 3 and _is_address(tokens[1]):
        module = tokens[0]
        function = " ".join(tokens[2:])
        return module, function, detail
    if len(tokens) >= 2 and _is_address(tokens[-1]):
        module = tokens[0]
        function = " ".join(tokens[1:-1])
        return module, function, detail
    if len(tokens) == 1:
        return "", tokens[0], detail
    module = tokens[0]
    function = " ".join(tokens[1:])
    return module, function, detail


def _is_address(token: str) -> bool:
    return token.lower().startswith("0x") and all(ch in "0123456789abcdefx" for ch in token.lower())


def _looks_like_module(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (".dylib", ".framework", ".appex", ".app", "kernel", "libsystem")
    )


def _parse_metadata(metadata: Mapping[str, Any]) -> _ParsedCrash | None:
    frames_raw = _first_present(metadata.get("frames"), metadata.get("stack_frames"), metadata.get("backtrace_frames"))
    stack_text = _first_present(metadata.get("stack"), metadata.get("backtrace"), metadata.get("trace"))
    frames: list[NormalizedFrame] = []
    if isinstance(frames_raw, Sequence) and not isinstance(frames_raw, (str, bytes, bytearray)):
        for item in frames_raw[:_MAX_STORE_FRAMES]:
            frame = _frame_from_metadata_item(item)
            if frame is not None:
                frames.append(frame)
    if isinstance(stack_text, str) and stack_text.strip():
        for frame in _text_frames(stack_text):
            if frame not in frames:
                frames.append(frame)
            if len(frames) >= _MAX_STORE_FRAMES:
                break
    exception_type = _metadata_text(metadata, "exception_type", "exceptionType")
    exception_code = _metadata_text(metadata, "exception_code", "exceptionCode", "code")
    signal = _metadata_text(metadata, "signal")
    process = _metadata_text(metadata, "process", "proc", "process_name", "app_name")
    if not frames and not (exception_type or exception_code or signal or process):
        return None
    return _ParsedCrash(
        exception_type=exception_type,
        exception_code=exception_code,
        signal=signal,
        process=process,
        frames=tuple(frames[:_MAX_STORE_FRAMES]),
    )


def _frame_from_metadata_item(item: Any) -> NormalizedFrame | None:
    if isinstance(item, Mapping):
        module = _normalize_module(_json_text(item.get("module")) or _json_text(item.get("image")))
        function = _normalize_symbol(_json_text(item.get("function")) or _json_text(item.get("symbol")))
        if not module and not function:
            return None
        return NormalizedFrame(module=module or _UNKNOWN, function=function or _UNKNOWN)
    if isinstance(item, str):
        return _frame_from_text_line(item)
    return None


def _normalize_module(value: str) -> str:
    if not value:
        return ""
    base = value.replace("\\", "/").rsplit("/", 1)[-1]
    base = base.strip().strip('"')
    if not base or base == "0x0":
        return ""
    return base.lower()


def _normalize_symbol(value: str) -> str:
    if not value:
        return ""
    text = value.strip()
    text = re.sub(r"\s+\(in\s+[^)]+\)\s*$", "", text)
    text = _strip_trailing_offset(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _frame_match_key(frame: NormalizedFrame) -> str:
    return f"{frame.module}!{frame.function}#{frame.detail}"


def _frame_relaxed_key(frame: NormalizedFrame) -> str:
    return f"{frame.module}!{frame.function}"


def _stack_hash(frames: tuple[NormalizedFrame, ...]) -> str:
    keys = [_frame_relaxed_key(frame) for frame in frames[:_STACK_HASH_FRAMES]]
    if not keys:
        return sha256_hex(b"ra.dupe.no-frames")
    return sha256_hex("\n".join(keys).encode("utf-8"))


def _signature_hash(
    *,
    bug_class: str,
    exception_type: str,
    exception_code: str,
    signal: str,
    process: str,
    context: str,
    alloc_site: str,
    stack_hash: str,
    frames: tuple[NormalizedFrame, ...],
) -> str:
    # Exact identity is content-based: per-instance source ids/paths must not
    # split otherwise-identical crashes into different canonical signatures.
    material = {
        "bug_class": bug_class,
        "exception_type": exception_type,
        "exception_code": exception_code,
        "signal": signal,
        "process": process,
        "context": context,
        "alloc_site": alloc_site,
        "stack_hash": stack_hash,
        "frames": [_frame_relaxed_key(frame) for frame in frames[:_STACK_HASH_FRAMES]],
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return sha256_hex(encoded.encode("utf-8"))


def _exception_similarity(a: CrashSignature, b: CrashSignature) -> float:
    type_sim = _text_similarity(a.exception_type, b.exception_type)
    code_sim = _text_similarity(a.exception_code, b.exception_code)
    signal_sim = _text_similarity(a.signal, b.signal)
    if type_sim == 0.0 and code_sim == 0.0 and signal_sim == 0.0:
        return 0.5
    return min(1.0, 0.5 * type_sim + 0.3 * code_sim + 0.2 * signal_sim)


def _bug_class_similarity(a: str, b: str) -> float:
    left = a.strip().lower()
    right = b.strip().lower()
    if left in {"", _UNKNOWN} or right in {"", _UNKNOWN}:
        return 0.5
    return 1.0 if left == right else 0.0


def _alloc_site_similarity(a: str, b: str) -> float:
    left = a.strip().lower()
    right = b.strip().lower()
    if left in {"", _UNKNOWN} or right in {"", _UNKNOWN}:
        return 0.5
    if left == right:
        return 1.0
    if left in right or right in left:
        return 0.75
    return 0.0


def _text_similarity(a: str, b: str) -> float:
    left = a.strip().lower()
    right = b.strip().lower()
    if not left or not right:
        return 0.5
    if left == right:
        return 1.0
    if left in right or right in left:
        return 0.6
    return 0.0


def _cap_frames(frames: tuple[NormalizedFrame, ...]) -> tuple[NormalizedFrame, ...]:
    return frames[:_MAX_STORE_FRAMES]


def _first_text(*values: str) -> str:
    for value in values:
        if value and value.strip():
            return value.strip()
    return ""


def _metadata_text(metadata: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = metadata.get(name)
        text = _json_text(value)
        if text:
            return text
    return ""


def _json_text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _regex_text(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


__all__ = [
    "SignatureSimilarity",
    "finding_patches",
    "patch_proximity_for_finding",
    "patch_similarity_for_findings",
    "signature_for_finding",
    "signature_similarity",
    "stack_similarity",
]
