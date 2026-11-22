"""Symbolication boundary for triage.

Lane adapters own real atos/dsym symbolication on macOS/device.  This module
keeps a clean provider interface and a deterministic local provider that only
uses crash payload bytes and metadata already attached to the crash.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from itertools import islice
from typing import Any, Protocol

from .evidence import evidence_text, extract_frames, metadata_text, target_dict
from .models import CrashEvidence, SymbolizedCrash
from .sanitize import clean_multiline, clean_text, json_safe, safe_int_or_none

_MAX_FRAME_CHARS = 240
_MAX_FRAME_ITEMS = 32
_MAX_FRAME_KEEP = 12


class SymbolicationProvider(Protocol):
    async def symbolize(self, crash: CrashEvidence) -> SymbolizedCrash: ...


def _metadata(crash: CrashEvidence) -> Mapping[str, Any]:
    metadata = crash.metadata
    return metadata if isinstance(metadata, Mapping) else {}


def _optional_text(value: Any, *, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, bytes, bytearray)):
        return None
    text = clean_multiline(value, limit=limit)
    return text or None


def _clean_frame_items(values: Any) -> tuple[str, ...]:
    if values is None or isinstance(values, Mapping):
        return ()
    if isinstance(values, (str, bytes, bytearray)):
        candidates: Iterable[Any] = (values,)
    else:
        try:
            candidates = iter(values)
        except TypeError:
            return ()
    frames: list[str] = []
    for item in islice(candidates, _MAX_FRAME_ITEMS):
        text = clean_text(item, limit=_MAX_FRAME_CHARS, keep_newlines=False)
        if not text:
            continue
        frames.append(text)
        if len(frames) >= _MAX_FRAME_KEEP:
            break
    return tuple(frames)


def _frames_from_metadata(crash: CrashEvidence) -> tuple[str, ...]:
    metadata = _metadata(crash)
    for key in ("frames", "stack_frames", "symbolicated_frames"):
        raw = metadata.get(key)
        if isinstance(raw, (Mapping, str, bytes, bytearray)):
            continue
        frames = _clean_frame_items(raw)
        if frames:
            return frames
    stack = _optional_text(metadata.get("stack"), limit=8_000)
    if stack:
        lines = [clean_text(line, limit=_MAX_FRAME_CHARS, keep_newlines=False) for line in stack.splitlines()]
        return tuple(line for line in lines if line)[:_MAX_FRAME_KEEP]
    return ()


def _safe_target(value: Any) -> dict[str, Any]:
    safe = json_safe(value)
    return safe if isinstance(safe, dict) else {}


def _safe_bool(value: Any) -> bool:
    try:
        return bool(value)
    except Exception:
        return False


def _crash_kind(crash: CrashEvidence) -> str:
    return clean_text(crash.kind, limit=128) or "unknown"


def _make_symbolized(
    crash: CrashEvidence,
    *,
    crash_id: Any = None,
    crash_type: Any = None,
    frames: tuple[str, ...] = (),
    signal: Any = None,
    returncode: Any = None,
    stderr: Any = None,
    repro: Any = None,
    target: Any = None,
    symbolicated: bool = False,
    source: str = "none",
) -> SymbolizedCrash:
    metadata = _metadata(crash)
    text = evidence_text(crash)
    safe_crash_id = clean_text(crash_id if crash_id is not None else crash.id, limit=128) or "unknown"
    safe_crash_type = (
        _optional_text(crash_type, limit=128)
        or clean_text(metadata.get("crash_type"), limit=128)
        or _crash_kind(crash)
    )
    safe_signal = _optional_text(signal, limit=64) or _optional_text(metadata.get("signal"), limit=64)
    safe_returncode = safe_int_or_none(returncode)
    if safe_returncode is None:
        safe_returncode = safe_int_or_none(metadata.get("returncode"))
    safe_stderr = _optional_text(stderr, limit=3_000) or metadata_text(crash, limit=3_000)
    safe_repro = (
        _optional_text(repro, limit=8_000)
        or _optional_text(metadata.get("repro"), limit=8_000)
        or clean_multiline(text, limit=8_000)
    )
    safe_target_value = _safe_target(target)
    if not safe_target_value:
        safe_target_value = target_dict(crash)
    safe_source = clean_text(source, limit=64, keep_newlines=False) or "none"
    return SymbolizedCrash(
        crash_id=safe_crash_id,
        crash_type=safe_crash_type,
        frames=_clean_frame_items(frames),
        signal=safe_signal,
        returncode=safe_returncode,
        stderr=safe_stderr,
        repro=safe_repro,
        target=safe_target_value,
        symbolicated=_safe_bool(symbolicated),
        source=safe_source,
    )


class DefaultSymbolicator:
    """Deterministic provider used until lane-owned symbolication lands."""

    async def symbolize(self, crash: CrashEvidence) -> SymbolizedCrash:
        metadata_frames = _frames_from_metadata(crash)
        text = evidence_text(crash)
        payload_frames = extract_frames(text) if text else ()
        frames = metadata_frames or payload_frames
        symbolicated = bool(metadata_frames)
        source = "metadata" if metadata_frames else "payload" if payload_frames else "none"
        return _make_symbolized(
            crash,
            frames=frames,
            symbolicated=symbolicated,
            source=source,
            crash_type=_metadata(crash).get("crash_type"),
            signal=_metadata(crash).get("signal"),
            returncode=_metadata(crash).get("returncode"),
        )


class StubLaneSymbolicator:
    """Explicit stub for the missing lane symbolication dependency."""

    async def symbolize(self, crash: CrashEvidence) -> SymbolizedCrash:
        return await DefaultSymbolicator().symbolize(crash)


def coerce_symbolized(raw: Any, crash: CrashEvidence) -> SymbolizedCrash:
    """Return a bounded SymbolizedCrash even for hostile provider output."""
    if isinstance(raw, SymbolizedCrash):
        return _make_symbolized(
            crash,
            crash_id=raw.crash_id,
            crash_type=raw.crash_type,
            frames=raw.frames,
            signal=raw.signal,
            returncode=raw.returncode,
            stderr=raw.stderr,
            repro=raw.repro,
            target=raw.target,
            symbolicated=raw.symbolicated,
            source=raw.source,
        )
    if isinstance(raw, Mapping):
        get = raw.get
        return _make_symbolized(
            crash,
            crash_id=get("crash_id"),
            crash_type=get("crash_type"),
            frames=get("frames", ()),
            signal=get("signal"),
            returncode=get("returncode"),
            stderr=get("stderr"),
            repro=get("repro"),
            target=get("target"),
            symbolicated=get("symbolicated", False),
            source=get("source", "provider"),
        )
    metadata_frames = _frames_from_metadata(crash)
    text = evidence_text(crash)
    payload_frames = extract_frames(text) if text else ()
    frames = metadata_frames or payload_frames
    source = "metadata" if metadata_frames else "payload" if payload_frames else "invalid"
    return _make_symbolized(
        crash,
        frames=frames,
        symbolicated=bool(metadata_frames),
        source=source,
    )


__all__ = [
    "DefaultSymbolicator",
    "StubLaneSymbolicator",
    "SymbolicationProvider",
    "coerce_symbolized",
]
