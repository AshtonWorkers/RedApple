"""Defensive normalization for untrusted crash and model text."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

DEFAULT_TEXT_LIMIT = 16_000
MAX_FIELD_CHARS = 1_000
MAX_FRAME_CHARS = 240
MAX_GOAL_FIELD_CHARS = 4_000
MAX_JSON_STRING_CHARS = 2_000
MAX_JSON_KEY_CHARS = 128
MAX_JSON_DEPTH = 6
MAX_JSON_ITEMS = 64
_MAX_SAFE_INT = (1 << 63) - 1

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_WHITESPACE_RE = re.compile(r"\s+")


def clean_text(value: Any, *, limit: int = MAX_FIELD_CHARS, keep_newlines: bool = True) -> str:
    """Return bounded, control-character-free text for prompts and ledger values."""
    limit = max(0, limit)
    if limit == 0 or value is None:
        return ""
    if isinstance(value, bytes):
        sample = value[: max(64, limit * 4)]
        text = sample.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value[: max(64, limit * 4)] if len(value) > max(64, limit * 4) else value
    else:
        try:
            text = str(value)
        except Exception:
            return ""
        if len(text) > max(64, limit * 4):
            text = text[: max(64, limit * 4)]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_RE.sub("", text)
    if not keep_newlines:
        text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:limit]


def clean_multiline(value: Any, *, limit: int = DEFAULT_TEXT_LIMIT) -> str:
    return clean_text(value, limit=limit, keep_newlines=True)


def _decode_bounded(data: bytes, limit: int) -> str:
    limit = max(0, limit)
    if limit == 0 or not data:
        return ""
    sample = data[: max(64, limit * 4)]
    return clean_text(sample.decode("utf-8", errors="replace"), limit=limit)


def _json_sort_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def json_safe(value: Any, *, depth: int = 0) -> Any:
    """Convert arbitrary crash metadata into deterministic JSON-safe values."""
    if depth > MAX_JSON_DEPTH:
        return None
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean_text(value, limit=MAX_JSON_STRING_CHARS, keep_newlines=True)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return _decode_bounded(raw, MAX_JSON_STRING_CHARS)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        try:
            items = list(value.items())
        except Exception:
            return {}
        for key, item in items[:MAX_JSON_ITEMS]:
            name = clean_text(key, limit=MAX_JSON_KEY_CHARS, keep_newlines=False)
            if not name:
                continue
            out[name] = json_safe(item, depth=depth + 1)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        return [json_safe(item, depth=depth + 1) for item in list(value)[:MAX_JSON_ITEMS]]
    if isinstance(value, (set, frozenset)):
        converted = [json_safe(item, depth=depth + 1) for item in list(value)[:MAX_JSON_ITEMS]]
        return sorted(converted, key=_json_sort_key)
    return None


def json_dumps_safe(value: Any) -> str:
    """Deterministic JSON encoding for already-untrusted Python values."""
    return json.dumps(json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def safe_int(value: Any, default: int = 0) -> int:
    """Best-effort bounded integer conversion for ledger-shaped data."""
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return default
        number = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if len(text) > 20 or not text:
            return default
        try:
            number = int(text)
        except ValueError:
            return default
    else:
        try:
            number = int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if number < -_MAX_SAFE_INT or number > _MAX_SAFE_INT:
        return default
    return number


def safe_int_or_none(value: Any) -> int | None:
    """Best-effort bounded integer conversion that preserves absence."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        number = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if len(text) > 20 or not text:
            return None
        try:
            number = int(text)
        except ValueError:
            return None
    else:
        try:
            number = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
    if number < -_MAX_SAFE_INT or number > _MAX_SAFE_INT:
        return None
    return number


def safe_float(value: Any, default: float = 0.0) -> float:
    """Best-effort finite float conversion."""
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return default
    else:
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return default
    return number if math.isfinite(number) else default


__all__ = [
    "DEFAULT_TEXT_LIMIT",
    "MAX_FIELD_CHARS",
    "MAX_FRAME_CHARS",
    "MAX_GOAL_FIELD_CHARS",
    "MAX_JSON_STRING_CHARS",
    "clean_multiline",
    "clean_text",
    "json_dumps_safe",
    "json_safe",
    "safe_float",
    "safe_int",
    "safe_int_or_none",
]
