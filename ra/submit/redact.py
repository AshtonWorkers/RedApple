"""Submission-report redaction for secrets and PII."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from ..press.redact import redact_text as _press_redact_text

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER_RE = re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([^\s,;]+)")
_SECRET_KV_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"client[_-]?secret|secret[_-]?key|secret|password|passwd|session[_-]?token|token)"
    r"(\s*[:=]\s*)([\"']?)([^\s,;&\"']+)\3"
)
_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{16,}\b|"
    r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b|"
    r"\bsk-[A-Za-z0-9_-]{16,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAX_REDACT_DEPTH = 8


def redact_text(text: str) -> str:
    """Redact secrets, tokens, PII, device identifiers, and user paths."""
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    redacted = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", redacted)
    redacted = _SECRET_KV_RE.sub(_replace_secret_kv, redacted)
    redacted = _KNOWN_TOKEN_RE.sub("[REDACTED_TOKEN]", redacted)
    redacted = _JWT_RE.sub("[REDACTED_TOKEN]", redacted)
    redacted = _IP_RE.sub("[REDACTED_IP]", redacted)
    return _press_redact_text(redacted)


def _replace_secret_kv(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED_SECRET]{match.group(3)}"


def redact_json_value(value: Any, *, depth: int = 0) -> Any:
    """Return a JSON-safe copy with every nested string redacted."""
    if depth > _MAX_REDACT_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        return redact_text(raw.decode("utf-8", errors="replace"))
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = redact_text(str(key))[:256]
            out[safe_key] = redact_json_value(item, depth=depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [redact_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if value is None or isinstance(value, bool | int | float):
        return value
    try:
        return redact_text(str(value))
    except Exception:
        return "[UNPRINTABLE]"
