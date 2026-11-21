"""Egress redaction (RA-SEC-001, I9)."""

from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_USER_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s\"']+")
_SERIAL_RE = re.compile(r"\b[A-Z0-9]{10,12}\b")
_DEVICE_NAME_RE = re.compile(
    r"\b(?:iPhone|iPad|MacBook|Mac mini|Mac Pro|Mac Studio)[^\n]{0,40}", re.IGNORECASE
)


def redact_text(text: str) -> str:
    """Remove serials, Apple IDs/emails, device names, and user paths."""
    redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    redacted = _USER_PATH_RE.sub("/Users/[REDACTED]", redacted)
    redacted = _SERIAL_RE.sub("[REDACTED_SERIAL]", redacted)
    redacted = _DEVICE_NAME_RE.sub("[REDACTED_DEVICE]", redacted)
    return redacted
