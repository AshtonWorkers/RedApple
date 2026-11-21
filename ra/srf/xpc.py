"""XPC dictionary-shape extraction from cache image strings.

The dyld cache does not contain a queryable XPC schema database. We derive
deterministic field candidates from the same string sections that carry XPC
constants, and score them by structural rules only (RA-SRF-001/002).
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .models import XPCField, XPCShape

KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,95}$")
DENY_SUBSTR = (
    "com.apple.security.",
    "com.apple.private.",
    ".dylib",
    ".framework",
    ".app",
    ".appex",
    "http://",
    "https://",
    " file://",
    "%@",
    "%s",
    "%lld",
    "%llu",
    "error:",
    "failed ",
    "cannot ",
    "unable ",
    "invalid ",
)
DENY_PREFIX = ("xpc_", "__xpc_", "NSXPC", "_xpc_", "objc_", "__objc")
DENY_SUFFIX = (
    "Error",
    "Errors",
    "Notification",
    "Notifications",
    "Description",
    "Descriptions",
    "Keys",
    "Key",
)
INT_HINTS = (
    "count",
    "size",
    "index",
    "routine",
    "pid",
    "uid",
    "gid",
    "version",
    "flags",
    "mode",
    "length",
    "number",
    "value",
)
DATA_HINTS = ("data", "bytes", "blob", "auth", "signature", "cert", "payload")
DATE_HINTS = ("date", "time", "timestamp", "deadline")
ENDPOINT_HINTS = ("endpoint", "connection", "port", "listener", "peer")
UUID_HINTS = ("uuid", "guid", "token", "audit")
XPC_MARKERS = ("xpc", "NSXPC", "bootstrap_look_up", "mach_service", "xpc_connection")

MAX_FIELDS_PER_IMAGE = 48
MIN_XPC_STRINGS_FOR_SHAPE = 8


def image_has_xpc_markers(strings: Iterable[str]) -> bool:
    for s in strings:
        low = s.lower()
        if any(m.lower() in low for m in XPC_MARKERS):
            return True
    return False


def _score_key(s: str) -> int:
    score = 0
    if 3 <= len(s) <= 64:
        score += 4
    if re.search(r"[a-z]", s) and re.search(r"[A-Z]", s):
        score += 2
    elif "-" in s or "_" in s or s.islower():
        score += 1
    if s.startswith("com.apple."):
        score -= 10
    if any(x in s for x in DENY_SUBSTR):
        score -= 20
    if any(s.startswith(p) for p in DENY_PREFIX):
        score -= 15
    if any(s.endswith(x) for x in DENY_SUFFIX):
        score -= 6
    if s.endswith(".dylib") or "/" in s or " " in s:
        score -= 30
    return score


def _field_type(name: str) -> str:
    low = name.lower()
    if any(h in low for h in ENDPOINT_HINTS):
        return "endpoint"
    if any(h in low for h in DATA_HINTS):
        return "data"
    if any(h in low for h in DATE_HINTS):
        return "date"
    if any(h in low for h in UUID_HINTS):
        return "uuid"
    if any(h in low for h in INT_HINTS):
        return "uint64" if any(k in low for k in ("count", "size", "length", "number")) else "int64"
    if "bool" in low or low.startswith("is") or low.endswith("enabled") or low.endswith("allowed"):
        return "bool"
    return "string"


def probable_xpc_keys(strings: Iterable[str]) -> tuple[XPCField, ...]:
    seen: dict[str, int] = {}
    for s in strings:
        if not KEY_RE.match(s):
            continue
        score = _score_key(s)
        if score < 4:
            continue
        if s in seen:
            seen[s] = max(seen[s], score)
        else:
            seen[s] = score
    ranked = sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_FIELDS_PER_IMAGE]
    return tuple(XPCField(name=name, type=_field_type(name)) for name, _ in ranked)


def extract_xpc_shape(image_path: str, strings: Iterable[str]) -> Optional[XPCShape]:
    """Return a deterministic XPC shape for images with XPC markers."""
    materialized = tuple(strings)
    if not image_has_xpc_markers(materialized):
        return None
    if len(materialized) < MIN_XPC_STRINGS_FOR_SHAPE:
        return None
    fields = probable_xpc_keys(materialized)
    if not fields:
        return None
    return XPCShape(image_path=image_path, fields=fields)
