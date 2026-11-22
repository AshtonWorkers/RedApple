"""Crash classification and dedup signatures for discovery campaigns.

Real lanes emit sparse crash references: the payload is usually empty and the
path/handle ids are unique per occurrence. Dedup therefore keys on the crash
*class* (kind, context, category, signal, exception, image format) instead of
per-case identity, while the full per-occurrence detail stays in the claim
value for forensics.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import CrashRefLike

# Evidence scan is bounded so a huge payload cannot stall classification.
_MAX_EVIDENCE_BYTES = 65536
_MAX_METADATA_VALUE_CHARS = 4096

_SIGNAL_TOKENS = (
    b"SIGSEGV",
    b"SIGBUS",
    b"SIGILL",
    b"SIGABRT",
    b"SIGFPE",
    b"SIGTRAP",
    b"SIGSYS",
)

_EXCEPTION_TOKENS = (
    b"EXC_BAD_ACCESS",
    b"EXC_BAD_INSTRUCTION",
    b"EXC_BREAKPOINT",
    b"EXC_CRASH",
    b"EXC_GUARD",
    b"EXC_RESOURCE",
    b"NSInvalidArgumentException",
    b"NSRangeException",
    b"NSInternalInconsistencyException",
    b"NSException",
)

_TIMEOUT_METADATA_KEYS = frozenset({"feed_timeout_s", "timeout_s", "timed_out"})
_NATIVE_CRASH_KINDS = frozenset({"ios_crash", "macos_vm_crash"})
_CRASH_PATH_SUFFIXES = (".ips", ".crash", ".diag", ".panic")


@dataclass(frozen=True)
class CrashClassification:
    """Crash class used for dedup; occurrence detail lives in the claim value."""

    kind: str
    context: str
    category: str
    signal: str | None
    exception: str | None
    image_format: str | None

    def signature(self, campaign_id: str) -> dict[str, str | None]:
        """Return the JSON-safe dedup signature for this crash class."""
        return {
            "campaign_id": campaign_id,
            "kind": self.kind,
            "context": self.context,
            "category": self.category,
            "signal": self.signal,
            "exception": self.exception,
            "image_format": self.image_format,
        }


def _evidence_bytes(crash: CrashRefLike) -> bytes:
    parts: list[bytes] = []
    payload = bytes(getattr(crash, "payload", b"") or b"")
    if payload:
        parts.append(payload[:_MAX_EVIDENCE_BYTES])
    metadata = getattr(crash, "metadata", {}) or {}
    path = getattr(crash, "path", None)
    if isinstance(path, str) and path:
        parts.append(path.encode("utf-8", "replace")[:_MAX_METADATA_VALUE_CHARS])
    if isinstance(metadata, dict):
        for key in sorted(metadata):
            value = metadata[key]
            if isinstance(value, (str, int, float)):
                text = str(value)[:_MAX_METADATA_VALUE_CHARS]
                parts.append(f"{key}={text}".encode("utf-8", "replace"))
    return b"\n".join(parts)


def _find_token(evidence: bytes, tokens: tuple[bytes, ...]) -> str | None:
    for token in tokens:
        if token in evidence:
            return token.decode("ascii")
    return None


def classify_crash(crash: CrashRefLike, *, image_format: str | None = None) -> CrashClassification:
    """Classify one crash reference into a dedup-able crash class.

    Categories: ``timeout`` (feed/hang timeouts), ``native_crash`` (lane crash
    kinds, crash-report paths, or signal/exception evidence), else ``unknown``.
    """
    kind = str(getattr(crash, "kind", "unknown") or "unknown")
    context = str(getattr(crash, "context", "app") or "app")
    metadata = getattr(crash, "metadata", {}) or {}
    metadata_keys = set(metadata) if isinstance(metadata, dict) else set()
    path = getattr(crash, "path", None)
    path_text = path if isinstance(path, str) else ""

    evidence = _evidence_bytes(crash)
    signal = _find_token(evidence, _SIGNAL_TOKENS)
    exception = _find_token(evidence, _EXCEPTION_TOKENS)

    if kind == "hang" or metadata_keys & _TIMEOUT_METADATA_KEYS:
        category = "timeout"
    elif (
        signal is not None
        or exception is not None
        or kind in _NATIVE_CRASH_KINDS
        or path_text.lower().endswith(_CRASH_PATH_SUFFIXES)
    ):
        category = "native_crash"
    else:
        category = "unknown"

    return CrashClassification(
        kind=kind,
        context=context,
        category=category,
        signal=signal,
        exception=exception,
        image_format=image_format,
    )
