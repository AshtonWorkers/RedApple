"""ULID and dedup key helpers (RA-LED-005, RA-LED-008)."""

from __future__ import annotations

import hashlib
import secrets
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ALPHABET_INDEX = {char: idx for idx, char in enumerate(_CROCKFORD)}
_MASK_48 = (1 << 48) - 1
_MASK_80 = (1 << 80) - 1


def now_ms() -> int:
    """Current Unix time in integer milliseconds."""
    return time.time_ns() // 1_000_000


def _encode_ulid(value: int) -> str:
    chars: list[str] = []
    for _ in range(26):
        value, rem = divmod(value, 32)
        chars.append(_CROCKFORD[rem])
    if value:
        raise ValueError("ULID value exceeds 128 bits")
    return "".join(reversed(chars))


class UlidFactory:
    """Monotonic Crockford-base32 ULID factory.

    IDs sort lexicographically in creation order because the 48-bit millisecond
    prefix dominates the 80-bit random suffix, and same-millisecond suffixes are
    incremented instead of resampled.
    """

    def __init__(self) -> None:
        self._last_ms = -1
        self._last_suffix = 0

    def new(self, prefix: str = "cl") -> str:
        """Return ``<prefix>_<26-char ULID>``."""
        ms = now_ms()
        if ms <= self._last_ms:
            ms = self._last_ms
        suffix = (self._last_suffix + 1) & _MASK_80 if ms == self._last_ms else secrets.randbits(80)
        self._last_ms = ms
        self._last_suffix = suffix
        value = ((ms & _MASK_48) << 80) | suffix
        return f"{prefix}_{_encode_ulid(value)}"


def artifact_id(data: bytes) -> str:
    """Content-addressed artifact ID; identical bytes always yield the same ID (I2)."""
    return "art_" + hashlib.sha256(data).hexdigest()


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def dedup_key(bug_class: str, stack_hash: str, alloc_site: str) -> str:
    """RA-LED-008 dedup key: sha256(bug_class || stack_hash || alloc_site)[:32]."""
    material = f"{bug_class}|{stack_hash}|{alloc_site}".encode()
    return hashlib.sha256(material).hexdigest()[:32]
