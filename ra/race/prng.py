"""Deterministic randomness for the stochastic race harness (RA-RACE-001).

Schedules must replay byte-identically from a seed on any host, so this module
uses a counter-mode SHA-256 DRBG keyed by a canonical string. It never touches
the global ``random`` module and never reads wall-clock time.
"""

from __future__ import annotations

import hashlib

from ..errors import FormatFail

MAX_SEED = (1 << 63) - 1


def normalize_seed(seed: int | str) -> int:
    """Normalize a seed (int or decimal/0x/0o/0b string) to a canonical int."""
    if isinstance(seed, bool):
        raise FormatFail("race seed must be an int or str, not bool")
    if isinstance(seed, int):
        value = seed
    elif isinstance(seed, str):
        text = seed.strip()
        try:
            value = int(text, 0) if text.lower().startswith(("0x", "0o", "0b")) else int(text, 10)
        except ValueError as exc:
            raise FormatFail(f"invalid race seed {seed!r}") from exc
    else:
        raise FormatFail(f"race seed must be an int or str, got {type(seed).__name__}")
    if value < 0 or value > MAX_SEED:
        raise FormatFail(f"race seed out of range: {value}")
    return value


def seed_hex(seed: int | str) -> str:
    """Canonical fixed-width hex form of a seed."""
    return f"{normalize_seed(seed):016x}"


def parse_seed_hex(text: str) -> int:
    """Parse the canonical 16-char lowercase hex seed form."""
    if not isinstance(text, str) or len(text) != 16:
        raise FormatFail("seed hex must be exactly 16 chars")
    if any(ch not in "0123456789abcdef" for ch in text):
        raise FormatFail("seed hex must be lowercase hex")
    return int(text, 16)


class RaceRng:
    """Counter-mode SHA-256 DRBG.

    The same key always produces the same stream, in any process, on any host.
    """

    def __init__(self, key: bytes | str) -> None:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if not key:
            raise FormatFail("RaceRng key must not be empty")
        self._key = key
        self._counter = 0
        self._block = b""
        self._pos = 32

    def _next_block(self) -> bytes:
        counter = self._counter.to_bytes(8, "big")
        self._counter += 1
        return hashlib.sha256(self._key + counter).digest()

    def _byte(self) -> int:
        if self._pos >= 32:
            self._block = self._next_block()
            self._pos = 0
        value = self._block[self._pos]
        self._pos += 1
        return value

    def next_u64(self) -> int:
        """Draw a uniform 64-bit unsigned integer."""
        return int.from_bytes(bytes(self._byte() for _ in range(8)), "big")

    def randbelow(self, n: int) -> int:
        """Draw a uniform integer in ``[0, n)`` by rejection sampling."""
        if isinstance(n, bool) or not isinstance(n, int):
            raise FormatFail(f"randbelow bound must be int, got {type(n).__name__}")
        if n <= 0:
            raise FormatFail("randbelow bound must be positive")
        if n == 1:
            return 0
        bits = n.bit_length()
        mask = (1 << bits) - 1
        words = (bits + 63) // 64
        while True:
            value = 0
            for _ in range(words):
                value = (value << 64) | self.next_u64()
            value &= mask
            if value < n:
                return value

    def uniform(self) -> float:
        """Draw a uniform float in ``[0.0, 1.0)``."""
        return self.next_u64() / float(1 << 64)

    def choice(self, options: tuple[str, ...]) -> str:
        """Choose one option uniformly."""
        if not options:
            raise FormatFail("choice requires at least one option")
        return options[self.randbelow(len(options))]

    def jitter_us(self, max_delay_us: int) -> int:
        """Draw a delay in microseconds in ``[0, max_delay_us]``."""
        if max_delay_us < 0:
            raise FormatFail("max_delay_us must be >= 0")
        if max_delay_us == 0:
            return 0
        return self.randbelow(max_delay_us + 1)
