"""Deterministic HEIF/image mutation engine for discovery campaigns."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import TypeVar

from ..errors import FormatFail
from .heif import HEIF_BRANDS, heif_gate, parse_boxes, read_u32, write_u32, write_u64
from .models import CampaignConfig, MutationCase

_T = TypeVar("_T")
_MASK64 = (1 << 64) - 1

MUTATION_STRATEGIES = (
    "bitflip",
    "byte_set",
    "truncate",
    "extend",
    "box_size",
    "box_type",
    "brand",
    "arith",
    "dictionary",
    "splice",
)

BOX_TYPES = (
    b"ftyp",
    b"meta",
    b"hdlr",
    b"pitm",
    b"iloc",
    b"iinf",
    b"iprp",
    b"ipco",
    b"ispe",
    b"pixi",
    b"mdat",
    b"free",
    b"skip",
    b"uuid",
    b"junk",
)

BRAND_MUTATIONS = tuple(sorted(HEIF_BRANDS)) + (b"avif", b"avis", b"xxxx", b"zzzz", b"\x00\x00\x00\x00")


class DeterministicRng:
    """Small deterministic RNG so campaigns replay byte-for-byte."""

    def __init__(self, seed: int) -> None:
        self._state = (seed & _MASK64) or 0x9E3779B97F4A7C15

    def next_u64(self) -> int:
        """Advance xorshift64* and return the next uint64."""
        x = self._state
        x ^= x >> 12
        x ^= (x << 25) & _MASK64
        x ^= x >> 27
        self._state = x & _MASK64
        return ((x & _MASK64) * 0x2545F4914F6CDD1D) & _MASK64

    def randbelow(self, n: int) -> int:
        """Return a uniform integer in [0, n)."""
        if n <= 0:
            raise ValueError("n must be positive")
        limit = (1 << 64) - ((1 << 64) % n)
        while True:
            value = self.next_u64()
            if value < limit:
                return value % n

    def randrange(self, start: int, stop: int) -> int:
        """Return a uniform integer in [start, stop)."""
        if stop <= start:
            raise ValueError("stop must be greater than start")
        return start + self.randbelow(stop - start)

    def choice(self, items: Sequence[_T]) -> _T:
        """Choose one item deterministically."""
        if not items:
            raise ValueError("items must be non-empty")
        return items[self.randbelow(len(items))]

    def randbytes(self, n: int) -> bytes:
        """Return ``n`` deterministic bytes."""
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        while len(out) < n:
            out += self.next_u64().to_bytes(8, "little")
        return bytes(out[:n])


def mutate_bytes(
    data: bytes,
    strategy: str,
    rng: DeterministicRng,
    *,
    max_bytes: int,
    seeds: Sequence[bytes] = (),
) -> bytes:
    """Apply one mutation strategy, capped at ``max_bytes``."""
    if strategy not in MUTATION_STRATEGIES:
        raise FormatFail(f"unknown mutation strategy {strategy!r}")
    if len(data) > max_bytes:
        data = data[:max_bytes]
    if strategy == "bitflip":
        return _bitflip(data, rng)
    if strategy == "byte_set":
        return _byte_set(data, rng)
    if strategy == "truncate":
        return _truncate(data, rng)
    if strategy == "extend":
        return _extend(data, rng, max_bytes=max_bytes)
    if strategy == "box_size":
        return _box_size(data, rng)
    if strategy == "box_type":
        return _box_type(data, rng)
    if strategy == "brand":
        return _brand(data, rng)
    if strategy == "arith":
        return _arith(data, rng)
    if strategy == "dictionary":
        return _dictionary(data, rng)
    return _splice(data, rng, max_bytes=max_bytes, seeds=seeds)


def _bitflip(data: bytes, rng: DeterministicRng) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    for _ in range(1 + rng.randbelow(8)):
        pos = rng.randrange(0, len(out))
        out[pos] ^= 1 << rng.randbelow(8)
    return bytes(out)


def _byte_set(data: bytes, rng: DeterministicRng) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    for _ in range(1 + rng.randbelow(min(16, len(out)))):
        out[rng.randrange(0, len(out))] = rng.randbelow(256)
    return bytes(out)


def _truncate(data: bytes, rng: DeterministicRng) -> bytes:
    if len(data) <= 1:
        return data
    return data[: 1 + rng.randbelow(len(data) - 1)]


def _extend(data: bytes, rng: DeterministicRng, *, max_bytes: int) -> bytes:
    room = max_bytes - len(data)
    if room <= 0:
        return data[:max_bytes]
    extra = 1 + rng.randbelow(min(64, room))
    if rng.randbelow(2) == 0:
        return data + rng.randbytes(extra)
    if not data:
        return data + rng.randbytes(extra)
    start = rng.randrange(0, len(data))
    return data + data[start : start + extra]


def _box_size(data: bytes, rng: DeterministicRng) -> bytes:
    boxes = parse_boxes(data)
    if not boxes:
        return _byte_set(data, rng)
    box = rng.choice(boxes)
    remaining = len(data) - box.offset
    candidates = [0, 1, box.header_size, max(0, box.size - 1), box.size + 1, remaining]
    candidates.extend(rng.randrange(0, remaining + 1) for _ in range(2))
    new_size = rng.choice(candidates)
    out = bytearray(data)
    if box.header_size == 16:
        write_u64(out, box.offset + 8, new_size)
    else:
        write_u32(out, box.offset, min(new_size, 0xFFFFFFFF))
    return bytes(out)


def _box_type(data: bytes, rng: DeterministicRng) -> bytes:
    boxes = parse_boxes(data)
    if not boxes:
        return _byte_set(data, rng)
    box = rng.choice(boxes)
    out = bytearray(data)
    out[box.offset + 4 : box.offset + 8] = rng.choice(BOX_TYPES)
    return bytes(out)


def _brand(data: bytes, rng: DeterministicRng) -> bytes:
    boxes = parse_boxes(data)
    ftyp = next((box for box in boxes if box.type == b"ftyp"), None)
    if ftyp is None or ftyp.payload_size < 8:
        return _byte_set(data, rng)
    payload_offset = ftyp.payload_offset
    payload_end = payload_offset + ftyp.payload_size
    compatible = [pos for pos in range(payload_offset + 8, payload_end - 3, 4)]
    pos = (
        rng.choice(compatible)
        if compatible and rng.randbelow(2) == 0
        else payload_offset
    )
    out = bytearray(data)
    out[pos : pos + 4] = rng.choice(BRAND_MUTATIONS)
    return bytes(out)


def _arith(data: bytes, rng: DeterministicRng) -> bytes:
    boxes = parse_boxes(data)
    if not boxes:
        return _byte_set(data, rng)
    box = rng.choice(boxes)
    hi = min(box.offset + box.size, len(data)) - 4
    if hi < box.offset:
        return _byte_set(data, rng)
    span = (hi - box.offset) // 4 + 1
    offset = box.offset + 4 * rng.randrange(0, span)
    out = bytearray(data)
    value = read_u32(out, offset)
    write_u32(out, offset, value + rng.randrange(-32, 33))
    return bytes(out)


def _dictionary(data: bytes, rng: DeterministicRng) -> bytes:
    tokens = BOX_TYPES + tuple(sorted(HEIF_BRANDS)) + (b"avif", b"avis")
    hits: list[tuple[int, bytes]] = []
    for token in tokens:
        start = 0
        while True:
            pos = data.find(token, start)
            if pos < 0:
                break
            hits.append((pos, token))
            start = pos + 1
            if len(hits) >= 64:
                break
        if len(hits) >= 64:
            break
    if not hits:
        return _bitflip(data, rng)
    pos, old = rng.choice(hits)
    replacement = rng.choice(tokens)
    if replacement == old:
        replacement = tokens[(tokens.index(old) + 1) % len(tokens)]
    return data[:pos] + replacement + data[pos + len(old) :]


def _splice(
    data: bytes, rng: DeterministicRng, *, max_bytes: int, seeds: Sequence[bytes]
) -> bytes:
    if not data:
        return data
    donors = [seed for seed in seeds if seed] or [data]
    donor = rng.choice(donors)
    src_start = rng.randrange(0, len(donor))
    src_len = 1 + rng.randrange(0, min(64, len(donor) - src_start))
    chunk = donor[src_start : src_start + src_len]
    dst = rng.randrange(0, len(data) + 1)
    out = data[:dst] + chunk + data[dst:]
    return out[:max_bytes]


class MutationEngine:
    """Plan deterministic mutated HEIF/image inputs."""

    def __init__(
        self,
        seeds: Sequence[bytes],
        *,
        seed: int = CampaignConfig().seed,
        max_input_bytes: int = CampaignConfig().max_input_bytes,
    ) -> None:
        clean = [bytes(seed_data) for seed_data in seeds if seed_data]
        if not clean:
            raise FormatFail("discovery campaign requires at least one non-empty seed")
        if any(len(seed_data) > max_input_bytes for seed_data in clean):
            raise FormatFail("seed exceeds max_input_bytes")
        self._seeds = tuple(clean)
        self._seed = seed
        self._max_input_bytes = max_input_bytes

    @property
    def seed_count(self) -> int:
        """Number of corpus seeds loaded."""
        return len(self._seeds)

    def plan(self, index: int, campaign_id: str) -> MutationCase:
        """Return the deterministic mutation for ``index``."""
        if index < 0:
            raise ValueError("case index must be >= 0")
        seed_index = index % len(self._seeds)
        strategy = MUTATION_STRATEGIES[index % len(MUTATION_STRATEGIES)]
        rng = DeterministicRng((self._seed + index * 0x9E3779B97F4A7C15) & _MASK64)
        data = mutate_bytes(
            self._seeds[seed_index],
            strategy,
            rng,
            max_bytes=self._max_input_bytes,
            seeds=self._seeds,
        )
        digest = hashlib.sha256(data).hexdigest()
        gate = heif_gate(data)
        case_id = f"{campaign_id}-case-{index:08d}"
        return MutationCase(
            campaign_id=campaign_id,
            index=index,
            case_id=case_id,
            seed_index=seed_index,
            strategy=strategy,
            data=data,
            digest=digest,
            gate_pass=gate.passes,
        )


def load_corpus(paths: Sequence[str], *, max_input_bytes: int = CampaignConfig().max_input_bytes) -> list[bytes]:
    """Load seed bytes from files or directories (sorted, deterministic)."""
    from pathlib import Path

    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(item for item in path.iterdir() if item.is_file()))
        elif path.is_file():
            files.append(path)
    if not files:
        raise FormatFail("discovery corpus is empty")
    seeds: list[bytes] = []
    for path in files:
        data = path.read_bytes()
        if not data:
            continue
        seeds.append(data[:max_input_bytes])
    if not seeds:
        raise FormatFail("discovery corpus has no non-empty seeds")
    return seeds
