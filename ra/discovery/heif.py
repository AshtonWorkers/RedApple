"""Minimal ISO BMFF/HEIF box parsing for mutation planning.

This parser is deliberately mechanical and mirrors the Foundry proof harness:
it walks top-level boxes only and never decodes image payloads on the host.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HEIF_BRANDS = frozenset(
    {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1"}
)


def read_u32(data: bytes | bytearray, offset: int) -> int:
    """Read a big-endian uint32."""
    return int(struct.unpack_from(">I", data, offset)[0])


def read_u64(data: bytes | bytearray, offset: int) -> int:
    """Read a big-endian uint64."""
    return int(struct.unpack_from(">Q", data, offset)[0])


def write_u32(data: bytearray, offset: int, value: int) -> None:
    """Write a big-endian uint32."""
    struct.pack_into(">I", data, offset, value & 0xFFFFFFFF)


def write_u64(data: bytearray, offset: int, value: int) -> None:
    """Write a big-endian uint64."""
    struct.pack_into(">Q", data, offset, value & 0xFFFFFFFFFFFFFFFF)


def is_heif_brand(brand: bytes) -> bool:
    """Return whether ``brand`` is an accepted HEIF major/compatible brand."""
    return len(brand) == 4 and brand in HEIF_BRANDS


@dataclass(frozen=True)
class Box:
    """One top-level ISO BMFF box."""

    offset: int
    size: int
    header_size: int
    type: bytes
    payload_offset: int
    payload_size: int


@dataclass(frozen=True)
class HeifGate:
    """Result of the same ftyp/meta gate used by the ImageIO proof harness."""

    has_ftyp_heif: bool
    has_meta: bool
    major_brand: bytes | None
    box_count: int

    @property
    def passes(self) -> bool:
        """Whether the input reaches ImageIO decode in the proof harness."""
        return self.has_ftyp_heif and self.has_meta


def parse_boxes(data: bytes, *, max_boxes: int = 32) -> list[Box]:
    """Parse top-level boxes; malformed tails stop parsing like the C++ proof."""
    boxes: list[Box] = []
    size = len(data)
    if size < 8 or max_boxes < 1:
        return boxes
    offset = 0
    while offset + 8 <= size and len(boxes) < max_boxes:
        declared = read_u32(data, offset)
        box_type = data[offset + 4 : offset + 8]
        header_size = 8
        box_size = declared
        if declared == 1:
            if offset + 16 > size:
                break
            box_size = read_u64(data, offset + 8)
            header_size = 16
        elif declared == 0:
            box_size = size - offset
        if box_size < header_size or box_size > size - offset:
            break
        payload_offset = offset + header_size
        payload_size = int(box_size) - header_size
        boxes.append(
            Box(
                offset=offset,
                size=int(box_size),
                header_size=header_size,
                type=box_type,
                payload_offset=payload_offset,
                payload_size=payload_size,
            )
        )
        offset += int(box_size)
    return boxes


def heif_gate(data: bytes) -> HeifGate:
    """Evaluate the proof harness gate for ``data``."""
    boxes = parse_boxes(data)
    has_meta = any(box.type == b"meta" for box in boxes)
    has_ftyp_heif = False
    major_brand: bytes | None = None
    for box in boxes:
        if box.type != b"ftyp" or box.size < box.header_size + 8:
            continue
        payload = data[box.payload_offset : box.payload_offset + box.payload_size]
        if len(payload) < 8:
            continue
        major = payload[:4]
        major_brand = major
        if is_heif_brand(major):
            has_ftyp_heif = True
            break
        # Minor version occupies payload[4:8]; compatible brands follow.
        pos = 8
        while pos + 4 <= len(payload):
            if is_heif_brand(payload[pos : pos + 4]):
                has_ftyp_heif = True
                break
            pos += 4
        if has_ftyp_heif:
            break
    return HeifGate(
        has_ftyp_heif=has_ftyp_heif,
        has_meta=has_meta,
        major_brand=major_brand,
        box_count=len(boxes),
    )
