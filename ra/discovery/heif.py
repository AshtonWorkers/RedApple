"""Minimal ISO BMFF/HEIF box parsing for mutation planning.

This parser is deliberately mechanical: it walks top-level boxes by default and
offers an opt-in bounded tree walk for structure-aware mutations. It never
decodes image payloads on the host.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

HEIF_BRANDS = frozenset(
    {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1"}
)

# Container boxes relevant to HEIF stills and generic ISO BMFF mutation. The
# parser is intentionally permissive: unknown containers are still walked when
# they are in this set, and malformed children stop only that container.
CONTAINER_BOXES = frozenset(
    {
        b"moov",
        b"trak",
        b"mdia",
        b"minf",
        b"dinf",
        b"stbl",
        b"edts",
        b"udta",
        b"meta",
        b"iprp",
        b"ipco",
        b"iinf",
        b"iref",
        b"grpl",
    }
)

# Containers whose payload begins with a 32-bit FullBox version/flags word.
FULL_CONTAINER_BOXES = frozenset({b"meta", b"iinf", b"iref"})

# Boxes the mutator knows how to target with field-level edits.
FIELD_BOXES = frozenset({b"ispe", b"pixi", b"pitm", b"iloc", b"iinf", b"hdlr", b"ipma"})


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
    """One ISO BMFF box.

    ``header_size`` is the size-field header (8 or 16 bytes). ``payload_offset``
    also skips the 16-byte UUID usertype for ``uuid`` boxes.
    """

    offset: int
    size: int
    header_size: int
    type: bytes
    payload_offset: int
    payload_size: int


@dataclass(frozen=True)
class BoxNode:
    """A box plus its bounded child boxes."""

    box: Box
    depth: int
    children: tuple[BoxNode, ...] = field(default_factory=tuple)


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


def _box_at(data: bytes, offset: int, end: int) -> tuple[Box, int] | None:
    """Parse one box in ``[offset, end)`` and return it with the next offset."""
    if offset + 8 > end:
        return None
    declared = read_u32(data, offset)
    box_type = data[offset + 4 : offset + 8]
    header_size = 8
    box_size = declared
    if declared == 1:
        if offset + 16 > end:
            return None
        box_size = read_u64(data, offset + 8)
        header_size = 16
    elif declared == 0:
        box_size = end - offset
    if box_size < header_size or box_size > end - offset:
        return None
    payload_offset = offset + header_size
    if box_type == b"uuid" and box_size >= header_size + 16:
        payload_offset += 16
    payload_end = offset + int(box_size)
    return (
        Box(
            offset=offset,
            size=int(box_size),
            header_size=header_size,
            type=box_type,
            payload_offset=payload_offset,
            payload_size=max(0, payload_end - payload_offset),
        ),
        payload_end,
    )


def container_payload_range(data: bytes, box: Box) -> tuple[int, int] | None:
    """Return the byte range that may contain child boxes for ``box``."""
    if box.type not in CONTAINER_BOXES:
        return None
    start = box.payload_offset
    end = box.offset + box.size
    if start > end:
        return None
    if box.type in FULL_CONTAINER_BOXES:
        if start + 4 > end:
            return None
        start += 4
        if box.type == b"iinf":
            version = data[box.payload_offset]
            count_size = 2 if version < 2 else 4
            if start + count_size > end:
                return None
            start += count_size
    if start > end:
        return None
    return start, end


def _parse_range(
    data: bytes,
    start: int,
    end: int,
    depth: int,
    *,
    max_depth: int,
    budget: list[int],
) -> list[BoxNode]:
    nodes: list[BoxNode] = []
    offset = start
    while offset + 8 <= end and budget[0] > 0:
        parsed = _box_at(data, offset, end)
        if parsed is None:
            break
        box, next_offset = parsed
        budget[0] -= 1
        children: tuple[BoxNode, ...] = ()
        if depth < max_depth and budget[0] > 0:
            child_range = container_payload_range(data, box)
            if child_range is not None:
                child_start, child_end = child_range
                children = tuple(
                    _parse_range(
                        data,
                        child_start,
                        child_end,
                        depth + 1,
                        max_depth=max_depth,
                        budget=budget,
                    )
                )
        nodes.append(BoxNode(box=box, depth=depth, children=children))
        if next_offset <= offset:
            break
        offset = next_offset
    return nodes


def parse_box_tree(data: bytes, *, max_boxes: int = 128, max_depth: int = 8) -> list[BoxNode]:
    """Parse a bounded ISO BMFF box tree.

    Malformed boxes stop the current container only; the walk is capped by
    ``max_boxes`` and ``max_depth`` so hostile nesting cannot exhaust the host.
    """
    if len(data) < 8 or max_boxes < 1 or max_depth < 1:
        return []
    return _parse_range(data, 0, len(data), 0, max_depth=max_depth, budget=[max_boxes])


def iter_box_nodes(nodes: list[BoxNode] | tuple[BoxNode, ...]) -> Iterator[BoxNode]:
    """Yield every node in a parsed box tree depth-first."""
    for node in nodes:
        yield node
        yield from iter_box_nodes(node.children)


def find_box_nodes(
    nodes: list[BoxNode] | tuple[BoxNode, ...], box_type: bytes
) -> list[BoxNode]:
    """Return all nodes with ``box_type`` in tree order."""
    return [node for node in iter_box_nodes(nodes) if node.box.type == box_type]


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
