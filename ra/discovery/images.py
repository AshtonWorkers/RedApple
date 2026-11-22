"""Image format detection, seed builders, and structure-aware mutators.

The mutators here are host-side planning helpers only: they never decode image
pixels. They understand just enough container structure (ISO BMFF is handled in
``heif.py``; PNG/JPEG/GIF/BMP/TIFF/WebP here) to make malformed-size, field,
nesting, truncation, and insertion cases deterministic.
"""

from __future__ import annotations

import base64
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, TypeVar

from ..errors import FormatFail
from .heif import heif_gate

_T = TypeVar("_T")
_Endian = Literal["little", "big"]


class ImageRng(Protocol):
    """Structural RNG interface shared with ``DeterministicRng``."""

    def randbelow(self, n: int) -> int: ...

    def randrange(self, start: int, stop: int) -> int: ...

    def choice(self, items: Sequence[_T]) -> _T: ...

    def randbytes(self, n: int) -> bytes: ...


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
GIF_MAGIC = (b"GIF87a", b"GIF89a")
BMP_MAGIC = b"BM"
TIFF_MAGICS = (b"II*\x00", b"MM\x00*")
RIFF_MAGIC = b"RIFF"
WEBP_MAGIC = b"WEBP"

IMAGE_FORMATS = ("heif", "png", "jpeg", "gif", "bmp", "tiff", "webp")

_MIN_GATE_BYTES = {
    "heif": 8,
    "png": 8,
    "jpeg": 4,
    "gif": 13,
    "bmp": 26,
    "tiff": 8,
    "webp": 12,
}

PNG_CHUNK_TYPES = (
    b"IHDR",
    b"PLTE",
    b"IDAT",
    b"IEND",
    b"tRNS",
    b"gAMA",
    b"cHRM",
    b"sRGB",
    b"iCCP",
    b"tEXt",
    b"zTXt",
    b"iTXt",
    b"bKGD",
    b"pHYs",
    b"tIME",
    b"acTL",
    b"fcTL",
    b"fdAT",
)
PNG_ANCILLARY_TYPES = (b"tEXt", b"zTXt", b"iCCP", b"pHYs", b"tIME", b"bKGD")

JPEG_MARKER_TYPES = (0xE0, 0xE1, 0xE2, 0xED, 0xEE, 0xFE, 0xDB, 0xC4, 0xDD, 0xDA)
JPEG_SOF_MARKERS = (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)
JPEG_STANDALONE_MARKERS = frozenset({0x01, 0xD8, 0xD9, *range(0xD0, 0xD8)})

WEBP_CHUNK_TYPES = (b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF", b"ICCP", b"EXIF", b"XMP ")
WEBP_META_TYPES = (b"VP8X", b"EXIF", b"XMP ", b"ICCP")

TIFF_TAGS = (256, 257, 258, 259, 262, 266, 270, 273, 274, 277, 278, 279, 282, 283, 284, 330)
TIFF_TYPES = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)

_STRUCTURE_OPS = ("box_size", "box_type", "box_field", "box_insert", "box_delete", "box_nest")

_GIF_1X1 = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
_WEBP_1X1 = base64.b64decode("UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA")


@dataclass(frozen=True)
class ImageGate:
    """Result of the image plausibility gate used for campaign planning."""

    image_format: str | None
    passes: bool
    detail: str = ""


@dataclass(frozen=True)
class _Chunk:
    offset: int
    length: int
    kind: bytes
    data_offset: int
    end: int
    tail_offset: int | None = None


@dataclass(frozen=True)
class _Segment:
    offset: int
    marker: int
    length_offset: int
    length: int
    data_offset: int
    end: int
    has_length: bool


@dataclass(frozen=True)
class _TiffEntry:
    offset: int
    tag: int
    type: int
    count: int
    value_offset: int


@dataclass(frozen=True)
class _GifLayout:
    image_sep_offset: int
    lzw_offset: int
    sub_start: int
    sub_blocks: tuple[_Chunk, ...]
    terminator_offset: int | None


def _bounded(data: bytes, max_bytes: int) -> bytes:
    if max_bytes < 0:
        max_bytes = 0
    return data if len(data) <= max_bytes else data[:max_bytes]


def _fallback(data: bytes, rng: ImageRng, max_bytes: int) -> bytes:
    out = bytearray(_bounded(data, max_bytes))
    if not out:
        return b""
    pos = rng.randrange(0, len(out))
    out[pos] ^= 1 << rng.randbelow(8)
    return bytes(out)


def _read_u16(data: bytes, offset: int, endian: _Endian = "big") -> int:
    return int.from_bytes(data[offset : offset + 2], endian)


def _read_u32(data: bytes, offset: int, endian: _Endian = "big") -> int:
    return int.from_bytes(data[offset : offset + 4], endian)


def _write_u16(out: bytearray, offset: int, value: int, endian: _Endian = "big") -> None:
    out[offset : offset + 2] = (value & 0xFFFF).to_bytes(2, endian)


def _write_u32(out: bytearray, offset: int, value: int, endian: _Endian = "big") -> None:
    out[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, endian)


def detect_image_format(data: bytes) -> str | None:
    """Return the best-known image container format for ``data``."""
    if heif_gate(data).has_ftyp_heif:
        return "heif"
    if data.startswith(PNG_SIGNATURE):
        return "png"
    if data.startswith(JPEG_MAGIC):
        return "jpeg"
    if data.startswith(GIF_MAGIC):
        return "gif"
    if data.startswith(BMP_MAGIC):
        return "bmp"
    if data.startswith(TIFF_MAGICS):
        return "tiff"
    if (
        len(data) >= 12
        and data[:4] == RIFF_MAGIC
        and data[8:12] == WEBP_MAGIC
    ):
        return "webp"
    return None


def image_gate(data: bytes) -> ImageGate:
    """Return whether ``data`` is plausible enough to feed ImageIO."""
    image_format = detect_image_format(data)
    if image_format is None:
        return ImageGate(None, False, "unknown")
    if image_format == "heif":
        gate = heif_gate(data)
        if gate.passes:
            return ImageGate("heif", True, f"ftyp+meta boxes={gate.box_count}")
        return ImageGate("heif", False, "heif_gate_failed")
    if len(data) < _MIN_GATE_BYTES[image_format]:
        return ImageGate(image_format, False, "truncated_header")
    return ImageGate(image_format, True, image_format)


def _check_dims(width: int, height: int) -> None:
    if width < 1 or height < 1 or width > 4096 or height > 4096:
        raise ValueError("image seed dimensions must be within 1..4096")


def _bmff_box(kind: bytes, payload: bytes = b"") -> bytes:
    return (8 + len(payload)).to_bytes(4, "big") + kind + payload


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return len(payload).to_bytes(4, "big") + kind + payload + crc.to_bytes(4, "big")


def build_png_seed(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal deterministic PNG seed."""
    _check_dims(width, height)
    ihdr = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes((8, 6, 0, 0, 0))
    )
    row = b"\x00" + b"\xff\x00\x00\xff" * width
    raw = row * height
    return (
        PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(raw))
        + _png_chunk(b"IEND", b"")
    )


def build_jpeg_seed(width: int = 1, height: int = 1) -> bytes:
    """Build a small structurally plausible JPEG seed for mutation."""
    _check_dims(width, height)
    app0_payload = b"JFIF\x00" + bytes((1, 1, 0)) + (1).to_bytes(2, "big") * 2 + b"\x00\x00"
    app0 = b"\xff\xe0" + (2 + len(app0_payload)).to_bytes(2, "big") + app0_payload
    dqt_payload = b"\x00" + bytes((16, 11, 10, 16, 24, 40, 51, 61) * 8)
    dqt = b"\xff\xdb" + (2 + len(dqt_payload)).to_bytes(2, "big") + dqt_payload
    sof_payload = (
        bytes((8,))
        + height.to_bytes(2, "big")
        + width.to_bytes(2, "big")
        + bytes((1, 1, 0x11, 0))
    )
    sof = b"\xff\xc0" + (2 + len(sof_payload)).to_bytes(2, "big") + sof_payload
    dht_payload = bytes((0x00,)) + bytes((0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0)) + bytes(range(12))
    dht = b"\xff\xc4" + (2 + len(dht_payload)).to_bytes(2, "big") + dht_payload
    sos_payload = bytes((1, 1, 0x00, 0, 63, 0))
    sos = b"\xff\xda" + (2 + len(sos_payload)).to_bytes(2, "big") + sos_payload
    entropy = b"\x00\x3f\x00\xff\x00"
    return b"\xff\xd8" + app0 + dqt + sof + dht + sos + entropy + b"\xff\xd9"


def build_gif_seed() -> bytes:
    """Return a deterministic 1x1 GIF89a seed."""
    return _GIF_1X1


def build_bmp_seed(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal uncompressed 24-bit BMP seed."""
    _check_dims(width, height)
    row_size = ((width * 3 + 3) // 4) * 4
    pixel_bytes = row_size * height
    file_size = 14 + 40 + pixel_bytes
    header = bytearray()
    header += BMP_MAGIC
    header += file_size.to_bytes(4, "little")
    header += b"\x00\x00\x00\x00"
    header += (14 + 40).to_bytes(4, "little")
    dib = bytearray()
    dib += (40).to_bytes(4, "little")
    dib += width.to_bytes(4, "little", signed=True)
    dib += height.to_bytes(4, "little", signed=True)
    dib += (1).to_bytes(2, "little")
    dib += (24).to_bytes(2, "little")
    dib += (0).to_bytes(4, "little")
    dib += pixel_bytes.to_bytes(4, "little")
    dib += (2835).to_bytes(4, "little", signed=True)
    dib += (2835).to_bytes(4, "little", signed=True)
    dib += (0).to_bytes(4, "little")
    dib += (0).to_bytes(4, "little")
    pixels = bytearray()
    for _ in range(height):
        pixels += b"\x00\x00\xff" * width
        pixels += b"\x00" * (row_size - width * 3)
    return bytes(header + dib + pixels)


def _tiff_entry(tag: int, type_: int, count: int, value: int) -> bytes:
    if type_ == 3 and count == 1:
        value_bytes = value.to_bytes(2, "little") + b"\x00\x00"
    else:
        value_bytes = value.to_bytes(4, "little")
    return (
        tag.to_bytes(2, "little")
        + type_.to_bytes(2, "little")
        + count.to_bytes(4, "little")
        + value_bytes
    )


def build_tiff_seed(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal little-endian grayscale TIFF seed."""
    _check_dims(width, height)
    entries = [
        _tiff_entry(256, 4, 1, width),
        _tiff_entry(257, 4, 1, height),
        _tiff_entry(258, 3, 1, 8),
        _tiff_entry(259, 3, 1, 1),
        _tiff_entry(262, 3, 1, 1),
        _tiff_entry(273, 4, 1, 8 + 2 + 10 * 12 + 4),
        _tiff_entry(277, 3, 1, 1),
        _tiff_entry(278, 4, 1, height),
        _tiff_entry(279, 4, 1, width * height),
        _tiff_entry(284, 3, 1, 1),
    ]
    ifd = (10).to_bytes(2, "little") + b"".join(entries) + (0).to_bytes(4, "little")
    return b"II*\x00" + (8).to_bytes(4, "little") + ifd + bytes([0x80]) * (width * height)


def build_webp_seed() -> bytes:
    """Return a deterministic tiny WebP seed."""
    return _WEBP_1X1


def build_heif_seed() -> bytes:
    """Return a minimal deterministic HEIF/ISO-BMFF seed."""
    ftyp_payload = b"heic" + (0).to_bytes(4, "big") + b"mif1"
    meta_payload = b"\x00\x00\x00\x00"
    return _bmff_box(b"ftyp", ftyp_payload) + _bmff_box(b"meta", meta_payload)


def build_image_seed(image_format: str, *, width: int = 1, height: int = 1) -> bytes:
    """Build one deterministic seed for ``image_format``."""
    if image_format == "heif":
        return build_heif_seed()
    if image_format == "png":
        return build_png_seed(width, height)
    if image_format == "jpeg":
        return build_jpeg_seed(width, height)
    if image_format == "gif":
        return build_gif_seed()
    if image_format == "bmp":
        return build_bmp_seed(width, height)
    if image_format == "tiff":
        return build_tiff_seed(width, height)
    if image_format == "webp":
        return build_webp_seed()
    raise FormatFail(f"unsupported image format {image_format!r}")


def default_imageio_seeds() -> dict[str, bytes]:
    """Return deterministic built-in seeds for every supported image format."""
    return {image_format: build_image_seed(image_format) for image_format in IMAGE_FORMATS}


def _png_chunks(data: bytes) -> list[_Chunk]:
    chunks: list[_Chunk] = []
    if len(data) < 8 + 8 or not data.startswith(PNG_SIGNATURE):
        return chunks
    pos = 8
    while pos + 8 <= len(data) and len(chunks) < 64:
        length = _read_u32(data, pos)
        kind = data[pos + 4 : pos + 8]
        data_offset = pos + 8
        declared_end = pos + 12 + length
        if declared_end > len(data):
            chunks.append(_Chunk(pos, length, kind, data_offset, len(data), None))
            break
        chunks.append(_Chunk(pos, length, kind, data_offset, declared_end, data_offset + length))
        pos = declared_end
    return chunks


def _png_chunk_bytes(kind: bytes, payload: bytes) -> bytes:
    return _png_chunk(kind, payload)


def _png_length_candidates(current: int, remaining: int, rng: ImageRng) -> list[int]:
    candidates = [0, 1, 2, 8, 12, 13, 0x7FFFFFFF, 0xFFFFFFFF, current - 1, current + 1]
    candidates.extend(rng.randrange(0, max(1, remaining + 1)) for _ in range(2))
    return [value & 0xFFFFFFFF for value in candidates]


def _png_mutate_size(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    candidates = [chunk for chunk in chunks if chunk.end <= len(data)]
    if not candidates:
        return _fallback(data, rng, len(data))
    chunk = rng.choice(candidates)
    out = bytearray(data)
    values = _png_length_candidates(chunk.length, len(data) - chunk.offset, rng)
    _write_u32(out, chunk.offset, rng.choice(values))
    return bytes(out)


def _png_mutate_type(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    candidates = [chunk for chunk in chunks if chunk.end <= len(data)]
    if not candidates:
        return _fallback(data, rng, len(data))
    chunk = rng.choice(candidates)
    replacement = rng.choice(PNG_CHUNK_TYPES)
    out = bytearray(data)
    out[chunk.offset + 4 : chunk.offset + 8] = replacement
    return bytes(out)


def _png_mutate_field(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    ihdr = next((chunk for chunk in chunks if chunk.kind == b"IHDR" and chunk.length >= 13), None)
    if ihdr is None or ihdr.data_offset + 13 > len(data):
        return _fallback(data, rng, len(data))
    out = bytearray(data)
    field = rng.choice(("width", "height", "bit_depth", "color_type"))
    if field == "width":
        current = _read_u32(data, ihdr.data_offset)
        value = rng.choice([0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFF, current - 1, current + 1])
        _write_u32(out, ihdr.data_offset, value)
    elif field == "height":
        current = _read_u32(data, ihdr.data_offset + 4)
        value = rng.choice([0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFF, current - 1, current + 1])
        _write_u32(out, ihdr.data_offset + 4, value)
    elif field == "bit_depth":
        out[ihdr.data_offset + 8] = rng.choice((0, 1, 2, 4, 8, 16, 255))
    else:
        out[ihdr.data_offset + 9] = rng.choice((0, 1, 2, 3, 4, 6, 255))
    return bytes(out)


def _png_insert(data: bytes, chunks: list[_Chunk], rng: ImageRng, *, ancillary: bool) -> bytes:
    boundaries = {8, len(data)}
    boundaries.update(chunk.offset for chunk in chunks if chunk.offset <= len(data))
    kinds: tuple[bytes, ...]
    if ancillary:
        iend = next((chunk for chunk in chunks if chunk.kind == b"IEND"), None)
        boundary = iend.offset if iend is not None else len(data)
        kinds = PNG_ANCILLARY_TYPES
    else:
        boundary = rng.choice(sorted(boundaries))
        kinds = PNG_CHUNK_TYPES
    kind = rng.choice(kinds)
    payload = rng.randbytes(rng.randrange(0, 17))
    inserted = _png_chunk_bytes(kind, payload)
    out = data[:boundary] + inserted + data[boundary:]
    return _bounded(out, len(data) + len(inserted))


def _png_delete(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    candidates = [chunk for chunk in chunks if chunk.end <= len(data) and chunk.end > chunk.offset]
    if not candidates:
        return _fallback(data, rng, len(data))
    chunk = rng.choice(candidates)
    out = data[: chunk.offset] + data[chunk.end :]
    if len(out) < len(PNG_SIGNATURE):
        return data[: len(PNG_SIGNATURE)]
    return out


def mutate_png(data: bytes, strategy: str, rng: ImageRng, *, max_bytes: int) -> bytes:
    """Apply a structure-aware PNG mutation."""
    if len(data) < len(PNG_SIGNATURE) or not data.startswith(PNG_SIGNATURE):
        return _fallback(data, rng, max_bytes)
    if strategy == "image_structure":
        return mutate_png(data, str(rng.choice(_STRUCTURE_OPS)), rng, max_bytes=max_bytes)
    chunks = _png_chunks(data)
    if strategy == "box_size":
        out = _png_mutate_size(data, chunks, rng)
    elif strategy == "box_type":
        out = _png_mutate_type(data, chunks, rng)
    elif strategy == "box_field":
        out = _png_mutate_field(data, chunks, rng)
    elif strategy == "box_insert":
        out = _png_insert(data, chunks, rng, ancillary=False)
    elif strategy == "box_delete":
        out = _png_delete(data, chunks, rng)
    elif strategy == "box_nest":
        out = _png_insert(data, chunks, rng, ancillary=True)
    else:
        return _fallback(data, rng, max_bytes)
    return _bounded(out, max_bytes)


def _jpeg_segments(data: bytes) -> list[_Segment]:
    segments: list[_Segment] = []
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return segments
    pos = 2
    while pos + 2 <= len(data) and len(segments) < 128:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0x00:
            break
        offset = pos
        pos += 2
        if marker in JPEG_STANDALONE_MARKERS:
            segments.append(_Segment(offset, marker, -1, 0, pos, pos, False))
            if marker == 0xD9:
                break
            continue
        if pos + 2 > len(data):
            break
        length = _read_u16(data, pos)
        if length < 2:
            break
        length_offset = pos
        data_offset = pos + 2
        end = length_offset + length
        if end > len(data):
            end = len(data)
        segments.append(_Segment(offset, marker, length_offset, length, data_offset, end, True))
        if marker == 0xDA or end <= length_offset:
            break
        pos = end
    return segments


def _jpeg_segment_bytes(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + (2 + len(payload)).to_bytes(2, "big") + payload


def _jpeg_mutate_size(data: bytes, segments: list[_Segment], rng: ImageRng) -> bytes:
    candidates = [segment for segment in segments if segment.has_length and segment.end <= len(data)]
    if not candidates:
        return _fallback(data, rng, len(data))
    segment = rng.choice(candidates)
    out = bytearray(data)
    remaining = max(1, len(data) - segment.length_offset)
    values = [0, 1, 2, 4, 8, 16, 0xFFFF, segment.length - 1, segment.length + 1]
    values.extend(rng.randrange(0, min(0x10000, remaining + 1)) for _ in range(2))
    _write_u16(out, segment.length_offset, rng.choice(values) & 0xFFFF)
    return bytes(out)


def _jpeg_mutate_type(data: bytes, segments: list[_Segment], rng: ImageRng) -> bytes:
    candidates = [segment for segment in segments if segment.has_length and segment.end <= len(data)]
    if not candidates:
        return _fallback(data, rng, len(data))
    segment = rng.choice(candidates)
    out = bytearray(data)
    out[segment.offset + 1] = rng.choice(JPEG_MARKER_TYPES)
    return bytes(out)


def _jpeg_mutate_field(data: bytes, segments: list[_Segment], rng: ImageRng) -> bytes:
    sof = next(
        (
            segment
            for segment in segments
            if segment.marker in JPEG_SOF_MARKERS and segment.data_offset + 6 <= len(data)
        ),
        None,
    )
    if sof is None:
        return _fallback(data, rng, len(data))
    out = bytearray(data)
    field = rng.choice(("precision", "height", "width", "components"))
    base = sof.data_offset
    if field == "precision":
        out[base] = rng.choice((0, 1, 8, 12, 16, 255))
    elif field == "height":
        current = _read_u16(data, base + 1)
        _write_u16(out, base + 1, rng.choice([0, 1, 2, 0xFFFF, current - 1, current + 1]))
    elif field == "width":
        current = _read_u16(data, base + 3)
        _write_u16(out, base + 3, rng.choice([0, 1, 2, 0xFFFF, current - 1, current + 1]))
    else:
        out[base + 5] = rng.choice((0, 1, 2, 3, 4, 255))
    return bytes(out)


def _jpeg_boundaries(segments: list[_Segment], data_len: int) -> list[int]:
    boundaries = {2}
    for segment in segments:
        if segment.marker == 0xDA:
            boundaries.add(segment.offset)
            break
        if segment.end <= data_len:
            boundaries.add(segment.end)
    return sorted(boundary for boundary in boundaries if 2 <= boundary <= data_len)


def _jpeg_insert(data: bytes, segments: list[_Segment], rng: ImageRng, *, comment: bool) -> bytes:
    boundaries = _jpeg_boundaries(segments, len(data))
    if not boundaries:
        return _fallback(data, rng, len(data))
    boundary = boundaries[-1] if comment else rng.choice(boundaries)
    marker = rng.choice((0xFE, 0xE0, 0xE1)) if comment else rng.choice(JPEG_MARKER_TYPES)
    payload = rng.randbytes(rng.randrange(0, 17))
    inserted = _jpeg_segment_bytes(marker, payload)
    return data[:boundary] + inserted + data[boundary:]


def _jpeg_delete(data: bytes, segments: list[_Segment], rng: ImageRng) -> bytes:
    candidates = [
        segment
        for segment in segments
        if segment.end <= len(data) and segment.end > segment.offset and segment.offset >= 2
    ]
    if not candidates:
        return _fallback(data, rng, len(data))
    segment = rng.choice(candidates)
    out = data[: segment.offset] + data[segment.end :]
    if len(out) < 4 or out[:2] != b"\xff\xd8":
        return data[:4]
    return out


def mutate_jpeg(data: bytes, strategy: str, rng: ImageRng, *, max_bytes: int) -> bytes:
    """Apply a structure-aware JPEG marker/segment mutation."""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return _fallback(data, rng, max_bytes)
    if strategy == "image_structure":
        return mutate_jpeg(data, str(rng.choice(_STRUCTURE_OPS)), rng, max_bytes=max_bytes)
    segments = _jpeg_segments(data)
    if strategy == "box_size":
        out = _jpeg_mutate_size(data, segments, rng)
    elif strategy == "box_type":
        out = _jpeg_mutate_type(data, segments, rng)
    elif strategy == "box_field":
        out = _jpeg_mutate_field(data, segments, rng)
    elif strategy == "box_insert":
        out = _jpeg_insert(data, segments, rng, comment=False)
    elif strategy == "box_delete":
        out = _jpeg_delete(data, segments, rng)
    elif strategy == "box_nest":
        out = _jpeg_insert(data, segments, rng, comment=True)
    else:
        return _fallback(data, rng, max_bytes)
    return _bounded(out, max_bytes)


def _gif_gct_end(data: bytes) -> int | None:
    if len(data) < 13:
        return None
    packed = data[10]
    if not packed & 0x80:
        return 13
    table_size = 3 * (2 ** ((packed & 0x07) + 1))
    end = 13 + table_size
    return end if end <= len(data) else None


def _gif_sub_blocks(data: bytes, start: int) -> tuple[tuple[_Chunk, ...], int | None]:
    blocks: list[_Chunk] = []
    pos = start
    while pos < len(data) and len(blocks) < 256:
        size = data[pos]
        if size == 0:
            return tuple(blocks), pos
        end = pos + 1 + size
        if end > len(data):
            break
        blocks.append(_Chunk(pos, size, b"", pos + 1, end, None))
        pos = end
    return tuple(blocks), None


def _gif_layout(data: bytes) -> _GifLayout | None:
    gct_end = _gif_gct_end(data)
    if gct_end is None:
        return None
    pos = gct_end
    for _ in range(64):
        if pos >= len(data):
            return None
        marker = data[pos]
        if marker == 0x3B:
            return None
        if marker == 0x21:
            pos += 2
            while pos < len(data):
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
                if pos > len(data):
                    return None
            continue
        if marker != 0x2C or pos + 10 > len(data):
            pos += 1
            continue
        lzw_offset = pos + 10
        if lzw_offset >= len(data):
            return None
        sub_start = lzw_offset + 1
        blocks, terminator = _gif_sub_blocks(data, sub_start)
        return _GifLayout(pos, lzw_offset, sub_start, blocks, terminator)
    return None


def _gif_mutate_size(data: bytes, layout: _GifLayout | None, rng: ImageRng) -> bytes:
    if layout is None or not layout.sub_blocks:
        return _fallback(data, rng, len(data))
    block = rng.choice(layout.sub_blocks)
    out = bytearray(data)
    remaining = max(1, len(data) - block.offset)
    values = [0, 1, 2, 3, 255, block.length - 1, block.length + 1]
    values.extend(rng.randrange(0, min(256, remaining + 1)) for _ in range(2))
    out[block.offset] = rng.choice(values) & 0xFF
    return bytes(out)


def _gif_mutate_type(data: bytes, rng: ImageRng) -> bytes:
    if len(data) < 6 or not data.startswith(GIF_MAGIC):
        return _fallback(data, rng, len(data))
    out = bytearray(data)
    out[0:6] = rng.choice(GIF_MAGIC)
    return bytes(out)


def _gif_mutate_field(data: bytes, layout: _GifLayout | None, rng: ImageRng) -> bytes:
    if len(data) < 13:
        return _fallback(data, rng, len(data))
    out = bytearray(data)
    field = rng.choice(("width", "height", "packed", "bg", "aspect", "lzw"))
    if field == "width":
        current = _read_u16(data, 6, "little")
        _write_u16(out, 6, rng.choice([0, 1, 2, 0xFFFF, current - 1, current + 1]), "little")
    elif field == "height":
        current = _read_u16(data, 8, "little")
        _write_u16(out, 8, rng.choice([0, 1, 2, 0xFFFF, current - 1, current + 1]), "little")
    elif field == "packed":
        out[10] = rng.choice((0x00, 0x80, 0x87, 0xF7, 0xFF))
    elif field == "bg":
        out[11] = rng.randrange(0, 256)
    elif field == "aspect":
        out[12] = rng.randrange(0, 256)
    elif layout is not None and layout.lzw_offset < len(out):
        out[layout.lzw_offset] = rng.choice((0, 1, 2, 7, 8, 11, 12, 255))
    else:
        return _fallback(data, rng, len(data))
    return bytes(out)


def _gif_insert(data: bytes, layout: _GifLayout | None, rng: ImageRng) -> bytes:
    if layout is None:
        return _fallback(data, rng, len(data))
    boundary = layout.terminator_offset if layout.terminator_offset is not None else len(data)
    payload = rng.randbytes(rng.randrange(0, 17))
    inserted = bytes((len(payload),)) + payload
    out = data[:boundary] + inserted + data[boundary:]
    return _bounded(out, len(data) + len(inserted))


def _gif_delete(data: bytes, layout: _GifLayout | None, rng: ImageRng) -> bytes:
    if layout is None or not layout.sub_blocks:
        return _fallback(data, rng, len(data))
    block = rng.choice(layout.sub_blocks)
    out = data[: block.offset] + data[block.end :]
    if len(out) < 13:
        return data[:13]
    return out


def _gif_comment_insert(data: bytes, layout: _GifLayout | None, rng: ImageRng) -> bytes:
    if layout is None:
        return _fallback(data, rng, len(data))
    payload = rng.randbytes(rng.randrange(0, 32))
    inserted = b"\x21\xfe" + bytes((len(payload),)) + payload + b"\x00"
    boundary = layout.image_sep_offset
    out = data[:boundary] + inserted + data[boundary:]
    return _bounded(out, len(data) + len(inserted))


def mutate_gif(data: bytes, strategy: str, rng: ImageRng, *, max_bytes: int) -> bytes:
    """Apply a structure-aware GIF mutation."""
    if len(data) < 6 or not data.startswith(GIF_MAGIC):
        return _fallback(data, rng, max_bytes)
    if strategy == "image_structure":
        return mutate_gif(data, str(rng.choice(_STRUCTURE_OPS)), rng, max_bytes=max_bytes)
    layout = _gif_layout(data)
    if strategy == "box_size":
        out = _gif_mutate_size(data, layout, rng)
    elif strategy == "box_type":
        out = _gif_mutate_type(data, rng)
    elif strategy == "box_field":
        out = _gif_mutate_field(data, layout, rng)
    elif strategy == "box_insert":
        out = _gif_insert(data, layout, rng)
    elif strategy == "box_delete":
        out = _gif_delete(data, layout, rng)
    elif strategy == "box_nest":
        out = _gif_comment_insert(data, layout, rng)
    else:
        return _fallback(data, rng, max_bytes)
    return _bounded(out, max_bytes)


def mutate_bmp(data: bytes, strategy: str, rng: ImageRng, *, max_bytes: int) -> bytes:
    """Apply a structure-aware BMP header/pixel mutation."""
    if len(data) < 26 or not data.startswith(BMP_MAGIC):
        return _fallback(data, rng, max_bytes)
    if strategy == "image_structure":
        return mutate_bmp(data, str(rng.choice(_STRUCTURE_OPS)), rng, max_bytes=max_bytes)
    out = bytearray(data)
    if strategy == "box_size":
        targets = [2, 10, 14]
        if len(out) >= 38:
            targets.append(34)
        target = rng.choice([offset for offset in targets if offset + 4 <= len(out)])
        if not targets:
            return _fallback(data, rng, max_bytes)
        current = _read_u32(bytes(out), target, "little")
        value = rng.choice([0, 1, 14, 26, 40, 54, 0xFFFFFFFF, current - 1, current + 1])
        _write_u32(out, target, value, "little")
    elif strategy == "box_type":
        out[0:2] = rng.choice((BMP_MAGIC, b"BA", b"CI", b"CP", b"IC", b"PT"))
    elif strategy == "box_field":
        fields = ["pixel_offset", "width", "height", "planes", "bpp", "compression"]
        field = rng.choice([name for name in fields if _bmp_field_available(out, name)])
        _bmp_mutate_field(out, field, rng)
    elif strategy == "box_insert":
        pixel_offset = _read_u32(bytes(out), 10, "little") if len(out) >= 14 else len(out)
        if not 26 <= pixel_offset < len(out):
            return _fallback(data, rng, max_bytes)
        inserted = rng.randbytes(rng.randrange(1, 17))
        result = bytes(out[:pixel_offset]) + inserted + bytes(out[pixel_offset:])
        return _bounded(result, max_bytes)
    elif strategy == "box_delete":
        pixel_offset = _read_u32(bytes(out), 10, "little") if len(out) >= 14 else len(out)
        if not 26 <= pixel_offset < len(out):
            return _fallback(data, rng, max_bytes)
        delete_len = rng.randrange(1, min(32, len(out) - pixel_offset) + 1)
        result = bytes(out[:pixel_offset]) + bytes(out[pixel_offset + delete_len :])
        return _bounded(result, max_bytes)
    elif strategy == "box_nest":
        return mutate_bmp(data, "box_insert", rng, max_bytes=max_bytes)
    else:
        return _fallback(data, rng, max_bytes)
    return _bounded(bytes(out), max_bytes)


def _bmp_field_available(out: bytearray, field: str) -> bool:
    required = {
        "pixel_offset": 14,
        "width": 22,
        "height": 26,
        "planes": 28,
        "bpp": 30,
        "compression": 34,
    }[field]
    return len(out) >= required


def _bmp_mutate_field(out: bytearray, field: str, rng: ImageRng) -> None:
    if field == "pixel_offset":
        current = _read_u32(bytes(out), 10, "little")
        _write_u32(out, 10, rng.choice([26, 54, 0, 1, 0xFFFFFFFF, current - 1, current + 1]), "little")
    elif field == "width":
        current = int.from_bytes(out[18:22], "little", signed=True)
        value = rng.choice([0, 1, 2, -1, 0x7FFFFFFF, current - 1, current + 1])
        out[18:22] = (value & 0xFFFFFFFF).to_bytes(4, "little")
    elif field == "height":
        current = int.from_bytes(out[22:26], "little", signed=True)
        value = rng.choice([0, 1, 2, -1, 0x7FFFFFFF, current - 1, current + 1])
        out[22:26] = (value & 0xFFFFFFFF).to_bytes(4, "little")
    elif field == "planes":
        _write_u16(out, 26, rng.choice([0, 1, 2, 4, 255]), "little")
    elif field == "bpp":
        _write_u16(out, 28, rng.choice([0, 1, 4, 8, 16, 24, 32, 255]), "little")
    else:
        current = _read_u32(bytes(out), 30, "little")
        _write_u32(out, 30, rng.choice([0, 1, 2, 3, 4, 5, 0xFFFFFFFF, current - 1, current + 1]), "little")


def _tiff_endian(data: bytes) -> _Endian | None:
    if data.startswith(b"II*\x00"):
        return "little"
    if data.startswith(b"MM\x00*"):
        return "big"
    return None


def _tiff_layout(data: bytes) -> tuple[_Endian, int, int, list[_TiffEntry], int | None] | None:
    endian = _tiff_endian(data)
    if endian is None or len(data) < 8:
        return None
    ifd_offset = _read_u32(data, 4, endian)
    if ifd_offset + 2 > len(data):
        return None
    count = _read_u16(data, ifd_offset, endian)
    entries: list[_TiffEntry] = []
    entry_offset = ifd_offset + 2
    for _ in range(min(count, 64)):
        if entry_offset + 12 > len(data):
            break
        tag = _read_u16(data, entry_offset, endian)
        type_ = _read_u16(data, entry_offset + 2, endian)
        entry_count = _read_u32(data, entry_offset + 4, endian)
        entries.append(_TiffEntry(entry_offset, tag, type_, entry_count, entry_offset + 8))
        entry_offset += 12
    next_offset = None
    next_at = ifd_offset + 2 + count * 12
    if next_at + 4 <= len(data):
        next_offset = _read_u32(data, next_at, endian)
    return endian, ifd_offset, count, entries, next_offset


def _tiff_mutate_size(data: bytes, layout: tuple[_Endian, int, int, list[_TiffEntry], int | None] | None, rng: ImageRng) -> bytes:
    if layout is None:
        return _fallback(data, rng, len(data))
    endian, ifd_offset, count, entries, next_offset = layout
    out = bytearray(data)
    targets = ["ifd_offset", "count"]
    if next_offset is not None:
        targets.append("next_ifd")
    if entries:
        targets.append("value")
    target = rng.choice(targets)
    if target == "ifd_offset":
        value = rng.choice([0, 1, 2, 4, 6, 8, 0x7FFFFFFF, 0xFFFFFFFF])
        _write_u32(out, 4, value, endian)
    elif target == "count":
        value = rng.choice([0, 1, 2, 10, 64, 255, 256, 0xFFFF])
        _write_u16(out, ifd_offset, value, endian)
    elif target == "next_ifd":
        next_at = ifd_offset + 2 + count * 12
        if next_at + 4 <= len(out):
            value = rng.choice([0, 1, 4, 8, 0x7FFFFFFF, 0xFFFFFFFF])
            _write_u32(out, next_at, value, endian)
        else:
            return _fallback(data, rng, len(data))
    else:
        entry = rng.choice(entries)
        value = rng.choice([0, 1, 2, 8, 0x7FFFFFFF, 0xFFFFFFFF])
        _write_u32(out, entry.value_offset, value, endian)
    return bytes(out)


def _tiff_mutate_type(data: bytes, rng: ImageRng) -> bytes:
    if _tiff_endian(data) is None or len(data) < 4:
        return _fallback(data, rng, len(data))
    out = bytearray(data)
    if rng.randbelow(2) == 0:
        out[0:2] = b"MM" if data.startswith(b"II") else b"II"
    else:
        magic = rng.choice([0, 1, 42, 43, 0xFFFF])
        endian: _Endian = "little" if data.startswith(b"II") else "big"
        _write_u16(out, 2, magic, endian)
    return bytes(out)


def _tiff_mutate_field(data: bytes, layout: tuple[_Endian, int, int, list[_TiffEntry], int | None] | None, rng: ImageRng) -> bytes:
    if layout is None:
        return _fallback(data, rng, len(data))
    endian, _, _, entries, _ = layout
    if not entries:
        return _fallback(data, rng, len(data))
    entry = rng.choice(entries)
    out = bytearray(data)
    field = rng.choice(("tag", "type", "count", "value"))
    if field == "tag":
        _write_u16(out, entry.offset, rng.choice(TIFF_TAGS), endian)
    elif field == "type":
        _write_u16(out, entry.offset + 2, rng.choice(TIFF_TYPES), endian)
    elif field == "count":
        value = rng.choice([0, 1, 2, 3, 4, 0x7FFFFFFF, 0xFFFFFFFF])
        _write_u32(out, entry.offset + 4, value, endian)
    else:
        out[entry.value_offset : entry.value_offset + 4] = rng.randbytes(4)
    return bytes(out)


def _tiff_insert(data: bytes, layout: tuple[_Endian, int, int, list[_TiffEntry], int | None] | None, rng: ImageRng) -> bytes:
    if layout is None:
        return _fallback(data, rng, len(data))
    _, ifd_offset, _, _, _ = layout
    if ifd_offset + 2 > len(data):
        return _fallback(data, rng, len(data))
    inserted = rng.randbytes(12)
    boundary = ifd_offset + 2
    out = data[:boundary] + inserted + data[boundary:]
    return _bounded(out, len(data) + len(inserted))


def _tiff_delete(data: bytes, layout: tuple[_Endian, int, int, list[_TiffEntry], int | None] | None, rng: ImageRng) -> bytes:
    if layout is None:
        return _fallback(data, rng, len(data))
    _, _, _, entries, _ = layout
    if entries:
        entry = rng.choice(entries)
        start = entry.offset
    else:
        _, ifd_offset, _, _, _ = layout
        start = ifd_offset + 2
    if start + 12 > len(data):
        return _fallback(data, rng, len(data))
    out = data[:start] + data[start + 12 :]
    if len(out) < 8:
        return data[:8]
    return out


def mutate_tiff(data: bytes, strategy: str, rng: ImageRng, *, max_bytes: int) -> bytes:
    """Apply a structure-aware TIFF header/IFD mutation."""
    if _tiff_endian(data) is None or len(data) < 8:
        return _fallback(data, rng, max_bytes)
    if strategy == "image_structure":
        return mutate_tiff(data, str(rng.choice(_STRUCTURE_OPS)), rng, max_bytes=max_bytes)
    layout = _tiff_layout(data)
    if strategy == "box_size":
        out = _tiff_mutate_size(data, layout, rng)
    elif strategy == "box_type":
        out = _tiff_mutate_type(data, rng)
    elif strategy == "box_field":
        out = _tiff_mutate_field(data, layout, rng)
    elif strategy == "box_insert":
        out = _tiff_insert(data, layout, rng)
    elif strategy == "box_delete":
        out = _tiff_delete(data, layout, rng)
    elif strategy == "box_nest":
        out = _tiff_insert(data, layout, rng)
    else:
        return _fallback(data, rng, max_bytes)
    return _bounded(out, max_bytes)


def _riff_chunks(data: bytes) -> list[_Chunk]:
    chunks: list[_Chunk] = []
    if len(data) < 12 or data[:4] != RIFF_MAGIC or data[8:12] != WEBP_MAGIC:
        return chunks
    pos = 12
    while pos + 8 <= len(data) and len(chunks) < 64:
        kind = data[pos : pos + 4]
        size = _read_u32(data, pos + 4, "little")
        data_offset = pos + 8
        pad = size % 2
        declared_end = pos + 8 + size + pad
        if declared_end > len(data):
            chunks.append(_Chunk(pos, size, kind, data_offset, len(data), None))
            break
        chunks.append(_Chunk(pos, size, kind, data_offset, declared_end, None))
        pos = declared_end
    return chunks


def _riff_chunk_bytes(kind: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if len(payload) % 2 else b""
    return kind + len(payload).to_bytes(4, "little") + payload + pad


def _webp_update_riff_size(out: bytearray) -> None:
    if len(out) >= 8:
        _write_u32(out, 4, max(0, len(out) - 8), "little")


def _webp_mutate_size(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    out = bytearray(data)
    if chunks and rng.randbelow(4) == 0:
        _write_u32(out, 4, rng.choice([0, 1, 4, len(data) - 9, len(data) - 8, 0xFFFFFFFF]), "little")
        return bytes(out)
    candidates = [chunk for chunk in chunks if chunk.end <= len(data)] or chunks
    if not candidates:
        return _fallback(data, rng, len(data))
    chunk = rng.choice(candidates)
    current = chunk.length
    values = [0, 1, 2, 4, 8, current - 1, current + 1, 0xFFFFFFFF]
    values.extend(rng.randrange(0, max(1, len(data) - chunk.offset)) for _ in range(2))
    _write_u32(out, chunk.offset + 4, rng.choice(values) & 0xFFFFFFFF, "little")
    return bytes(out)


def _webp_mutate_type(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    out = bytearray(data)
    candidates = [chunk for chunk in chunks if chunk.end <= len(data)]
    if candidates and rng.randbelow(4) != 0:
        chunk = rng.choice(candidates)
        out[chunk.offset : chunk.offset + 4] = rng.choice(WEBP_CHUNK_TYPES)
    elif len(out) >= 12:
        out[8:12] = rng.choice((WEBP_MAGIC, b"WAVE", b"AVI "))
    else:
        return _fallback(data, rng, len(data))
    return bytes(out)


def _webp_mutate_field(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    vp8x = next((chunk for chunk in chunks if chunk.kind == b"VP8X" and chunk.length >= 10), None)
    if vp8x is None:
        return _fallback(data, rng, len(data))
    out = bytearray(data)
    base = vp8x.data_offset
    if base + 10 > len(out):
        return _fallback(data, rng, len(data))
    field = rng.choice(("flags", "width", "height", "reserved"))
    if field == "flags":
        out[base] = rng.randrange(0, 256)
    elif field == "reserved":
        out[base + 1 : base + 4] = rng.randbytes(3)
    elif field == "width":
        value = rng.randrange(0, 1 << 24)
        out[base + 4 : base + 7] = value.to_bytes(3, "little")
    else:
        value = rng.randrange(0, 1 << 24)
        out[base + 7 : base + 10] = value.to_bytes(3, "little")
    return bytes(out)


def _webp_boundaries(chunks: list[_Chunk], data_len: int) -> list[int]:
    boundaries = {12, data_len}
    boundaries.update(chunk.end for chunk in chunks if chunk.end <= data_len)
    return sorted(boundary for boundary in boundaries if 12 <= boundary <= data_len)


def _webp_insert(data: bytes, chunks: list[_Chunk], rng: ImageRng, *, meta: bool) -> bytes:
    boundaries = _webp_boundaries(chunks, len(data))
    if not boundaries:
        return _fallback(data, rng, len(data))
    boundary = len(data) if meta else rng.choice(boundaries)
    kind = rng.choice(WEBP_META_TYPES if meta else WEBP_CHUNK_TYPES)
    payload = rng.randbytes(rng.randrange(0, 25))
    inserted = _riff_chunk_bytes(kind, payload)
    out = bytearray(data[:boundary] + inserted + data[boundary:])
    _webp_update_riff_size(out)
    return _bounded(bytes(out), len(data) + len(inserted))


def _webp_delete(data: bytes, chunks: list[_Chunk], rng: ImageRng) -> bytes:
    candidates = [chunk for chunk in chunks if chunk.end <= len(data) and chunk.end > chunk.offset]
    if not candidates:
        return _fallback(data, rng, len(data))
    chunk = rng.choice(candidates)
    out = bytearray(data[: chunk.offset] + data[chunk.end :])
    _webp_update_riff_size(out)
    if len(out) < 12:
        return data[:12]
    return bytes(out)


def mutate_webp(data: bytes, strategy: str, rng: ImageRng, *, max_bytes: int) -> bytes:
    """Apply a structure-aware RIFF/WebP chunk mutation."""
    if len(data) < 12 or data[:4] != RIFF_MAGIC or data[8:12] != WEBP_MAGIC:
        return _fallback(data, rng, max_bytes)
    if strategy == "image_structure":
        return mutate_webp(data, str(rng.choice(_STRUCTURE_OPS)), rng, max_bytes=max_bytes)
    chunks = _riff_chunks(data)
    if strategy == "box_size":
        out = _webp_mutate_size(data, chunks, rng)
    elif strategy == "box_type":
        out = _webp_mutate_type(data, chunks, rng)
    elif strategy == "box_field":
        out = _webp_mutate_field(data, chunks, rng)
    elif strategy == "box_insert":
        out = _webp_insert(data, chunks, rng, meta=False)
    elif strategy == "box_delete":
        out = _webp_delete(data, chunks, rng)
    elif strategy == "box_nest":
        out = _webp_insert(data, chunks, rng, meta=True)
    else:
        return _fallback(data, rng, max_bytes)
    return _bounded(out, max_bytes)


def mutate_image_structure(
    data: bytes,
    image_format: str | None,
    strategy: str,
    rng: ImageRng,
    *,
    max_bytes: int,
) -> bytes:
    """Dispatch a structure-aware mutation for non-HEIF image formats."""
    detected = image_format or detect_image_format(data)
    if detected == "png":
        return mutate_png(data, strategy, rng, max_bytes=max_bytes)
    if detected == "jpeg":
        return mutate_jpeg(data, strategy, rng, max_bytes=max_bytes)
    if detected == "gif":
        return mutate_gif(data, strategy, rng, max_bytes=max_bytes)
    if detected == "bmp":
        return mutate_bmp(data, strategy, rng, max_bytes=max_bytes)
    if detected == "tiff":
        return mutate_tiff(data, strategy, rng, max_bytes=max_bytes)
    if detected == "webp":
        return mutate_webp(data, strategy, rng, max_bytes=max_bytes)
    return _bounded(data, max_bytes)
