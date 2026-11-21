"""Synthetic dyld shared-cache fixtures for RA-SRF tests."""

from __future__ import annotations

import struct
from collections.abc import Sequence
from pathlib import Path

from ra.srf.dyld import IMAGES_COUNT, IMAGES_OFFSET, MAPPING_COUNT, MAPPING_OFFSET

VA_BASE = 0x100000000
LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF

SectionSpec = tuple[str, str, bytes]
ImageSpec = tuple[str, Sequence[SectionSpec]]


def _align(value: int, alignment: int = 0x100) -> int:
    return (value + alignment - 1) // alignment * alignment


def _section_bytes(segment: str, name: str, addr: int, size: int) -> bytes:
    out = bytearray(80)
    out[0:16] = name.encode("utf-8").ljust(16, b"\0")[:16]
    out[16:32] = segment.encode("utf-8").ljust(16, b"\0")[:16]
    struct.pack_into("<QQI", out, 32, addr, size, 0)
    struct.pack_into("<I", out, 64, 0)
    return bytes(out)


def _macho(sections: Sequence[tuple[str, str, int, int]]) -> bytes:
    nsects = len(sections)
    sizeofcmds = 72 + 80 * nsects
    data = bytearray(32 + sizeofcmds)
    struct.pack_into(
        "<IIIIIIII",
        data,
        0,
        MH_MAGIC_64,
        0x100000C,
        0,
        6,
        1,
        sizeofcmds,
        0,
        0,
    )
    struct.pack_into("<II", data, 32, LC_SEGMENT_64, sizeofcmds)
    data[40:56] = b"__TEXT".ljust(16, b"\0")
    struct.pack_into("<QQQQIIII", data, 56, VA_BASE, 0x10000, 0, 0x10000, 7, 5, nsects, 0)
    for idx, (segment, name, addr, size) in enumerate(sections):
        off = 104 + idx * 80
        data[off : off + 80] = _section_bytes(segment, name, addr, size)
    return bytes(data)


def cstring(*parts: str) -> bytes:
    if not parts:
        return b""
    return b"\0".join(part.encode("utf-8") for part in parts) + b"\0"


def utf16le_cstring(*parts: str) -> bytes:
    out = bytearray()
    for part in parts:
        out.extend(part.encode("utf-16-le"))
        out.extend(b"\x00\x00")
    return bytes(out)


def utf16be_cstring(*parts: str) -> bytes:
    out = bytearray()
    for part in parts:
        out.extend(part.encode("utf-16-be"))
        out.extend(b"\x00\x00")
    return bytes(out)


def write_minimal_cache(path: Path, images: Sequence[ImageSpec]) -> Path:
    """Write a minimal single-mapping dyld cache containing `images`.

    Each image is `(path, sections)` where sections are `(segment, name, data)`.
    Section VAs are derived from file offsets in one mapping covering the file.
    """
    count = len(images)
    if count == 0:
        raise ValueError("at least one image is required")

    images_offset = 0x500
    path_area = _align(images_offset + 32 * count)
    path_size = 256
    macho_area = _align(path_area + path_size * count)
    macho_sizes = [32 + 72 + 80 * len(sections) for _path, sections in images]
    data_area = _align(macho_area + sum(macho_sizes))

    data_offsets: list[list[int]] = []
    offset = data_area
    for _path, sections in images:
        row: list[int] = []
        for _segment, _name, data in sections:
            offset = _align(offset, 16)
            row.append(offset)
            offset += len(data)
        data_offsets.append(row)
    file_size = offset

    buf = bytearray(file_size)
    buf[0:len(b"dyld_v1")] = b"dyld_v1"
    struct.pack_into("<I", buf, MAPPING_OFFSET, 0x400)
    struct.pack_into("<I", buf, MAPPING_COUNT, 1)
    struct.pack_into("<I", buf, IMAGES_OFFSET, images_offset)
    struct.pack_into("<I", buf, IMAGES_COUNT, count)
    struct.pack_into("<QQQII", buf, 0x400, VA_BASE, file_size, 0, 7, 5)

    macho_off = macho_area
    for idx, ((image_path, sections), offsets) in enumerate(zip(images, data_offsets, strict=True)):
        path_off = path_area + idx * path_size
        encoded_path = image_path.encode("utf-8") + b"\0"
        if len(encoded_path) > path_size:
            raise ValueError("image path is too long for fixture")
        struct.pack_into(
            "<QQQII",
            buf,
            images_offset + idx * 32,
            VA_BASE + macho_off,
            0,
            0,
            path_off,
            0,
        )
        buf[path_off : path_off + len(encoded_path)] = encoded_path
        macho_sections = [
            (segment, name, VA_BASE + data_off, len(data))
            for (segment, name, data), data_off in zip(sections, offsets, strict=True)
        ]
        macho = _macho(macho_sections)
        buf[macho_off : macho_off + len(macho)] = macho
        macho_off += len(macho)

    for (_path, sections), offsets in zip(images, data_offsets, strict=True):
        for (_segment, _name, data), data_off in zip(sections, offsets, strict=True):
            if data:
                buf[data_off : data_off + len(data)] = data

    path.write_bytes(bytes(buf))
    return path
