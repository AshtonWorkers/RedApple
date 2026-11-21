"""Async dyld shared-cache reader for RA-SRF-001.

Parsing helpers are synchronous and pure; every file read is `async def` and runs
through an executor so the module satisfies RA-REP-003.
"""

from __future__ import annotations

import asyncio
import os
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAGIC = b"dyld_v1"
HEADER_SIZE = 0x400
MAPPING_OFFSET = 0x10
MAPPING_COUNT = 0x14
IMAGES_OFFSET = 0x1C0
IMAGES_COUNT = 0x1C4

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF
SECTION_64_SIZE = 80
SEGMENT_64_HEADER_SIZE = 72

STRING_SECTION_NAMES = frozenset({"__cstring", "__oslogstring", "__ustring"})
PROFILE_SCAN_SECTION_NAMES = frozenset({"__const", "__cstring", "__oslogstring", "__ustring"})
MAX_SECTION_BYTES = 96 * 1024 * 1024
MAX_STRING_BYTES = 1024 * 1024
MAX_LOAD_COMMAND_BYTES = 16 * 1024 * 1024


class CacheError(RuntimeError):
    pass


@dataclass(frozen=True)
class CacheMapping:
    file_index: int
    va_start: int
    va_end: int
    file_offset: int
    max_prot: int
    init_prot: int


@dataclass(frozen=True)
class MachOSection:
    segment: str
    name: str
    addr: int
    size: int
    flags: int

    @property
    def key(self) -> tuple[str, str]:
        return (self.segment, self.name)


@dataclass(frozen=True)
class MachOImage:
    address: int
    path: str
    filetype: int
    flags: int
    sections: tuple[MachOSection, ...]


class _CacheFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.name = path.name
        self._fd: int | None = None
        self.size = 0

    async def open(self) -> None:
        def _open() -> int:
            fd = os.open(str(self.path), os.O_RDONLY)
            try:
                self.size = os.fstat(fd).st_size
            except Exception:
                os.close(fd)
                raise
            return fd

        self._fd = await asyncio.get_running_loop().run_in_executor(None, _open)

    async def read_at(self, offset: int, size: int) -> bytes:
        if self._fd is None:
            raise CacheError(f"cache file is closed: {self.path}")
        if offset < 0 or size < 0 or offset + size > self.size:
            raise CacheError(f"read out of range: {self.path} @{offset:#x}+{size:#x}")
        if size == 0:
            return b""

        def _read() -> bytes:
            assert self._fd is not None
            return os.pread(self._fd, size, offset)

        data = await asyncio.get_running_loop().run_in_executor(None, _read)
        if len(data) != size:
            raise CacheError(f"short read: {self.path} @{offset:#x}+{size:#x}")
        return data

    async def close(self) -> None:
        if self._fd is not None:
            fd = self._fd
            self._fd = None

            def _close() -> None:
                os.close(fd)

            await asyncio.get_running_loop().run_in_executor(None, _close)

    async def __aenter__(self) -> _CacheFile:
        await self.open()
        return self

    async def __aexit__(
        self, exc_type: type | None, exc: BaseException | None, tb: Any | None
    ) -> None:
        await self.close()


def _u32(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", buf, off)[0])


def _u64(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<Q", buf, off)[0])


@dataclass(frozen=True)
class _Header:
    mapping_offset: int
    mapping_count: int
    images_offset: int
    images_count: int


def _parse_header(buf: bytes) -> _Header:
    if len(buf) < HEADER_SIZE:
        raise CacheError("short dyld cache header")
    if not buf.startswith(MAGIC):
        raise CacheError("not a dyld shared cache")
    return _Header(
        mapping_offset=_u32(buf, MAPPING_OFFSET),
        mapping_count=_u32(buf, MAPPING_COUNT),
        images_offset=_u32(buf, IMAGES_OFFSET),
        images_count=_u32(buf, IMAGES_COUNT),
    )


def _parse_mapping(rec: bytes, file_index: int) -> CacheMapping:
    address, size, file_offset, max_prot, init_prot = struct.unpack("<QQQII", rec)
    return CacheMapping(
        file_index=file_index,
        va_start=address,
        va_end=address + size,
        file_offset=file_offset,
        max_prot=max_prot,
        init_prot=init_prot,
    )


def parse_macho(data: bytes, image_va: int) -> MachOImage:
    """Pure Mach-O 64 parser for one image's header+load commands."""
    if len(data) < 32:
        raise CacheError("short Mach-O header")
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
        "<IIIIIIII", data[:32]
    )
    if magic != MH_MAGIC_64:
        raise CacheError(f"bad Mach-O magic {magic:#x} at {image_va:#x}")
    need = 32 + sizeofcmds
    if len(data) < need:
        raise CacheError(f"short Mach-O load commands at {image_va:#x}")
    sections: list[MachOSection] = []
    off = 32
    for _ in range(ncmds):
        if off + 8 > need:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > need:
            break
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8 : off + 24].split(b"\0", 1)[0].decode("utf-8", "replace")
            nsects = _u32(data, off + 64)
            so = off + SEGMENT_64_HEADER_SIZE
            for _si in range(nsects):
                if so + SECTION_64_SIZE > off + cmdsize:
                    break
                sectname = data[so : so + 16].split(b"\0", 1)[0].decode("utf-8", "replace")
                sect_seg = data[so + 16 : so + 32].split(b"\0", 1)[0].decode("utf-8", "replace")
                addr = _u64(data, so + 32)
                size = _u64(data, so + 40)
                sect_flags = _u32(data, so + 64)
                sections.append(
                    MachOSection(
                        segment=sect_seg or segname,
                        name=sectname,
                        addr=addr,
                        size=size,
                        flags=sect_flags,
                    )
                )
                so += SECTION_64_SIZE
        off += cmdsize
    return MachOImage(
        address=image_va, path="", filetype=filetype, flags=flags, sections=tuple(sections)
    )


def split_strings(data: bytes, *, max_len: int = MAX_STRING_BYTES) -> list[str]:
    """Deterministic NUL-separated string extraction."""
    out: list[str] = []
    for part in data.split(b"\0"):
        if not part or len(part) > max_len:
            continue
        try:
            s = part.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s and all((32 <= ord(c) < 127) or c in "\t\n\r" for c in s):
            out.append(s)
    return out


def _utf16_strings(data: bytes, encoding: str, max_len: int) -> list[str]:
    text = data.decode(encoding, "ignore")
    out: list[str] = []
    for part in text.split("\x00"):
        if not part or len(part) > max_len:
            continue
        if all((32 <= ord(c) < 127) or c in "\t\n\r" for c in part):
            out.append(part)
    return out


def split_utf16_strings(data: bytes, *, max_len: int = MAX_STRING_BYTES) -> list[str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return _utf16_strings(data, "utf-16", max_len)
    little = _utf16_strings(data, "utf-16-le", max_len)
    big = _utf16_strings(data, "utf-16-be", max_len)
    return little if len(little) >= len(big) else big


class DyldCache:
    """Opened dyld shared cache (main file plus subcache siblings)."""

    def __init__(
        self,
        files: Sequence[_CacheFile],
        headers: Sequence[_Header],
        mappings: Sequence[CacheMapping],
        images: Sequence[MachOImage],
    ) -> None:
        self.files = list(files)
        self.headers = list(headers)
        self.mappings = sorted(mappings, key=lambda m: (m.va_start, m.file_index, m.file_offset))
        self.images = sorted(images, key=lambda im: (im.path, im.address))
        self.path = str(self.files[0].path) if self.files else ""

    @classmethod
    async def open(cls, path: str | Path) -> DyldCache:
        root = Path(path)
        candidates = _cache_candidates(root)
        files: list[_CacheFile] = []
        headers: list[_Header] = []
        try:
            for cand in candidates:
                cf = _CacheFile(cand)
                await cf.open()
                if cf.size < HEADER_SIZE:
                    await cf.close()
                    continue
                head = await cf.read_at(0, HEADER_SIZE)
                if not head.startswith(MAGIC):
                    await cf.close()
                    continue
                files.append(cf)
                headers.append(_parse_header(head))
            if not files:
                raise CacheError(f"no dyld shared cache found at {root}")
            mappings: list[CacheMapping] = []
            for idx, cf in enumerate(files):
                h = headers[idx]
                if h.mapping_count and h.mapping_offset:
                    recs = await cf.read_at(h.mapping_offset, 32 * h.mapping_count)
                    for i in range(h.mapping_count):
                        mappings.append(_parse_mapping(recs[i * 32 : (i + 1) * 32], idx))
            images = await _load_images(files, mappings)
            return cls(files, headers, mappings, images)
        except Exception:
            for cf in files:
                await cf.close()
            raise

    async def read_va(self, va: int, size: int) -> bytes:
        return await _read_va(self.files, self.mappings, va, size)

    async def read_cstr_va(self, va: int, limit: int = 4096) -> str:
        size = limit
        for mapping in self.mappings:
            if mapping.va_start <= va < mapping.va_end:
                size = min(limit, mapping.va_end - va)
                break
        else:
            raise CacheError(f"VA {va:#x} is not mapped")
        data = await self.read_va(va, size)
        end = data.find(b"\0")
        if end >= 0:
            data = data[:end]
        return data.decode("utf-8", "replace")

    async def section_bytes(self, image: MachOImage, section: MachOSection) -> bytes:
        if section.size <= 0 or section.size > MAX_SECTION_BYTES:
            return b""
        return await self.read_va(section.addr, section.size)

    async def image_strings(
        self,
        image: MachOImage,
        names: Iterable[str] = STRING_SECTION_NAMES,
    ) -> list[str]:
        wanted = set(names)
        out: list[str] = []
        for section in image.sections:
            if section.name not in wanted or section.size <= 0 or section.size > MAX_SECTION_BYTES:
                continue
            data = await self.section_bytes(image, section)
            if section.name == "__ustring":
                out.extend(split_utf16_strings(data))
            else:
                out.extend(split_strings(data))
        return out

    async def close(self) -> None:
        for cf in self.files:
            await cf.close()

    async def __aenter__(self) -> DyldCache:
        return self

    async def __aexit__(
        self, exc_type: type | None, exc: BaseException | None, tb: Any | None
    ) -> None:
        await self.close()


def _native_cache_arch() -> str:
    machine = os.uname().machine.lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64e"
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    return ""


def _family_paths(directory: Path, stem: str) -> list[Path]:
    paths = [p for p in directory.glob(stem) if p.is_file()]
    paths += [p for p in directory.glob(stem + ".*") if p.is_file()]
    return sorted(paths)


def _cache_candidates(root: Path) -> list[Path]:
    if root.is_file():
        stem = root.name.split(".", 1)[0]
        return _family_paths(root.parent, stem)
    arch = _native_cache_arch()
    if arch:
        paths = _family_paths(root, f"dyld_shared_cache_{arch}")
        if paths:
            return paths
    return sorted(p for p in root.glob("dyld_shared_cache*") if p.is_file())


async def _read_va(
    files: Sequence[_CacheFile], mappings: Sequence[CacheMapping], va: int, size: int
) -> bytes:
    if size < 0:
        raise CacheError("negative read size")
    if size == 0:
        return b""
    for m in mappings:
        if m.va_start <= va and va + size <= m.va_end:
            off = m.file_offset + (va - m.va_start)
            return await files[m.file_index].read_at(off, size)
    raise CacheError(f"VA {va:#x}+{size:#x} is not mapped")


async def _load_images(
    files: Sequence[_CacheFile], mappings: Sequence[CacheMapping]
) -> list[MachOImage]:
    images: list[MachOImage] = []
    headers_by_file = [
        _parse_header(await files[idx].read_at(0, HEADER_SIZE)) for idx in range(len(files))
    ]
    for idx, h in enumerate(headers_by_file):
        if h.images_count == 0 or h.images_offset == 0:
            continue
        cf = files[idx]
        table = await cf.read_at(h.images_offset, 32 * h.images_count)
        for i in range(h.images_count):
            rec = table[i * 32 : (i + 1) * 32]
            address, _mod_time, _inode, path_off, _pad = struct.unpack("<QQQII", rec)
            if address == 0:
                continue
            path_size = min(4096, max(0, cf.size - path_off))
            path_bytes = await cf.read_at(path_off, path_size) if path_size else b""
            end = path_bytes.find(b"\0")
            if end >= 0:
                path_bytes = path_bytes[:end]
            path = path_bytes.decode("utf-8", "replace")
            hdr = await _read_va(files, mappings, address, 32)
            sizeofcmds = _u32(hdr, 20)
            if sizeofcmds > MAX_LOAD_COMMAND_BYTES:
                raise CacheError(f"Mach-O load commands too large at {address:#x}")
            cmds = await _read_va(files, mappings, address, 32 + sizeofcmds)
            image = parse_macho(cmds, address)
            images.append(
                MachOImage(
                    address=image.address,
                    path=path,
                    filetype=image.filetype,
                    flags=image.flags,
                    sections=image.sections,
                )
            )
    return images


async def mappings_for_cache(
    files: Sequence[_CacheFile], headers: Sequence[_Header]
) -> list[CacheMapping]:
    mappings: list[CacheMapping] = []
    for idx, h in enumerate(headers):
        if h.mapping_count and h.mapping_offset:
            recs = await files[idx].read_at(h.mapping_offset, 32 * h.mapping_count)
            for i in range(h.mapping_count):
                mappings.append(_parse_mapping(recs[i * 32 : (i + 1) * 32], idx))
    return mappings
