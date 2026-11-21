"""Dyld cache parsing unit tests (synthetic Mach-O bytes)."""

import asyncio
import os
import struct
from types import SimpleNamespace

import pytest

from ra.srf.dyld import (
    HEADER_SIZE,
    IMAGES_COUNT,
    MAX_LOAD_COMMAND_BYTES,
    MH_MAGIC_64,
    CacheError,
    DyldCache,
    MachOImage,
    MachOSection,
    _cache_candidates,
    _CacheFile,
    _native_cache_arch,
    _parse_header,
    mappings_for_cache,
    parse_macho,
    split_strings,
    split_utf16_strings,
)
from tests.unit.srf_cache import cstring, utf16le_cstring, write_minimal_cache


def _section(seg: str, name: str, addr: int, size: int) -> bytes:
    out = bytearray(80)
    out[0:16] = name.encode().ljust(16, b"\0")
    out[16:32] = seg.encode().ljust(16, b"\0")
    struct.pack_into("<QQI", out, 32, addr, size, 0)
    struct.pack_into("<I", out, 64, 0)
    return bytes(out)


def test_RA_SRF_001_parse_macho_sections():
    nsects = 1
    sizeofcmds = 72 + 80 * nsects
    data = bytearray(32 + sizeofcmds)
    struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x100000C, 0, 6, 1, sizeofcmds, 0, 0)
    struct.pack_into("<II", data, 32, 0x19, sizeofcmds)
    data[40:56] = b"__TEXT".ljust(16, b"\0")
    struct.pack_into("<QQQQIIII", data, 56, 0x1000, 0x1000, 0, 0x1000, 7, 5, nsects, 0)
    data[104:184] = _section("__TEXT", "__cstring", 0x2000, 16)
    image = parse_macho(bytes(data), 0x180000000)
    assert isinstance(image, MachOImage)
    assert image.filetype == 6
    assert image.sections == (MachOSection("__TEXT", "__cstring", 0x2000, 16, 0),)
    assert image.sections[0].key == ("__TEXT", "__cstring")


def test_RA_SRF_001_parse_macho_rejects_malformed_headers():
    with pytest.raises(CacheError, match="short Mach-O header"):
        parse_macho(b"\0" * 31, 0)
    with pytest.raises(CacheError, match="bad Mach-O magic"):
        parse_macho(b"\0" * 32, 0)
    data = bytearray(32)
    struct.pack_into("<IIIIIIII", data, 0, MH_MAGIC_64, 0, 0, 6, 1, 128, 0, 0)
    with pytest.raises(CacheError, match="short Mach-O load commands"):
        parse_macho(bytes(data), 0)


def test_RA_SRF_001_split_strings_is_deterministic():
    assert split_strings(b"alpha\0beta\0\0gamma\0") == ["alpha", "beta", "gamma"]
    assert split_strings("caf\u00e9".encode() + b"\0plain\0") == ["plain"]
    assert split_strings(b"\xff\xfe\0plain\0") == ["plain"]
    assert split_strings(b"x" * 11 + b"\0", max_len=10) == []


def test_RA_SRF_001_split_utf16_strings():
    assert split_utf16_strings("com.apple.foo".encode("utf-16-le") + b"\x00\x00") == [
        "com.apple.foo"
    ]
    assert split_utf16_strings("com.apple.foo".encode("utf-16-be") + b"\x00\x00") == [
        "com.apple.foo"
    ]
    assert split_utf16_strings("com.apple.foo".encode("utf-16") + b"\x00\x00") == [
        "com.apple.foo"
    ]
    assert split_utf16_strings("com.apple.foo".encode("utf-16-le") + b"\x00\x00", max_len=3) == []


def test_RA_SRF_001_synthetic_cache_open_strings_and_reads(tmp_path):
    cache_path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [
            (
                "/usr/lib/libSystem.dylib",
                [
                    ("__TEXT", "__cstring", cstring("com.apple.foo", "xpc_connection_create")),
                    ("__TEXT", "__ustring", utf16le_cstring("com.apple.bar")),
                    ("__TEXT", "__oslogstring", cstring("oslog marker")),
                ],
            )
        ],
    )

    async def exercise() -> None:
        async with await DyldCache.open(cache_path) as cache:
            assert cache.path == str(cache_path)
            assert len(cache.images) == 1
            image = cache.images[0]
            assert image.path == "/usr/lib/libSystem.dylib"
            assert [s.name for s in image.sections] == ["__cstring", "__ustring", "__oslogstring"]
            strings = await cache.image_strings(image)
            assert "com.apple.foo" in strings
            assert "com.apple.bar" in strings
            assert "oslog marker" in strings
            assert await cache.read_cstr_va(image.sections[0].addr, 20) == "com.apple.foo"
            empty = MachOSection("__TEXT", "__cstring", 0, 0, 0)
            assert await cache.section_bytes(image, empty) == b""
            assert await cache.read_va(image.sections[0].addr, 0) == b""
            assert await mappings_for_cache(cache.files, cache.headers) == cache.mappings
            fake = MachOImage(
                address=0,
                path="/fake",
                filetype=6,
                flags=0,
                sections=(
                    MachOSection("__TEXT", "__cstring", 0, 0, 0),
                    MachOSection("__TEXT", "__text", 1, 10, 0),
                ),
            )
            assert await cache.image_strings(fake, names={"__cstring"}) == []
            with pytest.raises(CacheError, match="negative read size"):
                await cache.read_va(image.sections[0].addr, -1)
            with pytest.raises(CacheError, match="is not mapped"):
                await cache.read_va(0xDEADBEEF, 1)
            with pytest.raises(CacheError, match="is not mapped"):
                await cache.read_cstr_va(0xDEADBEEF)

    asyncio.run(exercise())


def test_RA_SRF_001_cache_close_makes_reads_fail(tmp_path):
    cache_path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring("com.apple.foo"))])],
    )

    async def exercise() -> None:
        cache = await DyldCache.open(cache_path)
        await cache.close()
        with pytest.raises(CacheError, match="cache file is closed"):
            await cache.files[0].read_at(0, 1)

    asyncio.run(exercise())


def test_RA_SRF_001_cache_open_skips_non_cache_and_short_files(tmp_path):
    bad = tmp_path / "dyld_shared_cache_arm64e"
    bad.write_bytes(b"not-a-cache" + b"\0" * (HEADER_SIZE - len(b"not-a-cache")))
    with pytest.raises(CacheError, match="no dyld shared cache found"):
        asyncio.run(DyldCache.open(bad))

    short = tmp_path / "dyld_shared_cache_arm64e"
    short.write_bytes(b"dyld_v1" + b"\0" * 32)
    with pytest.raises(CacheError, match="no dyld shared cache found"):
        asyncio.run(DyldCache.open(short))


def test_RA_SRF_001_load_command_size_is_bounded(tmp_path):
    cache_path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring("com.apple.foo"))])],
    )
    data = bytearray(cache_path.read_bytes())
    macho_off = data.find(struct.pack("<I", MH_MAGIC_64))
    assert macho_off > 0
    struct.pack_into("<I", data, macho_off + 20, MAX_LOAD_COMMAND_BYTES + 1)
    cache_path.write_bytes(bytes(data))
    with pytest.raises(CacheError, match="load commands too large"):
        asyncio.run(DyldCache.open(cache_path))


def test_RA_SRF_001_zero_image_address_is_skipped(tmp_path):
    cache_path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring("com.apple.foo"))])],
    )
    data = bytearray(cache_path.read_bytes())
    struct.pack_into("<Q", data, 0x500, 0)
    cache_path.write_bytes(bytes(data))

    async def exercise() -> DyldCache:
        return await DyldCache.open(cache_path)

    cache = asyncio.run(exercise())
    assert cache.images == []
    asyncio.run(cache.close())


def test_RA_SRF_001_cache_arch_and_family_selection(monkeypatch, tmp_path):
    for machine, expected in [
        ("arm64", "arm64e"),
        ("aarch64", "arm64e"),
        ("x86_64", "x86_64"),
        ("amd64", "x86_64"),
        ("ppc", ""),
    ]:
        monkeypatch.setattr(os, "uname", lambda machine=machine: SimpleNamespace(machine=machine))
        assert _native_cache_arch() == expected

    directory = tmp_path / "dyld"
    directory.mkdir()
    names = ("dyld_shared_cache_arm64e", "dyld_shared_cache_x86_64", "dyld_shared_cache_x86_64.01")
    for name in names:
        (directory / name).write_bytes(b"x")

    monkeypatch.setattr(os, "uname", lambda: SimpleNamespace(machine="x86_64"))
    assert [p.name for p in _cache_candidates(directory)] == [
        "dyld_shared_cache_x86_64",
        "dyld_shared_cache_x86_64.01",
    ]

    monkeypatch.setattr(os, "uname", lambda: SimpleNamespace(machine="ppc"))
    assert [p.name for p in _cache_candidates(directory)] == [
        "dyld_shared_cache_arm64e",
        "dyld_shared_cache_x86_64",
        "dyld_shared_cache_x86_64.01",
    ]

    single = directory / "dyld_shared_cache_ppc.01"
    single.write_bytes(b"dyld_v1")
    assert [p.name for p in _cache_candidates(single)] == ["dyld_shared_cache_ppc.01"]


def test_RA_SRF_001_parse_header_rejects_bad_headers():
    with pytest.raises(CacheError, match="short dyld cache header"):
        _parse_header(b"\0" * 10)
    bad = bytearray(HEADER_SIZE)
    bad[0:4] = b"nope"
    with pytest.raises(CacheError, match="not a dyld shared cache"):
        _parse_header(bytes(bad))


def test_RA_SRF_001_parse_macho_tolerates_truncated_commands():
    data = bytearray(40)
    struct.pack_into("<IIIIIIII", data, 0, MH_MAGIC_64, 0, 0, 6, 2, 8, 0, 0)
    struct.pack_into("<II", data, 32, 0, 8)
    assert parse_macho(bytes(data), 0).sections == ()

    data = bytearray(40)
    struct.pack_into("<IIIIIIII", data, 0, MH_MAGIC_64, 0, 0, 6, 1, 8, 0, 0)
    struct.pack_into("<II", data, 32, 1, 4)
    assert parse_macho(bytes(data), 0).sections == ()

    data = bytearray(104)
    struct.pack_into("<IIIIIIII", data, 0, MH_MAGIC_64, 0, 0, 6, 1, 72, 0, 0)
    struct.pack_into("<II", data, 32, 0x19, 72)
    struct.pack_into("<I", data, 96, 1)
    assert parse_macho(bytes(data), 0).sections == ()


def test_RA_SRF_001_cache_file_context_bounds_and_short_read(tmp_path, monkeypatch):
    path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring("com.apple.foo"))])],
    )

    async def exercise() -> None:
        async with _CacheFile(path) as cf:
            assert cf.size > HEADER_SIZE
            assert await cf.read_at(0, 0) == b""
            with pytest.raises(CacheError, match="read out of range"):
                await cf.read_at(-1, 1)
            with pytest.raises(CacheError, match="read out of range"):
                await cf.read_at(0, cf.size + 1)
            monkeypatch.setattr(os, "pread", lambda fd, size, offset: b"")
            with pytest.raises(CacheError, match="short read"):
                await cf.read_at(0, HEADER_SIZE)

    asyncio.run(exercise())


def test_RA_SRF_001_cache_open_closes_fd_when_fstat_fails(tmp_path):
    path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring("com.apple.foo"))])],
    )
    real_fstat = os.fstat

    def bad_fstat(fd: int):
        raise OSError("fstat boom")

    async def exercise() -> None:
        os.fstat = bad_fstat
        try:
            cf = _CacheFile(path)
            with pytest.raises(OSError, match="fstat boom"):
                await cf.open()
        finally:
            os.fstat = real_fstat

    asyncio.run(exercise())


def test_RA_SRF_001_cache_without_images_is_empty(tmp_path):
    cache_path = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring("com.apple.foo"))])],
    )
    data = bytearray(cache_path.read_bytes())
    struct.pack_into("<I", data, IMAGES_COUNT, 0)
    cache_path.write_bytes(bytes(data))

    async def exercise() -> DyldCache:
        return await DyldCache.open(cache_path)

    cache = asyncio.run(exercise())
    assert cache.images == []
    asyncio.run(cache.close())
