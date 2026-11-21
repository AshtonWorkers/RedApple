"""Dyld cache parsing unit tests (synthetic Mach-O bytes)."""

import struct

from ra.srf.dyld import MachOImage, MachOSection, parse_macho, split_strings


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


def test_RA_SRF_001_split_strings_is_deterministic():
    assert split_strings(b"alpha\0beta\0\0gamma\0") == ["alpha", "beta", "gamma"]
