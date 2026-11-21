"""Deterministic RA-FND harness synthesis.

PRESS may replace :class:`TemplateHarnessSynthesizer` later; the Foundry only
depends on the :class:`HarnessSynthesizer` protocol.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from .models import Dialect

SOURCE_NAME = "LLVMFuzzerTestOneInput.cc"
DIALECT_NAME = "groom-dialect.json"
MANIFEST_NAME = "harness.json"
CORPUS_PREFIX = "corpus/"

_C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class SynthesisRequest:
    """Inputs for one synthesis attempt."""

    harness_id: str
    format: str
    dialect: Dialect
    dialect_bytes: bytes
    attempt: int
    feedback: dict[str, Any] | None = None
    surface: str = ""
    surface_median_edges_per_sec: float = 0.0
    parser_malloc_symbol: str = "parser_malloc"
    dry_run_seconds: float = 600.0
    clangxx: str = "clang++"
    compile_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class SynthesizedHarness:
    """Files produced by a synthesizer."""

    files: dict[str, bytes]
    manifest: dict[str, Any]
    source_name: str = SOURCE_NAME
    dialect_name: str = DIALECT_NAME
    manifest_name: str = MANIFEST_NAME
    extra: dict[str, Any] = field(default_factory=dict)


class HarnessSynthesizer(Protocol):
    """Synthesizes harness files for one attempt."""

    def synthesize(self, request: SynthesisRequest) -> SynthesizedHarness:
        """Return harness files and a manifest for ``request``."""


def _c_identifier(symbol: str) -> str:
    if _C_IDENTIFIER_RE.fullmatch(symbol):
        return symbol
    return "parser_malloc"


_GENERIC_TEMPLATE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) void *__PARSER_MALLOC__(size_t size) {
    return malloc(size == 0 ? 1 : size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    uint8_t *copy = (uint8_t *)__PARSER_MALLOC__(size);
    if (copy == nullptr) {
        return 0;
    }
    memcpy(copy, data, size);
    volatile uint64_t checksum = 0;
    for (size_t i = 0; i < size; ++i) {
        checksum = checksum * 1315423911u + copy[i];
        if ((copy[i] & 0x0f) == 0x0a && i + 4 < size) {
            checksum ^= (uint64_t)copy[i + 4] << 8;
        }
    }
    free(copy);
    return (int)(checksum & 0x7fffffff);
}
'''

_HEIF_TEMPLATE = r'''
#include <ImageIO/ImageIO.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

__attribute__((noinline)) void *__PARSER_MALLOC__(size_t size) {
    return malloc(size == 0 ? 1 : size);
}

static int looks_like_heif(const uint8_t *data, size_t size) {
    if (size < 12) {
        return 0;
    }
    return memcmp(data + 4, "ftyp", 4) == 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!looks_like_heif(data, size)) {
        return 0;
    }
    char path[] = "/tmp/redapple_heif_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }
    ssize_t written = write(fd, data, size);
    close(fd);
    if (written != (ssize_t)size) {
        unlink(path);
        return 0;
    }
    CFStringRef cf_path = CFStringCreateWithCString(
        kCFAllocatorDefault, path, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault, cf_path, kCFURLPOSIXPathStyle, false);
    CGImageSourceRef source = CGImageSourceCreateWithURL(url, nullptr);
    if (source != nullptr) {
        CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, nullptr);
        if (image != nullptr) {
            size_t width = CGImageGetWidth(image);
            size_t height = CGImageGetHeight(image);
            volatile size_t sink = width ^ height;
            (void)sink;
            CGImageRelease(image);
        }
        CFRelease(source);
    }
    if (url != nullptr) {
        CFRelease(url);
    }
    if (cf_path != nullptr) {
        CFRelease(cf_path);
    }
    unlink(path);
    return 0;
}
'''


def _render_source(request: SynthesisRequest) -> str:
    symbol = _c_identifier(request.parser_malloc_symbol)
    if request.format == "heif" or request.format.endswith(".heif"):
        template = _HEIF_TEMPLATE
    else:
        template = _GENERIC_TEMPLATE
    return (
        "// synthesized by ra.foundry.synthesis\n"
        f"// harness={request.harness_id} attempt={request.attempt}\n"
        + template.replace("__PARSER_MALLOC__", symbol)
    )


def _seed_inputs(request: SynthesisRequest) -> list[bytes]:
    seeds = [
        b"\x00" * 32,
        bytes(range(256)),
        f"RA-FND {request.harness_id} attempt {request.attempt}".encode(),
    ]
    if request.format == "heif" or request.format.endswith(".heif"):
        seeds.insert(
            0,
            b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heicmif1"
            b"\x00\x00\x00\x08free",
        )
    return seeds


class TemplateHarnessSynthesizer:
    """Deterministic synthesizer used until PRESS harness_synth is wired."""

    def synthesize(self, request: SynthesisRequest) -> SynthesizedHarness:
        """Synthesize a libFuzzer harness bundle from a validated dialect."""
        source = _render_source(request)
        manifest = {
            "id": request.harness_id,
            "format": request.format,
            "surface": request.surface,
            "source": SOURCE_NAME,
            "dialect": DIALECT_NAME,
            "manifest": MANIFEST_NAME,
            "clangxx": request.clangxx,
            "compile_args": list(request.compile_args),
            "dry_run_seconds": request.dry_run_seconds,
            "surface_median_edges_per_sec": request.surface_median_edges_per_sec,
            "throughput_metric": "coverage_edges_per_sec",
            "parser_malloc_symbol": request.parser_malloc_symbol,
            "baseline_coverage": True,
            "seed_corpus": CORPUS_PREFIX,
            "generated_by": "ra.foundry.synthesis.TemplateHarnessSynthesizer",
            "attempt": request.attempt,
        }
        files = {
            SOURCE_NAME: source.encode("utf-8"),
            DIALECT_NAME: request.dialect_bytes,
            MANIFEST_NAME: (
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8"),
        }
        for index, seed in enumerate(_seed_inputs(request)):
            files[f"{CORPUS_PREFIX}seed_{index:03d}"] = seed
        return SynthesizedHarness(files=files, manifest=manifest)
