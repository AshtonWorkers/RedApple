"""Unified-diff parsing and patch-diff similarity for RA-DUP."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from .models import _SYMBOL_RE, CrashSignature, PatchDiff

_MAX_SYMBOLS = 512
_MAX_PATHS = 256

_KEYWORDS = frozenset(
    {
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "default",
        "return",
        "break",
        "continue",
        "goto",
        "sizeof",
        "typeof",
        "const",
        "static",
        "extern",
        "inline",
        "void",
        "int",
        "char",
        "short",
        "long",
        "float",
        "double",
        "bool",
        "true",
        "false",
        "nil",
        "self",
        "super",
        "NULL",
        "YES",
        "NO",
        "new",
        "delete",
        "class",
        "struct",
        "enum",
        "union",
        "typedef",
        "namespace",
        "using",
        "public",
        "private",
        "protected",
        "virtual",
        "override",
        "final",
    }
)

_PATH_PREFIX_RE = re.compile(r"^(?:a|b)/")
_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def parse_unified_diff(text: str, *, source: str = "", ring_node: str | None = None) -> PatchDiff:
    """Parse a unified diff into normalized paths and changed identifiers."""
    paths: list[str] = []
    symbols: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped:
            continue
        git_match = _DIFF_GIT_RE.match(stripped)
        if git_match:
            _add_path(paths, git_match.group(2))
        if stripped.startswith("+++ ") or stripped.startswith("--- "):
            path = _path_from_marker(stripped)
            if path:
                _add_path(paths, path)
            continue
        if stripped.startswith(("+", "-")) and not stripped.startswith(("+++", "---")):
            for match in _SYMBOL_RE.finditer(stripped[1:]):
                symbol = match.group(0)
                if symbol in _KEYWORDS or len(symbol) < 2:
                    continue
                if symbol not in symbols:
                    symbols.append(symbol)
                    if len(symbols) >= _MAX_SYMBOLS:
                        break
        if len(symbols) >= _MAX_SYMBOLS:
            break
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return PatchDiff(
        paths=tuple(paths[:_MAX_PATHS]),
        symbols=tuple(symbols),
        source=source,
        ring_node=ring_node,
        text_hash=digest,
    )


def patch_similarity(a: PatchDiff, b: PatchDiff) -> float:
    """Jaccard-style similarity over normalized paths and changed symbols."""
    if not a.has_evidence or not b.has_evidence:
        return 0.0
    path_sim = _jaccard(a.paths, b.paths)
    symbol_sim = _jaccard(a.symbols, b.symbols)
    if a.paths and b.paths:
        return 0.65 * path_sim + 0.35 * symbol_sim
    if a.symbols and b.symbols:
        return symbol_sim
    return 0.5 * (path_sim + symbol_sim)


def patch_proximity(patch: PatchDiff, signature: CrashSignature) -> float:
    """Proximity of a patch to the modules/functions implicated by a crash."""
    if not patch.has_evidence or not signature.frames:
        return 0.0
    frame_modules = {frame.module.lower() for frame in signature.frames if frame.module}
    frame_functions = {frame.function for frame in signature.frames if frame.function}
    frame_keys = {frame.key().lower() for frame in signature.frames}
    path_hits = 0
    for path in patch.paths:
        base = path.rsplit("/", 1)[-1].lower()
        stem = base.rsplit(".", 1)[0]
        if base in frame_modules or stem in frame_modules or base in frame_keys:
            path_hits += 1
    symbol_hits = 0
    for symbol in patch.symbols:
        if symbol in frame_functions or symbol.lower() in frame_keys:
            symbol_hits += 1
    path_score = path_hits / max(1, min(len(patch.paths), 8))
    symbol_score = symbol_hits / max(1, min(len(patch.symbols), 16))
    return min(1.0, 0.45 * path_score + 0.55 * symbol_score)


def max_patch_proximity(patches: Iterable[PatchDiff], signature: CrashSignature) -> float | None:
    """Return the best patch-to-crash proximity, or None when no patch evidence exists."""
    best: float | None = None
    for patch in patches:
        if not patch.has_evidence:
            continue
        value = patch_proximity(patch, signature)
        if best is None or value > best:
            best = value
    return best


def max_patch_similarity(patches_a: Iterable[PatchDiff], patches_b: Iterable[PatchDiff]) -> float | None:
    """Return the best patch-to-patch similarity, or None without evidence on both sides."""
    best: float | None = None
    for a in patches_a:
        if not a.has_evidence:
            continue
        for b in patches_b:
            if not b.has_evidence:
                continue
            value = patch_similarity(a, b)
            if best is None or value > best:
                best = value
    return best


def _path_from_marker(line: str) -> str:
    body = line[4:].strip()
    if body == "/dev/null":
        return ""
    body = body.split("\t", 1)[0].strip()
    body = _PATH_PREFIX_RE.sub("", body, count=1)
    return _normalize_path(body)


def _normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    while "//" in path:
        path = path.replace("//", "/")
    return path.strip().strip('"')


def _add_path(paths: list[str], raw: str) -> None:
    path = _normalize_path(_PATH_PREFIX_RE.sub("", raw.strip(), count=1))
    if path and path != "/dev/null" and path not in paths and len(paths) < _MAX_PATHS:
        paths.append(path)


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    left = {item for item in a if item}
    right = {item for item in b if item}
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


__all__ = [
    "max_patch_proximity",
    "max_patch_similarity",
    "parse_unified_diff",
    "patch_proximity",
    "patch_similarity",
]
