"""Seed corpus loading for the JSC discovery fuzzer.

The bundled corpus under ``ra/discovery/corpus/*.js`` is ported verbatim from
PR #3's ``redapple_discovery/corpus``: typed-array, ArrayBuffer, Proxy, and
JIT stress seeds that exercise WebKit/JSC engine edges.
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
FALLBACK_CORPUS: tuple[str, ...] = ("print(1);",)


def load_corpus(directory: str | Path | None = None) -> tuple[str, ...]:
    """Load ``*.js`` seeds sorted by name; falls back to a trivial seed."""
    root = Path(directory) if directory is not None else DEFAULT_CORPUS_DIR
    entries: list[str] = []
    for path in sorted(root.glob("*.js")):
        try:
            entries.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return tuple(entries) or FALLBACK_CORPUS
