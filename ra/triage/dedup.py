"""Exact and MinHash crash deduplication over ledger-backed triage claims."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from ra.ledger import Ledger, dedup_key

from .evidence import (
    bug_class_hint,
    evidence_text,
    normalize_stack_text,
    normalized_frames,
    stack_hash,
)
from .models import CrashEvidence, DedupSignature, SymbolizedCrash
from .sanitize import clean_text, safe_int

MINHASH_SIZE = 128
DEDUP_THRESHOLD = 0.78
_FRAME_DEPTH = 5
_MAX_CLAIMS = 10_000
_HASH_SPACE = 1 << 64


def _hash_element(seed: int, element: str) -> int:
    digest = hashlib.md5(f"{seed}|{element}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def signature_elements(frames: Sequence[str], stderr: str = "") -> tuple[str, ...]:
    top = normalized_frames(frames, depth=_FRAME_DEPTH)
    if not top:
        return (f"nostack:{normalize_stack_text(stderr)}",)
    elements = [f"{index}:{frame}" for index, frame in enumerate(top)]
    elements.extend(
        f"{index}:{left}>{right}"
        for index, (left, right) in enumerate(zip(top, top[1:], strict=False))
    )
    return tuple(elements)


def minhash128(elements: Sequence[str]) -> tuple[int, ...]:
    values = list(dict.fromkeys(elements)) or ["empty"]
    mins = [_HASH_SPACE - 1] * MINHASH_SIZE
    for element in values:
        for seed in range(MINHASH_SIZE):
            value = _hash_element(seed, element)
            if value < mins[seed]:
                mins[seed] = value
    return tuple(mins)


def minhash_similarity(left: Sequence[int], right: Sequence[int]) -> float:
    if len(left) != MINHASH_SIZE or len(right) != MINHASH_SIZE:
        return 0.0
    matches = sum(1 for a, b in zip(left, right, strict=False) if a == b)
    return matches / MINHASH_SIZE


def build_signature(
    crash: CrashEvidence,
    symbolized: SymbolizedCrash,
    *,
    hint: str | None = None,
) -> DedupSignature:
    frames = symbolized.frames or ()
    normalized = normalized_frames(frames, depth=_FRAME_DEPTH)
    text = evidence_text(crash)
    fallback = symbolized.stderr or text
    digest = stack_hash(frames, fallback)
    metadata = crash.metadata if isinstance(crash.metadata, Mapping) else {}
    alloc_site = clean_text(
        metadata.get("alloc_site") or metadata.get("allocation_site") or "unknown",
        limit=256,
        keep_newlines=False,
    ) or "unknown"
    bug_class = hint or bug_class_hint(crash, frames, symbolized=bool(normalized))
    elements = signature_elements(normalized, symbolized.stderr)
    return DedupSignature(
        dedup_key=dedup_key(bug_class, digest, alloc_site),
        stack_hash=digest,
        alloc_site=alloc_site,
        bug_class=bug_class,
        frames=normalized,
        signature=minhash128(elements),
        created_ms=safe_int(crash.created_ms, 0),
    )


def _claim_value(row: Mapping[str, Any]) -> dict[str, Any]:
    raw = row.get("value_json")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, RecursionError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    if isinstance(raw, Mapping):
        return dict(raw)
    return {}


class TriageDeduper:
    """Find the oldest matching triage claim for a crash signature."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        threshold: float = DEDUP_THRESHOLD,
        max_claims: int = _MAX_CLAIMS,
    ) -> None:
        self._ledger = ledger
        self._threshold = threshold
        self._max_claims = max_claims

    def find_duplicate(self, signature: DedupSignature) -> tuple[str, float] | None:
        exact = self._ledger.claim_by_dedup(signature.dedup_key)
        if exact is not None and exact.get("type") == "bug_class":
            value = _claim_value(exact)
            if value.get("triage_status") != "duplicate":
                return str(exact["id"]), 1.0
        for row in self._ledger.claims_by_type("bug_class", limit=self._max_claims):
            value = _claim_value(row)
            if value.get("triage_status") == "duplicate":
                continue
            dedup = value.get("dedup")
            if not isinstance(dedup, Mapping):
                continue
            candidate = DedupSignature.from_dict(dedup)
            if candidate.dedup_key == signature.dedup_key:
                return str(row["id"]), 1.0
            similarity = minhash_similarity(signature.signature, candidate.signature)
            if similarity >= self._threshold:
                return str(row["id"]), similarity
        return None


__all__ = [
    "DEDUP_THRESHOLD",
    "MINHASH_SIZE",
    "TriageDeduper",
    "build_signature",
    "minhash128",
    "minhash_similarity",
    "signature_elements",
]
