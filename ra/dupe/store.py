"""Ledger-backed persistence for dupe-oracle records (RA-DUP)."""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ..ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger, UlidFactory
from .models import CrashSignature, DupeScore, PatchDiff

_DUPE_CLAIM_TYPE = "dupe_score"
_SCHEMA = "ra.dupe.v1"


@dataclass(frozen=True)
class DupeRecord:
    """One canonical or observation record stored as a ledger claim."""

    claim_id: str
    dedup_key: str
    record_kind: str
    canonical_id: str
    created_ms: int
    signature: CrashSignature
    patches: tuple[PatchDiff, ...] = ()
    score: DupeScore | None = None
    is_duplicate: bool = False
    match_kind: str = "new"
    similarity: float = 1.0
    source_id: str = ""

    def to_value_json(self) -> str:
        payload: dict[str, Any] = {
            "schema": _SCHEMA,
            "record_kind": self.record_kind,
            "canonical_id": self.canonical_id,
            "created_ms": self.created_ms,
            "signature": self.signature.to_dict(),
            "patches": [patch.to_dict() for patch in self.patches],
            "is_duplicate": self.is_duplicate,
            "match_kind": self.match_kind,
            "similarity": self.similarity,
            "source_id": self.source_id,
        }
        if self.score is not None:
            payload["score"] = self.score.to_dict()
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> DupeRecord | None:
        try:
            raw = json.loads(str(row["value_json"]))
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        if not isinstance(raw, dict):
            return None
        data = raw
        if data.get("schema") != _SCHEMA:
            return None
        signature_raw = data.get("signature")
        if not isinstance(signature_raw, dict):
            return None
        patches_raw = data.get("patches", ())
        patches: list[PatchDiff] = []
        if isinstance(patches_raw, Sequence) and not isinstance(patches_raw, (str, bytes, bytearray)):
            for item in patches_raw:
                if isinstance(item, dict):
                    patches.append(PatchDiff.from_dict(item))
        score_raw = data.get("score")
        score = DupeScore.from_dict(score_raw) if isinstance(score_raw, dict) else None
        return cls(
            claim_id=str(row.get("id", "")),
            dedup_key=str(row.get("dedup_key", "")),
            record_kind=str(data.get("record_kind", "")),
            canonical_id=str(data.get("canonical_id", "")),
            created_ms=_as_int(data.get("created_ms")) or _as_int(row.get("created")) or 0,
            signature=CrashSignature.from_dict(signature_raw),
            patches=tuple(patches),
            score=score,
            is_duplicate=bool(data.get("is_duplicate", False)),
            match_kind=str(data.get("match_kind", "new")),
            similarity=_as_float(data.get("similarity"), default=1.0),
            source_id=str(data.get("source_id", "")),
        )


class DupeStore(Protocol):
    """Persistence surface used by the dupe oracle."""

    async def get_canonical(self, signature_hash: str) -> DupeRecord | None:
        """Fetch the canonical record for an exact signature hash."""
        ...  # pragma: no cover

    async def canonicals(self) -> Sequence[DupeRecord]:
        """List canonical records in creation order."""
        ...  # pragma: no cover

    async def save_canonical(self, record: DupeRecord, artifact_data: bytes) -> str:
        """Persist a canonical record and return its claim id."""
        ...  # pragma: no cover

    async def save_observation(self, record: DupeRecord, artifact_data: bytes) -> str:
        """Persist a duplicate observation and return its claim id."""
        ...  # pragma: no cover


def canonical_id_for_signature(signature_hash: str) -> str:
    """Deterministic canonical id for a normalized crash signature."""
    return f"dupc_{signature_hash}"


def canonical_dedup_key(signature_hash: str) -> str:
    """Ledger dedup key for one canonical signature."""
    return f"dupe:canonical:{signature_hash}"


class LedgerDupeStore:
    """Store dupe records as bound ``dupe_score`` ledger claims."""

    def __init__(self, ledger: Ledger, *, scan_limit: int = 10000) -> None:
        self._ledger = ledger
        self._scan_limit = scan_limit
        self._ids = UlidFactory()

    async def get_canonical(self, signature_hash: str) -> DupeRecord | None:
        row = self._ledger.claim_by_dedup(canonical_dedup_key(signature_hash))
        if row is None:
            return None
        record = DupeRecord.from_row(row)
        if record is None or record.record_kind != "canonical":
            return None
        return record

    async def canonicals(self) -> Sequence[DupeRecord]:
        records: list[DupeRecord] = []
        for row in self._ledger.claims_by_type(_DUPE_CLAIM_TYPE, limit=self._scan_limit):
            record = DupeRecord.from_row(row)
            if record is not None and record.record_kind == "canonical":
                records.append(record)
        return records

    async def save_canonical(self, record: DupeRecord, artifact_data: bytes) -> str:
        return await self._save(record, artifact_data, kind="dupe_signature", ttl_class="pinned")

    async def save_observation(self, record: DupeRecord, artifact_data: bytes) -> str:
        return await self._save(record, artifact_data, kind="dupe_observation", ttl_class="run")

    async def _save(self, record: DupeRecord, artifact_data: bytes, *, kind: str, ttl_class: str) -> str:
        claim_id = record.claim_id or self._ids.new("dupe")
        claim = ClaimInput(
            claim_id=claim_id,
            type=_DUPE_CLAIM_TYPE,
            value_json=record.to_value_json(),
            confidence=_clamp_confidence(record.similarity if record.is_duplicate else 1.0),
            dedup_key=record.dedup_key,
            created=record.created_ms,
            artifacts=(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind=kind, data=artifact_data, ttl_class=ttl_class),
                    role="signature" if record.record_kind == "canonical" else "evidence",
                ),
            ),
        )
        await self._ledger.create_claim(claim)
        await self._ledger.transition_claim(claim_id, ClaimState.BOUND)
        return claim_id


def _clamp_confidence(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return 0.0
    return min(1.0, max(0.0, float(value)))


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _as_float(value: Any, *, default: float) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


__all__ = [
    "DupeRecord",
    "DupeStore",
    "LedgerDupeStore",
    "canonical_dedup_key",
    "canonical_id_for_signature",
]
