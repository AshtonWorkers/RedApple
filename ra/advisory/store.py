"""Ledger-backed persistence for advisory snapshots and prioritization results.

All advisory state is stored as content-addressed artifacts linked to bound
claims; there is no advisory JSON/SQLite side store.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, NoReturn

from ..errors import FormatFail
from ..ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    ClaimState,
    Ledger,
    UlidFactory,
)
from ..ledger.ids import now_ms
from .models import AdvisorySnapshot
from .prioritize import PrioritizationResult

SNAPSHOT_CLAIM_TYPE = "advisory_snapshot"
PRIORITY_CLAIM_TYPE = "advisory_priorities"
_MAX_CLAIM_ROWS = 10000


def _canonical_json(value: dict[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as exc:
        raise FormatFail("advisory value must be finite JSON") from exc


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reject_json_constant(value: str) -> NoReturn:
    raise FormatFail(f"advisory claim contains non-finite JSON constant {value}")


def _loads_json(text: str) -> Any:
    try:
        return json.loads(text, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise FormatFail("advisory claim value_json must be JSON") from exc
    except RecursionError as exc:
        raise FormatFail("advisory claim value_json is nested too deeply") from exc


def _iso_to_ms(text: str) -> int:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return now_ms()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def _latest_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return max(rows, key=lambda row: (int(row["created"]), str(row["id"])))


class LedgerAdvisoryStore:
    """Persist advisory intelligence through the M0 claim ledger."""

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._ids = UlidFactory()

    async def _save_claim(
        self,
        *,
        claim_type: str,
        dedup_key: str,
        value_json: str,
        artifact_kind: str,
        role: str,
        created: int,
    ) -> str:
        existing = self._ledger.claim_by_dedup(dedup_key)
        if existing is not None:
            return str(existing["id"])
        payload = value_json.encode("utf-8")
        claim_id = self._ids.new("adv")
        claim = ClaimInput(
            claim_id=claim_id,
            type=claim_type,
            value_json=value_json,
            confidence=1.0,
            dedup_key=dedup_key,
            created=created,
            artifacts=(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind=artifact_kind, data=payload, ttl_class="pinned"),
                    role=role,
                ),
            ),
        )
        await self._ledger.create_claim(claim)
        await self._ledger.transition_claim(claim_id, ClaimState.BOUND)
        return claim_id

    async def save_snapshot(self, snapshot: AdvisorySnapshot) -> str:
        """Store one advisory snapshot as a bound ledger claim."""
        value = snapshot.to_dict()
        value_json = _canonical_json(value)
        digest = _digest(value_json)
        return await self._save_claim(
            claim_type=SNAPSHOT_CLAIM_TYPE,
            dedup_key=f"{SNAPSHOT_CLAIM_TYPE}:{digest}",
            value_json=value_json,
            artifact_kind=SNAPSHOT_CLAIM_TYPE,
            role="snapshot",
            created=_iso_to_ms(snapshot.fetched_at),
        )

    async def load_latest_snapshot(self) -> AdvisorySnapshot | None:
        """Load the newest stored advisory snapshot, if any."""
        rows = self._ledger.claims_by_type(SNAPSHOT_CLAIM_TYPE, limit=_MAX_CLAIM_ROWS)
        latest = _latest_row(rows)
        if latest is None:
            return None
        raw = _loads_json(str(latest["value_json"]))
        if not isinstance(raw, dict):
            return None
        return AdvisorySnapshot.from_dict(raw)

    async def save_prioritization(self, result: PrioritizationResult) -> str:
        """Store one prioritization result as a bound ledger claim."""
        value = result.to_dict()
        value_json = _canonical_json(value)
        digest = _digest(value_json)
        return await self._save_claim(
            claim_type=PRIORITY_CLAIM_TYPE,
            dedup_key=f"{PRIORITY_CLAIM_TYPE}:{digest}",
            value_json=value_json,
            artifact_kind=PRIORITY_CLAIM_TYPE,
            role="priorities",
            created=_iso_to_ms(result.generated_at),
        )

    async def load_latest_prioritization(self) -> PrioritizationResult | None:
        """Load the newest stored prioritization result, if any."""
        rows = self._ledger.claims_by_type(PRIORITY_CLAIM_TYPE, limit=_MAX_CLAIM_ROWS)
        latest = _latest_row(rows)
        if latest is None:
            return None
        raw = _loads_json(str(latest["value_json"]))
        if not isinstance(raw, dict):
            return None
        return PrioritizationResult.from_dict(raw)
