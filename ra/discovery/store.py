"""Ledger persistence for discovery campaigns and crash references."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..errors import DuplicateDedup
from ..ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger, UlidFactory
from .crashsig import classify_crash
from .models import CampaignState, CrashRecord, CrashRefLike


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _payload_sha256(payload: bytes) -> str | None:
    return None if not payload else _sha256(payload)


class LedgerDiscoveryStore:
    """Store campaign state and crash claims in the M0 claim ledger."""

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._ids = UlidFactory()

    def _state_rows(self) -> list[dict[str, Any]]:
        return self._ledger.claims_by_type("discovery_state", limit=10000)

    @staticmethod
    def _state_from_row(row: dict[str, Any]) -> tuple[tuple[int, str], CampaignState] | None:
        try:
            raw = json.loads(str(row["value_json"]))
            if not isinstance(raw, dict):
                return None
            state = CampaignState.from_dict(dict(raw))
            return (int(row["created"]), str(row["id"])), state
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None

    async def load(self, campaign_id: str) -> CampaignState | None:
        """Load the latest state snapshot for ``campaign_id``."""
        latest: tuple[tuple[int, str], CampaignState] | None = None
        for row in self._state_rows():
            parsed = self._state_from_row(row)
            if parsed is None:
                continue
            key, state = parsed
            if state.campaign_id != campaign_id:
                continue
            if latest is None or key > latest[0]:
                latest = (key, state)
        return None if latest is None else latest[1]

    async def save(self, state: CampaignState) -> None:
        """Append a bound ``discovery_state`` claim snapshot."""
        state_json = _json_dumps(state.to_dict())
        state_bytes = state_json.encode("utf-8")
        claim_id = self._ids.new("ds")
        claim = ClaimInput(
            claim_id=claim_id,
            type="discovery_state",
            value_json=state_json,
            confidence=1.0,
            dedup_key=f"discovery_state:{claim_id}",
            created=state.updated_ms,
            artifacts=(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind="discovery_state", data=state_bytes, ttl_class="run"),
                    role="state",
                ),
            ),
        )
        await self._ledger.create_claim(claim)
        await self._ledger.transition_claim(claim_id, ClaimState.BOUND)

    async def list_ids(self) -> list[str]:
        """List campaign ids with persisted state."""
        ids: set[str] = set()
        for row in self._state_rows():
            parsed = self._state_from_row(row)
            if parsed is not None:
                ids.add(parsed[1].campaign_id)
        return sorted(ids)

    async def record_crash(
        self,
        *,
        campaign_id: str,
        case_id: str,
        crash: CrashRefLike,
        input_digest: str,
        strategy: str,
        seed_index: int,
        case_index: int,
        created_ms: int,
        image_format: str | None = None,
    ) -> CrashRecord:
        """Record one crash reference; duplicate crash *classes* return ``claim_id=None``.

        Dedup keys on the classified crash signature (kind/context/category/
        signal/exception/image format) so the same bug found by different cases
        collapses into one claim. Per-occurrence detail (case id, input digest,
        payload hash, metadata) stays in the claim value.
        """
        classification = classify_crash(crash, image_format=image_format)
        payload = bytes(getattr(crash, "payload", b"") or b"")
        metadata = dict(getattr(crash, "metadata", {}) or {})
        signature = classification.signature(campaign_id)
        dedup = "discovery_crash:" + _sha256(_json_dumps(signature).encode("utf-8"))
        value = {
            **signature,
            "case_id": case_id,
            "crash_id": str(getattr(crash, "id", "")),
            "handle_id": getattr(crash, "handle_id", None),
            "path": getattr(crash, "path", None),
            "digest": getattr(crash, "digest", None),
            "payload_sha256": _payload_sha256(payload),
            "input_sha256": input_digest,
            "metadata": metadata,
            "created_ms": int(getattr(crash, "created_ms", created_ms)),
            "strategy": strategy,
            "seed_index": seed_index,
            "case_index": case_index,
            "payload_bytes": len(payload),
        }
        value_json = _json_dumps(value)
        record_bytes = value_json.encode("utf-8")
        claim_id = self._ids.new("dc")
        claim = ClaimInput(
            claim_id=claim_id,
            type="discovery_crash",
            value_json=value_json,
            confidence=0.7,
            dedup_key=dedup,
            created=created_ms,
            artifacts=(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind="discovery_crash", data=record_bytes, ttl_class="run"),
                    role="evidence",
                ),
            ),
        )
        try:
            await self._ledger.create_claim(claim)
            await self._ledger.transition_claim(claim_id, ClaimState.BOUND)
        except DuplicateDedup:
            return CrashRecord(
                claim_id=None,
                campaign_id=campaign_id,
                case_id=case_id,
                crash_id=str(getattr(crash, "id", "")),
                kind=str(getattr(crash, "kind", "unknown")),
                dedup_key=dedup,
                value=value,
            )
        return CrashRecord(
            claim_id=claim_id,
            campaign_id=campaign_id,
            case_id=case_id,
            crash_id=str(getattr(crash, "id", "")),
            kind=str(getattr(crash, "kind", "unknown")),
            dedup_key=dedup,
            value=value,
        )
