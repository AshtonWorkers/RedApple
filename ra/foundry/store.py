"""Thin Foundry persistence interface.

``JsonFoundryStore`` is the standalone PR #7 fallback. The integration rewire
into PR #8's ledger is documented in ``docs/foundry-ledger-rewire.md``; this
module intentionally does not import ``ra.ledger`` so RA-FND can land first.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Protocol

from ..ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger, UlidFactory
from ..ledger.ids import now_ms
from .models import FoundryState


class FoundryStore(Protocol):
    """Persistence surface used by the Foundry."""

    async def load(self, harness_id: str) -> FoundryState | None:
        """Load state for one harness, or None when absent."""

    async def save(self, state: FoundryState) -> None:
        """Upsert state for one harness."""

    async def list_ids(self) -> list[str]:
        """List known harness ids."""


class JsonFoundryStore:
    """Small JSON-file implementation of :class:`FoundryStore`."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "foundry_state.json"
        self._save_lock = asyncio.Lock()

    def _read_all_sync(self) -> dict[str, FoundryState]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        states: dict[str, FoundryState] = {}
        for harness_id, data in raw.items():
            states[harness_id] = FoundryState.from_dict(data)
        return states

    def _write_all_sync(self, states: dict[str, FoundryState]) -> None:
        payload = {harness_id: state.to_dict() for harness_id, state in states.items()}
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp.replace(self.path)

    async def load(self, harness_id: str) -> FoundryState | None:
        states = await asyncio.to_thread(self._read_all_sync)
        return states.get(harness_id)

    async def save(self, state: FoundryState) -> None:
        async with self._save_lock:

            def _save() -> None:
                states = self._read_all_sync()
                states[state.harness_id] = state
                self._write_all_sync(states)

            await asyncio.to_thread(_save)

    async def list_ids(self) -> list[str]:
        states = await asyncio.to_thread(self._read_all_sync)
        return sorted(states)


class LedgerFoundryStore:
    """Foundry state stored as bound harness claims in the claim ledger."""

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._ids = UlidFactory()

    async def load(self, harness_id: str) -> FoundryState | None:
        claims = self._ledger.claims_by_type("harness", limit=10000)
        latest: dict[str, object] | None = None
        for claim in claims:
            data = json.loads(str(claim["value_json"]))
            if data.get("harness_id") != harness_id:
                continue
            if latest is None or int(str(latest["created"])) < int(str(claim["created"])):
                latest = claim
        if latest is None:
            return None
        return FoundryState.from_dict(json.loads(str(latest["value_json"])))

    async def save(self, state: FoundryState) -> None:
        state_json = json.dumps(state.to_dict(), sort_keys=True, separators=(",", ":"))
        claim_id = self._ids.new("fs")
        created = state.updated_at or now_ms()
        await self._ledger.create_claim(
            ClaimInput(
                claim_id=claim_id,
                type="harness",
                value_json=state_json,
                confidence=1.0,
                dedup_key=f"harness_state:{state.harness_id}:{claim_id}",
                created=created,
                artifacts=(
                    ClaimArtifactInput(
                        artifact=ArtifactInput(
                            kind="foundry_state",
                            data=state_json.encode("utf-8"),
                            ttl_class="run",
                        ),
                        role="state",
                    ),
                ),
            )
        )
        await self._ledger.transition_claim(claim_id, ClaimState.BOUND)

    async def list_ids(self) -> list[str]:
        claims = self._ledger.claims_by_type("harness", limit=10000)
        ids = {
            str(json.loads(str(claim["value_json"]))["harness_id"]) for claim in claims
        }
        return sorted(ids)
