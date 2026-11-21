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
