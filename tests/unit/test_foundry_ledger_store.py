"""Ledger-backed Foundry store tests."""

import asyncio

from ra.foundry import FoundryState, LedgerFoundryStore
from ra.ledger import Ledger


def _state(harness_id: str, updated_at: int) -> FoundryState:
    return FoundryState(harness_id=harness_id, format="edge", updated_at=updated_at)


def test_ledger_foundry_store_roundtrip(tmp_path):
    async def body():
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        try:
            store = LedgerFoundryStore(ledger)
            assert await store.load("h1") is None
            await store.save(_state("h1", 100))
            await store.save(_state("h1", 200))
            await store.save(_state("h2", 150))
            got = await store.load("h1")
            assert got is not None
            assert got.harness_id == "h1"
            assert got.updated_at == 200
            assert await store.list_ids() == ["h1", "h2"]
        finally:
            await ledger.close()

    asyncio.run(body())
