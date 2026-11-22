"""Store tests for RA-SFC-006: ranked targets persisted through the M0 ledger."""

import asyncio
import json
import sqlite3
from pathlib import Path

from ra.ledger import Ledger
from ra.srf.models import ReachRecord
from ra.surface.models import ExpandedTarget, TargetList, stable_id
from ra.surface.rank import rank_targets
from ra.surface.store import (
    InMemorySurfaceStore,
    LedgerSurfaceStore,
    feed_payload,
    surface_targets_from_rows,
)


def _target_list(ring_node: str = "ring") -> TargetList:
    targets = [
        ExpandedTarget(
            ring_node=ring_node,
            name=name,
            reach_from=(ReachRecord(source="image:/x", hops=2, via="dyld-cache"),),
            base_weight=weight,
            privilege_delta=1,
            parser_complexity=0.5,
        )
        for name, weight in (("com.apple.low", 0.1), ("com.apple.high", 2.0))
    ]
    return rank_targets(targets, ring_node=ring_node)


def test_RA_SFC_006_in_memory_store_replace_and_read():
    async def body() -> None:
        store = InMemorySurfaceStore()
        tl = _target_list()
        await store.replace_targets(tl)
        rows = store.read_targets("ring")
        assert [r["name"] for r in rows] == ["com.apple.high", "com.apple.low"]
        assert store.read_targets("other") == []
        # second replace on another ring node leaves the first untouched
        await store.replace_targets(_target_list("ring2"))
        assert [r["name"] for r in store.read_targets("ring")] == ["com.apple.high", "com.apple.low"]
        assert [r["ring_node"] for r in store.read_targets("ring2")] == ["ring2", "ring2"]

    asyncio.run(body())


def test_RA_SFC_006_ledger_store_round_trip_and_overwrite(tmp_path: Path) -> None:
    async def body() -> None:
        path = tmp_path / "ledger.sqlite"
        tl = _target_list()
        ledger = await Ledger.open(path)
        store = LedgerSurfaceStore(ledger)
        await store.replace_targets(tl)
        await ledger.close()

        # hand-edit a weight, then replace again: ranked rows must win
        conn = sqlite3.connect(str(path))
        conn.execute("UPDATE entry_point SET weight = 999.0")
        conn.commit()
        conn.close()

        ledger = await Ledger.open(path)
        store = LedgerSurfaceStore(ledger)
        await store.replace_targets(tl)
        rows = store.read_targets("ring")
        assert [r["name"] for r in rows] == ["com.apple.high", "com.apple.low"]
        assert rows[0]["weight"] < 10.0
        assert rows[0]["id"] == stable_id("surf", "ring", "com.apple.high")
        # thin targets re-derive ranks from persisted weights
        thin = surface_targets_from_rows(rows)
        assert [t.rank for t in thin] == [1, 2]
        await ledger.close()

    asyncio.run(body())


def test_RA_SFC_006_ledger_ring_node_isolation(tmp_path: Path) -> None:
    async def body() -> None:
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        store = LedgerSurfaceStore(ledger)
        await store.replace_targets(_target_list("ring1"))
        await store.replace_targets(_target_list("ring2"))
        ring1 = store.read_targets("ring1")
        ring2 = store.read_targets("ring2")
        assert {r["ring_node"] for r in ring1} == {"ring1"}
        assert {r["ring_node"] for r in ring2} == {"ring2"}
        await ledger.close()

    asyncio.run(body())


def test_RA_SFC_006_feed_payload_is_json_serializable():
    tl = _target_list()
    payload = feed_payload(list(tl.targets))
    text = json.dumps(payload)
    assert json.loads(text)[0]["name"] in {"com.apple.high", "com.apple.low"}
    assert payload[0]["tier"] in {"S", "A", "B", "C"}
