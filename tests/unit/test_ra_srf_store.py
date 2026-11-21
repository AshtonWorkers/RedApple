"""Store persistence tests for RA-SRF-004."""

import asyncio
import sqlite3

from ra.srf.store import (
    DDL,
    InMemoryEntryPointStore,
    SQLiteEntryPointStore,
    ledger_entry_point_payload,
    rows_to_json,
)


def _row(id_: str, name: str, weight: float) -> dict:
    return {
        "id": id_,
        "name": name,
        "reach_from_json": '[{"source":"image:/x","hops":2,"via":"dyld-cache"}]',
        "privilege_delta": 1,
        "parser_complexity": 0.5,
        "weight": weight,
        "ring_node": "ring",
    }


def test_RA_SRF_004_replace_overwrites_hand_edited_weights(tmp_path):
    path = tmp_path / "entry_points.sqlite3"
    store = SQLiteEntryPointStore(path)
    rows = [_row("ep_a", "com.apple.a", 1.25), _row("ep_b", "com.apple.b", 0.75)]
    asyncio.run(store.replace_ring_node("ring", rows))

    conn = sqlite3.connect(str(path))
    conn.executescript(DDL)
    conn.execute("UPDATE entry_point SET weight = 999.0 WHERE id = 'ep_a'")
    conn.commit()
    conn.close()

    asyncio.run(store.replace_ring_node("ring", rows))
    got = asyncio.run(store.read_ring_node("ring"))
    assert [r["id"] for r in got] == ["ep_a", "ep_b"]
    assert got[0]["weight"] == 1.25


def test_RA_SRF_004_ring_node_isolation_and_order(tmp_path):
    store = SQLiteEntryPointStore(tmp_path / "ep.sqlite")
    asyncio.run(store.replace_ring_node("ring1", [_row("ep_a", "com.apple.a", 0.1)]))
    asyncio.run(store.replace_ring_node("ring2", [_row("ep_b", "com.apple.b", 9.0)]))
    ring1 = asyncio.run(store.read_ring_node("ring1"))
    ring2 = asyncio.run(store.read_ring_node("ring2"))
    assert [r["name"] for r in ring1] == ["com.apple.a"]
    assert [r["name"] for r in ring2] == ["com.apple.b"]


def test_RA_SRF_004_in_memory_store_copies_rows_and_missing_ring_is_empty():
    store = InMemoryEntryPointStore()
    row = _row("ep_a", "com.apple.a", 1.0)
    asyncio.run(store.replace_ring_node("ring", [row]))
    row["name"] = "mutated"
    got = asyncio.run(store.read_ring_node("ring"))
    assert got == [_row("ep_a", "com.apple.a", 1.0)]
    assert asyncio.run(store.read_ring_node("missing")) == []


def test_RA_SRF_004_sqlite_creates_parent_and_reads_empty_ring(tmp_path):
    store = SQLiteEntryPointStore(tmp_path / "nested" / "dir" / "ep.sqlite")
    assert asyncio.run(store.read_ring_node("missing")) == []
    asyncio.run(store.replace_ring_node("ring", []))
    assert asyncio.run(store.read_ring_node("ring")) == []


def test_RA_SRF_004_rows_to_json_and_ledger_payload_mapping():
    row = _row("ep_a", "com.apple.a", 1.5)
    assert rows_to_json([row]) == (
        '[{"id":"ep_a","name":"com.apple.a",'
        '"parser_complexity":0.5,"privilege_delta":1,'
        '"reach_from_json":"[{\\"source\\":\\"image:/x\\",\\"hops\\":2,\\"via\\":\\"dyld-cache\\"}]",'
        '"ring_node":"ring","weight":1.5}]'
    )
    payload = ledger_entry_point_payload(row)
    assert payload == {
        "entry_point_id": "ep_a",
        "name": "com.apple.a",
        "reach_from_json": row["reach_from_json"],
        "privilege_delta": 1,
        "parser_complexity": 0.5,
        "weight": 1.5,
        "ring_node": "ring",
    }
    assert "id" not in payload
