import asyncio
import sqlite3

import pytest

from ra.ledger import Ledger, LedgerStore
from ra.ledger.operations import LedgerOperation
from tests.conftest import run


def artifact_payload(data: bytes) -> dict[str, object]:
    import hashlib

    digest = hashlib.sha256(data).hexdigest()
    return {
        "artifact_id": "art_" + digest,
        "kind": "crash",
        "sha256": digest,
        "bytes": len(data),
        "created": 1,
        "ttl_class": "run",
    }


def test_sqlite_busy_rejects_writer_until_lock_released(tmp_path):
    path = tmp_path / "busy.sqlite"
    setup = LedgerStore(path)
    setup.close()

    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("BEGIN IMMEDIATE")
    store = LedgerStore(path)
    store._conn.execute("PRAGMA busy_timeout=50")
    operation = LedgerOperation("put_artifact", artifact_payload(b"busy"), rows=1)
    try:
        with pytest.raises(sqlite3.OperationalError):
            store.apply_batch([operation])
    finally:
        raw.execute("ROLLBACK")
        raw.close()

    assert store.apply_batch([operation]) == [operation.payload["artifact_id"]]
    store.close()


def test_two_ledgers_same_file_writer_contention(tmp_path):
    async def body():
        path = tmp_path / "contended.sqlite"
        first = await Ledger.open(path, max_queue=256)
        second = await Ledger.open(path, max_queue=256)
        try:
            await asyncio.gather(
                *(first.put_artifact("crash", f"a-{index}".encode()) for index in range(50)),
                *(second.put_artifact("crash", f"b-{index}".encode()) for index in range(50)),
            )
        finally:
            await first.close()
            await second.close()

        check = await Ledger.open(path)
        try:
            assert check.integrity_check() == "ok"
            assert check.artifact_count() == 100
        finally:
            await check.close()

    run(body())
