"""Thin `entry_point` persistence interface for RA-SRF.

This module intentionally does not import other `ra/` modules: the M0 ledger
foundation owns the real ledger, and this shim lets RA-SRF land in parallel.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Protocol, Sequence, Union

DDL = """
CREATE TABLE IF NOT EXISTS entry_point (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  reach_from_json TEXT NOT NULL,
  privilege_delta INT NOT NULL,
  parser_complexity REAL NOT NULL,
  weight REAL NOT NULL,
  ring_node TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ep_weight ON entry_point(weight DESC, id);
"""


class EntryPointStore(Protocol):
    async def replace_ring_node(self, ring_node: str, rows: Sequence[Dict[str, Any]]) -> None:
        ...

    async def read_ring_node(self, ring_node: str) -> List[Dict[str, Any]]:
        ...


class InMemoryEntryPointStore:
    def __init__(self) -> None:
        self._rows: Dict[str, List[Dict[str, Any]]] = {}

    async def replace_ring_node(self, ring_node: str, rows: Sequence[Dict[str, Any]]) -> None:
        self._rows[ring_node] = [dict(r) for r in rows]

    async def read_ring_node(self, ring_node: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._rows.get(ring_node, [])]


class SQLiteEntryPointStore:
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path))
        conn.executescript(DDL)
        return conn

    async def replace_ring_node(self, ring_node: str, rows: Sequence[Dict[str, Any]]) -> None:
        payload = [dict(r) for r in rows]

        def _replace() -> None:
            with self._connect() as conn:
                conn.execute("DELETE FROM entry_point WHERE ring_node = ?", (ring_node,))
                conn.executemany(
                    """
                    INSERT INTO entry_point
                      (id, name, reach_from_json, privilege_delta,
                       parser_complexity, weight, ring_node)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            r["id"],
                            r["name"],
                            r["reach_from_json"],
                            int(r["privilege_delta"]),
                            float(r["parser_complexity"]),
                            float(r["weight"]),
                            ring_node,
                        )
                        for r in payload
                    ],
                )
                conn.commit()

        await asyncio.get_running_loop().run_in_executor(None, _replace)

    async def read_ring_node(self, ring_node: str) -> List[Dict[str, Any]]:
        def _read() -> List[Dict[str, Any]]:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    SELECT id, name, reach_from_json, privilege_delta,
                           parser_complexity, weight, ring_node
                    FROM entry_point
                    WHERE ring_node = ?
                    ORDER BY weight DESC, id ASC
                    """,
                    (ring_node,),
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

        return await asyncio.get_running_loop().run_in_executor(None, _read)


def rows_to_json(rows: Iterable[Dict[str, Any]]) -> str:
    return json.dumps(list(rows), sort_keys=True, separators=(",", ":"))
