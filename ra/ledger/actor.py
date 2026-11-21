"""Single-writer ledger actor with bounded mailbox and batched commits."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Mapping
from typing import Any

from ..errors import RaError
from .db import LedgerStore
from .operations import LedgerOperation


class LedgerActor:
    """One asyncio task owns all ledger writes (RA-TOP-001, RA-LED-006)."""

    def __init__(
        self,
        store: LedgerStore,
        *,
        max_batch_rows: int = 200,
        max_batch_ms: int = 25,
        max_queue: int = 1024,
    ) -> None:
        self._store = store
        self._max_batch_rows = max_batch_rows
        self._max_batch_ms = max_batch_ms
        self._queue: asyncio.Queue[LedgerOperation] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None
        self._stopped = False
        self._closing = False
        self._state_lock = asyncio.Lock()
        self._max_depth = 0
        self._batches = 0
        self._rows = 0
        self._commit_ms_total = 0.0
        self._commit_ms_samples: list[float] = []

    async def start(self) -> None:
        """Start the writer task."""
        if self._task is None and not self._stopped:
            self._task = asyncio.create_task(self._run(), name="ra-ledger-actor")

    async def stop(self) -> None:
        """Reject new writes, wait for queued writes, then stop the writer task."""
        if self._task is None:
            self._closing = True
            self._stopped = True
            return
        async with self._state_lock:
            self._closing = True
        await self._queue.join()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        self._stopped = True

    async def submit(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        rows: int = 1,
        telemetry: bool = False,
    ) -> object:
        """Submit one write; producers await when the bounded mailbox is full."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[object] = loop.create_future()
        operation = LedgerOperation(kind=kind, payload=payload, rows=rows, future=future)
        async with self._state_lock:
            if self._closing or self._stopped:
                raise RaError("ledger actor is stopped", code="LEDGER_STOPPED")
            if telemetry and self._queue.full():
                return None
            await self._queue.put(operation)
            self._max_depth = max(self._max_depth, self._queue.qsize())
        return await future

    def stats(self) -> dict[str, int | float]:
        """Return mailbox/batch telemetry for /healthz."""
        return {
            "queue_depth": self._queue.qsize(),
            "queue_maxsize": self._queue.maxsize,
            "queue_max_depth": self._max_depth,
            "batches": self._batches,
            "rows": self._rows,
            "commit_ms_avg": (self._commit_ms_total / self._batches) if self._batches else 0.0,
            "commit_ms_p99": _percentile(self._commit_ms_samples, 0.99),
            "commit_ms_max": max(self._commit_ms_samples, default=0.0),
        }

    async def _run(self) -> None:
        while True:
            first = await self._queue.get()
            batch = [first]
            rows = first.rows
            deadline = time.monotonic() + (self._max_batch_ms / 1000.0)
            while rows < self._max_batch_rows and len(batch) < self._max_batch_rows:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout)
                except TimeoutError:
                    break
                batch.append(item)
                rows += item.rows
            started = time.perf_counter()
            with contextlib.suppress(Exception):
                # Futures already carry the failure; the writer stays alive.
                self._store.apply_batch(batch)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self._batches += 1
            self._rows += sum(op.rows for op in batch)
            self._commit_ms_total += elapsed_ms
            self._commit_ms_samples.append(elapsed_ms)
            for _ in batch:
                self._queue.task_done()


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * q))
    return ordered[index]
