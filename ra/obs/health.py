"""Health endpoint and payload (RA-TOP-003)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable, Mapping
from typing import Any

from ..ledger import Ledger


class HealthServer:
    """Minimal asyncio /healthz HTTP server."""

    def __init__(
        self,
        payload_factory: Callable[[], Mapping[str, Any]],
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self._payload_factory = payload_factory
        self._host = host
        self._port = port
        self._server: asyncio.AbstractServer | None = None
        self._serve_task: asyncio.Task[None] | None = None

    @property
    def port(self) -> int:
        """Bound TCP port."""
        if self._server is None:
            raise RuntimeError("health server is not started")
        sockets = getattr(self._server, "sockets", None)
        if not sockets:
            raise RuntimeError("health server has no bound socket")
        return int(sockets[0].getsockname()[1])

    async def start(self) -> None:
        """Start serving /healthz."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        self._serve_task = asyncio.create_task(self._server.serve_forever())

    async def stop(self) -> None:
        """Stop the health server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._serve_task is not None:
            self._serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._serve_task
            self._serve_task = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            while True:
                line = await reader.readline()
                if line in {b"\r\n", b"\n", b""}:
                    break
            parts = request_line.decode("latin1").split()
            path = parts[1] if len(parts) >= 2 else "/"
            if path == "/healthz" or path.startswith("/healthz?"):
                body = json.dumps(dict(self._payload_factory()), sort_keys=True).encode("utf-8")
                status = b"200 OK"
            else:
                body = b'{"error":"not_found"}'
                status = b"404 Not Found"
            writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n")
            writer.write(
                b"Content-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
            )
            writer.write(body)
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, asyncio.CancelledError):
                await writer.wait_closed()


def health_payload(ledger: Ledger, *, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build the /healthz payload with queue depths, saturation, and cap status."""
    payload = ledger.health()
    actor = payload.get("actor", {})
    if isinstance(actor, dict):
        depth = int(actor.get("queue_depth", 0))
        maximum = int(actor.get("queue_maxsize", 1024))
        payload["mailbox_saturation"] = round(depth / maximum, 4) if maximum else 0.0
    payload["cap_status"] = dict(extra or {})
    return payload
