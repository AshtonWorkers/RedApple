"""Async subprocess command runner shared by lanes and discovery components.

Extracted from ``ra.lanes.commands`` so modules outside ``ra.lanes`` (the lane
package is fleet-orchestrated only) can execute argv-only subprocesses without
importing the lanes package. ``ra.lanes.commands`` re-exports these names.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

DEFAULT_KILL_GRACE_S = 1.0


@dataclass(frozen=True)
class CommandResult:
    """Captured result of one argv-only subprocess invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False


class CommandRunner(Protocol):
    """Minimal async command execution interface."""

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> CommandResult: ...


class SubprocessRunner:
    """CommandRunner backed by asyncio subprocesses.

    argv is executed without a shell. ``input_bytes`` is piped to stdin; when it
    is ``None`` stdin is /dev/null so commands cannot block waiting for input.
    Timeouts and cancellation kill the child's whole process group and wait a
    bounded grace period so descendants cannot keep the campaign stuck.
    """

    def __init__(self, *, kill_grace_s: float = DEFAULT_KILL_GRACE_S) -> None:
        if kill_grace_s < 0:
            raise ValueError("kill_grace_s must be non-negative")
        self._kill_grace_s = kill_grace_s

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        if not argv:
            raise ValueError("argv must not be empty")
        if timeout_s is not None and timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        started = time.monotonic()
        merged_env = None if env is None else {**os.environ, **env}
        stdin = asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=merged_env,
            stdin=stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=input_bytes), timeout=timeout_s
            )
            timed_out = False
        except TimeoutError:
            self._kill_process_group(proc)
            await self._wait_for_exit(proc)
            stdout_b, stderr_b = await self._drain_output(proc)
            timed_out = True
        except asyncio.CancelledError:
            self._kill_process_group(proc)
            await self._wait_for_exit(proc)
            raise
        duration_ms = int((time.monotonic() - started) * 1000)
        return CommandResult(
            argv=tuple(argv),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
            duration_ms=duration_ms,
            timed_out=timed_out,
        )

    async def _wait_for_exit(self, proc: asyncio.subprocess.Process) -> None:
        """Wait briefly for a killed process; force-kill once if needed."""
        if proc.returncode is not None:
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=self._kill_grace_s)
            return
        except TimeoutError:
            pass
        with contextlib.suppress(ProcessLookupError, PermissionError):
            proc.kill()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=self._kill_grace_s)

    async def _drain_output(
        self, proc: asyncio.subprocess.Process
    ) -> tuple[bytes, bytes]:
        """Drain pipes after a timeout without letting a stray fd hang forever."""
        if self._kill_grace_s <= 0:
            return b"", b""
        try:
            return await asyncio.wait_for(proc.communicate(), timeout=self._kill_grace_s)
        except TimeoutError:
            return b"", b""

    def _kill_process_group(self, proc: asyncio.subprocess.Process) -> None:
        """Kill the child's process group so descendants cannot hold pipes open."""
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                proc.kill()
