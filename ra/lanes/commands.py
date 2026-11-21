"""Async subprocess command runner used by lane adapters."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence


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
    """Minimal async command execution interface for lane adapters."""

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
    Timeouts and cancellation kill the child before the error propagates.
    """

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
            await proc.wait()
            stdout_b, stderr_b = await proc.communicate()
            timed_out = True
        except asyncio.CancelledError:
            self._kill_process_group(proc)
            await proc.wait()
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

    @staticmethod
    def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
        """Kill the child's process group so descendants cannot hold pipes open."""
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
