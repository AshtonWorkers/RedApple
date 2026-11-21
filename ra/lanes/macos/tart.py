"""tart VM control for the macOS lane."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Sequence

from ra.lanes.base import LaneError, LaneErrorCode
from ra.lanes.commands import CommandResult, CommandRunner


class TartVMController:
    """Small async wrapper around the tart CLI.

    ``tart run`` is intentionally long-running, so start is performed as a
    detached asyncio subprocess and readiness is polled with ``tart get``.
    """

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner
        self._processes: dict[str, asyncio.subprocess.Process] = {}

    async def get(self, vm: str) -> dict[str, Any] | None:
        """Return ``tart get --format=json`` output, or None if unavailable."""
        res = await self._runner.run(["tart", "get", "--format=json", vm], timeout_s=10)
        if res.returncode != 0 or res.timed_out:
            return None
        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    async def is_running(self, vm: str) -> bool:
        """Whether tart reports the VM as running."""
        info = await self.get(vm)
        return bool(info and info.get("Running") is True)

    async def start(self, vm: str, *, timeout_s: float = 120.0) -> None:
        """Start ``vm`` with ``tart run --no-graphics`` and wait until running."""
        if await self.is_running(vm):
            return
        proc = await asyncio.create_subprocess_exec(
            "tart",
            "run",
            "--no-graphics",
            vm,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._processes[vm] = proc
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if proc.returncode is not None:
                raise LaneError(
                    LaneErrorCode.DEVICE_LOST,
                    f"tart run exited before {vm} was running",
                    details={"vm": vm, "returncode": proc.returncode},
                )
            if await self.is_running(vm):
                return
            await asyncio.sleep(0.5)
        proc.kill()
        await proc.wait()
        raise LaneError(
            LaneErrorCode.DEVICE_LOST,
            f"timed out waiting for tart VM {vm} to run",
            details={"vm": vm, "timeout_s": timeout_s},
        )

    async def exec(
        self,
        vm: str,
        argv: Sequence[str],
        *,
        timeout_s: float | None = None,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        """Execute argv inside the guest through ``tart exec``."""
        return await self._runner.run(
            ["tart", "exec", vm, *argv],
            timeout_s=timeout_s,
            input_bytes=input_bytes,
        )

    async def stop(self, vm: str) -> None:
        """Stop the VM and reap the local ``tart run`` process if present."""
        await self._runner.run(["tart", "stop", vm], timeout_s=30)
        proc = self._processes.pop(vm, None)
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except TimeoutError:
                proc.kill()
                await proc.wait()

    async def close(self) -> None:
        """Terminate any tracked ``tart run`` processes."""
        processes = list(self._processes.values())
        self._processes.clear()
        for proc in processes:
            if proc.returncode is None:
                proc.terminate()
        if not processes:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(*(proc.wait() for proc in processes), return_exceptions=True),
                timeout=10,
            )
        except TimeoutError:
            for proc in processes:
                if proc.returncode is None:
                    proc.kill()
            await asyncio.gather(*(proc.wait() for proc in processes), return_exceptions=True)
