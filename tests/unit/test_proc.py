"""Tests for ``ra.proc`` async subprocess runner."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from ra.proc import CommandResult, SubprocessRunner


class FakeProc:
    def __init__(
        self,
        *,
        returncode: int | None = None,
        wait_delay: float = 0.0,
        communicate_result: tuple[bytes, bytes] = (b"", b""),
    ) -> None:
        self.returncode = returncode
        self.pid = 424242
        self.killed = False
        self.communicate_calls = 0
        self._wait_delay = wait_delay
        self._communicate_result = communicate_result

    async def wait(self) -> int | None:
        if self._wait_delay:
            await asyncio.sleep(self._wait_delay)
        return self.returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        self.communicate_calls += 1
        if self._wait_delay:
            await asyncio.sleep(self._wait_delay)
        return self._communicate_result

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class SubprocessRunnerTest(unittest.IsolatedAsyncioTestCase):
    async def test_echo_roundtrip(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run([sys.executable, "-c", "print('hello')"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "hello")
        self.assertEqual(result.stderr, "")
        self.assertFalse(result.timed_out)
        self.assertGreaterEqual(result.duration_ms, 0)

    async def test_stderr_captured(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run(
            [sys.executable, "-c", "import sys; sys.stderr.write('oops')"]
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "oops")

    async def test_nonzero_returncode(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run([sys.executable, "-c", "raise SystemExit(3)"])
        self.assertEqual(result.returncode, 3)

    async def test_empty_argv_rejected(self) -> None:
        runner = SubprocessRunner()
        with self.assertRaises(ValueError):
            await runner.run([])

    async def test_nonpositive_timeout_rejected(self) -> None:
        runner = SubprocessRunner()
        with self.assertRaises(ValueError):
            await runner.run([sys.executable, "-c", "pass"], timeout_s=0)
        with self.assertRaises(ValueError):
            await runner.run([sys.executable, "-c", "pass"], timeout_s=-1)

    def test_negative_kill_grace_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SubprocessRunner(kill_grace_s=-0.1)

    async def test_missing_binary_raises(self) -> None:
        runner = SubprocessRunner()
        with self.assertRaises(FileNotFoundError):
            await runner.run(["/nonexistent/ra-proc-binary"])

    async def test_timeout_kills_process(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout_s=0.2
        )
        self.assertTrue(result.timed_out)

    async def test_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "descendant-survived"
            child_code = (
                "import time; time.sleep(0.5); "
                f"open({marker.as_posix()!r}, 'w').write('x')"
            )
            code = (
                "import subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', "
                + repr(child_code)
                + "]); time.sleep(30)"
            )
            runner = SubprocessRunner(kill_grace_s=0.2)
            result = await runner.run([sys.executable, "-c", code], timeout_s=0.2)
            self.assertTrue(result.timed_out)
            await asyncio.sleep(0.8)
            self.assertFalse(marker.exists())

    async def test_input_bytes_piped_to_stdin(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run(
            [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
            input_bytes=b"ping",
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "PING")

    async def test_env_merged_over_os_environ(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run(
            [sys.executable, "-c", "import os; print(os.environ.get('RA_PROC_TEST'))"],
            env={"RA_PROC_TEST": "present"},
        )
        self.assertEqual(result.stdout.strip(), "present")

    async def test_cwd_used(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run(
            [sys.executable, "-c", "import os; print(os.getcwd())"], cwd="/tmp"
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip().startswith("/tmp"))

    async def test_process_group_kill_on_cancel(self) -> None:
        runner = SubprocessRunner()
        task = asyncio.ensure_future(
            runner.run(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout_s=30
            )
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_wait_for_exit_returns_when_already_exited(self) -> None:
        runner = SubprocessRunner(kill_grace_s=0.01)
        proc = FakeProc(returncode=0)
        await runner._wait_for_exit(proc)  # type: ignore[arg-type]
        self.assertFalse(proc.killed)

    async def test_wait_for_exit_force_kills_after_grace(self) -> None:
        runner = SubprocessRunner(kill_grace_s=0.01)
        proc = FakeProc(returncode=None, wait_delay=0.05)
        await runner._wait_for_exit(proc)  # type: ignore[arg-type]
        self.assertTrue(proc.killed)

    async def test_drain_output_zero_grace_returns_empty(self) -> None:
        runner = SubprocessRunner(kill_grace_s=0)
        proc = FakeProc(communicate_result=(b"x", b"y"))
        result = await runner._drain_output(proc)  # type: ignore[arg-type]
        self.assertEqual(result, (b"", b""))
        self.assertEqual(proc.communicate_calls, 0)

    async def test_drain_output_timeout_returns_empty(self) -> None:
        runner = SubprocessRunner(kill_grace_s=0.01)
        proc = FakeProc(wait_delay=0.05, communicate_result=(b"x", b"y"))
        result = await runner._drain_output(proc)  # type: ignore[arg-type]
        self.assertEqual(result, (b"", b""))
        self.assertEqual(proc.communicate_calls, 1)

    def test_kill_process_group_returns_when_exited(self) -> None:
        runner = SubprocessRunner()
        proc = FakeProc(returncode=0)
        runner._kill_process_group(proc)  # type: ignore[arg-type]
        self.assertFalse(proc.killed)

    def test_kill_process_group_falls_back_to_proc_kill(self) -> None:
        runner = SubprocessRunner()
        proc = FakeProc(returncode=None)
        with unittest.mock.patch("ra.proc.os.killpg", side_effect=PermissionError):
            runner._kill_process_group(proc)  # type: ignore[arg-type]
        self.assertTrue(proc.killed)

    def test_command_result_defaults(self) -> None:
        result = CommandResult(
            argv=("a",), returncode=0, stdout="", stderr="", duration_ms=0
        )
        self.assertFalse(result.timed_out)

    async def test_signal_death_returncode(self) -> None:
        runner = SubprocessRunner()
        result = await runner.run([sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"])
        self.assertNotEqual(result.returncode, 0)
