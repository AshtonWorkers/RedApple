"""SubprocessRunner tests using harmless local Python commands."""

from __future__ import annotations

import asyncio
import os
import sys
import unittest

from ra.lanes.commands import SubprocessRunner


class SubprocessRunnerTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.runner = SubprocessRunner()

    async def test_empty_argv_rejected(self) -> None:
        with self.assertRaises(ValueError):
            await self.runner.run([])

    async def test_success_captures_output_and_input(self) -> None:
        result = await self.runner.run(
            [
                sys.executable,
                "-c",
                "import sys; data=sys.stdin.buffer.read(); sys.stdout.write('out:'+data.decode()); sys.stderr.write('err')",
            ],
            input_bytes=b"payload",
            env={"RA_TEST_ENV": "present"},
            cwd=os.getcwd(),
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "out:payload")
        self.assertEqual(result.stderr, "err")
        self.assertFalse(result.timed_out)
        self.assertEqual(result.argv[0], sys.executable)
        self.assertGreaterEqual(result.duration_ms, 0)

    async def test_nonzero_return_code_is_captured(self) -> None:
        result = await self.runner.run(
            [sys.executable, "-c", "import sys; sys.stderr.write('bad'); sys.exit(3)"]
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, "bad")

    async def test_timeout_kills_process_and_marks_timed_out(self) -> None:
        result = await self.runner.run(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_s=0.05,
        )
        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.returncode, 0)

    async def test_cancellation_kills_process(self) -> None:
        task = asyncio.create_task(
            self.runner.run(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout_s=5,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task


if __name__ == "__main__":
    unittest.main()
