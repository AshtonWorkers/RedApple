"""TartVMController tests with a fake runner and fake tart run processes."""

from __future__ import annotations

import unittest
from unittest import mock

from ra.lanes.base import LaneError, LaneErrorCode
from ra.lanes.commands import CommandResult
from ra.lanes.macos.tart import TartVMController


def cmd(argv, *, rc: int = 0, out: str = "", err: str = "") -> CommandResult:
    return CommandResult(tuple(argv), rc, out, err, 1)


class FakeRunner:
    def __init__(self, *, get_rc: int = 0, get_stdout: str = '{"Running": false}') -> None:
        self.get_rc = get_rc
        self.get_stdout = get_stdout
        self.get_calls = 0
        self.calls: list[tuple[str, ...]] = []

    async def run(self, argv, **kwargs) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:3] == ("tart", "get", "--format=json"):
            self.get_calls += 1
            return cmd(argv, rc=self.get_rc, out=self.get_stdout, err="get failed" if self.get_rc else "")
        return cmd(argv)


class FakeProc:
    def __init__(self, *, returncode: int | None = None) -> None:
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.waits = 0

    def terminate(self) -> None:
        self.terminated = True
        if self.returncode is None:
            self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        self.waits += 1
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class TartVMControllerTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_and_is_running(self) -> None:
        runner = FakeRunner(get_stdout='{"Running": true, "Name": "vm"}')
        controller = TartVMController(runner)
        self.assertEqual(await controller.get("vm"), {"Running": True, "Name": "vm"})
        self.assertTrue(await controller.is_running("vm"))

        runner = FakeRunner(get_stdout='["not", "dict"]')
        controller = TartVMController(runner)
        self.assertIsNone(await controller.get("vm"))
        self.assertFalse(await controller.is_running("vm"))

        runner = FakeRunner(get_rc=1)
        controller = TartVMController(runner)
        self.assertIsNone(await controller.get("vm"))

    async def test_start_returns_when_already_running(self) -> None:
        runner = FakeRunner(get_stdout='{"Running": true}')
        controller = TartVMController(runner)
        with mock.patch("asyncio.create_subprocess_exec") as create:
            await controller.start("vm", timeout_s=1)
        create.assert_not_called()

    async def test_start_launches_and_tracks_process(self) -> None:
        runner = FakeRunner(get_stdout='{"Running": false}')
        # First is_running poll before launch is false; the next poll is true.
        runner.get_stdout = '{"Running": false}'
        controller = TartVMController(runner)
        outputs = iter(['{"Running": false}', '{"Running": true}'])

        async def fake_run(argv, **kwargs):
            if argv[:3] == ["tart", "get", "--format=json"]:
                return cmd(argv, out=next(outputs))
            return await FakeRunner.run(runner, argv, **kwargs)

        runner.run = fake_run  # type: ignore[method-assign]
        proc = FakeProc()
        with mock.patch("asyncio.create_subprocess_exec", new=mock.AsyncMock(return_value=proc)) as create:
            await controller.start("vm", timeout_s=5)
        create.assert_awaited_once()
        self.assertEqual(controller._processes["vm"], proc)

    async def test_start_fails_when_tart_run_exits(self) -> None:
        runner = FakeRunner(get_stdout='{"Running": false}')
        controller = TartVMController(runner)
        proc = FakeProc(returncode=1)
        with (
            mock.patch("asyncio.create_subprocess_exec", new=mock.AsyncMock(return_value=proc)),
            self.assertRaises(LaneError) as cm,
        ):
            await controller.start("vm", timeout_s=1)
        self.assertIs(cm.exception.code, LaneErrorCode.DEVICE_LOST)

    async def test_start_times_out_and_kills_process(self) -> None:
        runner = FakeRunner(get_stdout='{"Running": false}')
        controller = TartVMController(runner)
        proc = FakeProc()
        with (
            mock.patch("asyncio.create_subprocess_exec", new=mock.AsyncMock(return_value=proc)),
            self.assertRaises(LaneError) as cm,
        ):
            await controller.start("vm", timeout_s=0.1)
        self.assertIs(cm.exception.code, LaneErrorCode.DEVICE_LOST)
        self.assertTrue(proc.killed)
        self.assertGreaterEqual(proc.waits, 1)

    async def test_exec_stop_and_close(self) -> None:
        runner = FakeRunner(get_stdout='{"Running": false}')
        controller = TartVMController(runner)
        await controller.exec("vm", ["tool"], input_bytes=b"x", timeout_s=3)
        self.assertIn(("tart", "exec", "-i", "vm", "tool"), runner.calls)

        proc = FakeProc()
        controller._processes["vm"] = proc
        await controller.stop("vm")
        self.assertIn(("tart", "stop", "vm"), runner.calls)
        self.assertTrue(proc.terminated)

        proc2 = FakeProc()
        controller._processes["other"] = proc2
        await controller.close()
        self.assertTrue(proc2.terminated)
        self.assertEqual(proc2.waits, 1)


if __name__ == "__main__":
    unittest.main()
