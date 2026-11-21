"""Unit tests for the macOS tart VM lane (guest boundary faked)."""

from __future__ import annotations

import unittest

from ra.lanes.base import (
    CrashRef,
    DeviceProfile,
    FeedResult,
    HarnessRef,
    HumanCard,
    LaneError,
    LaneErrorCode,
    ProvisionState,
    Thermal,
    Tier,
)
from ra.lanes.commands import CommandResult
from ra.lanes.macos import MacOSVMLane, TartVMController


def cmd(argv, *, rc: int = 0, out: str = "", err: str = "", timed_out: bool = False) -> CommandResult:
    return CommandResult(
        argv=tuple(argv),
        returncode=rc,
        stdout=out,
        stderr=err,
        duration_ms=1,
        timed_out=timed_out,
    )


class FakeRunner:
    def __init__(self, *, version_rc: int = 0, list_rc: int = 0, list_stdout: str = "redapple-macos\n") -> None:
        self.version_rc = version_rc
        self.list_rc = list_rc
        self.list_stdout = list_stdout
        self.calls: list[tuple[str, ...]] = []

    async def run(self, argv, **kwargs) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:2] == ("tart", "--version"):
            return cmd(argv, rc=self.version_rc, out="tart 2.5.0\n" if self.version_rc == 0 else "", err="bad" if self.version_rc else "")
        if argv[:2] == ("tart", "list"):
            return cmd(argv, rc=self.list_rc, out=self.list_stdout, err="bad" if self.list_rc else "")
        return cmd(argv)


class FakeTartController:
    def __init__(
        self,
        *,
        running: bool = True,
        feed_rc: int = 0,
        missing: str | None = None,
        crash_stdout: str = "",
        build_rc: int = 0,
        build_stderr: str = "",
        crash_rc: int = 0,
        pmset_stdout: str | None = None,
        thermal: Thermal = Thermal.NOMINAL,
    ) -> None:
        self.running = running
        self.feed_rc = feed_rc
        self.missing = missing
        self.crash_stdout = crash_stdout
        self.build_rc = build_rc
        self.build_stderr = build_stderr
        self.crash_rc = crash_rc
        self.pmset_stdout = pmset_stdout
        self.thermal = thermal
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.closed = False
        self.exec_calls: list[tuple[str, tuple[str, ...], dict]] = []

    async def start(self, vm: str, *, timeout_s: float = 120.0) -> None:
        self.started.append(vm)

    async def is_running(self, vm: str) -> bool:
        return self.running

    async def exec(self, vm: str, argv, **kwargs) -> CommandResult:
        argv = tuple(str(part) for part in argv)
        self.exec_calls.append((vm, argv, kwargs))
        text = argv[-1] if argv else ""
        if "command -v" in text:
            if self.missing:
                return cmd(argv, rc=1, err=f"missing:{self.missing}\n")
            return cmd(argv)
        if "xcodes installed" in text:
            return cmd(argv, out="17.0\n")
        if "xcodes select" in text:
            return cmd(argv)
        if "sccache --show-stats" in text:
            return cmd(argv, out="Compile requests 1\n")
        if "xcodebuild -version" in text:
            return cmd(argv, out="Xcode 16.0\n")
        if "build-webkit" in text:
            return cmd(argv, rc=self.build_rc, out="build ok\n" if self.build_rc == 0 else "", err=self.build_stderr)
        if "DiagnosticReports" in text or ".ips" in text:
            return cmd(argv, rc=self.crash_rc, out=self.crash_stdout, err="crash collect failed" if self.crash_rc else "")
        if "pmset" in text:
            return cmd(argv, out=self.pmset_stdout if self.pmset_stdout is not None else f"{self.thermal.value}\n")
        return cmd(argv, rc=self.feed_rc, out="feed out\n", err="feed err\n")

    async def stop(self, vm: str) -> None:
        self.stopped.append(vm)
        self.running = False

    async def close(self) -> None:
        self.closed = True


class MacOSVMLaneTest(unittest.IsolatedAsyncioTestCase):
    def make_profile(self, **metadata) -> DeviceProfile:
        return DeviceProfile(
            udid="vm-macos",
            ring_node="node-macos",
            state="attached",
            tier=Tier.A,
            build="macos-15",
            metadata=dict(metadata),
        )

    def make_lane(self, runner: FakeRunner, controller: FakeTartController, **kwargs) -> tuple[MacOSVMLane, list[HumanCard]]:
        cards: list[HumanCard] = []
        lane = MacOSVMLane(
            runner=runner,
            controller=controller,
            card_sink=cards.append,
            which=lambda name: "/opt/homebrew/bin/tart" if name == "tart" else None,
            **kwargs,
        )
        return lane, cards

    async def test_provision_ready_when_tart_and_vm_exist(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController()
        lane, cards = self.make_lane(runner, controller)
        profile = self.make_profile()
        result = await lane.provision(profile)

        self.assertIs(result.state, ProvisionState.READY)
        self.assertIs(result.tier, Tier.A)
        self.assertEqual(profile.state, "ready")
        self.assertEqual(cards, [])
        self.assertEqual(result.details["vm"], "redapple-macos")
        self.assertIn(("tart", "--version"), runner.calls)
        self.assertTrue(any(call[:2] == ("tart", "list") for call in runner.calls))

    async def test_missing_tart_parks_needs_hand_with_one_card(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController()
        lane, cards = self.make_lane(runner, controller)
        lane._which = lambda name: None
        result = await lane.provision(self.make_profile())

        self.assertIs(result.state, ProvisionState.NEEDS_HAND)
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].action, "install_macos_lane_tools")
        self.assertEqual(cards[0].device_udid, "vm-macos")
        self.assertEqual(runner.calls, [])

    async def test_missing_vm_image_parks_needs_hand(self) -> None:
        runner = FakeRunner(list_stdout="other-vm\n")
        controller = FakeTartController()
        lane, cards = self.make_lane(runner, controller)
        result = await lane.provision(self.make_profile())

        self.assertIs(result.state, ProvisionState.NEEDS_HAND)
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].action, "create_tart_vm")

    async def test_launch_builds_jsc_only_and_feed_maps_results(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController(feed_rc=0)
        lane, cards = self.make_lane(
            runner,
            controller,
            sccache=True,
            pinned_xcode_version=None,
            webkit_dir="/Users/devin/webkit",
        )
        await lane.provision(self.make_profile())
        harness = HarnessRef(
            name="imageio",
            argv=["feed-tool"],
            metadata={"build_webkit": True, "build_args": ["--release"]},
        )
        handle = await lane.launch("imageio", harness)

        self.assertEqual(controller.started, ["redapple-macos"])
        exec_text = "\n".join(argv[-1] for _, argv, _ in controller.exec_calls if "-lc" in argv)
        self.assertIn("export WK_USE_SCCACHE=YES", exec_text)
        self.assertIn("Tools/Scripts/build-webkit --jsc-only --release", exec_text)
        self.assertEqual(cards, [])

        self.assertIs(await lane.feed(handle, b"bytes"), FeedResult.ACCEPTED)
        controller.feed_rc = 75
        self.assertIs(await lane.feed(handle, b"bytes"), FeedResult.SATURATED)
        controller.feed_rc = 1
        self.assertIs(await lane.feed(handle, b"bytes"), FeedResult.REJECTED)

    async def test_collect_crashes_then_reset(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController(
            crash_stdout="/Library/Logs/DiagnosticReports/a.ips\n/Library/Logs/DiagnosticReports/b.crash\n"
        )
        lane, _ = self.make_lane(runner, controller, sccache=False)
        await lane.provision(self.make_profile())
        handle = await lane.launch(
            "imageio", HarnessRef(name="h", argv=["feed-tool"], metadata={"build_webkit": False})
        )

        refs = await lane.collect_crashes(handle)
        self.assertEqual(len(refs), 2)
        self.assertTrue(all(isinstance(ref, CrashRef) for ref in refs))
        self.assertEqual(refs[0].kind, "macos_vm_crash")
        self.assertEqual(refs[0].context, "app")

        await lane.reset(handle)
        self.assertEqual(controller.stopped, ["redapple-macos"])
        self.assertTrue(handle.reset)

    async def test_guest_tool_gap_emits_card_and_parks_needs_hand(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController(missing="sccache")
        lane, cards = self.make_lane(
            runner,
            controller,
            sccache=True,
            pinned_xcode_version="17.0",
            webkit_dir=None,
        )
        profile = self.make_profile()
        await lane.provision(profile)
        harness = HarnessRef(name="h", argv=["feed-tool"], metadata={"build_webkit": False})
        with self.assertRaises(LaneError) as cm:
            await lane.launch("target", harness)
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)
        self.assertEqual(profile.state, "needs_hand")
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].action, "provision_vm_tools")
        self.assertIn("sccache", cards[0].instruction)

    async def test_tart_exec_forwards_stdin_with_dash_i(self) -> None:
        runner = FakeRunner()
        controller = TartVMController(runner)
        await controller.exec("redapple-macos", ["feed-tool"], input_bytes=b"payload")
        self.assertEqual(runner.calls, [("tart", "exec", "-i", "redapple-macos", "feed-tool")])

    async def test_pmset_no_thermal_warning_is_nominal(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController(pmset_stdout="No thermal warning level has been recorded\n")
        lane, _ = self.make_lane(runner, controller, sccache=False)
        await lane.provision(self.make_profile())
        self.assertIs(await lane.thermal(), Thermal.NOMINAL)
        self.assertFalse(lane.paused)

    async def test_crash_collection_failure_raises(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController(crash_rc=1)
        lane, _ = self.make_lane(runner, controller, sccache=False)
        await lane.provision(self.make_profile())
        handle = await lane.launch(
            "imageio", HarnessRef(name="h", argv=["feed-tool"], metadata={"build_webkit": False})
        )
        with self.assertRaises(LaneError) as cm:
            await lane.collect_crashes(handle)
        self.assertIs(cm.exception.code, LaneErrorCode.DEVICE_LOST)
        self.assertFalse(handle.crashes_collected)

    async def test_thermal_reader_drives_critical_drain(self) -> None:
        runner = FakeRunner()
        controller = FakeTartController()
        lane, _ = self.make_lane(runner, controller, sccache=False, thermal_reader=lambda: Thermal.CRITICAL)
        await lane.provision(self.make_profile())
        self.assertIs(await lane.thermal(), Thermal.CRITICAL)
        self.assertTrue(lane.drained)


if __name__ == "__main__":
    unittest.main()
