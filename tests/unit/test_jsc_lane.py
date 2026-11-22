"""Tests for ``ra.lanes.jsc`` JSC discovery lane adapter."""

from __future__ import annotations

import signal
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from ra.discovery.store import CampaignSummary, CrashRecord
from ra.lanes.base import (
    CrashRef,
    DeviceProfile,
    FeedStatus,
    Handle,
    HarnessRef,
    LaneError,
    LaneErrorCode,
    ProvisionState,
    Tier,
)
from ra.lanes.jsc import JSC_DISCOVERY_CAPABILITIES, JscDiscoveryLane, crash_ref_for_record
from ra.proc import CommandResult


def ok(argv: Sequence[str], **overrides: object) -> CommandResult:
    base: dict[str, object] = {
        "argv": tuple(argv),
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "duration_ms": 1,
        "timed_out": False,
    }
    base.update(overrides)
    return CommandResult(**base)  # type: ignore[arg-type]


class FakeCommandRunner:
    def __init__(self, results: Sequence[CommandResult | Exception] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[list[str]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        self.calls.append(list(argv))
        if not self.results:
            return ok(argv)
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeSink:
    def __init__(self) -> None:
        self.known: set[str] = set()
        self.records: list[CrashRecord] = []
        self.campaigns: list[CampaignSummary] = []
        self._counter = 0

    async def known_signatures(self) -> set[str]:
        return set(self.known)

    async def record_crash(
        self, content: str | bytes, result, meta: Mapping[str, object]
    ) -> CrashRecord | None:
        if result.signature in self.known:
            return None
        self.known.add(result.signature)
        self._counter += 1
        data = content if isinstance(content, bytes) else content.encode()
        record = CrashRecord(
            claim_id=f"jsc_{self._counter:04d}",
            signature=result.signature,
            crash_type=result.crash_type,
            signal=result.signal,
            returncode=result.returncode,
            stack=result.stack,
            input_js=data,
            stderr=result.stderr,
            handle_id=str(meta.get("handle_id", "")),
            target=str(meta.get("target", "")),
            ring_node=None,
            build=None,
            artifact_ids=("art_x",),
            created_ms=self._counter,
            campaign_id=None,
            metadata={},
        )
        self.records.append(record)
        return record

    async def record_campaign(self, summary: CampaignSummary) -> str:
        self.campaigns.append(summary)
        return f"camp_{len(self.campaigns)}"

    async def crashes_for_handle(self, handle_id: str) -> list[CrashRecord]:
        return [r for r in self.records if r.handle_id == handle_id]


def profile(**overrides: object) -> DeviceProfile:
    base: dict[str, object] = {
        "udid": "host-1",
        "ring_node": "node-1",
        "state": "attached",
        "tier": Tier.B,
        "build": "webkit-1",
    }
    base.update(overrides)
    return DeviceProfile(**base)  # type: ignore[arg-type]


class JscDiscoveryLaneProvisionTest(unittest.IsolatedAsyncioTestCase):
    async def test_capability(self) -> None:
        lane = JscDiscoveryLane(sink=FakeSink())
        tier, caps = lane.capability()
        self.assertIs(tier, Tier.B)
        self.assertEqual(caps, JSC_DISCOVERY_CAPABILITIES)
        self.assertEqual(lane.name, "jsc-discovery")

    async def test_provision_explicit_binary_on_linux(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jsc"
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o755)
            lane = JscDiscoveryLane(sink=FakeSink(), jsc_binary=str(binary), platform="linux")
            result = await lane.provision(profile())
            self.assertTrue(result.ready)
            self.assertEqual(result.state, ProvisionState.READY)
            self.assertEqual(result.details["jsc_binary"], str(binary))
            self.assertEqual(result.details["jsc_binary_source"], "explicit")
            self.assertIn("--useDollarVM=1", result.details["jsc_args"])
            self.assertTrue(lane.ready)

    async def test_provision_darwin_uses_path(self) -> None:
        lane = JscDiscoveryLane(
            sink=FakeSink(), platform="darwin", which=lambda name: "/usr/bin/jsc" if name == "jsc" else None
        )
        result = await lane.provision(profile())
        self.assertTrue(result.ready)
        self.assertEqual(result.details["jsc_binary_source"], "path")

    async def test_provision_linux_without_binary_needs_hand(self) -> None:
        cards: list[object] = []
        lane = JscDiscoveryLane(
            sink=FakeSink(), platform="linux", which=lambda name: None, card_sink=cards.append
        )
        result = await lane.provision(profile())
        self.assertEqual(result.state, ProvisionState.NEEDS_HAND)
        self.assertIsNotNone(result.human_card)
        assert result.human_card is not None
        self.assertEqual(result.human_card.blocker, "jsc_requires_macos_or_explicit_binary")
        self.assertEqual(len(cards), 1)
        self.assertFalse(lane.ready)

    async def test_provision_darwin_missing_binary_needs_hand(self) -> None:
        lane = JscDiscoveryLane(sink=FakeSink(), platform="darwin", which=lambda name: None)
        result = await lane.provision(profile())
        self.assertEqual(result.state, ProvisionState.NEEDS_HAND)
        assert result.human_card is not None
        self.assertEqual(result.human_card.blocker, "jsc_binary_missing")

    async def test_provision_explicit_binary_invalid_needs_hand(self) -> None:
        lane = JscDiscoveryLane(
            sink=FakeSink(), jsc_binary="/nonexistent/jsc", platform="linux"
        )
        result = await lane.provision(profile())
        self.assertEqual(result.state, ProvisionState.NEEDS_HAND)
        assert result.human_card is not None
        self.assertEqual(result.human_card.blocker, "jsc_binary_invalid")

    async def test_provision_binary_from_profile_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jsc"
            binary.write_text("x")
            binary.chmod(0o755)
            lane = JscDiscoveryLane(sink=FakeSink(), platform="linux")
            p = profile(metadata={"jsc_binary": str(binary)})
            result = await lane.provision(p)
            self.assertTrue(result.ready)

    async def test_provision_explicit_name_resolved_via_which(self) -> None:
        lane = JscDiscoveryLane(
            sink=FakeSink(),
            jsc_binary="custom-jsc",
            platform="linux",
            which=lambda name: "/opt/bin/custom-jsc" if name == "custom-jsc" else None,
        )
        result = await lane.provision(profile())
        self.assertTrue(result.ready)
        self.assertEqual(result.details["jsc_binary_source"], "explicit")

    async def test_provision_explicit_name_unresolvable_needs_hand(self) -> None:
        lane = JscDiscoveryLane(
            sink=FakeSink(), jsc_binary="custom-jsc", platform="linux", which=lambda name: None
        )
        result = await lane.provision(profile())
        self.assertEqual(result.state, ProvisionState.NEEDS_HAND)
        assert result.human_card is not None
        self.assertEqual(result.human_card.blocker, "jsc_binary_invalid")

    async def test_provision_ring_gate(self) -> None:
        class DenyRing:
            def allows(self, ring_node: str, build: str | None) -> bool:
                return False

        lane = JscDiscoveryLane(sink=FakeSink(), ring=DenyRing())
        with self.assertRaises(LaneError) as cm:
            await lane.provision(profile())
        self.assertIs(cm.exception.code, LaneErrorCode.OUT_OF_RING)

    async def test_provision_rejects_not_provisioned_launch(self) -> None:
        lane = JscDiscoveryLane(sink=FakeSink(), platform="linux", which=lambda name: None)
        with self.assertRaises(LaneError) as cm:
            await lane.launch("t", HarnessRef(name="h"))
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)


class JscDiscoveryLaneFeedTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        binary = Path(self._tmp.name) / "jsc"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        self.sink = FakeSink()
        self.runner_impl = FakeCommandRunner()
        self.lane = JscDiscoveryLane(
            sink=self.sink,
            jsc_binary=str(binary),
            platform="linux",
            command_runner=self.runner_impl,
            jsc_args=("--test-flag",),
        )
        await self.lane.provision(profile())
        self.handle = await self.lane.launch("webkit-jsc", HarnessRef(name="jsc", kind="command"))

    async def asyncTearDown(self) -> None:
        self._tmp.cleanup()

    async def test_launch_stores_runner_and_corpus(self) -> None:
        state = self.handle.metadata["jsc"]
        self.assertIn("runner", state)
        self.assertGreaterEqual(len(state["corpus"]), 8)
        config = state["config"]
        self.assertEqual(config.args, ("--test-flag",))

    async def test_feed_success_accepted(self) -> None:
        result = await self.lane.feed(self.handle, b"print(1);")
        self.assertIs(result.status, FeedStatus.ACCEPTED)
        stats = self.handle.metadata["jsc_stats"]
        self.assertEqual(stats["executions"], 1)
        argv = self.runner_impl.calls[0]
        self.assertIn("--test-flag", argv)
        self.assertTrue(argv[-1].endswith(".js"))

    async def test_feed_crash_recorded_and_collected(self) -> None:
        self.runner_impl.results.append(
            ok(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv\n")
        )
        result = await self.lane.feed(self.handle, b"crashme();")
        self.assertIs(result.status, FeedStatus.ACCEPTED)
        stats = self.handle.metadata["jsc_stats"]
        self.assertEqual(stats["crashes"], 1)
        self.assertEqual(len(self.sink.records), 1)
        self.assertEqual(self.sink.records[0].handle_id, self.handle.handle_id)

        refs = await self.lane.collect_crashes(self.handle)
        self.assertEqual(len(refs), 1)
        ref = refs[0]
        self.assertIsInstance(ref, CrashRef)
        self.assertEqual(ref.kind, "jsc_crash")
        self.assertEqual(ref.handle_id, self.handle.handle_id)
        self.assertEqual(ref.payload, b"crashme();")
        self.assertEqual(ref.digest, self.sink.records[0].signature)
        self.assertEqual(ref.context, "app")
        self.assertIn("stack", ref.metadata)

        # Second collect returns nothing (already handed out)
        refs2 = await self.lane.collect_crashes(self.handle)
        self.assertEqual(refs2, [])

    async def test_feed_binary_malformed_input_accepted_without_crash(self) -> None:
        result = await self.lane.feed(self.handle, b"\x00\xff\xfe binary")
        self.assertIs(result.status, FeedStatus.ACCEPTED)
        self.assertEqual(self.handle.metadata["jsc_stats"]["executions"], 1)
        self.assertEqual(self.sink.records, [])

    async def test_feed_exec_error_rejected(self) -> None:
        self.runner_impl.results.append(FileNotFoundError("missing"))
        result = await self.lane.feed(self.handle, b"x")
        self.assertIs(result.status, FeedStatus.REJECTED)
        stats = self.handle.metadata["jsc_stats"]
        self.assertEqual(stats["exec_errors"], 1)
        self.assertIn("missing", stats["last_exec_error"])

    async def test_feed_timeout_accepted(self) -> None:
        self.runner_impl.results.append(ok(["jsc"], timed_out=True, returncode=-1))
        result = await self.lane.feed(self.handle, b"slow();")
        self.assertIs(result.status, FeedStatus.ACCEPTED)
        self.assertEqual(self.handle.metadata["jsc_stats"]["timeouts"], 1)

    async def test_duplicate_crash_signature_not_duplicated(self) -> None:
        crash = ok(["jsc"], returncode=-int(signal.SIGSEGV), stderr="same fault\n")
        self.runner_impl.results.extend([crash, crash])
        await self.lane.feed(self.handle, b"one();")
        await self.lane.feed(self.handle, b"two();")
        self.assertEqual(len(self.sink.records), 1)
        refs = await self.lane.collect_crashes(self.handle)
        self.assertEqual(len(refs), 1)

    async def test_reset_requires_collect(self) -> None:
        with self.assertRaises(LaneError) as cm:
            await self.lane.reset(self.handle)
        self.assertIs(cm.exception.code, LaneErrorCode.FORMAT_FAIL)
        await self.lane.collect_crashes(self.handle)
        await self.lane.reset(self.handle)
        self.assertTrue(self.handle.reset)

    async def test_feed_unknown_handle_rejected(self) -> None:
        foreign = Handle(id="nope", udid="", target="t", lane="other", harness=HarnessRef(name="h"))
        with self.assertRaises(LaneError) as cm:
            await self.lane.feed(foreign, b"x")
        self.assertIs(cm.exception.code, LaneErrorCode.FORMAT_FAIL)

    async def test_teardown_marks_not_ready(self) -> None:
        await self.lane.teardown()
        self.assertFalse(self.lane.ready)

    async def test_collect_foreign_handle_rejected(self) -> None:
        foreign = Handle(id="nope", udid="", target="t", lane="other", harness=HarnessRef(name="h"))
        with self.assertRaises(LaneError):
            await self.lane.collect_crashes(foreign)
        with self.assertRaises(LaneError):
            await self.lane.reset(foreign)

    async def test_launch_harness_metadata_overrides(self) -> None:
        handle = await self.lane.launch(
            "webkit",
            HarnessRef(
                name="jsc",
                metadata={
                    "jsc_args": "--meta-a --meta-b",
                    "timeout_s": "not-a-float",
                    "max_executions": "not-an-int",
                    "time_budget_s": "also-bad",
                    "jsc_binary": str(Path(self._tmp.name) / "jsc"),
                    "mutation_kinds": "number, string",
                    "mutation_stacks": "3",
                    "minimize_crashes": "true",
                    "minimize_attempts": "9",
                    "minimize_budget_s": "1.5",
                    "use_coverage_scheduler": "yes",
                },
            ),
        )
        state = handle.metadata["jsc"]
        config = state["config"]
        self.assertEqual(config.args, ("--meta-a", "--meta-b"))
        self.assertEqual(config.timeout_s, 10.0)
        self.assertEqual(state["campaign_defaults"]["max_executions"], 200000)
        self.assertEqual(state["campaign_defaults"]["time_budget_s"], 60.0)
        defaults = state["campaign_defaults"]
        self.assertEqual(defaults["mutation_kinds"], ("number", "string"))
        self.assertEqual(defaults["mutation_stacks"], 3)
        self.assertTrue(defaults["minimize_crashes"])
        self.assertEqual(defaults["minimize_attempts"], 9)
        self.assertEqual(defaults["minimize_budget_s"], 1.5)
        self.assertTrue(defaults["use_coverage_scheduler"])

    async def test_launch_harness_metadata_sequence_args(self) -> None:
        handle = await self.lane.launch(
            "webkit", HarnessRef(name="jsc", metadata={"jsc_args": ["--seq", 42]})
        )
        self.assertEqual(handle.metadata["jsc"]["config"].args, ("--seq", "42"))


class JscDiscoveryLaneFuzzTest(unittest.IsolatedAsyncioTestCase):
    async def test_fuzz_campaign_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jsc"
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o755)
            crash = ok(
                ["jsc"],
                returncode=-int(signal.SIGSEGV),
                stderr="AddressSanitizer: heap-use-after-free\n#0 0x1 in JSC::A::b() a.cpp:1\n",
            )
            sink = FakeSink()
            lane = JscDiscoveryLane(
                sink=sink,
                jsc_binary=str(binary),
                platform="linux",
                command_runner=FakeCommandRunner([crash]),
                jsc_args=("--fuzz",),
                seed=7,
            )
            await lane.provision(profile())
            handle = await lane.launch("webkit", HarnessRef(name="jsc"))
            progress_calls: list[tuple[int, int, int]] = []
            result = await lane.fuzz(
                handle,
                time_budget_s=0.05,
                max_executions=25,
                progress=lambda e, u, t: progress_calls.append((e, u, t)),
            )
            self.assertEqual(result.stats.unique_crashes, 1)
            self.assertGreaterEqual(result.stats.executions, 1)
            self.assertEqual(len(sink.campaigns), 1)
            summary = sink.campaigns[0]
            self.assertEqual(summary.handle_id, handle.handle_id)
            self.assertEqual(summary.jsc_binary, str(binary))
            self.assertEqual(summary.jsc_args, ("--fuzz",))
            self.assertEqual(summary.seed, 7)
            # Crash is collectable through the normal lane path
            refs = await lane.collect_crashes(handle)
            self.assertEqual(len(refs), 1)
            self.assertEqual(refs[0].payload, sink.records[0].input_js)

    async def test_fuzz_threads_mutation_minimize_and_coverage_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jsc"
            binary.write_text("x")
            binary.chmod(0o755)
            sink = FakeSink()
            lane = JscDiscoveryLane(
                sink=sink,
                jsc_binary=str(binary),
                platform="linux",
                command_runner=FakeCommandRunner(),
            )
            await lane.provision(profile())
            handle = await lane.launch("t", HarnessRef(name="jsc"))
            result = await lane.fuzz(
                handle,
                time_budget_s=0.05,
                max_executions=4,
                mutation_kinds=["number"],
                mutation_stacks=1,
                minimize_crashes=True,
                minimize_attempts=2,
                use_coverage_scheduler=True,
            )
            self.assertGreaterEqual(result.stats.executions, 4)
            summary = sink.campaigns[0]
            self.assertEqual(summary.extra["mutation_kinds"], ["number"])
            self.assertEqual(summary.extra["minimized_crashes"], 0)
            self.assertIn("coverage_edges", summary.extra)

    async def test_fuzz_requires_ready_lane(self) -> None:
        sink = FakeSink()
        lane = JscDiscoveryLane(sink=sink, platform="linux", which=lambda name: None)
        handle = Handle(
            id="h", udid="", target="t", lane="jsc-discovery", harness=HarnessRef(name="x")
        )
        with self.assertRaises(LaneError) as cm:
            await lane.fuzz(handle)
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)

    async def test_fuzz_should_stop_breaks_early(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jsc"
            binary.write_text("x")
            binary.chmod(0o755)
            sink = FakeSink()
            lane = JscDiscoveryLane(
                sink=sink,
                jsc_binary=str(binary),
                platform="linux",
                command_runner=FakeCommandRunner(),
            )
            await lane.provision(profile())
            handle = await lane.launch("t", HarnessRef(name="jsc"))
            calls = {"n": 0}

            def stopper() -> bool:
                calls["n"] += 1
                return calls["n"] > 3

            result = await lane.fuzz(
                handle, time_budget_s=5.0, max_executions=1000, should_stop=stopper
            )
            self.assertLessEqual(result.stats.executions, 8)

    async def test_fuzz_paused_lane_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jsc"
            binary.write_text("x")
            binary.chmod(0o755)
            sink = FakeSink()
            lane = JscDiscoveryLane(
                sink=sink,
                jsc_binary=str(binary),
                platform="linux",
                command_runner=FakeCommandRunner(),
            )
            await lane.provision(profile())
            handle = await lane.launch("t", HarnessRef(name="jsc"))
            lane._paused = True  # noqa: SLF001 - test-only state injection
            with self.assertRaises(LaneError) as cm:
                await lane.fuzz(handle, time_budget_s=1.0)
            self.assertIs(cm.exception.code, LaneErrorCode.THERMAL_DRAIN)


class CrashRefForRecordTest(unittest.TestCase):
    def test_conversion(self) -> None:
        record = CrashRecord(
            claim_id="cl_1",
            signature="sig123",
            crash_type="SIGSEGV",
            signal="SIGSEGV",
            returncode=-11,
            stack=("A::b",),
            input_js=b"js",
            stderr="err",
            handle_id="h",
            target="t",
            ring_node="n",
            build="b",
            artifact_ids=("art_1",),
            created_ms=123,
            campaign_id="camp",
        )
        ref = crash_ref_for_record(record)
        self.assertEqual(ref.id, "cl_1")
        self.assertEqual(ref.kind, "jsc_crash")
        self.assertEqual(ref.digest, "sig123")
        self.assertEqual(ref.payload, b"js")
        self.assertEqual(ref.metadata["crash_type"], "SIGSEGV")
        self.assertEqual(ref.metadata["artifact_ids"], ["art_1"])
        self.assertEqual(ref.metadata["ring_node"], "n")

    def test_conversion_custom_context(self) -> None:
        record = CrashRecord(
            claim_id="c", signature="s", crash_type="t", signal="", returncode=0,
            stack=(), input_js=b"", stderr="", handle_id="h", target="",
            ring_node=None, build=None, artifact_ids=(), created_ms=0,
        )
        ref = crash_ref_for_record(record, context="daemon")
        self.assertEqual(ref.context, "daemon")
