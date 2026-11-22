"""Tests for ``ra.discovery`` corpus loading, runner, and fuzzer."""

from __future__ import annotations

import random
import signal
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from ra.discovery import (
    SPICY,
    TOKENS,
    WRAPPERS,
    CampaignMeta,
    JscConfig,
    JscFuzzer,
    JscRunner,
    load_corpus,
    mutate,
)
from ra.discovery.fuzzer import CampaignResult
from ra.discovery.harness import ASAN_EXITCODE, CrashResult
from ra.discovery.jsc_store import CampaignSummary, CrashRecord
from ra.proc import CommandResult

ASAN_CRASH = (
    "==1==ERROR: AddressSanitizer: heap-use-after-free\n"
    "    #0 0x1 in JSC::A::b() a.cpp:1\n"
)


class FakeCommandRunner:
    """Scripted CommandRunner: returns queued results or raises."""

    def __init__(self, results: Sequence[CommandResult | Exception] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[dict[str, object]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        self.calls.append({"argv": list(argv), "timeout_s": timeout_s, "env": env})
        if not self.results:
            return CommandResult(
                argv=tuple(argv), returncode=0, stdout="", stderr="", duration_ms=1
            )
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def ok_result(argv: Sequence[str], **overrides: object) -> CommandResult:
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


class FakeSink:
    """In-memory CrashSink for fuzzer tests."""

    def __init__(self, known: set[str] | None = None) -> None:
        self.known = set(known or set())
        self.crashes: list[tuple[str, CrashResult, Mapping[str, object]]] = []
        self.records: list[CrashRecord] = []
        self.campaigns: list[CampaignSummary] = []
        self.fail_record = False

    async def known_signatures(self) -> set[str]:
        return set(self.known)

    async def record_crash(
        self, content: str, result: CrashResult, meta: Mapping[str, object]
    ) -> CrashRecord | None:
        if self.fail_record:
            raise RuntimeError("sink exploded")
        if result.signature in self.known:
            return None
        self.known.add(result.signature)
        record = CrashRecord(
            claim_id=f"cl_{len(self.crashes):04d}",
            signature=result.signature,
            crash_type=result.crash_type,
            signal=result.signal,
            returncode=result.returncode,
            stack=result.stack,
            input_js=content.encode(),
            stderr=result.stderr,
            handle_id=str(meta.get("handle_id", "")),
            target=str(meta.get("target", "")),
            ring_node=None,
            build=None,
            artifact_ids=(),
            created_ms=len(self.crashes),
            campaign_id=None,
            metadata={},
        )
        self.crashes.append((content, result, dict(meta)))
        self.records.append(record)
        return record

    async def record_campaign(self, summary: CampaignSummary) -> str:
        self.campaigns.append(summary)
        return f"camp_claim_{len(self.campaigns)}"

    async def crashes_for_handle(self, handle_id: str) -> list[CrashRecord]:
        return [record for record in self.records if record.handle_id == handle_id]


class LoadCorpusTest(unittest.TestCase):
    def test_bundled_corpus_loads_pr3_seeds(self) -> None:
        corpus = load_corpus()
        self.assertGreaterEqual(len(corpus), 8)
        joined = "\n".join(corpus)
        self.assertIn("Float64Array", joined)

    def test_custom_directory_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "b.js").write_text("b();")
            (root / "a.js").write_text("a();")
            (root / "ignored.txt").write_text("nope")
            corpus = load_corpus(root)
            self.assertEqual(corpus, ("a();", "b();"))

    def test_missing_directory_falls_back(self) -> None:
        corpus = load_corpus(Path("/nonexistent/ra-corpus"))
        self.assertEqual(corpus, ("print(1);",))

    def test_empty_directory_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_corpus(tmp), ("print(1);",))

    def test_unreadable_file_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "good.js").write_text("good();")
            bad = root / "bad.js"
            bad.write_text("bad();")
            bad.chmod(0)
            try:
                corpus = load_corpus(root)
            finally:
                bad.chmod(0o644)
            self.assertEqual(corpus, ("good();",))


class MutateTest(unittest.TestCase):
    def test_all_operators_reachable(self) -> None:
        seen: set[str] = set()
        rng = random.Random(7)
        source = "var a = [1,2,3];\nvar b = a.concat(a);\nprint(a[0]);"
        for _ in range(300):
            out = mutate(source, rng)
            self.assertIsInstance(out, str)
            if "gc()" in out or "edenGC()" in out or "ArrayBuffer" in out:
                seen.add("spicy")
            if "for (let i=0" in out or "(function(){" in out or "try{" in out or "function g(){" in out:
                seen.add("wrap")
            if any(tok in out for tok in ("0x7fffffff", "new.target", "arguments")):
                seen.add("token")
        self.assertIn("spicy", seen)
        self.assertIn("wrap", seen)
        self.assertIn("token", seen)

    def test_mutate_is_deterministic_per_seed(self) -> None:
        source = "var a = 1;\nprint(a);"
        self.assertEqual(mutate(source, random.Random(42)), mutate(source, random.Random(42)))

    def test_mutate_empty_source(self) -> None:
        out = mutate("", random.Random(1))
        self.assertIsInstance(out, str)

    def test_mutate_single_line_drop_keeps_line(self) -> None:
        rng = random.Random(0)
        # Force the drop-line branch by exhausting rng until op in [0.5, 0.65)
        for _ in range(1000):
            out = mutate("only_line();", rng)
            self.assertIn("only_line();", out)

    def test_wrapped_output_contains_body(self) -> None:
        rng = random.Random(3)
        body = "MARKER_UNIQUE_LINE();"
        for _ in range(200):
            out = mutate(body, rng)
            if "MARKER_UNIQUE_LINE" in out:
                continue
            # wrapped forms keep the body too
            self.assertIn("MARKER_UNIQUE_LINE", out)

    def test_spicy_and_tokens_constants(self) -> None:
        self.assertEqual(len(SPICY), 26)
        self.assertEqual(len(TOKENS), 17)
        self.assertEqual(len(WRAPPERS), 5)


class JscRunnerTest(unittest.IsolatedAsyncioTestCase):
    async def test_run_source_success(self) -> None:
        runner_impl = FakeCommandRunner(
            [ok_result(["jsc", "--x", "/tmp/candidate.js"], stdout="ok")]
        )
        config = JscConfig(binary="jsc", args=("--x",), timeout_s=3.0)
        runner = JscRunner(config, runner=runner_impl, workdir=None)
        result = await runner.run_source("print(1);")
        self.assertFalse(result.is_crash)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.returncode, 0)
        call = runner_impl.calls[0]
        argv = call["argv"]
        self.assertEqual(argv[0], "jsc")
        self.assertEqual(argv[1], "--x")
        self.assertTrue(str(argv[2]).endswith(".js"))
        self.assertEqual(call["timeout_s"], 3.0)
        self.assertIn("ASAN_OPTIONS", call["env"] or {})

    async def test_run_source_crash_classified(self) -> None:
        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        runner = JscRunner(
            JscConfig(binary="jsc"), runner=FakeCommandRunner([crash])
        )
        result = await runner.run_source("x")
        self.assertTrue(result.is_crash)
        self.assertEqual(result.crash_type, "SIGSEGV")

    async def test_run_source_timeout(self) -> None:
        timeout = ok_result(["jsc"], timed_out=True, returncode=-1)
        runner = JscRunner(
            JscConfig(binary="jsc", timeout_s=2.0), runner=FakeCommandRunner([timeout])
        )
        result = await runner.run_source("x")
        self.assertTrue(result.timed_out)
        self.assertFalse(result.is_crash)
        self.assertEqual(result.crash_type, "timeout")

    async def test_run_source_oserror_is_exec_error(self) -> None:
        runner = JscRunner(
            JscConfig(binary="/missing/jsc"),
            runner=FakeCommandRunner([FileNotFoundError("no such file")]),
        )
        result = await runner.run_source("x")
        self.assertTrue(result.exec_error)
        self.assertIn("no such file", result.stderr)

    async def test_run_source_runner_defect_is_exec_error(self) -> None:
        runner = JscRunner(
            JscConfig(binary="jsc"), runner=FakeCommandRunner([RuntimeError("boom")])
        )
        result = await runner.run_source("x")
        self.assertTrue(result.exec_error)
        self.assertIn("runner error", result.stderr)

    async def test_run_source_bytes_input(self) -> None:
        runner_impl = FakeCommandRunner()
        runner = JscRunner(JscConfig(binary="jsc"), runner=runner_impl)
        result = await runner.run_source(b"print(2);")
        self.assertFalse(result.is_crash)

    async def test_workdir_candidate_cleaned_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "work"
            runner = JscRunner(
                JscConfig(binary="jsc"), runner=FakeCommandRunner(), workdir=root
            )
            await runner.run_source("print(1);")
            self.assertTrue(root.exists())
            self.assertEqual(list(root.iterdir()), [])

    async def test_unwritable_workdir_is_exec_error(self) -> None:
        # A path that is a file, not a directory, makes mkdir fail.
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x")
            runner = JscRunner(
                JscConfig(binary="jsc"), runner=FakeCommandRunner(), workdir=blocker / "sub"
            )
            result = await runner.run_source("print(1);")
            # mkdir(parents=True) raises FileExistsError (OSError) -> exec_error
            self.assertTrue(result.exec_error)

    async def test_unwritable_workdir_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "work"
            root.mkdir()
            root.chmod(0o500)
            try:
                runner = JscRunner(
                    JscConfig(binary="jsc"), runner=FakeCommandRunner(), workdir=root
                )
                result = await runner.run_source("print(1);")
            finally:
                root.chmod(0o700)
            self.assertTrue(result.exec_error)
            self.assertIn("candidate write failed", result.stderr)

    async def test_config_property(self) -> None:
        config = JscConfig(binary="jsc", args=("--a",))
        runner = JscRunner(config, runner=FakeCommandRunner())
        self.assertIs(runner.config, config)

    async def test_base_env_override(self) -> None:
        runner_impl = FakeCommandRunner()
        runner = JscRunner(
            JscConfig(binary="jsc"), runner=runner_impl, base_env={"CUSTOM": "1"}
        )
        await runner.run_source("x")
        env = runner_impl.calls[0]["env"] or {}
        self.assertEqual(env.get("CUSTOM"), "1")


class JscFuzzerTest(unittest.IsolatedAsyncioTestCase):
    def make_fuzzer(
        self,
        runner_impl: FakeCommandRunner,
        sink: FakeSink,
        corpus: tuple[str, ...] = ("print(1);",),
        **kwargs: object,
    ) -> JscFuzzer:
        config = JscConfig(binary="jsc", args=("--test",))
        runner = JscRunner(config, runner=runner_impl)
        meta = CampaignMeta(handle_id="h-1", target="webkit", jsc_binary="jsc")
        seed = kwargs.pop("seed", 1234)
        assert isinstance(seed, int)
        return JscFuzzer(runner, corpus, sink, meta, seed=seed)

    async def test_seed_crashes_recorded(self) -> None:
        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        sink = FakeSink()
        fuzzer = self.make_fuzzer(FakeCommandRunner([crash]), sink, corpus=("a=1;", "b=2;"))
        # Second case falls back to default ok (queue exhausted)
        count = await fuzzer.check_seed_crashes()
        self.assertEqual(count, 1)
        self.assertEqual(fuzzer.stats.executions, 2)
        self.assertEqual(fuzzer.stats.unique_crashes, 1)
        self.assertEqual(len(sink.crashes), 1)
        self.assertEqual(fuzzer.records[0].handle_id, "h-1")

    async def test_duplicate_signature_not_recorded_twice(self) -> None:
        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        sink = FakeSink()
        fuzzer = self.make_fuzzer(
            FakeCommandRunner([crash, crash]), sink, corpus=("same;", "same;")
        )
        count = await fuzzer.check_seed_crashes()
        self.assertEqual(count, 1)
        self.assertEqual(fuzzer.stats.executions, 2)
        self.assertEqual(len(sink.crashes), 1)

    async def test_known_signature_from_sink_skipped(self) -> None:
        from ra.discovery.harness import classify_run

        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        sig = classify_run(-int(signal.SIGSEGV), "segv").signature
        sink = FakeSink(known={sig})
        fuzzer = self.make_fuzzer(FakeCommandRunner([crash]), sink, corpus=("x;",))
        count = await fuzzer.check_seed_crashes()
        self.assertEqual(count, 0)
        self.assertEqual(fuzzer.stats.total_crashes, 1)
        self.assertEqual(len(sink.crashes), 0)

    async def test_run_campaign_records_summary(self) -> None:
        crash = ok_result(["jsc"], returncode=ASAN_EXITCODE, stderr=ASAN_CRASH)
        sink = FakeSink()
        fuzzer = self.make_fuzzer(
            FakeCommandRunner([crash]), sink, corpus=("print(1);",), seed=5
        )
        result: CampaignResult = await fuzzer.run(0.05, max_executions=20)
        self.assertEqual(len(sink.campaigns), 1)
        summary = sink.campaigns[0]
        self.assertEqual(summary.handle_id, "h-1")
        self.assertEqual(summary.jsc_binary, "jsc")
        self.assertEqual(summary.jsc_args, ("--test",))
        self.assertGreaterEqual(summary.executions, 1)
        self.assertEqual(result.campaign_claim_id, "camp_claim_1")
        self.assertEqual(result.stats.unique_crashes, 1)

    async def test_run_without_campaign_recording(self) -> None:
        sink = FakeSink()
        fuzzer = self.make_fuzzer(FakeCommandRunner(), sink)
        result = await fuzzer.run(0.05, max_executions=10, record_campaign=False)
        self.assertEqual(sink.campaigns, [])
        self.assertIsNone(result.campaign_claim_id)

    async def test_should_stop_breaks_campaign(self) -> None:
        sink = FakeSink()
        fuzzer = self.make_fuzzer(FakeCommandRunner(), sink, corpus=("x;",))
        result = await fuzzer.run(10.0, max_executions=1000, should_stop=lambda: True)
        self.assertLessEqual(result.stats.executions, 1)

    async def test_max_executions_cap(self) -> None:
        sink = FakeSink()
        fuzzer = self.make_fuzzer(FakeCommandRunner(), sink, corpus=("x;",))
        result = await fuzzer.run(10.0, max_executions=3)
        # 1 seed execution + 2 fuzz iterations
        self.assertEqual(result.stats.executions, 3)

    async def test_progress_callback_fires(self) -> None:
        sink = FakeSink()
        fuzzer = self.make_fuzzer(FakeCommandRunner(), sink, corpus=("x;",))
        calls: list[tuple[int, int, int]] = []

        def progress(executions: int, unique: int, total: int) -> None:
            calls.append((executions, unique, total))

        # Patch PROGRESS_EVERY down via many executions is slow; instead run enough
        # that seed phase (1 execution) + budget loop crosses a 200 boundary is too
        # slow, so verify callback wiring with a tiny monkeypatched constant.
        import ra.discovery.fuzzer as fuzzer_mod

        original = fuzzer_mod.PROGRESS_EVERY
        fuzzer_mod.PROGRESS_EVERY = 1
        try:
            await fuzzer.run(0.05, max_executions=3, progress=progress)
        finally:
            fuzzer_mod.PROGRESS_EVERY = original
        self.assertTrue(calls)

    async def test_exec_errors_and_timeouts_counted(self) -> None:
        timeout = ok_result(["jsc"], timed_out=True, returncode=-1)
        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        sink = FakeSink()
        fuzzer = self.make_fuzzer(
            FakeCommandRunner([timeout, crash]), sink, corpus=("a;", "b;")
        )
        await fuzzer.check_seed_crashes()
        self.assertEqual(fuzzer.stats.timeouts, 1)
        self.assertEqual(fuzzer.stats.total_crashes, 1)

    async def test_sink_failure_propagates(self) -> None:
        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        sink = FakeSink()
        sink.fail_record = True
        fuzzer = self.make_fuzzer(FakeCommandRunner([crash]), sink, corpus=("x;",))
        with self.assertRaises(RuntimeError):
            await fuzzer.check_seed_crashes()

    async def test_exec_error_tally(self) -> None:
        sink = FakeSink()
        fuzzer = self.make_fuzzer(
            FakeCommandRunner([FileNotFoundError("no jsc")]), sink, corpus=("x;",)
        )
        await fuzzer.check_seed_crashes()
        self.assertEqual(fuzzer.stats.exec_errors, 1)
        self.assertIn("no jsc", fuzzer.stats.last_exec_error)

    async def test_ledger_level_duplicate_returns_none(self) -> None:
        class NoneSink(FakeSink):
            async def record_crash(self, content, result, meta):
                return None

        sink = NoneSink()
        crash = ok_result(["jsc"], returncode=-int(signal.SIGSEGV), stderr="segv")
        fuzzer = self.make_fuzzer(FakeCommandRunner([crash]), sink, corpus=("x;",))
        count = await fuzzer.check_seed_crashes()
        self.assertEqual(count, 0)
        self.assertEqual(fuzzer.stats.total_crashes, 1)
        self.assertEqual(fuzzer.stats.unique_crashes, 0)
        self.assertFalse(fuzzer.records)

    async def test_campaign_id_from_meta_reused(self) -> None:
        sink = FakeSink()
        config = JscConfig(binary="jsc")
        runner = JscRunner(config, runner=FakeCommandRunner())
        meta = CampaignMeta(handle_id="h", campaign_id="fixed-campaign")
        fuzzer = JscFuzzer(runner, ("x;",), sink, meta, seed=1)
        self.assertEqual(fuzzer.campaign_id, "fixed-campaign")

    async def test_default_campaign_id_unique(self) -> None:
        sink = FakeSink()
        config = JscConfig(binary="jsc")
        runner = JscRunner(config, runner=FakeCommandRunner())
        meta = CampaignMeta(handle_id="h")
        a = JscFuzzer(runner, ("x;",), sink, meta, seed=1)
        b = JscFuzzer(runner, ("x;",), sink, meta, seed=1)
        self.assertNotEqual(a.campaign_id, b.campaign_id)


class CampaignSummaryTest(unittest.TestCase):
    def test_to_from_dict_roundtrip(self) -> None:
        summary = CampaignSummary(
            campaign_id="c1",
            handle_id="h1",
            target="webkit",
            ring_node="node-1",
            build="build-1",
            jsc_binary="/usr/bin/jsc",
            jsc_args=("--a", "--b"),
            seed=42,
            executions=10,
            unique_crashes=2,
            total_crashes=5,
            exec_errors=1,
            timeouts=3,
            duration_ms=1234,
            run_id="run-1",
        )
        restored = CampaignSummary.from_dict(summary.to_dict())
        self.assertEqual(restored, summary)

    def test_from_dict_tolerates_missing_optionals(self) -> None:
        restored = CampaignSummary.from_dict({"campaign_id": "c", "handle_id": "h"})
        self.assertIsNone(restored.ring_node)
        self.assertEqual(restored.executions, 0)
        self.assertEqual(restored.jsc_args, ())

    def test_from_dict_rejects_missing_required(self) -> None:
        with self.assertRaises(KeyError):
            CampaignSummary.from_dict({"handle_id": "h"})
