"""Tests for TASK-25 JSC discovery hardening and capability extensions."""

from __future__ import annotations

import random
import signal
import unittest
import unittest.mock
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ra.discovery import (
    CampaignMeta,
    CoverageSample,
    CoverageScheduler,
    JscConfig,
    JscFuzzer,
    JscRunner,
    timeout_result,
)
from ra.discovery.harness import CrashResult, classify_run, exec_error_result
from ra.discovery.minimize import minimize_crash_input
from ra.discovery.mutators import (
    GC_SNIPPETS,
    JS_BUILTIN_SNIPPETS,
    mutate_builtin_call,
    mutate_gc_stress,
    mutate_identifier,
    mutate_jit_warmup,
    mutate_number,
    mutate_operator,
    mutate_program,
    mutate_string,
    mutate_wrapper,
)
from ra.discovery.runner import _candidate_bytes
from ra.discovery.store import CrashRecord
from ra.proc import CommandResult

ASAN_CRASH = (
    "==ERROR: AddressSanitizer: SEGV on unknown address 0xdeadbeef\n"
    "#0 0x1 in JSC::Bug::crash() /src/bug.cpp:10\n"
    "#1 0x2 in JSC::Bug::run() /src/bug.cpp:20\n"
)


class FakeCommandRunner:
    def __init__(
        self,
        handler: Callable[[Sequence[str]], CommandResult] | None = None,
    ) -> None:
        self.handler = handler
        self.calls: list[list[str]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout_s: float,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        self.calls.append(list(argv))
        if self.handler is not None:
            return self.handler(argv)
        return CommandResult(
            argv=tuple(argv), returncode=0, stdout="", stderr="", duration_ms=1
        )


class ContentCommandRunner(FakeCommandRunner):
    def __init__(self) -> None:
        super().__init__(self._handle)

    def _handle(self, argv: Sequence[str]) -> CommandResult:
        text = Path(argv[-1]).read_text(encoding="utf-8", errors="replace")
        if "EXPLODE_RUNNER" in text:
            raise RuntimeError("injected runner failure")
        if "KEEP_CRASH" in text:
            return CommandResult(
                argv=tuple(argv),
                returncode=-int(signal.SIGSEGV),
                stdout="",
                stderr=ASAN_CRASH,
                duration_ms=1,
            )
        return CommandResult(
            argv=tuple(argv), returncode=0, stdout="ok", stderr="", duration_ms=1
        )


class FakeSink:
    def __init__(self) -> None:
        self.known: set[str] = set()
        self.crashes: list[tuple[str | bytes, CrashResult, Mapping[str, Any]]] = []
        self.campaigns: list[Any] = []
        self._counter = 0

    async def known_signatures(self) -> set[str]:
        return set(self.known)

    async def record_crash(
        self, content: str | bytes, result: CrashResult, meta: Mapping[str, Any]
    ) -> CrashRecord | None:
        if result.signature in self.known:
            return None
        self.known.add(result.signature)
        self._counter += 1
        data = content if isinstance(content, bytes) else content.encode()
        record = CrashRecord(
            claim_id=f"c{self._counter}",
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
            artifact_ids=(),
            created_ms=self._counter,
            campaign_id=None,
            metadata={},
        )
        self.crashes.append((content, result, meta))
        return record

    async def record_campaign(self, summary: Any) -> str:
        self.campaigns.append(summary)
        return "campaign-id"


class Provider:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.fail = fail

    async def coverage_for(self, content: str) -> CoverageSample | None:
        self.calls.append(content)
        if self.fail:
            raise RuntimeError("coverage provider failed")
        return CoverageSample(
            edges=frozenset({content.strip()[:20] or "empty", "common-edge"}),
            features={"len": len(content)},
        )


class MutatorExtensionTest(unittest.TestCase):
    def test_identifier_number_string_and_operator_mutations(self) -> None:
        rng = random.Random(7)
        self.assertNotIn("alpha", mutate_identifier("var alpha = 1;", rng))
        self.assertNotIn("12345", mutate_number("var x = 12345;", rng))
        self.assertNotIn("hello", mutate_string('var s = "hello";', rng))
        source = "var x = 1 + 2;"
        out = source
        for _ in range(20):
            out = mutate_operator(source, random.Random(_))
            if out != source:
                break
        self.assertNotEqual(out, source)

    def test_operator_mutation_preserves_literals_and_comments(self) -> None:
        source = 'var s = "a + b"; // c + d\nvar x = 1 + 2;'
        out = source
        for seed in range(30):
            out = mutate_operator(source, random.Random(seed))
            if out != source:
                break
        self.assertNotEqual(out, source)
        self.assertIn('"a + b"', out)
        self.assertIn("// c + d", out)

    def test_builtin_gc_jit_and_wrapper_mutations(self) -> None:
        rng = random.Random(11)
        gc_out = mutate_gc_stress("var x = 1;", rng)
        self.assertTrue(any(snippet in gc_out for snippet in GC_SNIPPETS))
        builtin = mutate_builtin_call("array[0];", rng)
        self.assertTrue(any(snippet.strip() in builtin for snippet in JS_BUILTIN_SNIPPETS))
        jit = mutate_jit_warmup("function foo(a) { return a + 1; }", rng)
        self.assertIn("__ra_target", jit)
        self.assertIn("foo(1.1", jit)
        wrapped = mutate_wrapper("doThing();", rng)
        self.assertTrue(any(token in wrapped for token in ("for (", "try {", "do {")))
        self.assertIn("doThing();", wrapped)

    def test_mutate_program_kind_selection_and_errors(self) -> None:
        source = "var x = 12345;"
        out = mutate_program(source, random.Random(3), kinds=["number"])
        self.assertNotEqual(out, source)
        with self.assertRaises(ValueError):
            mutate_program(source, random.Random(3), kinds=["not-a-kind"])

    def test_mutate_program_is_deterministic_and_handles_oversize_input(self) -> None:
        source = "var alpha = 12345; array[0];"
        first = mutate_program(source, random.Random(123))
        second = mutate_program(source, random.Random(123))
        self.assertEqual(first, second)
        huge = "x" * 250_001
        self.assertIsInstance(mutate_program(huge, random.Random(1)), str)

    def test_gc_snippets_are_valid_ascii_js_lines(self) -> None:
        for snippet in GC_SNIPPETS:
            self.assertNotIn("\x00", snippet)
            self.assertTrue(snippet.endswith((";", "\n")))


class CoverageSchedulerTest(unittest.IsolatedAsyncioTestCase):
    async def test_observe_tracks_edges_stats_and_energy(self) -> None:
        scheduler = CoverageScheduler(Provider(), seed_energy=1.0, new_edge_bonus=5.0)
        result = CrashResult(
            is_crash=True,
            crash_type="SIGSEGV",
            signal="SIGSEGV",
            returncode=-int(signal.SIGSEGV),
            stderr="boom",
            stack=(),
            signature="sig",
            timed_out=False,
            exec_error=False,
        )
        sample = await scheduler.observe("seed-a", "content-a", result)
        self.assertIsNotNone(sample)
        self.assertEqual(scheduler.stats.executions, 1)
        self.assertEqual(scheduler.stats.samples, 1)
        self.assertEqual(scheduler.stats.new_edges, 2)
        self.assertEqual(scheduler.stats.crashes, 1)
        self.assertGreater(scheduler.energy_for("seed-a"), scheduler.energy_for("seed-b"))

    async def test_observe_timeout_error_and_provider_failure(self) -> None:
        scheduler = CoverageScheduler(Provider())
        await scheduler.observe("s", "ok", classify_run(0, ""))
        await scheduler.observe("s", "timeout", timeout_result(1.0))
        await scheduler.observe("s", "exec", exec_error_result("bad"))
        self.assertEqual(scheduler.stats.timeouts, 1)
        self.assertEqual(scheduler.stats.exec_errors, 1)

        failing = CoverageScheduler(Provider(fail=True))
        sample = await failing.observe("s", "x", classify_run(0, ""))
        self.assertIsNone(sample)
        self.assertEqual(failing.stats.executions, 1)
        self.assertEqual(failing.stats.samples, 0)

    def test_choose_requires_corpus_and_reset_clears_state(self) -> None:
        scheduler = CoverageScheduler()
        with self.assertRaises(ValueError):
            scheduler.choose(random.Random(0), [])
        scheduler.stats.executions = 9
        scheduler.reset()
        self.assertEqual(scheduler.stats.executions, 0)
        self.assertEqual(scheduler.energy_for("anything"), 1.0)

    def test_scheduler_rejects_invalid_energy_parameters(self) -> None:
        with self.assertRaises(ValueError):
            CoverageScheduler(seed_energy=0)
        with self.assertRaises(ValueError):
            CoverageScheduler(min_energy=0)
        with self.assertRaises(ValueError):
            CoverageScheduler(decay=1.5)

    def test_choose_falls_through_to_last_seed_at_total_weight(self) -> None:
        class TotalRandom:
            def random(self) -> float:
                return 1.0

        scheduler = CoverageScheduler()
        chosen = scheduler.choose(TotalRandom(), ["a", "b", "c"])  # type: ignore[arg-type]
        self.assertEqual(chosen, "c")

    async def test_explicit_sample_and_no_provider_edge_accounting(self) -> None:
        scheduler = CoverageScheduler()
        clean = classify_run(0, "")
        first = await scheduler.observe(
            "s", "a", clean, sample=CoverageSample(edges=frozenset({"e1", "e2"}))
        )
        self.assertIsNotNone(first)
        second = await scheduler.observe("s", "b", clean, sample=None)
        self.assertIsNone(second)
        self.assertEqual(scheduler.stats.edges, 2)
        self.assertEqual(scheduler.stats.samples, 1)


class CrashMinimizerTest(unittest.IsolatedAsyncioTestCase):
    async def _runner(self) -> JscRunner:
        return JscRunner(JscConfig(binary="jsc", timeout_s=2), runner=ContentCommandRunner())

    async def test_minimizes_crashing_input_while_preserving_signature(self) -> None:
        runner = await self._runner()
        crash = classify_run(-int(signal.SIGSEGV), ASAN_CRASH)
        original = "KEEP_CRASH\n" + "".join(f"junk{i}();\n" for i in range(30)) + "tail();\n"
        minimized = await minimize_crash_input(runner, original, crash, max_attempts=80)
        self.assertTrue(minimized.changed)
        self.assertTrue(minimized.preserved_signature)
        self.assertIn("KEEP_CRASH", minimized.content)
        self.assertLess(minimized.minimized_size, minimized.original_size)
        self.assertGreater(minimized.attempts, 0)

    async def test_minimizer_rejects_runner_failures_and_non_crashes(self) -> None:
        runner = await self._runner()
        crash = classify_run(-int(signal.SIGSEGV), ASAN_CRASH)
        original = "KEEP_CRASH\nEXPLODE_RUNNER\njunk\n"
        minimized = await minimize_crash_input(runner, original, crash, max_attempts=20)
        self.assertTrue(minimized.preserved_signature)
        self.assertIn("KEEP_CRASH", minimized.content)
        self.assertGreater(minimized.attempts, 0)

        clean = classify_run(0, "ok")
        unchanged = await minimize_crash_input(runner, "clean();\n", clean)
        self.assertFalse(unchanged.changed)
        self.assertEqual(unchanged.attempts, 0)

    async def test_minimizer_budget_and_stop_controls(self) -> None:
        runner = await self._runner()
        crash = classify_run(-int(signal.SIGSEGV), ASAN_CRASH)
        original = "KEEP_CRASH\n" + "junk\n" * 20
        stopped = await minimize_crash_input(
            runner, original, crash, max_attempts=20, should_stop=lambda: True
        )
        self.assertEqual(stopped.attempts, 0)
        expired = await minimize_crash_input(
            runner, original, crash, max_attempts=20, time_budget_s=0.0
        )
        self.assertEqual(expired.attempts, 0)
        limited = await minimize_crash_input(runner, original, crash, max_attempts=0)
        self.assertEqual(limited.attempts, 0)
        self.assertFalse(limited.changed)

    async def test_minimizer_rejects_raising_runner_and_non_string_input(self) -> None:
        class RaisingRunner:
            async def run_source(self, content: str | bytes) -> CrashResult:
                raise RuntimeError("runner exploded")

        crash = classify_run(-int(signal.SIGSEGV), ASAN_CRASH)
        minimized = await minimize_crash_input(
            RaisingRunner(),  # type: ignore[arg-type]
            "KEEP_CRASH\njunk\n",
            crash,
            max_attempts=3,
        )
        self.assertFalse(minimized.changed)
        self.assertEqual(minimized.attempts, 3)
        with self.assertRaises(TypeError):
            await minimize_crash_input(
                await self._runner(), b"bytes", crash  # type: ignore[arg-type]
            )


class RunnerHardeningTest(unittest.IsolatedAsyncioTestCase):
    async def test_config_rejects_invalid_limits(self) -> None:
        with self.assertRaises(ValueError):
            JscConfig(binary="jsc", timeout_s=0)
        with self.assertRaises(ValueError):
            JscConfig(binary="jsc", max_input_bytes=0)

    async def test_oversize_binary_and_empty_binary_inputs_are_exec_errors(self) -> None:
        command = FakeCommandRunner()
        runner = JscRunner(JscConfig(binary="jsc", max_input_bytes=8), runner=command)
        oversize = await runner.run_source(b"x" * 9)
        self.assertTrue(oversize.exec_error)
        self.assertIn("too large", oversize.stderr)
        self.assertEqual(command.calls, [])

        empty = JscRunner(JscConfig(binary=""), runner=FakeCommandRunner())
        result = await empty.run_source("x")
        self.assertTrue(result.exec_error)
        self.assertIn("empty", result.stderr)

    async def test_binary_malformed_input_does_not_crash_runner(self) -> None:
        runner = JscRunner(JscConfig(binary="jsc"), runner=FakeCommandRunner())
        result = await runner.run_source(b"\x00\xff\xfe not utf8 \x80")
        self.assertFalse(result.is_crash)
        self.assertFalse(result.exec_error)

    def test_candidate_bytes_failure_is_contained(self) -> None:
        class BadBytes:
            def __bytes__(self) -> bytes:
                raise RuntimeError("bad bytes")

        self.assertEqual(_candidate_bytes(BadBytes()), b"")  # type: ignore[arg-type]

    async def test_candidate_write_failure_is_exec_error(self) -> None:
        runner = JscRunner(JscConfig(binary="jsc"), runner=FakeCommandRunner())
        with unittest.mock.patch(
            "pathlib.Path.write_bytes", side_effect=OSError("disk full")
        ):
            result = await runner.run_source("x();")
        self.assertTrue(result.exec_error)
        self.assertIn("write failed", result.stderr)


class FuzzerExtensionTest(unittest.IsolatedAsyncioTestCase):
    def _meta(self) -> CampaignMeta:
        return CampaignMeta(handle_id="h1", target="webkit-jsc")

    def test_constructor_validates_new_options(self) -> None:
        runner = JscRunner(JscConfig(binary="jsc"), runner=FakeCommandRunner())
        with self.assertRaises(ValueError):
            JscFuzzer(runner, ["x();"], FakeSink(), self._meta(), mutation_kinds=["bogus"])
        with self.assertRaises(ValueError):
            JscFuzzer(runner, ["x();"], FakeSink(), self._meta(), mutation_stacks=-1)
        with self.assertRaises(ValueError):
            JscFuzzer(runner, ["x();"], FakeSink(), self._meta(), mutation_kinds=[])
        with self.assertRaises(TypeError):
            JscFuzzer(runner, "x();", FakeSink(), self._meta())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            JscFuzzer(
                runner,
                ["x();"],
                FakeSink(),
                self._meta(),
                minimize_crashes=True,
                minimize_attempts=-1,
            )
        with self.assertRaises(ValueError):
            JscFuzzer(
                runner,
                ["x();"],
                FakeSink(),
                self._meta(),
                minimize_crashes=True,
                minimize_budget_s=-1,
            )

    async def test_seed_crash_is_minimized_and_signature_preserved(self) -> None:
        command = ContentCommandRunner()
        runner = JscRunner(JscConfig(binary="jsc", timeout_s=2), runner=command)
        sink = FakeSink()
        original = "KEEP_CRASH\n" + "".join(f"noise{i}();\n" for i in range(20))
        fuzzer = JscFuzzer(
            runner,
            [original],
            sink,
            self._meta(),
            seed=5,
            minimize_crashes=True,
            minimize_attempts=60,
        )
        count = await fuzzer.check_seed_crashes()
        self.assertEqual(count, 1)
        self.assertEqual(len(sink.crashes), 1)
        recorded = sink.crashes[0][0]
        self.assertIsInstance(recorded, str)
        assert isinstance(recorded, str)
        self.assertIn("KEEP_CRASH", recorded)
        self.assertLess(len(recorded), len(original))
        self.assertEqual(sink.crashes[0][1].signature, classify_run(-int(signal.SIGSEGV), ASAN_CRASH).signature)

    async def test_coverage_scheduler_drives_campaign_and_summary(self) -> None:
        command = FakeCommandRunner()
        runner = JscRunner(JscConfig(binary="jsc", timeout_s=2), runner=command)
        sink = FakeSink()
        provider = Provider()
        fuzzer = JscFuzzer(
            runner,
            ["let value = 1;"],
            sink,
            self._meta(),
            seed=9,
            use_coverage_scheduler=True,
            coverage_provider=provider,
        )
        result = await fuzzer.run(time_budget_s=5.0, max_executions=3, should_stop=lambda: False)
        self.assertEqual(result.stats.executions, 3)
        self.assertGreater(len(provider.calls), 0)
        summary = sink.campaigns[-1]
        self.assertGreaterEqual(summary.extra.get("coverage_edges", 0), 1)
        self.assertIn("mutation_kinds", summary.extra)

    async def test_run_with_restricted_mutation_kinds(self) -> None:
        command = FakeCommandRunner()
        runner = JscRunner(JscConfig(binary="jsc", timeout_s=2), runner=command)
        sink = FakeSink()
        fuzzer = JscFuzzer(
            runner,
            ["var x = 12345;"],
            sink,
            self._meta(),
            seed=2,
            mutation_kinds=["number"],
            mutation_stacks=1,
        )
        result = await fuzzer.run(time_budget_s=5.0, max_executions=3)
        self.assertEqual(result.stats.executions, 3)
        self.assertEqual(sink.campaigns[-1].extra["mutation_kinds"], ["number"])

    async def test_known_signatures_loaded_once_across_seed_checks(self) -> None:
        runner = JscRunner(JscConfig(binary="jsc"), runner=FakeCommandRunner())
        sink = FakeSink()
        sink.known.add("already-known")
        fuzzer = JscFuzzer(runner, ["x();"], sink, self._meta(), seed=4)
        await fuzzer.check_seed_crashes()
        await fuzzer.check_seed_crashes()
        self.assertEqual(fuzzer.stats.executions, 2)

    async def test_minimization_attempt_that_cannot_shrink_still_records(self) -> None:
        runner = JscRunner(JscConfig(binary="jsc", timeout_s=2), runner=ContentCommandRunner())
        sink = FakeSink()
        original = "KEEP_CRASH"
        fuzzer = JscFuzzer(
            runner,
            [original],
            sink,
            self._meta(),
            seed=6,
            minimize_crashes=True,
            minimize_attempts=1,
        )
        count = await fuzzer.check_seed_crashes()
        self.assertEqual(count, 1)
        self.assertEqual(fuzzer.stats.minimized_crashes, 0)
        self.assertEqual(fuzzer.stats.minimization_attempts, 1)
        self.assertEqual(sink.crashes[0][0], original)


if __name__ == "__main__":
    unittest.main()
