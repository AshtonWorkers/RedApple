"""Unit and property tests for ``ra.discovery.harness`` (PR #3 port)."""

from __future__ import annotations

import hashlib
import os
import random
import re
import signal
import unittest
import unittest.mock

from ra.discovery.harness import (
    ASAN_EXITCODE,
    CRASH_SIGNALS,
    DEFAULT_ARGS,
    CrashResult,
    JscConfig,
    _normalize_output,
    classify_run,
    exec_error_result,
    extract_stack,
    make_signature,
    timeout_result,
)

ASAN_REPORT = """\
=================================================================
==123==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020000abcde
READ of size 8 at 0x6020000abcde thread T0
    #0 0x7f123456 in JSC::DFG::JITCode::pdfBundle() const 0x123 + 16
    #1 0x7f123457 in JSC::DFG::JITCompiler::compileFunction(JSC::DFG::CompilationContext&) lambda.cpp:42
    #2 0x7f123458 in __asan_report_error /build/asan/asan_report.cpp:300
SUMMARY: AddressSanitizer: heap-use-after-free js/src/jsc/dfg/JITCode.cpp:1234
"""

WTF_REPORT = """\
3   0x00007f1234567890  JSC::DFG::JITCode::pdfBundle() const + 16
4   0x00007f1234567891  JSC::DFG::JITCompiler::compileFunction(JSC::DFG::CompilationContext&)
5   0x00007f1234567892  llint_op_call + 256
"""

ASSERT_REPORT = "RELEASE_ASSERT NOT REACHED in WTF::fastMalloc\n"


class CrashSignalsTest(unittest.TestCase):
    def test_signal_table_is_platform_correct(self) -> None:
        self.assertIn(-int(signal.SIGSEGV), CRASH_SIGNALS)
        self.assertEqual(CRASH_SIGNALS[-int(signal.SIGSEGV)], "SIGSEGV")
        self.assertEqual(CRASH_SIGNALS[-int(signal.SIGABRT)], "SIGABRT")
        for name in ("SIGTRAP", "SIGILL", "SIGFPE", "SIGBUS"):
            num = getattr(signal, name, None)
            if num is not None:
                self.assertEqual(CRASH_SIGNALS[-int(num)], name)

    def test_signal_table_keys_are_negative(self) -> None:
        self.assertTrue(all(key < 0 for key in CRASH_SIGNALS))


class ClassifyRunTest(unittest.TestCase):
    def test_plain_exit_is_not_a_crash(self) -> None:
        result = classify_run(0, "")
        self.assertFalse(result.is_crash)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.crash_type, "")

    def test_js_exception_output_is_not_a_crash(self) -> None:
        result = classify_run(1, "SyntaxError: unexpected token\n")
        self.assertFalse(result.is_crash)
        self.assertEqual(result.stderr, "SyntaxError: unexpected token\n")

    def test_signal_death_is_crash(self) -> None:
        result = classify_run(-int(signal.SIGSEGV), "")
        self.assertTrue(result.is_crash)
        self.assertEqual(result.crash_type, "SIGSEGV")
        self.assertEqual(result.signal, "SIGSEGV")
        self.assertTrue(result.signature)

    def test_unknown_negative_returncode_is_not_a_crash(self) -> None:
        # PR-faithful: only known crash signals (or ASAN/assertion markers)
        # classify as crashes; an unmapped negative returncode is ignored.
        result = classify_run(-99, "")
        self.assertFalse(result.is_crash)

    def test_asan_report_is_crash_with_type(self) -> None:
        result = classify_run(1, ASAN_REPORT)
        self.assertTrue(result.is_crash)
        self.assertEqual(result.crash_type, "ASAN-heap-use-after-free")
        self.assertIn("JSC::DFG::JITCode::pdfBundle", result.stack)
        self.assertNotIn("asan_report", " ".join(result.stack).lower())

    def test_asan_exitcode_is_crash_without_report(self) -> None:
        result = classify_run(ASAN_EXITCODE, "")
        self.assertTrue(result.is_crash)
        self.assertEqual(result.crash_type, "signal-99")

    def test_custom_asan_exitcode(self) -> None:
        result = classify_run(42, "", asan_exitcode=42)
        self.assertTrue(result.is_crash)
        result = classify_run(42, "")
        self.assertFalse(result.is_crash)

    def test_assertion_is_crash(self) -> None:
        result = classify_run(1, ASSERT_REPORT)
        self.assertTrue(result.is_crash)
        self.assertEqual(result.crash_type, "RELEASE_ASSERT")

    def test_assertion_failed_variant(self) -> None:
        result = classify_run(-int(signal.SIGABRT), "ASSERTION FAILED in foo\n")
        self.assertTrue(result.is_crash)
        self.assertEqual(result.crash_type, "ASSERTION_FAILED")

    def test_crash_type_priority_asan_over_assertion(self) -> None:
        result = classify_run(1, ASAN_REPORT + ASSERT_REPORT)
        self.assertEqual(result.crash_type, "ASAN-heap-use-after-free")

    def test_stderr_bounded_for_crash_and_non_crash(self) -> None:
        big = "x" * 20000
        crash = classify_run(-int(signal.SIGSEGV), big)
        self.assertLessEqual(len(crash.stderr), 8000)
        plain = classify_run(0, big)
        self.assertLessEqual(len(plain.stderr), 8000)

    def test_custom_stderr_limit(self) -> None:
        result = classify_run(0, "y" * 5000, stderr_limit=1000)
        self.assertEqual(len(result.stderr), 1000)

    def test_signature_is_stable_sha1(self) -> None:
        result = classify_run(-int(signal.SIGSEGV), ASAN_REPORT)
        self.assertRegex(result.signature, r"^[0-9a-f]{16}$")
        again = classify_run(-int(signal.SIGSEGV), ASAN_REPORT)
        self.assertEqual(result.signature, again.signature)

    def test_empty_stderr_crash_signature_still_computed(self) -> None:
        result = classify_run(-int(signal.SIGSEGV), "")
        self.assertTrue(result.signature)
        self.assertEqual(result.stack, ())

    def test_additional_crash_classes(self) -> None:
        self.assertEqual(classify_run(1, "FATAL ERROR: Out of memory").crash_type, "OOM")
        self.assertEqual(
            classify_run(1, "Exception Type: EXC_BAD_ACCESS (SIGSEGV)").crash_type,
            "EXC_BAD_ACCESS",
        )
        self.assertEqual(
            classify_run(1, "Termination Reason: SIGNAL SIGSEGV").crash_type, "SIGSEGV"
        )
        self.assertEqual(classify_run(1, "FATAL ERROR: bad invariant").crash_type, "JSC_FATAL")
        self.assertEqual(classify_run(ASAN_EXITCODE, "").crash_type, f"signal-{ASAN_EXITCODE}")


class ExtractStackTest(unittest.TestCase):
    def test_asan_frames_preferred_over_wtf(self) -> None:
        combined = ASAN_REPORT + WTF_REPORT
        stack = extract_stack(combined)
        self.assertTrue(any(frame.startswith("JSC::DFG::JITCode") for frame in stack))

    def test_wtf_frames_when_no_asan(self) -> None:
        stack = extract_stack(WTF_REPORT)
        self.assertEqual(len(stack), 3)
        self.assertIn("JSC::DFG::JITCompiler::compileFunction", stack[1])

    def test_noise_frames_filtered(self) -> None:
        noisy = (
            "#0 0x1 in __asan_report_error /asan/asan_report.cpp:300\n"
            "#1 0x2 in JSC::Real::frame() /src/frame.cpp:10\n"
            "#2 0x3 in WTF::wtfCrash() wtf/Assertions.cpp:1\n"
        )
        stack = extract_stack(noisy)
        self.assertEqual(stack, ["JSC::Real::frame"])

    def test_all_noise_falls_back_to_raw_frames(self) -> None:
        noisy = "#0 0x1 in __asan_report_error /asan/asan_report.cpp:300\n"
        stack = extract_stack(noisy)
        self.assertEqual(len(stack), 1)

    def test_stack_limit(self) -> None:
        frames = "\n".join(f"#0 0x{i:x} in JSC::F{i}::g() f{i}.cpp:1" for i in range(30))
        stack = extract_stack(frames, limit=5)
        self.assertEqual(len(stack), 5)

    def test_clean_frame_strips_arguments_file_and_offset(self) -> None:
        stack = extract_stack(
            "#0 0xdeadbeef in JSC::Foo::bar(int, char*) + 128 /src/foo.cpp:42\n"
        )
        self.assertEqual(stack, ["JSC::Foo::bar"])

    def test_empty_input(self) -> None:
        self.assertEqual(extract_stack(""), [])


class MakeSignatureTest(unittest.TestCase):
    def test_stack_signature_uses_top_frames(self) -> None:
        stack = ["A::one", "B::two", "C::three", "D::four", "E::five", "F::six"]
        sig = make_signature("SIGSEGV", stack)
        expected_raw = "sigv2::SIGSEGV::" + "|".join(stack[:5])
        expected = hashlib.sha1(expected_raw.encode()).hexdigest()[:16]
        self.assertEqual(sig, expected)

    def test_nostack_signature_uses_normalized_extra(self) -> None:
        sig = make_signature("SIGSEGV", [], extra="boom at 0xdeadbeef 12345")
        self.assertTrue(sig)
        self.assertNotEqual(sig, make_signature("SIGSEGV", [], extra="different fault 99999"))

    def test_signature_deterministic_and_sixteen_hex(self) -> None:
        sig = make_signature("ASAN-x", ["F::g"])
        self.assertRegex(sig, r"^[0-9a-f]{16}$")
        self.assertEqual(sig, make_signature("ASAN-x", ["F::g"]))

    def test_depth_parameter(self) -> None:
        stack = ["A", "B", "C", "D", "E", "F"]
        shallow = make_signature("T", stack, depth=2)
        deep = make_signature("T", stack, depth=6)
        self.assertNotEqual(shallow, deep)


class NormalizeOutputTest(unittest.TestCase):
    def test_addresses_and_numbers_normalized(self) -> None:
        text = "ptr 0xdeadbeef offset 0x1234 count 987654 size 12"
        out = _normalize_output(text)
        self.assertNotIn("0xdeadbeef", out)
        self.assertIn("0xADDR", out)
        self.assertIn("N", out)
        self.assertNotIn("987654", out)
        self.assertNotIn("  ", out)

    def test_small_numbers_preserved(self) -> None:
        out = _normalize_output("line 42 col 7")
        self.assertIn("42", out)
        self.assertIn("7", out)

    def test_limit_keeps_tail(self) -> None:
        out = _normalize_output("a" * 1000 + "TAIL", limit=10)
        self.assertEqual(out, "aaaaaaTAIL")

    def test_none_and_empty(self) -> None:
        self.assertEqual(_normalize_output(""), "")


class ResultHelpersTest(unittest.TestCase):
    def test_timeout_result(self) -> None:
        result = timeout_result(10.0)
        self.assertFalse(result.is_crash)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.crash_type, "timeout")

    def test_exec_error_result(self) -> None:
        result = exec_error_result("boom")
        self.assertFalse(result.is_crash)
        self.assertTrue(result.exec_error)
        self.assertEqual(result.crash_type, "exec-error")
        self.assertEqual(result.stderr, "boom")


class CrashResultTest(unittest.TestCase):
    def test_defaults(self) -> None:
        result = CrashResult(is_crash=False)
        self.assertEqual(result.stack, ())
        self.assertEqual(result.signature, "")


class JscConfigTest(unittest.TestCase):
    def test_default_args_are_immutable_tuple(self) -> None:
        self.assertIsInstance(DEFAULT_ARGS, tuple)
        self.assertIn("--useDollarVM=1", DEFAULT_ARGS)

    def test_resolve_args_override_wins(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"REDAPPLE_JSC_ARGS": "--foo"}, clear=False):
            self.assertEqual(JscConfig.resolve_args(["--bar"]), ("--bar",))

    def test_resolve_args_env(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"REDAPPLE_JSC_ARGS": "--a --b"}, clear=True):
            self.assertEqual(JscConfig.resolve_args(None), ("--a", "--b"))

    def test_resolve_args_default(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("REDAPPLE_JSC_ARGS", None)
            self.assertEqual(JscConfig.resolve_args(None), DEFAULT_ARGS)

    def test_resolve_args_stringified(self) -> None:
        self.assertEqual(JscConfig.resolve_args(["--x", 1]), ("--x", "1"))  # type: ignore[list-item]

    def test_build_env_without_library_path(self) -> None:
        config = JscConfig(binary="/bin/jsc")
        env = config.build_env({"PATH": "/usr/bin"})
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertIn("ASAN_OPTIONS", env)
        self.assertIn("exitcode=99", env["ASAN_OPTIONS"])

    def test_build_env_prepends_library_paths(self) -> None:
        config = JscConfig(binary="/bin/jsc", library_path="/opt/jsc/lib")
        env = config.build_env({"LD_LIBRARY_PATH": "/existing"})
        self.assertEqual(env["LD_LIBRARY_PATH"], "/opt/jsc/lib:/existing")
        self.assertEqual(env["DYLD_LIBRARY_PATH"], "/opt/jsc/lib")

    def test_build_env_extra_env_overrides(self) -> None:
        config = JscConfig(binary="/bin/jsc", extra_env=(("ASAN_OPTIONS", "custom=1"),))
        env = config.build_env({})
        self.assertEqual(env["ASAN_OPTIONS"], "custom=1")

    def test_config_defaults(self) -> None:
        config = JscConfig(binary="jsc")
        self.assertEqual(config.timeout_s, 10.0)
        self.assertIsNone(config.library_path)


class SignaturePropertyTest(unittest.TestCase):
    """Deterministic property checks over randomized crash outputs."""

    def test_addresses_do_not_change_stack_signature(self) -> None:
        rng = random.Random(1234)
        frames = [f"JSC::F{i}::g()" for i in range(8)]
        base = classify_run(
            -int(signal.SIGSEGV),
            "\n".join(f"#{i} 0x{i:x} in {frame} f{i}.cpp:1" for i, frame in enumerate(frames)),
        )
        for _ in range(20):
            mutated = classify_run(
                -int(signal.SIGSEGV),
                "\n".join(
                    f"#{i} 0x{rng.getrandbits(32):x} in {frame} f{i}.cpp:{rng.randint(1, 999)}"
                    for i, frame in enumerate(frames)
                ),
            )
            self.assertEqual(base.signature, mutated.signature)

    def test_distinct_faults_get_distinct_signatures(self) -> None:
        sigs = set()
        for i in range(25):
            result = classify_run(-int(signal.SIGSEGV), f"distinct fault number {i} at 0x{i:x}")
            sigs.add(result.signature)
        self.assertEqual(len(sigs), 25)

    def test_signature_length_and_hex_for_random_inputs(self) -> None:
        rng = random.Random(99)
        for _ in range(50):
            text = "".join(rng.choice("abcXYZ019 _-:") for _ in range(rng.randint(0, 200)))
            sig = make_signature(rng.choice(["SIGSEGV", "ASAN-x", "T"]), [text], extra=text)
            self.assertRegex(sig, re.compile(r"^[0-9a-f]{16}$"))
