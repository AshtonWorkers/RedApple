"""JSC crash harness: run classification, stack extraction, and signatures.

Ported from PR #3's ``redapple_discovery/fuzz.py`` crash harness and hardened
for the M0 trunk: typed dataclasses, bounded stderr, platform-correct signal
table, macOS Mach exception classes, and pure functions so every piece is
unit/property testable on Linux.
"""

from __future__ import annotations

import hashlib
import os
import re
import signal as _signal
from collections.abc import Sequence
from dataclasses import dataclass

# Signals that indicate an engine crash (as negative returncodes). Signal
# numbers differ across OSes (SIGBUS is 7 on Linux, 10 on macOS), so resolve
# them from the signal module instead of hardcoding.
CRASH_SIGNALS: dict[int, str] = {
    -int(getattr(_signal, name)): name
    for name in (
        "SIGSEGV",
        "SIGABRT",
        "SIGTRAP",
        "SIGILL",
        "SIGFPE",
        "SIGBUS",
        "SIGSYS",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGEMT",
    )
    if getattr(_signal, name, None) is not None
}

ASAN_RE = re.compile(r"(?:ERROR: )?AddressSanitizer: ([a-z0-9\-]+)", re.I)
ASSERT_RE = re.compile(
    r"(ASSERTION FAILED|RELEASE_ASSERT|SHOULD NEVER BE REACHED|CHECK failed|CHECK_FAILED|UNREACHABLE)",
    re.I,
)
FATAL_RE = re.compile(r"(?:^|\n)\s*(?:FATAL ERROR|Fatal error)\b", re.I)
OOM_RE = re.compile(
    r"(FATAL ERROR: Out of memory|OutOfMemoryError|MemoryError|Unable to allocate|"
    r"allocation size too big|allocation-size-too-big)",
    re.I,
)
MACH_EXCEPTION_RE = re.compile(r"Exception Type:\s*(EXC_[A-Z0-9_]+)", re.I)
TERMINATION_SIGNAL_RE = re.compile(r"Termination Reason:\s*[^\n]*?\b(SIG(?!NALS?\b)[A-Z]+)\b", re.I)
# ASAN frame: "    #3 0x.... in JSC::Foo::bar(...) file.cpp:123"
ASAN_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+([^\n]+?)(?:\s+[^\s]+:\d+)?$", re.M | re.I)
# WTF/jsc frame: "3   0x....  JSC::Foo::bar"  (symbol last)
WTF_FRAME_RE = re.compile(r"^\s*\d+\s+0x[0-9a-f]+\s+(.+?)\s*$", re.M | re.I)
# macOS crash-log frame: "0   com.apple.JavaScriptCore  0x.... symbol + 16"
MAC_FRAME_RE = re.compile(
    r"^\s*\d+\s+[A-Za-z0-9_.+/-]+\s+0x[0-9a-f]+\s+(.+?)(?:\s+\+\s+\d+)?\s*$",
    re.M | re.I,
)

STDERR_CRASH_LIMIT = 8000
STACK_LIMIT = 12
SIGNATURE_DEPTH = 5
NORMALIZE_LIMIT = 600
SIGNATURE_LENGTH = 16
SIGNATURE_VERSION = "sigv2"
ASAN_EXITCODE = 99

NOISE_FRAMES = (
    "asan",
    "__interceptor",
    "wtfcrash",
    "wtfreportbacktrace",
    "abort",
    "raise",
    "pthread_kill",
)

# Debug/validation flags: make JSC assert aggressively so fuzzing surfaces
# latent engine bugs instead of only hard signals. Overridable via
# REDAPPLE_JSC_ARGS or an explicit args override.
DEFAULT_ARGS: tuple[str, ...] = (
    "--useDollarVM=1",
    "--useConcurrentJIT=false",
    "--thresholdForJITAfterWarmUp=10",
    "--thresholdForOptimizeAfterWarmUp=30",
    "--thresholdForFTLOptimizeAfterWarmUp=60",
    "--validateBCE=true",
    "--collectContinuously=true",
    "--maxPerThreadStackUsage=1572864",
)


@dataclass(frozen=True)
class CrashResult:
    """Outcome of running one JavaScript candidate through ``jsc``."""

    is_crash: bool
    crash_type: str = ""
    signal: str = ""
    returncode: int = 0
    stderr: str = ""
    stack: tuple[str, ...] = ()
    signature: str = ""
    timed_out: bool = False
    exec_error: bool = False


def _clean_frame(symbol: str) -> str:
    symbol = symbol.strip()
    symbol = re.sub(r"\(.*$", "", symbol)  # drop argument lists
    symbol = re.sub(r"\s+[^\s]+\.(?:cpp|h|c|mm):\d+.*$", "", symbol)
    symbol = re.sub(r"\s+\+\s+(?:0x[0-9a-f]+|\d+)$", "", symbol, flags=re.I)
    symbol = re.sub(r"\+0x[0-9a-f]+$", "", symbol, flags=re.I)
    return symbol.strip()


def _is_noise(frame: str) -> bool:
    lowered = frame.lower()
    return any(noise in lowered for noise in NOISE_FRAMES)


def extract_stack(stderr: str, limit: int = STACK_LIMIT) -> list[str]:
    """Extract symbolized frames from ASAN, WTF/jsc, or macOS crash output."""
    frames = [_clean_frame(match.group(1)) for match in ASAN_FRAME_RE.finditer(stderr)]
    if not frames:
        frames = [_clean_frame(match.group(1)) for match in WTF_FRAME_RE.finditer(stderr)]
    if not frames:
        frames = [_clean_frame(match.group(1)) for match in MAC_FRAME_RE.finditer(stderr)]
    cleaned = [frame for frame in frames if frame and not _is_noise(frame)]
    return (cleaned or frames)[:limit]


def _normalize_output(text: str, limit: int = NORMALIZE_LIMIT) -> str:
    """Normalize crash output for signatures.

    PIDs, addresses, long hex tokens, source line/column numbers, and large
    decimal numbers are stripped so repeats of one fault collapse while
    distinct faults stay distinct.
    """
    text = (text or "")[-limit:]
    text = re.sub(r"==\d+==", "==PID==", text)
    text = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", text)
    text = re.sub(r"\b[0-9a-fA-F]{8,}\b", "HEX", text)
    text = re.sub(r"\b\d{3,}\b", "N", text)
    text = re.sub(r":\d+(?::\d+)?\b", ":N", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def make_signature(
    crash_type: str,
    stack: Sequence[str],
    depth: int = SIGNATURE_DEPTH,
    extra: str = "",
) -> str:
    """Stable crash signature: SHA1 of versioned type plus top stack frames.

    When no symbolized stack exists, the normalized crash output discriminates
    so distinct stackless faults do not collapse into one signature. The length
    is 16 hex chars (64 bits) to keep ledger dedup collisions negligible.
    """
    top = "|".join(stack[:depth])
    raw = (
        f"{SIGNATURE_VERSION}::{crash_type}::{top}"
        if top
        else f"{SIGNATURE_VERSION}::{crash_type}::nostack::{_normalize_output(extra)}"
    )
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:SIGNATURE_LENGTH]


def _crash_type_for(
    *,
    asan: re.Match[str] | None,
    oom: re.Match[str] | None,
    assertion: re.Match[str] | None,
    mach: re.Match[str] | None,
    termination: re.Match[str] | None,
    fatal: re.Match[str] | None,
    signal: str,
    returncode: int,
    asan_exit: bool,
) -> str:
    if asan:
        return "ASAN-" + asan.group(1).lower()
    if oom:
        return "OOM"
    if assertion:
        return assertion.group(1).upper().replace(" ", "_")
    if mach:
        return mach.group(1).upper()
    if termination:
        return termination.group(1).upper()
    if fatal:
        return "JSC_FATAL"
    if signal:
        return signal
    if asan_exit:
        return f"signal-{returncode}"
    return ""


def classify_run(
    returncode: int,
    stderr: str,
    *,
    asan_exitcode: int = ASAN_EXITCODE,
    stderr_limit: int = STDERR_CRASH_LIMIT,
) -> CrashResult:
    """Decide whether a finished ``jsc`` run is a genuine engine crash.

    A crash is a signal death, an ASAN report, an assertion/fatal marker, a
    Mach exception, a termination signal, OOM, or the configured ASAN
    exitcode. Ordinary JS exceptions exit 0/1 with no crash markers and are
    not crashes.
    """
    bounded = stderr[-stderr_limit:] if stderr else ""
    asan = ASAN_RE.search(bounded)
    oom = OOM_RE.search(bounded)
    assertion = ASSERT_RE.search(bounded)
    mach = MACH_EXCEPTION_RE.search(bounded)
    termination = TERMINATION_SIGNAL_RE.search(bounded)
    fatal = FATAL_RE.search(bounded)
    signal = CRASH_SIGNALS.get(returncode, "")
    asan_exit = returncode == asan_exitcode
    found = signal or asan or oom or assertion or mach or termination or fatal or asan_exit

    if not found:
        return CrashResult(is_crash=False, returncode=returncode, stderr=bounded)

    crash_type = _crash_type_for(
        asan=asan,
        oom=oom,
        assertion=assertion,
        mach=mach,
        termination=termination,
        fatal=fatal,
        signal=signal,
        returncode=returncode,
        asan_exit=asan_exit,
    )
    stack = extract_stack(bounded)
    signature = make_signature(crash_type, stack, extra="" if stack else bounded)
    return CrashResult(
        is_crash=True,
        crash_type=crash_type,
        signal=signal or (termination.group(1).upper() if termination else ""),
        returncode=returncode,
        stderr=bounded,
        stack=tuple(stack),
        signature=signature,
    )


def timeout_result(timeout_s: float) -> CrashResult:
    """Result for a candidate that exceeded the per-case timeout."""
    return CrashResult(
        is_crash=False, timed_out=True, crash_type="timeout", stderr=f"timeout:{timeout_s}"
    )


def exec_error_result(message: str) -> CrashResult:
    """Result for a candidate that could not be executed at all."""
    return CrashResult(is_crash=False, exec_error=True, crash_type="exec-error", stderr=message)


@dataclass(frozen=True)
class JscConfig:
    """Configuration for one ``jsc`` binary invocation profile."""

    binary: str
    args: tuple[str, ...] = ()
    timeout_s: float = 10.0
    library_path: str | None = None
    extra_env: tuple[tuple[str, str], ...] = ()
    max_input_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if self.max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")

    @staticmethod
    def resolve_args(override: Sequence[str] | None = None) -> tuple[str, ...]:
        """Resolve JSC flags: explicit override, then REDAPPLE_JSC_ARGS, then defaults."""
        if override is not None:
            return tuple(str(arg) for arg in override)
        env_args = os.environ.get("REDAPPLE_JSC_ARGS")
        if env_args:
            return tuple(env_args.split())
        return DEFAULT_ARGS

    def build_env(self, base_env: dict[str, str]) -> dict[str, str]:
        """Build the subprocess environment with ASAN and library path settings."""
        env = dict(base_env)
        if self.library_path:
            for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
                existing = env.get(var, "")
                env[var] = f"{self.library_path}:{existing}" if existing else self.library_path
        env.setdefault(
            "ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=1:exitcode=99"
        )
        env.update(dict(self.extra_env))
        return env
