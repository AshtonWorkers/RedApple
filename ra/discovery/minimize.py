"""Crash-preserving JavaScript input minimization.

Minimization is a bounded greedy delta-debug pass over lines and then bytes of
UTF-8 text. A candidate is accepted only when ``jsc`` still crashes with the
same signature, so the minimized repro stays ledger-dedup compatible.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from .harness import CrashResult
from .runner import JscRunner


@dataclass(frozen=True)
class MinimizedInput:
    """Result of trying to shrink one crashing JavaScript input."""

    content: str
    result: CrashResult
    attempts: int
    original_size: int
    minimized_size: int
    changed: bool
    preserved_signature: bool

    @property
    def size_delta(self) -> int:
        return self.original_size - self.minimized_size


async def _run_preserving(
    runner: JscRunner,
    candidate: str,
    signature: str,
    should_stop: Callable[[], bool] | None,
) -> CrashResult | None:
    if should_stop is not None and should_stop():
        return None
    try:
        result = await runner.run_source(candidate)
    except Exception:
        return None
    if result.is_crash and result.signature == signature:
        return result
    return None


def _remove_lines(text: str, start: int, count: int) -> str:
    lines = text.splitlines(keepends=True)
    if start >= len(lines):
        return text
    del lines[start : start + count]
    return "".join(lines)


def _remove_span(text: str, start: int, count: int) -> str:
    if start >= len(text):
        return text
    return text[:start] + text[start + count :]


def _line_chunk_sizes(line_count: int) -> list[int]:
    sizes = {max(1, line_count // 2), max(1, line_count // 3), max(1, line_count // 5), 1}
    return sorted((size for size in sizes if size <= line_count), reverse=True)


def _char_chunk_sizes(length: int) -> list[int]:
    sizes = {max(1, length // 2), max(1, length // 4), max(1, length // 8), 32, 8, 1}
    return sorted((size for size in sizes if size <= length), reverse=True)


async def minimize_crash_input(
    runner: JscRunner,
    content: str,
    result: CrashResult,
    *,
    max_attempts: int = 32,
    time_budget_s: float | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> MinimizedInput:
    """Greedily minimize ``content`` while preserving ``result.signature``.

    The pass first removes line chunks, then character chunks. Every candidate
    costs one process execution; ``max_attempts`` and ``time_budget_s`` bound
    the work so minimization cannot stall a campaign.
    """
    if not isinstance(content, str):
        raise TypeError("content must be str")
    if not result.is_crash or not result.signature:
        return MinimizedInput(
            content=content,
            result=result,
            attempts=0,
            original_size=len(content),
            minimized_size=len(content),
            changed=False,
            preserved_signature=False,
        )

    attempts = 0
    current = content
    current_result = result
    deadline = None if time_budget_s is None else time.monotonic() + max(0.0, time_budget_s)
    signature = result.signature

    def budget_left() -> bool:
        if should_stop is not None and should_stop():
            return False
        return deadline is None or time.monotonic() < deadline

    async def try_candidate(candidate: str) -> bool:
        nonlocal attempts, current, current_result
        if candidate == current or not budget_left():
            return False
        preserved = await _run_preserving(runner, candidate, signature, should_stop)
        attempts += 1
        if preserved is None:
            return False
        current = candidate
        current_result = preserved
        return True

    # Line-level pass: remove chunks of whole lines first.
    while attempts < max_attempts and budget_left():
        lines = current.splitlines()
        if len(lines) <= 1:
            break
        improved = False
        for size in _line_chunk_sizes(len(lines)):
            for start in range(0, len(lines), size):
                if attempts >= max_attempts or not budget_left():
                    break
                candidate = _remove_lines(current, start, size)
                if await try_candidate(candidate):
                    improved = True
                    break
            if improved or attempts >= max_attempts or not budget_left():
                break
        if not improved:
            break

    # Character-level pass: shrink long tails/comments/whitespace safely.
    while attempts < max_attempts and budget_left():
        improved = False
        for size in _char_chunk_sizes(len(current)):
            for start in range(0, len(current), size):
                if attempts >= max_attempts or not budget_left():
                    break
                candidate = _remove_span(current, start, size)
                if await try_candidate(candidate):
                    improved = True
                    break
            if improved or attempts >= max_attempts or not budget_left():
                break
        if not improved:
            break

    return MinimizedInput(
        content=current,
        result=current_result,
        attempts=attempts,
        original_size=len(content),
        minimized_size=len(current),
        changed=current != content,
        preserved_signature=current_result.signature == signature,
    )
