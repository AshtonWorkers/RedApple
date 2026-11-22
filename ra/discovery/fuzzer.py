"""Mutation/grammar fuzzer for JSC discovery campaigns.

Ported from PR #3's ``Fuzzer`` and hardened for the M0 trunk: the mutation
operator takes an injected ``random.Random`` (seedable, property-testable),
every candidate runs process-per-case through :class:`JscRunner`, and unique
crashes are deduped through the ledger-backed :class:`CrashSink` instead of an
in-memory dict plus crash files on disk.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ..ledger.ids import UlidFactory
from .coverage import CoverageProvider, CoverageScheduler
from .harness import CrashResult
from .jsc_store import CampaignSummary, CrashRecord
from .minimize import minimize_crash_input
from .mutators import (
    MUTATION_KIND_NAMES,
    mutate_program,
)
from .mutators import (
    mutate as mutate,
)
from .runner import JscRunner

DEFAULT_SEED = 0xA11E
DEFAULT_MAX_EXECUTIONS = 200000
PROGRESS_EVERY = 200
DEFAULT_MINIMIZE_ATTEMPTS = 32
DEFAULT_MINIMIZE_BUDGET_S = 5.0


class CrashSink(Protocol):
    """Persistence boundary for campaign crashes (ledger-backed in production)."""

    async def known_signatures(self) -> set[str]:
        """Signatures already persisted; used for cross-campaign dedup."""
        ...

    async def record_crash(
        self, content: str | bytes, result: CrashResult, meta: Mapping[str, Any]
    ) -> CrashRecord | None:
        """Persist one unique crash; ``None`` when the signature is already known."""
        ...

    async def record_campaign(self, summary: CampaignSummary) -> str:
        """Persist the end-of-campaign summary; returns the claim id."""
        ...

    async def crashes_for_handle(self, handle_id: str) -> list[CrashRecord]:
        """Crash records observed by one lane handle, oldest first."""
        ...


@dataclass(frozen=True)
class CampaignMeta:
    """Context stamped onto every crash record and the campaign summary."""

    handle_id: str
    target: str = ""
    ring_node: str | None = None
    build: str | None = None
    run_id: str | None = None
    campaign_id: str | None = None
    jsc_binary: str = ""
    jsc_args: tuple[str, ...] = ()

    def as_meta_dict(self, campaign_id: str) -> dict[str, Any]:
        return {
            "handle_id": self.handle_id,
            "target": self.target,
            "ring_node": self.ring_node,
            "build": self.build,
            "run_id": self.run_id,
            "campaign_id": campaign_id,
            "jsc_binary": self.jsc_binary,
            "jsc_args": tuple(self.jsc_args),
        }


@dataclass
class CampaignStats:
    """Mutable counters for one campaign."""

    executions: int = 0
    unique_crashes: int = 0
    total_crashes: int = 0
    exec_errors: int = 0
    timeouts: int = 0
    last_exec_error: str = ""
    duration_ms: int = 0
    minimization_attempts: int = 0
    minimization_savings: int = 0
    minimized_crashes: int = 0


@dataclass(frozen=True)
class CampaignResult:
    """Outcome of one fuzzing campaign."""

    campaign_id: str
    records: tuple[CrashRecord, ...]
    stats: CampaignStats
    campaign_claim_id: str | None


class JscFuzzer:
    """Seed-corpus mutation campaign over process-per-case ``jsc`` runs."""

    def __init__(
        self,
        runner: JscRunner,
        corpus: Sequence[str],
        sink: CrashSink,
        meta: CampaignMeta,
        *,
        seed: int = DEFAULT_SEED,
        mutation_kinds: Sequence[str] | None = None,
        mutation_stacks: int = 2,
        coverage_provider: CoverageProvider | None = None,
        use_coverage_scheduler: bool = False,
        minimize_crashes: bool = False,
        minimize_attempts: int = DEFAULT_MINIMIZE_ATTEMPTS,
        minimize_budget_s: float = DEFAULT_MINIMIZE_BUDGET_S,
    ) -> None:
        if not isinstance(corpus, Sequence) or isinstance(corpus, (str, bytes)):
            raise TypeError("corpus must be a sequence of strings")
        if mutation_stacks < 0:
            raise ValueError("mutation_stacks must be non-negative")
        if minimize_attempts < 0:
            raise ValueError("minimize_attempts must be non-negative")
        if minimize_budget_s < 0:
            raise ValueError("minimize_budget_s must be non-negative")
        if mutation_kinds is not None:
            if not mutation_kinds:
                raise ValueError("mutation_kinds must not be empty")
            unknown = sorted(set(mutation_kinds) - set(MUTATION_KIND_NAMES))
            if unknown:
                raise ValueError(f"unknown mutation kinds: {', '.join(unknown)}")
            self._mutation_kinds: tuple[str, ...] | None = tuple(mutation_kinds)
        else:
            self._mutation_kinds = None
        self._runner = runner
        self._corpus: tuple[str, ...] = tuple(corpus) or ("print(1);",)
        self._sink = sink
        self._meta = meta
        self._seed = seed
        self._rng = random.Random(seed)
        self._mutation_stacks = mutation_stacks
        self._minimize_crashes = minimize_crashes
        self._minimize_attempts = minimize_attempts
        self._minimize_budget_s = minimize_budget_s
        self._coverage = (
            CoverageScheduler(coverage_provider)
            if use_coverage_scheduler or coverage_provider is not None
            else None
        )
        self._campaign_id = meta.campaign_id or UlidFactory().new("camp")
        self._known: set[str] = set()
        self._records: list[CrashRecord] = []
        self.stats = CampaignStats()
        self._campaign_claim_id: str | None = None

    @property
    def campaign_id(self) -> str:
        return self._campaign_id

    @property
    def records(self) -> tuple[CrashRecord, ...]:
        return tuple(self._records)

    @property
    def coverage(self) -> CoverageScheduler | None:
        return self._coverage

    async def check_seed_crashes(
        self, should_stop: Callable[[], bool] | None = None
    ) -> int:
        """Run the raw corpus first — some seeds are known crashers.

        Returns the number of previously-unknown crashes recorded.
        """
        await self._load_known()
        recorded = 0
        for content in self._corpus:
            if should_stop is not None and should_stop():
                break
            self.stats.executions += 1
            result = await self._runner.run_source(content)
            self._tally(result)
            await self._observe_coverage(content, content, result)
            if result.is_crash:
                record = await self._record(content, result, should_stop=should_stop)
                if record is not None:
                    recorded += 1
        return recorded

    async def run(
        self,
        time_budget_s: float,
        max_executions: int = DEFAULT_MAX_EXECUTIONS,
        progress: Callable[[int, int, int], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
        record_campaign: bool = True,
    ) -> CampaignResult:
        """Run the mutation campaign until the time budget or execution cap.

        ``progress(executions, unique, total)`` fires every
        ``PROGRESS_EVERY`` executions; ``should_stop()`` is polled each case.
        """
        started = time.monotonic()
        deadline = started + max(0.0, time_budget_s)
        await self.check_seed_crashes(should_stop)
        while time.monotonic() < deadline and self.stats.executions < max_executions:
            if should_stop is not None and should_stop():
                break
            base = self._choose_base()
            content = self._mutate(base)
            self.stats.executions += 1
            result = await self._runner.run_source(content)
            self._tally(result)
            await self._observe_coverage(base, content, result)
            if result.is_crash:
                await self._record(content, result, should_stop=should_stop)
            if progress is not None and self.stats.executions % PROGRESS_EVERY == 0:
                progress(self.stats.executions, self.stats.unique_crashes, self.stats.total_crashes)
        self.stats.duration_ms = int((time.monotonic() - started) * 1000)
        if record_campaign:
            self._campaign_claim_id = await self._sink.record_campaign(
                self._campaign_summary()
            )
        return CampaignResult(
            campaign_id=self._campaign_id,
            records=tuple(self._records),
            stats=self.stats,
            campaign_claim_id=self._campaign_claim_id,
        )

    def _choose_base(self) -> str:
        if self._coverage is not None:
            return self._coverage.choose(self._rng, self._corpus)
        return self._rng.choice(self._corpus)

    def _mutate(self, base: str) -> str:
        content = mutate_program(base, self._rng, kinds=self._mutation_kinds)
        for _ in range(self._rng.randrange(0, self._mutation_stacks + 1)):
            content = mutate_program(content, self._rng, kinds=self._mutation_kinds)
        return content

    async def _observe_coverage(self, base: str, content: str, result: CrashResult) -> None:
        if self._coverage is not None:
            await self._coverage.observe(base, content, result)

    def _campaign_summary(self) -> CampaignSummary:
        coverage_edges = self._coverage.stats.edges if self._coverage is not None else 0
        return CampaignSummary(
            campaign_id=self._campaign_id,
            handle_id=self._meta.handle_id,
            target=self._meta.target,
            ring_node=self._meta.ring_node,
            build=self._meta.build,
            jsc_binary=self._meta.jsc_binary or self._runner.config.binary,
            jsc_args=self._meta.jsc_args or self._runner.config.args,
            seed=self._seed,
            executions=self.stats.executions,
            unique_crashes=self.stats.unique_crashes,
            total_crashes=self.stats.total_crashes,
            exec_errors=self.stats.exec_errors,
            timeouts=self.stats.timeouts,
            duration_ms=self.stats.duration_ms,
            run_id=self._meta.run_id,
            extra={
                "coverage_edges": coverage_edges,
                "minimization_attempts": self.stats.minimization_attempts,
                "minimized_crashes": self.stats.minimized_crashes,
                "mutation_kinds": list(self._mutation_kinds or MUTATION_KIND_NAMES),
            },
        )

    async def _load_known(self) -> None:
        if not self._known:
            self._known = await self._sink.known_signatures()

    def _tally(self, result: CrashResult) -> None:
        if result.exec_error:
            self.stats.exec_errors += 1
            self.stats.last_exec_error = result.stderr
        elif result.timed_out:
            self.stats.timeouts += 1
        if result.is_crash:
            self.stats.total_crashes += 1

    async def _record(
        self,
        content: str,
        result: CrashResult,
        *,
        should_stop: Callable[[], bool] | None = None,
    ) -> CrashRecord | None:
        """Dedup by signature, minimize new crashes, then persist through the sink."""
        if result.signature in self._known:
            return None
        recorded_content = content
        recorded_result = result
        if self._minimize_crashes and self._minimize_attempts > 0:
            minimized = await minimize_crash_input(
                self._runner,
                content,
                result,
                max_attempts=self._minimize_attempts,
                time_budget_s=self._minimize_budget_s,
                should_stop=should_stop,
            )
            self.stats.minimization_attempts += minimized.attempts
            self.stats.minimization_savings += minimized.size_delta
            if minimized.changed and minimized.preserved_signature:
                recorded_content = minimized.content
                recorded_result = minimized.result
                self.stats.minimized_crashes += 1
        record = await self._sink.record_crash(
            recorded_content,
            recorded_result,
            self._meta.as_meta_dict(self._campaign_id),
        )
        if record is None:  # ledger-level duplicate (concurrent campaign)
            self._known.add(result.signature)
            return None
        self._known.add(record.signature)
        self._records.append(record)
        self.stats.unique_crashes += 1
        return record
