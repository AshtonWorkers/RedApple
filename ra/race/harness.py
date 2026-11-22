"""Stochastic race harness orchestration (RA-RACE).

Probe phase samples seeds from a distribution and executes deterministic
schedules on a backend. Crash findings are reproduced within the KCSan-free
repro budget, scored for flakiness against the flake budget, and persisted as
CAS-bound ``race`` claims in the M0 ledger. Replay rebuilds the exact schedule
from the claim's seed/digest and re-executes it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from ..errors import BudgetExhausted, FormatFail, OutOfRing
from ..ledger import Ledger, UlidFactory
from ..ledger.ids import now_ms
from .backend import RaceBackend
from .errors import RaceBackendError
from .models import (
    RaceBudget,
    RaceClaimRecord,
    RaceCrash,
    RaceRunResult,
    RaceSchedule,
    RaceState,
    RaceTarget,
)
from .prng import RaceRng, normalize_seed, seed_hex
from .scheduler import build_schedule
from .seeds import SeedDistribution
from .store import LedgerRaceStore, RaceCas
from .strategies import ScheduleStrategy, normalize_strategy


class RingVerifier(Protocol):
    """Ring gate for pinning race targets (structurally satisfied by RingManager)."""

    def assert_in_ring(
        self,
        build: str,
        *,
        ipsw_sha: str | None = None,
        xcode: str | None = None,
        sdk: str | None = None,
        webkit_commit: str | None = None,
    ) -> Mapping[str, Any]:
        """Return the matching ring node row or raise OutOfRing."""
        ...


@dataclass(frozen=True)
class ReproOutcome:
    """Result of replay attempts for one observed crash."""

    reproduced: bool
    attempts: int
    signatures: tuple[str, ...]


@dataclass(frozen=True)
class ProbeReport:
    """Summary of one stochastic probe session."""

    target: str
    session: int
    iterations_requested: int
    iterations_completed: int
    truncated_by_budget: bool
    parked: bool
    parked_reason: str | None
    claims: tuple[str, ...]
    state: RaceState


def _normalize_strategies(strategies: tuple[str, ...]) -> tuple[ScheduleStrategy, ...]:
    if not strategies:
        raise FormatFail("race harness requires at least one schedule strategy")
    seen: set[ScheduleStrategy] = set()
    normalized: list[ScheduleStrategy] = []
    for strategy in strategies:
        name = normalize_strategy(strategy)
        if name not in seen:
            seen.add(name)
            normalized.append(name)
    return tuple(normalized)


@dataclass(frozen=True)
class ReplayReport:
    """Result of deterministic replay from a persisted race claim."""

    claim_id: str
    schedule_digest: str
    reproduced: bool
    attempts: int
    crashes: tuple[RaceCrash, ...]
    signatures: tuple[str, ...]


class RaceHarness:
    """Stochastic race probing, reproduction, and replay over a lane backend."""

    def __init__(
        self,
        ledger: Ledger,
        backend: RaceBackend,
        *,
        cas: RaceCas,
        ring: RingVerifier | None = None,
        budget: RaceBudget | None = None,
        ids: UlidFactory | None = None,
        strategies: tuple[str, ...] = ("random",),
    ) -> None:
        self._ledger = ledger
        self._backend = backend
        self._ring = ring
        self._budget = budget or RaceBudget()
        self._ids = ids or UlidFactory()
        self.store = LedgerRaceStore(ledger, cas, ids=self._ids)
        self._cas = cas
        self._strategies = _normalize_strategies(strategies)

    # -- ring pinning ----------------------------------------------------

    def _assert_ring(self, target: RaceTarget) -> None:
        if self._ring is None:
            return
        row = self._ring.assert_in_ring(
            target.build,
            ipsw_sha=target.ipsw_sha,
            xcode=target.xcode,
            sdk=target.sdk,
            webkit_commit=target.webkit_commit,
        )
        node_id = str(row.get("ring_node_id") or row.get("id") or "")
        if node_id and node_id != target.ring_node:
            raise OutOfRing(
                f"build {target.build} resolves to ring node {node_id}, "
                f"not pinned node {target.ring_node}"
            )

    @staticmethod
    def _check_run(schedule: RaceSchedule, run: RaceRunResult) -> None:
        if run.schedule_digest != schedule.digest:
            raise RaceBackendError(
                f"race backend returned digest {run.schedule_digest} for schedule "
                f"{schedule.digest}"
            )
        if run.steps_executed > len(schedule.steps):
            raise RaceBackendError(
                f"race backend executed {run.steps_executed} steps for schedule "
                f"with {len(schedule.steps)} steps"
            )

    # -- probing ---------------------------------------------------------

    async def probe(
        self,
        target: RaceTarget,
        distribution: SeedDistribution,
        *,
        iterations: int,
        master_seed: int,
        budget: RaceBudget | None = None,
        run_id: str | None = None,
    ) -> ProbeReport:
        """Run a stochastic probe session over ``target``.

        Seeds are sampled from ``distribution`` under a master seed, so the
        session itself replays deterministically (RA-RACE-002). Budget state is
        loaded from and persisted to the ledger around the session.
        """
        budget = budget or self._budget
        if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
            raise FormatFail("probe iterations must be a positive int")
        master_seed = normalize_seed(master_seed)
        self._assert_ring(target)

        state = await self.store.load_state(target.name)
        if state is None:
            state = RaceState.initial(
                target=target.name,
                master_seed=master_seed,
                distribution=distribution.describe(),
                updated_ms=now_ms(),
            )
        if state.parked:
            raise BudgetExhausted(
                f"race target {target.name} is parked: {state.parked_reason}"
            )
        remaining = budget.max_probes - state.probes
        if remaining <= 0:
            raise BudgetExhausted("race probe budget exhausted for target")
        planned = min(iterations, remaining)
        truncated = planned < iterations

        rng = RaceRng(f"ra.race.probe|{seed_hex(master_seed)}|{target.name}|{state.session}")
        claims: list[str] = []
        consecutive_errors = 0
        aborted: RaceBackendError | None = None
        completed = 0

        for _ in range(planned):
            strategy = self._strategies[rng.randbelow(len(self._strategies))]
            seed = distribution.sample(rng)
            schedule = build_schedule(target, seed, iteration=state.attempts, strategy=strategy)
            state = state.next_attempt()
            try:
                run = await self._backend.run_schedule(schedule)
                self._check_run(schedule, run)
            except Exception as exc:
                state = state.record_error()
                consecutive_errors += 1
                if consecutive_errors >= budget.max_consecutive_errors:
                    aborted = RaceBackendError(
                        f"race backend failed {consecutive_errors} times consecutively"
                    )
                    aborted.__cause__ = exc
                    break
                continue
            consecutive_errors = 0
            completed += 1
            state = state.record_probe(seed, len(run.crashes))
            if run.crashes:
                for index, crash in enumerate(run.crashes):
                    claim_id, state = await self._probe_crash(
                        target, schedule, crash, index, budget, state, run_id=run_id
                    )
                    claims.append(claim_id)
                    if state.flakes > budget.flake_budget and not state.parked:
                        state = state.park("flake_budget")
                    if state.parked:
                        break
            if state.parked:
                break

        state = state.next_session(updated_ms=now_ms())
        await self.store.save_state(state)
        if aborted is not None:
            raise aborted
        return ProbeReport(
            target=target.name,
            session=state.session,
            iterations_requested=iterations,
            iterations_completed=completed,
            truncated_by_budget=truncated,
            parked=state.parked,
            parked_reason=state.parked_reason,
            claims=tuple(claims),
            state=state,
        )

    async def _probe_crash(
        self,
        target: RaceTarget,
        schedule: RaceSchedule,
        crash: RaceCrash,
        index: int,
        budget: RaceBudget,
        state: RaceState,
        *,
        run_id: str | None,
    ) -> tuple[str, RaceState]:
        """Reproduce, score, and persist one observed crash."""
        outcome = await self.reproduce(schedule, crash, attempts=budget.repro_budget)
        record = RaceClaimRecord(
            target=target.name,
            target_digest=target.target_digest,
            ring_node=target.ring_node,
            build=target.build,
            corpus_digest=target.corpus_digest,
            seed=schedule.seed,
            seed_hex=schedule.seed_hex,
            iteration=schedule.iteration,
            schedule_digest=schedule.digest,
            outcome="reproduced" if outcome.reproduced else "flaky",
            reproduced=outcome.reproduced,
            replay_attempts=outcome.attempts,
            backend=self._backend.name,
            deterministic=self._backend.deterministic,
            flake_budget=budget.flake_budget,
            repro_budget=budget.repro_budget,
            crash=crash.summary(),
            created_ms=now_ms(),
        )
        claim_id = await self.store.save_crash_claim(
            record, schedule=schedule, crash=crash, run_id=run_id
        )
        updated = state.record_reproduction(outcome.attempts, outcome.reproduced)
        return claim_id, updated

    # -- reproduction ----------------------------------------------------

    async def reproduce(
        self, schedule: RaceSchedule, crash: RaceCrash, *, attempts: int = 1
    ) -> ReproOutcome:
        """Replay ``schedule`` up to ``attempts`` times seeking ``crash``.

        Attempts are KCSan-free deterministic replays; the caller's budget
        bounds them (RA-RACE-006).
        """
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
            raise FormatFail("reproduce attempts must be a positive int")
        target_signature = crash.signature()
        seen: list[str] = []
        for attempt in range(attempts):
            run = await self._backend.run_schedule(schedule)
            self._check_run(schedule, run)
            signatures = tuple(crash.signature() for crash in run.crashes)
            seen.extend(signatures)
            if target_signature in signatures:
                return ReproOutcome(
                    reproduced=True, attempts=attempt + 1, signatures=tuple(seen)
                )
        return ReproOutcome(reproduced=False, attempts=attempts, signatures=tuple(seen))

    # -- replay ----------------------------------------------------------

    async def replay_claim(self, claim_id: str, *, attempts: int = 1) -> ReplayReport:
        """Deterministically replay a persisted race claim from its seed (RA-RACE-004).

        The claim's CAS binding is verified first; the schedule bytes are read
        from the CAS by digest, the target is re-checked against the version
        ring, and the schedule is re-executed until the recorded crash
        signature reappears or ``attempts`` is exhausted.
        """
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
            raise FormatFail("replay attempts must be a positive int")
        record = await self.store.verify_claim(claim_id)
        schedule_bytes = await self._cas.get(record.schedule_digest)
        schedule = RaceSchedule.from_bytes(schedule_bytes)
        self._assert_ring(schedule.target)

        target_signature = record.crash.signature()
        seen: list[str] = []
        crashes: tuple[RaceCrash, ...] = ()
        reproduced = False
        used = 0
        for _ in range(attempts):
            run = await self._backend.run_schedule(schedule)
            self._check_run(schedule, run)
            used += 1
            crashes = run.crashes
            signatures = tuple(crash.signature() for crash in run.crashes)
            seen.extend(signatures)
            if target_signature in signatures:
                reproduced = True
                break
        return ReplayReport(
            claim_id=claim_id,
            schedule_digest=record.schedule_digest,
            reproduced=reproduced,
            attempts=used,
            crashes=crashes,
            signatures=tuple(seen),
        )

    # -- read helpers ----------------------------------------------------

    async def claims_for_target(self, target: str) -> list[dict[str, Any]]:
        """Race claims for one target with parsed records."""
        return self.store.race_claims(target=target)

    async def state_for_target(self, target: str) -> RaceState | None:
        """Latest persisted state snapshot for one target."""
        return await self.store.load_state(target)


__all__ = [
    "ProbeReport",
    "RaceHarness",
    "ReproOutcome",
    "ReplayReport",
    "RingVerifier",
]
