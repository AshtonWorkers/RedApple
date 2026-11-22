"""Stochastic race harness (RA-RACE).

Probes TOCTOU/race conditions stochastically with deterministic seeded
schedules, reproduces crashes within explicit flakiness and KCSan-free
reproduction budgets, and persists CAS-bound race claims in the M0 ledger.
"""

from .backend import DeterministicRaceBackend, RaceBackend, ScriptedRaceBackend
from .coverage import CoverageGap, InterleavingCoverage
from .errors import RaceBackendError, RaceError
from .harness import ProbeReport, RaceHarness, ReplayReport, ReproOutcome, RingVerifier
from .models import (
    CLAIM_FORMAT,
    REPRO_FORMAT,
    STATE_FORMAT,
    CrashSummary,
    RaceBudget,
    RaceClaimRecord,
    RaceCrash,
    RaceRunResult,
    RaceSchedule,
    RaceState,
    RaceStep,
    RaceTarget,
    SeedScore,
    canonical_json,
)
from .prng import MAX_SEED, RaceRng, normalize_seed, parse_seed_hex, seed_hex
from .scheduler import build_schedule, schedule_rng_key
from .seeds import (
    FixedSeedDistribution,
    SeedDistribution,
    UniformSeedDistribution,
    WeightedSeedDistribution,
    index_seed,
    score_seed_outcomes,
    seed_sequence,
)
from .store import (
    CLAIM_TYPE_RACE,
    CLAIM_TYPE_STATE,
    LedgerRaceStore,
    RaceCas,
    assert_race_claim_bound,
    race_claim_dedup_key,
    repro_manifest_bytes,
)
from .strategies import (
    SCHEDULE_STRATEGIES,
    ScheduleStrategy,
    build_strategy_steps,
    normalize_strategy,
)

__all__ = [
    "CLAIM_FORMAT",
    "CLAIM_TYPE_RACE",
    "CLAIM_TYPE_STATE",
    "REPRO_FORMAT",
    "STATE_FORMAT",
    "MAX_SEED",
    "CrashSummary",
    "CoverageGap",
    "DeterministicRaceBackend",
    "InterleavingCoverage",
    "FixedSeedDistribution",
    "LedgerRaceStore",
    "ProbeReport",
    "RaceBackend",
    "RaceBackendError",
    "RaceBudget",
    "RaceCas",
    "RaceClaimRecord",
    "RaceCrash",
    "RaceError",
    "RaceHarness",
    "RaceRng",
    "RaceRunResult",
    "RaceSchedule",
    "RaceState",
    "RaceStep",
    "RaceTarget",
    "ReproOutcome",
    "ReplayReport",
    "RingVerifier",
    "SCHEDULE_STRATEGIES",
    "ScheduleStrategy",
    "ScriptedRaceBackend",
    "SeedDistribution",
    "SeedScore",
    "UniformSeedDistribution",
    "WeightedSeedDistribution",
    "assert_race_claim_bound",
    "build_schedule",
    "build_strategy_steps",
    "canonical_json",
    "index_seed",
    "normalize_seed",
    "normalize_strategy",
    "parse_seed_hex",
    "race_claim_dedup_key",
    "repro_manifest_bytes",
    "schedule_rng_key",
    "score_seed_outcomes",
    "seed_hex",
    "seed_sequence",
]
