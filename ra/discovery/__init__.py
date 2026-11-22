"""JSC discovery: crash harness, mutation fuzzer, and ledger persistence.

Ports PR #3's WebKit/JSC crash harness into the M0 trunk as a lane-producing
engine. State is persisted exclusively through the claim ledger (see
:mod:`ra.discovery.store`); there are no side JSON/SQLite stores.
"""

from .corpus import DEFAULT_CORPUS_DIR, load_corpus
from .coverage import CoverageProvider, CoverageSample, CoverageScheduler, CoverageStats
from .fuzzer import (
    DEFAULT_MAX_EXECUTIONS,
    DEFAULT_MINIMIZE_ATTEMPTS,
    DEFAULT_MINIMIZE_BUDGET_S,
    DEFAULT_SEED,
    PROGRESS_EVERY,
    CampaignMeta,
    CampaignResult,
    CampaignStats,
    CrashSink,
    JscFuzzer,
    mutate,
)
from .harness import (
    ASAN_EXITCODE,
    DEFAULT_ARGS,
    CrashResult,
    JscConfig,
    classify_run,
    exec_error_result,
    extract_stack,
    make_signature,
    timeout_result,
)
from .minimize import MinimizedInput, minimize_crash_input
from .mutators import (
    MUTATION_KIND_NAMES,
    SPICY,
    TOKENS,
    WRAPPERS,
    MutationKind,
    legacy_mutate,
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
from .runner import JscRunner
from .store import (
    CLAIM_TYPE_CAMPAIGN,
    CLAIM_TYPE_CRASH,
    CampaignSummary,
    CrashRecord,
    LedgerCrashStore,
)

__all__ = [
    "ASAN_EXITCODE",
    "CLAIM_TYPE_CAMPAIGN",
    "CLAIM_TYPE_CRASH",
    "DEFAULT_ARGS",
    "DEFAULT_CORPUS_DIR",
    "DEFAULT_MAX_EXECUTIONS",
    "DEFAULT_MINIMIZE_ATTEMPTS",
    "DEFAULT_MINIMIZE_BUDGET_S",
    "DEFAULT_SEED",
    "MUTATION_KIND_NAMES",
    "PROGRESS_EVERY",
    "SPICY",
    "TOKENS",
    "WRAPPERS",
    "CampaignMeta",
    "CampaignResult",
    "CampaignStats",
    "CampaignSummary",
    "CoverageProvider",
    "CoverageSample",
    "CoverageScheduler",
    "CoverageStats",
    "CrashRecord",
    "CrashResult",
    "CrashSink",
    "JscConfig",
    "JscFuzzer",
    "JscRunner",
    "LedgerCrashStore",
    "MinimizedInput",
    "MutationKind",
    "classify_run",
    "exec_error_result",
    "extract_stack",
    "legacy_mutate",
    "load_corpus",
    "make_signature",
    "minimize_crash_input",
    "mutate",
    "mutate_builtin_call",
    "mutate_gc_stress",
    "mutate_identifier",
    "mutate_jit_warmup",
    "mutate_number",
    "mutate_operator",
    "mutate_program",
    "mutate_string",
    "mutate_wrapper",
    "timeout_result",
]
