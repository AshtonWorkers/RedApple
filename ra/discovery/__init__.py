"""Discovery engines: JSC fuzzing and surface/ImageIO campaigns.

JSC discovery state is persisted through :mod:`ra.discovery.jsc_store`; surface
campaign state is persisted through :mod:`ra.discovery.store`. Both use the M0
claim ledger only.
"""

from .campaign import DiscoveryCampaign, DiscoveryLane
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
from .jsc_store import (
    CLAIM_TYPE_CAMPAIGN,
    CLAIM_TYPE_CRASH,
    CampaignSummary,
    CrashRecord,
    LedgerCrashStore,
)
from .macos import (
    MacOSUnavailable,
    imageio_heif_feed_manifest,
    imageio_heif_feed_source,
    imageio_heif_harness_ref,
    macos_available,
    macos_verification_checklist,
    require_macos,
)
from .minimize import MinimizedInput, minimize_crash_input
from .models import (
    CampaignConfig,
    CampaignState,
    CrashRefLike,
    DiscoveryHarnessRef,
    MutationCase,
)
from .mutate import MutationEngine
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
from .store import LedgerDiscoveryStore

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
    "CampaignConfig",
    "CampaignMeta",
    "CampaignResult",
    "CampaignState",
    "CampaignStats",
    "CampaignSummary",
    "CoverageProvider",
    "CoverageSample",
    "CoverageScheduler",
    "CoverageStats",
    "CrashRecord",
    "CrashRefLike",
    "CrashResult",
    "CrashSink",
    "DiscoveryCampaign",
    "DiscoveryHarnessRef",
    "DiscoveryLane",
    "JscConfig",
    "JscFuzzer",
    "JscRunner",
    "LedgerCrashStore",
    "LedgerDiscoveryStore",
    "MacOSUnavailable",
    "MinimizedInput",
    "MutationCase",
    "MutationEngine",
    "MutationKind",
    "classify_run",
    "exec_error_result",
    "extract_stack",
    "imageio_heif_feed_manifest",
    "imageio_heif_feed_source",
    "imageio_heif_harness_ref",
    "legacy_mutate",
    "load_corpus",
    "macos_available",
    "macos_verification_checklist",
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
    "require_macos",
    "timeout_result",
]
