"""Foundry public API."""

from .acceptance import (
    coverage_edge_counts,
    covered_functions,
    evaluate_acceptance,
    parser_malloc_reachable,
)
from .cas import ContentAddressedStore, pack_harness_files, unpack_harness_files
from .dialect import load_dialect_file, validate_dialect
from .errors import CasCorrupt, DialectDefect, FoundryError, HarnessRejected
from .foundry import PARK_AFTER_ATTEMPTS, ROLLBACK_BUDGET_MS, Foundry, FoundryOutcome
from .models import (
    AcceptanceDecision,
    AcceptanceMeasurements,
    AttemptRecord,
    Dialect,
    FoundryState,
    HarnessSpec,
    now_ms,
)
from .runner import (
    CompileResult,
    DryRunResult,
    compile_harness,
    harness_spec_from_manifest,
    load_manifest,
    measure_harness,
    resolve_clangxx,
    run_dry_run,
    run_seed_coverage,
)
from .store import FoundryStore, JsonFoundryStore, LedgerFoundryStore
from .synthesis import (
    HarnessSynthesizer,
    SynthesisRequest,
    SynthesizedHarness,
    TemplateHarnessSynthesizer,
)

__all__ = [
    "AcceptanceDecision",
    "AcceptanceMeasurements",
    "AttemptRecord",
    "CasCorrupt",
    "CompileResult",
    "ContentAddressedStore",
    "Dialect",
    "DialectDefect",
    "DryRunResult",
    "Foundry",
    "FoundryError",
    "FoundryOutcome",
    "FoundryState",
    "FoundryStore",
    "HarnessRejected",
    "HarnessSpec",
    "HarnessSynthesizer",
    "JsonFoundryStore",
    "LedgerFoundryStore",
    "PARK_AFTER_ATTEMPTS",
    "ROLLBACK_BUDGET_MS",
    "SynthesisRequest",
    "SynthesizedHarness",
    "TemplateHarnessSynthesizer",
    "compile_harness",
    "coverage_edge_counts",
    "covered_functions",
    "evaluate_acceptance",
    "harness_spec_from_manifest",
    "load_dialect_file",
    "load_manifest",
    "measure_harness",
    "now_ms",
    "pack_harness_files",
    "parser_malloc_reachable",
    "resolve_clangxx",
    "run_dry_run",
    "run_seed_coverage",
    "unpack_harness_files",
    "validate_dialect",
]
