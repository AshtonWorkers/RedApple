"""Foundry public API."""

from .acceptance import covered_functions, evaluate_acceptance, parser_malloc_reachable
from .cas import ContentAddressedStore, pack_harness_files, unpack_harness_files
from .dialect import load_dialect_file, validate_dialect
from .errors import CasCorrupt, DialectDefect, FoundryError, HarnessRejected
from .foundry import Foundry, PARK_AFTER_ATTEMPTS, ROLLBACK_BUDGET_MS
from .runner import (
    CompileResult,
    DryRunResult,
    compile_harness,
    harness_spec_from_manifest,
    load_manifest,
    measure_harness,
    parse_average_exec_per_sec,
    resolve_clangxx,
    run_dry_run,
)
from .models import (
    AcceptanceDecision,
    AcceptanceMeasurements,
    AttemptRecord,
    Dialect,
    FoundryOutcome,
    FoundryState,
    HarnessSpec,
    RollbackResult,
    now_ms,
)
from .store import FoundryStore, JsonFoundryStore

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
    "JsonFoundryStore",
    "PARK_AFTER_ATTEMPTS",
    "ROLLBACK_BUDGET_MS",
    "RollbackResult",
    "compile_harness",
    "covered_functions",
    "evaluate_acceptance",
    "harness_spec_from_manifest",
    "load_dialect_file",
    "load_manifest",
    "measure_harness",
    "now_ms",
    "pack_harness_files",
    "parse_average_exec_per_sec",
    "parser_malloc_reachable",
    "resolve_clangxx",
    "run_dry_run",
    "unpack_harness_files",
    "validate_dialect",
]
