"""Groom planner and primitive validator ladder (RA-GRM / RA-LAD)."""

from .allocators import (
    AllocatorModel,
    AllocatorModelSet,
    adjacent_size_classes,
    is_valid_size_class,
    load_allocator_models,
    size_class_for_kb,
)
from .foundry import FoundryDialectGate, LedgerFoundryDefectSink
from .heapdiff import HeapDiffResult, diff_heap_states, validate_heap_diff
from .interfaces import (
    FoundryDefectSink,
    FoundryDialectValidator,
    PressAdvisor,
    PrimitiveAttemptPort,
    TriageService,
)
from .ladder import LadderRunner
from .models import (
    LADDER_ORDER,
    MAX_GROOM_CANDIDATES,
    MAX_GROOM_DEPTH,
    PROMOTION_CONSECUTIVE_PASSES,
    RUNG_ASSERTIONS,
    AttemptEvidence,
    CrashCase,
    GroomCandidate,
    GroomPlan,
    GroomPlanOutcome,
    HeapDiff,
    HeapDiffExpectation,
    HeapObject,
    HeapSnapshot,
    LadderOutcome,
    LadderRung,
    RungResult,
    TriageResult,
)
from .planner import GroomPlanner
from .service import GroomProcessResult, GroomService
from .stubs import NullAttemptPort, NullPressAdvisor, StaticTriage

__all__ = [
    "LADDER_ORDER",
    "MAX_GROOM_CANDIDATES",
    "MAX_GROOM_DEPTH",
    "PROMOTION_CONSECUTIVE_PASSES",
    "RUNG_ASSERTIONS",
    "AllocatorModel",
    "AllocatorModelSet",
    "AttemptEvidence",
    "CrashCase",
    "FoundryDefectSink",
    "FoundryDialectGate",
    "FoundryDialectValidator",
    "GroomCandidate",
    "GroomPlan",
    "GroomPlanOutcome",
    "GroomPlanner",
    "GroomProcessResult",
    "GroomService",
    "HeapDiff",
    "HeapDiffExpectation",
    "HeapDiffResult",
    "HeapObject",
    "HeapSnapshot",
    "LadderOutcome",
    "LadderRung",
    "LadderRunner",
    "LedgerFoundryDefectSink",
    "NullAttemptPort",
    "NullPressAdvisor",
    "PressAdvisor",
    "PrimitiveAttemptPort",
    "RungResult",
    "StaticTriage",
    "TriageResult",
    "TriageService",
    "adjacent_size_classes",
    "diff_heap_states",
    "is_valid_size_class",
    "load_allocator_models",
    "size_class_for_kb",
    "validate_heap_diff",
]
