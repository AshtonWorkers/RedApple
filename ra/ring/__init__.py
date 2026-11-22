"""Version ring: pinned nodes, ingest, corpora, and nightly replay (RA-RING)."""

from __future__ import annotations

from .corpus import CorpusRegistry
from .ingest import ArtifactFetcher, ArtifactStore, RingIngester
from .manager import (
    BOOT_FAILURE_THRESHOLD,
    DEFAULT_HISTORY_CAPACITY,
    MIN_CURRENT_NODES,
    MIN_PINNED_NODES,
    RingManager,
)
from .models import IngestedSource, RingNodeSpec, RingSource
from .replay import (
    FindingSource,
    LedgerFindingSource,
    NightlyReplayScheduler,
    ReplayBackend,
    ReplayFinding,
    ReplayOutcome,
    ReplayResult,
    ReplayRunSummary,
)

__all__ = [
    "BOOT_FAILURE_THRESHOLD",
    "DEFAULT_HISTORY_CAPACITY",
    "MIN_CURRENT_NODES",
    "MIN_PINNED_NODES",
    "ArtifactFetcher",
    "ArtifactStore",
    "CorpusRegistry",
    "FindingSource",
    "IngestedSource",
    "LedgerFindingSource",
    "NightlyReplayScheduler",
    "ReplayBackend",
    "ReplayFinding",
    "ReplayOutcome",
    "ReplayResult",
    "ReplayRunSummary",
    "RingIngester",
    "RingManager",
    "RingNodeSpec",
    "RingSource",
]
