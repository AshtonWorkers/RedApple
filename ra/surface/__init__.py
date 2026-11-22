"""Attack-surface expansion and prioritization (RA-SFC).

Builds on the surface compiler (``ra.srf``): expands SBPL/XPC/mach-lookup
entry points into a ranked target list persisted through the M0 claim ledger
and fed to discovery lanes and chain search.
"""

from .expand import (
    REGEX_PREFIX,
    capability_risk_total,
    classify_ingress,
    expand_surface,
    harvest_service_names,
    profile_capabilities,
    shape_risk_from_fields,
    xpc_risk_from_spec,
    xpc_risky_fields_for,
)
from .feed import (
    ChainFeed,
    LaneFeed,
    LaneTarget,
    LedgerChainFeed,
    LedgerLaneFeed,
    StaticChainFeed,
    StaticLaneFeed,
    StubChainSearch,
    feed_dicts,
    lane_targets_from_surface,
    rows_to_lane_targets,
)
from .models import (
    CAPABILITY_RISK,
    CAPABILITY_RISK_TOTAL,
    XPC_RISKY_TYPES,
    Capability,
    ExpandedTarget,
    IngressClass,
    SurfaceTarget,
    SurfaceTier,
    TargetList,
)
from .pipeline import RankResult, SurfaceInputs, compile_and_rank, scan_surface_inputs
from .rank import RankConfig, rank_targets, score_target, thin_targets_from_rows, tier_for_score
from .store import (
    InMemorySurfaceStore,
    LedgerSurfaceStore,
    SurfaceStore,
    feed_payload,
    surface_targets_from_rows,
)

__all__ = [
    "CAPABILITY_RISK",
    "CAPABILITY_RISK_TOTAL",
    "REGEX_PREFIX",
    "XPC_RISKY_TYPES",
    "Capability",
    "ChainFeed",
    "ExpandedTarget",
    "IngressClass",
    "InMemorySurfaceStore",
    "LaneFeed",
    "LaneTarget",
    "LedgerChainFeed",
    "LedgerLaneFeed",
    "LedgerSurfaceStore",
    "RankConfig",
    "RankResult",
    "StaticChainFeed",
    "StaticLaneFeed",
    "StubChainSearch",
    "SurfaceInputs",
    "SurfaceStore",
    "SurfaceTarget",
    "SurfaceTier",
    "TargetList",
    "capability_risk_total",
    "classify_ingress",
    "compile_and_rank",
    "expand_surface",
    "feed_dicts",
    "feed_payload",
    "harvest_service_names",
    "lane_targets_from_surface",
    "profile_capabilities",
    "rank_targets",
    "rows_to_lane_targets",
    "scan_surface_inputs",
    "score_target",
    "shape_risk_from_fields",
    "surface_targets_from_rows",
    "thin_targets_from_rows",
    "tier_for_score",
    "xpc_risk_from_spec",
    "xpc_risky_fields_for",
]
