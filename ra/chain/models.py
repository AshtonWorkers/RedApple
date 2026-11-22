"""Data models for RedApple chain search and join pricing (RA-CHN/RA-JON)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

JOIN_TRIALS = 10_000
LIVE_LOWER_BOUND = 0.99
RESEARCH_LOWER_BOUND = 0.90
WILSON_Z = 1.959_963_984_540_054
MAX_CHAIN_NODES = 50_000
CHAIN_DEADLINE_S = 5.0
MIN_EDGE_COST = 0.1
PAC_SPTM_MULTIPLIER = 3.0
MAX_ESCALATION_DELTA = 1_000_000
MAX_PRICING_FACTOR = 1_000_000.0
DENSITY_WINDOW_MS = 90 * 60 * 1000
DENSITY_FLOOR_PER_HOUR = 0.25


class AssertionKind(StrEnum):
    """Invariant categories every join assertion must cover."""

    ADDRESS_VALIDITY = "address_validity"
    RIGHT_LIVENESS = "right_liveness"
    SIGNATURE_VALIDITY = "signature_validity"
    SANDBOX_STATE = "sandbox_state"


REQUIRED_ASSERTION_KINDS = frozenset(
    {
        AssertionKind.ADDRESS_VALIDITY,
        AssertionKind.RIGHT_LIVENESS,
        AssertionKind.SIGNATURE_VALIDITY,
    }
)
KNOWN_ASSERTION_KINDS = frozenset(AssertionKind)


class JoinState(StrEnum):
    """Measured reliability states for a ledger join row."""

    CANDIDATE = "candidate"
    RESEARCH = "research"
    LIVE = "live"
    FAILED = "failed"


CHAIN_CLAIM_TYPES = (
    "bug_class",
    "rung",
    "groom",
    "gadget_set",
    "root_cause",
)
DEFAULT_EDGE_STATES = (JoinState.RESEARCH.value, JoinState.LIVE.value)


@dataclass(frozen=True)
class JoinAssertion:
    """One named invariant assertion inside a join program."""

    kind: str
    name: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "detail": self.detail}


@dataclass(frozen=True)
class JoinProgram:
    """A join as one deterministic code artifact: A -> assertions -> B."""

    join_id: str
    a_claim: str
    b_claim: str
    assertions: tuple[JoinAssertion, ...]
    repro: str
    trials: int = JOIN_TRIALS

    @property
    def assertion_kinds(self) -> tuple[str, ...]:
        return tuple(assertion.kind for assertion in self.assertions)


@dataclass(frozen=True)
class PrimitiveProfile:
    """Optional ladder/groom facts for one primitive claim."""

    privilege_delta: int | None = None
    impact_delta: int | None = None
    pac: bool = False
    sptm: bool = False
    persistence: bool = False
    zero_click: bool = False
    ingress_weight: float | None = None


@dataclass(frozen=True)
class ChainNode:
    """One primitive/escalation node in the chain graph."""

    id: str
    claim_id: str
    claim_type: str
    privilege_delta: int = 0
    impact_delta: int = 0
    pac: bool = False
    sptm: bool = False
    persistence: bool = False
    zero_click: bool = False
    ingress_weight: float = 1.0
    entry_point_id: str | None = None

    @property
    def protected(self) -> bool:
        return self.pac or self.sptm

    @property
    def escalation_delta(self) -> int:
        return self.privilege_delta + self.impact_delta


@dataclass(frozen=True)
class ChainEdge:
    """A priced ledger join directed from ``a_claim`` to ``b_claim``."""

    id: str
    a_claim: str
    b_claim: str
    lower_bound: float
    state: str
    created: int = 0
    reliability: float | None = None


@dataclass(frozen=True)
class ChainGraph:
    """Immutable graph view used by the chain search."""

    nodes: Mapping[str, ChainNode]
    edges: tuple[ChainEdge, ...]
    skipped_edges: int = 0


@dataclass(frozen=True)
class ChainPath:
    """A zero-click-ingress-to-persistence path."""

    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    cost: float
    join_count: int
    ingress_weight: float
    min_lower_bound: float
    weakest_join_id: str | None
    total_privilege_delta: int
    total_impact_delta: int = 0

    @property
    def source(self) -> str:
        return self.node_ids[0]

    @property
    def target(self) -> str:
        return self.node_ids[-1]

    @property
    def total_escalation_delta(self) -> int:
        return self.total_privilege_delta + self.total_impact_delta

    @property
    def escalation_score(self) -> float:
        delta = min(max(self.total_escalation_delta, 0), MAX_ESCALATION_DELTA)
        return float(delta) * self.min_lower_bound * self.ingress_weight


@dataclass(frozen=True)
class ChainSearchResult:
    """Result of one bounded chain search."""

    path: ChainPath | None
    nodes_expanded: int
    edges_relaxed: int
    elapsed_s: float
    stop_reason: str
    paths: tuple[ChainPath, ...] = ()
    pruned_edges: int = 0


@dataclass(frozen=True)
class JoinPrice:
    """Cost/benefit price for one ledger join row."""

    join_id: str
    a_claim: str
    b_claim: str
    state: str
    created: int
    reliability: float | None
    lower_bound: float | None
    probability_join: float
    chain_bonus: float
    ingress_weight: float
    dupe_score: float
    cost_usd_micro: int
    benefit: float
    ev_cost: float
    privilege_delta: int = 0
    impact_delta: int = 0
    escalation_score: float = 0.0


@dataclass(frozen=True)
class SubfactoryCandidate:
    """A below-floor path allowed to request one subfactory per join."""

    join_id: str
    path: ChainPath
    price_ev_cost: float


@dataclass(frozen=True)
class DensityReport:
    """Join-density measurement over one trailing window."""

    join_count: int
    ingress_count: int
    window_ms: int
    density_per_hour: float
    floor_per_hour: float
    low: bool
