"""Cross-surface exploit-chain enumeration, affinity scoring, and ranking."""

from __future__ import annotations

import heapq
import json
import math
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from ..errors import DuplicateDedup, FormatFail
from ..ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    Ledger,
    UlidFactory,
    dedup_key,
)
from ..ledger.ids import now_ms
from .ports import DupeOracle

SURFACE_CHAIN_SCHEMA = "ra.surface_chain.v1"
SURFACE_CHAIN_RECORD_KIND = "surface_chain"
SURFACE_CHAIN_LEDGER_TYPE = "bug_class"
SURFACE_CHAIN_ARTIFACT_KIND = "surface_chain"

MAX_SURFACE_NODES = 20_000
MAX_SURFACE_EDGES = 100_000
MAX_SURFACE_PATHS = 1024
MAX_SURFACE_PENDING_STATES = 100_000
MAX_SURFACE_HOPS = 8
DEFAULT_MAX_EXPANSIONS = 100_000
DEFAULT_MAX_RELAXATIONS = 1_000_000
DEFAULT_CHAIN_DEADLINE_S = 5.0
MAX_SURFACE_AFFINITY = 1.0
MAX_SURFACE_FEASIBILITY = 1.0
MAX_SURFACE_RELIABILITY = 1.0
MAX_SURFACE_IMPACT = 1.0
MAX_SURFACE_PRIVILEGE_DELTA = 8.0
MAX_SURFACE_COST = 1_000_000.0
MAX_EVIDENCE_ITEMS = 16


class SurfaceCategory(StrEnum):
    """Broad attack-surface families used for cross-surface chaining."""

    MEDIA = "media"
    CODEC = "codec"
    FONT = "font"
    RENDER = "render"
    XPC = "xpc"
    SANDBOX = "sandbox"
    IOKIT = "iokit"
    JSC = "jsc"
    KERNEL = "kernel"
    NETWORK = "network"
    OTHER = "other"


class SurfaceHopKind(StrEnum):
    """Cross-surface hop types; a crash in one surface can feed another entry."""

    CRASH_FEEDS_ENTRY = "crash_feeds_entry"
    CODEC_HANDOFF = "codec_handoff"
    RENDER_PIPELINE = "render_pipeline"
    XPC_DISPATCH = "xpc_dispatch"
    SANDBOX_ESCAPE = "sandbox_escape"
    IOKIT_KERNEL = "iokit_kernel"
    JSC_BRIDGE = "jsc_bridge"
    PERSISTENCE = "persistence"
    GENERIC = "generic"


class SurfaceSearchAlgorithm(StrEnum):
    BFS = "bfs"
    DFS = "dfs"


_CATEGORY_ALIASES = {
    "media": SurfaceCategory.MEDIA,
    "coremedia": SurfaceCategory.MEDIA,
    "avfoundation": SurfaceCategory.MEDIA,
    "multimedia": SurfaceCategory.MEDIA,
    "codec": SurfaceCategory.CODEC,
    "videotoolbox": SurfaceCategory.CODEC,
    "audio": SurfaceCategory.CODEC,
    "video": SurfaceCategory.CODEC,
    "font": SurfaceCategory.FONT,
    "coretext": SurfaceCategory.FONT,
    "ctfont": SurfaceCategory.FONT,
    "render": SurfaceCategory.RENDER,
    "coreanimation": SurfaceCategory.RENDER,
    "metal": SurfaceCategory.RENDER,
    "quartzcore": SurfaceCategory.RENDER,
    "xpc": SurfaceCategory.XPC,
    "mach": SurfaceCategory.XPC,
    "mach_xpc": SurfaceCategory.XPC,
    "service": SurfaceCategory.XPC,
    "daemon": SurfaceCategory.XPC,
    "sandbox": SurfaceCategory.SANDBOX,
    "sbpl": SurfaceCategory.SANDBOX,
    "sandbox_profile": SurfaceCategory.SANDBOX,
    "iokit": SurfaceCategory.IOKIT,
    "io-kit": SurfaceCategory.IOKIT,
    "io_kit": SurfaceCategory.IOKIT,
    "driver": SurfaceCategory.IOKIT,
    "jsc": SurfaceCategory.JSC,
    "javascriptcore": SurfaceCategory.JSC,
    "webkit": SurfaceCategory.JSC,
    "js": SurfaceCategory.JSC,
    "kernel": SurfaceCategory.KERNEL,
    "xnu": SurfaceCategory.KERNEL,
    "kernelcache": SurfaceCategory.KERNEL,
    "network": SurfaceCategory.NETWORK,
    "networking": SurfaceCategory.NETWORK,
    "bluetooth": SurfaceCategory.NETWORK,
    "wifi": SurfaceCategory.NETWORK,
    "other": SurfaceCategory.OTHER,
    "unknown": SurfaceCategory.OTHER,
}

_HOP_ALIASES = {
    "crash_feeds_entry": SurfaceHopKind.CRASH_FEEDS_ENTRY,
    "crash": SurfaceHopKind.CRASH_FEEDS_ENTRY,
    "feeds_entry": SurfaceHopKind.CRASH_FEEDS_ENTRY,
    "codec_handoff": SurfaceHopKind.CODEC_HANDOFF,
    "codec": SurfaceHopKind.CODEC_HANDOFF,
    "render_pipeline": SurfaceHopKind.RENDER_PIPELINE,
    "render": SurfaceHopKind.RENDER_PIPELINE,
    "xpc_dispatch": SurfaceHopKind.XPC_DISPATCH,
    "xpc": SurfaceHopKind.XPC_DISPATCH,
    "dispatch": SurfaceHopKind.XPC_DISPATCH,
    "sandbox_escape": SurfaceHopKind.SANDBOX_ESCAPE,
    "escape": SurfaceHopKind.SANDBOX_ESCAPE,
    "sandbox": SurfaceHopKind.SANDBOX_ESCAPE,
    "iokit_kernel": SurfaceHopKind.IOKIT_KERNEL,
    "iokit": SurfaceHopKind.IOKIT_KERNEL,
    "kernel": SurfaceHopKind.IOKIT_KERNEL,
    "jsc_bridge": SurfaceHopKind.JSC_BRIDGE,
    "jsc": SurfaceHopKind.JSC_BRIDGE,
    "bridge": SurfaceHopKind.JSC_BRIDGE,
    "persistence": SurfaceHopKind.PERSISTENCE,
    "persist": SurfaceHopKind.PERSISTENCE,
    "generic": SurfaceHopKind.GENERIC,
    "hop": SurfaceHopKind.GENERIC,
}

_AFFINITY_TABLE = {
    (SurfaceCategory.MEDIA, SurfaceCategory.CODEC): 0.95,
    (SurfaceCategory.CODEC, SurfaceCategory.MEDIA): 0.45,
    (SurfaceCategory.FONT, SurfaceCategory.RENDER): 0.95,
    (SurfaceCategory.RENDER, SurfaceCategory.FONT): 0.35,
    (SurfaceCategory.RENDER, SurfaceCategory.JSC): 0.80,
    (SurfaceCategory.JSC, SurfaceCategory.RENDER): 0.55,
    (SurfaceCategory.XPC, SurfaceCategory.SANDBOX): 0.90,
    (SurfaceCategory.SANDBOX, SurfaceCategory.XPC): 0.50,
    (SurfaceCategory.IOKIT, SurfaceCategory.KERNEL): 0.95,
    (SurfaceCategory.KERNEL, SurfaceCategory.IOKIT): 0.45,
    (SurfaceCategory.JSC, SurfaceCategory.XPC): 0.75,
    (SurfaceCategory.XPC, SurfaceCategory.JSC): 0.65,
    (SurfaceCategory.SANDBOX, SurfaceCategory.KERNEL): 0.70,
    (SurfaceCategory.KERNEL, SurfaceCategory.SANDBOX): 0.30,
    (SurfaceCategory.CODEC, SurfaceCategory.RENDER): 0.60,
    (SurfaceCategory.MEDIA, SurfaceCategory.RENDER): 0.55,
    (SurfaceCategory.RENDER, SurfaceCategory.CODEC): 0.40,
    (SurfaceCategory.NETWORK, SurfaceCategory.MEDIA): 0.70,
    (SurfaceCategory.NETWORK, SurfaceCategory.XPC): 0.65,
    (SurfaceCategory.MEDIA, SurfaceCategory.NETWORK): 0.30,
    (SurfaceCategory.FONT, SurfaceCategory.JSC): 0.45,
    (SurfaceCategory.JSC, SurfaceCategory.FONT): 0.35,
    (SurfaceCategory.CODEC, SurfaceCategory.JSC): 0.40,
    (SurfaceCategory.JSC, SurfaceCategory.CODEC): 0.35,
    (SurfaceCategory.IOKIT, SurfaceCategory.SANDBOX): 0.55,
    (SurfaceCategory.SANDBOX, SurfaceCategory.IOKIT): 0.40,
    (SurfaceCategory.JSC, SurfaceCategory.KERNEL): 0.25,
    (SurfaceCategory.KERNEL, SurfaceCategory.JSC): 0.20,
}

_HOP_KIND_BONUS = {
    SurfaceHopKind.CRASH_FEEDS_ENTRY: 0.10,
    SurfaceHopKind.CODEC_HANDOFF: 0.05,
    SurfaceHopKind.RENDER_PIPELINE: 0.05,
    SurfaceHopKind.XPC_DISPATCH: 0.05,
    SurfaceHopKind.SANDBOX_ESCAPE: 0.10,
    SurfaceHopKind.IOKIT_KERNEL: 0.05,
    SurfaceHopKind.JSC_BRIDGE: 0.05,
    SurfaceHopKind.PERSISTENCE: -0.05,
    SurfaceHopKind.GENERIC: 0.0,
}


def _finite(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{field_name} must be a finite number")
    out = float(value)
    if not math.isfinite(out):
        raise FormatFail(f"{field_name} must be finite")
    return out


def _clamped(value: object, field_name: str, low: float, high: float) -> float:
    return min(high, max(low, _finite(value, field_name)))


def _optional_text(value: object, field_name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FormatFail(f"{field_name} must be str")
    return value


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise FormatFail(f"{field_name} must be str")
    text = value.strip()
    if not text:
        raise FormatFail(f"{field_name} must not be empty")
    return text


def _first_text(mapping: Mapping[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _number(mapping: Mapping[str, Any], *keys: str, default: float = 0.0) -> float:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        return _finite(value, key)
    return default


def _unit(mapping: Mapping[str, Any], *keys: str, default: float = 0.0) -> float:
    return _clamped(_number(mapping, *keys, default=default), "value", 0.0, 1.0)


def _nonnegative(mapping: Mapping[str, Any], *keys: str, default: float = 0.0) -> float:
    value = _number(mapping, *keys, default=default)
    if value < 0:
        raise FormatFail("value must be non-negative")
    return value


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _evidence_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items: tuple[object, ...] = (value,)
    elif isinstance(value, (list, tuple)):
        items = tuple(value)
    else:
        raise FormatFail("edge evidence must be a string or sequence of strings")
    cleaned: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise FormatFail("edge evidence items must be str")
        text = item.strip()
        if text:
            cleaned.add(text)
    return tuple(sorted(cleaned)[:MAX_EVIDENCE_ITEMS])


def _category_from_text(value: object) -> SurfaceCategory:
    if isinstance(value, SurfaceCategory):
        return value
    if not isinstance(value, str):
        raise FormatFail("surface category must be a string")
    key = value.strip().lower().replace(" ", "_").replace("-", "_")
    if not key:
        return SurfaceCategory.OTHER
    return _CATEGORY_ALIASES.get(key, SurfaceCategory.OTHER)


def parse_surface_category(value: object) -> SurfaceCategory:
    """Parse a surface category, mapping unknown names to ``other``."""
    return _category_from_text(value)


def _hop_from_text(value: object) -> SurfaceHopKind:
    if isinstance(value, SurfaceHopKind):
        return value
    if not isinstance(value, str):
        raise FormatFail("surface hop kind must be a string")
    key = value.strip().lower().replace(" ", "_").replace("-", "_")
    if not key:
        return SurfaceHopKind.GENERIC
    kind = _HOP_ALIASES.get(key)
    if kind is None:
        raise FormatFail(f"unknown surface hop kind {value!r}")
    return kind


def parse_surface_hop_kind(value: object) -> SurfaceHopKind:
    """Parse a cross-surface hop kind or raise FORMAT_FAIL."""
    return _hop_from_text(value)


def surface_affinity(
    source: SurfaceCategory | str,
    target: SurfaceCategory | str,
    kind: SurfaceHopKind | str = SurfaceHopKind.GENERIC,
) -> float:
    """Score how naturally one surface category feeds another entry point."""
    source_category = _category_from_text(source)
    target_category = _category_from_text(target)
    hop_kind = _hop_from_text(kind)
    if source_category is target_category:
        base = 0.30
    else:
        base = _AFFINITY_TABLE.get((source_category, target_category), 0.20)
    score = base + _HOP_KIND_BONUS[hop_kind]
    return min(1.0, max(0.0, score))


@dataclass(frozen=True)
class SurfaceNode:
    """One attack-surface node in a cross-surface chain graph."""

    id: str
    category: SurfaceCategory
    name: str = ""
    impact: float = 0.0
    feasibility: float = 1.0
    privilege: float = 0.0
    zero_click: bool = False
    persistence: bool = False
    terminal: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _required_text(self.id, "surface node id"))
        object.__setattr__(self, "category", _category_from_text(self.category))
        object.__setattr__(self, "name", _optional_text(self.name, "surface node name"))
        object.__setattr__(self, "impact", _clamped(self.impact, "node impact", 0.0, MAX_SURFACE_IMPACT))
        object.__setattr__(
            self,
            "feasibility",
            _clamped(self.feasibility, "node feasibility", 0.0, MAX_SURFACE_FEASIBILITY),
        )
        object.__setattr__(
            self,
            "privilege",
            _clamped(self.privilege, "node privilege", 0.0, MAX_SURFACE_PRIVILEGE_DELTA),
        )
        for field_name in ("zero_click", "persistence", "terminal"):
            value = getattr(self, field_name)
            if not isinstance(value, bool):
                raise FormatFail(f"{field_name} must be bool")

    @property
    def is_ingress(self) -> bool:
        return self.zero_click

    @property
    def is_target(self) -> bool:
        return self.persistence or self.terminal or self.category is SurfaceCategory.KERNEL


@dataclass(frozen=True)
class SurfaceEdge:
    """One directed cross-surface hop between two surface nodes."""

    id: str
    source: str
    target: str
    kind: SurfaceHopKind = SurfaceHopKind.GENERIC
    privilege_delta: float = 0.0
    impact_delta: float = 0.5
    feasibility: float = 1.0
    reliability: float = 1.0
    cost: float = 0.0
    affinity: float | None = None
    join_count: int = 0
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _required_text(self.id, "surface edge id"))
        object.__setattr__(self, "source", _required_text(self.source, "edge source"))
        object.__setattr__(self, "target", _required_text(self.target, "edge target"))
        object.__setattr__(self, "kind", _hop_from_text(self.kind))
        object.__setattr__(
            self,
            "privilege_delta",
            _clamped(self.privilege_delta, "edge privilege_delta", 0.0, MAX_SURFACE_PRIVILEGE_DELTA),
        )
        object.__setattr__(
            self, "impact_delta", _clamped(self.impact_delta, "edge impact_delta", 0.0, MAX_SURFACE_IMPACT)
        )
        object.__setattr__(
            self, "feasibility", _clamped(self.feasibility, "edge feasibility", 0.0, MAX_SURFACE_FEASIBILITY)
        )
        object.__setattr__(
            self, "reliability", _clamped(self.reliability, "edge reliability", 0.0, MAX_SURFACE_RELIABILITY)
        )
        object.__setattr__(self, "cost", _clamped(self.cost, "edge cost", 0.0, MAX_SURFACE_COST))
        if self.affinity is not None:
            object.__setattr__(
                self,
                "affinity",
                _clamped(self.affinity, "edge affinity", 0.0, MAX_SURFACE_AFFINITY),
            )
        if isinstance(self.join_count, bool) or not isinstance(self.join_count, int):
            raise FormatFail("join_count must be int")
        if self.join_count < 0:
            raise FormatFail("join_count must be non-negative")
        object.__setattr__(self, "evidence", _evidence_tuple(self.evidence))

    @property
    def key(self) -> tuple[str, str, SurfaceHopKind]:
        kind = self.kind
        if not isinstance(kind, SurfaceHopKind):
            raise FormatFail("surface edge kind must be SurfaceHopKind")
        return (self.source, self.target, kind)


def _with_edge_affinity(edge: SurfaceEdge, node_by_id: Mapping[str, SurfaceNode]) -> SurfaceEdge:
    if edge.affinity is not None:
        return edge
    source = node_by_id[edge.source]
    target = node_by_id[edge.target]
    return replace(edge, affinity=surface_affinity(source.category, target.category, edge.kind))


@dataclass(frozen=True)
class SurfaceGraph:
    """Immutable cross-surface graph with resolved hop affinities."""

    nodes: tuple[SurfaceNode, ...]
    edges: tuple[SurfaceEdge, ...]

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        if len(nodes) > MAX_SURFACE_NODES or len(edges) > MAX_SURFACE_EDGES:
            raise FormatFail("surface graph exceeds bounded size")
        if not all(isinstance(node, SurfaceNode) for node in nodes):
            raise FormatFail("surface graph nodes must be SurfaceNode values")
        if not all(isinstance(edge, SurfaceEdge) for edge in edges):
            raise FormatFail("surface graph edges must be SurfaceEdge values")
        node_ids = tuple(node.id for node in nodes)
        if len(set(node_ids)) != len(node_ids):
            raise FormatFail("duplicate surface node id")
        node_by_id = {node.id: node for node in nodes}
        node_set = set(node_ids)
        edge_ids: set[str] = set()
        for edge in edges:
            if edge.id in edge_ids:
                raise FormatFail("duplicate surface edge id")
            edge_ids.add(edge.id)
            if edge.source == edge.target:
                raise FormatFail("self-loop surface edges are not allowed")
            if edge.source not in node_set or edge.target not in node_set:
                raise FormatFail("surface edge references unknown node")
        resolved = tuple(_with_edge_affinity(edge, node_by_id) for edge in edges)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", resolved)

    @property
    def node_map(self) -> dict[str, SurfaceNode]:
        return {node.id: node for node in self.nodes}

    def adjacency(self) -> dict[str, tuple[SurfaceEdge, ...]]:
        grouped: dict[str, list[SurfaceEdge]] = {}
        for edge in self.edges:
            grouped.setdefault(edge.source, []).append(edge)
        return {
            source: tuple(
                sorted(
                    items,
                    key=lambda edge: (
                        -(edge.affinity if edge.affinity is not None else 0.0),
                        -edge.reliability,
                        edge.cost,
                        edge.id,
                    ),
                )
            )
            for source, items in grouped.items()
        }


@dataclass(frozen=True)
class SurfaceChainPath:
    """A simple cross-surface chain path with deterministic scores."""

    nodes: tuple[str, ...]
    edges: tuple[SurfaceEdge, ...]
    categories: tuple[SurfaceCategory, ...]
    privilege_gain: float = 0.0
    impact: float = 0.0
    feasibility: float = 1.0
    reliability: float = 1.0
    affinity: float = 0.0
    cost: float = 0.0

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        categories = tuple(_category_from_text(item) for item in self.categories)
        if not nodes or not all(isinstance(node, str) and node for node in nodes):
            raise FormatFail("surface path nodes must be non-empty strings")
        if len(set(nodes)) != len(nodes):
            raise FormatFail("surface path nodes must be unique")
        if not all(isinstance(edge, SurfaceEdge) for edge in edges):
            raise FormatFail("surface path edges must be SurfaceEdge values")
        if len(edges) != len(nodes) - 1:
            raise FormatFail("surface path edge count must be node count minus one")
        if len(categories) != len(nodes):
            raise FormatFail("surface path categories must align with nodes")
        for index, edge in enumerate(edges):
            if edge.source != nodes[index] or edge.target != nodes[index + 1]:
                raise FormatFail("surface path edges must connect consecutive nodes")
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(self, "categories", categories)
        object.__setattr__(
            self,
            "privilege_gain",
            _clamped(self.privilege_gain, "path privilege_gain", 0.0, MAX_SURFACE_PRIVILEGE_DELTA * MAX_SURFACE_HOPS),
        )
        object.__setattr__(self, "impact", _clamped(self.impact, "path impact", 0.0, 1.0))
        object.__setattr__(self, "feasibility", _clamped(self.feasibility, "path feasibility", 0.0, 1.0))
        object.__setattr__(self, "reliability", _clamped(self.reliability, "path reliability", 0.0, 1.0))
        object.__setattr__(self, "affinity", _clamped(self.affinity, "path affinity", 0.0, 1.0))
        object.__setattr__(self, "cost", _clamped(self.cost, "path cost", 0.0, MAX_SURFACE_COST * MAX_SURFACE_HOPS))

    @property
    def source(self) -> str:
        return self.nodes[0]

    @property
    def target(self) -> str:
        return self.nodes[-1]

    @property
    def hop_count(self) -> int:
        return len(self.edges)

    @property
    def category_count(self) -> int:
        return len(set(self.categories))

    @property
    def cross_surface(self) -> bool:
        return self.category_count >= 2

    @property
    def edge_ids(self) -> tuple[str, ...]:
        return tuple(edge.id for edge in self.edges)

    @property
    def rank_key(self) -> tuple[float, ...]:
        return (-self.impact, -self.feasibility, -self.affinity, -self.reliability, self.cost)

    def dedup_material(self) -> str:
        return json.dumps(
            {
                "nodes": list(self.nodes),
                "edge_ids": list(self.edge_ids),
                "categories": [category.value for category in self.categories],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "edges": [
                {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "kind": edge.kind.value,
                    "privilege_delta": _round(edge.privilege_delta),
                    "impact_delta": _round(edge.impact_delta),
                    "feasibility": _round(edge.feasibility),
                    "reliability": _round(edge.reliability),
                    "affinity": _round(edge.affinity if edge.affinity is not None else 0.0),
                    "cost": _round(edge.cost),
                    "join_count": edge.join_count,
                    "evidence": list(edge.evidence),
                }
                for edge in self.edges
            ],
            "categories": [category.value for category in self.categories],
            "hop_count": self.hop_count,
            "category_count": self.category_count,
            "cross_surface": self.cross_surface,
            "privilege_gain": _round(self.privilege_gain),
            "impact": _round(self.impact),
            "feasibility": _round(self.feasibility),
            "reliability": _round(self.reliability),
            "affinity": _round(self.affinity),
            "cost": _round(self.cost),
        }


@dataclass(frozen=True)
class SurfaceChainConfig:
    """Bounds for deterministic BFS/DFS cross-surface enumeration."""

    algorithm: SurfaceSearchAlgorithm | str = SurfaceSearchAlgorithm.BFS
    min_hops: int = 3
    max_hops: int = MAX_SURFACE_HOPS
    max_paths: int = 32
    max_expansions: int = DEFAULT_MAX_EXPANSIONS
    max_relaxations: int = DEFAULT_MAX_RELAXATIONS
    require_cross_surface: bool = True
    dead_end_pruning: bool = True
    deadline_s: float = DEFAULT_CHAIN_DEADLINE_S
    clock: Callable[[], float] | None = None

    def validate(self) -> None:
        parse_search_algorithm(self.algorithm)
        for name, value in (("min_hops", self.min_hops), ("max_hops", self.max_hops)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise FormatFail(f"surface {name} must be int")
        if not 1 <= self.min_hops <= self.max_hops <= MAX_SURFACE_HOPS:
            raise FormatFail(f"surface hops must satisfy 1 <= min_hops <= max_hops <= {MAX_SURFACE_HOPS}")
        for name, value, maximum in (
            ("max_paths", self.max_paths, MAX_SURFACE_PATHS),
            ("max_expansions", self.max_expansions, None),
            ("max_relaxations", self.max_relaxations, None),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise FormatFail(f"surface {name} must be positive")
            if maximum is not None and value > maximum:
                raise FormatFail(f"surface {name} must be <= {maximum}")
        if not isinstance(self.require_cross_surface, bool) or not isinstance(self.dead_end_pruning, bool):
            raise FormatFail("surface search flags must be bool")
        if not math.isfinite(self.deadline_s) or self.deadline_s <= 0:
            raise FormatFail("surface deadline_s must be positive")


def parse_search_algorithm(value: SurfaceSearchAlgorithm | str) -> SurfaceSearchAlgorithm:
    if isinstance(value, SurfaceSearchAlgorithm):
        return value
    if not isinstance(value, str):
        raise FormatFail("surface search algorithm must be bfs or dfs")
    key = value.strip().lower().replace("-", "_")
    if key in {"bfs", "breadth_first", "breadth-first"}:
        return SurfaceSearchAlgorithm.BFS
    if key in {"dfs", "depth_first", "depth-first"}:
        return SurfaceSearchAlgorithm.DFS
    raise FormatFail("surface search algorithm must be bfs or dfs")


@dataclass(frozen=True)
class SurfaceChainResult:
    """Deterministic result of one bounded cross-surface enumeration."""

    paths: tuple[SurfaceChainPath, ...]
    nodes_considered: int
    edges_considered: int
    expansions: int
    relaxations: int
    truncated: bool
    stop_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": [path.to_dict() for path in self.paths],
            "nodes_considered": self.nodes_considered,
            "edges_considered": self.edges_considered,
            "expansions": self.expansions,
            "relaxations": self.relaxations,
            "truncated": self.truncated,
            "stop_reason": self.stop_reason,
        }


_PathSortKey = tuple[int, float, float, float, float, tuple[str, ...], tuple[str, ...]]

_SearchState = tuple[
    str,
    tuple[str, ...],
    tuple[SurfaceEdge, ...],
    frozenset[SurfaceCategory],
]


def _nodes_reaching_targets(graph: SurfaceGraph, target_ids: set[str]) -> set[str]:
    reverse: dict[str, set[str]] = {}
    for edge in graph.edges:
        reverse.setdefault(edge.target, set()).add(edge.source)
    useful = {node_id for node_id in target_ids if node_id in graph.node_map}
    stack = sorted(useful)
    while stack:
        node_id = stack.pop()
        for parent in reverse.get(node_id, ()):
            if parent not in useful:
                useful.add(parent)
                stack.append(parent)
    return useful


def _resolve_ids(
    graph: SurfaceGraph,
    values: Sequence[str] | None,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    if values is None:
        return default
    if isinstance(values, str):
        values = (values,)
    resolved_set: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise FormatFail("surface node ids must be strings")
        text = value.strip()
        if text:
            resolved_set.add(text)
    resolved = tuple(sorted(resolved_set))
    for value in resolved:
        if value not in graph.node_map:
            raise FormatFail(f"unknown surface node {value!r}")
    return resolved


def _make_path(
    graph: SurfaceGraph,
    node_ids: tuple[str, ...],
    edges: tuple[SurfaceEdge, ...],
) -> SurfaceChainPath:
    node_map = graph.node_map
    nodes = tuple(node_map[node_id] for node_id in node_ids)
    privilege_gain = sum(edge.privilege_delta for edge in edges)
    impact = 1.0 - math.prod(1.0 - edge.impact_delta for edge in edges) if edges else 0.0
    reliability = math.prod(edge.reliability for edge in edges) if edges else 1.0
    feasibility = math.prod(edge.feasibility * edge.reliability for edge in edges) if edges else 1.0
    affinity_values = [edge.affinity for edge in edges if edge.affinity is not None]
    affinity = min(affinity_values) if affinity_values else 0.0
    cost = sum(edge.cost for edge in edges)
    return SurfaceChainPath(
        nodes=node_ids,
        edges=edges,
        categories=tuple(node.category for node in nodes),
        privilege_gain=privilege_gain,
        impact=impact,
        feasibility=feasibility,
        reliability=reliability,
        affinity=affinity,
        cost=cost,
    )


def _path_sort_key(path: SurfaceChainPath) -> _PathSortKey:
    return (
        path.hop_count,
        -path.affinity,
        -path.feasibility,
        -path.impact,
        -path.privilege_gain,
        path.nodes,
        path.edge_ids,
    )


class _FoundPath:
    __slots__ = ("key", "material", "path")

    def __init__(self, key: _PathSortKey, material: str, path: SurfaceChainPath) -> None:
        self.key = key
        self.material = material
        self.path = path

    def __lt__(self, other: _FoundPath) -> bool:
        if self.key != other.key:
            return self.key > other.key
        return self.material > other.material


def _result(
    graph: SurfaceGraph,
    paths: Sequence[SurfaceChainPath],
    *,
    expansions: int,
    relaxations: int,
    truncated: bool,
    stop_reason: str,
    limit: int = MAX_SURFACE_PATHS,
) -> SurfaceChainResult:
    ordered = tuple(sorted(paths, key=_path_sort_key)[:limit])
    return SurfaceChainResult(
        paths=ordered,
        nodes_considered=len(graph.nodes),
        edges_considered=len(graph.edges),
        expansions=expansions,
        relaxations=relaxations,
        truncated=truncated,
        stop_reason=stop_reason,
    )


def enumerate_surface_chains(
    graph: SurfaceGraph,
    config: SurfaceChainConfig | None = None,
    *,
    sources: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
) -> SurfaceChainResult:
    """Enumerate bounded simple cross-surface chains with BFS or DFS."""
    if not isinstance(graph, SurfaceGraph):
        raise FormatFail("surface enumeration requires a SurfaceGraph")
    cfg = config or SurfaceChainConfig()
    cfg.validate()
    algorithm = parse_search_algorithm(cfg.algorithm)
    clock = cfg.clock or time.monotonic
    started = clock()
    deadline = started + cfg.deadline_s
    node_map = graph.node_map
    default_sources = tuple(sorted(node.id for node in graph.nodes if node.zero_click))
    default_targets = tuple(sorted(node.id for node in graph.nodes if node.is_target))
    source_ids = _resolve_ids(graph, sources, default_sources)
    target_ids = _resolve_ids(graph, targets, default_targets)
    if not source_ids:
        return _result(graph, (), expansions=0, relaxations=0, truncated=False, stop_reason="no_ingress")
    if not target_ids:
        return _result(graph, (), expansions=0, relaxations=0, truncated=False, stop_reason="no_target")
    target_set = set(target_ids)
    useful = (
        _nodes_reaching_targets(graph, target_set)
        if cfg.dead_end_pruning
        else set(node_map)
    )
    adjacency = graph.adjacency()
    found: dict[str, SurfaceChainPath] = {}
    found_heap: list[_FoundPath] = []
    found_limit = cfg.max_paths
    expansions = 0
    relaxations = 0
    truncated = False
    stop_reason = "no_path"

    def consider(node_ids: tuple[str, ...], edges: tuple[SurfaceEdge, ...]) -> None:
        path = _make_path(graph, node_ids, edges)
        material = path.dedup_material()
        if material in found:
            return
        key = _path_sort_key(path)
        if len(found) < found_limit:
            found[material] = path
            heapq.heappush(found_heap, _FoundPath(key, material, path))
            return
        worst = found_heap[0]
        if key < worst.key:
            found.pop(worst.material, None)
            heapq.heapreplace(found_heap, _FoundPath(key, material, path))
            found[material] = path

    for source in source_ids:
        if source not in useful:
            continue
        source_node = node_map[source]
        initial: _SearchState = (
            source,
            (source,),
            (),
            frozenset({source_node.category}),
        )
        if algorithm is SurfaceSearchAlgorithm.BFS:
            queue: deque[_SearchState] = deque([initial])
            while queue and not truncated:
                if clock() >= deadline:
                    truncated = True
                    stop_reason = "deadline"
                    break
                if expansions >= cfg.max_expansions:
                    truncated = True
                    stop_reason = "expansion_cap"
                    break
                node_id, node_ids, edges_path, categories = queue.popleft()
                expansions += 1
                neighbors = adjacency.get(node_id, ())
                for edge in neighbors:
                    relaxations += 1
                    if relaxations > cfg.max_relaxations:
                        truncated = True
                        stop_reason = "relaxation_cap"
                        break
                    target_node = node_map.get(edge.target)
                    if target_node is None or edge.target in node_ids or edge.target not in useful:
                        continue
                    new_edges = (*edges_path, edge)
                    hop_count = len(new_edges)
                    if hop_count > cfg.max_hops:
                        continue
                    new_nodes = (*node_ids, edge.target)
                    new_categories = categories | {target_node.category}
                    if (
                        hop_count >= cfg.min_hops
                        and edge.target in target_set
                        and (not cfg.require_cross_surface or len(new_categories) >= 2)
                    ):
                        consider(new_nodes, new_edges)
                    if hop_count < cfg.max_hops and not (
                        target_node.persistence or target_node.terminal
                    ):
                        if len(queue) >= MAX_SURFACE_PENDING_STATES:
                            truncated = True
                            stop_reason = "pending_cap"
                            break
                        queue.append((edge.target, new_nodes, new_edges, new_categories))
                if truncated:
                    break
        else:
            stack: list[_SearchState] = [initial]
            while stack and not truncated:
                if clock() >= deadline:
                    truncated = True
                    stop_reason = "deadline"
                    break
                if expansions >= cfg.max_expansions:
                    truncated = True
                    stop_reason = "expansion_cap"
                    break
                node_id, node_ids, edges_path, categories = stack.pop()
                expansions += 1
                neighbors = tuple(reversed(adjacency.get(node_id, ())))
                for edge in neighbors:
                    relaxations += 1
                    if relaxations > cfg.max_relaxations:
                        truncated = True
                        stop_reason = "relaxation_cap"
                        break
                    target_node = node_map.get(edge.target)
                    if target_node is None or edge.target in node_ids or edge.target not in useful:
                        continue
                    new_edges = (*edges_path, edge)
                    hop_count = len(new_edges)
                    if hop_count > cfg.max_hops:
                        continue
                    new_nodes = (*node_ids, edge.target)
                    new_categories = categories | {target_node.category}
                    if (
                        hop_count >= cfg.min_hops
                        and edge.target in target_set
                        and (not cfg.require_cross_surface or len(new_categories) >= 2)
                    ):
                        consider(new_nodes, new_edges)
                    if hop_count < cfg.max_hops and not (
                        target_node.persistence or target_node.terminal
                    ):
                        if len(stack) >= MAX_SURFACE_PENDING_STATES:
                            truncated = True
                            stop_reason = "pending_cap"
                            break
                        stack.append((edge.target, new_nodes, new_edges, new_categories))
                if truncated:
                    break
        if truncated:
            break

    paths = tuple(found.values())
    if paths and not truncated:
        stop_reason = "found"
    elif truncated:
        stop_reason = stop_reason
    else:
        stop_reason = "no_path"
    return _result(
        graph,
        paths,
        expansions=expansions,
        relaxations=relaxations,
        truncated=truncated,
        stop_reason=stop_reason,
        limit=cfg.max_paths,
    )


@dataclass(frozen=True)
class SurfaceQualityWeights:
    """Weights for combined impact, feasibility, affinity, and novelty scoring."""

    impact: float = 0.40
    feasibility: float = 0.25
    affinity: float = 0.20
    novelty: float = 0.15

    def __post_init__(self) -> None:
        total = 0.0
        for name, value in (
            ("impact", self.impact),
            ("feasibility", self.feasibility),
            ("affinity", self.affinity),
            ("novelty", self.novelty),
        ):
            number = _finite(value, f"quality weight {name}")
            if number < 0 or number > 1:
                raise FormatFail(f"quality weight {name} must be in [0, 1]")
            total += number
        if total <= 0 or total > 1.0:
            raise FormatFail("quality weights must sum to (0, 1]")


@dataclass(frozen=True)
class SurfaceChainQuality:
    """A surface chain path plus combined quality components and rank."""

    path: SurfaceChainPath
    impact_score: float
    feasibility_score: float
    affinity_score: float
    novelty_score: float
    quality_score: float
    rank: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.path, SurfaceChainPath):
            raise FormatFail("surface chain quality requires a SurfaceChainPath")
        for name in ("impact_score", "feasibility_score", "affinity_score", "novelty_score", "quality_score"):
            object.__setattr__(
                self,
                name,
                _clamped(getattr(self, name), name, 0.0, 1.0),
            )
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank < 0:
            raise FormatFail("surface chain rank must be a non-negative int")

    @property
    def dedup_material(self) -> str:
        return self.path.dedup_material()

    @property
    def rank_key(self) -> tuple[object, ...]:
        return (
            -self.quality_score,
            -self.impact_score,
            -self.feasibility_score,
            -self.affinity_score,
            -self.novelty_score,
            self.path.hop_count,
            self.path.nodes,
            self.path.edge_ids,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path.to_dict(),
            "impact_score": _round(self.impact_score),
            "feasibility_score": _round(self.feasibility_score),
            "affinity_score": _round(self.affinity_score),
            "novelty_score": _round(self.novelty_score),
            "quality_score": _round(self.quality_score),
            "rank": self.rank,
        }


def _round(value: float) -> float:
    return round(value, 9)


def _unit_value(value: object, field_name: str) -> float:
    number = _finite(value, field_name)
    if number < 0.0 or number > 1.0:
        raise FormatFail(f"{field_name} must be in [0, 1]")
    return number


def _novelty_for_path(
    path: SurfaceChainPath,
    *,
    novelty_scores: Mapping[str, float] | None,
    dupe: DupeOracle | None,
    default_novelty: float,
) -> float:
    default = _unit_value(default_novelty, "default_novelty")
    values: list[float] = []
    if dupe is not None:
        for node_id in path.nodes:
            values.append(_unit_value(dupe.score(node_id), "dupe novelty"))
    elif novelty_scores is not None:
        for node_id in path.nodes:
            values.append(_unit_value(novelty_scores.get(node_id, default), "novelty score"))
    else:
        return default
    return min(values) if values else default


def rank_surface_chains(
    paths: Sequence[SurfaceChainPath],
    *,
    novelty_scores: Mapping[str, float] | None = None,
    dupe: DupeOracle | None = None,
    default_novelty: float = 1.0,
    weights: SurfaceQualityWeights | None = None,
) -> tuple[SurfaceChainQuality, ...]:
    """Rank chains by combined impact, feasibility, affinity, and novelty."""
    if dupe is not None and novelty_scores is not None:
        raise FormatFail("pass either dupe oracle or novelty_scores, not both")
    weight = weights or SurfaceQualityWeights()
    ranked: list[SurfaceChainQuality] = []
    for path in paths:
        if not isinstance(path, SurfaceChainPath):
            raise FormatFail("surface ranking requires SurfaceChainPath values")
        novelty = _novelty_for_path(
            path,
            novelty_scores=novelty_scores,
            dupe=dupe,
            default_novelty=default_novelty,
        )
        quality = (
            weight.impact * path.impact
            + weight.feasibility * path.feasibility
            + weight.affinity * path.affinity
            + weight.novelty * novelty
        )
        ranked.append(
            SurfaceChainQuality(
                path=path,
                impact_score=path.impact,
                feasibility_score=path.feasibility,
                affinity_score=path.affinity,
                novelty_score=novelty,
                quality_score=min(1.0, max(0.0, quality)),
            )
        )
    ordered = sorted(ranked, key=lambda item: item.rank_key)
    return tuple(replace(item, rank=index + 1) for index, item in enumerate(ordered))


@dataclass(frozen=True)
class SurfaceChainEmitResult:
    """Claim ids created by a surface-chain emission run, plus dedup hits."""

    emitted: tuple[str, ...]
    skipped: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"emitted": list(self.emitted), "skipped": list(self.skipped)}


class SurfaceChainEmitter:
    """Persist ranked surface chains as ledger claims without duplicating paths."""

    def __init__(self, ledger: Ledger, *, claim_type: str = SURFACE_CHAIN_LEDGER_TYPE) -> None:
        self._ledger = ledger
        self._ids = UlidFactory()
        self._claim_type = claim_type

    async def emit(
        self,
        ranked: Sequence[SurfaceChainQuality],
        *,
        run_id: str | None = None,
        created: int | None = None,
        ttl_class: str = "run",
        limit: int | None = None,
    ) -> SurfaceChainEmitResult:
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
        ):
            raise FormatFail("limit must be a positive integer")
        items = ranked if limit is None else ranked[:limit]
        for quality in items:
            if not isinstance(quality, SurfaceChainQuality):
                raise FormatFail("surface emission requires SurfaceChainQuality values")
            _validate_claim_path(quality.path)
        emitted: list[str] = []
        skipped: list[str] = []
        created_ms = now_ms() if created is None else created
        for index, quality in enumerate(items, start=1):
            rank = quality.rank or index
            value_json = _claim_value_json(quality, rank)
            data = value_json.encode("utf-8")
            dedup = dedup_key(
                SURFACE_CHAIN_RECORD_KIND,
                quality.path.dedup_material(),
                SURFACE_CHAIN_SCHEMA,
            )
            existing = self._ledger.claim_by_dedup(dedup)
            if existing is not None:
                skipped.append(str(existing["id"]))
                continue
            claim_id = self._ids.new("cl")
            try:
                await self._ledger.create_claim(
                    ClaimInput(
                        claim_id=claim_id,
                        type=self._claim_type,
                        value_json=value_json,
                        confidence=quality.quality_score,
                        dedup_key=dedup,
                        created=created_ms,
                        run_id=run_id,
                        artifacts=(
                            ClaimArtifactInput(
                                artifact=ArtifactInput(
                                    kind=SURFACE_CHAIN_ARTIFACT_KIND,
                                    data=data,
                                    ttl_class=ttl_class,
                                ),
                                role="evidence",
                            ),
                        ),
                    )
                )
            except DuplicateDedup:
                existing = self._ledger.claim_by_dedup(dedup)
                if existing is None:
                    raise
                skipped.append(str(existing["id"]))
                continue
            emitted.append(claim_id)
        return SurfaceChainEmitResult(tuple(emitted), tuple(skipped))


def _validate_claim_path(path: SurfaceChainPath) -> None:
    if not isinstance(path, SurfaceChainPath):
        raise FormatFail("surface emission requires SurfaceChainPath values")
    privilege_gain = 0.0
    impact = 0.0
    reliability = 1.0
    feasibility = 1.0
    affinity_values: list[float] = []
    cost = 0.0
    for edge in path.edges:
        privilege_gain += edge.privilege_delta
        impact = 1.0 - (1.0 - impact) * (1.0 - edge.impact_delta)
        reliability *= edge.reliability
        feasibility *= edge.feasibility * edge.reliability
        if edge.affinity is not None:
            affinity_values.append(edge.affinity)
        cost += edge.cost
    affinity = min(affinity_values) if affinity_values else 0.0
    expected = {
        "privilege_gain": privilege_gain,
        "impact": impact,
        "feasibility": feasibility,
        "reliability": reliability,
        "affinity": affinity,
        "cost": cost,
    }
    actual = {
        "privilege_gain": path.privilege_gain,
        "impact": path.impact,
        "feasibility": path.feasibility,
        "reliability": path.reliability,
        "affinity": path.affinity,
        "cost": path.cost,
    }
    for field, expected_value in expected.items():
        actual_value = actual[field]
        if not math.isclose(actual_value, expected_value, rel_tol=1e-9, abs_tol=1e-9):
            raise FormatFail(f"surface path {field} is inconsistent with its edges")


def _claim_value_json(quality: SurfaceChainQuality, rank: int) -> str:
    payload = {
        "schema": SURFACE_CHAIN_SCHEMA,
        "record_kind": SURFACE_CHAIN_RECORD_KIND,
        "claim_kind": "surface_chain",
        "rank": rank,
        "path": quality.path.to_dict(),
        "scores": {
            "impact": quality.impact_score,
            "feasibility": quality.feasibility_score,
            "affinity": quality.affinity_score,
            "novelty": quality.novelty_score,
            "quality": quality.quality_score,
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _edge_from_mapping(item: Mapping[str, Any], *, default_source: str | None = None) -> SurfaceEdge:
    source = _first_text(item, "source", "from", "src") or (default_source or "")
    target = _first_text(item, "target", "to", "dst")
    if not source or not target:
        raise FormatFail("surface edge mapping requires source and target")
    kind_value = item.get("kind")
    if kind_value is None:
        kind_value = item.get("relation")
    if kind_value is None:
        kind_value = item.get("type")
    return SurfaceEdge(
        id=_first_text(item, "id", "edge_id", "join_id") or f"{source}->{target}",
        source=source,
        target=target,
        kind=SurfaceHopKind.GENERIC if kind_value is None else _hop_from_text(kind_value),
        privilege_delta=_nonnegative(item, "privilege_delta", "privilege", default=0.0),
        impact_delta=_unit(item, "impact_delta", "impact", default=0.5),
        feasibility=_unit(item, "feasibility", "reliability_feasibility", default=1.0),
        reliability=_unit(item, "reliability", "confidence", default=1.0),
        cost=_nonnegative(item, "cost", "weight", "price", default=0.0),
        affinity=(
            None
            if item.get("affinity") is None
            else _unit({"affinity": item.get("affinity")}, "affinity")
        ),
        join_count=max(0, _int_value(item, "join_count", "joins", default=0)),
        evidence=_evidence_tuple(item.get("evidence")),
    )


def _int_value(mapping: Mapping[str, Any], *keys: str, default: int = 0) -> int:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FormatFail(f"{key} must be a finite integer")
        out = float(value)
        if not math.isfinite(out) or not out.is_integer():
            raise FormatFail(f"{key} must be a finite integer")
        return int(out)
    return default


def _require_mapping(value: object, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatFail(f"{field_name} must be a mapping")
    return value


def _node_from_row(row: Mapping[str, Any], index: int) -> SurfaceNode:
    node_id = (
        _first_text(row, "id", "entry_point_id", "node_id", "name")
        or f"surface-{index:06d}"
    )
    category_value = row.get("category")
    if category_value is None:
        category_value = row.get("surface")
    if category_value is None:
        category_value = row.get("family")
    if category_value is None:
        category_value = row.get("family_name")
    impact_value = row.get("impact")
    if impact_value is None:
        impact_value = row.get("severity")
    if impact_value is None:
        impact_value = row.get("impact_delta")
    feasibility_value = row.get("feasibility")
    if feasibility_value is None:
        feasibility_value = row.get("reliability")
    if feasibility_value is None:
        feasibility_value = row.get("confidence")
    reach_value = row.get("reach_from")
    if reach_value is None:
        reach_value = row.get("reach_from_json")
    return SurfaceNode(
        id=node_id,
        category=_category_from_text(category_value if category_value is not None else "other"),
        name=_first_text(row, "display_name", "label") or node_id,
        impact=_unit({"impact": impact_value if impact_value is not None else 0.0}, "impact"),
        feasibility=_unit(
            {"feasibility": feasibility_value if feasibility_value is not None else 1.0},
            "feasibility",
        ),
        privilege=_nonnegative(row, "privilege", "privilege_delta", "privilege_level", default=0.0),
        zero_click=(
            _truthy(row.get("zero_click"))
            or _truthy(row.get("zeroClick"))
            or _reach_zero_click(reach_value)
        ),
        persistence=_truthy(row.get("persistence")),
        terminal=_truthy(row.get("terminal")),
    )


def _reach_zero_click(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return False
    items: tuple[object, ...]
    if isinstance(value, Mapping):
        items = (value,)
    elif isinstance(value, (list, tuple)):
        items = tuple(value)
    else:
        return False
    for item in items:
        if not isinstance(item, Mapping):
            continue
        haystack = " ".join(
            str(item.get(key, "")) for key in ("source", "via", "mechanism", "note")
        ).lower().replace("-", "_")
        if "zero_click" in haystack or item.get("hops") == 0:
            return True
    return False


def surface_graph_from_rows(
    rows: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]] | None = None,
) -> SurfaceGraph:
    """Build a surface graph from catalog rows plus explicit or inline hops."""
    node_items = [
        _require_mapping(row, f"surface row {index}") for index, row in enumerate(rows)
    ]
    nodes = tuple(_node_from_row(row, index) for index, row in enumerate(node_items))
    edge_items: list[SurfaceEdge] = []
    if edges is not None:
        for index, item in enumerate(edges):
            edge_items.append(_edge_from_mapping(_require_mapping(item, f"surface edge {index}"), default_source=None))
    for row, node in zip(node_items, nodes, strict=True):
        for key in ("edges", "hops", "feeds", "entry_points"):
            value = row.get(key)
            if value is None:
                continue
            targets: list[object]
            if isinstance(value, str):
                targets = [value]
            elif isinstance(value, (list, tuple)):
                targets = list(value)
            else:
                raise FormatFail(f"surface row {key} must be a string or sequence")
            for target in targets:
                if isinstance(target, Mapping):
                    edge_items.append(
                        _edge_from_mapping(
                            _require_mapping(target, f"surface row {key} target"),
                            default_source=node.id,
                        )
                    )
                elif isinstance(target, str):
                    edge_items.append(
                        SurfaceEdge(
                            id=f"{node.id}->{target.strip()}",
                            source=node.id,
                            target=target.strip(),
                            kind=SurfaceHopKind.CRASH_FEEDS_ENTRY,
                        )
                    )
                else:
                    raise FormatFail("surface row hop targets must be mappings or strings")
    return SurfaceGraph(nodes=nodes, edges=tuple(edge_items))


__all__ = [
    "DEFAULT_CHAIN_DEADLINE_S",
    "DEFAULT_MAX_EXPANSIONS",
    "DEFAULT_MAX_RELAXATIONS",
    "MAX_SURFACE_AFFINITY",
    "MAX_SURFACE_COST",
    "MAX_SURFACE_EDGES",
    "MAX_SURFACE_FEASIBILITY",
    "MAX_SURFACE_HOPS",
    "MAX_SURFACE_IMPACT",
    "MAX_SURFACE_NODES",
    "MAX_SURFACE_PATHS",
    "MAX_SURFACE_PRIVILEGE_DELTA",
    "MAX_SURFACE_RELIABILITY",
    "SURFACE_CHAIN_ARTIFACT_KIND",
    "SURFACE_CHAIN_LEDGER_TYPE",
    "SURFACE_CHAIN_RECORD_KIND",
    "SURFACE_CHAIN_SCHEMA",
    "SurfaceCategory",
    "SurfaceChainConfig",
    "SurfaceChainEmitter",
    "SurfaceChainPath",
    "SurfaceChainQuality",
    "SurfaceChainResult",
    "SurfaceEdge",
    "SurfaceGraph",
    "SurfaceHopKind",
    "SurfaceNode",
    "SurfaceQualityWeights",
    "SurfaceSearchAlgorithm",
    "enumerate_surface_chains",
    "parse_search_algorithm",
    "parse_surface_category",
    "parse_surface_hop_kind",
    "rank_surface_chains",
    "surface_affinity",
    "surface_graph_from_rows",
]
