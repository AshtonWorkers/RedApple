"""Bounded Dijkstra chain search from zero-click ingress to persistence."""

from __future__ import annotations

import heapq
import json
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ..errors import FormatFail
from ..ledger import Ledger
from .models import (
    CHAIN_CLAIM_TYPES,
    CHAIN_DEADLINE_S,
    DEFAULT_EDGE_STATES,
    MAX_CHAIN_NODES,
    MAX_ESCALATION_DELTA,
    MAX_PRICING_FACTOR,
    MIN_EDGE_COST,
    PAC_SPTM_MULTIPLIER,
    ChainEdge,
    ChainGraph,
    ChainNode,
    ChainPath,
    ChainSearchResult,
    PrimitiveProfile,
)
from .ports import PrimitiveProvider
from .stubs import NullPrimitiveProvider

_MAX_EDGE_RECIPROCAL = 1_000_000_000.0
_MAX_EDGE_COST = 1_000_000_000_000.0


@dataclass(frozen=True)
class ChainSearchConfig:
    """Bounds and cost constants for RA-CHN-002/003."""

    max_nodes: int = MAX_CHAIN_NODES
    deadline_s: float = CHAIN_DEADLINE_S
    edge_floor: float = MIN_EDGE_COST
    pac_sptm_multiplier: float = PAC_SPTM_MULTIPLIER
    clock: Callable[[], float] | None = None
    max_joins: int | None = None
    max_paths: int = 1
    dead_end_pruning: bool = True

    def validate(self) -> None:
        if self.max_nodes <= 0:
            raise FormatFail("chain max_nodes must be positive")
        if not math.isfinite(self.deadline_s) or self.deadline_s <= 0:
            raise FormatFail("chain deadline_s must be positive")
        if not math.isfinite(self.edge_floor) or self.edge_floor < 0:
            raise FormatFail("chain edge_floor must be non-negative")
        if not math.isfinite(self.pac_sptm_multiplier) or self.pac_sptm_multiplier < 1:
            raise FormatFail("chain pac_sptm_multiplier must be >= 1")
        if self.max_joins is not None and self.max_joins <= 0:
            raise FormatFail("chain max_joins must be positive")
        if self.max_paths <= 0:
            raise FormatFail("chain max_paths must be positive")


@dataclass(frozen=True)
class _Label:
    node_id: str
    cost: float
    join_count: int
    path_key: tuple[str, ...]
    parent: _Label | None = None
    edge: ChainEdge | None = None
    visited: frozenset[str] = field(default_factory=frozenset)


def _as_object(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FormatFail("claim value_json is not valid JSON") from exc
    if parsed is None:
        return {}
    if not isinstance(parsed, Mapping):
        return {}
    return dict(parsed)


def _bool_field(value: Mapping[str, Any], key: str) -> bool:
    item = value.get(key)
    if isinstance(item, bool):
        return item
    if isinstance(item, str):
        return item.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _int_field(value: Mapping[str, Any], key: str) -> int | None:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        return None
    return item


def _float_field(value: Mapping[str, Any], key: str) -> float | None:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        return None
    value_float = float(item)
    return value_float if math.isfinite(value_float) and value_float > 0 else None


def _clamped_delta(value: int) -> int:
    return max(0, min(value, MAX_ESCALATION_DELTA))


def _protection_flags(value: Mapping[str, Any]) -> tuple[bool, bool]:
    pac = _bool_field(value, "pac")
    sptm = _bool_field(value, "sptm")
    protections = value.get("protections")
    if isinstance(protections, Sequence) and not isinstance(protections, str):
        flags = {str(item).strip().lower() for item in protections}
        pac = pac or "pac" in flags or "pointer_authentication" in flags
        sptm = sptm or "sptm" in flags or "sptm_protect" in flags
    return pac, sptm


def _reach_records(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = row.get("reach_from_json")
    if not isinstance(raw, str) or not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [dict(item) for item in parsed if isinstance(item, Mapping)]


def is_zero_click_entry_point(row: Mapping[str, Any]) -> bool:
    """Return whether an entry point has a zero-click reach record."""
    for record in _reach_records(row):
        haystack = f"{record.get('source', '')} {record.get('via', '')}".lower().replace("-", "_")
        if "zero_click" in haystack or record.get("hops") == 0:
            return True
    return False


def _entry_references(value: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    wanted_ids = {value.get("entry_point_id"), value.get("entryPointId")}
    wanted_names = {value.get("entry_point"), value.get("entry_point_name"), value.get("surface")}
    for key in ("entry_points", "entryPoints"):
        items = value.get(key)
        if isinstance(items, Sequence) and not isinstance(items, str):
            wanted_ids.update(items)
            wanted_names.update(items)
    return str(row.get("id")) in {str(item) for item in wanted_ids if item is not None} or str(
        row.get("name")
    ) in {str(item) for item in wanted_names if item is not None}


def _linked_zero_click_entry(
    value: Mapping[str, Any], entry_points: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    for row in entry_points:
        if is_zero_click_entry_point(row) and _entry_references(value, row):
            return row
    return None


def _node_from_claim(
    row: Mapping[str, Any],
    provider: PrimitiveProvider,
    entry_points: Sequence[Mapping[str, Any]],
) -> ChainNode:
    claim_id = str(row["id"])
    claim_type = str(row.get("type", ""))
    value = _as_object(row.get("value_json"))
    profile: PrimitiveProfile | None = provider.profile(claim_id, claim_type, value)
    pac, sptm = _protection_flags(value)
    privilege = _int_field(value, "privilege_delta")
    impact = _int_field(value, "impact_delta")
    if profile is not None:
        if privilege is None:
            privilege = profile.privilege_delta
        if impact is None:
            impact = profile.impact_delta
    privilege = _clamped_delta(0 if privilege is None else privilege)
    impact = _clamped_delta(0 if impact is None else impact)
    if profile is not None:
        pac = pac or profile.pac
        sptm = sptm or profile.sptm
    linked = _linked_zero_click_entry(value, entry_points)
    zero_click = _bool_field(value, "zero_click") or _bool_field(value, "zeroClick")
    ingress_weight = _float_field(value, "ingress_weight") or _float_field(value, "ingressWeight")
    if profile is not None and profile.zero_click:
        zero_click = True
    profile_weight = None if profile is None else profile.ingress_weight
    if profile_weight is not None and math.isfinite(profile_weight) and profile_weight > 0:
        ingress_weight = profile_weight if ingress_weight is None else max(
            ingress_weight, profile_weight
        )
    entry_id: str | None = None
    if linked is not None:
        zero_click = True
        entry_id = str(linked.get("id"))
        entry_delta = linked.get("privilege_delta")
        if isinstance(entry_delta, int) and not isinstance(entry_delta, bool):
            privilege = _clamped_delta(max(privilege, max(0, entry_delta)))
        weight = linked.get("weight")
        if isinstance(weight, (int, float)) and not isinstance(weight, bool):
            weight_float = float(weight)
            if math.isfinite(weight_float) and weight_float > 0:
                ingress_weight = (
                    weight_float if ingress_weight is None else max(ingress_weight, weight_float)
                )
    persistence = _bool_field(value, "persistence") or claim_type == "root_cause"
    if profile is not None and profile.persistence:
        persistence = True
    ingress = 1.0 if ingress_weight is None else min(ingress_weight, MAX_PRICING_FACTOR)
    return ChainNode(
        id=claim_id,
        claim_id=claim_id,
        claim_type=claim_type,
        privilege_delta=privilege,
        impact_delta=impact,
        pac=pac,
        sptm=sptm,
        persistence=persistence,
        zero_click=zero_click,
        ingress_weight=ingress,
        entry_point_id=entry_id,
    )


def _join_edge(row: Mapping[str, Any]) -> ChainEdge | None:
    lower = row.get("lower_bound")
    if isinstance(lower, bool) or not isinstance(lower, (int, float)) or not 0.0 < lower <= 1.0:
        return None
    reliability = row.get("reliability")
    if reliability is not None and (
        isinstance(reliability, bool) or not isinstance(reliability, (int, float))
    ):
        reliability = None
    created = row.get("created", 0)
    return ChainEdge(
        id=str(row["id"]),
        a_claim=str(row["a_claim"]),
        b_claim=str(row["b_claim"]),
        lower_bound=float(lower),
        state=str(row["state"]),
        created=int(created) if isinstance(created, int) and not isinstance(created, bool) else 0,
        reliability=None if reliability is None else float(reliability),
    )


def build_graph(
    ledger: Ledger,
    *,
    primitives: PrimitiveProvider | None = None,
    edge_states: Sequence[str] = DEFAULT_EDGE_STATES,
    claim_limit: int = 10_000,
    join_limit: int = 50_000,
    entry_point_limit: int = 1_000,
) -> ChainGraph:
    """Build a chain graph from ledger claims, entry points, and join rows."""
    provider = primitives or NullPrimitiveProvider()
    claim_rows: dict[str, dict[str, Any]] = {}
    for claim_type in CHAIN_CLAIM_TYPES:
        for row in ledger.claims_by_type(claim_type, limit=claim_limit):
            claim_rows.setdefault(str(row["id"]), row)
    entry_points: list[dict[str, Any]] = []
    for ring in ledger.ring_nodes():
        entry_points.extend(
            ledger.entry_points(str(ring["id"]), limit=entry_point_limit)
        )
    entry_points.sort(key=lambda row: (-float(row.get("weight", 0.0)), str(row.get("id", ""))))
    join_rows = ledger.joins(states=edge_states, limit=join_limit)
    for row in join_rows:
        for key in ("a_claim", "b_claim"):
            claim_id = str(row[key])
            if claim_id not in claim_rows:
                fetched = ledger.get_claim(claim_id)
                if fetched is not None:
                    claim_rows[claim_id] = fetched
    nodes = {
        claim_id: _node_from_claim(row, provider, entry_points)
        for claim_id, row in sorted(claim_rows.items())
    }
    edges: list[ChainEdge] = []
    skipped = 0
    for row in join_rows:
        edge = _join_edge(row)
        if edge is None or edge.a_claim not in nodes or edge.b_claim not in nodes:
            skipped += 1
            continue
        edges.append(edge)
    edges.sort(key=lambda edge: (edge.a_claim, edge.b_claim, edge.id))
    return ChainGraph(nodes=MappingProxyType(nodes), edges=tuple(edges), skipped_edges=skipped)


def _dominates(first: _Label, second: _Label) -> bool:
    if first.cost > second.cost or first.join_count > second.join_count:
        return False
    if first.cost < second.cost or first.join_count < second.join_count:
        return True
    return first.path_key <= second.path_key


def _add_label(best: dict[str, list[_Label]], node_id: str, label: _Label) -> bool:
    labels = best.setdefault(node_id, [])
    if any(_dominates(old, label) for old in labels):
        return False
    kept = [old for old in labels if not _dominates(label, old)]
    kept.append(label)
    best[node_id] = kept
    return True


def _current(best: dict[str, list[_Label]], label: _Label) -> bool:
    return any(existing is label for existing in best.get(label.node_id, ()))


def _edge_cost(
    edge: ChainEdge,
    target: ChainNode,
    join_count: int,
    config: ChainSearchConfig,
) -> float:
    lower = edge.lower_bound
    if not math.isfinite(lower) or lower <= 0:
        lower = 1.0
    reciprocal = 1.0 / lower
    if not math.isfinite(reciprocal) or reciprocal > _MAX_EDGE_RECIPROCAL:
        reciprocal = _MAX_EDGE_RECIPROCAL
    delta = min(max(target.escalation_delta, 0), 2 * MAX_ESCALATION_DELTA)
    raw = join_count * reciprocal - delta
    cost = max(config.edge_floor, min(raw, _MAX_EDGE_COST))
    if target.protected:
        cost *= config.pac_sptm_multiplier
    return cost


def _build_path(label: _Label, graph: ChainGraph) -> ChainPath:
    chain: list[_Label] = []
    current: _Label | None = label
    while current is not None:
        chain.append(current)
        current = current.parent
    chain.reverse()
    node_ids = tuple(item.node_id for item in chain)
    edge_ids = tuple(item.edge.id for item in chain[1:] if item.edge is not None)
    edge_rows = [item.edge for item in chain[1:] if item.edge is not None]
    min_lb = min((edge.lower_bound for edge in edge_rows), default=1.0)
    weakest = min(edge_rows, key=lambda edge: (edge.lower_bound, edge.id), default=None)
    source = graph.nodes[node_ids[0]]
    return ChainPath(
        node_ids=node_ids,
        edge_ids=edge_ids,
        cost=label.cost,
        join_count=label.join_count,
        ingress_weight=source.ingress_weight,
        min_lower_bound=min_lb,
        weakest_join_id=None if weakest is None else weakest.id,
        total_privilege_delta=sum(
            graph.nodes[node_id].privilege_delta for node_id in node_ids[1:]
        ),
        total_impact_delta=sum(graph.nodes[node_id].impact_delta for node_id in node_ids[1:]),
    )


def _nodes_reaching_targets(graph: ChainGraph, target_ids: set[str]) -> set[str]:
    """Return nodes that can reach a target; used to prune dead ends."""
    reverse: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.a_claim in graph.nodes and edge.b_claim in graph.nodes:
            reverse.setdefault(edge.b_claim, set()).add(edge.a_claim)
    useful = {node_id for node_id in target_ids if node_id in graph.nodes}
    stack = sorted(useful)
    while stack:
        node_id = stack.pop()
        for parent in reverse.get(node_id, ()):
            if parent not in useful:
                useful.add(parent)
                stack.append(parent)
    return useful


def search_chain(
    graph: ChainGraph,
    config: ChainSearchConfig | None = None,
    *,
    sources: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
) -> ChainSearchResult:
    """Run bounded multi-criteria Dijkstra over ledger join edges."""
    cfg = config or ChainSearchConfig()
    cfg.validate()
    clock = cfg.clock or time.monotonic
    started = clock()
    deadline = started + cfg.deadline_s
    require_persistence = targets is None
    source_ids = (
        [node.id for node in graph.nodes.values() if node.zero_click]
        if sources is None
        else list(sources)
    )
    target_ids = (
        {node.id for node in graph.nodes.values() if node.persistence}
        if targets is None
        else set(targets)
    )
    source_ids = sorted(set(source_ids))
    if not source_ids:
        return ChainSearchResult(None, 0, 0, clock() - started, "no_ingress")
    if not target_ids:
        return ChainSearchResult(None, 0, 0, clock() - started, "no_persistence")
    useful = (
        _nodes_reaching_targets(graph, target_ids) if cfg.dead_end_pruning else set(graph.nodes)
    )
    adjacency: dict[str, list[ChainEdge]] = {}
    pruned = 0
    for edge in graph.edges:
        if edge.a_claim in useful and edge.b_claim in useful:
            adjacency.setdefault(edge.a_claim, []).append(edge)
        else:
            pruned += 1
    for items in adjacency.values():
        items.sort(key=lambda edge: edge.id)
    if cfg.dead_end_pruning and not useful:
        return ChainSearchResult(
            None, 0, 0, clock() - started, "no_path", pruned_edges=pruned
        )
    available_sources = [source_id for source_id in source_ids if source_id in graph.nodes]
    if not available_sources:
        return ChainSearchResult(None, 0, 0, clock() - started, "no_ingress")
    best: dict[str, list[_Label]] = {}
    heap: list[tuple[float, int, tuple[str, ...], int, _Label]] = []
    serial = 0
    for source_id in available_sources:
        node = graph.nodes[source_id]
        if node.id not in useful:
            continue
        best[node.id] = [_Label(
            node_id=node.id,
            cost=0.0,
            join_count=0,
            path_key=(f"n:{node.id}",),
            visited=frozenset({node.id}),
        )]
        label = best[node.id][0]
        heapq.heappush(heap, (label.cost, label.join_count, label.path_key, serial, label))
        serial += 1
    if not heap:
        return ChainSearchResult(
            None, 0, 0, clock() - started, "no_path", pruned_edges=pruned
        )
    expansions = 0
    relaxed = 0
    found: list[ChainPath] = []
    while heap:
        now = clock()
        if now >= deadline:
            return ChainSearchResult(
                found[0] if found else None,
                expansions,
                relaxed,
                now - started,
                "deadline",
                paths=tuple(found),
                pruned_edges=pruned,
            )
        _, _, _, _, label = heapq.heappop(heap)
        if not _current(best, label):
            continue
        node = graph.nodes[label.node_id]
        if (
            node.id in target_ids
            and label.join_count > 0
            and (not require_persistence or node.persistence)
        ):
            found.append(_build_path(label, graph))
            if len(found) >= cfg.max_paths:
                return ChainSearchResult(
                    found[0],
                    expansions,
                    relaxed,
                    clock() - started,
                    "found",
                    paths=tuple(found),
                    pruned_edges=pruned,
                )
            continue
        if expansions >= cfg.max_nodes:
            return ChainSearchResult(
                found[0] if found else None,
                expansions,
                relaxed,
                clock() - started,
                "node_cap",
                paths=tuple(found),
                pruned_edges=pruned,
            )
        expansions += 1
        for edge in adjacency.get(node.id, ()):
            relaxed += 1
            target = graph.nodes.get(edge.b_claim)
            if target is None or target.id in label.visited:
                continue
            join_count = label.join_count + 1
            if cfg.max_joins is not None and join_count > cfg.max_joins:
                continue
            cost = label.cost + _edge_cost(edge, target, join_count, cfg)
            new_label = _Label(
                node_id=target.id,
                cost=cost,
                join_count=join_count,
                path_key=label.path_key + (f"e:{edge.id}", f"n:{target.id}"),
                parent=label,
                edge=edge,
                visited=label.visited.union({target.id}),
            )
            if _add_label(best, target.id, new_label):
                heapq.heappush(
                    heap,
                    (new_label.cost, new_label.join_count, new_label.path_key, serial, new_label),
                )
                serial += 1
    return ChainSearchResult(
        found[0] if found else None,
        expansions,
        relaxed,
        clock() - started,
        "found" if found else "no_path",
        paths=tuple(found),
        pruned_edges=pruned,
    )
