"""Graph construction, path search, and scoring for escalation reasoning."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from ..errors import FormatFail
from ..srf.models import EntryPoint
from .models import (
    DEFAULT_REACH_DECAY,
    MAX_EVIDENCE_ITEMS,
    MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES,
    MAX_PATH_HOPS,
    SURFACE_WEIGHT_NORM,
    EscalationEdge,
    EscalationNode,
    EscalationPath,
    EscalationStage,
    default_privilege,
    edge_impact_score,
    parse_stage,
    stage_for_name,
)

MAX_RESULT_PATHS = 1024
MAX_SEARCH_STACK = 100_000
DEFAULT_MAX_EXPANSIONS = 100_000
DEFAULT_MAX_RELAXATIONS = 1_000_000

SearchFrame = tuple[
    str,
    tuple[str, ...],
    tuple[EscalationEdge, ...],
    float,
    float,
    float,
    float,
    float,
]


@dataclass(frozen=True)
class EscalationGraph:
    """Immutable escalation graph ready for deterministic path search."""

    nodes: tuple[EscalationNode, ...]
    edges: tuple[EscalationEdge, ...]

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        if len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES:
            raise FormatFail("escalation graph exceeds bounded size")
        if not all(isinstance(node, EscalationNode) for node in nodes):
            raise FormatFail("graph nodes must be EscalationNode values")
        if not all(isinstance(edge, EscalationEdge) for edge in edges):
            raise FormatFail("graph edges must be EscalationEdge values")
        node_ids = tuple(node.id for node in nodes)
        if len(set(node_ids)) != len(node_ids):
            raise FormatFail("duplicate escalation node id")
        node_set = set(node_ids)
        edge_keys: set[tuple[str, str, str]] = set()
        for edge in edges:
            if edge.source not in node_set or edge.target not in node_set:
                raise FormatFail("escalation edge references unknown node")
            if edge.source == edge.target:
                raise FormatFail("self-loop escalation edges are not allowed")
            if edge.key in edge_keys:
                raise FormatFail("duplicate escalation edge")
            edge_keys.add(edge.key)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)

    @property
    def node_map(self) -> dict[str, EscalationNode]:
        return {node.id: node for node in self.nodes}

    def adjacency(self) -> dict[str, tuple[EscalationEdge, ...]]:
        grouped: dict[str, list[EscalationEdge]] = defaultdict(list)
        for edge in self.edges:
            grouped[edge.source].append(edge)
        return {
            source: tuple(sorted(edges, key=_edge_sort_key)) for source, edges in grouped.items()
        }

    def _active_node_ids(self) -> set[str]:
        active: set[str] = set()
        for edge in self.edges:
            active.add(edge.source)
            active.add(edge.target)
        return active

    def sources(self) -> tuple[str, ...]:
        active = self._active_node_ids()
        if not active:
            return ()
        candidates = [node for node in self.nodes if node.id in active]
        sandbox = sorted(node.id for node in candidates if node.stage is EscalationStage.SANDBOX_PROFILE)
        if sandbox:
            return tuple(sandbox)
        lowest = min(node.stage.rank for node in candidates)
        return tuple(sorted(node.id for node in candidates if node.stage.rank == lowest))

    def targets(self) -> tuple[str, ...]:
        active = self._active_node_ids()
        if not active:
            return ()
        candidates = [node for node in self.nodes if node.id in active]
        preferred = sorted(
            node.id
            for node in candidates
            if node.stage in (EscalationStage.KERNEL, EscalationStage.ROOT)
        )
        if preferred:
            return tuple(preferred)
        highest = max(node.stage.rank for node in candidates)
        return tuple(sorted(node.id for node in candidates if node.stage.rank == highest))


@dataclass(frozen=True)
class EscalationResult:
    """Deterministic escalation analysis result."""

    paths: tuple[EscalationPath, ...]
    nodes_considered: int
    edges_considered: int
    expansions: int
    relaxations: int
    truncated: bool

    @property
    def highest_impact(self) -> EscalationPath | None:
        return self.paths[0] if self.paths else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": [path.to_dict() for path in self.paths],
            "nodes_considered": self.nodes_considered,
            "edges_considered": self.edges_considered,
            "expansions": self.expansions,
            "relaxations": self.relaxations,
            "truncated": self.truncated,
            "highest_impact": (
                None if self.highest_impact is None else self.highest_impact.to_dict()
            ),
        }


def _edge_sort_key(edge: EscalationEdge) -> tuple[float, float, float, float, int, str, str]:
    return (
        -edge_impact_score(edge),
        -edge.privilege_delta,
        -edge.impact_delta,
        edge.cost,
        edge.join_count,
        edge.target,
        edge.relation,
    )


def _require_mapping(value: object, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatFail(f"{field_name} must be a mapping")
    return cast(Mapping[str, Any], value)


def _first_text(mapping: Mapping[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _finite_number(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{field_name} must be a finite number")
    out = float(value)
    if not math.isfinite(out):
        raise FormatFail(f"{field_name} must be finite")
    return out


def _number(mapping: Mapping[str, Any], *keys: str, default: float = 0.0) -> float:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        return _finite_number(value, key)
    return default


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
        return max(0, int(out))
    return default


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _positive_int(value: object, field_name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"{field_name} must be an integer")
    if value <= 0 or (maximum is not None and value > maximum):
        bound = f" in [1,{maximum}]" if maximum is not None else " positive"
        raise FormatFail(f"{field_name} must be{bound}")
    return value


def _clean_evidence(value: object) -> tuple[str, ...]:
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


def _edge_evidence(item: Mapping[str, Any]) -> tuple[str, ...]:
    if item.get("evidence") is not None:
        return _clean_evidence(item.get("evidence"))
    parts = [
        text
        for key in ("via", "mechanism", "note")
        if isinstance((text := item.get(key)), str) and text.strip()
    ]
    return tuple(sorted(set(parts))[:MAX_EVIDENCE_ITEMS])


def _node_from_mapping(item: Mapping[str, Any], index: int) -> EscalationNode:
    node_id = _first_text(item, "id", "node_id", "name") or f"node-{index:06d}"
    stage_value = item.get("stage")
    stage = parse_stage(stage_value) if stage_value is not None else stage_for_name(node_id)
    if any(item.get(key) is not None for key in ("privilege", "privilege_level")):
        privilege = _number(item, "privilege", "privilege_level", default=0.0)
    else:
        privilege = default_privilege(stage)
    return EscalationNode(
        id=node_id,
        stage=stage,
        privilege=privilege,
        impact=_number(item, "impact", "impact_score", "severity", default=0.0),
        name=_first_text(item, "display_name", "label"),
    )


def _edge_from_mapping(item: Mapping[str, Any]) -> EscalationEdge:
    source = _first_text(item, "source", "from", "src")
    target = _first_text(item, "target", "to", "dst")
    if not source or not target:
        raise FormatFail("edge mapping requires source and target")
    return EscalationEdge(
        source=source,
        target=target,
        relation=_first_text(item, "relation", "kind", "type", default="escalates")
        or "escalates",
        privilege_delta=_number(item, "privilege_delta", "privilege", default=0.0),
        impact_delta=_number(item, "impact_delta", "impact", default=0.0),
        cost=_number(item, "cost", "weight", "price", default=0.0),
        reliability=_number(item, "reliability", "confidence", default=1.0),
        join_count=_int_value(item, "join_count", "joins", default=0),
        evidence=_edge_evidence(item),
    )


def graph_from_mappings(
    nodes: Iterable[Mapping[str, Any]],
    edges: Iterable[Mapping[str, Any]],
) -> EscalationGraph:
    """Build a graph from plain node and edge mappings."""
    node_items = [
        _require_mapping(item, f"node {index}") for index, item in enumerate(nodes)
    ]
    edge_items = [_require_mapping(item, f"edge {index}") for index, item in enumerate(edges)]
    return EscalationGraph(
        nodes=_dedupe_nodes([_node_from_mapping(item, index) for index, item in enumerate(node_items)]),
        edges=_dedupe_edges([_edge_from_mapping(item) for item in edge_items]),
    )


def graph_from_entry_points(entry_points: Iterable[EntryPoint]) -> EscalationGraph:
    """Adapt RA-SRF EntryPoint rows into an escalation graph."""
    return graph_from_surface_rows([entry_point.to_row() for entry_point in entry_points])


def graph_from_surface_rows(rows: Sequence[Mapping[str, Any]]) -> EscalationGraph:
    """Adapt surface-graph rows (including ``reach_from_json``) into a graph."""
    nodes: list[EscalationNode] = []
    edges: list[EscalationEdge] = []
    for index, raw in enumerate(rows):
        row = _require_mapping(raw, f"surface row {index}")
        entry_id = (
            _first_text(row, "id", "entry_point_id", "entry_point", "name")
            or f"surface-{index:06d}"
        )
        node_name = _first_text(row, "name", "entry_point", "label") or entry_id
        stage = stage_for_name(node_name)
        privilege_delta = _number(row, "privilege_delta", "privilege", default=0.0)
        parser_complexity = _clamp01(
            _number(row, "parser_complexity", "complexity", default=0.0)
        )
        weight = _clamp01(_number(row, "weight", default=0.0) / SURFACE_WEIGHT_NORM)
        impact = _clamp01((parser_complexity * 0.6) + (weight * 0.4))
        nodes.append(
            EscalationNode(
                id=entry_id,
                stage=stage,
                privilege=default_privilege(stage),
                impact=impact,
                name=node_name,
            )
        )
        reach_value = row.get("reach_from")
        if reach_value is None:
            reach_value = row.get("reach_from_json")
        for reach_index, reach in enumerate(_reach_items(reach_value)):
            source = _reach_source(reach, reach_index)
            profile = _profile_node(source)
            nodes.append(profile)
            edges.append(
                EscalationEdge(
                    source=profile.id,
                    target=entry_id,
                    relation="surface_reach",
                    privilege_delta=privilege_delta,
                    impact_delta=impact,
                    cost=_reach_cost(reach),
                    reliability=_reach_reliability(reach),
                    join_count=_reach_join_count(reach),
                    evidence=_reach_evidence(reach, row),
                )
            )
    return EscalationGraph(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))


def _reach_items(value: object) -> tuple[Mapping[str, Any], ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise FormatFail("reach_from_json must be valid JSON") from exc
    if isinstance(value, Mapping):
        return (_require_mapping(value, "reach_from"),)
    if isinstance(value, (list, tuple)):
        items: list[Mapping[str, Any]] = []
        for item in value:
            if isinstance(item, Mapping):
                items.append(_require_mapping(item, "reach_from entry"))
            elif isinstance(item, str):
                items.append({"source": item})
            elif hasattr(item, "as_dict"):
                items.append(_require_mapping(item.as_dict(), "reach_from entry"))
            else:
                raise FormatFail("reach_from entries must be mappings or strings")
        return tuple(items)
    raise FormatFail("reach_from must be a mapping or sequence")


def _reach_source(reach: Mapping[str, Any], index: int) -> str:
    source = _first_text(reach, "source", "from", "profile", "sandbox")
    if not source:
        raise FormatFail(f"reach_from entry {index + 1} requires a source")
    return source


def _profile_node(source: str) -> EscalationNode:
    profile_id = source if source.startswith("sandbox:") else f"sandbox:{source}"
    return EscalationNode(
        id=profile_id,
        stage=EscalationStage.SANDBOX_PROFILE,
        privilege=default_privilege(EscalationStage.SANDBOX_PROFILE),
        impact=0.0,
        name=source,
    )


def _reach_cost(reach: Mapping[str, Any]) -> float:
    return _number(reach, "cost", "weight", default=0.0)


def _reach_reliability(reach: Mapping[str, Any]) -> float:
    if reach.get("reliability") is not None:
        return _clamp01(_number(reach, "reliability", default=1.0))
    if reach.get("confidence") is not None:
        return _clamp01(_number(reach, "confidence", default=1.0))
    hops = _number(reach, "hops", "hop_count", default=1.0)
    return _clamp01(DEFAULT_REACH_DECAY ** max(0.0, hops))


def _reach_join_count(reach: Mapping[str, Any]) -> int:
    return min(1_000_000, _int_value(reach, "join_count", "joins", default=0))


def _reach_evidence(reach: Mapping[str, Any], row: Mapping[str, Any]) -> tuple[str, ...]:
    parts = [
        text
        for key in ("via", "mechanism", "note")
        if isinstance((text := reach.get(key)), str) and text.strip()
    ]
    if reach.get("evidence") is not None:
        parts.extend(_clean_evidence(reach.get("evidence")))
    entry_name = _first_text(row, "name", "entry_point")
    if entry_name:
        parts.append(f"surface:{entry_name}")
    return tuple(sorted(set(parts)))


def graph_from_chain_outputs(value: object) -> EscalationGraph:
    """Adapt chain-search-like outputs into an escalation graph.

    Accepted shapes are ``None``, an existing ``EscalationGraph``, mappings with
    ``nodes``/``edges`` and/or ``path``/``paths``/``steps``, single edge/node
    mappings, or sequences of those mappings.
    """
    if value is None:
        return EscalationGraph(nodes=(), edges=())
    if isinstance(value, EscalationGraph):
        return value
    nodes: list[EscalationNode] = []
    edges: list[EscalationEdge] = []
    _collect_chain_value(value, nodes, edges)
    return EscalationGraph(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))


def _collect_chain_value(
    value: object,
    nodes: list[EscalationNode],
    edges: list[EscalationEdge],
) -> None:
    if isinstance(value, Mapping):
        _collect_chain_mapping(value, nodes, edges)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_chain_value(item, nodes, edges)
    else:
        raise FormatFail("chain output must be a mapping, sequence, or EscalationGraph")


def _collect_chain_mapping(
    value: Mapping[str, Any],
    nodes: list[EscalationNode],
    edges: list[EscalationEdge],
) -> None:
    handled = False
    if value.get("nodes") is not None:
        _collect_chain_nodes(value.get("nodes"), nodes)
        handled = True
    if value.get("edges") is not None:
        _collect_chain_edges(value.get("edges"), nodes, edges)
        handled = True
    if value.get("paths") is not None:
        _collect_chain_paths(value.get("paths"), nodes, edges, multiple=True)
        handled = True
    if value.get("path") is not None:
        _collect_chain_paths(value.get("path"), nodes, edges)
        handled = True
    if value.get("steps") is not None:
        _collect_chain_edges(value.get("steps"), nodes, edges)
        handled = True
    if handled:
        return
    if any(key in value for key in ("source", "target", "from", "to")):
        edge = _edge_from_mapping(value)
        _ensure_edge_nodes(edge, nodes)
        edges.append(edge)
        return
    if any(key in value for key in ("node", "entry_point", "service", "name", "id", "node_id")):
        nodes.append(_node_from_mapping(value, len(nodes)))
        return
    if "value" in value:
        _collect_chain_value(value.get("value"), nodes, edges)
        return
    if not value:
        return
    raise FormatFail("unrecognized chain output mapping")


def _collect_chain_nodes(value: object, nodes: list[EscalationNode]) -> None:
    if value is None:
        return
    if isinstance(value, Mapping):
        nodes.append(_node_from_mapping(value, len(nodes)))
        return
    if isinstance(value, str):
        nodes.append(_node_for_id(value))
        return
    if not isinstance(value, (list, tuple)):
        raise FormatFail("chain nodes must be mappings or strings")
    for item in value:
        _collect_chain_nodes(item, nodes)


def _collect_chain_edges(
    value: object,
    nodes: list[EscalationNode],
    edges: list[EscalationEdge],
) -> None:
    if value is None:
        return
    specs: tuple[object, ...]
    if isinstance(value, (Mapping, str)):
        specs = (value,)
    elif isinstance(value, (list, tuple)):
        specs = tuple(value)
    else:
        raise FormatFail("chain edges must be mappings or strings")
    for spec in specs:
        if isinstance(spec, Mapping):
            edge = _edge_from_mapping(spec)
        elif isinstance(spec, str) and "->" in spec:
            source, target = spec.split("->", 1)
            edge = EscalationEdge(
                source=source.strip(),
                target=target.strip(),
                relation="chain_step",
                reliability=1.0,
            )
        else:
            raise FormatFail("chain edge must be a mapping or 'source->target' string")
        _ensure_edge_nodes(edge, nodes)
        edges.append(edge)


def _collect_chain_paths(
    value: object,
    nodes: list[EscalationNode],
    edges: list[EscalationEdge],
    *,
    multiple: bool = False,
) -> None:
    if value is None:
        return
    paths: tuple[object, ...]
    if multiple:
        if isinstance(value, (Mapping, str)):
            paths = (value,)
        elif isinstance(value, (list, tuple)):
            paths = tuple(value)
        else:
            raise FormatFail("chain paths must be sequences or mappings")
    elif isinstance(value, (Mapping, str)) or (
        isinstance(value, (list, tuple))
        and value
        and all(isinstance(step, (str, Mapping)) for step in value)
    ):
        paths = (value,)
    elif isinstance(value, (list, tuple)):
        paths = tuple(value)
    else:
        raise FormatFail("chain paths must be sequences or mappings")
    for path in paths:
        if isinstance(path, Mapping):
            _collect_chain_mapping(path, nodes, edges)
        elif isinstance(path, str):
            nodes.append(_node_for_id(path))
        elif isinstance(path, (list, tuple)):
            _collect_chain_path_sequence(path, nodes, edges)
        else:
            raise FormatFail("chain path entries must be mappings, strings, or sequences")


def _collect_chain_path_sequence(
    steps: Sequence[object],
    nodes: list[EscalationNode],
    edges: list[EscalationEdge],
) -> None:
    previous_id: str | None = None
    for index, step in enumerate(steps):
        if isinstance(step, Mapping):
            node = _node_from_path_step(step, index)
        elif isinstance(step, str):
            node = _node_for_id(step)
        else:
            raise FormatFail("chain path steps must be mappings or strings")
        nodes.append(node)
        if previous_id is not None:
            payload = step.get("edge") if isinstance(step, Mapping) else None
            edges.append(_path_edge(previous_id, node.id, payload))
        previous_id = node.id


def _node_for_id(node_id: str) -> EscalationNode:
    node_id = node_id.strip()
    if not node_id:
        raise FormatFail("chain node id must not be empty")
    stage = stage_for_name(node_id)
    return EscalationNode(
        id=node_id,
        stage=stage,
        privilege=default_privilege(stage),
        impact=0.0,
        name=node_id,
    )


def _node_from_path_step(step: Mapping[str, Any], index: int) -> EscalationNode:
    node_id = _first_text(step, "id", "node_id", "node", "name") or f"path-node-{index:06d}"
    stage_value = step.get("stage")
    stage = parse_stage(stage_value) if stage_value is not None else stage_for_name(node_id)
    if any(step.get(key) is not None for key in ("privilege", "privilege_level")):
        privilege = _number(step, "privilege", "privilege_level", default=0.0)
    else:
        privilege = default_privilege(stage)
    return EscalationNode(
        id=node_id,
        stage=stage,
        privilege=privilege,
        impact=_number(step, "impact", "impact_score", "severity", default=0.0),
        name=_first_text(step, "display_name", "label") or node_id,
    )


def _path_edge(source: str, target: str, payload: object) -> EscalationEdge:
    if payload is None:
        return EscalationEdge(
            source=source,
            target=target,
            relation="chain_step",
            reliability=1.0,
        )
    if not isinstance(payload, Mapping):
        raise FormatFail("chain path edge payload must be a mapping")
    return EscalationEdge(
        source=source,
        target=target,
        relation=_first_text(payload, "relation", "kind", "type", default="chain_step")
        or "chain_step",
        privilege_delta=_number(payload, "privilege_delta", "privilege", default=0.0),
        impact_delta=_number(payload, "impact_delta", "impact", default=0.0),
        cost=_number(payload, "cost", "weight", "price", default=0.0),
        reliability=_number(payload, "reliability", "confidence", default=1.0),
        join_count=_int_value(payload, "join_count", "joins", default=0),
        evidence=_edge_evidence(payload),
    )


def _ensure_edge_nodes(edge: EscalationEdge, nodes: list[EscalationNode]) -> None:
    existing = {node.id for node in nodes}
    for endpoint in (edge.source, edge.target):
        if endpoint not in existing:
            nodes.append(_node_for_id(endpoint))
            existing.add(endpoint)


def _dedupe_nodes(nodes: Sequence[EscalationNode]) -> tuple[EscalationNode, ...]:
    by_id: dict[str, EscalationNode] = {}
    for node in nodes:
        existing = by_id.get(node.id)
        if existing is None:
            by_id[node.id] = node
            continue
        names = [name for name in (existing.name, node.name) if name]
        by_id[node.id] = EscalationNode(
            id=node.id,
            stage=existing.stage if existing.stage.rank >= node.stage.rank else node.stage,
            privilege=max(existing.privilege, node.privilege),
            impact=max(existing.impact, node.impact),
            name=min(names) if names else "",
        )
    return tuple(by_id[key] for key in sorted(by_id))


def _dedupe_edges(edges: Sequence[EscalationEdge]) -> tuple[EscalationEdge, ...]:
    by_key: dict[tuple[str, str, str], EscalationEdge] = {}
    for edge in edges:
        existing = by_key.get(edge.key)
        if existing is None:
            by_key[edge.key] = edge
            continue
        by_key[edge.key] = EscalationEdge(
            source=edge.source,
            target=edge.target,
            relation=edge.relation,
            privilege_delta=max(existing.privilege_delta, edge.privilege_delta),
            impact_delta=max(existing.impact_delta, edge.impact_delta),
            cost=min(existing.cost, edge.cost),
            reliability=max(existing.reliability, edge.reliability),
            join_count=max(existing.join_count, edge.join_count),
            evidence=tuple(sorted(set(existing.evidence) | set(edge.evidence)))[
                :MAX_EVIDENCE_ITEMS
            ],
        )
    return tuple(by_key[key] for key in sorted(by_key))


def analyze_escalations(
    graph: EscalationGraph,
    *,
    sources: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
    max_paths: int = 32,
    max_expansions: int = DEFAULT_MAX_EXPANSIONS,
    max_relaxations: int = DEFAULT_MAX_RELAXATIONS,
) -> EscalationResult:
    """Search bounded simple paths and return the highest-impact escalations."""
    if not isinstance(graph, EscalationGraph):
        raise FormatFail("escalation analysis requires an EscalationGraph")
    max_paths = _positive_int(max_paths, "max_paths", maximum=MAX_RESULT_PATHS)
    max_expansions = _positive_int(max_expansions, "max_expansions")
    max_relaxations = _positive_int(max_relaxations, "max_relaxations")

    node_map = graph.node_map
    adjacency = graph.adjacency()
    source_ids = _resolve_ids(graph, sources, graph.sources())
    target_ids = _resolve_ids(graph, targets, graph.targets())
    target_set = set(target_ids)
    if not source_ids or not target_set:
        return EscalationResult((), len(graph.nodes), len(graph.edges), 0, 0, False)

    best: list[EscalationPath] = []
    expansions = 0
    relaxations = 0
    truncated = False

    for source in source_ids:
        if truncated:
            break
        stack: list[SearchFrame] = [(source, (source,), (), 0.0, 0.0, 0.0, 1.0, 0.0)]
        while stack and not truncated:
            if expansions >= max_expansions:
                truncated = True
                break
            node_id, nodes_path, edges_path, privilege_gain, impact_gain, impact_score, reliability, cost = (
                stack.pop()
            )
            expansions += 1
            if len(edges_path) >= MAX_PATH_HOPS:
                continue
            neighbors = adjacency.get(node_id, ())
            for edge in reversed(neighbors):
                relaxations += 1
                if relaxations > max_relaxations:
                    truncated = True
                    break
                if edge.target in nodes_path:
                    continue
                target_node = node_map[edge.target]
                new_nodes = (*nodes_path, edge.target)
                new_edges = (*edges_path, edge)
                new_privilege = privilege_gain + edge.privilege_delta
                new_impact_gain = impact_gain + edge.impact_delta
                new_score = impact_score + edge_impact_score(edge)
                new_reliability = reliability * edge.reliability
                new_cost = cost + edge.cost
                if edge.target in target_set:
                    _consider_path(
                        best,
                        _make_path(
                            new_nodes,
                            new_edges,
                            privilege_gain=new_privilege,
                            impact_gain=new_impact_gain,
                            impact_score=new_score,
                            reliability=new_reliability,
                            cost=new_cost,
                            stage_progress=(
                                target_node.stage.rank - node_map[source].stage.rank
                            ),
                        ),
                        max_paths,
                    )
                if len(new_edges) < MAX_PATH_HOPS:
                    if len(stack) >= MAX_SEARCH_STACK:
                        truncated = True
                        break
                    stack.append(
                        (
                            edge.target,
                            new_nodes,
                            new_edges,
                            new_privilege,
                            new_impact_gain,
                            new_score,
                            new_reliability,
                            new_cost,
                        )
                    )

    paths = tuple(sorted(best, key=lambda path: path.rank_key))
    return EscalationResult(
        paths,
        len(graph.nodes),
        len(graph.edges),
        expansions,
        relaxations,
        truncated,
    )


def _resolve_ids(
    graph: EscalationGraph,
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
            raise FormatFail("escalation node ids must be strings")
        text = value.strip()
        if text:
            resolved_set.add(text)
    resolved = tuple(sorted(resolved_set))
    for value in resolved:
        if value not in graph.node_map:
            raise FormatFail(f"unknown escalation node {value!r}")
    return resolved


def _consider_path(
    best: list[EscalationPath], path: EscalationPath, max_paths: int
) -> None:
    if len(best) < max_paths:
        best.append(path)
        return
    worst_index = 0
    for index in range(1, len(best)):
        if best[index].rank_key > best[worst_index].rank_key:
            worst_index = index
    if path.rank_key < best[worst_index].rank_key:
        best[worst_index] = path


def _make_path(
    nodes: tuple[str, ...],
    edges: tuple[EscalationEdge, ...],
    *,
    privilege_gain: float,
    impact_gain: float,
    impact_score: float,
    reliability: float,
    cost: float,
    stage_progress: int,
) -> EscalationPath:
    values = (privilege_gain, impact_gain, impact_score, reliability, cost)
    if not all(math.isfinite(value) for value in values):
        raise FormatFail("escalation path score must be finite")
    return EscalationPath(
        nodes=nodes,
        edges=edges,
        privilege_gain=privilege_gain,
        impact_gain=impact_gain,
        impact_score=impact_score,
        reliability=reliability,
        cost=cost,
        stage_progress=stage_progress,
    )


__all__ = [
    "DEFAULT_MAX_EXPANSIONS",
    "DEFAULT_MAX_RELAXATIONS",
    "MAX_RESULT_PATHS",
    "EscalationGraph",
    "EscalationResult",
    "analyze_escalations",
    "graph_from_chain_outputs",
    "graph_from_entry_points",
    "graph_from_mappings",
    "graph_from_surface_rows",
]
