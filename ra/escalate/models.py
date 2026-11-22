"""Deterministic models for sandbox-escape escalation reasoning."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..errors import FormatFail

MAX_PRIVILEGE_LEVEL = 5.0
MAX_NODE_IMPACT = 1.0
MAX_EDGE_IMPACT = 1.0
MAX_EDGE_COST = 1_000_000.0
MAX_PATH_HOPS = 8
MAX_GRAPH_NODES = 20_000
MAX_GRAPH_EDGES = 100_000
MAX_EVIDENCE_ITEMS = 16
DEFAULT_REACH_DECAY = 0.7
SURFACE_WEIGHT_NORM = 6.0

EdgeKey = tuple[str, str, str]
RankKey = tuple[
    float,
    float,
    float,
    int,
    float,
    int,
    tuple[str, ...],
    tuple[EdgeKey, ...],
]


class EscalationStage(StrEnum):
    """Privilege-escalation stages modeled by the reasoner."""

    SANDBOX_PROFILE = "sandbox_profile"
    ENTITLEMENT = "entitlement"
    SERVICE = "service"
    KERNEL = "kernel"
    ROOT = "root"

    @property
    def rank(self) -> int:
        return _STAGE_RANK[self]


_STAGE_RANK = {
    EscalationStage.SANDBOX_PROFILE: 0,
    EscalationStage.ENTITLEMENT: 1,
    EscalationStage.SERVICE: 2,
    EscalationStage.KERNEL: 3,
    EscalationStage.ROOT: 4,
}
_STAGE_ALIASES = {
    "sandbox": EscalationStage.SANDBOX_PROFILE,
    "sandbox_profile": EscalationStage.SANDBOX_PROFILE,
    "sandbox-profile": EscalationStage.SANDBOX_PROFILE,
    "entitlement": EscalationStage.ENTITLEMENT,
    "ent": EscalationStage.ENTITLEMENT,
    "service": EscalationStage.SERVICE,
    "svc": EscalationStage.SERVICE,
    "kernel": EscalationStage.KERNEL,
    "xnu": EscalationStage.KERNEL,
    "iokit": EscalationStage.KERNEL,
    "root": EscalationStage.ROOT,
    "uid0": EscalationStage.ROOT,
}
_DEFAULT_PRIVILEGE = {
    EscalationStage.SANDBOX_PROFILE: 0.0,
    EscalationStage.ENTITLEMENT: 1.0,
    EscalationStage.SERVICE: 2.0,
    EscalationStage.KERNEL: 4.0,
    EscalationStage.ROOT: 5.0,
}


def _finite_float(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{field_name} must be a finite number")
    out = float(value)
    if not math.isfinite(out):
        raise FormatFail(f"{field_name} must be finite")
    return out


def _clamped(value: object, field_name: str, low: float, high: float) -> float:
    return min(high, max(low, _finite_float(value, field_name)))


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


def parse_stage(value: object) -> EscalationStage:
    if isinstance(value, EscalationStage):
        return value
    if not isinstance(value, str):
        raise FormatFail("stage must be an EscalationStage or str")
    try:
        return EscalationStage(value)
    except ValueError:
        stage = _STAGE_ALIASES.get(value.strip().lower())
        if stage is None:
            raise FormatFail(f"unknown escalation stage {value!r}") from None
        return stage


def stage_for_name(name: str) -> EscalationStage:
    """Classify a node id/name into an escalation stage deterministically."""
    low = name.lower()
    if "sandbox" in low:
        return EscalationStage.SANDBOX_PROFILE
    if "entitlement" in low or low.startswith("ent:"):
        return EscalationStage.ENTITLEMENT
    if "root" in low or "uid0" in low:
        return EscalationStage.ROOT
    if "kernel" in low or "xnu" in low or "iokit" in low:
        return EscalationStage.KERNEL
    return EscalationStage.SERVICE


def default_privilege(stage: EscalationStage) -> float:
    """Default absolute privilege level for a stage."""
    return _DEFAULT_PRIVILEGE[stage]


def edge_impact_score(edge: EscalationEdge) -> float:
    """Per-hop impact score: impact delta weighted by privilege delta."""
    return edge.impact_delta * (1.0 + edge.privilege_delta)


@dataclass(frozen=True)
class EscalationNode:
    """One node in an escalation graph."""

    id: str
    stage: EscalationStage
    privilege: float = 0.0
    impact: float = 0.0
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _required_text(self.id, "node id"))
        object.__setattr__(self, "stage", parse_stage(self.stage))
        object.__setattr__(
            self,
            "privilege",
            _clamped(self.privilege, "node privilege", 0.0, MAX_PRIVILEGE_LEVEL),
        )
        object.__setattr__(
            self, "impact", _clamped(self.impact, "node impact", 0.0, MAX_NODE_IMPACT)
        )
        object.__setattr__(self, "name", _optional_text(self.name, "node name"))


@dataclass(frozen=True)
class EscalationEdge:
    """One directed escalation hop."""

    source: str
    target: str
    relation: str = "escalates"
    privilege_delta: float = 0.0
    impact_delta: float = 0.0
    cost: float = 0.0
    reliability: float = 1.0
    join_count: int = 0
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _required_text(self.source, "edge source"))
        object.__setattr__(self, "target", _required_text(self.target, "edge target"))
        object.__setattr__(self, "relation", _required_text(self.relation, "edge relation"))
        object.__setattr__(
            self,
            "privilege_delta",
            _clamped(self.privilege_delta, "edge privilege_delta", 0.0, MAX_PRIVILEGE_LEVEL),
        )
        object.__setattr__(
            self,
            "impact_delta",
            _clamped(self.impact_delta, "edge impact_delta", 0.0, MAX_EDGE_IMPACT),
        )
        object.__setattr__(self, "cost", _clamped(self.cost, "edge cost", 0.0, MAX_EDGE_COST))
        object.__setattr__(
            self,
            "reliability",
            _clamped(self.reliability, "edge reliability", 0.0, 1.0),
        )
        object.__setattr__(self, "join_count", _nonnegative_int(self.join_count))
        object.__setattr__(self, "evidence", _evidence_tuple(self.evidence))

    @property
    def key(self) -> EdgeKey:
        return (self.source, self.target, self.relation)

    def impact_score(self) -> float:
        return edge_impact_score(self)


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail("join_count must be int")
    return max(0, value)


def _evidence_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items: tuple[object, ...] = (value,)
    elif isinstance(value, (list, tuple)):
        items = tuple(value)
    else:
        raise FormatFail("evidence must be a string or sequence of strings")
    cleaned: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise FormatFail("evidence items must be str")
        text = item.strip()
        if text:
            cleaned.add(text)
    return tuple(sorted(cleaned)[:MAX_EVIDENCE_ITEMS])


@dataclass(frozen=True)
class EscalationPath:
    """A simple directed escalation path and its deterministic scores."""

    nodes: tuple[str, ...]
    edges: tuple[EscalationEdge, ...]
    privilege_gain: float
    impact_gain: float
    impact_score: float
    reliability: float
    cost: float
    stage_progress: int = 0

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        if not nodes or not all(isinstance(node, str) and node for node in nodes):
            raise FormatFail("path nodes must be non-empty strings")
        if not all(isinstance(edge, EscalationEdge) for edge in edges):
            raise FormatFail("path edges must be EscalationEdge values")
        if len(set(nodes)) != len(nodes):
            raise FormatFail("path nodes must be unique")
        if len(edges) != len(nodes) - 1:
            raise FormatFail("path edge count must be node count minus one")
        for index, edge in enumerate(edges):
            if edge.source != nodes[index] or edge.target != nodes[index + 1]:
                raise FormatFail("path edges must connect consecutive nodes")
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(
            self,
            "privilege_gain",
            _clamped(self.privilege_gain, "path privilege_gain", 0.0, MAX_PRIVILEGE_LEVEL * 32),
        )
        object.__setattr__(
            self, "impact_gain", _clamped(self.impact_gain, "path impact_gain", 0.0, 32.0)
        )
        object.__setattr__(
            self, "impact_score", _clamped(self.impact_score, "path impact_score", 0.0, 192.0)
        )
        object.__setattr__(
            self, "reliability", _clamped(self.reliability, "path reliability", 0.0, 1.0)
        )
        object.__setattr__(self, "cost", _clamped(self.cost, "path cost", 0.0, MAX_EDGE_COST * 32))
        if isinstance(self.stage_progress, bool) or not isinstance(self.stage_progress, int):
            raise FormatFail("stage_progress must be int")

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
    def edge_keys(self) -> tuple[EdgeKey, ...]:
        return tuple(edge.key for edge in self.edges)

    @property
    def rank_key(self) -> RankKey:
        return (
            -self.impact_score,
            -self.privilege_gain,
            -self.reliability,
            -self.stage_progress,
            self.cost,
            self.hop_count,
            self.nodes,
            self.edge_keys,
        )

    def dedup_material(self) -> str:
        return json.dumps(
            {"nodes": list(self.nodes), "edges": [list(key) for key in self.edge_keys]},
            sort_keys=True,
            separators=(",", ":"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hop_count": self.hop_count,
            "nodes": list(self.nodes),
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation,
                    "privilege_delta": _round(edge.privilege_delta),
                    "impact_delta": _round(edge.impact_delta),
                    "impact_score": _round(edge.impact_score()),
                    "cost": _round(edge.cost),
                    "reliability": _round(edge.reliability),
                    "join_count": edge.join_count,
                    "evidence": list(edge.evidence),
                }
                for edge in self.edges
            ],
            "privilege_gain": _round(self.privilege_gain),
            "impact_gain": _round(self.impact_gain),
            "impact_score": _round(self.impact_score),
            "reliability": _round(self.reliability),
            "cost": _round(self.cost),
            "stage_progress": self.stage_progress,
        }


def _round(value: float) -> float:
    return round(value, 9)


__all__ = [
    "DEFAULT_REACH_DECAY",
    "EdgeKey",
    "EscalationEdge",
    "EscalationNode",
    "EscalationPath",
    "EscalationStage",
    "MAX_EDGE_COST",
    "MAX_EDGE_IMPACT",
    "MAX_GRAPH_EDGES",
    "MAX_GRAPH_NODES",
    "MAX_NODE_IMPACT",
    "MAX_PATH_HOPS",
    "MAX_PRIVILEGE_LEVEL",
    "RankKey",
    "SURFACE_WEIGHT_NORM",
    "default_privilege",
    "edge_impact_score",
    "parse_stage",
    "stage_for_name",
]
