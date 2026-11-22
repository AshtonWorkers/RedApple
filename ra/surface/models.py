"""Pure models for attack-surface expansion and prioritization (RA-SFC).

No I/O lives here: every function is synchronous and deterministic
(RA-REP-003). Ranking is a total order whose sort key ends in ``id`` (I5).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any

from ..srf.models import ReachRecord, compute_weight, reach_from_json


class SurfaceTier(StrEnum):
    """Priority tier for a ranked attack-surface target.

    Distinct from ``device_profile.tier`` (hardware class A/B/C); this is the
    exploitation-priority band assigned by :func:`ra.surface.rank.rank_targets`.
    """

    S = "S"
    A = "A"
    B = "B"
    C = "C"


class Capability(StrEnum):
    """SBPL operation families that make a target worth attacking."""

    NETWORK_INBOUND = "network-inbound"
    NETWORK_OUTBOUND = "network-outbound"
    NETWORK_BIND = "network-bind"
    FILE_WRITE = "file-write"
    IOKIT = "iokit-open"
    MACH_PRIV = "mach-priv"
    SYSCTL_WRITE = "sysctl-write"
    NVRAM = "nvram"
    KEYCHAIN = "keychain"
    PROCESS_EXEC = "process-exec"
    XPC_MESSAGE = "xpc-message"


class IngressClass(StrEnum):
    """How reachable a target is from an attacker-controlled context."""

    ZERO_CLICK = "zero-click"
    NETWORK = "network"
    LOCAL = "local"
    UNKNOWN = "unknown"


CAPABILITY_RISK: dict[Capability, float] = {
    Capability.NETWORK_INBOUND: 3.0,
    Capability.MACH_PRIV: 3.0,
    Capability.FILE_WRITE: 2.5,
    Capability.IOKIT: 2.5,
    Capability.PROCESS_EXEC: 2.0,
    Capability.SYSCTL_WRITE: 2.0,
    Capability.NVRAM: 1.5,
    Capability.KEYCHAIN: 1.5,
    Capability.NETWORK_BIND: 1.5,
    Capability.NETWORK_OUTBOUND: 1.0,
    Capability.XPC_MESSAGE: 0.5,
}
CAPABILITY_RISK_TOTAL = sum(CAPABILITY_RISK.values())

XPC_RISKY_TYPES = frozenset({"endpoint", "data", "uuid", "int64", "uint64"})


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic content id: ``<prefix>_<sha256[:24]>``."""
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


@dataclass(frozen=True)
class ExpandedTarget:
    """One unranked attack-surface target produced by expansion (RA-SFC-001..003)."""

    ring_node: str
    name: str
    reach_from: tuple[ReachRecord, ...]
    base_weight: float
    privilege_delta: int
    parser_complexity: float
    capabilities: frozenset[Capability] = field(default_factory=frozenset)
    xpc_risky_fields: int = 0
    image_paths: tuple[str, ...] = ()
    entry_point_id: str = ""

    @property
    def id(self) -> str:
        return stable_id("surf", self.ring_node, self.name)

    @property
    def hops(self) -> int:
        return max(1, min((r.hops for r in self.reach_from), default=1))


@dataclass(frozen=True)
class SurfaceTarget:
    """One ranked attack-surface target (RA-SFC-004)."""

    ring_node: str
    name: str
    id: str
    weight: float
    base_weight: float
    tier: SurfaceTier
    rank: int
    privilege_delta: int
    parser_complexity: float
    hops: int
    capabilities: tuple[Capability, ...]
    xpc_risky_fields: int
    ingress: IngressClass
    rationale: str
    entry_point_id: str
    reach_from: tuple[ReachRecord, ...]

    def to_row(self) -> dict[str, Any]:
        """Ledger ``entry_point`` row; ``weight`` is the priority score."""
        return {
            "id": self.id,
            "name": self.name,
            "reach_from_json": reach_from_json(self.reach_from),
            "privilege_delta": self.privilege_delta,
            "parser_complexity": self.parser_complexity,
            "weight": self.weight,
            "ring_node": self.ring_node,
        }

    def to_dict(self) -> dict[str, Any]:
        """Full JSON-able view for feeds and work-order payloads."""
        return {
            "id": self.id,
            "name": self.name,
            "ring_node": self.ring_node,
            "weight": self.weight,
            "base_weight": self.base_weight,
            "tier": self.tier.value,
            "rank": self.rank,
            "privilege_delta": self.privilege_delta,
            "parser_complexity": self.parser_complexity,
            "hops": self.hops,
            "capabilities": sorted(c.value for c in self.capabilities),
            "xpc_risky_fields": self.xpc_risky_fields,
            "ingress": self.ingress.value,
            "rationale": self.rationale,
            "entry_point_id": self.entry_point_id,
            "reach_from": [r.as_dict() for r in self.reach_from],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SurfaceTarget:
        """Rebuild a target from :meth:`to_dict` output."""
        caps = tuple(Capability(c) for c in data["capabilities"])
        reach = tuple(
            ReachRecord(
                source=str(item["source"]),
                hops=int(item["hops"]),
                via=str(item.get("via", "")),
            )
            for item in data["reach_from"]
        )
        return cls(
            ring_node=str(data["ring_node"]),
            name=str(data["name"]),
            id=str(data["id"]),
            weight=float(data["weight"]),
            base_weight=float(data["base_weight"]),
            tier=SurfaceTier(str(data["tier"])),
            rank=int(data["rank"]),
            privilege_delta=int(data["privilege_delta"]),
            parser_complexity=float(data["parser_complexity"]),
            hops=int(data["hops"]),
            capabilities=caps,
            xpc_risky_fields=int(data["xpc_risky_fields"]),
            ingress=IngressClass(str(data["ingress"])),
            rationale=str(data["rationale"]),
            entry_point_id=str(data["entry_point_id"]),
            reach_from=reach,
        )


@dataclass(frozen=True)
class TargetList:
    """Deterministic ranked target list for one ring node (RA-SFC-005)."""

    ring_node: str
    targets: tuple[SurfaceTarget, ...]
    sha256: str

    @property
    def rows(self) -> tuple[dict[str, Any], ...]:
        return tuple(t.to_row() for t in self.targets)

    def tier_counts(self) -> dict[str, int]:
        counts = {tier.value: 0 for tier in SurfaceTier}
        for target in self.targets:
            counts[target.tier.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "ring_node": self.ring_node,
            "sha256": self.sha256,
            "count": len(self.targets),
            "tiers": self.tier_counts(),
            "targets": [t.to_dict() for t in self.targets],
        }


def canonical_sha256(rows: Iterable[Mapping[str, Any]]) -> str:
    """Content hash of canonical row JSON (mirrors the compiler's digest)."""
    payload = json.dumps(list(rows), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def with_rank(target: SurfaceTarget, rank: int) -> SurfaceTarget:
    return replace(target, rank=rank)


def base_weight_for(delta: int, complexity: float, hops: int) -> float:
    """Compiler-consistent base weight ``(1+delta)*complexity*0.7**hops``."""
    return compute_weight(delta, complexity, hops)


def safe_float(value: object, default: float = 0.0) -> float:
    """Tolerant float parse; non-finite or malformed input yields ``default``."""
    try:
        out = float(str(value))
    except (TypeError, ValueError):
        return default
    return out if math.isfinite(out) else default


def clamp_parser_complexity(value: object) -> float:
    """Clamp parser complexity into the compiler's ``[0, 1]`` range."""
    return min(1.0, max(0.0, safe_float(value)))


def safe_int(value: object, default: int = 0) -> int:
    """Tolerant int parse; malformed input yields ``default``."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def parse_reach_records(raw: object) -> tuple[ReachRecord, ...]:
    """Tolerantly parse ``reach_from_json`` into reach records.

    Malformed input yields an empty tuple rather than raising, so a corrupt
    row degrades to a low-information target instead of killing the pipeline.
    """
    if not isinstance(raw, str) or not raw:
        return ()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return ()
    if not isinstance(data, list):
        return ()
    records: list[ReachRecord] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        hops = item.get("hops")
        if not isinstance(source, str) or not isinstance(hops, int) or isinstance(hops, bool):
            continue
        via = item.get("via", "")
        records.append(ReachRecord(source=source, hops=hops, via=str(via)))
    return tuple(records)


def row_image_paths(reach: Sequence[ReachRecord]) -> tuple[str, ...]:
    """Image paths referenced by ``image:<path>`` reach records."""
    paths = {r.source[len("image:") :] for r in reach if r.source.startswith("image:")}
    return tuple(sorted(paths))
