"""Pure models and deterministic scoring for the Surface Graph compiler.

No I/O lives here (RA-REP-003): every function is synchronous and import-free of
async or filesystem state.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Iterable

REACH_DECAY = 0.7
MAX_PRIVILEGE_DELTA = 5
PARSER_COMPLEXITY_NORM = 256.0

PrivilegeDelta = int
ParserComplexity = float
Weight = float


@dataclass(frozen=True)
class ReachRecord:
    """One deterministic path by which a node is reachable."""

    source: str
    hops: int
    via: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "hops": self.hops, "via": self.via}


@dataclass(frozen=True)
class EntryPoint:
    """RA-SRF-002 row: one ranked surface entry point."""

    ring_node: str
    name: str
    format_spec: str
    reach_from: tuple[ReachRecord, ...]
    privilege_delta: PrivilegeDelta
    parser_complexity: ParserComplexity

    @property
    def id(self) -> str:
        reach_json = reach_from_json(self.reach_from)
        digest = hashlib.sha256(
            "\0".join(
                [
                    self.ring_node,
                    self.name,
                    self.format_spec,
                    reach_json,
                    str(self.privilege_delta),
                    f"{self.parser_complexity:.6f}",
                ]
            ).encode("utf-8")
        ).hexdigest()[:24]
        return f"ep_{digest}"

    @property
    def hops(self) -> int:
        return min((r.hops for r in self.reach_from), default=3)

    @property
    def weight(self) -> Weight:
        return compute_weight(self.privilege_delta, self.parser_complexity, self.hops)

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "reach_from_json": reach_from_json(self.reach_from),
            "privilege_delta": self.privilege_delta,
            "parser_complexity": self.parser_complexity,
            "weight": self.weight,
            "ring_node": self.ring_node,
        }


def reach_from_json(records: Iterable[ReachRecord]) -> str:
    items = sorted(
        (r.as_dict() for r in records),
        key=lambda d: (int(d["hops"]), str(d["source"]), str(d["via"])),
    )
    return json.dumps(items, sort_keys=True, separators=(",", ":"))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parser_complexity(format_spec: str, field_count: int) -> ParserComplexity:
    """Entropy(format spec) x field count, normalized to [0, 1]."""
    if field_count <= 0:
        return 0.0
    value = shannon_entropy(format_spec) * field_count / PARSER_COMPLEXITY_NORM
    return round(min(1.0, max(0.0, value)), 6)


def compute_weight(privilege_delta: int, complexity: float, hops: int) -> Weight:
    delta = max(0, min(MAX_PRIVILEGE_DELTA, int(privilege_delta)))
    c = max(0.0, min(1.0, float(complexity)))
    h = max(1, int(hops))
    return (1 + delta) * c * (REACH_DECAY**h)


def clamp_privilege_delta(value: int) -> PrivilegeDelta:
    return max(0, min(MAX_PRIVILEGE_DELTA, int(value)))


def sort_entry_points(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """RA-SRF-005: deterministic output order."""
    return sorted(rows, key=lambda r: (-float(r["weight"]), str(r["id"])))


@dataclass(frozen=True)
class XPCField:
    name: str
    type: str


@dataclass(frozen=True)
class XPCShape:
    image_path: str
    fields: tuple[XPCField, ...]

    @property
    def format_spec(self) -> str:
        return xpc_format_spec(self.fields)

    @property
    def field_count(self) -> int:
        return max(1, len(self.fields))

    @property
    def parser_complexity(self) -> ParserComplexity:
        return parser_complexity(self.format_spec, self.field_count)


def xpc_format_spec(fields: Iterable[XPCField]) -> str:
    parts = sorted(f"{f.name}:{f.type}" for f in fields)
    return "xpc-dictionary[" + ",".join(parts) + "]"
