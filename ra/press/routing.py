"""PRESS routing, budgets, and planning costs (Appendix D)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TaskType(StrEnum):
    """PRESS task types."""

    DEDUP_MATCH = "dedup_match"
    BUG_CLASS = "bug_class"
    RUNG_SELECT = "rung_select"
    GROOM_FILL = "groom_fill"
    HARNESS_SYNTH = "harness_synth"
    GADGET_RANK = "gadget_rank"
    CHAIN_STRATEGY = "chain_strategy"
    REPORT_TEXT = "report_text"


@dataclass(frozen=True)
class RouteSpec:
    """One Appendix D routing row."""

    max_bytes: int
    grammar: str
    temperature: float
    samples: int
    max_hops: int
    escalate: str


ROUTING: dict[TaskType, RouteSpec] = {
    TaskType.DEDUP_MATCH: RouteSpec(3_000, "enum", 0.0, 1, 0, "sim 0.55-0.75"),
    TaskType.BUG_CLASS: RouteSpec(6_000, "enum", 0.0, 3, 2, "disagreement"),
    TaskType.RUNG_SELECT: RouteSpec(5_000, "enum", 0.0, 3, 2, "disagreement"),
    TaskType.GROOM_FILL: RouteSpec(6_000, "numeric", 0.1, 1, 2, "heap-diff fail"),
    TaskType.HARNESS_SYNTH: RouteSpec(12_000, "code", 0.6, 1, 2, "2 compile fails"),
    TaskType.GADGET_RANK: RouteSpec(9_000, "ranked", 0.2, 1, 1, "always"),
    TaskType.CHAIN_STRATEGY: RouteSpec(10_000, "path", 0.4, 1, 1, "always"),
    TaskType.REPORT_TEXT: RouteSpec(16_000, "prose", 0.7, 1, 0, "never"),
}


@dataclass(frozen=True)
class Caps:
    """Nightly caps from Appendix D; money is integer micro-USD."""

    spend_usd_micro: int = 40_000_000
    cas_bytes: int = 60 * 1024 * 1024 * 1024
    corpus_max: int = 250_000
    crashes_per_device: int = 400
    escalations: int = 120


ACTION_COST_USD_MICRO: dict[str, int] = {
    "retarget": 20_000,
    "reweight": 10_000,
    "spawn_subfactory": 300_000,
    "widen_dialect": 50_000,
    "force_groom": 20_000,
    "try_gadget_set": 120_000,
    "escalate_model": 400_000,
    "demote": 0,
    "park": 0,
}

ACTIONS = frozenset(ACTION_COST_USD_MICRO)


def route_for(task_type: TaskType) -> RouteSpec:
    """Return the Appendix D route for a task type."""
    return ROUTING[task_type]


def action_cost_usd_micro(action: str) -> int:
    """Planning cost for a policy action in integer micro-USD."""
    return ACTION_COST_USD_MICRO[action]
