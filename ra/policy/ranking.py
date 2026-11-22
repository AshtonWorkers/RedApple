"""Policy EV ranking and shedding (RA-POL-002, RA-POL-006, I5)."""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..errors import FormatFail
from .actions import parse_action
from .models import SQLITE_INT_MAX

WORK_ORDER_STATES = frozenset({"ready", "parked", "done", "failed", "shed", "dialect_defect"})


@dataclass(frozen=True)
class WorkOrderCandidate:
    """Rankable work-order view."""

    id: str
    action: str
    unit: str
    ev_cost: float
    created: int
    state: str = "ready"
    join_live: bool = False
    cas_bytes: int = 0
    lane_id: str | None = None
    requires_lane: bool = False

    def __post_init__(self) -> None:
        """Reject malformed candidates before ranking or shedding."""
        if not isinstance(self.id, str) or not self.id:
            raise FormatFail("work_order id must be a non-empty string")
        if not isinstance(self.unit, str) or not self.unit:
            raise FormatFail("work_order unit must be a non-empty string")
        parse_action(self.action)
        if isinstance(self.ev_cost, bool) or not isinstance(self.ev_cost, (int, float)):
            raise FormatFail("work_order ev_cost must be a number")
        if not math.isfinite(float(self.ev_cost)) or float(self.ev_cost) < 0.0:
            raise FormatFail("work_order ev_cost must be finite and >= 0")
        if isinstance(self.created, bool) or not isinstance(self.created, int):
            raise FormatFail("work_order created must be int")
        if self.created < 0:
            raise FormatFail("work_order created must be >= 0")
        if self.state not in WORK_ORDER_STATES:
            raise FormatFail(f"work_order state is invalid: {self.state}")
        if not isinstance(self.join_live, bool):
            raise FormatFail("join_live must be bool")
        if isinstance(self.cas_bytes, bool) or not isinstance(self.cas_bytes, int):
            raise FormatFail("cas_bytes must be int")
        if self.cas_bytes < 0 or self.cas_bytes > SQLITE_INT_MAX:
            raise FormatFail("cas_bytes must be within ledger integer range")
        if self.lane_id is not None and (
            not isinstance(self.lane_id, str) or not self.lane_id
        ):
            raise FormatFail("lane_id must be a non-empty string when set")
        if not isinstance(self.requires_lane, bool):
            raise FormatFail("requires_lane must be bool")


def _finite_nonnegative(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{name} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise FormatFail(f"{name} must be finite and >= 0")
    return number


def ev_score(
    probability_join: float, chain_bonus: float, ingress_weight: float, cost_usd_micro: int
) -> float:
    """EV = (P(join) * chain_bonus * ingress_weight) / cost."""
    probability = _finite_nonnegative("probability_join", probability_join)
    if probability > 1.0:
        raise FormatFail("probability_join must be in [0,1]")
    bonus = _finite_nonnegative("chain_bonus", chain_bonus)
    weight = _finite_nonnegative("ingress_weight", ingress_weight)
    if isinstance(cost_usd_micro, bool) or not isinstance(cost_usd_micro, int):
        raise FormatFail("cost_usd_micro must be int")
    if cost_usd_micro < 0 or cost_usd_micro > SQLITE_INT_MAX:
        raise FormatFail("cost_usd_micro must be within ledger integer range")
    numerator = probability * bonus * weight
    score = numerator if cost_usd_micro == 0 else numerator / cost_usd_micro
    if not math.isfinite(score):
        raise FormatFail("ev_score must be finite")
    return score


def sort_key(candidate: WorkOrderCandidate) -> tuple[float, int, str]:
    """Total order: EV desc, created asc, id asc (I5)."""
    return (-float(candidate.ev_cost), candidate.created, candidate.id)


def rank(candidates: list[WorkOrderCandidate]) -> list[WorkOrderCandidate]:
    """Return candidates in policy order."""
    return sorted(candidates, key=sort_key)


def shed(
    candidates: list[WorkOrderCandidate], *, backlog_limit: int = 5000
) -> tuple[list[WorkOrderCandidate], list[WorkOrderCandidate]]:
    """Drop lowest-EV work first; never drop live-join work (RA-POL-006)."""
    excess = max(0, len(candidates) - backlog_limit)
    if excess == 0:
        return list(candidates), []
    ranked = rank(candidates)
    dropped: list[WorkOrderCandidate] = []
    for candidate in reversed(ranked):
        if len(dropped) >= excess:
            break
        if candidate.join_live:
            continue
        dropped.append(candidate)
    dropped_ids = {candidate.id for candidate in dropped}
    kept = [candidate for candidate in ranked if candidate.id not in dropped_ids]
    return kept, dropped


def _validate_shed_limits(backlog_limit: int, cas_bytes_limit: int | None) -> None:
    if isinstance(backlog_limit, bool) or not isinstance(backlog_limit, int):
        raise FormatFail("backlog_limit must be int")
    if backlog_limit < 0 or backlog_limit > SQLITE_INT_MAX:
        raise FormatFail("backlog_limit must be within ledger integer range")
    if cas_bytes_limit is not None and (
        isinstance(cas_bytes_limit, bool)
        or not isinstance(cas_bytes_limit, int)
        or cas_bytes_limit < 0
        or cas_bytes_limit > SQLITE_INT_MAX
    ):
        raise FormatFail("cas_bytes_limit must be within ledger integer range")


def shed_budget(
    candidates: list[WorkOrderCandidate],
    *,
    backlog_limit: int = 5000,
    cas_bytes_limit: int | None = None,
) -> tuple[list[WorkOrderCandidate], list[WorkOrderCandidate]]:
    """Drop lowest-EV non-live work until count and CAS budgets fit.

    Live-join work is never dropped. When live work alone exceeds a budget the
    engine keeps it and sheds every droppable candidate, matching RA-POL-006.
    """
    _validate_shed_limits(backlog_limit, cas_bytes_limit)
    ranked = rank(candidates)
    remaining_count = len(ranked)
    remaining_cas = sum(candidate.cas_bytes for candidate in ranked)
    droppable = [candidate for candidate in ranked if not candidate.join_live]
    dropped: list[WorkOrderCandidate] = []
    dropped_ids: set[str] = set()
    for candidate in reversed(droppable):
        over_count = remaining_count > backlog_limit
        over_cas = cas_bytes_limit is not None and remaining_cas > cas_bytes_limit
        if not over_count and not over_cas:
            break
        dropped.append(candidate)
        dropped_ids.add(candidate.id)
        remaining_count -= 1
        remaining_cas -= candidate.cas_bytes
    kept = [candidate for candidate in ranked if candidate.id not in dropped_ids]
    return kept, dropped
