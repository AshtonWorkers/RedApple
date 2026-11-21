"""Policy EV ranking and shedding (RA-POL-002, RA-POL-006, I5)."""

from __future__ import annotations

from dataclasses import dataclass


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


def ev_score(
    probability_join: float, chain_bonus: float, ingress_weight: float, cost_usd_micro: int
) -> float:
    """EV = (P(join) * chain_bonus * ingress_weight) / cost."""
    if cost_usd_micro <= 0:
        return probability_join * chain_bonus * ingress_weight
    return (probability_join * chain_bonus * ingress_weight) / cost_usd_micro


def sort_key(candidate: WorkOrderCandidate) -> tuple[float, int, str]:
    """Total order: EV desc, created asc, id asc (I5)."""
    return (-candidate.ev_cost, candidate.created, candidate.id)


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
