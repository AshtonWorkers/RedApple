"""Policy engine skeleton (RA-POL)."""

from __future__ import annotations

import asyncio
import json
import math
from dataclasses import dataclass
from typing import Any

from ..errors import FormatFail
from ..ledger import Ledger
from .actions import ACTION_COST_USD_MICRO, Action, parse_action
from .ranking import WorkOrderCandidate, rank, shed


@dataclass(frozen=True)
class ExecutorCaps:
    """Hard caps checked before any side effect (I8)."""

    spend_usd_micro: int
    cas_bytes: int = 60 * 1024 * 1024 * 1024
    corpus_max: int = 250_000
    crashes_per_device: int = 400
    escalations: int = 120


class Executor:
    """Cap gate for policy actions."""

    def __init__(self, caps: ExecutorCaps, *, spent_usd_micro: int = 0) -> None:
        self.caps = caps
        self.spent_usd_micro = spent_usd_micro
        self.corpus_rows = 0
        self.crashes = 0
        self.escalations = 0

    def admits(self, action: Action) -> bool:
        """Return whether an action may execute under caps."""
        cost = ACTION_COST_USD_MICRO[action]
        if self.spent_usd_micro + cost > self.caps.spend_usd_micro:
            return False
        if action is Action.SPAWN_SUBFACTORY and self.corpus_rows >= self.caps.corpus_max:
            return False
        return not (action is Action.ESCALATE_MODEL and self.escalations >= self.caps.escalations)

    def record_spend(self, action: Action) -> int:
        """Record integer micro-USD spend for an admitted action."""
        cost = ACTION_COST_USD_MICRO[action]
        self.spent_usd_micro += cost
        if action is Action.ESCALATE_MODEL:
            self.escalations += 1
        return cost


class PolicyEngine:
    """Skeleton policy engine: plan, rank, gate, dispatch."""

    def __init__(self, ledger: Ledger, caps: ExecutorCaps) -> None:
        self.ledger = ledger
        self.caps = caps
        self.executor = Executor(caps)
        self._failures: dict[str, int] = {}

    @staticmethod
    def _validate_plan_inputs(
        probability_join: float, chain_bonus: float, ingress_weight: float
    ) -> None:
        if (
            isinstance(probability_join, bool)
            or not isinstance(probability_join, (int, float))
            or not math.isfinite(probability_join)
            or not 0.0 <= probability_join <= 1.0
        ):
            raise FormatFail("probability_join must be a finite number in [0,1]")
        for name, value in (("chain_bonus", chain_bonus), ("ingress_weight", ingress_weight)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise FormatFail(f"{name} must be a finite non-negative number")

    async def plan_action(
        self,
        action: str,
        unit: str,
        *,
        probability_join: float,
        chain_bonus: float = 1.0,
        ingress_weight: float = 1.0,
        run_id: str | None = None,
        trigger_metric: str = "policy",
        observed: float = 0.0,
        expected: str = "",
    ) -> str:
        """Validate, EV-rank, and enqueue one work order."""
        parsed = parse_action(action)
        if self._failures.get(unit, 0) >= 3 and parsed is not Action.PARK:
            parsed = Action.PARK
        self._validate_plan_inputs(probability_join, chain_bonus, ingress_weight)
        cost = ACTION_COST_USD_MICRO[parsed]
        ev = (
            (probability_join * chain_bonus * ingress_weight) / cost
            if cost > 0
            else probability_join * chain_bonus * ingress_weight
        )
        if not math.isfinite(ev) or ev <= 0:
            raise FormatFail("work_order ev_cost must be > 0")
        payload = json.dumps(
            {
                "probability_join": probability_join,
                "chain_bonus": chain_bonus,
                "ingress_weight": ingress_weight,
                "cost_usd_micro": cost,
            },
            sort_keys=True,
        )
        wo_id = await self.ledger.enqueue_work_order(
            action=parsed.value,
            unit=unit,
            ev_cost=ev,
            state="ready",
            run_id=run_id,
            payload_json=payload,
        )
        return wo_id

    async def dispatch_ready(self, *, limit: int = 64) -> tuple[int, list[str]]:
        """Dispatch ready work orders through the atomic executor cap gate."""
        rows = self.ledger.ready_work_orders(limit=limit)
        actions = [parse_action(str(row["action"])) for row in rows]
        outcomes = await asyncio.gather(
            *(
                self.ledger.dispatch_work_order(
                    work_order_id=str(row["id"]),
                    budget_usd_micro=self.caps.spend_usd_micro,
                    spent_usd_micro=ACTION_COST_USD_MICRO[action],
                    observed=float(row["ev_cost"]),
                    expected=action.value,
                )
                for row, action in zip(rows, actions, strict=True)
            )
        )
        dispatched = 0
        refusals: list[str] = []
        for row, outcome in zip(rows, outcomes, strict=True):
            if outcome.get("dispatched") is True:
                dispatched += 1
            else:
                refusals.append(str(row["id"]))
        return dispatched, refusals

    async def record_failure(self, unit: str) -> int:
        """Count a failed remedy; three failures park the unit (I7)."""
        count = self._failures.get(unit, 0) + 1
        self._failures[unit] = count
        if count >= 3:
            await self.park_unit(unit, reason="TRIPLE_FAILURE")
        return count

    async def park_unit(self, unit: str, *, reason: str = "PARKED") -> int:
        """Park every ready work order for a unit."""
        parked = 0
        for row in self.ledger.work_orders_for_unit(unit):
            if str(row["state"]) == "ready":
                payload = json.dumps({"park_reason": reason}, sort_keys=True)
                await self.ledger.update_work_order_state(
                    str(row["id"]), "parked", payload_json=payload
                )
                parked += 1
        return parked

    def rank_candidates(self, candidates: list[WorkOrderCandidate]) -> list[WorkOrderCandidate]:
        """Rank work-order candidates."""
        return rank(candidates)

    def shed_candidates(
        self, candidates: list[WorkOrderCandidate], *, backlog_limit: int = 5000
    ) -> tuple[list[WorkOrderCandidate], list[WorkOrderCandidate]]:
        """Apply RA-POL-006 shedding."""
        return shed(candidates, backlog_limit=backlog_limit)


def cast_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def candidates_from_rows(rows: list[dict[str, Any]]) -> list[WorkOrderCandidate]:
    """Convert ledger rows to rankable candidates."""
    out: list[WorkOrderCandidate] = []
    for row in rows:
        out.append(
            WorkOrderCandidate(
                id=str(row["id"]),
                action=str(row["action"]),
                unit=str(row["unit"]),
                ev_cost=float(row["ev_cost"]),
                created=int(row["created"]),
                state=str(row["state"]),
                join_live=False,
            )
        )
    return out


__all__ = ["Executor", "ExecutorCaps", "PolicyEngine", "candidates_from_rows"]
