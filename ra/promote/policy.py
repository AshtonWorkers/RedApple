"""Ledger-backed policy port for the promotion gate."""

from __future__ import annotations

from ..ledger import Ledger
from ..ledger.ids import sha256_hex
from ..policy.actions import ACTION_COST_USD_MICRO, Action, parse_action
from ..policy.ranking import ev_score
from .models import PolicyAuthorization, PolicyRequest, RemedyRequest, RemedyResult, json_bytes

DEFAULT_SPEND_CAP_USD_MICRO = 40_000_000


class LedgerPolicyGate:
    """Policy port that checks caps and enqueues remedies through the ledger."""

    def __init__(self, ledger: Ledger, *, spend_cap_usd_micro: int = DEFAULT_SPEND_CAP_USD_MICRO) -> None:
        if spend_cap_usd_micro < 0:
            raise ValueError("spend_cap_usd_micro must be >= 0")
        self.ledger = ledger
        self.spend_cap_usd_micro = spend_cap_usd_micro

    async def authorize_promotion(self, request: PolicyRequest) -> PolicyAuthorization:
        """Check the promotion side effect against the spend cap before it happens."""
        spent = self.ledger.spent_usd_micro(request.run_id)
        required = request.estimated_cost_usd_micro
        allowed = spent + required <= self.spend_cap_usd_micro
        decision_id = await self.ledger.record_decision(
            trigger_metric="promotion_gate",
            observed=request.dupe_score,
            expected="promote" if allowed else "budget_gate",
            spent_usd_micro=0,
            run_id=request.run_id,
        )
        reason = "ok" if allowed else "BUDGET_GATE"
        return PolicyAuthorization(
            allowed=allowed,
            reason=reason,
            spent_usd_micro=spent,
            decision_id=decision_id,
        )

    async def plan_remedy(self, request: RemedyRequest) -> RemedyResult:
        """Enqueue one deterministic, idempotent policy work order."""
        action = parse_action(request.action)
        cost = ACTION_COST_USD_MICRO[action]
        ev = ev_score(request.probability_join, request.chain_bonus, request.ingress_weight, cost)
        work_order_id = self._work_order_id(request, action)
        existing = self.ledger.get_work_order(work_order_id)
        if existing is not None:
            return RemedyResult(
                work_order_id=work_order_id,
                action=action.value,
                state=str(existing["state"]),
                reason="existing",
            )
        payload = json_bytes(
            {
                "stage": request.stage.value,
                "reason": request.reason,
                "action": action.value,
                "attempt": request.attempt,
                "probability_join": request.probability_join,
                "chain_bonus": request.chain_bonus,
                "ingress_weight": request.ingress_weight,
                "cost_usd_micro": cost,
                "case_metadata": dict(request.metadata),
            }
        )
        await self.ledger.enqueue_work_order(
            work_order_id=work_order_id,
            action=action.value,
            unit=request.claim_id,
            ev_cost=max(ev, 0.0),
            state="ready",
            run_id=request.run_id,
            payload_json=payload.decode("utf-8"),
        )
        await self.ledger.record_decision(
            trigger_metric="promotion_gate",
            observed=ev,
            expected=action.value,
            spent_usd_micro=0,
            run_id=request.run_id,
            wo_id=work_order_id,
        )
        return RemedyResult(work_order_id=work_order_id, action=action.value)

    @staticmethod
    def _work_order_id(request: RemedyRequest, action: Action) -> str:
        material = "|".join(
            [
                "promote",
                request.claim_id,
                request.stage.value,
                action.value,
                str(request.attempt),
                request.reason,
            ]
        )
        return "wo_" + sha256_hex(material.encode("utf-8"))[:26]
