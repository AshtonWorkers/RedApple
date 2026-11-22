"""Ledger-backed promotion gate and escalation sink for reviewer."""

from __future__ import annotations

import json

from ra.errors import FormatFail
from ra.ledger import ClaimState, Ledger
from ra.policy.actions import ACTION_COST_USD_MICRO, Action

from .models import ReviewDecision


class LedgerPromotionGate:
    """Promote agreed candidates through bound -> reviewed -> promoted."""

    def __init__(self, ledger: Ledger):
        self._ledger = ledger

    async def promote(self, claim_id: str, *, review_claim_id: str) -> None:
        row = self._ledger.get_claim(claim_id)
        if row is None:
            raise FormatFail(f"unknown claim: {claim_id}")
        state = str(row["state"])
        if state == ClaimState.PROMOTED.value:
            return
        if state == ClaimState.BOUND.value:
            await self._ledger.transition_claim(claim_id, ClaimState.REVIEWED)
            state = ClaimState.REVIEWED.value
        if state != ClaimState.REVIEWED.value:
            raise FormatFail(f"claim {claim_id} cannot be promoted from {state}")
        await self._ledger.transition_claim(claim_id, ClaimState.PROMOTED)
        _ = review_claim_id


class LedgerEscalationSink:
    """Enqueue larger-model escalation work orders in the claim ledger."""

    def __init__(self, ledger: Ledger):
        self._ledger = ledger

    async def escalate(
        self,
        claim_id: str,
        review_claim_id: str,
        decision: ReviewDecision,
        *,
        run_id: str | None = None,
    ) -> str:
        payload = {
            "claim_id": claim_id,
            "review_claim_id": review_claim_id,
            "status": decision.status,
            "bug_class": decision.bug_class,
            "primitive": decision.primitive,
            "candidate_bug_class": decision.candidate_bug_class,
            "candidate_primitive": decision.candidate_primitive,
            "reasons": list(decision.reasons),
        }
        cost = ACTION_COST_USD_MICRO[Action.ESCALATE_MODEL] / 1_000_000
        return await self._ledger.enqueue_work_order(
            action=Action.ESCALATE_MODEL.value,
            unit=f"review:{claim_id}",
            ev_cost=max(cost, 0.000001),
            state="ready",
            run_id=run_id,
            payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )


class LedgerRequeueSink:
    """Enqueue retarget work for claims that cannot be reviewed yet."""

    def __init__(self, ledger: Ledger):
        self._ledger = ledger

    async def requeue(
        self,
        claim_id: str,
        review_claim_id: str,
        decision: ReviewDecision,
        *,
        run_id: str | None = None,
    ) -> str:
        payload = {
            "claim_id": claim_id,
            "review_claim_id": review_claim_id,
            "status": decision.status,
            "reasons": list(decision.reasons),
        }
        cost = ACTION_COST_USD_MICRO[Action.RETARGET] / 1_000_000
        return await self._ledger.enqueue_work_order(
            action=Action.RETARGET.value,
            unit=f"claim:{claim_id}",
            ev_cost=max(cost, 0.000001),
            state="ready",
            run_id=run_id,
            payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
