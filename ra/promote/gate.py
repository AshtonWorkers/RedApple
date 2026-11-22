"""End-to-end promotion gate over the M0 claim ledger."""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import weakref
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, cast

from ..errors import DuplicateDedup, FormatFail
from ..ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    ClaimState,
    Ledger,
)
from ..ledger.ids import artifact_id as ledger_artifact_id
from ..ledger.ids import dedup_key as ledger_dedup_key
from ..ledger.ids import now_ms, sha256_hex
from ..policy.actions import Action
from .interfaces import (
    DupeOracle,
    GroomEngine,
    LadderEngine,
    PolicyGate,
    Reviewer,
    TriageEngine,
)
from .models import (
    LADDER_RUNGS,
    ArtifactView,
    DupeEvidence,
    DupeResult,
    DupeStatus,
    EvidenceArtifact,
    GroomEvidence,
    GroomResult,
    GroomStatus,
    LadderEvidence,
    LadderResult,
    LadderStatus,
    PolicyRequest,
    PromotionRequest,
    PromotionResult,
    PromotionStage,
    PromotionStatus,
    RemedyRequest,
    RemedyResult,
    ReviewEvidence,
    ReviewResult,
    ReviewStatus,
    ReviewVerdict,
    SubmissionEntry,
    TriageEvidence,
    TriageResult,
    TriageStatus,
    json_bytes,
)
from .policy import LedgerPolicyGate
from .stubs import StubDupe, StubGroom, StubLadder, StubReviewer, StubTriage

_STAGE_CLAIM_TYPES = frozenset({"rung", "groom", "dupe_score"})
_LEDGER_CLAIM_LOCKS: weakref.WeakKeyDictionary[Ledger, dict[str, asyncio.Lock]] = (
    weakref.WeakKeyDictionary()
)


class PromotionGate:
    """Run one crash through triage, proof, review, policy, and promotion."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        triage: TriageEngine | None = None,
        ladder: LadderEngine | None = None,
        groom: GroomEngine | None = None,
        dupe: DupeOracle | None = None,
        reviewer: Reviewer | None = None,
        policy: PolicyGate | None = None,
        max_attempts: int = 3,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.ledger = ledger
        self._triage = triage or StubTriage()
        self._ladder = ladder or StubLadder()
        self._groom = groom or StubGroom()
        self._dupe = dupe or StubDupe()
        self._reviewer = reviewer or StubReviewer()
        self._policy = policy or LedgerPolicyGate(ledger)
        self.max_attempts = max_attempts
        self._claim_locks = _LEDGER_CLAIM_LOCKS.setdefault(self.ledger, {})

    async def evaluate(self, request: PromotionRequest) -> PromotionResult:
        """Evaluate one crash evidence bundle and return its gate disposition."""
        req = request.validated()
        views = req.artifact_views()
        triage = await self._classify_triage(req, views)
        if (
            triage.duplicate_of is not None
            and triage.duplicate_of.strip()
            and triage.status is TriageStatus.CLASSIFIED
        ):
            triage = replace(
                triage,
                status=TriageStatus.DUPLICATE,
                reason=triage.reason or f"duplicate_of:{triage.duplicate_of.strip()}",
            )
        details: dict[str, Any] = {"triage": triage.to_dict()}
        if triage.status is not TriageStatus.CLASSIFIED:
            return await self._handle_triage_pause(req, triage, details)

        bug_class = self._required_text(triage.bug_class, "triage bug_class")
        primitive = self._required_text(triage.primitive, "triage primitive")
        confidence = self._unit_interval(triage.confidence, "triage confidence")
        dedup = triage.dedup_key or self._fallback_dedup(bug_class, primitive, views)
        claim_id = self._claim_id_for_dedup(dedup)
        claim = await self._ensure_main_claim(
            req, triage, bug_class, primitive, confidence, dedup, claim_id
        )
        state = str(claim["state"])
        terminal = {
            "promoted": PromotionStatus.ALREADY_PROMOTED,
            "demoted": PromotionStatus.DEMOTED,
            "parked": PromotionStatus.PARKED,
        }
        if state in terminal:
            submission = self._submission_for(claim_id) if state == "promoted" else None
            return PromotionResult(
                terminal[state],
                f"claim already {state}",
                claim_id=claim_id,
                stage=PromotionStage.PROMOTE if state == "promoted" else None,
                submission=submission,
                details=details,
            )

        unbound = await self._ensure_artifacts(req, claim_id, triage)
        if unbound is not None:
            return unbound
        await self._ensure_state(claim_id, ClaimState.BOUND)

        ladder = await self._climb_ladder(req, claim_id, bug_class, primitive, views)
        details["ladder"] = ladder.to_dict()
        details["ladder_claim_id"] = await self._record_stage_claim(
            "rung", claim_id, req, ladder.to_dict(), ladder.artifact
        )
        if ladder.status in (LadderStatus.RETRY, LadderStatus.UNAVAILABLE):
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.LADDER,
                reason=ladder.reason or ladder.status.value,
                details=details,
            )
        if ladder.status is not LadderStatus.PASSED:
            return await self._terminate_claim(
                req,
                claim_id,
                ClaimState.DEMOTED,
                PromotionStage.LADDER,
                ladder.reason or "LADDER_EXHAUSTED",
                Action.DEMOTE,
                PromotionStatus.DEMOTED,
                details,
            )
        proof_error = self._ladder_proof_error(ladder)
        if proof_error is not None:
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.LADDER,
                reason=proof_error,
                details=details,
            )
        rung = self._required_text(ladder.rung, "ladder rung")
        assertions = ladder.assertions

        groom = await self._validate_groom(req, claim_id, bug_class, primitive, rung, assertions, views)
        details["groom"] = groom.to_dict()
        details["groom_claim_id"] = await self._record_stage_claim(
            "groom", claim_id, req, groom.to_dict(), groom.artifact
        )
        if groom.status in (GroomStatus.RETRY, GroomStatus.UNAVAILABLE):
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.GROOM,
                reason=groom.reason or groom.status.value,
                details=details,
            )
        if groom.status is GroomStatus.INVALID:
            return await self._terminate_claim(
                req,
                claim_id,
                ClaimState.DEMOTED,
                PromotionStage.GROOM,
                groom.reason or "GROOM_INVALID",
                Action.DEMOTE,
                PromotionStatus.DEMOTED,
                details,
            )
        if groom.status is GroomStatus.DEFECT:
            return await self._escalate_claim(
                req,
                claim_id,
                PromotionStage.GROOM,
                groom.reason or "DIALECT_DEFECT",
                Action.FORCE_GROOM,
                details,
            )
        if groom.status is not GroomStatus.VALID:
            raise FormatFail(f"unknown groom status: {groom.status}")
        groom_error = self._groom_validator_error(groom)
        if groom_error is not None:
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.GROOM,
                reason=groom_error,
                details=details,
            )
        groom_validator = self._required_text(groom.validator, "groom validator")

        dupe = await self._score_dupe(req, claim_id, bug_class, primitive, rung, groom_validator, views)
        details["dupe"] = dupe.to_dict()
        details["dupe_claim_id"] = await self._record_stage_claim(
            "dupe_score", claim_id, req, dupe.to_dict(), dupe.artifact
        )
        if dupe.status in (DupeStatus.RETRY, DupeStatus.UNAVAILABLE):
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.DUPE,
                reason=dupe.reason or dupe.status.value,
                details=details,
            )
        if dupe.status is not DupeStatus.SCORED:
            raise FormatFail(f"unknown dupe status: {dupe.status}")
        score_error = self._dupe_score_error(dupe)
        if score_error is not None:
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.DUPE,
                reason=score_error,
                details=details,
            )

        review = await self._review_claim(req, claim_id, views)
        verdict_dict = None if review.verdict is None else review.verdict.to_dict()
        details["review"] = {
            "status": review.status.value,
            "reason": review.reason,
            "verdict": verdict_dict,
        }
        if review.status in (ReviewStatus.RETRY, ReviewStatus.UNAVAILABLE):
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.REVIEWER,
                reason=review.reason or review.status.value,
                details=details,
            )
        if review.status.value != "ok" or review.verdict is None:
            raise FormatFail(f"reviewer returned no verdict: {review.status}")
        self._validate_review_verdict(review.verdict)

        verdict_id, agreed, agreement_reason = await self._record_verdict(
            req, claim_id, review.verdict, bug_class, primitive
        )
        details["verdict_id"] = verdict_id
        details["review_agreement"] = agreement_reason
        if not agreed:
            await self._ensure_state(claim_id, ClaimState.REVIEWED)
            return await self._escalate_claim(
                req,
                claim_id,
                PromotionStage.REVIEWER,
                agreement_reason,
                Action.ESCALATE_MODEL,
                details,
                verdict_id=verdict_id,
            )

        await self._ensure_state(claim_id, ClaimState.REVIEWED)
        authorization = await self._policy.authorize_promotion(
            PolicyRequest(
                claim_id=claim_id,
                dupe_score=dupe.score,
                run_id=req.run_id,
                ingress_weight=req.ingress_weight,
                chain_bonus=req.chain_bonus,
                probability_join=req.probability_join,
                estimated_cost_usd_micro=req.estimated_cost_usd_micro,
                attempt=req.attempt,
            )
        )
        details["policy"] = {
            "allowed": authorization.allowed,
            "reason": authorization.reason,
            "spent_usd_micro": authorization.spent_usd_micro,
            "decision_id": authorization.decision_id,
        }
        if not authorization.allowed:
            return PromotionResult(
                PromotionStatus.BUDGET_GATE,
                authorization.reason,
                claim_id=claim_id,
                stage=PromotionStage.POLICY,
                verdict_id=verdict_id,
                details=details,
            )
        await self._ensure_state(claim_id, ClaimState.REVIEWED)
        transition = await self.ledger.transition_claim(claim_id, ClaimState.PROMOTED)
        submission = self._submission_for(claim_id)
        if not bool(transition.get("changed")):
            row = self.ledger.get_claim(claim_id)
            state = str(row["state"]) if row is not None else ""
            if state == ClaimState.PROMOTED.value:
                return PromotionResult(
                    PromotionStatus.ALREADY_PROMOTED,
                    "claim already promoted",
                    claim_id=claim_id,
                    stage=PromotionStage.PROMOTE,
                    verdict_id=verdict_id,
                    submission=submission,
                    details=details,
                )
            raise FormatFail(f"promotion transition did not change claim state: {state}")
        return PromotionResult(
            PromotionStatus.PROMOTED,
            "promoted",
            claim_id=claim_id,
            stage=PromotionStage.PROMOTE,
            verdict_id=verdict_id,
            submission=submission,
            details=details,
        )

    async def _classify_triage(self, req: PromotionRequest, views: tuple[ArtifactView, ...]) -> TriageResult:
        try:
            result = await self._triage.classify(
                TriageEvidence(
                    case_id=req.case_id,
                    artifacts=views,
                    run_id=req.run_id,
                    attempt=req.attempt,
                    metadata=req.metadata,
                )
            )
        except Exception as exc:
            return TriageResult(
                status=TriageStatus.UNAVAILABLE,
                reason=f"triage_error:{exc.__class__.__name__}",
            )
        if (
            not isinstance(result, TriageResult)
            or not isinstance(result.status, TriageStatus)
            or (result.dedup_key is not None and not isinstance(result.dedup_key, str))
            or (result.duplicate_of is not None and not isinstance(result.duplicate_of, str))
        ):
            return TriageResult(status=TriageStatus.UNAVAILABLE, reason="triage_result_invalid")
        return result

    async def _climb_ladder(
        self,
        req: PromotionRequest,
        claim_id: str,
        bug_class: str,
        primitive: str,
        views: tuple[ArtifactView, ...],
    ) -> LadderResult:
        try:
            result = await self._ladder.climb(
                LadderEvidence(
                    case_id=req.case_id,
                    claim_id=claim_id,
                    bug_class=bug_class,
                    primitive=primitive,
                    artifacts=views,
                    run_id=req.run_id,
                    attempt=req.attempt,
                    metadata=req.metadata,
                )
            )
        except Exception as exc:
            return LadderResult(
                status=LadderStatus.UNAVAILABLE,
                reason=f"ladder_error:{exc.__class__.__name__}",
            )
        if not isinstance(result, LadderResult) or not isinstance(result.status, LadderStatus):
            return LadderResult(status=LadderStatus.UNAVAILABLE, reason="ladder_result_invalid")
        return result

    async def _validate_groom(
        self,
        req: PromotionRequest,
        claim_id: str,
        bug_class: str,
        primitive: str,
        rung: str,
        assertions: tuple[str, ...],
        views: tuple[ArtifactView, ...],
    ) -> GroomResult:
        try:
            result = await self._groom.validate(
                GroomEvidence(
                    case_id=req.case_id,
                    claim_id=claim_id,
                    bug_class=bug_class,
                    primitive=primitive,
                    rung=rung,
                    assertions=assertions,
                    artifacts=views,
                    run_id=req.run_id,
                    attempt=req.attempt,
                    metadata=req.metadata,
                )
            )
        except Exception as exc:
            return GroomResult(
                status=GroomStatus.UNAVAILABLE,
                reason=f"groom_error:{exc.__class__.__name__}",
            )
        if not isinstance(result, GroomResult) or not isinstance(result.status, GroomStatus):
            return GroomResult(status=GroomStatus.UNAVAILABLE, reason="groom_result_invalid")
        return result

    async def _score_dupe(
        self,
        req: PromotionRequest,
        claim_id: str,
        bug_class: str,
        primitive: str,
        rung: str,
        groom_validator: str,
        views: tuple[ArtifactView, ...],
    ) -> DupeResult:
        try:
            result = await self._dupe.score(
                DupeEvidence(
                    case_id=req.case_id,
                    claim_id=claim_id,
                    bug_class=bug_class,
                    primitive=primitive,
                    rung=rung,
                    groom_validator=groom_validator,
                    artifacts=views,
                    run_id=req.run_id,
                    attempt=req.attempt,
                    metadata=req.metadata,
                )
            )
        except Exception as exc:
            return DupeResult(
                status=DupeStatus.UNAVAILABLE,
                reason=f"dupe_error:{exc.__class__.__name__}",
            )
        if not isinstance(result, DupeResult) or not isinstance(result.status, DupeStatus):
            return DupeResult(status=DupeStatus.UNAVAILABLE, reason="dupe_result_invalid")
        return result

    async def _review_claim(
        self, req: PromotionRequest, claim_id: str, views: tuple[ArtifactView, ...]
    ) -> ReviewResult:
        try:
            result = await self._reviewer.review(
                ReviewEvidence(
                    case_id=req.case_id,
                    claim_id=claim_id,
                    artifacts=views,
                    run_id=req.run_id,
                    attempt=req.attempt,
                    metadata=req.metadata,
                )
            )
        except Exception as exc:
            return ReviewResult(
                status=ReviewStatus.UNAVAILABLE,
                reason=f"reviewer_error:{exc.__class__.__name__}",
            )
        if (
            not isinstance(result, ReviewResult)
            or not isinstance(result.status, ReviewStatus)
            or (result.verdict is not None and not isinstance(result.verdict, ReviewVerdict))
        ):
            return ReviewResult(status=ReviewStatus.UNAVAILABLE, reason="reviewer_result_invalid")
        return result

    async def _handle_triage_pause(
        self, req: PromotionRequest, triage: TriageResult, details: dict[str, Any]
    ) -> PromotionResult:
        unit = f"case:{req.case_id}"
        if triage.status is TriageStatus.DUPLICATE:
            await self._record_decision(req, observed=triage.confidence, expected="duplicate")
            return PromotionResult(
                PromotionStatus.DUPLICATE,
                triage.reason or "duplicate",
                stage=PromotionStage.TRIAGE,
                details=details,
            )
        if triage.status is TriageStatus.INSUFFICIENT:
            return await self._pause_with_remedy(
                req,
                unit,
                PromotionStage.TRIAGE,
                triage.reason or "TRIAGE_INSUFFICIENT",
                Action.RETARGET,
                PromotionStatus.REQUEUED,
                details,
            )
        if triage.status is TriageStatus.SPLIT:
            return await self._pause_with_remedy(
                req,
                unit,
                PromotionStage.TRIAGE,
                triage.reason or "TRIAGE_SPLIT",
                Action.ESCALATE_MODEL,
                PromotionStatus.ESCALATED,
                details,
            )
        if triage.status in (TriageStatus.UNAVAILABLE, TriageStatus.RETRY):
            return await self._requeue_request(
                req,
                claim_id=None,
                unit=unit,
                stage=PromotionStage.TRIAGE,
                reason=triage.reason or triage.status.value,
                details=details,
            )
        raise FormatFail(f"unknown triage status: {triage.status}")

    async def _pause_with_remedy(
        self,
        req: PromotionRequest,
        unit: str,
        stage: PromotionStage,
        reason: str,
        action: Action,
        status: PromotionStatus,
        details: dict[str, Any],
    ) -> PromotionResult:
        remedy = await self._plan_remedy(req, unit, stage, reason, action)
        return PromotionResult(
            status,
            reason,
            stage=stage,
            work_order_id=remedy.work_order_id,
            details=details,
        )

    async def _requeue_request(
        self,
        req: PromotionRequest,
        *,
        claim_id: str | None,
        stage: PromotionStage,
        reason: str,
        details: dict[str, Any],
        unit: str | None = None,
    ) -> PromotionResult:
        work_unit = unit or claim_id or f"case:{req.case_id}"
        if req.attempt + 1 >= self.max_attempts:
            if claim_id is not None:
                return await self._terminate_claim(
                    req,
                    claim_id,
                    ClaimState.PARKED,
                    stage,
                    reason,
                    Action.PARK,
                    PromotionStatus.PARKED,
                    details,
                )
            remedy = await self._plan_remedy(req, work_unit, stage, reason, Action.PARK)
            return PromotionResult(
                PromotionStatus.PARKED,
                reason,
                claim_id=claim_id,
                stage=stage,
                work_order_id=remedy.work_order_id,
                details=details,
            )
        await self._record_decision(req, observed=0.0, expected="requeue")
        return PromotionResult(
            PromotionStatus.REQUEUED,
            reason,
            claim_id=claim_id,
            stage=stage,
            details=details,
        )

    async def _terminate_claim(
        self,
        req: PromotionRequest,
        claim_id: str,
        target: ClaimState,
        stage: PromotionStage,
        reason: str,
        action: Action,
        status: PromotionStatus,
        details: dict[str, Any],
    ) -> PromotionResult:
        await self._ensure_state(claim_id, ClaimState.REVIEWED)
        await self.ledger.transition_claim(claim_id, target)
        remedy = await self._plan_remedy(req, claim_id, stage, reason, action)
        await self._record_decision(req, observed=0.0, expected=target.value)
        return PromotionResult(
            status,
            reason,
            claim_id=claim_id,
            stage=stage,
            work_order_id=remedy.work_order_id,
            details=details,
        )

    async def _escalate_claim(
        self,
        req: PromotionRequest,
        claim_id: str,
        stage: PromotionStage,
        reason: str,
        action: Action,
        details: dict[str, Any],
        *,
        verdict_id: int | None = None,
    ) -> PromotionResult:
        remedy = await self._plan_remedy(req, claim_id, stage, reason, action)
        await self._record_decision(req, observed=0.0, expected=action.value)
        return PromotionResult(
            PromotionStatus.ESCALATED,
            reason,
            claim_id=claim_id,
            stage=stage,
            work_order_id=remedy.work_order_id,
            verdict_id=verdict_id,
            details=details,
        )

    async def _plan_remedy(
        self, req: PromotionRequest, unit: str, stage: PromotionStage, reason: str, action: Action
    ) -> RemedyResult:
        return await self._policy.plan_remedy(
            RemedyRequest(
                claim_id=unit,
                stage=stage,
                reason=reason,
                action=action.value,
                run_id=req.run_id,
                probability_join=req.probability_join,
                chain_bonus=req.chain_bonus,
                ingress_weight=req.ingress_weight,
                attempt=req.attempt,
                metadata=req.metadata,
            )
        )

    async def _record_decision(
        self, req: PromotionRequest, *, observed: float, expected: str, wo_id: str | None = None
    ) -> int:
        return await self.ledger.record_decision(
            trigger_metric="promotion_gate",
            observed=observed,
            expected=expected,
            spent_usd_micro=0,
            run_id=req.run_id,
            wo_id=wo_id,
        )

    async def _ensure_main_claim(
        self,
        req: PromotionRequest,
        triage: TriageResult,
        bug_class: str,
        primitive: str,
        confidence: float,
        dedup: str,
        claim_id: str,
    ) -> dict[str, Any]:
        async with self._claim_lock(claim_id):
            return await self._ensure_main_claim_unlocked(
                req, triage, bug_class, primitive, confidence, dedup, claim_id
            )

    async def _ensure_main_claim_unlocked(
        self,
        req: PromotionRequest,
        triage: TriageResult,
        bug_class: str,
        primitive: str,
        confidence: float,
        dedup: str,
        claim_id: str,
    ) -> dict[str, Any]:
        value = {
            "gate": "promotion-v1",
            "case_id": req.case_id,
            "bug_class": bug_class,
            "primitive": primitive,
            "confidence": confidence,
            "attempt": req.attempt,
            "proposer_family": req.proposer_family,
            "triage": triage.to_dict(),
            "artifact_ids": [view.artifact_id for view in req.artifact_views()],
        }
        existing = self.ledger.claim_by_dedup(dedup)
        if existing is None:
            claim = ClaimInput(
                claim_id=claim_id,
                type="bug_class",
                value_json=json.dumps(value, sort_keys=True, separators=(",", ":")),
                confidence=confidence,
                dedup_key=dedup,
                created=now_ms(),
                run_id=req.run_id,
                artifacts=self._claim_artifact_inputs(req, triage),
            )
            with contextlib.suppress(DuplicateDedup):
                await self.ledger.create_claim(claim)
            existing = self.ledger.claim_by_dedup(dedup)
        if existing is None:
            raise FormatFail("claim dedup lookup failed after create")
        self._verify_main_claim_identity(existing, claim_id, bug_class, primitive)
        return existing

    @staticmethod
    def _verify_main_claim_identity(
        row: Mapping[str, Any], claim_id: str, bug_class: str, primitive: str
    ) -> None:
        if str(row.get("id")) != claim_id:
            raise FormatFail("claim dedup collision")
        try:
            value = json.loads(str(row.get("value_json")))
        except ValueError as exc:
            raise FormatFail("claim value_json is invalid") from exc
        if not isinstance(value, dict) or value.get("gate") != "promotion-v1":
            raise FormatFail("claim dedup collision")
        if value.get("bug_class") != bug_class or value.get("primitive") != primitive:
            raise FormatFail("claim identity mismatch")

    def _claim_artifact_inputs(
        self, req: PromotionRequest, triage: TriageResult
    ) -> tuple[ClaimArtifactInput, ...]:
        links: dict[tuple[str, str], ClaimArtifactInput] = {}
        for evidence in req.artifacts:
            view = evidence.to_view(data=False)
            links[(view.artifact_id, evidence.role)] = ClaimArtifactInput(
                artifact=ArtifactInput(
                    kind=evidence.kind,
                    data=evidence.data,
                    ttl_class=evidence.ttl_class,
                ),
                role=evidence.role,
            )
        if triage.artifact is not None:
            view = triage.artifact.to_view(data=False)
            key = (view.artifact_id, triage.artifact.role)
            if key not in links:
                links[key] = ClaimArtifactInput(
                    artifact=ArtifactInput(
                        kind=triage.artifact.kind,
                        data=triage.artifact.data,
                        ttl_class=triage.artifact.ttl_class,
                    ),
                    role=triage.artifact.role,
                )
        return tuple(links.values())

    async def _ensure_artifacts(
        self, req: PromotionRequest, claim_id: str, triage: TriageResult
    ) -> PromotionResult | None:
        if self.ledger.claim_artifact_count(claim_id) == 0:
            return await self._requeue_request(
                req,
                claim_id=claim_id,
                stage=PromotionStage.TRIAGE,
                reason="unbound_claim",
                details={"claim_id": claim_id},
            )
        linked = {
            (str(row["artifact_id"]), str(row["role"]))
            for row in self.ledger.claim_artifacts(claim_id)
        }
        for link in self._claim_artifact_inputs(req, triage):
            artifact_view_id = ledger_artifact_id(link.artifact.data)
            if (artifact_view_id, link.role) not in linked:
                await self.ledger.link_claim_artifact(claim_id, link.artifact, role=link.role)
        return None

    async def _ensure_state(self, claim_id: str, target: ClaimState) -> str:
        row = self.ledger.get_claim(claim_id)
        if row is None:
            raise FormatFail("claim does not exist")
        state = ClaimState(str(row["state"]))
        if target is ClaimState.BOUND and state is ClaimState.LIMBO:
            await self.ledger.transition_claim(claim_id, ClaimState.BOUND)
        elif target is ClaimState.REVIEWED:
            if state is ClaimState.LIMBO:
                await self.ledger.transition_claim(claim_id, ClaimState.BOUND)
                state = ClaimState.BOUND
            if state is ClaimState.BOUND:
                await self.ledger.transition_claim(claim_id, ClaimState.REVIEWED)
        refreshed = self.ledger.get_claim(claim_id)
        if refreshed is None:
            raise FormatFail("claim disappeared during transition")
        return str(refreshed["state"])

    async def _record_stage_claim(
        self,
        stage: str,
        main_claim_id: str,
        req: PromotionRequest,
        result: Mapping[str, Any],
        artifact: EvidenceArtifact | None,
    ) -> str:
        async with self._claim_lock(main_claim_id):
            return await self._record_stage_claim_unlocked(
                stage, main_claim_id, req, result, artifact
            )

    async def _record_stage_claim_unlocked(
        self,
        stage: str,
        main_claim_id: str,
        req: PromotionRequest,
        result: Mapping[str, Any],
        artifact: EvidenceArtifact | None,
    ) -> str:
        if stage not in _STAGE_CLAIM_TYPES:
            raise FormatFail(f"unknown promotion stage claim type: {stage}")
        artifact_view = None if artifact is None else artifact.to_view(data=False).to_dict()
        value = {
            "gate": "promotion-v1",
            "stage": stage,
            "claim_id": main_claim_id,
            "case_id": req.case_id,
            "attempt": req.attempt,
            "result": dict(result),
            "artifact": artifact_view,
        }
        value_json = json.dumps(value, sort_keys=True, separators=(",", ":"))
        result_artifact = EvidenceArtifact(
            kind=f"promote_{stage}",
            data=json_bytes(value),
            role="result",
            ttl_class="run",
        )
        links = [
            ClaimArtifactInput(
                artifact=ArtifactInput(
                    kind=result_artifact.kind,
                    data=result_artifact.data,
                    ttl_class=result_artifact.ttl_class,
                ),
                role="result",
            )
        ]
        if artifact is not None:
            links.append(
                ClaimArtifactInput(
                    artifact=ArtifactInput(
                        kind=artifact.kind,
                        data=artifact.data,
                        ttl_class=artifact.ttl_class,
                    ),
                    role="proof",
                )
            )
        dedup = f"promote:{stage}:{main_claim_id}:{req.attempt}:{sha256_hex(value_json.encode('utf-8'))[:16]}"
        claim_id = "cl_" + sha256_hex(dedup.encode("utf-8"))[:26]
        row = self.ledger.claim_by_dedup(dedup)
        if row is None:
            claim = ClaimInput(
                claim_id=claim_id,
                type=stage,
                value_json=value_json,
                confidence=1.0,
                dedup_key=dedup,
                created=now_ms(),
                run_id=req.run_id,
                artifacts=tuple(links),
            )
            with contextlib.suppress(DuplicateDedup):
                await self.ledger.create_claim(claim)
            row = self.ledger.claim_by_dedup(dedup)
        if row is None:
            raise FormatFail("stage claim dedup lookup failed after create")
        if str(row.get("id")) != claim_id:
            raise FormatFail("stage claim dedup collision")
        if str(row["state"]) == ClaimState.LIMBO.value:
            await self.ledger.transition_claim(claim_id, ClaimState.BOUND)
        return claim_id

    def _claim_lock(self, claim_id: str) -> asyncio.Lock:
        lock = self._claim_locks.get(claim_id)
        if lock is None:
            lock = asyncio.Lock()
            self._claim_locks[claim_id] = lock
        return lock

    async def _record_verdict(
        self,
        req: PromotionRequest,
        claim_id: str,
        verdict: ReviewVerdict,
        bug_class: str,
        primitive: str,
    ) -> tuple[int, bool, str]:
        async with self._claim_lock(claim_id):
            agreed, agreement_reason = self._agreement(req, verdict, bug_class, primitive)
            payload = {
                "gate": "promotion-v1",
                "claim_id": claim_id,
                "case_id": req.case_id,
                "attempt": req.attempt,
                "agreement": agreed,
                "agreement_reason": agreement_reason,
                "verdict": verdict.to_dict(),
            }
            identity = {
                "gate": "promotion-v1",
                "claim_id": claim_id,
                "agreement": agreed,
                "agreement_reason": agreement_reason,
                "verdict": self._verdict_identity(verdict),
            }
            idem = "review:" + sha256_hex(json_bytes(identity))[:32]
            reason_json = json.dumps({**payload, "idempotency_key": idem}, sort_keys=True)
            for row in self.ledger.verdicts_for_claim(claim_id):
                if str(row["reviewer"]) != verdict.reviewer:
                    continue
                raw_reason = row.get("reason")
                try:
                    parsed = json.loads(str(raw_reason)) if raw_reason is not None else {}
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict) and parsed.get("idempotency_key") == idem:
                    return int(row["id"]), agreed, agreement_reason
            if verdict.artifact is not None:
                await self.ledger.link_claim_artifact(
                    claim_id,
                    ArtifactInput(
                        kind=verdict.artifact.kind,
                        data=verdict.artifact.data,
                        ttl_class=verdict.artifact.ttl_class,
                    ),
                    role="reviewer",
                )
            verdict_id = await self.ledger.insert_verdict(
                claim_id=claim_id,
                reviewer=verdict.reviewer,
                agree=agreed,
                reason=reason_json,
            )
            return verdict_id, agreed, agreement_reason

    @staticmethod
    def _verdict_identity(verdict: ReviewVerdict) -> dict[str, Any]:
        return {
            "reviewer": verdict.reviewer,
            "bug_class": verdict.bug_class,
            "primitive": verdict.primitive,
            "confidence": verdict.confidence,
            "reviewer_family": verdict.reviewer_family,
            "reason": verdict.reason,
            "artifact": (
                None if verdict.artifact is None else verdict.artifact.to_view(data=False).to_dict()
            ),
        }

    @staticmethod
    def _validate_review_verdict(verdict: ReviewVerdict) -> None:
        for name, value in (
            ("reviewer", verdict.reviewer),
            ("bug_class", verdict.bug_class),
            ("primitive", verdict.primitive),
        ):
            if not isinstance(value, str) or not value.strip():
                raise FormatFail(f"reviewer {name} must be non-empty")
        if verdict.reviewer_family is not None and (
            not isinstance(verdict.reviewer_family, str) or not verdict.reviewer_family.strip()
        ):
            raise FormatFail("reviewer reviewer_family must be non-empty")
        if not isinstance(verdict.reason, str):
            raise FormatFail("reviewer reason must be a string")
        confidence = verdict.confidence
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0.0 <= confidence <= 1.0
        ):
            raise FormatFail("reviewer confidence must be in [0,1]")
        if verdict.artifact is not None and not isinstance(verdict.artifact, EvidenceArtifact):
            raise FormatFail("reviewer artifact must be an EvidenceArtifact")

    @staticmethod
    def _agreement(
        req: PromotionRequest, verdict: ReviewVerdict, bug_class: str, primitive: str
    ) -> tuple[bool, str]:
        if verdict.bug_class.strip() != bug_class or verdict.primitive.strip() != primitive:
            return False, "reviewer_disagreement"
        if req.proposer_family is not None:
            if verdict.reviewer_family is None:
                return False, "reviewer_family_unknown"
            if verdict.reviewer_family == req.proposer_family:
                return False, "reviewer_family_not_independent"
        return True, "agree"

    @staticmethod
    def _ladder_proof_error(ladder: LadderResult) -> str | None:
        if not isinstance(ladder.rung, str) or ladder.rung not in LADDER_RUNGS:
            return "ladder_rung_unknown"
        assertions = ladder.assertions
        if not isinstance(assertions, (tuple, list)) or not assertions:
            return "ladder_assertions_missing"
        if any(not isinstance(item, str) or not item.strip() for item in assertions):
            return "ladder_assertions_missing"
        for name in ("required_passes", "consecutive_passes"):
            value = getattr(ladder, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return "ladder_passes_insufficient"
        if ladder.required_passes < 1 or ladder.consecutive_passes < ladder.required_passes:
            return "ladder_passes_insufficient"
        return None

    @staticmethod
    def _groom_validator_error(groom: GroomResult) -> str | None:
        if not isinstance(groom.validator, str) or not groom.validator.strip():
            return "groom_validator_missing"
        return None

    @staticmethod
    def _dupe_score_error(dupe: DupeResult) -> str | None:
        score = dupe.score
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
            or score < 0.0
        ):
            return "dupe_score_invalid"
        for name in ("saturation", "patch_proximity", "shipped_coverage"):
            value = getattr(dupe, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.0 <= value <= 1.0
            ):
                return "dupe_term_invalid"
        return None

    @staticmethod
    def _required_text(value: str | None, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise FormatFail(f"{name} is required")
        return value.strip()

    @staticmethod
    def _unit_interval(value: float, name: str) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0.0 <= value <= 1.0
        ):
            raise FormatFail(f"{name} must be in [0,1]")
        return float(value)

    @staticmethod
    def _fallback_dedup(bug_class: str, primitive: str, views: tuple[ArtifactView, ...]) -> str:
        stack_hash = sha256_hex("|".join(sorted(view.artifact_id for view in views)).encode())
        return ledger_dedup_key(bug_class, stack_hash, primitive)

    @staticmethod
    def _claim_id_for_dedup(dedup: str) -> str:
        return "cl_" + sha256_hex(dedup.encode("utf-8"))[:26]

    def _dupe_scores(self) -> dict[str, float]:
        scores: dict[str, float] = {}
        for row in self.ledger.claims_by_type("dupe_score", limit=10000):
            try:
                raw = json.loads(str(row["value_json"]))
            except ValueError:
                continue
            if not isinstance(raw, dict):
                continue
            claim_id = raw.get("claim_id")
            result = raw.get("result")
            if not isinstance(claim_id, str) or not isinstance(result, dict):
                continue
            if result.get("status") != DupeStatus.SCORED.value:
                continue
            score = result.get("score")
            if (
                isinstance(score, (int, float))
                and not isinstance(score, bool)
                and math.isfinite(float(score))
            ):
                scores[claim_id] = float(score)
        return scores

    def _entry_for_row(
        self, row: Mapping[str, Any], dupe_score: float
    ) -> SubmissionEntry | None:
        if str(row["type"]) != "bug_class" or str(row["state"]) != ClaimState.PROMOTED.value:
            return None
        try:
            raw = json.loads(str(row["value_json"]))
        except ValueError:
            raw = {}
        value = cast(dict[str, Any], raw) if isinstance(raw, dict) else {}
        claim_id = str(row["id"])
        return SubmissionEntry(
            claim_id=claim_id,
            bug_class=str(value.get("bug_class") or ""),
            primitive=str(value.get("primitive") or ""),
            dupe_score=dupe_score,
            created=int(row["created"]),
            artifact_count=self.ledger.claim_artifact_count(claim_id),
        )

    def _submission_for(self, claim_id: str) -> SubmissionEntry | None:
        row = self.ledger.get_claim(claim_id)
        if row is None:
            return None
        return self._entry_for_row(row, self._dupe_scores().get(claim_id, 0.0))

    def submission_queue(self, *, limit: int = 100) -> list[SubmissionEntry]:
        """Return promoted findings ordered for the human submit gate."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        scores = self._dupe_scores()
        rows = self.ledger.claims_by_state(ClaimState.PROMOTED, limit=max(limit, 1000))
        entries = [
            entry
            for row in rows
            if (entry := self._entry_for_row(row, scores.get(str(row["id"]), 0.0))) is not None
        ]
        entries.sort(key=lambda entry: entry.sort_key())
        return entries[:limit]
