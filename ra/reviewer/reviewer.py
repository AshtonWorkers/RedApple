"""Adversarial reviewer orchestration (RA-REV)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ra.errors import DuplicateDedup, FormatFail
from ra.ledger import ClaimState, Ledger
from ra.ledger.ids import UlidFactory, sha256_hex
from ra.ledger.models import ArtifactInput, ClaimArtifactInput, ClaimInput

from .checks import (
    evidence_signature,
    evidence_signatures,
    excerpt_bytes,
    run_checks,
    run_rebuttals,
)
from .gates import LedgerEscalationSink, LedgerPromotionGate, LedgerRequeueSink
from .models import (
    CANDIDATE_TYPES,
    INSUFFICIENT_EVIDENCE,
    NO_PRIMITIVE,
    REVIEW_CLAIM_TYPE,
    ArtifactEvidence,
    ArtifactLink,
    ArtifactResolver,
    CheckResult,
    IndependentDerivation,
    PromotionGate,
    ReviewDecision,
    ReviewModel,
    ReviewOutcome,
    ReviewPacket,
    candidate_claim_fields,
    now_ms,
    primitive_rank,
)


class AdversarialReviewer:
    """Challenge candidate claims before promotion using an independent model."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        resolver: ArtifactResolver,
        model: ReviewModel,
        promoter: PromotionGate | None = None,
        escalation: LedgerEscalationSink | None = None,
        requeue: LedgerRequeueSink | None = None,
        proposer_family: str = "proposer",
        ids: UlidFactory | None = None,
        duplicate_scan_limit: int = 64,
        duplicate_artifact_limit: int = 8,
        now: Callable[[], int] = now_ms,
    ):
        if model.family == proposer_family:
            raise FormatFail("reviewer model must be a different family from proposer")
        if duplicate_scan_limit < 1 or duplicate_artifact_limit < 1:
            raise FormatFail("duplicate scan limits must be positive")
        self._ledger = ledger
        self._resolver = resolver
        self._model = model
        self._promoter = promoter or LedgerPromotionGate(ledger)
        self._escalation = escalation or LedgerEscalationSink(ledger)
        self._requeue = requeue or LedgerRequeueSink(ledger)
        self._ids = ids or UlidFactory()
        self._proposer_family = proposer_family
        self._duplicate_scan_limit = duplicate_scan_limit
        self._duplicate_artifact_limit = duplicate_artifact_limit
        self._now = now

    async def review_bound_claims(self, *, limit: int = 100) -> list[ReviewOutcome]:
        """Review bound candidate claims, skipping review claims and terminal rows."""
        rows = self._ledger.claims_by_state(ClaimState.BOUND.value, limit=limit)
        outcomes: list[ReviewOutcome] = []
        for row in rows:
            if str(row.get("type")) not in CANDIDATE_TYPES:
                continue
            outcomes.append(await self.review_claim(str(row["id"])))
        return outcomes

    async def review_claim(self, claim_id: str) -> ReviewOutcome:
        """Review one candidate claim and persist verdict, review claim, and action."""
        row = self._ledger.get_claim(claim_id)
        if row is None:
            raise FormatFail(f"unknown claim: {claim_id}")
        claim_type = str(row["type"])
        if claim_type not in CANDIDATE_TYPES:
            raise FormatFail(f"claim {claim_id} is not a review candidate: {claim_type}")
        state = str(row["state"])
        if state in {
            ClaimState.PROMOTED.value,
            ClaimState.DEMOTED.value,
            ClaimState.PARKED.value,
        }:
            return self._skipped(claim_id, claim_type, row)
        links = tuple(
            ArtifactLink.from_row(item) for item in self._ledger.claim_artifacts(claim_id)
        )
        if not links:
            return await self._requeue_no_artifacts(claim_id, claim_type, row)
        if state == ClaimState.LIMBO.value:
            await self._ledger.transition_claim(claim_id, ClaimState.BOUND)
            state = ClaimState.BOUND.value
        if state not in {ClaimState.BOUND.value, ClaimState.REVIEWED.value}:
            return self._skipped(claim_id, claim_type, row)
        evidence = await self._resolve_evidence(links)
        packet = ReviewPacket(claim_id=claim_id, claim_type=claim_type, artifacts=evidence)
        candidate_bug, candidate_primitive = candidate_claim_fields(str(row["value_json"]))
        duplicate_matches = await self._duplicate_matches(claim_id, claim_type, evidence)
        checks = run_checks(evidence) + run_rebuttals(
            evidence,
            candidate_bug_class=candidate_bug,
            candidate_primitive=candidate_primitive,
            duplicate_matches=duplicate_matches,
        )
        try:
            derivation = (await self._model.derive(packet)).normalized()
        except Exception as exc:  # fail closed: model errors cannot promote
            derivation = IndependentDerivation(
                bug_class=INSUFFICIENT_EVIDENCE,
                primitive=NO_PRIMITIVE,
                confidence=0.0,
                reasons=(f"model_error:{type(exc).__name__}",),
                model_family=self._model.family,
                error=True,
            )
        family_independent = derivation.model_family != self._proposer_family
        checks = checks + (
            CheckResult(
                "reviewer_family_independent",
                family_independent,
                ""
                if family_independent
                else f"reviewer family {derivation.model_family} equals proposer",
            ),
        )
        if not family_independent:
            derivation = IndependentDerivation(
                bug_class=derivation.bug_class,
                primitive=derivation.primitive,
                confidence=derivation.confidence,
                reasons=(*derivation.reasons, "reviewer_family_impersonation"),
                model_family=self._model.family,
                error=True,
            )
        decision = self._decide(
            claim_id=claim_id,
            claim_type=claim_type,
            candidate_bug_class=candidate_bug,
            candidate_primitive=candidate_primitive,
            packet=packet,
            checks=checks,
            derivation=derivation,
        )
        return await self._persist(claim_id, row, packet, decision, derivation.confidence)

    async def _resolve_evidence(self, links: tuple[ArtifactLink, ...]) -> tuple[ArtifactEvidence, ...]:
        evidence: list[ArtifactEvidence] = []
        for link in links:
            try:
                data = await self._resolver.resolve(link)
            except Exception as exc:  # fail closed on resolver faults
                evidence.append(
                    ArtifactEvidence(link=link, data=None, excerpt="", error=type(exc).__name__)
                )
                continue
            if data is None:
                evidence.append(
                    ArtifactEvidence(link=link, data=None, excerpt="", error="unresolved")
                )
                continue
            if not isinstance(data, (bytes, bytearray, memoryview)):
                evidence.append(
                    ArtifactEvidence(
                        link=link, data=None, excerpt="", error="invalid_artifact_bytes"
                    )
                )
                continue
            data_bytes = bytes(data)
            evidence.append(
                ArtifactEvidence(link=link, data=data_bytes, excerpt=excerpt_bytes(data_bytes))
            )
        return tuple(evidence)

    async def _duplicate_matches(
        self,
        claim_id: str,
        claim_type: str,
        evidence: tuple[ArtifactEvidence, ...],
    ) -> tuple[str, ...]:
        current_sha = {str(item.link.sha256) for item in evidence if item.link.sha256}
        current_ids = {str(item.link.artifact_id) for item in evidence}
        current_signatures = set(evidence_signatures(evidence))
        if not current_sha and not current_signatures:
            return ()
        rows = self._ledger.claims_by_type(
            claim_type, limit=self._duplicate_scan_limit + 1
        )[: self._duplicate_scan_limit]
        matches: list[str] = []
        seen: set[str] = set()
        resolver_cache: dict[str, bytes | None] = {}
        for row in rows:
            other_id = str(row["id"])
            if other_id == claim_id:
                continue
            other_artifacts = self._ledger.claim_artifacts(other_id)[
                : self._duplicate_artifact_limit
            ]
            for artifact in other_artifacts:
                artifact_id = str(artifact["artifact_id"])
                sha256 = str(artifact["sha256"])
                if sha256 in current_sha or artifact_id in current_ids:
                    match = f"{other_id}:{artifact_id}:exact_artifact"
                    if match not in seen:
                        seen.add(match)
                        matches.append(match)
            if not current_signatures:
                continue
            for artifact in other_artifacts:
                artifact_id = str(artifact["artifact_id"])
                sha256 = str(artifact["sha256"])
                if sha256 in current_sha or artifact_id in current_ids:
                    continue
                link = ArtifactLink.from_row(artifact)
                data = await self._resolve_duplicate_artifact(link, resolver_cache)
                if data is None:
                    continue
                candidate = ArtifactEvidence(link=link, data=data, excerpt=excerpt_bytes(data))
                signature = evidence_signature(candidate)
                if signature in current_signatures:
                    match = f"{other_id}:{artifact_id}:similar_crash_signature"
                    if match not in seen:
                        seen.add(match)
                        matches.append(match)
        return tuple(matches)

    async def _resolve_duplicate_artifact(
        self, link: ArtifactLink, cache: dict[str, bytes | None]
    ) -> bytes | None:
        if link.artifact_id in cache:
            return cache[link.artifact_id]
        try:
            data = await self._resolver.resolve(link)
        except Exception:
            data = None
        if data is not None and not isinstance(data, (bytes, bytearray, memoryview)):
            data = None
        resolved = bytes(data) if data is not None else None
        cache[link.artifact_id] = resolved
        return resolved

    def _decide(
        self,
        *,
        claim_id: str,
        claim_type: str,
        candidate_bug_class: str,
        candidate_primitive: str,
        packet: ReviewPacket,
        checks: tuple[CheckResult, ...],
        derivation: IndependentDerivation,
    ) -> ReviewDecision:
        reasons = list(derivation.reasons)
        if derivation.error:
            reasons.append("review_model_error")
        reasons.extend(f"check_failed:{check.name}" for check in checks if not check.passed)
        if candidate_bug_class == INSUFFICIENT_EVIDENCE:
            reasons.append("candidate_bug_class_insufficient")
        if derivation.bug_class == INSUFFICIENT_EVIDENCE:
            reasons.append("review_bug_class_insufficient")
        if candidate_bug_class != derivation.bug_class:
            reasons.append(f"bug_class_mismatch:{candidate_bug_class}!={derivation.bug_class}")
        if candidate_primitive != derivation.primitive:
            reasons.append(f"primitive_mismatch:{candidate_primitive}!={derivation.primitive}")
        if primitive_rank(candidate_primitive) > primitive_rank(derivation.primitive):
            reasons.append("candidate_overclaims_primitive")
        checks_passed = all(check.passed for check in checks)
        agree = (
            checks_passed
            and not derivation.error
            and candidate_bug_class != INSUFFICIENT_EVIDENCE
            and candidate_bug_class == derivation.bug_class
            and candidate_primitive == derivation.primitive
        )
        return ReviewDecision(
            agree=agree,
            status="promoted" if agree else "frozen",
            candidate_bug_class=candidate_bug_class,
            candidate_primitive=candidate_primitive,
            bug_class=derivation.bug_class,
            primitive=derivation.primitive,
            checks=checks,
            reasons=tuple(dict.fromkeys(reasons)),
            model_family=derivation.model_family,
            packet_sha=packet.digest(),
            escalate=not agree,
        )

    async def _persist(
        self,
        claim_id: str,
        row: dict[str, Any],
        packet: ReviewPacket,
        decision: ReviewDecision,
        confidence: float,
    ) -> ReviewOutcome:
        created = self._now()
        run_id = row.get("run_id")
        run_id = str(run_id) if run_id is not None else None
        packet_bytes = packet.canonical_json().encode("utf-8")
        decision_bytes = json.dumps(decision.to_dict(), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        dedup = sha256_hex(
            f"review|{claim_id}|{decision.packet_sha}|{decision.model_family}".encode()
        )[:32]
        review_claim = ClaimInput(
            claim_id=self._ids.new("rv"),
            type=REVIEW_CLAIM_TYPE,
            value_json=json.dumps(
                {"claim_id": claim_id, **decision.to_dict()}, sort_keys=True, separators=(",", ":")
            ),
            confidence=max(0.0, min(1.0, confidence)),
            dedup_key=dedup,
            created=created,
            run_id=run_id,
            artifacts=(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind="review_packet", data=packet_bytes, ttl_class="run"),
                    role="packet",
                ),
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind="review_decision", data=decision_bytes, ttl_class="run"),
                    role="decision",
                ),
            ),
        )
        try:
            await self._ledger.create_claim(review_claim)
        except DuplicateDedup:
            existing = self._ledger.claim_by_dedup(dedup)
            if existing is None:
                raise
            return ReviewOutcome(
                status="duplicate",
                claim_id=claim_id,
                decision=decision,
                review_claim_id=str(existing["id"]),
            )
        await self._ledger.transition_claim(review_claim.claim_id, ClaimState.BOUND)
        verdict_reason = (
            "agreement"
            if decision.agree
            else "; ".join(decision.reasons[:8]) or decision.status
        )
        verdict_id = await self._ledger.insert_verdict(
            claim_id=claim_id,
            reviewer=decision.model_family,
            agree=decision.agree,
            reason=verdict_reason,
            created=created,
        )
        work_order_id: str | None = None
        promoted = False
        if decision.status == "promoted":
            await self._promoter.promote(claim_id, review_claim_id=review_claim.claim_id)
            promoted = True
        elif decision.status == "frozen":
            current = self._ledger.get_claim(claim_id)
            current_state = str(current["state"]) if current is not None else ""
            if current_state == ClaimState.BOUND.value:
                await self._ledger.transition_claim(claim_id, ClaimState.REVIEWED)
            work_order_id = await self._escalation.escalate(
                claim_id, review_claim.claim_id, decision, run_id=run_id
            )
        elif decision.status == "requeued":
            work_order_id = await self._requeue.requeue(
                claim_id, review_claim.claim_id, decision, run_id=run_id
            )
        return ReviewOutcome(
            status=decision.status,
            claim_id=claim_id,
            decision=decision,
            review_claim_id=review_claim.claim_id,
            verdict_id=verdict_id,
            work_order_id=work_order_id,
            promoted=promoted,
        )

    async def _requeue_no_artifacts(
        self, claim_id: str, claim_type: str, row: dict[str, Any]
    ) -> ReviewOutcome:
        packet = ReviewPacket(claim_id=claim_id, claim_type=claim_type, artifacts=())
        checks = run_checks(())
        candidate_bug, candidate_primitive = candidate_claim_fields(str(row["value_json"]))
        decision = ReviewDecision(
            agree=False,
            status="requeued",
            candidate_bug_class=candidate_bug,
            candidate_primitive=candidate_primitive,
            bug_class=INSUFFICIENT_EVIDENCE,
            primitive=NO_PRIMITIVE,
            checks=checks,
            reasons=("no_artifact_links",),
            model_family=self._model.family,
            packet_sha=packet.digest(),
            escalate=False,
        )
        return await self._persist(claim_id, row, packet, decision, 0.0)

    def _skipped(self, claim_id: str, claim_type: str, row: dict[str, Any]) -> ReviewOutcome:
        candidate_bug, candidate_primitive = candidate_claim_fields(str(row["value_json"]))
        packet = ReviewPacket(claim_id=claim_id, claim_type=claim_type, artifacts=())
        decision = ReviewDecision(
            agree=False,
            status="skipped",
            candidate_bug_class=candidate_bug,
            candidate_primitive=candidate_primitive,
            bug_class=INSUFFICIENT_EVIDENCE,
            primitive=NO_PRIMITIVE,
            checks=(),
            reasons=(f"claim_state_{row['state']}",),
            model_family=self._model.family,
            packet_sha=packet.digest(),
            escalate=False,
        )
        return ReviewOutcome(status="skipped", claim_id=claim_id, decision=decision)
