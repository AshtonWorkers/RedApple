"""Primitive ladder: promote/reject groom candidates across RA-LAD rungs."""

from __future__ import annotations

from ..errors import DialectDefect, FormatFail
from ..ledger import Ledger
from .allocators import AllocatorModelSet
from .foundry import FoundryDialectGate, LedgerFoundryDefectSink
from .heapdiff import validate_heap_diff
from .interfaces import (
    FoundryDefectSink,
    FoundryDialectValidator,
    PressAdvisor,
    PrimitiveAttemptPort,
    TriageService,
)
from .ledgerio import create_reviewed_claim, finalize_claim
from .models import (
    LADDER_ORDER,
    PROMOTION_CONSECUTIVE_PASSES,
    RUNG_ASSERTIONS,
    AttemptEvidence,
    CrashCase,
    GroomCandidate,
    GroomPlan,
    LadderOutcome,
    LadderRung,
    RungResult,
    TriageResult,
    canonical_json,
    now_ms,
    sha256_text,
)
from .stubs import NullAttemptPort, NullPressAdvisor, StaticTriage


class LadderRunner:
    """Run retained crashes through ``info_leak -> oob_read -> rel_rw`` once each."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        attempt_port: PrimitiveAttemptPort | None = None,
        triage: TriageService | None = None,
        gate: FoundryDialectValidator | None = None,
        defect_sink: FoundryDefectSink | None = None,
        advisor: PressAdvisor | None = None,
        allocator_models: AllocatorModelSet | None = None,
    ) -> None:
        self._ledger = ledger
        self._attempt_port = attempt_port or NullAttemptPort()
        self._triage = triage or StaticTriage()
        self._allocator_models = allocator_models
        self._gate = gate or (
            FoundryDialectGate(allocator_models) if allocator_models is not None else FoundryDialectGate()
        )
        self._defect_sink = defect_sink or LedgerFoundryDefectSink(ledger)
        self._advisor = advisor or NullPressAdvisor()

    async def run(
        self,
        case: CrashCase,
        plan: GroomPlan | None,
        *,
        triage: TriageResult | None = None,
    ) -> LadderOutcome:
        """Attempt every ladder rung once and persist the outcome."""
        if not isinstance(case, CrashCase):
            raise ValueError("case must be a CrashCase")
        if plan is not None and not isinstance(plan, GroomPlan):
            raise ValueError("plan must be a GroomPlan or None")
        if triage is not None and not isinstance(triage, TriageResult):
            raise ValueError("triage must be a TriageResult")
        result = triage if triage is not None else await self._triage.classify(case)
        if not isinstance(result, TriageResult):
            raise ValueError("triage service must return a TriageResult")
        candidates = () if plan is None else plan.candidates
        results: list[RungResult] = []
        for index, rung in enumerate(LADDER_ORDER):
            rung_result = await self._attempt_rung(rung, candidates, index, case, result)
            results.append(rung_result)
        status, error_code = self._status(tuple(results))
        outcome = LadderOutcome(
            case=case,
            plan_id=None if plan is None else plan.plan_id,
            results=tuple(results),
            claim_id=None,
            status=status,
            error_code=error_code,
        )
        claim_id = await self._persist(case, plan, outcome, result)
        return LadderOutcome(
            case=case,
            plan_id=outcome.plan_id,
            results=outcome.results,
            claim_id=claim_id,
            status=outcome.status,
            error_code=outcome.error_code,
        )

    async def _attempt_rung(
        self,
        rung: LadderRung,
        candidates: tuple[GroomCandidate, ...],
        index: int,
        case: CrashCase,
        triage: TriageResult,
    ) -> RungResult:
        """Validate one candidate and attempt one rung."""
        assertion = RUNG_ASSERTIONS[rung]
        candidate = await self._select_candidate(candidates, rung, index, case, triage)
        if candidate is None:
            return RungResult(
                rung=rung,
                candidate_id="",
                passed=False,
                promoted=False,
                consecutive_passes=0,
                assertion=assertion,
                reason="no_groom_candidates",
            )
        try:
            self._gate.validate(candidate.dialect)
        except DialectDefect as exc:
            await self._defect_sink.report_dialect_defect(
                candidate=candidate,
                case=case,
                error=str(exc),
            )
            return RungResult(
                rung=rung,
                candidate_id=candidate.candidate_id,
                passed=False,
                promoted=False,
                consecutive_passes=0,
                assertion=assertion,
                reason="DIALECT_DEFECT",
            )
        try:
            evidence = await self._attempt_port.attempt(rung=rung, candidate=candidate, case=case)
        except Exception as exc:  # failure-injection: attempt ports must not crash the ladder
            return RungResult(
                rung=rung,
                candidate_id=candidate.candidate_id,
                passed=False,
                promoted=False,
                consecutive_passes=0,
                assertion=assertion,
                reason=f"attempt_error:{type(exc).__name__}",
            )
        if not isinstance(evidence, AttemptEvidence):
            return RungResult(
                rung=rung,
                candidate_id=candidate.candidate_id,
                passed=False,
                promoted=False,
                consecutive_passes=0,
                assertion=assertion,
                reason="invalid_evidence",
            )
        passed, reason = self._evaluate(evidence, rung, candidate)
        promoted = passed and evidence.consecutive_passes >= PROMOTION_CONSECUTIVE_PASSES
        if promoted:
            reason = "promoted"
        elif passed:
            reason = "passed_below_promotion_threshold"
        return RungResult(
            rung=rung,
            candidate_id=candidate.candidate_id,
            passed=passed,
            promoted=promoted,
            consecutive_passes=evidence.consecutive_passes if passed else 0,
            assertion=assertion,
            reason=reason,
            evidence=evidence,
        )

    def _evaluate(
        self,
        evidence: AttemptEvidence,
        rung: LadderRung,
        candidate: GroomCandidate,
    ) -> tuple[bool, str]:
        """Apply rung assertion and heap-diff checks to attempt evidence."""
        expected = RUNG_ASSERTIONS[rung]
        if evidence.rung != rung:
            return False, "rung_mismatch"
        if not evidence.passed:
            return False, "attempt_failed"
        if evidence.assertion != expected:
            return False, "assertion_mismatch"
        if evidence.assertion_results.get(expected) is not True:
            return False, "assertion_missing"
        if evidence.heap_expectation is not None and (
            evidence.heap_before is None or evidence.heap_after is None
        ):
            return False, "heap_evidence_missing"
        if evidence.heap_before is not None and evidence.heap_after is not None:
            try:
                heap_result = validate_heap_diff(
                    candidate.dialect,
                    evidence.heap_before,
                    evidence.heap_after,
                    expectation=evidence.heap_expectation,
                    allocator_models=self._allocator_models,
                )
            except (DialectDefect, FormatFail, ValueError) as exc:
                return False, f"heap_diff_error:{type(exc).__name__}"
            if not heap_result.passed:
                return False, "heap_diff_failed"
        else:
            return False, "heap_evidence_missing"
        return True, "passed"

    async def _select_candidate(
        self,
        candidates: tuple[GroomCandidate, ...],
        rung: LadderRung,
        index: int,
        case: CrashCase,
        triage: TriageResult,
    ) -> GroomCandidate | None:
        """Pick a candidate for a rung, optionally guided by PRESS advice."""
        if not candidates:
            return None
        advised = await self._advise_candidate(candidates, rung, case, triage)
        if advised is not None:
            return advised
        return candidates[index % len(candidates)]

    async def _advise_candidate(
        self,
        candidates: tuple[GroomCandidate, ...],
        rung: LadderRung,
        case: CrashCase,
        triage: TriageResult,
    ) -> GroomCandidate | None:
        try:
            advice = await self._advisor.advise_rung(case=case, triage=triage, rung=rung)
        except Exception:
            return None
        if not isinstance(advice, str) or not advice:
            return None
        for candidate in candidates:
            if candidate.candidate_id == advice:
                return candidate
        return None

    def _status(self, results: tuple[RungResult, ...]) -> tuple[str, str | None]:
        """Map rung results to ladder status and optional error code."""
        if not results or all(not result.passed for result in results):
            return "exhausted", "LADDER_EXHAUSTED"
        promoted = [result.rung for result in results if result.promoted]
        if promoted:
            highest = LADDER_ORDER[max(LADDER_ORDER.index(rung) for rung in promoted)]
            if highest == LadderRung.REL_RW:
                return "promoted", None
            return "partial", None
        return "rejected", None

    async def _persist(
        self,
        case: CrashCase,
        plan: GroomPlan | None,
        outcome: LadderOutcome,
        triage: TriageResult,
    ) -> str:
        """Persist ladder outcome as a reviewed claim and terminal transition."""
        value = outcome.to_dict()
        value["triage"] = triage.to_dict()
        artifacts: list[tuple[str, bytes]] = [("ladder_outcome", canonical_json(value).encode())]
        if case.payload:
            artifacts.append(("crash", case.payload))
        for result in outcome.results:
            if result.evidence is not None and result.evidence.artifact_payload:
                artifacts.append((f"rung_{result.rung.value}_artifact", result.evidence.artifact_payload))
        for index, blob in enumerate(triage.artifacts):
            artifacts.append((f"triage_{index}", blob))
        outcome_bytes = canonical_json(value).encode()
        dedup = f"ladder:{case.id}:{outcome.plan_id or 'noplan'}:{sha256_text(outcome_bytes.decode())[:16]}"
        claim_id = await create_reviewed_claim(
            self._ledger,
            claim_id="ladder_claim_" + sha256_text(dedup)[:24],
            claim_type="rung",
            value=value,
            confidence=self._confidence(outcome),
            dedup=dedup,
            artifacts=tuple(artifacts),
            run_id=case.run_id,
            created=now_ms(),
        )
        promoted = outcome.status == "promoted"
        demoted = outcome.status in {"exhausted", "rejected"}
        await finalize_claim(self._ledger, claim_id, promoted=promoted, demoted=demoted)
        return claim_id

    def _confidence(self, outcome: LadderOutcome) -> float:
        if outcome.status == "promoted":
            return 0.95
        if outcome.status == "partial":
            return 0.7
        if outcome.status == "rejected":
            return 0.4
        return 0.1
