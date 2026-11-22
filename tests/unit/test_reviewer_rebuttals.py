"""Adversarial tests for reviewer rebuttals, duplicate evidence, and garbage input."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ra.errors import FormatFail
from ra.ledger import ClaimState, Ledger
from ra.ledger.ids import UlidFactory, artifact_id
from ra.ledger.models import ArtifactInput, ClaimArtifactInput, ClaimInput
from ra.reviewer import (
    AdversarialReviewer,
    ArtifactEvidence,
    ArtifactLink,
    IndependentDerivation,
    MappingArtifactResolver,
    PacketDumpReviewModel,
    assess_evidence,
    candidate_claim_fields,
    detect_bug_class,
    detect_primitive,
    evidence_signature,
    excerpt_bytes,
    normalize_bug_class,
    normalize_crash_text,
    normalize_primitive,
    primitive_rank,
    run_checks,
    run_rebuttals,
)

OOB_WRITE_CRASH = (
    b"AddressSanitizer: heap-buffer-overflow WRITE of size 4\n"
    b"    #0 parser_write parcel parser.cc:10\n"
    b"    #1 LLVMFuzzerTestOneInput harness.cc:20\n"
)
OOB_WRITE_CRASH_DISGUISED = (
    b"AddressSanitizer: heap-buffer-overflow WRITE of size 8\n"
    b"    #0 parser_write parcel parser.cc:11\n"
    b"    #1 LLVMFuzzerTestOneInput harness.cc:22\n"
    b"2026-11-22 pid 4242 address 0xdeadbeef\n"
)
FABRICATED_CRASH = (
    b"ordinary application log\n"
    b"no sanitizer report here\n"
    b"request completed status=200\n"
)
INFO_LEAK_EVIDENCE = b"information disclosure: heap metadata address leak in response\n"


def artifact_link(data: bytes, *, kind: str = "crash", role: str = "evidence") -> ArtifactLink:
    return ArtifactLink(
        artifact_id=artifact_id(data),
        kind=kind,
        role=role,
        sha256=artifact_id(data).removeprefix("art_"),
        byte_count=len(data),
    )


def evidence_from(data: bytes, *, kind: str = "crash", role: str = "evidence") -> ArtifactEvidence:
    link = artifact_link(data, kind=kind, role=role)
    return ArtifactEvidence(link=link, data=data, excerpt=excerpt_bytes(data))


def artifact_input(
    data: bytes, *, kind: str = "crash", role: str = "evidence"
) -> ClaimArtifactInput:
    return ClaimArtifactInput(
        artifact=ArtifactInput(kind=kind, data=data, ttl_class="run"), role=role
    )


class GarbageResolver:
    async def resolve(self, link: ArtifactLink) -> bytes | None:
        return "not-bytes"  # type: ignore[return-value]


class GarbageReviewModel:
    family = "garbage_reviewer"

    async def derive(self, packet: object) -> IndependentDerivation:
        return IndependentDerivation(
            bug_class="not-a-real-class",
            primitive="super_primitive",
            confidence=float("nan"),
            reasons=(123, "ok"),  # type: ignore[arg-type]
            model_family=self.family,
        )


class ImpersonatingReviewModel:
    family = "imposter_reviewer"

    async def derive(self, packet: object) -> IndependentDerivation:
        return IndependentDerivation(
            bug_class="oob_write",
            primitive="oob_write",
            confidence=0.9,
            reasons=("stub",),
            model_family="test_proposer",
        ).normalized()


class ReviewerRebuttalPureTest(unittest.TestCase):
    def test_duplicate_signature_normalizes_volatile_crash_fields(self) -> None:
        original = evidence_from(OOB_WRITE_CRASH)
        disguised = evidence_from(OOB_WRITE_CRASH_DISGUISED)

        assert evidence_signature(original) is not None
        assert evidence_signature(original) == evidence_signature(disguised)

        normalized = normalize_crash_text(disguised.excerpt or "")
        assert "pid" not in normalized
        assert "0xdeadbeef" not in normalized
        assert "#" in normalized

    def test_assessment_and_rebuttals_are_deterministic(self) -> None:
        original = evidence_from(OOB_WRITE_CRASH)
        first_assessment = assess_evidence((original,))
        second_assessment = assess_evidence((original,))
        assert first_assessment == second_assessment
        assert first_assessment.supported_bug_class == "oob_write"
        assert first_assessment.supported_primitive == "oob_write"
        assert first_assessment.primary_evidence_substantiated

        good = run_rebuttals(
            (original,), candidate_bug_class="oob_write", candidate_primitive="oob_write"
        )
        assert all(check.passed for check in good)
        assert run_rebuttals(
            (original,), candidate_bug_class="oob_write", candidate_primitive="oob_write"
        ) == good

        bad = run_rebuttals(
            (original,),
            candidate_bug_class="oob_write",
            candidate_primitive="arbitrary_write",
            duplicate_matches=("cl_other:art_x:exact_artifact",),
        )
        failed = {check.name for check in bad if not check.passed}
        assert {"candidate_primitive_supported", "evidence_not_duplicate"} <= failed
        assert run_rebuttals(
            (original,),
            candidate_bug_class="oob_write",
            candidate_primitive="arbitrary_write",
            duplicate_matches=("cl_other:art_x:exact_artifact",),
        ) == bad

    def test_fabricated_and_unsubstantiated_evidence_is_assessed_honestly(self) -> None:
        fabricated = evidence_from(FABRICATED_CRASH)
        assessment = assess_evidence((fabricated,))
        assert assessment.supported_bug_class == "insufficient_evidence"
        assert assessment.supported_primitive == "none"
        assert not assessment.primary_evidence_substantiated
        assert assessment.signatures == ()
        assert evidence_signature(fabricated) is None

        checks = {check.name: check for check in run_checks((fabricated,))}
        assert checks["crash_evidence_present"].passed is True
        assert checks["crash_evidence_substantiated"].passed is False

        info = evidence_from(INFO_LEAK_EVIDENCE, kind="info_leak", role="evidence")
        info_checks = {check.name: check for check in run_checks((info,))}
        assert info_checks["crash_evidence_present"].passed is True
        assert info_checks["crash_evidence_substantiated"].passed is True
        assert detect_bug_class(info.excerpt or "") == "info_leak"

    def test_vocabulary_and_garbage_normalization(self) -> None:
        assert normalize_bug_class(None) == "insufficient_evidence"
        assert normalize_bug_class("not-a-real-class") == "insufficient_evidence"
        assert normalize_primitive(None) == "none"
        assert normalize_primitive(object()) == "none"
        assert primitive_rank(None) == 0
        assert candidate_claim_fields("null") == ("insufficient_evidence", "none")
        assert candidate_claim_fields('{"bug_class": null, "primitive": []}') == (
            "insufficient_evidence",
            "none",
        )
        assert detect_primitive("controlled write primitive", "oob_write") == "arbitrary_write"
        assert detect_primitive("instruction pointer control", "uaf") == "code_execution"

        derivation = IndependentDerivation(
            bug_class="OOB Write",
            primitive="RCE",
            confidence=float("nan"),
            reasons=(123, "ok"),  # type: ignore[arg-type]
            model_family="",
        ).normalized()
        assert derivation.bug_class == "oob_write"
        assert derivation.primitive == "code_execution"
        assert derivation.confidence == 0.0
        assert derivation.reasons == ("123", "ok")
        assert derivation.model_family == "unknown"

        string_reasons = IndependentDerivation(
            bug_class="oob_write",
            primitive="oob_write",
            confidence=0.9,
            reasons="single reason",  # type: ignore[arg-type]
            model_family="reviewer_alpha",
        ).normalized()
        assert string_reasons.reasons == ("single reason",)

        assert excerpt_bytes(b"abcdef", max_chars=0) == ""
        assert excerpt_bytes(b"abcdef", max_chars=-1) == ""
        assert excerpt_bytes(b"", max_chars=10) == ""

    def test_duplicate_scan_limits_are_validated(self) -> None:
        with self.assertRaises(FormatFail):
            AdversarialReviewer(
                object(),  # type: ignore[arg-type]
                resolver=MappingArtifactResolver({}),
                model=PacketDumpReviewModel("oob_write", "oob_write"),
                duplicate_scan_limit=0,
            )


class ReviewerRebuttalLedgerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ledger = await Ledger.open(Path(self._tmp.name) / "claims.db")
        self.ids = UlidFactory()

    async def asyncTearDown(self) -> None:
        await self.ledger.close()

    def artifact(
        self, data: bytes, *, kind: str = "crash", role: str = "evidence"
    ) -> ClaimArtifactInput:
        return artifact_input(data, kind=kind, role=role)

    async def create_candidate(
        self,
        *,
        value: dict[str, object] | str,
        artifacts: tuple[ClaimArtifactInput, ...],
        claim_type: str = "bug_class",
        state: ClaimState = ClaimState.BOUND,
        dedup_key: str | None = None,
    ) -> str:
        claim_id = self.ids.new("cl")
        value_json = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        await self.ledger.create_claim(
            ClaimInput(
                claim_id=claim_id,
                type=claim_type,
                value_json=value_json,
                confidence=0.5,
                dedup_key=dedup_key or f"candidate:{claim_id}",
                created=1,
                artifacts=artifacts,
            )
        )
        if state is ClaimState.BOUND:
            await self.ledger.transition_claim(claim_id, ClaimState.BOUND)
        elif state is ClaimState.REVIEWED:
            await self.ledger.transition_claim(claim_id, ClaimState.BOUND)
            await self.ledger.transition_claim(claim_id, ClaimState.REVIEWED)
        return claim_id

    def reviewer_for(
        self,
        model: object,
        artifacts: tuple[bytes, ...],
        **kwargs: object,
    ) -> AdversarialReviewer:
        resolver = MappingArtifactResolver(
            {artifact_id(data): data for data in artifacts if isinstance(data, bytes)}
        )
        return AdversarialReviewer(
            self.ledger,
            resolver=resolver,  # type: ignore[arg-type]
            model=model,  # type: ignore[arg-type]
            proposer_family="test_proposer",
            ids=self.ids,
            now=lambda: 1_000,
            **kwargs,  # type: ignore[arg-type]
        )

    def review_value(self, outcome_claim_id: str | None) -> dict[str, object]:
        assert outcome_claim_id is not None
        row = self.ledger.get_claim(outcome_claim_id)
        assert row is not None
        assert row["type"] == "review"
        value = json.loads(str(row["value_json"]))
        assert isinstance(value, dict)
        return value

    async def test_fabricated_crash_is_challenged_and_review_claim_is_well_formed(self) -> None:
        data = FABRICATED_CRASH
        claim_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            artifacts=(self.artifact(data),),
        )
        reviewer = self.reviewer_for(
            PacketDumpReviewModel("oob_write", "oob_write"), (data,)
        )

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        assert outcome.promoted is False
        row = self.ledger.get_claim(claim_id)
        assert row is not None and row["state"] == ClaimState.REVIEWED.value
        orders = self.ledger.ready_work_orders()
        assert len(orders) == 1
        assert orders[0]["action"] == "escalate_model"
        assert orders[0]["unit"] == f"review:{claim_id}"
        value = self.review_value(outcome.review_claim_id)
        assert value["claim_id"] == claim_id
        assert value["status"] == "frozen"
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert {
            "crash_evidence_substantiated",
            "candidate_bug_class_supported",
            "candidate_primitive_supported",
        } <= failed
        verdicts = self.ledger.verdicts_for_claim(claim_id)
        assert verdicts
        assert verdicts[0]["agree"] == 0
        assert "check_failed:crash_evidence_substantiated" in str(verdicts[0]["reason"])
        assert len(self.ledger.claim_artifacts(str(outcome.review_claim_id))) == 2

    async def test_mislabeled_exploitability_is_rebutted_when_model_agrees(self) -> None:
        data = OOB_WRITE_CRASH
        claim_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "arbitrary_write"},
            artifacts=(self.artifact(data),),
        )
        reviewer = self.reviewer_for(PacketDumpReviewModel("oob_write", "arbitrary_write"), (data,))

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        assert outcome.promoted is False
        value = self.review_value(outcome.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert "candidate_primitive_supported" in failed
        assert "candidate_bug_class_supported" not in failed
        checks = value["checks"]  # type: ignore[assignment]
        primitive_check = next(
            check for check in checks if check["name"] == "candidate_primitive_supported"
        )
        assert "supported=oob_write" in str(primitive_check["reason"])
        assert "candidate=arbitrary_write" in str(primitive_check["reason"])

    async def test_mislabeled_bug_class_is_rebutted_when_model_agrees(self) -> None:
        data = OOB_WRITE_CRASH
        claim_id = await self.create_candidate(
            value={"bug_class": "oob_read", "primitive": "arbitrary_read"},
            artifacts=(self.artifact(data),),
        )
        reviewer = self.reviewer_for(PacketDumpReviewModel("oob_read", "arbitrary_read"), (data,))

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        value = self.review_value(outcome.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert "candidate_bug_class_supported" in failed
        assert "candidate_primitive_supported" in failed

    async def test_duplicate_in_disguise_is_rebutted(self) -> None:
        original_data = OOB_WRITE_CRASH
        disguised_data = OOB_WRITE_CRASH_DISGUISED
        first_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            artifacts=(self.artifact(original_data),),
        )
        first_reviewer = self.reviewer_for(
            PacketDumpReviewModel("oob_write", "oob_write"), (original_data,)
        )
        first = await first_reviewer.review_claim(first_id)
        assert first.status == "promoted"

        second_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write", "note": "disguised"},
            artifacts=(self.artifact(disguised_data),),
        )
        second_reviewer = self.reviewer_for(
            PacketDumpReviewModel("oob_write", "oob_write"),
            (original_data, disguised_data),
        )
        second = await second_reviewer.review_claim(second_id)

        assert second.status == "frozen"
        assert second.promoted is False
        value = self.review_value(second.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert "evidence_not_duplicate" in failed
        checks = value["checks"]  # type: ignore[assignment]
        duplicate_check = next(check for check in checks if check["name"] == "evidence_not_duplicate")
        assert "similar_crash_signature" in str(duplicate_check["reason"])
        assert first_id in str(duplicate_check["reason"])
        first_row = self.ledger.get_claim(first_id)
        assert first_row is not None and first_row["state"] == ClaimState.PROMOTED.value

    async def test_exact_duplicate_artifact_is_rebutted(self) -> None:
        data = OOB_WRITE_CRASH
        first_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            artifacts=(self.artifact(data),),
        )
        first_reviewer = self.reviewer_for(
            PacketDumpReviewModel("oob_write", "oob_write"), (data,)
        )
        first = await first_reviewer.review_claim(first_id)
        assert first.status == "promoted"

        second_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write", "note": "copy"},
            artifacts=(self.artifact(data),),
        )
        second_reviewer = self.reviewer_for(
            PacketDumpReviewModel("oob_write", "oob_write"), (data,)
        )
        second = await second_reviewer.review_claim(second_id)

        assert second.status == "frozen"
        value = self.review_value(second.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert "evidence_not_duplicate" in failed
        checks = value["checks"]  # type: ignore[assignment]
        duplicate_check = next(check for check in checks if check["name"] == "evidence_not_duplicate")
        assert "exact_artifact" in str(duplicate_check["reason"])
        assert first_id in str(duplicate_check["reason"])

    async def test_garbage_candidate_value_fails_closed(self) -> None:
        data = OOB_WRITE_CRASH
        claim_id = await self.create_candidate(
            value='{"bug_class": null, "primitive": []}',
            artifacts=(self.artifact(data),),
        )
        reviewer = self.reviewer_for(PacketDumpReviewModel("oob_write", "oob_write"), (data,))

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        value = self.review_value(outcome.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert "candidate_bug_class_supported" in failed
        assert "candidate_primitive_supported" in failed

    async def test_resolver_garbage_bytes_fail_closed(self) -> None:
        data = OOB_WRITE_CRASH
        claim_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            artifacts=(self.artifact(data),),
        )
        reviewer = AdversarialReviewer(
            self.ledger,
            resolver=GarbageResolver(),  # type: ignore[arg-type]
            model=PacketDumpReviewModel("oob_write", "oob_write"),
            proposer_family="test_proposer",
            ids=self.ids,
            now=lambda: 1_000,
        )

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        value = self.review_value(outcome.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert {"artifact_bytes_resolved", "crash_evidence_substantiated"} <= failed

    async def test_model_family_impersonation_is_rebutted(self) -> None:
        data = OOB_WRITE_CRASH
        claim_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            artifacts=(self.artifact(data),),
        )
        reviewer = self.reviewer_for(ImpersonatingReviewModel(), (data,))

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        assert outcome.promoted is False
        verdicts = self.ledger.verdicts_for_claim(claim_id)
        assert verdicts and verdicts[0]["reviewer"] == "imposter_reviewer"
        assert "reviewer_family_independent" in str(verdicts[0]["reason"])
        value = self.review_value(outcome.review_claim_id)
        failed = {
            str(check["name"])
            for check in value["checks"]  # type: ignore[index]
            if not check["passed"]  # type: ignore[index]
        }
        assert "reviewer_family_independent" in failed

    async def test_garbage_model_output_is_normalized_fail_closed(self) -> None:
        data = OOB_WRITE_CRASH
        claim_id = await self.create_candidate(
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            artifacts=(self.artifact(data),),
        )
        reviewer = self.reviewer_for(GarbageReviewModel(), (data,))

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        row = self.ledger.get_claim(str(outcome.review_claim_id))
        assert row is not None
        assert row["confidence"] == 0.0
        value = self.review_value(outcome.review_claim_id)
        assert value["bug_class"] == "insufficient_evidence"
        assert value["primitive"] == "none"
        verdicts = self.ledger.verdicts_for_claim(claim_id)
        assert verdicts and verdicts[0]["agree"] == 0
