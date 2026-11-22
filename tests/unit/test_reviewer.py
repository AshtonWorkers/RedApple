"""RA-REV adversarial reviewer acceptance tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pytest

from ra.errors import FormatFail
from ra.ledger import ClaimState, Ledger
from ra.ledger.ids import UlidFactory, artifact_id
from ra.ledger.models import ArtifactInput, ClaimArtifactInput, ClaimInput
from ra.press.client import ChatResponse
from ra.press.harness import PressHarness
from ra.reviewer import (
    AdversarialReviewer,
    ArtifactEvidence,
    ArtifactLink,
    HeuristicReviewModel,
    JsonlPacketReviewModel,
    LedgerPromotionGate,
    MappingArtifactResolver,
    MetadataOnlyArtifactResolver,
    PacketDumpReviewModel,
    PressReviewModel,
    RaisingReviewModel,
    ReviewPacket,
    candidate_claim_fields,
    detect_bug_class,
    detect_primitive,
    excerpt_bytes,
    normalize_bug_class,
    normalize_primitive,
    primitive_rank,
    run_checks,
)

OOB_WRITE_CRASH = (
    b"AddressSanitizer: heap-buffer-overflow WRITE of size 4\n"
    b"    #0 parser_write parcel parser.cc:10\n"
    b"    #1 LLVMFuzzerTestOneInput harness.cc:20\n"
)
OOB_READ_CRASH = (
    b"AddressSanitizer: heap-buffer-overflow READ of size 8\n"
    b"    #0 parser_read parcel parser.cc:11\n"
)


def link_for(data: bytes, *, kind: str = "crash", role: str = "evidence") -> ArtifactLink:
    return ArtifactLink(
        artifact_id=artifact_id(data),
        kind=kind,
        role=role,
        sha256=artifact_id(data).removeprefix("art_"),
        byte_count=len(data),
    )


async def create_candidate(
    ledger: Ledger,
    *,
    value: dict[str, object],
    data: bytes = OOB_WRITE_CRASH,
    state: ClaimState = ClaimState.BOUND,
    claim_type: str = "bug_class",
) -> tuple[str, bytes]:
    ids = UlidFactory()
    claim_id = ids.new("cl")
    claim = ClaimInput(
        claim_id=claim_id,
        type=claim_type,
        value_json=json.dumps(value, sort_keys=True),
        confidence=0.5,
        dedup_key=f"candidate:{claim_id}",
        created=1,
        artifacts=(
            ClaimArtifactInput(
                artifact=ArtifactInput(kind="crash", data=data, ttl_class="run"),
                role="evidence",
            ),
        ),
    )
    await ledger.create_claim(claim)
    if state is ClaimState.BOUND:
        await ledger.transition_claim(claim_id, ClaimState.BOUND)
    elif state is ClaimState.REVIEWED:
        await ledger.transition_claim(claim_id, ClaimState.BOUND)
        await ledger.transition_claim(claim_id, ClaimState.REVIEWED)
    return claim_id, data


class RaisingResolver:
    async def resolve(self, link: ArtifactLink) -> bytes | None:
        raise OSError("artifact store unavailable")


class ReviewerLedgerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = await Ledger.open(self.root / "ledger.sqlite")

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def make_reviewer(
        self,
        model: object,
        data: bytes,
        *,
        proposer_family: str = "triage_beta",
    ) -> AdversarialReviewer:
        resolver = MappingArtifactResolver({artifact_id(data): data})
        return AdversarialReviewer(
            self.ledger,
            resolver=resolver,
            model=model,  # type: ignore[arg-type]
            proposer_family=proposer_family,
        )

    async def test_RA_REV_001_agreement_promotes_and_audits(self) -> None:
        claim_id, data = await create_candidate(
            self.ledger,
            value={
                "bug_class": "oob_write",
                "primitive": "oob_write",
                "summary": "proposer prose must not reach reviewer",
            },
        )
        model = PacketDumpReviewModel("oob_write", "oob_write", family="reviewer_alpha")
        reviewer = self.make_reviewer(model, data)

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "promoted"
        assert outcome.promoted is True
        assert self.ledger.get_claim(claim_id)["state"] == ClaimState.PROMOTED.value
        review = self.ledger.get_claim(outcome.review_claim_id or "")
        assert review is not None
        assert review["type"] == "review"
        assert review["state"] == ClaimState.BOUND.value
        verdicts = self.ledger.verdicts_for_claim(claim_id)
        assert len(verdicts) == 1
        assert verdicts[0]["agree"] == 1
        assert verdicts[0]["reviewer"] == "reviewer_alpha"
        assert self.ledger.ready_work_orders() == []
        packet_json = model.packets[0].canonical_json()
        assert "proposer prose" not in packet_json
        assert "summary" not in packet_json
        gate = LedgerPromotionGate(self.ledger)
        await gate.promote(claim_id, review_claim_id=str(review["id"]))
        again = await reviewer.review_claim(claim_id)
        assert again.status == "skipped"

    async def test_RA_REV_001_limbo_candidate_is_bound_before_review(self) -> None:
        claim_id, data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            state=ClaimState.LIMBO,
        )
        reviewer = self.make_reviewer(
            PacketDumpReviewModel("oob_write", "oob_write", family="reviewer_alpha"), data
        )
        outcome = await reviewer.review_claim(claim_id)
        assert outcome.status == "promoted"
        assert self.ledger.get_claim(claim_id)["state"] == ClaimState.PROMOTED.value

    async def test_RA_REV_002_disagreement_freezes_escalates_and_audits(self) -> None:
        claim_id, data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
        )
        reviewer = self.make_reviewer(
            PacketDumpReviewModel("oob_read", "oob_read", family="reviewer_beta"), data
        )

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "frozen"
        assert outcome.promoted is False
        assert self.ledger.get_claim(claim_id)["state"] == ClaimState.REVIEWED.value
        verdicts = self.ledger.verdicts_for_claim(claim_id)
        assert len(verdicts) == 1
        assert verdicts[0]["agree"] == 0
        assert "bug_class_mismatch" in str(verdicts[0]["reason"])
        orders = self.ledger.ready_work_orders()
        assert len(orders) == 1
        assert orders[0]["action"] == "escalate_model"
        assert orders[0]["unit"] == f"review:{claim_id}"
        payload = json.loads(str(orders[0]["payload_json"]))
        assert payload["review_claim_id"] == outcome.review_claim_id
        review = self.ledger.get_claim(outcome.review_claim_id or "")
        assert json.loads(str(review["value_json"]))["status"] == "frozen"

        duplicate = await reviewer.review_claim(claim_id)
        assert duplicate.status == "duplicate"
        assert duplicate.review_claim_id == outcome.review_claim_id
        assert len(self.ledger.verdicts_for_claim(claim_id)) == 1
        assert len(self.ledger.ready_work_orders()) == 1

    async def test_RA_REV_003_no_artifact_claim_requeues(self) -> None:
        claim_id, data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            state=ClaimState.LIMBO,
        )
        await self.ledger.delete_artifacts([artifact_id(data)])
        assert self.ledger.claim_artifacts(claim_id) == []
        reviewer = self.make_reviewer(
            PacketDumpReviewModel("oob_write", "oob_write", family="reviewer_gamma"), data
        )

        outcome = await reviewer.review_claim(claim_id)

        assert outcome.status == "requeued"
        assert self.ledger.get_claim(claim_id)["state"] == ClaimState.LIMBO.value
        verdicts = self.ledger.verdicts_for_claim(claim_id)
        assert verdicts[0]["agree"] == 0
        assert "no_artifact_links" in str(verdicts[0]["reason"])
        orders = self.ledger.ready_work_orders()
        assert len(orders) == 1
        assert orders[0]["action"] == "retarget"
        assert orders[0]["unit"] == f"claim:{claim_id}"

    async def test_RA_REV_004_review_bound_claims_filters_candidates(self) -> None:
        good, good_data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
        )
        other, other_data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
            data=OOB_READ_CRASH,
            claim_type="foundry_state",
        )
        resolver = MappingArtifactResolver(
            {artifact_id(good_data): good_data, artifact_id(other_data): other_data}
        )
        reviewer = AdversarialReviewer(
            self.ledger,
            resolver=resolver,
            model=PacketDumpReviewModel("oob_write", "oob_write", family="reviewer_delta"),
            proposer_family="triage_beta",
        )
        outcomes = await reviewer.review_bound_claims()
        assert [item.claim_id for item in outcomes] == [good]
        assert self.ledger.get_claim(other)["state"] == ClaimState.BOUND.value

    async def test_RA_REV_005_model_error_and_resolver_fail_closed(self) -> None:
        claim_id, data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
        )
        reviewer = AdversarialReviewer(
            self.ledger,
            resolver=MappingArtifactResolver({}),
            model=RaisingReviewModel(RuntimeError("boom")),
            proposer_family="triage_beta",
        )
        outcome = await reviewer.review_claim(claim_id)
        assert outcome.status == "frozen"
        assert outcome.promoted is False
        assert self.ledger.get_claim(claim_id)["state"] == ClaimState.REVIEWED.value
        verdict = self.ledger.verdicts_for_claim(claim_id)[0]
        assert verdict["agree"] == 0
        assert "model_error" in str(verdict["reason"])
        assert "check_failed:artifact_bytes_resolved" in str(verdict["reason"])
        assert self.ledger.ready_work_orders()[0]["action"] == "escalate_model"
        assert data

    async def test_RA_REV_005_same_family_and_non_candidate_rejected(self) -> None:
        with pytest.raises(FormatFail):
            AdversarialReviewer(
                self.ledger,
                resolver=MetadataOnlyArtifactResolver(),
                model=PacketDumpReviewModel("oob_write", "oob_write", family="same"),
                proposer_family="same",
            )
        claim_id, data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
        )
        reviewer = self.make_reviewer(
            PacketDumpReviewModel("oob_write", "oob_write", family="reviewer_epsilon"), data
        )
        outcome = await reviewer.review_claim(claim_id)
        with pytest.raises(FormatFail):
            await reviewer.review_claim(outcome.review_claim_id or "")

    async def test_RA_REV_005_promotion_gate_guards(self) -> None:
        claim_id, _data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
        )
        await self.ledger.transition_claim(claim_id, ClaimState.REVIEWED)
        await self.ledger.transition_claim(claim_id, ClaimState.PARKED)
        gate = LedgerPromotionGate(self.ledger)
        with pytest.raises(FormatFail):
            await gate.promote(claim_id, review_claim_id="rv_missing")
        with pytest.raises(FormatFail):
            await gate.promote("cl_missing", review_claim_id="rv_missing")

    async def test_RA_REV_005_resolver_exception_fails_closed(self) -> None:
        claim_id, data = await create_candidate(
            self.ledger,
            value={"bug_class": "oob_write", "primitive": "oob_write"},
        )
        reviewer = AdversarialReviewer(
            self.ledger,
            resolver=RaisingResolver(),
            model=HeuristicReviewModel(),
            proposer_family="triage_beta",
        )
        outcome = await reviewer.review_claim(claim_id)
        assert outcome.status == "frozen"
        assert self.ledger.get_claim(claim_id)["state"] == ClaimState.REVIEWED.value
        review = self.ledger.get_claim(outcome.review_claim_id or "")
        value = json.loads(str(review["value_json"]))
        assert value["checks"][1]["name"] == "artifact_bytes_resolved"
        assert value["checks"][1]["passed"] is False
        assert data

    async def test_RA_REV_006_heuristic_and_press_models(self) -> None:
        packet = ReviewPacket(
            claim_id="cl_test",
            claim_type="bug_class",
            artifacts=(
                ArtifactEvidence(link=link_for(OOB_WRITE_CRASH), data=OOB_WRITE_CRASH, excerpt=excerpt_bytes(OOB_WRITE_CRASH)),
            ),
        )
        heuristic = await HeuristicReviewModel().derive(packet)
        assert heuristic.bug_class == "oob_write"
        assert heuristic.primitive == "oob_write"

        local = PressReviewModel(PressHarness(local_only=True, queue_path=None), family="press_local")
        offline = await local.derive(packet)
        assert offline.bug_class == "insufficient_evidence"
        assert offline.confidence == 0.0

        jsonl = await JsonlPacketReviewModel().derive(packet)
        assert jsonl.bug_class == "oob_write"

        metadata = await MetadataOnlyArtifactResolver().resolve(link_for(OOB_WRITE_CRASH))
        assert metadata is None


class FakePressClient:
    def chat(self, system: str, user: str, **kwargs: object) -> ChatResponse:
        answer = "oob_write"
        return ChatResponse(text=json.dumps({"answer": answer}), tokens_in=1, tokens_out=1)


class PressReviewModelTest(unittest.IsolatedAsyncioTestCase):
    async def test_RA_REV_006_press_review_model_confident_path(self) -> None:
        packet = ReviewPacket(
            claim_id="cl_test",
            claim_type="bug_class",
            artifacts=(
                ArtifactEvidence(link=link_for(OOB_WRITE_CRASH), data=OOB_WRITE_CRASH, excerpt=excerpt_bytes(OOB_WRITE_CRASH)),
            ),
        )
        model = PressReviewModel(
            PressHarness(local_only=False, client=FakePressClient()), family="press_review"
        )
        derivation = await model.derive(packet)
        assert derivation.bug_class == "oob_write"
        assert derivation.primitive == "oob_write"
        assert derivation.confidence == 0.75
        assert len(derivation.reasons) == 2


class PureReviewerTest(unittest.TestCase):
    def test_RA_REV_007_normalization_and_vocab_properties(self) -> None:
        for bug in ("oob_read", "oob_write", "uaf", "type_confusion", "info_leak"):
            assert normalize_bug_class(bug) == bug
            assert normalize_bug_class(bug.replace("_", " ")) == bug
        for primitive in (
            "none",
            "crash",
            "info_leak",
            "oob_read",
            "oob_write",
            "uaf",
            "type_confusion",
            "arbitrary_read",
            "arbitrary_write",
            "code_execution",
        ):
            assert normalize_primitive(primitive) == primitive
        ranks = [primitive_rank(item) for item in (
            "none",
            "crash",
            "info_leak",
            "oob_read",
            "oob_write",
            "uaf",
            "type_confusion",
            "arbitrary_read",
            "arbitrary_write",
            "code_execution",
        )]
        assert ranks == sorted(ranks)
        assert candidate_claim_fields("not json") == ("insufficient_evidence", "none")
        assert candidate_claim_fields("[]") == ("insufficient_evidence", "none")
        assert candidate_claim_fields('{"bug_class":"oob_read"}') == ("oob_read", "oob_read")
        assert candidate_claim_fields('{"bug_class":"Use After Free","primitive":"rel_rw"}') == (
            "uaf",
            "oob_write",
        )

    def test_RA_REV_007_keyword_checks_and_excerpt_bounds(self) -> None:
        assert detect_bug_class("use-after-free in WebKit") == "uaf"
        assert detect_bug_class("type confusion via JSCell") == "type_confusion"
        assert detect_bug_class("heap-buffer-overflow WRITE") == "oob_write"
        assert detect_bug_class("heap-buffer-overflow READ") == "oob_read"
        assert detect_bug_class("heap-buffer-overflow; write size 4") == "oob_write"
        assert detect_bug_class("heap-buffer-overflow; read size 8") == "oob_read"
        assert detect_bug_class("out-of-bounds read") == "oob_read"
        assert detect_bug_class("information disclosure leak") == "info_leak"
        assert detect_bug_class("nothing useful") == "insufficient_evidence"
        assert detect_primitive("rip control shellcode", "oob_write") == "code_execution"
        assert detect_primitive("arbitrary write primitive", "oob_write") == "arbitrary_write"
        assert detect_primitive("arbitrary read primitive", "oob_read") == "arbitrary_read"
        assert detect_primitive("plain crash", "insufficient_evidence") == "crash"
        assert detect_primitive("plain text", "insufficient_evidence") == "none"
        big = b"A" * 10_000
        excerpt = excerpt_bytes(big, max_chars=256)
        assert "truncated" in excerpt
        assert len(excerpt) < 400
        empty = excerpt_bytes(b"")
        assert empty == ""

    def test_RA_REV_007_run_checks_edge_cases(self) -> None:
        good = ArtifactEvidence(link=link_for(OOB_WRITE_CRASH), data=OOB_WRITE_CRASH, excerpt=excerpt_bytes(OOB_WRITE_CRASH))
        checks = {check.name: check for check in run_checks((good,))}
        assert all(check.passed for check in checks.values())
        blob_link = link_for(OOB_WRITE_CRASH, kind="blob", role="payload")
        blob = ArtifactEvidence(link=blob_link, data=OOB_WRITE_CRASH, excerpt=excerpt_bytes(OOB_WRITE_CRASH))
        checks = {check.name: check for check in run_checks((blob,))}
        assert checks["crash_evidence_present"].passed is True
        unresolved = ArtifactEvidence(link=link_for(OOB_WRITE_CRASH), data=None, excerpt="", error="unresolved")
        checks = {check.name: check for check in run_checks((unresolved,))}
        assert checks["artifact_bytes_resolved"].passed is False
        corpus = ArtifactEvidence(link=link_for(OOB_WRITE_CRASH, kind="corpus"), data=OOB_WRITE_CRASH, excerpt=excerpt_bytes(OOB_WRITE_CRASH))
        checks = {check.name: check for check in run_checks((corpus,))}
        assert checks["no_host_corpus_parse"].passed is False
        many = tuple(
            ArtifactEvidence(link=link_for(OOB_WRITE_CRASH), data=OOB_WRITE_CRASH, excerpt="x")
            for _ in range(9)
        )
        checks = {check.name: check for check in run_checks(many, max_artifacts=8)}
        assert checks["artifact_count_bounded"].passed is False


if __name__ == "__main__":
    unittest.main()
