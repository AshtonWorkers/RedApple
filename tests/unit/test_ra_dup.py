"""RA-DUP dupe oracle acceptance, unit, property, and failure-injection tests."""

from __future__ import annotations

import json
import math
import random
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ra.dupe import (
    CorpusEvidence,
    CrashInput,
    CrashSignature,
    DupeOracle,
    DupeRecord,
    DupeScore,
    Finding,
    LedgerDupeStore,
    NormalizedFrame,
    NullCorpusIndex,
    NullPatchProximityProvider,
    NullSubmissionQueue,
    NullTriageClassifier,
    PatchDiff,
    SubmissionCandidate,
    candidates_from_verdicts,
    canonical_dedup_key,
    canonical_id_for_signature,
    compute_dupe_score,
    finding_patches,
    max_patch_proximity,
    max_patch_similarity,
    parse_unified_diff,
    patch_proximity,
    patch_proximity_for_finding,
    patch_similarity,
    patch_similarity_for_findings,
    rank_submissions,
    signature_for_finding,
    signature_similarity,
    stack_similarity,
)
from ra.errors import DuplicateDedup, FormatFail, RaError
from ra.ledger import Ledger

TEXT_CRASH = (
    "Exception Type: EXC_BAD_ACCESS\n"
    "Exception Codes: 1\n"
    "Signal: 11\n"
    "Process: TestApp\n"
    "Thread 0 Crashed:\n"
    "0   libfoo.dylib   0x000000010  foo_parse + 12\n"
    "1   libbar.dylib   0x000000020  bar_handle + 34\n"
)

JSON_CRASH = json.dumps(
    {
        "exception": {"type": "EXC_BAD_ACCESS", "code": "1", "signal": "11"},
        "procName": "TestApp",
        "usedImages": [{"name": "libfoo.dylib"}, {"name": "libbar.dylib"}],
        "faultingThread": 0,
        "threads": [
            {
                "frames": [
                    {"imageIndex": 0, "symbol": "foo_parse", "line": 12},
                    {"imageIndex": 1, "symbol": "bar_handle"},
                ]
            }
        ],
    }
).encode("utf-8")

RING_DIFF = (
    "diff --git a/src/libfoo.dylib b/src/libfoo.dylib\n"
    "--- a/src/libfoo.dylib\n"
    "+++ b/src/libfoo.dylib\n"
    "@@ -10,2 +10,2 @@\n"
    "-foo_parse(input)\n"
    "+foo_parse(input, options)\n"
)

STACK = (
    {"module": "libfoo.dylib", "function": "foo_parse"},
    {"module": "libbar.dylib", "function": "bar_handle"},
    {"module": "libsystem.dylib", "function": "dispatch"},
)


def metadata_crash(
    crash_id: str,
    *,
    frames: tuple[dict[str, str], ...] = STACK,
    process: str = "TestApp",
    exception_code: str = "1",
    context: str = "app",
) -> CrashInput:
    return CrashInput(
        id=crash_id,
        kind="meta",
        context=context,
        metadata={
            "exception_type": "EXC_BAD_ACCESS",
            "exception_code": exception_code,
            "signal": "11",
            "process": process,
            "frames": [dict(frame) for frame in frames],
        },
    )


def text_finding(crash_id: str, **overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "crash": CrashInput(id=crash_id, kind="ips", path=f"/{crash_id}.ips", payload=TEXT_CRASH.encode("utf-8")),
        "bug_class": "uaf",
        "saturation": 0.5,
        "patch_proximity": 0.5,
        "shipped_coverage": 0.5,
    }
    values.update(overrides)
    return Finding(**values)


class StaticCorpus:
    def __init__(self, evidence: list[CorpusEvidence]) -> None:
        self._evidence = evidence
        self.calls = 0

    async def evidence(self, finding: Finding, signature: Any) -> list[CorpusEvidence]:
        self.calls += 1
        return list(self._evidence)


class StaticTriage:
    def __init__(self, bug_class: str = "kernel_uaf") -> None:
        self.bug_class = bug_class

    async def classify(self, finding: Finding) -> str:
        return self.bug_class


class FailingTriage:
    async def classify(self, finding: Finding) -> str:
        raise FormatFail("triage unavailable")


class StaticPatchProvider:
    def __init__(self, value: float | None) -> None:
        self.value = value

    async def proximity(self, finding: Finding, signature: Any) -> float | None:
        return self.value


class FailingPatchProvider:
    async def proximity(self, finding: Finding, signature: Any) -> float | None:
        raise RaError("patch intel unavailable")


class RecordingQueue:
    def __init__(self) -> None:
        self.items: list[SubmissionCandidate] = []

    async def enqueue(self, candidate: SubmissionCandidate) -> str:
        self.items.append(candidate)
        return f"queue-{len(self.items)}"


class ExplodingStore:
    async def get_canonical(self, signature_hash: str) -> DupeRecord | None:
        return None

    async def canonicals(self) -> list[DupeRecord]:
        return []

    async def save_canonical(self, record: DupeRecord, artifact_data: bytes) -> str:
        raise FormatFail("canonical store failed")

    async def save_observation(self, record: DupeRecord, artifact_data: bytes) -> str:
        raise FormatFail("observation store failed")


class FailingCorpus:
    async def evidence(self, finding: Finding, signature: CrashSignature) -> list[CorpusEvidence]:
        raise RaError("corpus unavailable")


class MemoryStore:
    def __init__(self, *, observation_failures: int = 0) -> None:
        self.records: list[DupeRecord] = []
        self.observation_failures = observation_failures
        self.observation_calls = 0

    async def get_canonical(self, signature_hash: str) -> DupeRecord | None:
        for record in self.records:
            if record.record_kind == "canonical" and record.signature.signature_hash == signature_hash:
                return record
        return None

    async def canonicals(self) -> list[DupeRecord]:
        return [record for record in self.records if record.record_kind == "canonical"]

    async def save_canonical(self, record: DupeRecord, artifact_data: bytes) -> str:
        self.records.append(record)
        return record.claim_id

    async def save_observation(self, record: DupeRecord, artifact_data: bytes) -> str:
        self.observation_calls += 1
        if self.observation_failures:
            self.observation_failures -= 1
            raise FormatFail("observation store failed once")
        return f"obs-{self.observation_calls}"


class HiddenCanonicalStore(MemoryStore):
    async def get_canonical(self, signature_hash: str) -> DupeRecord | None:
        return None


class CollisionStore:
    def __init__(self) -> None:
        self.available = False

    async def get_canonical(self, signature_hash: str) -> DupeRecord | None:
        if not self.available:
            return None
        return DupeRecord(
            claim_id="existing-claim",
            dedup_key=canonical_dedup_key(signature_hash),
            record_kind="canonical",
            canonical_id="dupc_existing",
            created_ms=1,
            signature=minimal_signature(signature_hash),
        )

    async def canonicals(self) -> list[DupeRecord]:
        return []

    async def save_canonical(self, record: DupeRecord, artifact_data: bytes) -> str:
        self.available = True
        raise DuplicateDedup("canonical already exists")

    async def save_observation(self, record: DupeRecord, artifact_data: bytes) -> str:
        return "obs-collision"


def minimal_signature(signature_hash: str) -> CrashSignature:
    return CrashSignature(
        signature_hash=signature_hash,
        stack_hash="",
        bug_class="unknown",
        exception_type="",
        exception_code="",
        signal="",
        process="",
        context="app",
        alloc_site="",
        frames=(),
        source_kind="",
        source_id="",
        source_path="",
        source_digest="",
        created_ms=0,
    )


class DupeOracleTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.ledger = await Ledger.open(":memory:")
        self.oracle = DupeOracle(self.ledger)

    async def asyncTearDown(self) -> None:
        await self.ledger.close()

    async def test_RA_DUP_001_score_formula_terms_and_clamps(self) -> None:
        self.assertAlmostEqual(compute_dupe_score(0.5, 0.5, 0.5), 0.5)
        self.assertEqual(compute_dupe_score(1.0, 1.0, 0.0), 1.0)
        self.assertEqual(compute_dupe_score(0.0, 0.0, 1.0), 0.0)
        self.assertAlmostEqual(compute_dupe_score(2.0, -1.0, math.nan), 0.65)

        score = DupeScore.from_dict(
            {"saturation": 2.0, "patch_proximity": -1.0, "shipped_coverage": "bad", "total": 3.0}
        )
        self.assertEqual(score.saturation, 1.0)
        self.assertEqual(score.patch_proximity, 0.0)
        self.assertEqual(score.shipped_coverage, 0.0)
        self.assertEqual(score.total, 1.0)

        verdict = await self.oracle.check(text_finding("score-explicit"))
        self.assertAlmostEqual(verdict.score.total, 0.5)
        self.assertEqual(verdict.score.saturation, 0.5)
        self.assertEqual(verdict.score.patch_proximity, 0.5)
        self.assertEqual(verdict.score.shipped_coverage, 0.5)
        self.assertFalse(verdict.suppressed)

    async def test_RA_DUP_001_score_metadata_fallback(self) -> None:
        finding = Finding(
            crash=CrashInput(id="score-meta", kind="meta", metadata={"frames": [dict(STACK[0])]}),
            bug_class="uaf",
            metadata={"saturation": 0.8, "patch_proximity": 0.6, "shipped_coverage": 0.2},
        )
        verdict = await self.oracle.check(finding)
        self.assertAlmostEqual(verdict.score.total, 0.73)
        self.assertEqual(verdict.score.saturation, 0.8)

    async def test_RA_DUP_001_patch_proximity_from_ring_diff(self) -> None:
        patch = parse_unified_diff(RING_DIFF, source="ring-17", ring_node="node-17")
        self.assertEqual(patch.ring_node, "node-17")
        self.assertIn("src/libfoo.dylib", patch.paths)
        self.assertIn("foo_parse", patch.symbols)
        self.assertNotIn("if", patch.symbols)

        finding = Finding(
            crash=CrashInput(id="patch-prox", kind="ips", payload=TEXT_CRASH.encode("utf-8")),
            bug_class="uaf",
            patch_texts=(RING_DIFF,),
            saturation=0.0,
            shipped_coverage=1.0,
        )
        patches = finding_patches(finding)
        self.assertEqual(len(patches), 1)
        signature = signature_for_finding(finding, bug_class="uaf")
        expected_proximity = 19.0 / 30.0
        self.assertAlmostEqual(patch_proximity_for_finding(finding, signature) or 0.0, expected_proximity)
        self.assertAlmostEqual(patch_proximity(patch, signature), expected_proximity)

        verdict = await self.oracle.check(finding)
        self.assertAlmostEqual(verdict.score.patch_proximity, expected_proximity)
        self.assertAlmostEqual(verdict.score.total, 0.35 * expected_proximity)

        other = PatchDiff(paths=("src/other.dylib",), symbols=("unrelated",))
        self.assertEqual(patch_similarity(patch, other), 0.0)
        self.assertIsNone(max_patch_similarity((patch,), ()))
        self.assertIsNone(max_patch_similarity((), (patch,)))

    async def test_RA_DUP_002_submission_ordering_never_suppresses(self) -> None:
        candidates = [
            SubmissionCandidate(id="a", canonical_id="ka", score=0.5, is_duplicate=False, created_ms=1),
            SubmissionCandidate(id="b", canonical_id="kb", score=0.9, is_duplicate=True, created_ms=2),
            SubmissionCandidate(id="c", canonical_id="kc", score=0.4, is_duplicate=False, created_ms=3),
            SubmissionCandidate(id="d", canonical_id="kd", score=0.5, is_duplicate=True, created_ms=4),
            SubmissionCandidate(id="e", canonical_id="ke", score=0.9, is_duplicate=False, created_ms=5),
        ]
        ranked = rank_submissions(candidates)
        self.assertEqual([candidate.id for candidate in ranked], ["b", "e", "a", "d", "c"])
        self.assertEqual({candidate.id for candidate in ranked}, {candidate.id for candidate in candidates})

        verdict = await self.oracle.check(text_finding("submit-verdict"))
        self.assertFalse(verdict.suppressed)
        converted = candidates_from_verdicts([verdict])
        self.assertEqual(len(converted), 1)
        self.assertEqual(converted[0].canonical_id, verdict.canonical_id)
        self.assertEqual(converted[0].score, verdict.score.total)

    async def test_exact_duplicate_uses_content_signature_not_instance_ids(self) -> None:
        first = text_finding("instance-1")
        second = text_finding(
            "instance-2",
            crash=CrashInput(
                id="instance-2",
                kind="ips",
                path="/other/path.ips",
                digest="d" * 64,
                payload=TEXT_CRASH.encode("utf-8"),
                created_ms=first.crash.created_ms + 1000,
            ),
        )
        v1 = await self.oracle.check(first)
        v2 = await self.oracle.check(second)
        self.assertFalse(v1.is_duplicate)
        self.assertTrue(v2.is_duplicate)
        self.assertEqual(v2.match_kind, "exact")
        self.assertEqual(v2.canonical_id, v1.canonical_id)
        self.assertEqual(v2.similarity, 1.0)
        self.assertEqual(self.ledger.claim_artifact_count(v2.claim_id or ""), 1)
        self.assertEqual(self.ledger.get_claim(v2.claim_id or "") and self.ledger.get_claim(v2.claim_id or "")["state"], "bound")

    async def test_fuzzy_duplicate_normalized_stack_oldest_canonical_and_bug_class_cap(self) -> None:
        a = Finding(
            crash=metadata_crash("fuzzy-a"),
            bug_class="uaf",
            alloc_site="malloc_small",
            saturation=0.5,
            patch_proximity=0.5,
            shipped_coverage=0.5,
        )
        b = Finding(
            crash=metadata_crash("fuzzy-b"),
            bug_class="uaf",
            alloc_site="malloc_large",
            saturation=0.5,
            patch_proximity=0.5,
            shipped_coverage=0.5,
        )
        c = Finding(
            crash=metadata_crash("fuzzy-c"),
            bug_class="overflow",
            alloc_site="malloc_small",
            saturation=0.5,
            patch_proximity=0.5,
            shipped_coverage=0.5,
        )
        d = Finding(
            crash=metadata_crash("fuzzy-d", process="TestApp"),
            bug_class="uaf",
            alloc_site="malloc_small",
            saturation=0.5,
            patch_proximity=0.5,
            shipped_coverage=0.5,
        )

        va = await self.oracle.check(a)
        vb = await self.oracle.check(b)
        vc = await self.oracle.check(c)
        vd = await self.oracle.check(d)

        self.assertFalse(va.is_duplicate)
        self.assertTrue(vb.is_duplicate)
        self.assertEqual(vb.match_kind, "fuzzy")
        self.assertGreaterEqual(vb.similarity, 0.8)
        self.assertEqual(vb.canonical_id, va.canonical_id)
        self.assertFalse(vc.is_duplicate)
        self.assertNotEqual(vc.canonical_id, va.canonical_id)
        self.assertTrue(vd.is_duplicate)
        self.assertEqual(vd.canonical_id, va.canonical_id)

        sig_a = signature_for_finding(a, bug_class="uaf")
        sig_c = signature_for_finding(c, bug_class="overflow")
        self.assertLessEqual(signature_similarity(sig_a, sig_c).score, 0.49)

        rows = self.ledger.claims_by_type("dupe_score")
        records = [DupeRecord.from_row(row) for row in rows]
        canonical = [record for record in records if record is not None and record.record_kind == "canonical"]
        self.assertEqual(len(canonical), 2)

    async def test_ledger_reopen_persists_canonical_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.sqlite"
            ledger = await Ledger.open(path)
            try:
                first = await DupeOracle(ledger).check(text_finding("persist-1"))
            finally:
                await ledger.close()

            ledger = await Ledger.open(path)
            try:
                second = await DupeOracle(ledger).check(text_finding("persist-2"))
                self.assertTrue(second.is_duplicate)
                self.assertEqual(second.canonical_id, first.canonical_id)
                self.assertEqual(len(ledger.claims_by_type("dupe_score")), 2)
            finally:
                await ledger.close()

    async def test_internal_corpus_overlap_is_artifact_bound(self) -> None:
        # The unbound evidence claims higher coverage, but only artifact-bound
        # evidence may influence shipped_coverage.
        unbound = CorpusEvidence(shipped_coverage=1.0, artifact_ids=())
        bound = CorpusEvidence(shipped_coverage=0.9, artifact_ids=("artifact-1",), source="corpus")
        corpus = StaticCorpus([bound, unbound])
        oracle = DupeOracle(self.ledger, corpus_index=corpus)

        verdict = await oracle.check(
            Finding(
                crash=CrashInput(id="corpus-bound", kind="meta", metadata={"frames": [dict(STACK[0])]}),
                bug_class="oob_read",
                saturation=0.5,
                patch_proximity=0.5,
            )
        )
        self.assertEqual(corpus.calls, 1)
        self.assertEqual(verdict.score.shipped_coverage, 0.9)

    async def test_corpus_evidence_without_artifacts_does_not_score(self) -> None:
        corpus = StaticCorpus([CorpusEvidence(shipped_coverage=0.9, artifact_ids=())])
        oracle = DupeOracle(self.ledger, corpus_index=corpus)
        verdict = await oracle.check(
            Finding(
                crash=CrashInput(id="corpus-unbound-2", kind="meta", metadata={"frames": [dict(STACK[2])]}),
                bug_class="oob_write",
                saturation=0.5,
                patch_proximity=0.5,
            )
        )
        self.assertEqual(corpus.calls, 1)
        self.assertEqual(verdict.score.shipped_coverage, 0.0)

    async def test_explicit_shipped_coverage_skips_corpus_index(self) -> None:
        corpus = StaticCorpus([CorpusEvidence(shipped_coverage=0.9, artifact_ids=("artifact-1",))])
        oracle = DupeOracle(self.ledger, corpus_index=corpus)
        verdict = await oracle.check(text_finding("explicit-shipped", shipped_coverage=0.25))
        self.assertEqual(corpus.calls, 0)
        self.assertEqual(verdict.score.shipped_coverage, 0.25)

    async def test_triage_classifier_failure_falls_back_to_metadata(self) -> None:
        oracle = DupeOracle(self.ledger, triage=StaticTriage("kernel_uaf"))
        verdict = await oracle.check(Finding(crash=metadata_crash("triage-static")))
        self.assertEqual(verdict.signature.bug_class, "kernel_uaf")

        failing = DupeOracle(self.ledger, triage=FailingTriage())
        fallback = await failing.check(
            Finding(
                crash=metadata_crash("triage-fallback"),
                metadata={"bug_class": "metadata_class"},
            )
        )
        self.assertEqual(fallback.signature.bug_class, "metadata_class")

        crash_metadata = await self.oracle.check(
            Finding(crash=CrashInput(id="triage-crash-meta", kind="meta", metadata={"bug_class": "crash_class"}))
        )
        self.assertEqual(crash_metadata.signature.bug_class, "crash_class")

    async def test_patch_provider_and_submission_queue_interfaces(self) -> None:
        oracle = DupeOracle(self.ledger, patch_provider=StaticPatchProvider(0.7))
        verdict = await oracle.check(
            Finding(
                crash=CrashInput(id="provider-patch", kind="meta", metadata={"frames": [dict(STACK[0])]}),
                bug_class="uaf",
                saturation=0.5,
                shipped_coverage=0.5,
            )
        )
        self.assertEqual(verdict.score.patch_proximity, 0.7)

        failing = DupeOracle(self.ledger, patch_provider=FailingPatchProvider())
        failed = await failing.check(
            Finding(
                crash=CrashInput(id="provider-fail", kind="meta", metadata={"frames": [dict(STACK[1])]}),
                bug_class="uaf",
                saturation=0.5,
                shipped_coverage=0.5,
            )
        )
        self.assertEqual(failed.score.patch_proximity, 0.0)

        queue = RecordingQueue()
        queued = DupeOracle(self.ledger, submission_queue=queue)
        candidate = SubmissionCandidate(
            id="candidate-1",
            canonical_id="dupc_test",
            score=0.8,
            is_duplicate=False,
            created_ms=1,
        )
        self.assertEqual(await queued.enqueue_submission(candidate), "queue-1")
        self.assertEqual(queue.items, [candidate])
        self.assertEqual(await queued.rank([candidate]), [candidate])

    async def test_structural_adapters_payload_kinds_and_patch_texts(self) -> None:
        json_finding = Finding(crash=CrashInput(id="json-crash", kind="ips", payload=JSON_CRASH), bug_class="uaf")
        json_sig = signature_for_finding(json_finding, bug_class="uaf")
        self.assertEqual(json_sig.process, "TestApp")
        self.assertEqual(json_sig.exception_type, "EXC_BAD_ACCESS")
        self.assertEqual(json_sig.signal, "11")
        self.assertEqual(json_sig.frames[0].module, "libfoo.dylib")
        self.assertEqual(json_sig.frames[0].function, "foo_parse")
        self.assertEqual(json_sig.frames[0].detail, "line:12")

        text_sig = signature_for_finding(
            Finding(crash=CrashInput(id="text-crash", kind="ips", payload=TEXT_CRASH.encode("utf-8")), bug_class="uaf"),
            bug_class="uaf",
        )
        self.assertEqual(text_sig.process, "TestApp")
        self.assertEqual(text_sig.frames[0].module, "libfoo.dylib")
        self.assertEqual(text_sig.frames[0].function, "foo_parse")
        self.assertEqual(text_sig.frames[0].detail, "")

        meta_sig = signature_for_finding(
            Finding(crash=metadata_crash("meta-sig"), bug_class="uaf"), bug_class="uaf"
        )
        self.assertEqual(meta_sig.frames[0].module, "libfoo.dylib")
        self.assertEqual(stack_similarity(meta_sig, meta_sig), 1.0)

        crash_ref = SimpleNamespace(
            id="ref-1",
            kind="fake",
            path="/tmp/ref.ips",
            payload=TEXT_CRASH.encode("utf-8"),
            metadata={},
            created_ms=123,
        )
        finding_obj = SimpleNamespace(
            crash=crash_ref,
            bug_class="uaf",
            saturation=0.25,
            patch_proximity=None,
            shipped_coverage=None,
            patches=(),
            patch_texts=(RING_DIFF,),
            created_ms=124,
            metadata={},
        )
        adapted = Finding.from_object(finding_obj)
        self.assertEqual(adapted.crash.id, "ref-1")
        self.assertEqual(adapted.bug_class, "uaf")
        self.assertEqual(adapted.patch_texts, (RING_DIFF,))

        mapped = Finding.from_object(
            {
                "crash": {"id": "map-1", "kind": "ips", "payload": TEXT_CRASH},
                "bug_class": "oob_read",
                "patch_texts": [RING_DIFF],
                "metadata": {"saturation": 0.3},
            }
        )
        self.assertEqual(mapped.crash.id, "map-1")
        self.assertEqual(mapped.bug_class, "oob_read")
        self.assertEqual(mapped.patch_texts, (RING_DIFF,))
        self.assertEqual(mapped.metadata["saturation"], 0.3)

    async def test_store_record_roundtrip_and_invalid_rows(self) -> None:
        finding = Finding(crash=metadata_crash("store-roundtrip"), bug_class="uaf")
        signature = signature_for_finding(finding, bug_class="uaf")
        patch = parse_unified_diff(RING_DIFF, source="test")
        score = DupeScore(saturation=0.5, patch_proximity=0.5, shipped_coverage=0.5, total=0.5)
        record = DupeRecord(
            claim_id="claim-1",
            dedup_key="dupe:test",
            record_kind="canonical",
            canonical_id="dupc_test",
            created_ms=42,
            signature=signature,
            patches=(patch,),
            score=score,
            is_duplicate=False,
            match_kind="new",
            similarity=1.0,
            source_id="store-roundtrip",
        )
        row = {
            "id": "claim-1",
            "dedup_key": "dupe:test",
            "created": 42,
            "value_json": record.to_value_json(),
        }
        restored = DupeRecord.from_row(row)
        self.assertIsNotNone(restored)
        assert restored is not None
        self.assertEqual(restored.record_kind, "canonical")
        self.assertEqual(restored.canonical_id, "dupc_test")
        self.assertEqual(restored.signature.signature_hash, signature.signature_hash)
        self.assertEqual(restored.patches, (patch,))
        self.assertEqual(restored.score, score)

        self.assertIsNone(DupeRecord.from_row({"value_json": "{"}))
        self.assertIsNone(DupeRecord.from_row({"value_json": "{}"}))
        self.assertIsNone(DupeRecord.from_row({"value_json": json.dumps({"schema": "other"})}))
        self.assertEqual(canonical_id_for_signature("abc"), "dupc_abc")
        self.assertEqual(canonical_dedup_key("abc"), "dupe:canonical:abc")

    async def test_failure_injection_store_failure_propagates(self) -> None:
        oracle = DupeOracle(self.ledger, store=ExplodingStore())
        with self.assertRaises(FormatFail):
            await oracle.check(text_finding("exploding-store"))

    async def test_signature_similarity_bounds_and_optional_patch_term(self) -> None:
        finding = Finding(crash=metadata_crash("sim-bounds"), bug_class="uaf", alloc_site="malloc_small")
        signature = signature_for_finding(finding, bug_class="uaf")
        same = signature_similarity(signature, signature)
        self.assertEqual(same.score, 1.0)
        self.assertIsNone(same.patch)
        patched = signature_similarity(signature, signature, patch_similarity=0.5)
        self.assertEqual(patched.patch, 0.5)
        self.assertGreaterEqual(patched.score, 0.0)
        self.assertLessEqual(patched.score, 1.0)

        empty = signature_for_finding(Finding(crash=CrashInput(id="empty"), bug_class="unknown"), bug_class="unknown")
        self.assertEqual(stack_similarity(empty, empty), 0.5)
        self.assertGreaterEqual(signature_similarity(empty, empty).score, 0.0)
        self.assertLessEqual(signature_similarity(empty, empty).score, 1.0)

    async def test_property_score_bounds_and_rank_never_drops_claims(self) -> None:
        rng = random.Random(20261122)
        for _ in range(250):
            saturation = rng.uniform(-2.0, 2.0) if rng.random() < 0.9 else math.nan
            patch = rng.uniform(-2.0, 2.0) if rng.random() < 0.9 else math.inf
            shipped = rng.uniform(-2.0, 2.0) if rng.random() < 0.9 else -math.inf
            total = compute_dupe_score(saturation, patch, shipped)
            self.assertGreaterEqual(total, 0.0)
            self.assertLessEqual(total, 1.0)

        candidates = [
            SubmissionCandidate(
                id=f"candidate-{index}",
                canonical_id=f"canonical-{index % 3}",
                score=rng.choice([0.1, 0.4, 0.4, 0.7, 0.7, 0.9]),
                is_duplicate=index % 2 == 0,
                created_ms=index,
            )
            for index in range(40)
        ]
        ranked = rank_submissions(candidates)
        self.assertEqual(len(ranked), len(candidates))
        self.assertEqual({candidate.id for candidate in ranked}, {candidate.id for candidate in candidates})
        scores = [candidate.score for candidate in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))
        positions = {candidate.id: index for index, candidate in enumerate(candidates)}
        for score in set(scores):
            ids = [candidate.id for candidate in ranked if candidate.score == score]
            self.assertEqual(ids, sorted(ids, key=positions.__getitem__))

    async def test_edge_empty_crash_becomes_new_unknown_canonical(self) -> None:
        verdict = await self.oracle.check({})
        self.assertFalse(verdict.is_duplicate)
        self.assertEqual(verdict.match_kind, "new")
        self.assertEqual(verdict.signature.bug_class, "unknown")
        self.assertEqual(verdict.signature.frames, ())
        self.assertFalse(verdict.suppressed)

    async def test_model_adapters_and_serialization_edges(self) -> None:
        crash = CrashInput(id="direct", payload=b"payload")
        self.assertIs(CrashInput.from_object(crash), crash)

        patch_obj = SimpleNamespace(
            paths=["src/a.dylib", "src/b.dylib"],
            symbols="foo_bar",
            source="obj",
            ring_node="node",
            text_hash="hash",
        )
        adapted_patch = PatchDiff.from_object(patch_obj)
        assert adapted_patch is not None
        self.assertEqual(adapted_patch.paths, ("src/a.dylib", "src/b.dylib"))
        self.assertEqual(adapted_patch.symbols, ("foo_bar",))
        self.assertEqual(adapted_patch.text_hash, "hash")
        self.assertEqual(adapted_patch.fingerprint(), "hash")
        self.assertIsNone(PatchDiff.from_object(SimpleNamespace()))
        patch_instance = PatchDiff(paths=("x",), symbols=("y",))
        self.assertIs(PatchDiff.from_object(patch_instance), patch_instance)
        self.assertIsNone(PatchDiff.from_object(None))
        scalar_patch = PatchDiff.from_object(SimpleNamespace(paths=5, symbols={"bad": "dict"}))
        assert scalar_patch is not None
        self.assertEqual(scalar_patch.paths, ("5",))
        self.assertEqual(scalar_patch.symbols, ())
        self.assertEqual(PatchDiff().fingerprint(), PatchDiff(paths=(), symbols=()).fingerprint())
        mapped_patch = PatchDiff.from_object({"files": ["a"], "identifiers": ["sym"], "name": "n"})
        assert mapped_patch is not None
        self.assertEqual(mapped_patch.paths, ("a",))
        self.assertEqual(mapped_patch.symbols, ("sym",))
        self.assertEqual(mapped_patch.source, "n")

        mapped_only = Finding.from_object({"bug_class": "mapped_only"})
        self.assertEqual(mapped_only.bug_class, "mapped_only")
        self.assertTrue(mapped_only.crash.id.startswith("crash_"))

        payload_adapted = CrashInput.from_object(
            {"id": "payload-edges", "payload": memoryview(b"abc"), "metadata": "bad", "created_ms": "42", "kind": 7}
        )
        self.assertEqual(payload_adapted.payload, b"abc")
        self.assertEqual(payload_adapted.metadata, {})
        self.assertEqual(payload_adapted.created_ms, 42)
        self.assertEqual(payload_adapted.kind, "7")
        self.assertEqual(CrashInput.from_object({"id": "str-payload", "payload": "text"}).payload, b"text")
        self.assertEqual(CrashInput.from_object({"id": "bytearray", "payload": bytearray(b"xy")}).payload, b"xy")
        self.assertEqual(CrashInput.from_object({"id": "bad-kind", "kind": {"bad": "dict"}}).kind, "unknown")
        self.assertEqual(CrashInput.from_object({"id": "bad-payload", "payload": object()}).payload, b"")
        bool_created = CrashInput.from_object({"id": "bool-created", "created_ms": True}).created_ms
        self.assertIsInstance(bool_created, int)
        self.assertGreater(bool_created, 0)
        self.assertEqual(CrashInput.from_object({"id": "float-created", "created_ms": 12.9}).created_ms, 12)
        self.assertGreater(CrashInput.from_object({"id": "bad-created", "created_ms": "bad"}).created_ms, 0)
        bare = Finding.from_object(SimpleNamespace(metadata={"bug_class": "bare_class"}))
        self.assertIsNone(bare.bug_class)
        self.assertEqual(bare.crash.metadata["bug_class"], "bare_class")
        self.assertTrue(bare.crash.id.startswith("crash_"))

        score_flags = Finding.from_object(
            {
                "crash": {"id": "score-flags", "kind": "meta", "metadata": {"frames": [dict(STACK[0])]}},
                "bug_class": "uaf",
                "saturation": True,
                "patch_proximity": "bad",
                "shipped_coverage": {"bad": "mapping"},
            }
        )
        self.assertEqual(score_flags.saturation, 0.0)
        self.assertEqual(score_flags.patch_proximity, 0.0)
        self.assertEqual(score_flags.shipped_coverage, 0.0)

        signature_dict = minimal_signature("roundtrip").to_dict()
        signature_dict["frames"] = [{"module": "m", "function": "f"}, "bad", 3]
        restored_signature = CrashSignature.from_dict(signature_dict)
        self.assertEqual(len(restored_signature.frames), 1)
        self.assertEqual(restored_signature.frames[0].module, "m")

        rich = Finding.from_object(
            {
                "crash": {"id": "patch-edge", "kind": "meta", "metadata": {"frames": [dict(STACK[0])]}},
                "bug_class": "uaf",
                "patches": [
                    PatchDiff(paths=("a",)),
                    {"paths": ["b"], "symbols": ["sym"]},
                    "diff --git a/x b/x\n+foo_bar\n",
                    [SimpleNamespace(paths=["c"])],
                    None,
                    b"bytes",
                ],
                "patch_texts": ("diff --git a/y b/y\n+bar_baz\n",),
            }
        )
        self.assertEqual(len(rich.patches), 3)
        self.assertEqual(len(rich.patch_texts), 2)
        self.assertEqual(len(finding_patches(rich)), 5)

    async def test_null_interfaces(self) -> None:
        triage = NullTriageClassifier()
        self.assertEqual(
            await triage.classify(Finding(crash=CrashInput(id="n1"), bug_class="  explicit_class  ")),
            "explicit_class",
        )
        self.assertEqual(
            await triage.classify(Finding(crash=CrashInput(id="n2"), metadata={"bugClass": " meta_class "})),
            "meta_class",
        )
        self.assertEqual(
            await triage.classify(Finding(crash=CrashInput(id="n3"), metadata={"class": "class_value"})),
            "class_value",
        )
        self.assertEqual(
            await triage.classify(
                Finding(crash=CrashInput(id="n4", metadata={"bug_class": "crash_class"}))
            ),
            "crash_class",
        )
        self.assertEqual(await triage.classify(Finding(crash=CrashInput(id="n5"))), "unknown")

        signature = minimal_signature("null-signature")
        self.assertIsNone(await NullPatchProximityProvider().proximity(Finding(crash=CrashInput(id="n6")), signature))
        self.assertEqual(await NullCorpusIndex().evidence(Finding(crash=CrashInput(id="n7")), signature), ())
        candidate = SubmissionCandidate(id="null-candidate", canonical_id="dupc_null", score=0.1, is_duplicate=False, created_ms=1)
        self.assertEqual(await NullSubmissionQueue().enqueue(candidate), "stub:null-candidate")

    async def test_patch_parser_and_similarity_edges(self) -> None:
        diff = (
            "diff --git a/old\\name b/new//path\n"
            "--- a/old\\name\n"
            "+++ b/new//path\n"
            "--- /dev/null\n"
            "+++ b/created.txt\n"
            "@@ -1 +1 @@\n"
            "+if (foo_bar) { return options; }\n"
        )
        patch = parse_unified_diff(diff, source="edge")
        self.assertTrue(patch.has_evidence)
        self.assertIn("old/name", patch.paths)
        self.assertIn("new/path", patch.paths)
        self.assertIn("created.txt", patch.paths)
        self.assertNotIn("/dev/null", patch.paths)
        self.assertIn("foo_bar", patch.symbols)
        self.assertIn("options", patch.symbols)
        self.assertNotIn("if", patch.symbols)
        self.assertNotIn("return", patch.symbols)
        self.assertFalse(parse_unified_diff("").has_evidence)
        blank_patch = parse_unified_diff("\n+++ b/blank.dylib\n\n-foo\n+bar\n")
        self.assertIn("blank.dylib", blank_patch.paths)
        self.assertIn("foo", blank_patch.symbols)
        self.assertIn("bar", blank_patch.symbols)
        many_patch = parse_unified_diff("\n".join(f"+sym{i:04d}" for i in range(600)))
        self.assertEqual(len(many_patch.symbols), 512)

        path_only = PatchDiff(paths=("a",))
        symbols_only = PatchDiff(symbols=("s",))
        both = PatchDiff(paths=("a",), symbols=("s",))
        self.assertEqual(patch_similarity(PatchDiff(), both), 0.0)
        self.assertAlmostEqual(patch_similarity(path_only, PatchDiff(paths=("a",))), 0.65)
        self.assertEqual(patch_similarity(symbols_only, PatchDiff(symbols=("s",))), 1.0)
        self.assertEqual(patch_similarity(both, both), 1.0)
        self.assertEqual(patch_similarity(path_only, symbols_only), 0.0)

        signature = signature_for_finding(
            Finding(
                crash=metadata_crash("patch-edge", frames=({"module": "libfoo.dylib", "function": "foo_parse"},)),
                bug_class="uaf",
            ),
            bug_class="uaf",
        )
        path_patch = PatchDiff(paths=("src/libfoo.dylib",))
        symbol_patch = PatchDiff(symbols=("foo_parse",))
        self.assertAlmostEqual(patch_proximity(path_patch, signature), 0.45)
        self.assertAlmostEqual(patch_proximity(symbol_patch, signature), 0.55)
        self.assertEqual(patch_proximity(PatchDiff(), signature), 0.0)
        self.assertEqual(patch_proximity(both, minimal_signature("no-frames")), 0.0)
        self.assertIsNone(max_patch_proximity((PatchDiff(),), signature))
        self.assertAlmostEqual(max_patch_proximity((PatchDiff(), path_patch), signature) or 0.0, 0.45)
        self.assertEqual(max_patch_similarity((both,), (PatchDiff(), symbols_only)), 1.0)
        self.assertIsNone(max_patch_similarity((PatchDiff(),), (both,)))

        finding_a = Finding(
            crash=CrashInput(id="pa", kind="meta", metadata={"frames": [dict(STACK[0])]}),
            bug_class="uaf",
            patch_texts=(RING_DIFF,),
        )
        finding_b = Finding(
            crash=CrashInput(id="pb", kind="meta", metadata={"frames": [dict(STACK[0])]}),
            bug_class="uaf",
            patches=(parse_unified_diff(RING_DIFF, source="x"),),
        )
        finding_c = Finding(
            crash=CrashInput(id="pc", kind="meta", metadata={"frames": [dict(STACK[0])]}),
            bug_class="uaf",
            patches=(PatchDiff(),),
        )
        self.assertEqual(patch_similarity_for_findings(finding_a, finding_b), 1.0)
        self.assertIsNone(patch_similarity_for_findings(finding_a, finding_c))
        self.assertAlmostEqual(patch_proximity_for_finding(finding_b, signature_for_finding(finding_b, bug_class="uaf")) or 0.0, 19.0 / 30.0)

    async def test_json_crash_edge_variants(self) -> None:
        def signature_for_payload(payload: bytes, crash_id: str = "json-edge") -> Any:
            finding = Finding(crash=CrashInput(id=crash_id, kind="ips", payload=payload), bug_class="uaf")
            return signature_for_finding(finding, bug_class="uaf")

        termination = signature_for_payload(
            json.dumps(
                {
                    "termination": {"namespace": "EXC", "reason": "BAD_ACCESS", "code": "1"},
                    "procName": "TermApp",
                    "threads": [{"frames": [{"symbol": "term_func", "module": "libterm.dylib"}]}],
                }
            ).encode()
        )
        self.assertEqual(termination.exception_type, "EXC BAD_ACCESS 1")
        self.assertEqual(termination.process, "TermApp")
        self.assertEqual(termination.frames[0].module, "libterm.dylib")

        sigbus = signature_for_payload(
            json.dumps(
                {
                    "exception": "SIGBUS",
                    "procName": "SigApp",
                    "threads": [{"frames": [{"function": "sig_func"}]}],
                }
            ).encode()
        )
        self.assertEqual(sigbus.exception_type, "SIGBUS")
        self.assertEqual(sigbus.signal, "SIGBUS")
        self.assertEqual(sigbus.frames[0].module, "unknown")
        self.assertEqual(sigbus.frames[0].function, "sig_func")

        images = signature_for_payload(
            json.dumps(
                {
                    "signal": 9,
                    "usedImages": ["libone.dylib"],
                    "faultingThread": 5,
                    "threads": [
                        {
                            "frames": [
                                {"imageIndex": 3, "symbol": "img_func", "lineNumber": 7},
                                {"imageIndex": 0, "name": "named_func"},
                            ]
                        }
                    ],
                }
            ).encode()
        )
        self.assertEqual(images.signal, "9")
        self.assertEqual(images.frames[0].detail, "line:7")
        self.assertEqual(images.frames[0].module, "unknown")
        self.assertEqual(images.frames[1].module, "libone.dylib")
        self.assertEqual(images.frames[1].function, "named_func")

        prefixed = signature_for_payload(
            b'log line\n{"exception":{"type":"EXC","code":"2"},"process":"PrefApp","threads":[{"frames":[{"symbol":"pref_func","imageName":"libpref.dylib"}]}]}'
        )
        self.assertEqual(prefixed.exception_type, "EXC")
        self.assertEqual(prefixed.process, "PrefApp")
        self.assertEqual(prefixed.frames[0].module, "libpref.dylib")

        bad_threads = signature_for_payload(json.dumps({"threads": "bad", "exception": {"type": "EXC_X"}}).encode())
        self.assertEqual(bad_threads.frames, ())
        self.assertEqual(bad_threads.process, "ips")
        bad_frames = signature_for_payload(
            json.dumps({"threads": [{"frames": "bad"}], "exception": {"type": "EXC_Y"}}).encode()
        )
        self.assertEqual(bad_frames.frames, ())
        self.assertEqual(bad_frames.exception_type, "EXC_Y")

    async def test_text_crash_edge_variants(self) -> None:
        multi_thread = (
            "Exception Type: EXC_BAD_ACCESS\n"
            "Process: MultiApp\n"
            "Thread 0 Crashed:\n"
            "0   libfoo.dylib   0x000000010  foo_parse + 12\n"
            "Thread 1:\n"
            "1   libbar.dylib   0x000000020  bar_handle + 34\n"
        )
        multi = signature_for_finding(
            Finding(crash=CrashInput(id="multi", kind="ips", payload=multi_thread.encode()), bug_class="uaf"),
            bug_class="uaf",
        )
        self.assertEqual(len(multi.frames), 1)
        self.assertEqual(multi.frames[0].function, "foo_parse")

        plain = (
            "Process: PlainApp\n"
            "0 libfoo.dylib 0x1 foo_parse + 12\n"
            "1 libbar.dylib 0x2 bar_handle\n"
        )
        plain_sig = signature_for_finding(
            Finding(crash=CrashInput(id="plain", kind="ips", payload=plain.encode()), bug_class="uaf"),
            bug_class="uaf",
        )
        self.assertEqual(plain_sig.process, "PlainApp")
        self.assertEqual({frame.module for frame in plain_sig.frames}, {"libfoo.dylib", "libbar.dylib"})

        frames_text = (
            "Process: FrameApp\n"
            "0 0x0001 libalpha.dylib 0x0002 alpha_func + 0x10\n"
            "1 libbeta.dylib!beta_func extra words\n"
            "2 libgamma.dylib 0x0003 gamma_func\n"
            "3 libdelta.dylib delta_func 0x0004\n"
            "4 single_function\n"
            "5 libepsilon.dylib\n"
            "6 notamodule 0x0006\n"
            "7 libz.dylib 0x0007\n"
        )
        frame_sig = signature_for_finding(
            Finding(crash=CrashInput(id="frames", kind="ips", payload=frames_text.encode()), bug_class="uaf"),
            bug_class="uaf",
        )
        self.assertEqual(len(frame_sig.frames), 7)
        self.assertIn("libalpha.dylib", {frame.module for frame in frame_sig.frames})
        self.assertIn("libbeta.dylib", {frame.module for frame in frame_sig.frames})
        self.assertIn("alpha_func", {frame.function for frame in frame_sig.frames})
        self.assertIn("gamma_func", {frame.function for frame in frame_sig.frames})
        self.assertIn("delta_func", {frame.function for frame in frame_sig.frames})
        self.assertIn("single_function", {frame.function for frame in frame_sig.frames})
        self.assertIn("libz.dylib", {frame.module for frame in frame_sig.frames})

    async def test_metadata_crash_edge_variants(self) -> None:
        crash = CrashInput(
            id="meta-edge",
            kind="meta",
            metadata={
                "exception_type": 123,
                "exception_code": True,
                "signal": 11,
                "process": "MetaApp",
                "alloc_site": "malloc_zone",
                "frames": [
                    {"module": "/usr/lib/libmeta.dylib", "function": "meta_func", "symbol": "ignored"},
                    {"function": "only_func"},
                    {},
                    "libstr.dylib!str_func + 1",
                    42,
                ],
                "stack": "Thread 0 Crashed:\n0 libstack.dylib 0x1 stack_func + 1\n",
            },
        )
        signature = signature_for_finding(Finding(crash=crash, bug_class="uaf"), bug_class="uaf")
        self.assertEqual(signature.exception_type, "123")
        self.assertEqual(signature.exception_code, "")
        self.assertEqual(signature.signal, "11")
        self.assertEqual(signature.process, "MetaApp")
        self.assertEqual(signature.alloc_site, "malloc_zone")
        self.assertIn("meta_func", {frame.function for frame in signature.frames})
        self.assertIn("only_func", {frame.function for frame in signature.frames})
        self.assertIn("str_func", {frame.function for frame in signature.frames})
        self.assertIn("stack_func", {frame.function for frame in signature.frames})
        self.assertIn("libmeta.dylib", {frame.module for frame in signature.frames})

    async def test_similarity_helper_edges(self) -> None:
        def custom_signature(
            crash_id: str,
            *,
            exception_type: str = "",
            exception_code: str = "",
            signal: str = "",
            alloc_site: str | None = None,
            bug_class: str = "uaf",
            context: str = "app",
        ) -> Any:
            return signature_for_finding(
                Finding(
                    crash=CrashInput(
                        id=crash_id,
                        kind="meta",
                        context=context,
                        metadata={
                            "exception_type": exception_type,
                            "exception_code": exception_code,
                            "signal": signal,
                            "process": "SimApp",
                            "frames": [dict(STACK[0])],
                        },
                    ),
                    bug_class=bug_class,
                    alloc_site=alloc_site,
                ),
                bug_class=bug_class,
            )

        a = custom_signature("sim-a", exception_type="AAA", exception_code="111", signal="1", alloc_site="malloc_small")
        b = custom_signature("sim-b", exception_type="BBB", exception_code="222", signal="2", alloc_site="malloc")
        sim = signature_similarity(a, b)
        self.assertEqual(sim.exception, 0.5)
        self.assertEqual(sim.alloc_site, 0.75)
        self.assertEqual(sim.bug_class, 1.0)
        self.assertEqual(sim.context, 1.0)

        unknown = custom_signature("sim-unknown", bug_class="unknown")
        self.assertEqual(signature_similarity(a, unknown).bug_class, 0.5)
        kernel = custom_signature("sim-kernel", context="kernel")
        self.assertEqual(signature_similarity(a, kernel).context, 0.4)

        exc_a = custom_signature("exc-a", exception_type="EXC_BAD_ACCESS", exception_code="1", signal="11")
        exc_b = custom_signature("exc-b", exception_type="EXC_BAD", exception_code="1", signal="11")
        self.assertAlmostEqual(signature_similarity(exc_a, exc_b).exception, 0.8)

        empty = minimal_signature("empty-stack")
        self.assertEqual(stack_similarity(empty, a), 0.0)
        self.assertEqual(stack_similarity(a, empty), 0.0)
        detail_a = replace(
            minimal_signature("detail-a"),
            frames=(NormalizedFrame(module="m", function="f", detail="line:1"),),
        )
        detail_b = replace(
            minimal_signature("detail-b"),
            frames=(NormalizedFrame(module="m", function="f", detail="line:2"),),
        )
        self.assertAlmostEqual(stack_similarity(detail_a, detail_b), 0.8125)

    async def test_oracle_threshold_aliases_and_dependency_failures(self) -> None:
        with self.assertRaises(ValueError):
            DupeOracle(self.ledger, duplicate_threshold=1.1)

        first = await self.oracle.check_finding(text_finding("alias-1"))
        second = await self.oracle.dedup(text_finding("alias-2"))
        self.assertTrue(second.is_duplicate)
        self.assertEqual(second.canonical_id, first.canonical_id)

        corpus_down = DupeOracle(self.ledger, corpus_index=FailingCorpus())
        corpus_verdict = await corpus_down.check(
            Finding(
                crash=CrashInput(id="corpus-down", kind="meta", metadata={"frames": [dict(STACK[0])]}),
                bug_class="uaf",
                saturation=0.5,
                patch_proximity=0.5,
            )
        )
        self.assertEqual(corpus_verdict.score.shipped_coverage, 0.0)

        bool_metadata = await self.oracle.check(
            Finding(
                crash=CrashInput(id="bool-meta", kind="meta", metadata={"frames": [dict(STACK[1])]}),
                bug_class="uaf",
                metadata={"saturation": True, "patch_proximity": False, "shipped_coverage": "bad"},
            )
        )
        self.assertEqual(bool_metadata.score.saturation, 0.0)
        self.assertEqual(bool_metadata.score.patch_proximity, 0.0)
        self.assertEqual(bool_metadata.score.shipped_coverage, 0.0)

        failing_triage = DupeOracle(self.ledger, triage=FailingTriage())
        unknown_class = await failing_triage.check(
            Finding(
                crash=CrashInput(id="unknown-class", kind="meta", metadata={"bugClass": {"bad": "value"}}),
                metadata={"bug_class": 123},
            )
        )
        self.assertEqual(unknown_class.signature.bug_class, "unknown")

    async def test_oracle_collision_and_observation_retry(self) -> None:
        collision = DupeOracle(self.ledger, store=CollisionStore())
        verdict = await collision.check(text_finding("collision"))
        self.assertTrue(verdict.is_duplicate)
        self.assertEqual(verdict.match_kind, "exact")
        self.assertEqual(verdict.canonical_id, "dupc_existing")
        self.assertEqual(verdict.claim_id, "obs-collision")

        store = MemoryStore(observation_failures=1)
        oracle = DupeOracle(self.ledger, store=store)
        first = await oracle.check(text_finding("retry"))
        second = await oracle.check(text_finding("retry-2"))
        self.assertFalse(first.is_duplicate)
        self.assertTrue(second.is_duplicate)
        self.assertEqual(second.claim_id, "obs-2")
        self.assertEqual(store.observation_calls, 2)

    async def test_fuzzy_scan_skips_hidden_exact_signature(self) -> None:
        finding = text_finding("hidden-exact")
        signature = signature_for_finding(finding, bug_class="uaf")
        hidden = DupeRecord(
            claim_id="hidden-claim",
            dedup_key=canonical_dedup_key(signature.signature_hash),
            record_kind="canonical",
            canonical_id="dupc_hidden",
            created_ms=1,
            signature=signature,
        )
        store = HiddenCanonicalStore()
        store.records.append(hidden)
        oracle = DupeOracle(self.ledger, store=store)

        verdict = await oracle.check(finding)

        self.assertFalse(verdict.is_duplicate)
        self.assertEqual(verdict.match_kind, "new")
        self.assertEqual(verdict.canonical_id, canonical_id_for_signature(signature.signature_hash))
        self.assertEqual(store.records[0], hidden)
        self.assertEqual(len(store.records), 2)

    async def test_fuzzy_best_match_prefers_highest_similarity(self) -> None:
        def finding_for(crash_id: str, alloc_site: str, exception_code: str, context: str) -> Finding:
            return Finding(
                crash=metadata_crash(crash_id, exception_code=exception_code, context=context),
                bug_class="uaf",
                alloc_site=alloc_site,
                saturation=0.5,
                patch_proximity=0.5,
                shipped_coverage=0.5,
            )

        store = MemoryStore()
        oracle = DupeOracle(self.ledger, store=store)
        vb = await oracle.check(finding_for("best-b", "malloc_large", "1", "app"))
        va = await oracle.check(finding_for("best-a", "malloc_small", "2", "kernel"))
        vn = await oracle.check(finding_for("best-new", "malloc_small", "1", "kernel"))
        self.assertFalse(vb.is_duplicate)
        self.assertFalse(va.is_duplicate)
        self.assertTrue(vn.is_duplicate)
        self.assertEqual(vn.match_kind, "fuzzy")
        self.assertEqual(vn.canonical_id, va.canonical_id)
        self.assertGreater(vn.similarity, 0.8)

    async def test_store_record_invalid_shapes_and_confidence_clamps(self) -> None:
        finding = Finding(crash=metadata_crash("store-invalid"), bug_class="uaf")
        signature = signature_for_finding(finding, bug_class="uaf")
        payload = {
            "schema": "ra.dupe.v1",
            "record_kind": "canonical",
            "canonical_id": "dupc_invalid",
            "created_ms": True,
            "signature": {"signature_hash": "h", "frames": [{"module": "m"}, "bad", 3]},
            "patches": [{"paths": ["a"]}, 42, "bad"],
            "score": {"saturation": True, "patch_proximity": "bad", "shipped_coverage": 2.0, "total": -1.0},
            "is_duplicate": "yes",
            "match_kind": 3,
            "similarity": "bad",
            "source_id": None,
        }
        restored = DupeRecord.from_row({"id": "r", "dedup_key": "d", "created": 1.5, "value_json": json.dumps(payload)})
        assert restored is not None
        self.assertEqual(restored.created_ms, 0)
        self.assertEqual(len(restored.patches), 1)
        self.assertEqual(restored.score.saturation if restored.score else None, 0.0)
        self.assertEqual(restored.score.shipped_coverage if restored.score else None, 1.0)
        self.assertEqual(restored.score.total if restored.score else None, 0.0)
        self.assertEqual(restored.similarity, 1.0)
        self.assertTrue(restored.is_duplicate)
        self.assertEqual(restored.match_kind, "3")
        self.assertEqual(restored.source_id, "None")
        bool_payload = dict(payload)
        bool_payload["similarity"] = True
        bool_restored = DupeRecord.from_row({"id": "r2", "dedup_key": "d2", "created": 2, "value_json": json.dumps(bool_payload)})
        assert bool_restored is not None
        self.assertEqual(bool_restored.similarity, 1.0)

        self.assertIsNone(DupeRecord.from_row({"value_json": json.dumps(["not", "dict"])}))
        self.assertIsNone(
            DupeRecord.from_row(
                {"value_json": json.dumps({"schema": "ra.dupe.v1", "signature": "bad"})}
            )
        )

        store = LedgerDupeStore(self.ledger)
        for index, similarity in enumerate((True, math.nan, -1.0, 2.0)):
            record = DupeRecord(
                claim_id=f"confidence-{index}",
                dedup_key=f"dupe:confidence:{index}",
                record_kind="observation",
                canonical_id="dupc_confidence",
                created_ms=1,
                signature=signature,
                is_duplicate=True,
                match_kind="exact",
                similarity=similarity,  # type: ignore[arg-type]
            )
            await store.save_observation(record, b"{}")
        self.assertEqual(self.ledger.get_claim("confidence-0") and self.ledger.get_claim("confidence-0")["confidence"], 0.0)
        self.assertEqual(self.ledger.get_claim("confidence-1") and self.ledger.get_claim("confidence-1")["confidence"], 0.0)
        self.assertEqual(self.ledger.get_claim("confidence-2") and self.ledger.get_claim("confidence-2")["confidence"], 0.0)
        self.assertEqual(self.ledger.get_claim("confidence-3") and self.ledger.get_claim("confidence-3")["confidence"], 1.0)

        wrong_kind = DupeRecord(
            claim_id="wrong-kind",
            dedup_key=canonical_dedup_key("wrong-kind-hash"),
            record_kind="observation",
            canonical_id="dupc_wrong_kind",
            created_ms=1,
            signature=minimal_signature("wrong-kind-hash"),
            is_duplicate=True,
            match_kind="exact",
            similarity=0.5,
        )
        await store.save_observation(wrong_kind, b"{}")
        self.assertIsNone(await store.get_canonical("wrong-kind-hash"))

    async def test_json_parser_edge_variants(self) -> None:
        def signature_for_payload(payload: bytes, crash_id: str) -> Any:
            finding = Finding(crash=CrashInput(id=crash_id, kind="ips", payload=payload), bug_class="uaf")
            return signature_for_finding(finding, bug_class="uaf")

        whitespace = signature_for_payload(b" \n\t", "json-whitespace")
        self.assertEqual(whitespace.frames, ())
        self.assertEqual(whitespace.process, "ips")

        invalid_then_valid = signature_for_payload(
            b'{bad json\n{"exception":{"type":"EXC_OK"},"procName":"JsonApp","threads":[{"frames":[{"symbol":"json_func"}]}]}',
            "json-invalid-line",
        )
        self.assertEqual(invalid_then_valid.exception_type, "EXC_OK")
        self.assertEqual(invalid_then_valid.process, "JsonApp")
        self.assertEqual(invalid_then_valid.frames[0].function, "json_func")

        termination = signature_for_payload(
            json.dumps(
                {
                    "termination": "Terminated",
                    "procName": "TermApp",
                    "threads": [{"frames": [{"symbol": "term_str"}]}],
                }
            ).encode(),
            "json-termination-string",
        )
        self.assertEqual(termination.exception_type, "Terminated")
        self.assertEqual(termination.frames[0].function, "term_str")

        no_thread = signature_for_payload(
            json.dumps({"threads": [1, 2], "exception": {"type": "EXC_NO_THREAD"}}).encode(),
            "json-no-thread",
        )
        self.assertEqual(no_thread.frames, ())

        empty_frame = signature_for_payload(
            json.dumps({"threads": [{"frames": [{}]}], "exception": {"type": "EXC_EMPTY_FRAME"}}).encode(),
            "json-empty-frame",
        )
        self.assertEqual(empty_frame.frames, ())

        bad_fault = signature_for_payload(
            json.dumps(
                {
                    "faultingThread": True,
                    "usedImages": ["libx.dylib"],
                    "threads": [{"frames": [{"imageIndex": 0, "symbol": "bad_line_func", "lineNumber": True}]}],
                }
            ).encode(),
            "json-bad-fault-line",
        )
        self.assertEqual(bad_fault.frames[0].module, "libx.dylib")
        self.assertEqual(bad_fault.frames[0].function, "bad_line_func")
        self.assertEqual(bad_fault.frames[0].detail, "")

        zero_module = signature_for_payload(
            json.dumps({"threads": [{"frames": [{"imageName": "0x0", "symbol": "zero_func"}]}]}).encode(),
            "json-zero-module",
        )
        self.assertEqual(zero_module.frames[0].module, "unknown")
        self.assertEqual(zero_module.frames[0].function, "zero_func")

    async def test_text_parser_edge_variants(self) -> None:
        def signature_for_text(text: str, crash_id: str) -> Any:
            finding = Finding(crash=CrashInput(id=crash_id, kind="ips", payload=text.encode()), bug_class="uaf")
            return signature_for_finding(finding, bug_class="uaf")

        noisy = (
            "Exception Type: EXC_BAD_ACCESS\n"
            "Termination Reason: Namespace SIGNAL Code 11\n"
            "0 Binary Images:\n"
            "1 OS Version:\n"
            "2 Kernel:\n"
            "0 foo bar\n"
            "1 libfoo.dylib 0x2 foo_parse + 3\n"
            "3 0x1\n"
        )
        noisy_sig = signature_for_text(noisy, "text-noisy")
        self.assertIn("bar", {frame.function for frame in noisy_sig.frames})
        self.assertIn("foo_parse", {frame.function for frame in noisy_sig.frames})
        self.assertIn("foo", {frame.module for frame in noisy_sig.frames})
        self.assertIn("libfoo.dylib", {frame.module for frame in noisy_sig.frames})

        crashed_lines = "Thread 0 Crashed:\n" + "\n".join(["0 libfoo.dylib 0x1 foo_parse + 12"] * 70)
        crashed_sig = signature_for_text(crashed_lines, "text-max-crashed")
        self.assertEqual(len(crashed_sig.frames), 64)

        fallback_lines = "\n".join(["0 libfoo.dylib 0x1 foo_parse + 12"] * 70)
        fallback_sig = signature_for_text(fallback_lines, "text-max-fallback")
        self.assertEqual(len(fallback_sig.frames), 64)

    async def test_metadata_parser_edge_variants(self) -> None:
        stack_text = "Thread 0 Crashed:\n" + "\n".join(
            f"0 libmeta.dylib 0x1 meta_func_{index:02d} + 1" for index in range(70)
        )
        max_sig = signature_for_finding(
            Finding(
                crash=CrashInput(id="meta-max", kind="meta", metadata={"stack": stack_text}),
                bug_class="uaf",
            ),
            bug_class="uaf",
        )
        self.assertEqual(len(max_sig.frames), 64)

        fallback_sig = signature_for_finding(
            Finding(
                crash=CrashInput(
                    id="meta-json-text",
                    kind="meta",
                    metadata={
                        "exception_type": {"bad": "value"},
                        "exceptionType": "EXC_FALLBACK",
                        "frames": [{"module": "0x0", "function": "zero_func"}],
                    },
                ),
                bug_class="uaf",
            ),
            bug_class="uaf",
        )
        self.assertEqual(fallback_sig.exception_type, "EXC_FALLBACK")
        self.assertEqual(fallback_sig.frames[0].module, "unknown")
        self.assertEqual(fallback_sig.frames[0].function, "zero_func")


if __name__ == "__main__":
    unittest.main()
