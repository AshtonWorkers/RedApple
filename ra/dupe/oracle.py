"""Dupe oracle: crash-signature dedup with ledger-backed canonical records."""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..errors import DuplicateDedup, FormatFail, RaError
from ..ledger import Ledger, UlidFactory
from ..ledger.ids import artifact_id, now_ms
from .interfaces import (
    CorpusIndex,
    NullCorpusIndex,
    NullPatchProximityProvider,
    NullSubmissionQueue,
    NullTriageClassifier,
    PatchProximityProvider,
    SubmissionQueue,
    TriageClassifier,
)
from .models import (
    CrashSignature,
    DupeScore,
    DupeVerdict,
    Finding,
    PatchDiff,
    SubmissionCandidate,
    _first_present,
    _unit_interval,
    compute_dupe_score,
)
from .patch import max_patch_similarity
from .signatures import (
    SignatureSimilarity,
    finding_patches,
    patch_proximity_for_finding,
    signature_for_finding,
    signature_similarity,
)
from .store import (
    DupeRecord,
    DupeStore,
    LedgerDupeStore,
    canonical_dedup_key,
    canonical_id_for_signature,
)
from .submission import rank_submissions

DEFAULT_DUPLICATE_THRESHOLD = 0.80
_SATURATION_KEYS = ("saturation", "saturation_score")
_PATCH_KEYS = ("patch_proximity", "patch_score", "patch_proximity_score")
_SHIPPED_KEYS = ("shipped_coverage", "coverage", "shipped")
_BUG_CLASS_KEYS = ("bug_class", "bugClass", "class", "bugclass")


@dataclass(frozen=True)
class _Match:
    record: DupeRecord
    similarity: SignatureSimilarity


class DupeOracle:
    """Deduplicate crashes/findings and score submissions (RA-DUP-001/002)."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        store: DupeStore | None = None,
        triage: TriageClassifier | None = None,
        patch_provider: PatchProximityProvider | None = None,
        corpus_index: CorpusIndex | None = None,
        submission_queue: SubmissionQueue | None = None,
        duplicate_threshold: float = DEFAULT_DUPLICATE_THRESHOLD,
        scan_limit: int = 10000,
    ) -> None:
        if not math.isfinite(duplicate_threshold) or not 0.0 <= duplicate_threshold <= 1.0:
            raise ValueError("duplicate_threshold must be in [0, 1]")
        self._ledger = ledger
        self._store = store if store is not None else LedgerDupeStore(ledger, scan_limit=scan_limit)
        self._triage = triage if triage is not None else NullTriageClassifier()
        self._patch_provider = patch_provider if patch_provider is not None else NullPatchProximityProvider()
        self._corpus_index = corpus_index if corpus_index is not None else NullCorpusIndex()
        self._submission_queue = submission_queue if submission_queue is not None else NullSubmissionQueue()
        self._threshold = duplicate_threshold
        self._ids = UlidFactory()

    async def check(self, finding_or_ref: Finding | Any) -> DupeVerdict:
        """Return duplicate status and canonical id for a crash/finding."""
        return await self._check(finding_or_ref)

    async def check_finding(self, finding_or_ref: Finding | Any) -> DupeVerdict:
        """Alias for :meth:`check`."""
        return await self._check(finding_or_ref)

    async def dedup(self, finding_or_ref: Finding | Any) -> DupeVerdict:
        """Alias for :meth:`check`."""
        return await self._check(finding_or_ref)

    async def _check(self, finding_or_ref: Finding | Any) -> DupeVerdict:
        finding = Finding.from_object(finding_or_ref)
        bug_class = await self._bug_class(finding)
        signature = signature_for_finding(finding, bug_class=bug_class)
        patches = finding_patches(finding)
        score = await self._resolve_score(finding, signature, patches)
        signature_artifact = _signature_artifact(signature, patches)

        exact = await self._store.get_canonical(signature.signature_hash)
        if exact is not None:
            return await self._record_observation(
                finding,
                signature,
                patches,
                score,
                canonical=exact,
                match_kind="exact",
                similarity=1.0,
                artifact_data=_artifact_payload(finding, signature_artifact),
            )

        match = await self._best_fuzzy_match(signature, patches)
        if match is not None:
            return await self._record_observation(
                finding,
                signature,
                patches,
                score,
                canonical=match.record,
                match_kind="fuzzy",
                similarity=match.similarity.score,
                artifact_data=_artifact_payload(finding, signature_artifact),
            )

        return await self._record_new(finding, signature, patches, score, signature_artifact)

    async def _bug_class(self, finding: Finding) -> str:
        if finding.bug_class and finding.bug_class.strip():
            return finding.bug_class.strip()
        try:
            value = await self._triage.classify(finding)
        except RaError:
            value = None
        if isinstance(value, str) and value.strip():
            return value.strip()
        return _metadata_bug_class(finding) or "unknown"

    async def _resolve_score(
        self,
        finding: Finding,
        signature: CrashSignature,
        patches: tuple[PatchDiff, ...],
    ) -> DupeScore:
        saturation = _first_present(finding.saturation, _metadata_float(finding, _SATURATION_KEYS))
        patch_proximity = _first_present(
            finding.patch_proximity,
            _metadata_float(finding, _PATCH_KEYS),
            patch_proximity_for_finding(finding, signature),
        )
        if patch_proximity is None:
            try:
                patch_proximity = await self._patch_provider.proximity(finding, signature)
            except RaError:
                patch_proximity = None
        shipped_coverage = _first_present(finding.shipped_coverage, _metadata_float(finding, _SHIPPED_KEYS))
        if shipped_coverage is None:
            shipped_coverage = await self._shipped_coverage_from_corpus(finding, signature)
        return DupeScore(
            saturation=_unit_interval(saturation if saturation is not None else 0.0),
            patch_proximity=_unit_interval(patch_proximity if patch_proximity is not None else 0.0),
            shipped_coverage=_unit_interval(shipped_coverage if shipped_coverage is not None else 0.0),
            total=compute_dupe_score(
                saturation if saturation is not None else 0.0,
                patch_proximity if patch_proximity is not None else 0.0,
                shipped_coverage if shipped_coverage is not None else 0.0,
            ),
        )

    async def _shipped_coverage_from_corpus(self, finding: Finding, signature: CrashSignature) -> float | None:
        try:
            evidence = await self._corpus_index.evidence(finding, signature)
        except RaError:
            return None
        # Internal-corpus overlap is artifact-bound: evidence without ledger
        # artifact ids cannot influence the score.
        values = [
            item.shipped_coverage
            for item in evidence
            if item.artifact_ids and math.isfinite(item.shipped_coverage)
        ]
        if not values:
            return None
        return max(values)

    async def _best_fuzzy_match(self, signature: CrashSignature, patches: tuple[PatchDiff, ...]) -> _Match | None:
        best: _Match | None = None
        for record in await self._store.canonicals():
            if record.signature.signature_hash == signature.signature_hash:
                continue
            similarity = signature_similarity(
                signature,
                record.signature,
                patch_similarity=max_patch_similarity(patches, record.patches),
            )
            if similarity.score < self._threshold:
                continue
            candidate = _Match(record=record, similarity=similarity)
            if best is None or _match_key(candidate) < _match_key(best):
                best = candidate
        return best

    async def _record_observation(
        self,
        finding: Finding,
        signature: CrashSignature,
        patches: tuple[PatchDiff, ...],
        score: DupeScore,
        *,
        canonical: DupeRecord,
        match_kind: str,
        similarity: float,
        artifact_data: bytes,
    ) -> DupeVerdict:
        now = now_ms()
        claim_id = f"dupeobs_{self._ids.new('obs')}"
        record = DupeRecord(
            claim_id=claim_id,
            dedup_key=f"dupe:observation:{claim_id}",
            record_kind="observation",
            canonical_id=canonical.canonical_id,
            created_ms=now,
            signature=signature,
            patches=patches,
            score=score,
            is_duplicate=True,
            match_kind=match_kind,
            similarity=similarity,
            source_id=_source_id(finding),
        )
        saved_claim_id = await self._save_observation(record, artifact_data)
        return DupeVerdict(
            is_duplicate=True,
            canonical_id=canonical.canonical_id,
            match_kind=match_kind,
            similarity=similarity,
            score=score,
            signature=signature,
            claim_id=saved_claim_id,
            artifact_ids=(artifact_id(artifact_data),),
            reasons=(f"matched canonical {canonical.canonical_id} by {match_kind}",),
            created_ms=now,
        )

    async def _record_new(
        self,
        finding: Finding,
        signature: CrashSignature,
        patches: tuple[PatchDiff, ...],
        score: DupeScore,
        signature_artifact: bytes,
    ) -> DupeVerdict:
        now = now_ms()
        canonical_id = canonical_id_for_signature(signature.signature_hash)
        record = DupeRecord(
            claim_id=canonical_id,
            dedup_key=canonical_dedup_key(signature.signature_hash),
            record_kind="canonical",
            canonical_id=canonical_id,
            created_ms=now,
            signature=signature,
            patches=patches,
            score=score,
            is_duplicate=False,
            match_kind="new",
            similarity=1.0,
            source_id=_source_id(finding),
        )
        try:
            claim_id = await self._store.save_canonical(record, signature_artifact)
        except (DuplicateDedup, FormatFail):
            existing = await self._store.get_canonical(signature.signature_hash)
            if existing is not None:
                return await self._record_observation(
                    finding,
                    signature,
                    patches,
                    score,
                    canonical=existing,
                    match_kind="exact",
                    similarity=1.0,
                    artifact_data=_artifact_payload(finding, signature_artifact),
                )
            raise
        return DupeVerdict(
            is_duplicate=False,
            canonical_id=canonical_id,
            match_kind="new",
            similarity=1.0,
            score=score,
            signature=signature,
            claim_id=claim_id,
            artifact_ids=(artifact_id(signature_artifact),),
            reasons=("new canonical signature",),
            created_ms=now,
        )

    async def _save_observation(self, record: DupeRecord, artifact_data: bytes) -> str:
        try:
            return await self._store.save_observation(record, artifact_data)
        except (DuplicateDedup, FormatFail):
            # Observation keys are unique per check; a same-millisecond collision
            # gets one deterministic retry key.
            record = DupeRecord(
                claim_id=f"{record.claim_id}_r",
                dedup_key=f"{record.dedup_key}:r",
                record_kind=record.record_kind,
                canonical_id=record.canonical_id,
                created_ms=record.created_ms,
                signature=record.signature,
                patches=record.patches,
                score=record.score,
                is_duplicate=record.is_duplicate,
                match_kind=record.match_kind,
                similarity=record.similarity,
                source_id=record.source_id,
            )
            return await self._store.save_observation(record, artifact_data)

    async def enqueue_submission(self, candidate: SubmissionCandidate) -> str:
        """Enqueue a submission candidate through the chain/policy interface."""
        return await self._submission_queue.enqueue(candidate)

    async def rank(self, candidates: Sequence[SubmissionCandidate]) -> list[SubmissionCandidate]:
        """Order submission candidates by RA-DUP score without suppressing any."""
        return rank_submissions(candidates)


def _match_key(match: _Match) -> tuple[float, int, str]:
    """Deterministic best-match order: highest score, oldest record, stable id."""
    record = match.record
    return (-match.similarity.score, record.created_ms, record.claim_id)


def _signature_artifact(signature: CrashSignature, patches: tuple[PatchDiff, ...]) -> bytes:
    payload = {
        "schema": "ra.dupe.signature.v1",
        "signature": signature.to_dict(),
        "patches": [patch.to_dict() for patch in patches],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _artifact_payload(finding: Finding, signature_artifact: bytes) -> bytes:
    """Persist raw crash bytes when present; otherwise the normalized signature."""
    if finding.crash.payload:
        return finding.crash.payload
    return signature_artifact


def _source_id(finding: Finding) -> str:
    return finding.crash.id or finding.crash.path or finding.crash.digest or ""


def _metadata_float(finding: Finding, keys: Sequence[str]) -> float | None:
    for mapping in (finding.metadata, finding.crash.metadata):
        for key in keys:
            value = mapping.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                return float(value)
    return None


def _metadata_bug_class(finding: Finding) -> str | None:
    for mapping in (finding.metadata, finding.crash.metadata):
        for key in _BUG_CLASS_KEYS:
            value = mapping.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None

__all__ = ["DEFAULT_DUPLICATE_THRESHOLD", "DupeOracle"]
