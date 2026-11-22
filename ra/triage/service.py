"""Ledger-backed triage orchestration for crash evidence."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from ra.errors import DuplicateDedup, RaError
from ra.ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    ClaimState,
    Ledger,
    UlidFactory,
)
from ra.ledger.ids import artifact_id
from ra.press.harness import PressHarness

from .assessment import PressTriageAssessor, VariantReplayer, heuristic_assessment
from .classifier import BugClassClassifier, PressBugClassClassifier
from .dedup import DEDUP_THRESHOLD, TriageDeduper, build_signature
from .evidence import symbolized_payload_bytes
from .models import (
    BUG_CLASS_VOCAB,
    CRASH_CLASS_VOCAB,
    AssessmentResult,
    ClassifyResult,
    ClassifyStatus,
    CrashEvidence,
    DedupSignature,
    PacketRef,
    PocResult,
    SymbolizedCrash,
    TriageClaimResult,
    TriageStatus,
    now_ms,
)
from .sanitize import clean_multiline, clean_text, json_safe, safe_float, safe_int
from .symbolication import DefaultSymbolicator, SymbolicationProvider, coerce_symbolized

_MAX_ARTIFACT_BYTES = 65_536
_RATINGS = {"low", "medium", "high"}


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, RaError):
        return exc.code
    return "MODEL_ERROR"


def _safe_bool(value: Any) -> bool:
    try:
        return bool(value)
    except Exception:
        return False


def _safe_bug_class(value: Any, fallback: str = "other") -> str:
    candidate = clean_text(value, limit=64, keep_newlines=False).lower()
    if candidate in BUG_CLASS_VOCAB:
        return candidate
    return fallback if fallback in BUG_CLASS_VOCAB else "other"


def _safe_crash_class(value: Any) -> str:
    candidate = clean_text(value, limit=64, keep_newlines=False).lower()
    return candidate if candidate in CRASH_CLASS_VOCAB else "other"


def _safe_rating(value: Any, bug_class: str) -> str:
    candidate = clean_text(value, limit=32, keep_newlines=False).lower()
    if candidate in _RATINGS:
        return candidate
    if bug_class in {"uaf", "type_confusion", "oob_write"}:
        return "high"
    if bug_class in {"info_leak", "oob_read"}:
        return "medium"
    return "low"


def _safe_confidence(value: Any) -> float:
    return min(1.0, max(0.0, safe_float(value, 0.0)))


def _string_list(value: Any, *, limit: int, item_limit: int) -> list[str]:
    if isinstance(value, str):
        items: Iterable[Any] = value.splitlines()
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, (str, bytes, bytearray)):
            continue
        text = clean_text(item, limit=item_limit, keep_newlines=False)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _packet_dicts(packets: Iterable[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in packets:
        if len(out) >= 20:
            break
        task_type: Any
        sha: Any
        offline: Any
        if isinstance(item, PacketRef):
            task_type = item.task_type
            sha = item.sha
            offline = item.offline
        elif isinstance(item, Mapping):
            task_type = item.get("task_type")
            sha = item.get("sha")
            offline = item.get("offline", False)
        else:
            continue
        out.append(
            {
                "task_type": clean_text(task_type, limit=64, keep_newlines=False) or "unknown",
                "sha": clean_text(sha, limit=128, keep_newlines=False),
                "offline": _safe_bool(offline),
            }
        )
    return out


def _safe_exploitability(value: Any, bug_class: str) -> dict[str, Any]:
    mapping = value if isinstance(value, Mapping) else {}
    signals = _string_list(mapping.get("signals"), limit=8, item_limit=128)
    return {
        "rating": _safe_rating(mapping.get("rating"), bug_class),
        "assessment": clean_multiline(mapping.get("assessment"), limit=1_000),
        "primitive": clean_multiline(mapping.get("primitive"), limit=1_000),
        "signals": signals,
    }


def _safe_variants(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        items: Iterable[Any] = (value,)
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return []
    variants: list[dict[str, Any]] = []
    for item in items:
        if len(variants) >= 5:
            break
        if isinstance(item, Mapping):
            variant_id = clean_text(item.get("id"), limit=64, keep_newlines=False) or f"variant-{len(variants) + 1}"
            description = clean_multiline(item.get("description"), limit=1_000)
            code = clean_multiline(item.get("code"), limit=4_000)
            variant: dict[str, Any] = {"id": variant_id, "description": description, "code": code}
            if "replay" in item:
                replay = json_safe(item.get("replay"))
                variant["replay"] = replay if isinstance(replay, dict) else {"result": "error", "detail": "REPLAY_SHAPE"}
        elif isinstance(item, (str, bytes, bytearray)):
            description = clean_text(item, limit=1_000, keep_newlines=False)
            if not description:
                continue
            variant = {"id": f"variant-{len(variants) + 1}", "description": description, "code": ""}
        else:
            continue
        variants.append(variant)
    return variants


def _safe_target(value: Any) -> dict[str, Any]:
    safe = json_safe(value if isinstance(value, Mapping) else {})
    return safe if isinstance(safe, dict) else {}


def _frames_for_claim(symbolized: SymbolizedCrash) -> list[str]:
    frames = getattr(symbolized, "frames", ()) or ()
    if isinstance(frames, (str, bytes, bytearray)):
        frames = (frames,)
    out: list[str] = []
    for frame in frames[:12]:
        text = clean_text(frame, limit=240, keep_newlines=False)
        if text:
            out.append(text)
    return out


def _value_json(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return json.dumps(json_safe(value), sort_keys=True, separators=(",", ":"))


class TriageService:
    """Turn one crash evidence record into one ledger-backed triage claim."""

    def __init__(
        self,
        ledger: Ledger,
        harness: PressHarness,
        *,
        escalation_harness: PressHarness | None = None,
        symbolicator: SymbolicationProvider | None = None,
        replayer: VariantReplayer | None = None,
        classifier: BugClassClassifier | None = None,
        assessor: PressTriageAssessor | None = None,
        ids: UlidFactory | None = None,
        dedup_threshold: float = DEDUP_THRESHOLD,
    ) -> None:
        self._ledger = ledger
        self._harness = harness
        self._symbolicator = symbolicator or DefaultSymbolicator()
        self._classifier = classifier or PressBugClassClassifier(
            harness, escalation_harness=escalation_harness
        )
        self._assessor = assessor or PressTriageAssessor(harness, replayer=replayer)
        self._deduper = TriageDeduper(ledger, threshold=dedup_threshold)
        self._ids = ids or UlidFactory()

    async def triage(self, crash: CrashEvidence, *, run_id: str | None = None) -> TriageClaimResult:
        run_id = clean_text(run_id, limit=128, keep_newlines=False) if run_id is not None else None
        try:
            raw_symbolized = await self._symbolicator.symbolize(crash)
        except Exception:
            raw_symbolized = None
        symbolized = coerce_symbolized(raw_symbolized, crash)
        signature = build_signature(crash, symbolized)
        duplicate = self._deduper.find_duplicate(signature)
        if duplicate is not None:
            return await self._duplicate_claim(crash, symbolized, signature, duplicate, run_id)
        try:
            classify = await self._classifier.classify(
                crash,
                symbolized,
                artifacts=self._packet_artifacts(crash, symbolized),
            )
        except Exception as exc:
            classify = ClassifyResult(None, ClassifyStatus.ERROR, 0.0, (), _error_code(exc))
        if classify.status in {ClassifyStatus.SPLIT, ClassifyStatus.ERROR}:
            return await self._parked_claim(crash, symbolized, signature, classify, run_id)
        bug_class = _safe_bug_class(classify.answer or signature.bug_class, self._fallback_bug_class(signature))
        try:
            assessment = await self._assessor.assess(
                crash,
                symbolized,
                bug_class,
                artifacts=self._packet_artifacts(crash, symbolized),
            )
        except Exception as exc:
            assessment = AssessmentResult(
                heuristic_assessment(crash, symbolized, bug_class),
                (),
                "fallback",
                _error_code(exc),
            )
        try:
            poc = await self._assessor.write_poc(
                crash,
                symbolized,
                assessment.data if isinstance(assessment.data, Mapping) else {},
                bug_class,
                artifacts=self._packet_artifacts(crash, symbolized),
            )
        except Exception as exc:
            poc = PocResult("", (), "fallback", _error_code(exc))
        return await self._bound_claim(
            crash,
            symbolized,
            signature,
            classify,
            assessment,
            poc,
            run_id,
        )

    def _fallback_bug_class(self, signature: DedupSignature) -> str:
        return signature.bug_class if signature.bug_class in BUG_CLASS_VOCAB else "other"

    def _symbolized_bytes(self, symbolized: SymbolizedCrash) -> bytes:
        payload = {
            "crash_id": symbolized.crash_id,
            "crash_type": symbolized.crash_type,
            "frames": list(symbolized.frames),
            "signal": symbolized.signal,
            "returncode": symbolized.returncode,
            "stderr": symbolized.stderr,
            "repro": symbolized.repro,
            "target": dict(symbolized.target),
            "symbolicated": symbolized.symbolicated,
            "source": symbolized.source,
        }
        return symbolized_payload_bytes(payload)

    def _crash_bytes(self, crash: CrashEvidence) -> bytes:
        payload = crash.payload
        if payload:
            if isinstance(payload, (bytes, bytearray, memoryview)):
                return bytes(payload[:_MAX_ARTIFACT_BYTES])
            return clean_text(payload, limit=16_000).encode("utf-8")
        metadata = crash.metadata if isinstance(crash.metadata, Mapping) else {}
        fallback = {
            "id": crash.id,
            "kind": crash.kind,
            "path": crash.path,
            "handle_id": crash.handle_id,
            "context": crash.context,
            "metadata_keys": sorted(clean_text(key, limit=128, keep_newlines=False) for key in metadata),
        }
        return symbolized_payload_bytes(fallback)

    def _packet_artifacts(self, crash: CrashEvidence, symbolized: SymbolizedCrash) -> tuple[str, ...]:
        crash_bytes = self._crash_bytes(crash)
        symbolized_bytes = self._symbolized_bytes(symbolized)
        target_bytes = symbolized_payload_bytes(dict(symbolized.target)) if symbolized.target else symbolized_bytes
        return (artifact_id(crash_bytes), artifact_id(symbolized_bytes), artifact_id(target_bytes))

    def _artifact_inputs(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        value: Mapping[str, Any],
    ) -> tuple[tuple[ClaimArtifactInput, ...], tuple[str, ...]]:
        value_bytes = _value_json(value).encode("utf-8")
        inputs = (
            ArtifactInput(kind="crash", data=self._crash_bytes(crash)),
            ArtifactInput(kind="symbolized_crash", data=self._symbolized_bytes(symbolized)),
            ArtifactInput(kind="triage", data=value_bytes),
        )
        links = tuple(ClaimArtifactInput(artifact=item, role="evidence") for item in inputs)
        return links, tuple(artifact_id(item.data) for item in inputs)

    async def _create_claim(
        self,
        *,
        crash: CrashEvidence,
        value: Mapping[str, Any],
        confidence: float,
        dedup_value: str,
        links: tuple[ClaimArtifactInput, ...],
        run_id: str | None,
    ) -> str:
        claim_id = self._ids.new("cl")
        claim = ClaimInput(
            claim_id=claim_id,
            type="bug_class",
            value_json=_value_json(value),
            confidence=_safe_confidence(confidence),
            dedup_key=clean_text(dedup_value, limit=512, keep_newlines=False),
            created=safe_int(crash.created_ms, now_ms()),
            run_id=run_id,
            artifacts=links,
        )
        try:
            return await self._ledger.create_claim(claim)
        except DuplicateDedup:
            existing = self._ledger.claim_by_dedup(claim.dedup_key)
            if existing is not None:
                return str(existing["id"])
            raise

    async def _transition(self, claim_id: str, *states: ClaimState) -> str:
        for state in states:
            await self._ledger.transition_claim(claim_id, state)
        return states[-1].value if states else ClaimState.LIMBO.value

    def _base_value(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        signature: DedupSignature,
        *,
        status: TriageStatus,
        bug_class: str,
        confidence: float,
        packets: tuple[PacketRef, ...],
        assessment: Mapping[str, Any] | None = None,
        poc_markdown: str = "",
        assessment_source: str = "fallback",
        poc_source: str = "none",
        duplicate_of: str | None = None,
        park_reason: str | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        raw_assessment = assessment if isinstance(assessment, Mapping) else None
        if raw_assessment is None:
            raw_assessment = heuristic_assessment(crash, symbolized, bug_class)
        bug_class = _safe_bug_class(bug_class, self._fallback_bug_class(signature))
        exploitability = _safe_exploitability(raw_assessment.get("exploitability"), bug_class)
        signals = _string_list(raw_assessment.get("signals"), limit=8, item_limit=128) or exploitability["signals"]
        status_value = status.value if isinstance(status, TriageStatus) else clean_text(status, limit=32) or "unknown"
        return {
            "schema": "ra.triage.v1",
            "triage_status": status_value,
            "crash_id": clean_text(crash.id, limit=128, keep_newlines=False) or "unknown",
            "bug_class": bug_class,
            "bug_class_hint": self._fallback_bug_class(signature),
            "dedup": signature.to_dict(),
            "root_cause": clean_multiline(raw_assessment.get("root_cause"), limit=4_000)
            or "Root cause not established from the packet evidence.",
            "crash_class": _safe_crash_class(raw_assessment.get("crash_class")),
            "exploitability": exploitability,
            "impact": clean_multiline(raw_assessment.get("impact"), limit=2_000) or "Impact not established.",
            "variant_ideas": _string_list(raw_assessment.get("variant_ideas"), limit=4, item_limit=500),
            "variants": _safe_variants(raw_assessment.get("variants")),
            "dedup_note": clean_text(raw_assessment.get("dedup_note"), limit=1_000, keep_newlines=False)
            or "No duplicate note supplied.",
            "signals": signals,
            "poc_writeup_md": clean_multiline(poc_markdown, limit=20_000),
            "packets": _packet_dicts(packets),
            "symbolication": {
                "symbolicated": _safe_bool(getattr(symbolized, "symbolicated", False)),
                "source": clean_text(getattr(symbolized, "source", "none"), limit=64, keep_newlines=False) or "none",
                "frames": _frames_for_claim(symbolized),
            },
            "target": _safe_target(getattr(symbolized, "target", {})),
            "duplicate_of": clean_text(duplicate_of, limit=128, keep_newlines=False) if duplicate_of else None,
            "park_reason": clean_text(park_reason, limit=128, keep_newlines=False) if park_reason else None,
            "error_code": clean_text(error_code, limit=128, keep_newlines=False) if error_code else None,
            "assessment_source": clean_text(assessment_source, limit=32, keep_newlines=False) or "fallback",
            "poc_source": clean_text(poc_source, limit=32, keep_newlines=False) or "none",
        }

    async def _duplicate_claim(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        signature: DedupSignature,
        duplicate: tuple[str, float],
        run_id: str | None,
    ) -> TriageClaimResult:
        claim_id, similarity = duplicate
        claim_id = clean_text(claim_id, limit=128, keep_newlines=False) or "unknown"
        similarity_value = safe_float(similarity, 0.0)
        existing = self._ledger.get_claim(claim_id)
        bug_class = self._fallback_bug_class(signature)
        if existing is not None:
            try:
                parsed = json.loads(str(existing.get("value_json", "{}")))
            except (ValueError, RecursionError):
                parsed = None
            if isinstance(parsed, dict):
                bug_class = _safe_bug_class(parsed.get("bug_class"), bug_class)
        value = self._base_value(
            crash,
            symbolized,
            signature,
            status=TriageStatus.DUPLICATE,
            bug_class=bug_class,
            confidence=1.0,
            packets=(),
            assessment={
                "root_cause": "",
                "crash_class": "other",
                "exploitability": {"rating": "low", "assessment": "", "primitive": "", "signals": []},
                "impact": "",
                "variant_ideas": [],
                "variants": [],
                "dedup_note": f"Duplicate of {claim_id} (similarity {similarity_value:.3f}); not re-classified.",
                "signals": [],
            },
            duplicate_of=claim_id,
        )
        links, artifact_ids = self._artifact_inputs(crash, symbolized, value)
        crash_key = clean_text(crash.id, limit=128, keep_newlines=False) or "unknown"
        new_claim_id = await self._create_claim(
            crash=crash,
            value=value,
            confidence=1.0,
            dedup_value=f"triage_duplicate|{crash_key}|{signature.dedup_key}",
            links=links,
            run_id=run_id,
        )
        return TriageClaimResult(
            claim_id=new_claim_id,
            status=TriageStatus.DUPLICATE,
            bug_class=bug_class,
            confidence=1.0,
            claim_state=ClaimState.LIMBO.value,
            duplicate_of=claim_id,
            value=value,
            artifacts=artifact_ids,
        )

    async def _parked_claim(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        signature: DedupSignature,
        classify: ClassifyResult,
        run_id: str | None,
    ) -> TriageClaimResult:
        bug_class = _safe_bug_class(classify.answer or signature.bug_class, self._fallback_bug_class(signature))
        error_code = clean_text(classify.error_code, limit=128, keep_newlines=False) if classify.error_code else None
        value = self._base_value(
            crash,
            symbolized,
            signature,
            status=TriageStatus.PARKED,
            bug_class=bug_class,
            confidence=_safe_confidence(classify.confidence),
            packets=tuple(classify.packets or ()),
            assessment=heuristic_assessment(crash, symbolized, bug_class),
            park_reason=error_code or "TRIAGE_SPLIT",
            error_code=error_code,
            assessment_source="heuristic",
        )
        links, artifact_ids = self._artifact_inputs(crash, symbolized, value)
        claim_id = await self._create_claim(
            crash=crash,
            value=value,
            confidence=_safe_confidence(classify.confidence),
            dedup_value=signature.dedup_key,
            links=links,
            run_id=run_id,
        )
        state = await self._transition(claim_id, ClaimState.BOUND, ClaimState.REVIEWED, ClaimState.PARKED)
        return TriageClaimResult(
            claim_id=claim_id,
            status=TriageStatus.PARKED,
            bug_class=bug_class,
            confidence=_safe_confidence(classify.confidence),
            claim_state=state,
            error_code=error_code,
            value=value,
            artifacts=artifact_ids,
            packets=tuple(classify.packets or ()),
        )

    async def _bound_claim(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        signature: DedupSignature,
        classify: ClassifyResult,
        assessment: AssessmentResult,
        poc: PocResult,
        run_id: str | None,
    ) -> TriageClaimResult:
        bug_class = _safe_bug_class(classify.answer or signature.bug_class, self._fallback_bug_class(signature))
        packets = (
            tuple(classify.packets or ())
            + tuple(assessment.packets or ())
            + tuple(poc.packets or ())
        )
        value = self._base_value(
            crash,
            symbolized,
            signature,
            status=TriageStatus.BOUND,
            bug_class=bug_class,
            confidence=_safe_confidence(classify.confidence),
            packets=packets,
            assessment=assessment.data if isinstance(assessment.data, Mapping) else {},
            poc_markdown=poc.markdown if isinstance(poc.markdown, str) else "",
            assessment_source=assessment.source,
            poc_source=poc.source,
        )
        links, artifact_ids = self._artifact_inputs(crash, symbolized, value)
        claim_id = await self._create_claim(
            crash=crash,
            value=value,
            confidence=_safe_confidence(classify.confidence),
            dedup_value=signature.dedup_key,
            links=links,
            run_id=run_id,
        )
        state = await self._transition(claim_id, ClaimState.BOUND)
        return TriageClaimResult(
            claim_id=claim_id,
            status=TriageStatus.BOUND,
            bug_class=bug_class,
            confidence=_safe_confidence(classify.confidence),
            claim_state=state,
            value=value,
            artifacts=artifact_ids,
            packets=packets,
        )


__all__ = ["TriageService"]
