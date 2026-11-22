"""PRESS-backed n=3 bug-class classifier with one escalation."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from ra.errors import RaError
from ra.press.harness import ModelResult, PressHarness
from ra.press.routing import TaskType

from .evidence import evidence_text
from .models import (
    BUG_CLASS_VOCAB,
    ClassifyResult,
    ClassifyStatus,
    CrashEvidence,
    PacketRef,
    SymbolizedCrash,
)
from .sanitize import clean_text, json_dumps_safe, safe_int_or_none
from .symbolication import coerce_symbolized


class BugClassClassifier(Protocol):
    async def classify(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        *,
        artifacts: tuple[str, ...] = (),
    ) -> ClassifyResult: ...


def _packet_ref(result: ModelResult) -> PacketRef:
    task_type = getattr(result, "task_type", "unknown")
    task_value = getattr(task_type, "value", task_type)
    packet = getattr(result, "packet", None)
    sha = getattr(packet, "sha", "")
    offline = getattr(result, "offline", False)
    try:
        offline_bool = bool(offline)
    except Exception:
        offline_bool = False
    return PacketRef(
        clean_text(str(task_value), limit=64, keep_newlines=False) or "unknown",
        clean_text(str(sha), limit=128, keep_newlines=False),
        offline_bool,
    )


def _clean_answer(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = clean_text(value, limit=64, keep_newlines=False)
    return text or None


def _canonical_vocab(value: str | None, vocab: Sequence[str]) -> str | None:
    if value is None:
        return None
    lowered = value.lower()
    return lowered if lowered in vocab else None


def classification_goal(crash: CrashEvidence, symbolized: SymbolizedCrash) -> str:
    frames = "\n".join(
        f"{index + 1}. {frame}"
        for index, frame in enumerate(symbolized.frames[:8])
        if clean_text(frame, limit=240, keep_newlines=False)
    )
    target = json_dumps_safe(symbolized.target) if symbolized.target else "{}"
    excerpt = evidence_text(crash, limit=1_800)
    returncode = safe_int_or_none(symbolized.returncode)
    return (
        "Classify the crash bug class for Apple Security Bounty triage. "
        "Choose the single best vocab value, or insufficient_evidence when the evidence is ambiguous.\n"
        f"CRASH_KIND: {clean_text(crash.kind, limit=128, keep_newlines=False)}\n"
        f"CRASH_TYPE: {clean_text(symbolized.crash_type, limit=128, keep_newlines=False)}\n"
        f"SIGNAL: {clean_text(symbolized.signal or 'unknown', limit=64, keep_newlines=False)}\n"
        f"RETURN_CODE: {returncode if returncode is not None else 'unknown'}\n"
        f"TARGET: {target}\n"
        f"SYMBOLICATED: {symbolized.symbolicated} ({clean_text(symbolized.source, limit=64, keep_newlines=False)})\n"
        "TOP_FRAMES:\n"
        f"{frames or '(none)'}\n"
        "EVIDENCE_EXCERPT:\n"
        f"{excerpt}\n"
        "Kernel rubric tie-break order: uaf > type_confusion > oob_write > info_leak > oob_read > other."
    )


class PressBugClassClassifier:
    """Use PRESS BUG_CLASS sampling as the n=3 vote and escalate once."""

    def __init__(
        self,
        harness: PressHarness,
        *,
        escalation_harness: PressHarness | None = None,
        vocab: Sequence[str] = BUG_CLASS_VOCAB,
    ) -> None:
        self._harness = harness
        self._escalation_harness = escalation_harness
        self._vocab = tuple(vocab)

    async def classify(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        *,
        artifacts: tuple[str, ...] = (),
    ) -> ClassifyResult:
        symbolized = coerce_symbolized(symbolized, crash)
        goal = classification_goal(crash, symbolized)
        packet_artifacts = artifacts[:3]
        packets: list[PacketRef] = []
        try:
            primary = await self._harness.complete(
                TaskType.BUG_CLASS,
                goal,
                artifacts=packet_artifacts,
                vocab=self._vocab,
            )
        except RaError as exc:
            return ClassifyResult(None, ClassifyStatus.ERROR, 0.0, tuple(packets), exc.code)
        except Exception:
            return ClassifyResult(None, ClassifyStatus.ERROR, 0.0, tuple(packets), "MODEL_ERROR")
        packets.append(_packet_ref(primary))
        primary_output = primary.output if isinstance(primary.output, dict) else {}
        raw_answer = _clean_answer(primary_output.get("answer"))
        answer = _canonical_vocab(raw_answer, self._vocab)
        if answer is not None:
            return ClassifyResult(answer, ClassifyStatus.BOUND, 0.9, tuple(packets))
        if self._escalation_harness is None:
            return ClassifyResult(
                raw_answer,
                ClassifyStatus.SPLIT,
                0.25,
                tuple(packets),
                "TRIAGE_SPLIT",
            )
        escalation_goal = (
            goal
            + "\nESCALATION: the n=3 vote split or was insufficient. "
            "Act as the large-model tie-breaker and return one vocab value or insufficient_evidence."
        )
        try:
            escalated = await self._escalation_harness.complete(
                TaskType.BUG_CLASS,
                escalation_goal,
                artifacts=packet_artifacts,
                vocab=self._vocab,
            )
        except RaError as exc:
            return ClassifyResult(raw_answer, ClassifyStatus.ERROR, 0.0, tuple(packets), exc.code)
        except Exception:
            return ClassifyResult(raw_answer, ClassifyStatus.ERROR, 0.0, tuple(packets), "MODEL_ERROR")
        packets.append(_packet_ref(escalated))
        escalation_output = escalated.output if isinstance(escalated.output, dict) else {}
        escalation_raw = _clean_answer(escalation_output.get("answer"))
        escalation_answer = _canonical_vocab(escalation_raw, self._vocab)
        if escalation_answer is not None:
            return ClassifyResult(escalation_answer, ClassifyStatus.ESCALATED, 0.75, tuple(packets))
        return ClassifyResult(
            escalation_raw or raw_answer,
            ClassifyStatus.SPLIT,
            0.2,
            tuple(packets),
            "TRIAGE_SPLIT",
        )


__all__ = ["BUG_CLASS_VOCAB", "BugClassClassifier", "PressBugClassClassifier", "classification_goal"]
