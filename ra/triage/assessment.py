"""PR #3 triage/PoC contract rebuilt as PRESS REPORT_TEXT packets."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from itertools import islice
from typing import Any, Protocol

from ra.errors import RaError
from ra.press.harness import PressHarness
from ra.press.routing import TaskType

from .classifier import _packet_ref
from .evidence import crash_class_hint, evidence_text
from .models import (
    CRASH_CLASS_VOCAB,
    AssessmentResult,
    CrashEvidence,
    PacketRef,
    PocResult,
    SymbolizedCrash,
)
from .sanitize import clean_multiline, clean_text, json_safe, safe_int_or_none

_RATINGS = {"low", "medium", "high"}
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
_MAX_PARSE_CHARS = 120_000
_MAX_FIELD_CHARS = 1_000
_MAX_ROOT_CAUSE_CHARS = 4_000
_MAX_IMPACT_CHARS = 2_000
_MAX_NOTE_CHARS = 1_000
_MAX_POC_CHARS = 20_000
_MAX_SIGNAL_CHARS = 128
_MAX_SIGNALS = 8

_CRASH_CLASS_ALIASES = {
    "uaf": "use-after-free",
    "use_after_free": "use-after-free",
    "use-after-free": "use-after-free",
    "heap-use-after-free": "use-after-free",
    "heap_use_after_free": "use-after-free",
    "double_free": "double-free",
    "double-free": "double-free",
    "doublefree": "double-free",
    "oob": "out-of-bounds",
    "oob_read": "out-of-bounds",
    "oob_write": "out-of-bounds",
    "out_of_bounds": "out-of-bounds",
    "out-of-bounds": "out-of-bounds",
    "buffer-overflow": "out-of-bounds",
    "buffer_overflow": "out-of-bounds",
    "heap-buffer-overflow": "out-of-bounds",
    "stack-buffer-overflow": "out-of-bounds",
    "type_confusion": "type-confusion",
    "type-confusion": "type-confusion",
    "typeconfusion": "type-confusion",
    "stack_overflow": "stack-exhaustion",
    "stack-exhaustion": "stack-exhaustion",
    "stackoverflow": "stack-exhaustion",
    "null_deref": "null-deref",
    "null-deref": "null-deref",
    "nullptr": "null-deref",
    "nil-deref": "null-deref",
    "integer_overflow": "integer-overflow",
    "integer-overflow": "integer-overflow",
    "int-overflow": "integer-overflow",
    "uninitialized": "uninitialized-memory",
    "uninitialised": "uninitialized-memory",
    "uninitialized-memory": "uninitialized-memory",
    "msan": "uninitialized-memory",
    "use_after_poison": "use-after-poison",
    "use-after-poison": "use-after-poison",
    "oom": "out-of-memory",
    "out_of_memory": "out-of-memory",
    "timeout": "timeout",
    "assert": "assertion",
    "assertion": "assertion",
}


def parse_json_object(text: str) -> dict[str, Any] | None:
    if not isinstance(text, str):
        return None
    text = text[:_MAX_PARSE_CHARS]
    candidates = [text.strip()]
    fenced = _JSON_FENCE_RE.search(text)
    if fenced:
        candidates.insert(0, fenced.group(1).strip())
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _as_str(value: Any, default: str = "", *, limit: int = _MAX_FIELD_CHARS) -> str:
    if isinstance(value, str):
        return clean_text(value, limit=limit) or default
    if isinstance(value, (bytes, bytearray)):
        return clean_text(value, limit=limit) or default
    return default


def _first_present(mapping: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping.get(key)
            if value not in (None, ""):
                return value
    return None


def _string_items(value: Any, *, limit: int, item_limit: int) -> list[str]:
    if isinstance(value, str):
        items: Iterable[Any] = value.splitlines()
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return []
    out: list[str] = []
    for item in islice(items, limit * 3):
        if not isinstance(item, (str, bytes, bytearray)):
            continue
        text = clean_text(item, limit=item_limit, keep_newlines=False)
        if text:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _unique_strings(values: Iterable[str], *, limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = clean_text(value, limit=_MAX_SIGNAL_CHARS, keep_newlines=False)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _variant_ideas(raw: Mapping[str, Any]) -> list[str]:
    ideas: list[str] = []
    seen: set[str] = set()
    keys = (
        "variant_ideas",
        "variantIdeas",
        "variant_idea",
        "ideas",
        "suggested_variants",
        "next_steps",
        "follow_ups",
        "experiments",
    )
    for key in keys:
        for item in _string_items(_first_present(raw, (key,)), limit=4, item_limit=500):
            if item not in seen:
                seen.add(item)
                ideas.append(item)
        if len(ideas) >= 4:
            break
    return ideas[:4]


def _as_variants(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        items: Iterable[Any] = (value,)
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return []
    variants: list[dict[str, Any]] = []
    for item in islice(items, 12):
        if len(variants) >= 3:
            break
        if isinstance(item, Mapping):
            variant_id = _as_str(
                _first_present(item, ("id", "variant_id", "name")),
                f"variant-{len(variants) + 1}",
                limit=64,
            )
            description = _as_str(
                _first_present(item, ("description", "summary", "idea", "title")),
                "",
                limit=1_000,
            )
            code = _as_str(
                _first_present(item, ("code", "poc", "repro", "payload", "script")),
                "",
                limit=4_000,
            )
        elif isinstance(item, (str, bytes, bytearray)):
            variant_id = f"variant-{len(variants) + 1}"
            description = clean_text(item, limit=1_000, keep_newlines=False)
            code = ""
            if not description:
                continue
        else:
            continue
        variants.append({"id": variant_id, "description": description, "code": code})
    return variants


def _canonical_crash_class(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = clean_text(value, limit=64, keep_newlines=False).lower()
    cleaned = cleaned.replace("_", "-").replace(" ", "-")
    canonical = _CRASH_CLASS_ALIASES.get(cleaned, cleaned)
    return canonical if canonical in CRASH_CLASS_VOCAB else None


def crash_class_for_bug_class(bug_class: str) -> str:
    return {
        "uaf": "use-after-free",
        "type_confusion": "type-confusion",
        "oob_write": "out-of-bounds",
        "oob_read": "out-of-bounds",
        "info_leak": "uninitialized-memory",
        "other": "other",
    }.get(bug_class, "other")


def _rating_for_bug_class(bug_class: str) -> str:
    if bug_class in {"uaf", "type_confusion", "oob_write"}:
        return "high"
    if bug_class in {"info_leak", "oob_read"}:
        return "medium"
    return "low"


def _primitive_for_bug_class(bug_class: str) -> str:
    return {
        "uaf": "potential reclaim/use primitive after free",
        "type_confusion": "type-confused object access",
        "oob_write": "controllable out-of-bounds write",
        "info_leak": "disclosure of adjacent memory",
        "oob_read": "out-of-bounds read disclosure",
        "other": "unclear primitive",
    }.get(bug_class, "unclear primitive")


def _crash_metadata(crash: CrashEvidence) -> Mapping[str, Any]:
    metadata = crash.metadata
    return metadata if isinstance(metadata, Mapping) else {}


def _frame_texts(symbolized: SymbolizedCrash, *, limit: int = 12) -> list[str]:
    try:
        frames = symbolized.frames[:limit]
    except Exception:
        return []
    if isinstance(frames, (str, bytes, bytearray)):
        frames = (frames,)
    texts: list[str] = []
    for frame in frames:
        text = clean_text(frame, limit=240, keep_newlines=False)
        if text:
            texts.append(text)
    return texts


def exploitability_signals(
    crash: CrashEvidence,
    symbolized: SymbolizedCrash,
    bug_class: str,
) -> list[str]:
    """Deterministic reachability/primitive signals for the triage claim."""
    kind = clean_text(getattr(crash, "kind", ""), limit=128).lower()
    crash_type = clean_text(getattr(symbolized, "crash_type", ""), limit=128).lower()
    frame_text = " ".join(_frame_texts(symbolized, limit=8)).lower()
    haystack = f"{kind} {crash_type} {frame_text}"
    signals: list[str] = []
    if any(token in haystack for token in ("jsc", "javascriptcore", "webkit", "js", "java")):
        signals.append("js_reachable")
    if any(token in haystack for token in ("xnu", "kernel", "iokit", "mach", "iosurface")):
        signals.append("kernel_reachable")
    if getattr(symbolized, "symbolicated", False):
        signals.append("symbolicated")
    if getattr(crash, "payload", b""):
        signals.append("payload_present")
    metadata = _crash_metadata(crash)
    if metadata.get("alloc_site") or metadata.get("allocation_site"):
        signals.append("alloc_site_present")
    signal = clean_text(getattr(symbolized, "signal", "") or "", limit=64).lower()
    if signal in {"sigsegv", "sigbus", "sigill", "sigtrap", "sigabrt"}:
        signals.append("memory_fault")
    returncode = safe_int_or_none(getattr(symbolized, "returncode", None))
    if returncode is not None and returncode < 0:
        signals.append("signal_terminated")
    if bug_class == "uaf":
        signals.append("free_reclaim")
    elif bug_class == "type_confusion":
        signals.append("type_confused_access")
    elif bug_class == "oob_write":
        signals.append("oob_write")
    elif bug_class == "info_leak":
        signals.append("memory_disclosure")
    elif bug_class == "oob_read":
        signals.append("oob_read")
    return _unique_strings(signals, limit=_MAX_SIGNALS)


def heuristic_assessment(
    crash: CrashEvidence,
    symbolized: SymbolizedCrash,
    bug_class: str,
) -> dict[str, Any]:
    rating = _rating_for_bug_class(bug_class)
    primitive = _primitive_for_bug_class(bug_class)
    crash_class = _canonical_crash_class(
        crash_class_hint(crash, symbolized.frames, symbolized=symbolized.symbolicated)
    ) or crash_class_for_bug_class(bug_class)
    signals = exploitability_signals(crash, symbolized, bug_class)
    return {
        "root_cause": "Insufficient model evidence; deterministic triage fallback used the crash class and top frames.",
        "crash_class": crash_class,
        "exploitability": {
            "rating": rating,
            "assessment": f"Fallback assessment for {bug_class}; verify against the symbolicated stack.",
            "primitive": primitive,
            "signals": signals,
        },
        "impact": "Impact is bounded by the reachable component and the reliability of the primitive.",
        "variant_ideas": [
            "Vary object lifetime around the crashing allocation",
            "Replay with adjacent groom allocations",
            "Test the same path on the next ring revision",
        ][:4],
        "variants": [],
        "dedup_note": "Deterministic fallback assessment; no model packet was available.",
        "signals": signals,
    }


def normalize_assessment(raw: Mapping[str, Any], bug_class: str) -> dict[str, Any]:
    exploitability_raw = raw.get("exploitability")
    if isinstance(exploitability_raw, Mapping):
        rating = _as_str(exploitability_raw.get("rating"), _rating_for_bug_class(bug_class), limit=32)
        if rating not in _RATINGS:
            rating = _rating_for_bug_class(bug_class)
        assessment_text = _as_str(
            exploitability_raw.get("assessment"),
            "Exploitability assessment unavailable.",
            limit=_MAX_FIELD_CHARS,
        )
        primitive = _as_str(
            exploitability_raw.get("primitive"),
            _primitive_for_bug_class(bug_class),
            limit=_MAX_FIELD_CHARS,
        )
        model_signals = _string_items(
            _first_present(exploitability_raw, ("signals", "primitive_signals")),
            limit=_MAX_SIGNALS,
            item_limit=_MAX_SIGNAL_CHARS,
        )
    else:
        rating = _rating_for_bug_class(bug_class)
        assessment_text = _as_str(exploitability_raw, "", limit=_MAX_FIELD_CHARS) or (
            "Exploitability assessment unavailable."
        )
        primitive = _primitive_for_bug_class(bug_class)
        model_signals = []
    top_signals = _string_items(raw.get("signals"), limit=_MAX_SIGNALS, item_limit=_MAX_SIGNAL_CHARS)
    signals = _unique_strings([*top_signals, *model_signals], limit=_MAX_SIGNALS)

    crash_class = _canonical_crash_class(_first_present(raw, ("crash_class", "crashClass", "class")))
    if crash_class is None:
        crash_class = crash_class_for_bug_class(bug_class)

    root_cause = _as_str(
        _first_present(raw, ("root_cause", "rootCause", "cause", "summary", "analysis", "explanation")),
        "Root cause not established from the packet evidence.",
        limit=_MAX_ROOT_CAUSE_CHARS,
    )
    impact = _as_str(
        _first_present(raw, ("impact", "impact_summary", "security_impact")),
        "Impact not established.",
        limit=_MAX_IMPACT_CHARS,
    )
    dedup_note = _as_str(
        _first_present(raw, ("dedup_note", "dedupNote", "duplicate_note", "dedup")),
        "No duplicate note supplied.",
        limit=_MAX_NOTE_CHARS,
    )
    return {
        "root_cause": root_cause,
        "crash_class": crash_class,
        "exploitability": {
            "rating": rating,
            "assessment": assessment_text,
            "primitive": primitive,
            "signals": signals,
        },
        "impact": impact,
        "variant_ideas": _variant_ideas(raw),
        "variants": _as_variants(_first_present(raw, ("variants", "variant", "poc_variants"))),
        "dedup_note": dedup_note,
        "signals": signals,
    }


def _frames_block(frames: Any, *, limit: int) -> str:
    try:
        candidates: Iterable[Any] = (frames,) if isinstance(frames, (str, bytes, bytearray)) else iter(frames)
    except TypeError:
        return "(none)"
    lines: list[str] = []
    for frame in islice(candidates, limit):
        text = clean_text(frame, limit=240, keep_newlines=False)
        if text:
            lines.append(text)
    if not lines:
        return "(none)"
    return "\n".join(f"{index + 1}. {frame}" for index, frame in enumerate(lines))


def _target_json(target: Any) -> str:
    safe = json_safe(target if isinstance(target, Mapping) else {})
    if not isinstance(safe, dict):
        safe = {}
    return json.dumps(safe, sort_keys=True, separators=(",", ":"))


def triage_goal(
    crash: CrashEvidence,
    symbolized: SymbolizedCrash,
    bug_class: str,
) -> str:
    crash_class_vocab = ", ".join(CRASH_CLASS_VOCAB)
    repro = clean_multiline(getattr(symbolized, "repro", ""), limit=4_000) or evidence_text(crash, limit=4_000)
    stderr = clean_multiline(getattr(symbolized, "stderr", ""), limit=2_000)
    metadata = _crash_metadata(crash)
    source = clean_text(
        metadata.get("source_context") or metadata.get("source") or "",
        limit=1_000,
        keep_newlines=False,
    )
    returncode = safe_int_or_none(getattr(symbolized, "returncode", None))
    return (
        "You are a senior browser-security researcher triaging an Apple crash for Security Bounty. "
        "Respond ONLY with the requested JSON object.\n"
        "Return exactly these keys: root_cause, crash_class, exploitability, impact, "
        "variant_ideas, variants, dedup_note, signals. crash_class must be one of: "
        f"{crash_class_vocab}. "
        "exploitability must contain rating (low|medium|high), assessment, primitive, and signals. "
        "variant_ideas is up to 4 strings. variants is up to 3 objects with id, description, code. "
        "signals is up to 8 short snake_case reachability or primitive signals.\n"
        f"BUG_CLASS: {clean_text(bug_class, limit=64, keep_newlines=False)}\n"
        f"CRASH_KIND: {clean_text(getattr(crash, 'kind', ''), limit=128, keep_newlines=False)}\n"
        f"CRASH_TYPE: {clean_text(getattr(symbolized, 'crash_type', ''), limit=128, keep_newlines=False)}\n"
        f"SIGNAL: {clean_text(getattr(symbolized, 'signal', '') or 'unknown', limit=64, keep_newlines=False)}\n"
        f"RETURN_CODE: {returncode if returncode is not None else 'unknown'}\n"
        f"TARGET: {_target_json(getattr(symbolized, 'target', {}))}\n"
        "TOP_FRAMES:\n"
        f"{_frames_block(getattr(symbolized, 'frames', ()), limit=10)}\n"
        "STDERR:\n"
        f"{stderr or '(none)'}\n"
        "REPRO/SOURCE_CONTEXT:\n"
        f"{source or '(none)'}\n"
        "REPRO:\n"
        f"{repro}\n"
    )


def poc_goal(
    crash: CrashEvidence,
    symbolized: SymbolizedCrash,
    assessment: Mapping[str, Any],
    bug_class: str,
) -> str:
    exploitability = assessment.get("exploitability")
    rating = ""
    primitive = ""
    if isinstance(exploitability, Mapping):
        rating = _as_str(exploitability.get("rating"), "", limit=32)
        primitive = _as_str(exploitability.get("primitive"), "", limit=240)
    repro = clean_multiline(getattr(symbolized, "repro", ""), limit=3_000) or evidence_text(crash, limit=3_000)
    return (
        "Write a diagnostic Apple Security Bounty PoC writeup in Markdown. "
        "Use exactly these sections: Summary, Affected component, Reproduction steps, "
        "Root cause analysis, Exploitability assessment, Suggested bounty category, Disclosure note. "
        "Do not include exploit code beyond minimal diagnostic repro.\n"
        f"BUG_CLASS: {clean_text(bug_class, limit=64, keep_newlines=False)}\n"
        f"CRASH_TYPE: {clean_text(getattr(symbolized, 'crash_type', ''), limit=128, keep_newlines=False)}\n"
        f"RATING: {rating}\n"
        f"PRIMITIVE: {primitive}\n"
        f"ROOT_CAUSE: {_as_str(assessment.get('root_cause'), '', limit=_MAX_ROOT_CAUSE_CHARS)}\n"
        "TOP_FRAMES:\n"
        f"{_frames_block(getattr(symbolized, 'frames', ()), limit=8)}\n"
        "REPRO:\n"
        f"{repro}\n"
    )


class VariantReplayer(Protocol):
    async def replay(self, variant: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnavailableVariantReplayer:
    async def replay(self, variant: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"result": "unverified", "signature": "", "detail": "JSC replay dependency unavailable"}


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, RaError):
        return exc.code
    return "MODEL_ERROR"


class PressTriageAssessor:
    """Generate the structured triage contract and Markdown PoC through PRESS."""

    def __init__(
        self,
        harness: PressHarness,
        *,
        replayer: VariantReplayer | None = None,
    ) -> None:
        self._harness = harness
        self._replayer = replayer or UnavailableVariantReplayer()

    async def assess(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        bug_class: str,
        *,
        artifacts: tuple[str, ...] = (),
    ) -> AssessmentResult:
        goal = triage_goal(crash, symbolized, bug_class)
        packets: list[PacketRef] = []
        try:
            result = await self._harness.complete(
                TaskType.REPORT_TEXT,
                goal,
                artifacts=artifacts[:3],
            )
        except Exception as exc:
            return AssessmentResult(
                heuristic_assessment(crash, symbolized, bug_class),
                tuple(packets),
                "fallback",
                _error_code(exc),
            )
        packets.append(_packet_ref(result))
        output = result.output if isinstance(result.output, Mapping) else {}
        raw_text = output.get("text", "")
        parsed = parse_json_object(raw_text if isinstance(raw_text, str) else str(raw_text))
        if parsed is None:
            return AssessmentResult(
                heuristic_assessment(crash, symbolized, bug_class),
                tuple(packets),
                "fallback",
                "FORMAT_FAIL",
            )
        data = normalize_assessment(parsed, bug_class)
        signals = _unique_strings(
            [
                *data.get("signals", []),
                *exploitability_signals(crash, symbolized, bug_class),
            ],
            limit=_MAX_SIGNALS,
        )
        data["signals"] = signals
        exploitability = data.get("exploitability")
        if isinstance(exploitability, dict):
            exploitability["signals"] = signals
        await self._annotate_variants(data.get("variants"))
        return AssessmentResult(dict(data), tuple(packets), "press")

    async def write_poc(
        self,
        crash: CrashEvidence,
        symbolized: SymbolizedCrash,
        assessment: Mapping[str, Any],
        bug_class: str,
        *,
        artifacts: tuple[str, ...] = (),
    ) -> PocResult:
        goal = poc_goal(crash, symbolized, assessment, bug_class)
        try:
            result = await self._harness.complete(
                TaskType.REPORT_TEXT,
                goal,
                artifacts=artifacts[:3],
            )
        except Exception as exc:
            return PocResult("", tuple(), "fallback", _error_code(exc))
        packet = (_packet_ref(result),)
        output = result.output if isinstance(result.output, Mapping) else {}
        raw_text = output.get("text", "")
        text = clean_multiline(raw_text if isinstance(raw_text, str) else str(raw_text), limit=_MAX_POC_CHARS).strip()
        if not text or text == "insufficient_evidence":
            return PocResult("", packet, "press")
        parsed = parse_json_object(text)
        if isinstance(parsed, Mapping):
            for key in ("poc_writeup_md", "markdown", "poc", "text"):
                value = parsed.get(key)
                if isinstance(value, str) and value.strip():
                    return PocResult(clean_multiline(value, limit=_MAX_POC_CHARS).strip(), packet, "press")
        return PocResult(text, packet, "press")

    async def _annotate_variants(self, variants: Any) -> None:
        if not isinstance(variants, list):
            return
        for variant in variants[:3]:
            if not isinstance(variant, dict):
                continue
            try:
                replay = await self._replayer.replay(variant)
            except RaError as exc:
                variant["replay"] = {"result": "error", "detail": exc.code}
                continue
            except Exception:
                variant["replay"] = {"result": "error", "detail": "REPLAY_ERROR"}
                continue
            safe_replay = json_safe(replay)
            if isinstance(safe_replay, dict):
                variant["replay"] = safe_replay
            else:
                variant["replay"] = {"result": "error", "detail": "REPLAY_SHAPE"}


__all__ = [
    "PressTriageAssessor",
    "UnavailableVariantReplayer",
    "VariantReplayer",
    "crash_class_for_bug_class",
    "exploitability_signals",
    "heuristic_assessment",
    "normalize_assessment",
    "parse_json_object",
    "poc_goal",
    "triage_goal",
]
