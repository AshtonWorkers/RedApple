"""Build deterministic submission packets from promoted ledger claims."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from .estimate import estimate_bounty_tier
from .models import (
    MAX_EVIDENCE_REFS,
    MAX_FIELD_CHARS,
    MAX_REPRO_STEPS,
    MAX_TEXT_CHARS,
    EvidenceRef,
    SubmissionPacket,
    finalize_packet,
)

_MAX_SEARCH_MAPPINGS = 96
_MAX_SEARCH_CHILDREN = 64
_MAX_STEPS_CHARS = 8000
_IMPACT_PLACEHOLDER = "Impact not established from the promoted claim."
_STEP_PREFIX_RE = re.compile(r"^\d+[.)]\s*")


def _iter_mappings(root: Any) -> Iterable[Mapping[Any, Any]]:
    queue: list[Mapping[Any, Any]] = []
    if isinstance(root, Mapping):
        queue.append(root)
    elif isinstance(root, list | tuple):
        queue.extend(item for item in root if isinstance(item, Mapping))
    seen = 0
    while queue and seen < _MAX_SEARCH_MAPPINGS:
        mapping = queue.pop(0)
        seen += 1
        yield mapping
        children: list[Mapping[Any, Any]] = []
        for key in sorted(mapping.keys(), key=lambda item: str(item)):
            if len(children) >= _MAX_SEARCH_CHILDREN:
                break
            value = mapping.get(key)
            if isinstance(value, Mapping):
                children.append(value)
            elif isinstance(value, list | tuple):
                children.extend(item for item in value if isinstance(item, Mapping))
        queue.extend(children)


def _find_raw(root: Any, keys: tuple[str, ...]) -> Any:
    for mapping in _iter_mappings(root):
        for key in keys:
            if key in mapping:
                value = mapping.get(key)
                if value not in (None, "", [], {}):
                    return value
    return None


def _scalar_text(value: Any, *, limit: int = MAX_FIELD_CHARS) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, bytes | bytearray | memoryview):
        text = bytes(value).decode("utf-8", errors="replace")
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, int | float):
        text = str(value)
    else:
        return ""
    text = " ".join(text.split())
    return text[:limit] if len(text) > limit else text


def _multiline_text(value: Any, *, limit: int = MAX_TEXT_CHARS) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, bytes | bytearray | memoryview):
        text = bytes(value).decode("utf-8", errors="replace")
    else:
        return ""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    text = "\n".join(lines).strip("\n")
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text[:limit] if len(text) > limit else text


def _first_text(root: Any, keys: tuple[str, ...], *, limit: int = MAX_FIELD_CHARS) -> str:
    for mapping in _iter_mappings(root):
        for key in keys:
            if key in mapping:
                text = _scalar_text(mapping.get(key), limit=limit)
                if text:
                    return text
    return ""


def _first_multiline(root: Any, keys: tuple[str, ...], *, limit: int = MAX_TEXT_CHARS) -> str:
    for mapping in _iter_mappings(root):
        for key in keys:
            if key in mapping:
                text = _multiline_text(mapping.get(key), limit=limit)
                if text:
                    return text
    return ""


def _describe_value(value: Any, *, limit: int = 2000) -> str:
    if isinstance(value, str):
        return _multiline_text(value, limit=limit)
    if _scalar_text(value):
        return _scalar_text(value, limit=limit)
    if isinstance(value, Mapping | list | tuple):
        try:
            text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(value)
        return text[:limit] if len(text) > limit else text
    return ""


def _mapping_value(root: Any, keys: tuple[str, ...]) -> Mapping[Any, Any]:
    value = _find_raw(root, keys)
    return value if isinstance(value, Mapping) else {}


def _string_list(value: Any, *, limit: int = MAX_REPRO_STEPS) -> list[str]:
    if isinstance(value, str):
        items: Any = value.splitlines()
    elif isinstance(value, bytes | bytearray | memoryview):
        items = bytes(value).decode("utf-8", errors="replace").splitlines()
    elif isinstance(value, list | tuple):
        items = value
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if len(out) >= limit:
            break
        if isinstance(item, Mapping):
            item = next(
                (
                    _scalar_text(item.get(key), limit=MAX_FIELD_CHARS)
                    for key in ("step", "description", "command", "action", "text")
                    if _scalar_text(item.get(key), limit=MAX_FIELD_CHARS)
                ),
                "",
            )
        elif not isinstance(item, str | bytes | bytearray | memoryview):
            continue
        text = _multiline_text(item, limit=MAX_FIELD_CHARS).strip()
        if not text:
            continue
        lines = []
        for line in text.splitlines():
            cleaned = _STEP_PREFIX_RE.sub("", line.strip().lstrip("-*•").strip()).strip()
            if cleaned:
                lines.append(cleaned)
        for line in lines:
            if len(out) >= limit:
                break
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
    return out


def _repro_steps(root: Any, *, run_id: str | None, evidence: tuple[EvidenceRef, ...]) -> tuple[str, ...]:
    raw = _find_raw(
        root,
        (
            "repro_steps",
            "reproduction_steps",
            "steps",
            "repro",
            "proof_of_concept",
            "poc",
            "poc_writeup_md",
            "poc_writeup",
            "writeup",
        ),
    )
    steps = _string_list(raw)
    total = sum(len(step) for step in steps)
    while steps and total > _MAX_STEPS_CHARS:
        total -= len(steps[-1])
        steps.pop()
    if steps:
        return tuple(steps[:MAX_REPRO_STEPS])

    build = f"run `{run_id}`" if run_id else "the pinned build recorded for this claim"
    generated = [
        f"Reproduce on {build} using the exact target revision and sanitizer configuration.",
    ]
    if evidence:
        refs = ", ".join(item.artifact_id for item in evidence[:3])
        generated.append(f"Load promoted evidence artifact(s) {refs} into the RedApple lane.")
        generated.append("Replay the recorded crash input and confirm the crash signature below.")
    else:
        generated.append("Obtain the original crash artifact before submission; the claim had no artifact metadata.")
    return tuple(generated)


def _dedup_signature(dedup: Mapping[Any, Any]) -> str:
    parts: list[str] = []
    for key in ("stack_hash", "alloc_site", "top_frame", "signature", "hash", "bug_class"):
        text = _scalar_text(dedup.get(key), limit=240)
        if text:
            parts.append(f"{key}={text}")
    return " | ".join(parts)


def _crash_signature(root: Any, *, claim_type: str, bug_class: str) -> str:
    explicit = _first_text(
        root,
        (
            "crash_signature",
            "signature_text",
            "signature",
            "exception",
            "termination_reason",
            "crash_type",
            "error",
            "crash",
        ),
        limit=1000,
    )
    if explicit:
        return explicit
    symbolication = _mapping_value(root, ("symbolication",))
    frames = symbolication.get("frames")
    if isinstance(frames, list | tuple):
        texts = [_scalar_text(frame, limit=240) for frame in frames[:5]]
        joined = " <- ".join(text for text in texts if text)
        if joined:
            return joined[:1000]
    for key in ("dedup", "signature", "crash_signature", "class_signature"):
        value = _find_raw(root, (key,))
        if isinstance(value, Mapping):
            text = _dedup_signature(value)
            if text:
                return text[:1000]
        elif isinstance(value, str | bytes | bytearray | memoryview):
            text = _scalar_text(value, limit=1000)
            if text:
                return text
    crash_class = _first_text(root, ("crash_class",), limit=240)
    if crash_class:
        return crash_class
    if bug_class:
        return f"{claim_type}:{bug_class}"
    return f"{claim_type}:unknown"


def _joined_lines(parts: list[str]) -> str:
    return "\n".join(part for part in parts if part)


def _exploitability_text(root: Any) -> str:
    raw = _find_raw(root, ("exploitability", "exploitability_assessment", "exploit"))
    if isinstance(raw, Mapping):
        signals = raw.get("signals")
        signal_text = ""
        if isinstance(signals, list | tuple):
            signal_text = ", ".join(
                text for text in (_scalar_text(item, limit=128) for item in signals[:8]) if text
            )
        return _joined_lines(
            [
                f"Rating: {_scalar_text(raw.get('rating'), limit=32) or 'unknown'}",
                f"Primitive: {_multiline_text(raw.get('primitive'), limit=1000) or 'not established'}",
                f"Assessment: {_multiline_text(raw.get('assessment'), limit=1000) or 'not established'}",
                f"Signals: {signal_text or 'none'}",
            ]
        )
    if raw is not None:
        text = _multiline_text(raw, limit=2000) or _describe_value(raw, limit=2000)
        if text:
            return text
    rating = _first_text(root, ("exploitability_rating", "rating", "severity"), limit=64)
    primitive = _first_multiline(root, ("primitive", "primitive_description"), limit=1000)
    assessment = _first_multiline(root, ("exploit_assessment", "exploitability_assessment"), limit=1000)
    if not (rating or primitive or assessment):
        return "Exploitability not established from the promoted claim."
    return _joined_lines(
        [
            f"Rating: {rating or 'unknown'}",
            f"Primitive: {primitive or 'not established'}",
            f"Assessment: {assessment or 'not established'}",
        ]
    )


def _evidence_from_artifacts(artifacts: Iterable[Mapping[str, Any]]) -> tuple[EvidenceRef, ...]:
    refs: list[EvidenceRef] = []
    for row in artifacts:
        if len(refs) >= MAX_EVIDENCE_REFS:
            break
        artifact_id = _scalar_text(row.get("artifact_id"), limit=256)
        if not artifact_id:
            continue
        try:
            byte_size = int(row.get("bytes", row.get("byte_size", 0)))
        except (TypeError, ValueError):
            byte_size = 0
        try:
            created = int(row.get("created", 0))
        except (TypeError, ValueError):
            created = 0
        refs.append(
            EvidenceRef(
                artifact_id=artifact_id,
                kind=_scalar_text(row.get("kind"), limit=128) or "unknown",
                role=_scalar_text(row.get("role"), limit=128) or "evidence",
                sha256=_scalar_text(row.get("sha256"), limit=128),
                byte_size=max(0, byte_size),
                ttl_class=_scalar_text(row.get("ttl_class"), limit=32) or "run",
                created=max(0, created),
            )
        )
    return tuple(refs)


def _claim_value(row: Mapping[str, Any], warnings: list[str]) -> Mapping[Any, Any]:
    raw = row.get("value_json")
    if isinstance(raw, Mapping):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        warnings.append("claim value_json missing or empty")
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        warnings.append("claim value_json is not valid JSON")
        return {}
    if not isinstance(parsed, Mapping):
        warnings.append("claim value_json is not a JSON object")
        return {}
    return parsed


def _safe_int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, number)


def _safe_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number or number in (float("inf"), float("-inf")):
        return 0.0
    return min(1.0, max(0.0, number))


def _title(root: Any, *, bug_class: str, component: str, surface: str, claim_type: str) -> str:
    explicit = _first_text(
        root,
        ("title", "report_title", "finding_title", "headline", "summary", "name"),
        limit=240,
    )
    if explicit:
        return explicit
    label = bug_class.replace("_", " ") or claim_type.replace("_", " ") or "finding"
    target = component if component != "unknown component" else surface
    if target == "unknown surface":
        target = "unknown component"
    return f"{label} in {target}"[:240]


def packet_from_claim(
    row: Mapping[str, Any],
    artifacts: Iterable[Mapping[str, Any]] = (),
    *,
    extra_warnings: Iterable[str] = (),
) -> SubmissionPacket:
    """Assemble one redacted packet from a promoted claim row.

    The function is deliberately tolerant: malformed ``value_json`` and missing
    fields degrade to placeholders instead of raising.
    """
    warnings: list[str] = []
    value = _claim_value(row, warnings)
    evidence = _evidence_from_artifacts(artifacts)
    if not evidence:
        warnings.append("no artifact metadata available")
    for warning in extra_warnings:
        text = _scalar_text(warning, limit=240)
        if text and text not in warnings:
            warnings.append(text)

    claim_id = _scalar_text(row.get("id") or row.get("claim_id"), limit=128) or "unknown-claim"
    claim_type = _scalar_text(row.get("type") or row.get("claim_type"), limit=64) or "unknown"
    run_id = _scalar_text(row.get("run_id"), limit=128) or None
    dedup_key = _scalar_text(row.get("dedup_key"), limit=256) or f"{claim_id}:dedup"
    bug_class = _first_text(
        value,
        ("bug_class", "bugClass", "vulnerability_class", "finding_type", "class"),
        limit=64,
    )
    component = _first_text(
        value,
        (
            "component",
            "affected_component",
            "component_name",
            "target_component",
            "bundle_id",
            "bundle",
            "process",
            "daemon",
            "binary",
            "app",
            "name",
        ),
        limit=240,
    ) or "unknown component"
    surface = _first_text(
        value,
        (
            "surface",
            "attack_surface",
            "entry_point",
            "entrypoint",
            "reachability",
            "reach",
            "interface",
            "service",
            "mach_service",
            "xpc_service",
        ),
        limit=240,
    ) or "unknown surface"
    root_cause = _first_multiline(
        value,
        ("root_cause", "rootCause", "cause", "technical_root_cause", "analysis", "explanation"),
        limit=4000,
    ) or "Root cause not established from the promoted claim."
    crash_signature = _crash_signature(value, claim_type=claim_type, bug_class=bug_class)
    exploitability = _exploitability_text(value)
    impact = _first_multiline(
        value,
        ("impact", "security_impact", "impact_summary", "consequence", "impact_assessment"),
        limit=2000,
    ) or _IMPACT_PLACEHOLDER
    chain_summary = _first_multiline(
        value,
        ("chain_summary", "chain", "attack_path", "path", "join_summary", "joins"),
        limit=2000,
    )
    if not chain_summary:
        raw_chain = _find_raw(value, ("chain", "attack_path", "path", "joins", "join"))
        chain_summary = _describe_value(raw_chain, limit=2000) if raw_chain is not None else ""
    chain_summary = chain_summary or "No chain evidence was present in the promoted claim."
    escalation_summary = _first_multiline(
        value,
        ("escalation_summary", "escalation", "escalated", "post_exploit", "sandbox_escape"),
        limit=2000,
    ) or "No escalation evidence was present in the promoted claim."
    explicit_tier = _first_text(
        value,
        ("bounty_tier", "bounty_category", "reward_tier", "bounty_estimate", "tier"),
        limit=64,
    )
    bounty_tier, bounty_rationale = estimate_bounty_tier(
        explicit_tier=explicit_tier,
        bug_class=bug_class,
        surface=surface,
        component=component,
        exploitability=exploitability,
        impact=impact,
        chain_summary=chain_summary,
        escalation_summary=escalation_summary,
    )
    title = _title(value, bug_class=bug_class, component=component, surface=surface, claim_type=claim_type)
    packet = SubmissionPacket(
        packet_id="",
        schema="ra.submit.packet.v1",
        claim_id=claim_id,
        claim_type=claim_type,
        title=title,
        component=component,
        surface=surface,
        root_cause=root_cause,
        repro_steps=_repro_steps(value, run_id=run_id, evidence=evidence),
        crash_signature=crash_signature[:1000],
        exploitability=exploitability[:2000],
        impact=impact[:2000],
        chain_summary=chain_summary[:2000],
        escalation_summary=escalation_summary[:2000],
        bounty_tier=bounty_tier,
        bounty_rationale=bounty_rationale,
        confidence=_safe_float(row.get("confidence")),
        created=_safe_int(row.get("created")),
        run_id=run_id,
        dedup_key=dedup_key,
        evidence=evidence,
        warnings=tuple(warnings[:8]),
    )
    return finalize_packet(packet)


__all__ = ["packet_from_claim"]
