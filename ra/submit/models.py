"""Structured Apple Security Bounty submission packets."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field, replace
from typing import Any, cast

from .redact import redact_json_value

REPORT_SCHEMA = "ra.submit.report.v1"
PACKET_SCHEMA = "ra.submit.packet.v1"
BOUNTY_TIERS = frozenset({"critical", "high", "medium", "low", "unknown"})
MAX_REPRO_STEPS = 20
MAX_EVIDENCE_REFS = 32
MAX_TEXT_CHARS = 4000
MAX_FIELD_CHARS = 1000


@dataclass(frozen=True)
class EvidenceRef:
    """Ledger artifact metadata attached to a promoted finding."""

    artifact_id: str
    kind: str
    role: str
    sha256: str
    byte_size: int
    ttl_class: str
    created: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "role": self.role,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
            "ttl_class": self.ttl_class,
            "created": self.created,
        }


@dataclass(frozen=True)
class SubmissionPacket:
    """Deterministic, redacted submission packet assembled from one claim."""

    packet_id: str
    claim_id: str
    claim_type: str
    title: str
    component: str
    surface: str
    root_cause: str
    repro_steps: tuple[str, ...]
    crash_signature: str
    exploitability: str
    impact: str
    chain_summary: str
    escalation_summary: str
    bounty_tier: str
    bounty_rationale: str
    confidence: float
    created: int
    run_id: str | None
    dedup_key: str
    evidence: tuple[EvidenceRef, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    schema: str = PACKET_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return packet_payload(self, include_packet_id=True)


def _packet_core(packet: SubmissionPacket) -> dict[str, Any]:
    payload = packet_payload(packet, include_packet_id=False)
    return payload


def packet_payload(packet: SubmissionPacket, *, include_packet_id: bool) -> dict[str, Any]:
    """Canonical JSON-safe packet payload with all strings redacted."""
    payload: dict[str, Any] = {
        "schema": packet.schema,
        "claim_id": packet.claim_id,
        "claim_type": packet.claim_type,
        "title": packet.title,
        "component": packet.component,
        "surface": packet.surface,
        "root_cause": packet.root_cause,
        "repro_steps": list(packet.repro_steps),
        "crash_signature": packet.crash_signature,
        "exploitability": packet.exploitability,
        "impact": packet.impact,
        "chain_summary": packet.chain_summary,
        "escalation_summary": packet.escalation_summary,
        "bounty_tier": packet.bounty_tier,
        "bounty_rationale": packet.bounty_rationale,
        "confidence": packet.confidence,
        "created": packet.created,
        "run_id": packet.run_id,
        "dedup_key": packet.dedup_key,
        "evidence": [
            item.to_dict() if isinstance(item, EvidenceRef) else redact_json_value(item)
            for item in packet.evidence
        ],
        "warnings": list(packet.warnings),
    }
    if include_packet_id:
        payload["packet_id"] = packet.packet_id
    return cast(dict[str, Any], redact_json_value(payload))


def packet_id_for(packet: SubmissionPacket) -> str:
    """Stable packet id derived from the redacted packet content."""
    core = _canonical_json(_packet_core(packet))
    digest = hashlib.sha256(core.encode("utf-8")).hexdigest()[:24]
    return f"pkt_{digest}"


def finalize_packet(packet: SubmissionPacket) -> SubmissionPacket:
    """Return a packet copy whose id is bound to its deterministic content."""
    return replace(packet, packet_id=packet_id_for(packet))


def packet_json(packet: SubmissionPacket) -> str:
    """Canonical JSON rendering of a packet."""
    return _canonical_json(packet_payload(packet, include_packet_id=True))


def packet_sha256(packet: SubmissionPacket) -> str:
    return hashlib.sha256(packet_json(packet).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def validate_packet_schema(packet: SubmissionPacket) -> list[str]:
    """Return schema violations for a packet; empty means schema-valid."""
    errors: list[str] = []
    if packet.schema != PACKET_SCHEMA:
        errors.append("schema")
    for name in (
        "packet_id",
        "claim_id",
        "claim_type",
        "title",
        "component",
        "surface",
        "root_cause",
        "crash_signature",
        "exploitability",
        "impact",
        "chain_summary",
        "escalation_summary",
        "bounty_tier",
        "bounty_rationale",
        "dedup_key",
    ):
        if not isinstance(getattr(packet, name), str):
            errors.append(name)
    if not isinstance(packet.repro_steps, tuple) or not all(
        isinstance(step, str) for step in packet.repro_steps
    ):
        errors.append("repro_steps")
    if not isinstance(packet.evidence, tuple) or not all(
        isinstance(item, EvidenceRef) for item in packet.evidence
    ):
        errors.append("evidence")
    if not isinstance(packet.warnings, tuple) or not all(
        isinstance(item, str) for item in packet.warnings
    ):
        errors.append("warnings")
    if not isinstance(packet.created, int) or isinstance(packet.created, bool) or packet.created < 0:
        errors.append("created")
    if (
        not isinstance(packet.confidence, int | float)
        or isinstance(packet.confidence, bool)
        or not math.isfinite(float(packet.confidence))
        or not 0.0 <= float(packet.confidence) <= 1.0
    ):
        errors.append("confidence")
    if packet.bounty_tier not in BOUNTY_TIERS:
        errors.append("bounty_tier")
    if packet.run_id is not None and not isinstance(packet.run_id, str):
        errors.append("run_id")
    return errors


__all__ = [
    "BOUNTY_TIERS",
    "MAX_EVIDENCE_REFS",
    "MAX_FIELD_CHARS",
    "MAX_REPRO_STEPS",
    "MAX_TEXT_CHARS",
    "PACKET_SCHEMA",
    "REPORT_SCHEMA",
    "EvidenceRef",
    "SubmissionPacket",
    "finalize_packet",
    "packet_id_for",
    "packet_json",
    "packet_payload",
    "packet_sha256",
    "validate_packet_schema",
]
