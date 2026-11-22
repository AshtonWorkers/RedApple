"""Ledger-backed Apple Security Bounty submission report generation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..ledger import ClaimState, Ledger
from .extract import packet_from_claim
from .models import SubmissionPacket, packet_json, packet_sha256
from .render import render_report_markdown

_REPORT_KIND = "submission_report"
_PACKET_KIND = "submission_packet"


@dataclass(frozen=True)
class RenderedSubmission:
    """One rendered report plus its deterministic hashes and artifact refs."""

    packet: SubmissionPacket
    markdown: str
    packet_json: str
    report_sha256: str
    packet_sha256: str
    report_artifact_id: str | None
    packet_artifact_id: str | None


@dataclass(frozen=True)
class SubmitReportResult:
    """Result of generating submission reports for promoted claims."""

    submissions: tuple[RenderedSubmission, ...]
    stored: bool

    @property
    def packets(self) -> tuple[SubmissionPacket, ...]:
        return tuple(item.packet for item in self.submissions)

    @property
    def report_count(self) -> int:
        return len(self.submissions)


class SubmitReportService:
    """Assemble, render, redact, and persist ASB submission reports.

    All durable state is written through the M0 claim ledger artifact API;
    rendered bytes are returned to the caller and content-addressed in the ledger.
    """

    def __init__(self, ledger: Ledger, *, max_claims: int = 100) -> None:
        if max_claims < 1:
            raise ValueError("max_claims must be positive")
        self._ledger = ledger
        self._max_claims = max_claims

    def _resolve_limit(self, limit: int | None) -> int:
        if limit is None:
            return self._max_claims
        if limit < 1:
            raise ValueError("limit must be positive")
        return limit

    def packets(self, *, limit: int | None = None) -> list[SubmissionPacket]:
        """Build packets for promoted claims without rendering or storing."""
        rows = self._ledger.claims_by_state(ClaimState.PROMOTED, limit=self._resolve_limit(limit))
        packets: list[SubmissionPacket] = []
        for row in rows:
            warnings: list[str] = []
            artifacts: list[dict[str, Any]] = []
            claim_id = row.get("id")
            if isinstance(claim_id, str) and claim_id:
                try:
                    artifacts = self._ledger.claim_artifacts(claim_id)
                except Exception as exc:
                    warnings.append(f"artifact metadata read failed: {type(exc).__name__}")
            else:
                warnings.append("claim id missing; artifact metadata not read")
            packets.append(packet_from_claim(row, artifacts, extra_warnings=warnings))
        return packets

    async def generate(self, *, limit: int | None = None, store: bool = True) -> SubmitReportResult:
        """Render packets and optionally persist report/packet artifacts."""
        submissions: list[RenderedSubmission] = []
        for packet in self.packets(limit=limit):
            markdown = render_report_markdown(packet)
            packet_json_text = packet_json(packet)
            report_sha = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
            packet_sha = packet_sha256(packet)
            report_artifact_id: str | None = None
            packet_artifact_id: str | None = None
            if store:
                report_artifact_id = await self._ledger.put_artifact(
                    _REPORT_KIND,
                    markdown.encode("utf-8"),
                    ttl_class="pinned",
                )
                packet_artifact_id = await self._ledger.put_artifact(
                    _PACKET_KIND,
                    packet_json_text.encode("utf-8"),
                    ttl_class="pinned",
                )
            submissions.append(
                RenderedSubmission(
                    packet=packet,
                    markdown=markdown,
                    packet_json=packet_json_text,
                    report_sha256=report_sha,
                    packet_sha256=packet_sha,
                    report_artifact_id=report_artifact_id,
                    packet_artifact_id=packet_artifact_id,
                )
            )
        return SubmitReportResult(submissions=tuple(submissions), stored=store)


__all__ = ["RenderedSubmission", "SubmitReportResult", "SubmitReportService"]
