"""Ledger-backed persistence for JSC discovery crashes and campaigns.

All durable discovery state lives in the M0 claim ledger: each unique crash is
a ``discovery_crash`` claim whose ``value_json`` carries the bounded repro
input, stderr tail, and symbolized stack, plus content-addressed artifact
links (``art_<sha256>``) for CAS resolution. Dedup is the ledger's
``ux_claim_dedup`` unique index, so a restarted campaign never double-records
a signature. Campaign counters end as ``discovery_campaign`` claims.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..errors import DuplicateDedup, FormatFail
from ..ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    Ledger,
    UlidFactory,
    dedup_key,
)
from ..ledger.ids import artifact_id, now_ms
from .harness import CrashResult

CLAIM_TYPE_CRASH = "discovery_crash"
CLAIM_TYPE_CAMPAIGN = "discovery_campaign"
ARTIFACT_KIND_INPUT = "jsc_input"
ARTIFACT_KIND_STDERR = "jsc_stderr"
ARTIFACT_KIND_STACK = "jsc_stack"
ARTIFACT_KIND_CAMPAIGN = "discovery_campaign"
DEDUP_ALLOC_SITE = "jsc"
CRASH_CLAIM_LIMIT = 10000
MAX_INLINE_INPUT = 64 * 1024


@dataclass(frozen=True)
class CrashRecord:
    """One unique crash persisted as a ledger claim."""

    claim_id: str
    signature: str
    crash_type: str
    signal: str
    returncode: int
    stack: tuple[str, ...]
    input_js: bytes
    stderr: str
    handle_id: str
    target: str
    ring_node: str | None
    build: str | None
    artifact_ids: tuple[str, ...]
    created_ms: int
    campaign_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CampaignSummary:
    """End-of-campaign counters persisted as a ``discovery_campaign`` claim."""

    campaign_id: str
    handle_id: str
    target: str
    ring_node: str | None
    build: str | None
    jsc_binary: str
    jsc_args: tuple[str, ...]
    seed: int
    executions: int
    unique_crashes: int
    total_crashes: int
    exec_errors: int
    timeouts: int
    duration_ms: int
    run_id: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "handle_id": self.handle_id,
            "target": self.target,
            "ring_node": self.ring_node,
            "build": self.build,
            "jsc_binary": self.jsc_binary,
            "jsc_args": list(self.jsc_args),
            "seed": self.seed,
            "executions": self.executions,
            "unique_crashes": self.unique_crashes,
            "total_crashes": self.total_crashes,
            "exec_errors": self.exec_errors,
            "timeouts": self.timeouts,
            "duration_ms": self.duration_ms,
            "run_id": self.run_id,
            "extra": dict(self.extra),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> CampaignSummary:
        extra = data.get("extra")
        return CampaignSummary(
            campaign_id=str(data["campaign_id"]),
            handle_id=str(data["handle_id"]),
            target=str(data.get("target", "")),
            ring_node=_opt_str(data.get("ring_node")),
            build=_opt_str(data.get("build")),
            jsc_binary=str(data.get("jsc_binary", "")),
            jsc_args=tuple(str(arg) for arg in data.get("jsc_args", ())),
            seed=int(data.get("seed", 0)),
            executions=int(data.get("executions", 0)),
            unique_crashes=int(data.get("unique_crashes", 0)),
            total_crashes=int(data.get("total_crashes", 0)),
            exec_errors=int(data.get("exec_errors", 0)),
            timeouts=int(data.get("timeouts", 0)),
            duration_ms=int(data.get("duration_ms", 0)),
            run_id=_opt_str(data.get("run_id")),
            extra=dict(extra) if isinstance(extra, Mapping) else {},
        )


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


class LedgerCrashStore:
    """Persist discovery crashes and campaigns as ledger claims."""

    def __init__(self, ledger: Ledger, *, id_prefix: str = "jsc") -> None:
        self._ledger = ledger
        self._ids = UlidFactory()
        self._prefix = id_prefix

    async def known_signatures(self) -> set[str]:
        """All crash signatures already present in the ledger."""
        signatures: set[str] = set()
        for row in self._crash_rows():
            value = _value_json(row)
            signature = value.get("signature")
            if isinstance(signature, str):
                signatures.add(signature)
        return signatures

    async def record_crash(
        self,
        content: str | bytes,
        result: CrashResult,
        meta: Mapping[str, Any],
    ) -> CrashRecord | None:
        """Persist one unique crash; return ``None`` when the signature is known."""
        if not result.is_crash or not result.signature:
            raise FormatFail("record_crash requires a classified crash result")
        handle_id = _required_str(meta, "handle_id")
        data = _to_bytes(content)
        stack_json = json.dumps(list(result.stack), separators=(",", ":")).encode("utf-8")
        stderr_bytes = result.stderr.encode("utf-8", errors="replace")
        input_b64 = base64.b64encode(data).decode("ascii") if len(data) <= MAX_INLINE_INPUT else None
        value = {
            "signature": result.signature,
            "crash_type": result.crash_type,
            "signal": result.signal,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stack": list(result.stack),
            "input_sha256": artifact_id(data),
            "input_inline": input_b64,
            "stderr": result.stderr,
            "handle_id": handle_id,
            "target": str(meta.get("target", "")),
            "ring_node": _opt_str(meta.get("ring_node")),
            "build": _opt_str(meta.get("build")),
            "campaign_id": _opt_str(meta.get("campaign_id")),
            "run_id": _opt_str(meta.get("run_id")),
            "jsc_binary": _opt_str(meta.get("jsc_binary")),
            "jsc_args": [str(arg) for arg in meta.get("jsc_args", ())],
        }
        value_json = json.dumps(value, sort_keys=True, separators=(",", ":"))
        claim_id = self._ids.new(self._prefix)
        created = now_ms()
        try:
            await self._ledger.create_claim(
                ClaimInput(
                    claim_id=claim_id,
                    type=CLAIM_TYPE_CRASH,
                    value_json=value_json,
                    confidence=1.0,
                    dedup_key=dedup_key(result.crash_type, result.signature, DEDUP_ALLOC_SITE),
                    created=created,
                    run_id=_opt_str(meta.get("run_id")),
                    artifacts=(
                        ClaimArtifactInput(
                            artifact=ArtifactInput(kind=ARTIFACT_KIND_INPUT, data=data, ttl_class="run"),
                            role="repro",
                        ),
                        ClaimArtifactInput(
                            artifact=ArtifactInput(kind=ARTIFACT_KIND_STDERR, data=stderr_bytes, ttl_class="run"),
                            role="log",
                        ),
                        ClaimArtifactInput(
                            artifact=ArtifactInput(kind=ARTIFACT_KIND_STACK, data=stack_json, ttl_class="run"),
                            role="stack",
                        ),
                    ),
                )
            )
        except DuplicateDedup:
            return None
        return CrashRecord(
            claim_id=claim_id,
            signature=result.signature,
            crash_type=result.crash_type,
            signal=result.signal,
            returncode=result.returncode,
            stack=result.stack,
            input_js=data,
            stderr=result.stderr,
            handle_id=handle_id,
            target=str(meta.get("target", "")),
            ring_node=_opt_str(meta.get("ring_node")),
            build=_opt_str(meta.get("build")),
            artifact_ids=(
                artifact_id(data),
                artifact_id(stderr_bytes),
                artifact_id(stack_json),
            ),
            created_ms=created,
            campaign_id=_opt_str(meta.get("campaign_id")),
            metadata=dict(meta),
        )

    async def crashes_for_handle(self, handle_id: str) -> list[CrashRecord]:
        """All crash records observed by one lane handle, oldest first."""
        records: list[CrashRecord] = []
        for row in self._crash_rows():
            value = _value_json(row)
            if value.get("handle_id") != handle_id:
                continue
            record = _record_from_row(row, value, self._artifact_ids(str(row["id"])))
            if record is not None:
                records.append(record)
        records.sort(key=lambda record: (record.created_ms, record.claim_id))
        return records

    async def record_campaign(self, summary: CampaignSummary) -> str:
        """Persist a campaign summary claim; returns the claim id."""
        value_json = json.dumps(summary.to_dict(), sort_keys=True, separators=(",", ":"))
        data = value_json.encode("utf-8")
        dedup = f"{CLAIM_TYPE_CAMPAIGN}:{summary.campaign_id}"
        existing = self._ledger.claim_by_dedup(dedup)
        if existing is not None:
            return str(existing["id"])
        claim_id = self._ids.new("camp")
        await self._ledger.create_claim(
            ClaimInput(
                claim_id=claim_id,
                type=CLAIM_TYPE_CAMPAIGN,
                value_json=value_json,
                confidence=1.0,
                dedup_key=dedup,
                created=now_ms(),
                run_id=summary.run_id,
                artifacts=(
                    ClaimArtifactInput(
                        artifact=ArtifactInput(kind=ARTIFACT_KIND_CAMPAIGN, data=data, ttl_class="run"),
                        role="summary",
                    ),
                ),
            )
        )
        return claim_id

    async def campaign_summaries(self, *, limit: int = CRASH_CLAIM_LIMIT) -> list[CampaignSummary]:
        """All persisted campaign summaries, oldest first."""
        summaries: list[CampaignSummary] = []
        for row in self._ledger.claims_by_type(CLAIM_TYPE_CAMPAIGN, limit=limit):
            try:
                summaries.append(CampaignSummary.from_dict(_value_json(row)))
            except (KeyError, TypeError, ValueError):
                continue
        summaries.sort(key=lambda item: item.campaign_id)
        return summaries

    def _crash_rows(self) -> list[dict[str, Any]]:
        return self._ledger.claims_by_type(CLAIM_TYPE_CRASH, limit=CRASH_CLAIM_LIMIT)

    def _artifact_ids(self, claim_id: str) -> tuple[str, ...]:
        rows = self._ledger.claim_artifacts(claim_id)
        return tuple(sorted({str(row["artifact_id"]) for row in rows}))


def _to_bytes(content: str | bytes) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace")
    return bytes(content)


def _required_str(meta: Mapping[str, Any], key: str) -> str:
    value = meta.get(key)
    if not isinstance(value, str) or not value:
        raise FormatFail(f"crash meta requires non-empty {key!r}")
    return value


def _value_json(row: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(str(row["value_json"]))
    except (KeyError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _record_from_row(
    row: Mapping[str, Any], value: Mapping[str, Any], artifact_ids: tuple[str, ...]
) -> CrashRecord | None:
    signature = value.get("signature")
    crash_type = value.get("crash_type")
    if not isinstance(signature, str) or not isinstance(crash_type, str):
        return None
    stack_raw = value.get("stack")
    stack: tuple[str, ...] = (
        tuple(str(frame) for frame in stack_raw) if isinstance(stack_raw, list) else ()
    )
    input_js = _inline_input(value)
    return CrashRecord(
        claim_id=str(row["id"]),
        signature=signature,
        crash_type=crash_type,
        signal=str(value.get("signal", "")),
        returncode=_safe_int(value.get("returncode")),
        stack=stack,
        input_js=input_js,
        stderr=str(value.get("stderr", "")),
        handle_id=str(value.get("handle_id", "")),
        target=str(value.get("target", "")),
        ring_node=_opt_str(value.get("ring_node")),
        build=_opt_str(value.get("build")),
        artifact_ids=artifact_ids,
        created_ms=_safe_int(row.get("created")),
        campaign_id=_opt_str(value.get("campaign_id")),
        metadata={},
    )


def _inline_input(value: Mapping[str, Any]) -> bytes:
    inline = value.get("input_inline")
    if isinstance(inline, str) and inline:
        try:
            return base64.b64decode(inline, validate=True)
        except ValueError:
            return b""
    return b""


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def records_from_rows(rows: Sequence[Mapping[str, Any]]) -> list[CrashRecord]:
    """Convert raw claim rows to crash records (used by tests and tooling)."""
    records: list[CrashRecord] = []
    for row in rows:
        record = _record_from_row(row, _value_json(row), ())
        if record is not None:
            records.append(record)
    return records
