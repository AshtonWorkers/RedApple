"""Ledger emission tests for escalation claims."""

import asyncio
import json
from pathlib import Path

import pytest

from ra.errors import FormatFail
from ra.escalate import (
    ESCALATION_CLAIM_KIND,
    ESCALATION_LEDGER_TYPE,
    ESCALATION_SCHEMA,
    EscalationGraph,
    EscalationLedgerEmitter,
    analyze_escalations,
    graph_from_mappings,
)
from ra.ledger import Ledger


def _graph() -> EscalationGraph:
    return graph_from_mappings(
        [
            {"id": "sandbox:a", "stage": "sandbox_profile"},
            {"id": "ent:x", "stage": "entitlement"},
            {"id": "root:r", "stage": "root"},
        ],
        [
            {"source": "sandbox:a", "target": "ent:x", "privilege_delta": 1, "impact_delta": 0.25, "reliability": 0.8},
            {"source": "ent:x", "target": "root:r", "privilege_delta": 2, "impact_delta": 0.5, "reliability": 1.0},
        ],
    )


def test_emit_creates_deduped_claims_with_artifacts(tmp_path: Path):
    async def main() -> None:
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        try:
            await ledger.create_run("macos", run_id="run-1")
            result = analyze_escalations(_graph(), max_paths=5)
            emitter = EscalationLedgerEmitter(ledger)
            emitted = await emitter.emit(result, run_id="run-1", created=1234, ttl_class="pinned")
            assert len(emitted.emitted) == len(result.paths)
            assert emitted.skipped == ()
            assert emitted.to_dict()["emitted"]
            rows = ledger.claims_by_type(ESCALATION_LEDGER_TYPE, limit=10)
            assert len(rows) == len(result.paths)
            assert all(row["type"] == ESCALATION_LEDGER_TYPE for row in rows)
            assert all(row["state"] == "limbo" for row in rows)
            payload = json.loads(rows[0]["value_json"])
            assert payload["schema"] == ESCALATION_SCHEMA
            assert payload["kind"] == ESCALATION_CLAIM_KIND
            assert payload["claim_kind"] == "escalation"
            assert payload["path"]["nodes"]
            assert ledger.claim_artifact_count(rows[0]["id"]) == 1
            artifact = ledger.claim_artifacts(rows[0]["id"])[0]
            assert artifact["kind"] == "escalation_path"
            assert artifact["ttl_class"] == "pinned"

            again = await emitter.emit(result, run_id="run-1", created=1234)
            assert again.emitted == ()
            assert len(again.skipped) == len(result.paths)
            assert len(ledger.claims_by_type(ESCALATION_LEDGER_TYPE, limit=10)) == len(result.paths)

            limited = await emitter.emit(result, limit=1, created=5678)
            assert limited.emitted == ()
            assert len(limited.skipped) == 1
        finally:
            await ledger.close()

    asyncio.run(main())


def test_emit_rejects_bad_limit(tmp_path: Path):
    async def main() -> None:
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        try:
            result = analyze_escalations(_graph(), max_paths=1)
            with pytest.raises(FormatFail):
                await EscalationLedgerEmitter(ledger).emit(result, limit=0)
        finally:
            await ledger.close()

    asyncio.run(main())
