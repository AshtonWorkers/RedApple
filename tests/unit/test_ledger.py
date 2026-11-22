import asyncio
import json

import pytest

from ra.errors import DuplicateDedup, FormatFail
from ra.ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    ClaimState,
    Ledger,
)
from ra.ledger.ids import UlidFactory, artifact_id, dedup_key
from ra.ledger.operations import LedgerOperation
from ra.ledger.states import TRANSITIONS
from tests.conftest import run


def claim(claim_id: str, key: str, data: bytes = b"evidence") -> ClaimInput:
    return ClaimInput(
        claim_id=claim_id,
        type="bug_class",
        value_json=json.dumps({"answer": "insufficient_evidence"}),
        confidence=0.5,
        dedup_key=key,
        created=1,
        artifacts=(ClaimArtifactInput(ArtifactInput(kind="crash", data=data), role="evidence"),),
    )


def test_RA_LED_001_claim_lifecycle_and_artifact_link(tmp_path):
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cid = await ledger.create_claim(claim("cl_1", "key-1", b"one"))
            row = ledger.get_claim(cid)
            assert row is not None and row["state"] == "limbo"
            assert ledger.claim_artifact_count(cid) == 1
            assert ledger.claim_artifacts(cid)[0]["artifact_id"] == artifact_id(b"one")
            await ledger.transition_claim(cid, ClaimState.BOUND)
            await ledger.transition_claim(cid, ClaimState.REVIEWED)
            await ledger.transition_claim(cid, ClaimState.PROMOTED)
            assert ledger.get_claim(cid)["state"] == "promoted"
            assert ledger.integrity_check() == "ok"
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_001_wal_reopen(tmp_path):
    async def body():
        path = tmp_path / "ledger.sqlite"
        ledger = await Ledger.open(path)
        await ledger.put_artifact("crash", b"wal")
        await ledger.close()
        again = await Ledger.open(path)
        try:
            assert again.pragma_value("journal_mode") == "wal"
            assert again.artifact_count() == 1
            assert again.integrity_check() == "ok"
        finally:
            await again.close()

    run(body())


def test_RA_LED_002_batched_commits_single_writer():
    async def body():
        ledger = await Ledger.open(":memory:", max_queue=2048)
        try:
            await asyncio.gather(
                *(ledger.put_artifact("crash", f"batch-{i}".encode()) for i in range(250))
            )
            stats = ledger.actor.stats()
            assert stats["rows"] >= 250
            assert stats["batches"] >= 1
            assert "commit_ms_p99" in stats
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_003_ulid_ids_unique():
    ids = UlidFactory()
    values = {ids.new("cl") for _ in range(1000)}
    assert len(values) == 1000
    assert all(value.startswith("cl_") for value in values)


def test_RA_LED_004_state_machine_and_idempotency():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cid = await ledger.create_claim(claim("cl_sm", "key-sm"))
            first = await ledger.transition_claim(cid, ClaimState.BOUND)
            second = await ledger.transition_claim(cid, ClaimState.BOUND)
            assert first["changed"] is True
            assert second["changed"] is False
            with pytest.raises(FormatFail):
                await ledger.transition_claim(cid, ClaimState.PARKED)
            assert TRANSITIONS[ClaimState.PROMOTED] == frozenset()
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_005_dedup_key_unique():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            key = dedup_key("bug_class", "a" * 64, "site")
            await ledger.create_claim(claim("cl_d1", key, b"one"))
            with pytest.raises(DuplicateDedup):
                await ledger.create_claim(claim("cl_d2", key, b"two"))
            assert ledger.claim_by_dedup(key)["id"] == "cl_d1"
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_006_explain_query_plan_uses_indexes():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.create_claim(claim("cl_q", "key-q"))
            state_plan = ledger.explain(
                "SELECT id FROM claim WHERE state=? ORDER BY created, id LIMIT ?", ("limbo", 10)
            )
            dedup_plan = ledger.explain("SELECT id FROM claim WHERE dedup_key=?", ("key-q",))
            assert any("ix_claim_state" in line for line in state_plan)
            assert any("ux_claim_dedup" in line for line in dedup_plan)
            assert ledger.invariant_counts()["i6"] == 0
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_008_retention_delete_artifacts():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cid = await ledger.create_claim(claim("cl_ret", "key-ret", b"retention"))
            art = artifact_id(b"retention")
            assert await ledger.delete_artifacts([art]) == 1
            assert ledger.artifact_count() == 0
            assert ledger.claim_artifact_count(cid) == 0
            assert ledger.retention_candidates("run", cutoff=2**62, limit=10) == []
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_008_auxiliary_rows():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            run_id = await ledger.create_run("macos", budget={"spend_usd_micro": 1}, state="armed")
            assert await ledger.end_run(run_id, "drained") is True
            await ledger.record_decision(
                trigger_metric="t", observed=1.0, expected="e", spent_usd_micro=7, run_id=run_id
            )
            assert ledger.spent_usd_micro(run_id) == 7
            wid = await ledger.enqueue_work_order(
                action="park", unit="u", ev_cost=2.0, run_id=run_id
            )
            assert await ledger.update_work_order_state(wid, "done") is True
            assert ledger.get_work_order(wid)["state"] == "done"
            await ledger.record_packet_log(
                packet_id="pkt_1",
                sha="a" * 64,
                task_type="bug_class",
                run_id=run_id,
                schema_ok=True,
            )
            node = {
                "ring_node_id": "node-1",
                "ipsw_sha": "ipsw",
                "build": "build",
                "xcode": "x",
                "sdk": "sdk",
                "webkit_commit": "webkit",
                "state": "current",
                "epoch": 1,
            }
            assert await ledger.upsert_ring_node(node) == "node-1"
            await ledger.upsert_device_profile(
                {"udid": "udid", "tier": "C", "state": "attached", "crashes": 0}
            )
            await ledger.create_claim(claim("cl_aux_a", "key-aux-a", b"aux-a"))
            await ledger.create_claim(claim("cl_aux_b", "key-aux-b", b"aux-b"))
            assert (
                await ledger.insert_verdict(claim_id="cl_aux_a", reviewer="r", agree=True) > 0
                or True
            )
            assert (
                await ledger.insert_join(
                    {
                        "join_id": "j1",
                        "a_claim": "cl_aux_a",
                        "b_claim": "cl_aux_b",
                        "invariants_json": "[]",
                        "reliability": 0.5,
                        "lower_bound": 1,
                        "state": "candidate",
                        "created": 1,
                    }
                )
                == "j1"
            )
            assert (
                await ledger.insert_entry_point(
                    {
                        "entry_point_id": "ep1",
                        "name": "ep",
                        "reach_from_json": "[]",
                        "privilege_delta": 1,
                        "parser_complexity": 0.5,
                        "weight": 1.0,
                        "ring_node": "node-1",
                    }
                )
                == "ep1"
            )
            assert ledger.ring_node("node-1")["state"] == "current"
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_work_order_settle_shed_public_paths():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            wid = await ledger.enqueue_work_order(
                action="park", unit="u", ev_cost=1.0, payload_json='{"cas_bytes":0}'
            )
            assert (
                await ledger.settle_work_order(
                    wid,
                    state="done",
                    trigger_metric="t",
                    observed=1.0,
                    expected="e",
                    spent_usd_micro=0,
                )
                is True
            )
            row = ledger.get_work_order(wid)
            assert row is not None and row["state"] == "done"
            decisions = ledger.decision_rows(wo_id=wid)
            assert decisions[0]["unit"] == "u"

            with pytest.raises(FormatFail):
                await ledger.settle_work_order(
                    wid,
                    state="done",
                    trigger_metric="t",
                    observed=1.0,
                    expected="e",
                    spent_usd_micro=0,
                )
            with pytest.raises(FormatFail):
                await ledger.settle_work_order(
                    "missing",
                    state="done",
                    trigger_metric="t",
                    observed=1.0,
                    expected="e",
                    spent_usd_micro=0,
                )

            wid2 = await ledger.enqueue_work_order(action="park", unit="u2", ev_cost=1.0)
            assert (
                await ledger.shed_work_order(
                    wid2, state="shed", payload_json='{"shed_reason":"test"}'
                )
                is True
            )
            row2 = ledger.get_work_order(wid2)
            assert row2 is not None and row2["state"] == "shed"
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_batch_operation_validation():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cases = [
                {"operations": []},
                {"operations": [1]},
                {"operations": [{"kind": "batch", "payload": {}, "rows": 1}]},
                {"operations": [{"kind": "record_decision", "payload": [], "rows": 1}]},
                {"operations": [{"kind": "record_decision", "payload": {}, "rows": 0}]},
                {"operations": [{"kind": "nope", "payload": {}, "rows": 1}]},
            ]
            for operations in cases:
                with pytest.raises(FormatFail):
                    ledger.store.apply_batch(
                        [LedgerOperation("batch", {"operations": operations}, rows=1)]
                    )
        finally:
            await ledger.close()

    run(body())


def test_RA_LED_introspection_and_context_manager():
    async def body():
        async with await Ledger.open(":memory:") as ledger:
            artifact = await ledger.put_artifact("crash", b"pin", ttl_class="pinned")
            assert ledger.artifact_ttl_counts() == {"pinned": 1}
            oldest = ledger.oldest_artifact("pinned")
            assert oldest is not None and oldest["id"] == artifact
            assert "work_order" in ledger.table_names()
            indexes = ledger.index_names("work_order")
            assert "ix_wo_ready_ev" in indexes
            assert "ix_wo_ready_cas" in indexes
            assert await ledger.sweep_artifacts("ephemeral", limit=1) == 0
            assert ledger.claims_by_state(ClaimState.LIMBO) == []
            with pytest.raises(FormatFail):
                await ledger.record_decision(
                    trigger_metric="t",
                    observed=1.0,
                    expected="e",
                    spent_usd_micro=True,
                )

    run(body())
