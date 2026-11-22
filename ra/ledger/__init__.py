"""Claim Ledger public facade.

Writes go through the single-writer mailbox; reads use the same SQLite store.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from ..errors import FormatFail
from .actor import LedgerActor
from .db import LedgerStore
from .ids import UlidFactory, artifact_id, dedup_key, now_ms, sha256_hex
from .models import ArtifactInput, ClaimArtifactInput, ClaimInput
from .states import ClaimState

__all__ = [
    "Ledger",
    "LedgerStore",
    "ClaimState",
    "ArtifactInput",
    "ClaimArtifactInput",
    "ClaimInput",
    "UlidFactory",
    "dedup_key",
]


class Ledger:
    """Async facade over the ledger store and actor."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_queue: int = 1024,
        max_batch_rows: int = 200,
        max_batch_ms: int = 25,
        wal_autocheckpoint: int = 1000,
    ) -> None:
        self.store = LedgerStore(path, wal_autocheckpoint=wal_autocheckpoint)
        self.actor = LedgerActor(
            self.store,
            max_queue=max_queue,
            max_batch_rows=max_batch_rows,
            max_batch_ms=max_batch_ms,
        )
        self._ids = UlidFactory()

    @classmethod
    async def open(
        cls,
        path: str | Path,
        *,
        max_queue: int = 1024,
        max_batch_rows: int = 200,
        max_batch_ms: int = 25,
        wal_autocheckpoint: int = 1000,
    ) -> Ledger:
        """Open a ledger and start its writer actor."""
        ledger = cls(
            path,
            max_queue=max_queue,
            max_batch_rows=max_batch_rows,
            max_batch_ms=max_batch_ms,
            wal_autocheckpoint=wal_autocheckpoint,
        )
        await ledger.actor.start()
        return ledger

    async def close(self) -> None:
        """Stop the actor and close the store."""
        await self.actor.stop()
        self.store.close()

    async def __aenter__(self) -> Ledger:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    def _artifact_payload(
        self, artifact: ArtifactInput, *, created: int | None = None
    ) -> dict[str, Any]:
        when = now_ms() if created is None else created
        digest = sha256_hex(artifact.data)
        return {
            "artifact_id": artifact_id(artifact.data),
            "kind": artifact.kind,
            "sha256": digest,
            "bytes": len(artifact.data),
            "created": when,
            "ttl_class": artifact.ttl_class,
        }

    async def _submit(self, kind: str, payload: Mapping[str, Any], *, rows: int = 1) -> object:
        return await self.actor.submit(kind, payload, rows=rows)

    async def create_run(
        self,
        mode: str,
        *,
        budget: Mapping[str, Any] | None = None,
        state: str = "armed",
        run_id: str | None = None,
    ) -> str:
        """Create a run row; budget is JSON with integer micro-USD values."""
        rid = run_id or self._ids.new("run")
        budget_json = json.dumps(dict(budget or {}), sort_keys=True, separators=(",", ":"))
        result = await self._submit(
            "create_run",
            {
                "run_id": rid,
                "started": now_ms(),
                "ended": None,
                "mode": mode,
                "budget_json": budget_json,
                "state": state,
            },
        )
        return cast(str, result)

    async def end_run(self, run_id: str, state: str, *, ended: int | None = None) -> bool:
        """End a run row."""
        result = await self._submit(
            "end_run",
            {"run_id": run_id, "ended": now_ms() if ended is None else ended, "state": state},
        )
        return cast(bool, result)

    async def put_artifact(self, kind: str, data: bytes, *, ttl_class: str = "run") -> str:
        """Store content-addressed bytes; identical bytes reuse the same ID."""
        artifact = ArtifactInput(kind=kind, data=data, ttl_class=ttl_class)
        payload = self._artifact_payload(artifact)
        result = await self._submit("put_artifact", payload)
        return cast(str, result)

    async def create_claim(self, claim: ClaimInput) -> str:
        """Persist a model output as a limbo claim with artifact links (RA-LED-001)."""
        if not claim.artifacts:
            raise FormatFail("claim requires at least one artifact link")
        artifact_rows: list[dict[str, Any]] = []
        for link in claim.artifacts:
            row = self._artifact_payload(link.artifact, created=claim.created)
            row["role"] = link.role
            artifact_rows.append(row)
        payload = {
            "claim_id": claim.claim_id,
            "run_id": claim.run_id,
            "type": claim.type,
            "value_json": claim.value_json,
            "confidence": claim.confidence,
            "dedup_key": claim.dedup_key,
            "created": claim.created,
            "artifacts": artifact_rows,
        }
        result = await self._submit("create_claim", payload, rows=1 + 2 * len(artifact_rows))
        return cast(str, result)

    async def transition_claim(
        self, claim_id: str, to_state: str | ClaimState
    ) -> dict[str, object]:
        """Apply a legal claim transition exactly once per (claim, to_state)."""
        target = to_state.value if isinstance(to_state, ClaimState) else to_state
        result = await self._submit(
            "transition_claim",
            {"claim_id": claim_id, "to_state": target, "created": now_ms()},
            rows=3,
        )
        return cast(dict[str, object], result)

    async def record_decision(
        self,
        *,
        trigger_metric: str,
        observed: float,
        expected: str,
        spent_usd_micro: int,
        run_id: str | None = None,
        wo_id: str | None = None,
        created: int | None = None,
    ) -> int:
        """Record a policy decision; money is integer micro-USD (I4)."""
        if isinstance(spent_usd_micro, bool) or not isinstance(spent_usd_micro, int):
            raise FormatFail("spent_usd_micro must be int")
        if spent_usd_micro < 0:
            raise FormatFail("spent_usd_micro must be non-negative")
        result = await self._submit(
            "record_decision",
            {
                "run_id": run_id,
                "wo_id": wo_id,
                "trigger_metric": trigger_metric,
                "observed": observed,
                "expected": expected,
                "spent_usd_micro": spent_usd_micro,
                "created": now_ms() if created is None else created,
            },
        )
        return cast(int, result)

    async def enqueue_work_order(
        self,
        *,
        action: str,
        unit: str,
        ev_cost: float,
        state: str = "ready",
        run_id: str | None = None,
        payload_json: str | None = None,
        work_order_id: str | None = None,
        created: int | None = None,
    ) -> str:
        """Enqueue a policy work order."""
        wid = work_order_id or self._ids.new("wo")
        result = await self._submit(
            "enqueue_work_order",
            {
                "work_order_id": wid,
                "run_id": run_id,
                "action": action,
                "unit": unit,
                "payload_json": payload_json,
                "ev_cost": ev_cost,
                "state": state,
                "created": now_ms() if created is None else created,
            },
        )
        return cast(str, result)

    async def update_work_order_state(
        self, work_order_id: str, state: str, *, payload_json: str | None = None
    ) -> bool:
        """Update a work order state."""
        result = await self._submit(
            "update_work_order_state",
            {"work_order_id": work_order_id, "state": state, "payload_json": payload_json},
        )
        return cast(bool, result)

    async def dispatch_work_order(
        self,
        *,
        work_order_id: str,
        budget_usd_micro: int,
        spent_usd_micro: int,
        trigger_metric: str = "dispatch",
        observed: float = 0.0,
        expected: str = "",
        created: int | None = None,
    ) -> dict[str, object]:
        """Atomically gate, spend, decide, and complete one ready work order."""
        result = await self._submit(
            "dispatch_work_order",
            {
                "work_order_id": work_order_id,
                "budget_usd_micro": budget_usd_micro,
                "spent_usd_micro": spent_usd_micro,
                "trigger_metric": trigger_metric,
                "observed": observed,
                "expected": expected,
                "created": now_ms() if created is None else created,
            },
            rows=2,
        )
        return cast(dict[str, object], result)

    async def record_packet_log(
        self,
        *,
        packet_id: str,
        sha: str,
        task_type: str | None = None,
        run_id: str | None = None,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
        latency_ms: int | None = None,
        schema_ok: bool | None = None,
        bound_ok: bool | None = None,
        relevance: float | None = None,
        created: int | None = None,
    ) -> str:
        """Record PRESS telemetry (RA-MDL-008)."""
        result = await self._submit(
            "record_packet_log",
            {
                "packet_id": packet_id,
                "run_id": run_id,
                "task_type": task_type,
                "sha": sha,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "latency_ms": latency_ms,
                "schema_ok": schema_ok,
                "bound_ok": bound_ok,
                "relevance": relevance,
                "created": now_ms() if created is None else created,
            },
        )
        return cast(str, result)

    async def upsert_ring_node(self, payload: Mapping[str, Any]) -> str:
        """Upsert a version-ring node."""
        result = await self._submit("upsert_ring_node", dict(payload))
        return cast(str, result)

    async def upsert_device_profile(self, payload: Mapping[str, Any]) -> str:
        """Upsert a device profile."""
        result = await self._submit("upsert_device_profile", dict(payload))
        return cast(str, result)

    async def advance_ring(self, epoch: int, node_payloads: Sequence[Mapping[str, Any]]) -> int:
        """Atomically advance the version ring (RA-RING-004)."""
        result = await self._submit(
            "advance_ring",
            {"epoch": epoch, "nodes": [dict(node) for node in node_payloads]},
            rows=len(node_payloads) + 1,
        )
        return cast(int, result)

    async def delete_artifacts(
        self, artifact_ids: Sequence[str], *, min_set: int = 0
    ) -> int:
        """Delete retention-eligible artifacts and their claim links."""
        payload = {
            "artifact_ids": [{"artifact_id": item} for item in artifact_ids],
            "min_set": min_set,
        }
        result = await self._submit("delete_artifacts", payload, rows=2 * len(artifact_ids))
        return cast(int, result)

    async def insert_verdict(
        self,
        *,
        claim_id: str,
        reviewer: str,
        agree: bool,
        reason: str | None = None,
        created: int | None = None,
    ) -> int:
        """Record a review verdict for a claim."""
        result = await self._submit(
            "insert_verdict",
            {
                "claim_id": claim_id,
                "reviewer": reviewer,
                "agree": agree,
                "reason": reason,
                "created": now_ms() if created is None else created,
            },
        )
        return cast(int, result)

    async def link_claim_artifact(
        self,
        claim_id: str,
        artifact: ArtifactInput,
        *,
        role: str = "evidence",
        created: int | None = None,
    ) -> bool:
        """Link an existing artifact to an existing claim exactly once per role."""
        payload = self._artifact_payload(artifact, created=created)
        payload["claim_id"] = claim_id
        payload["role"] = role
        result = await self._submit("link_claim_artifact", payload, rows=2)
        return cast(bool, result)

    async def insert_join(self, payload: Mapping[str, Any]) -> str:
        """Insert a join row (skeleton; full join execution is M3)."""
        result = await self._submit("insert_join", dict(payload))
        return cast(str, result)

    async def update_join(
        self,
        join_id: str,
        *,
        state: str,
        reliability: float | None = None,
        lower_bound: float | None = None,
        invariants_json: str | None = None,
    ) -> bool:
        """Update measured reliability/state for one join row."""
        payload: dict[str, Any] = {"join_id": join_id, "state": state}
        if reliability is not None:
            payload["reliability"] = reliability
        if lower_bound is not None:
            payload["lower_bound"] = lower_bound
        if invariants_json is not None:
            payload["invariants_json"] = invariants_json
        result = await self._submit("update_join", payload)
        return cast(bool, result)

    async def insert_entry_point(self, payload: Mapping[str, Any]) -> str:
        """Insert a surface-graph entry point."""
        result = await self._submit("insert_entry_point", dict(payload))
        return cast(str, result)

    async def replace_entry_points(
        self, ring_node: str, rows: Sequence[Mapping[str, Any]]
    ) -> int:
        """Atomically replace all entry points for one ring node."""
        payload = {"ring_node": ring_node, "rows": [dict(row) for row in rows]}
        result = await self._submit("replace_entry_points", payload, rows=len(rows) + 1)
        return cast(int, result)

    async def sweep_artifacts(
        self, ttl_class: str, *, limit: int = 500, min_set: int = 0
    ) -> int:
        """Delete a batch of artifacts by TTL class (retention sweep helper)."""
        result = await self._submit(
            "sweep_artifacts",
            {"ttl_class": ttl_class, "limit": limit, "min_set": min_set},
            rows=limit,
        )
        return cast(int, result)

    async def upsert_memory_prior(
        self,
        *,
        kind: str,
        surface: str,
        key: str,
        value: Mapping[str, Any],
        score: float,
        support: int,
        confidence: float,
        source_claim: str | None = None,
        source_artifact: str | None = None,
        prior_id: str | None = None,
        created: int | None = None,
        updated: int | None = None,
    ) -> dict[str, Any]:
        """Upsert a compounding-memory prior (RA-MEM)."""
        now = now_ms()
        result = await self._submit(
            "upsert_memory_prior",
            {
                "prior_id": prior_id or self._ids.new("mem"),
                "kind": kind,
                "surface": surface,
                "key": key,
                "value_json": json.dumps(value, sort_keys=True, separators=(",", ":")),
                "score": score,
                "support": support,
                "confidence": confidence,
                "source_claim": source_claim,
                "source_artifact": source_artifact,
                "created": now if created is None else created,
                "updated": now if updated is None else updated,
            },
            rows=2,
        )
        return cast(dict[str, Any], result)

    async def retire_memory_prior(self, prior_id: str, *, updated: int | None = None) -> bool:
        """Retire one memory prior without deleting its audit trail."""
        result = await self._submit(
            "retire_memory_prior",
            {"prior_id": prior_id, "updated": now_ms() if updated is None else updated},
        )
        return cast(bool, result)

    async def ensure_memory_preference(
        self,
        *,
        pair_id: str,
        task_type: str,
        surface: str,
        prompt_sha: str,
        chosen: Mapping[str, Any],
        rejected: Mapping[str, Any],
        reward: float,
        rationale: str | None = None,
        source_claim: str | None = None,
        source_artifact: str | None = None,
        created: int | None = None,
    ) -> dict[str, Any]:
        """Insert one preference pair idempotently by pair_id."""
        result = await self._submit(
            "ensure_memory_preference",
            {
                "pair_id": pair_id,
                "task_type": task_type,
                "surface": surface,
                "prompt_sha": prompt_sha,
                "chosen_json": json.dumps(chosen, sort_keys=True, separators=(",", ":")),
                "rejected_json": json.dumps(rejected, sort_keys=True, separators=(",", ":")),
                "reward": reward,
                "rationale": rationale,
                "source_claim": source_claim,
                "source_artifact": source_artifact,
                "created": now_ms() if created is None else created,
            },
        )
        return cast(dict[str, Any], result)

    async def create_memory_adapter(
        self,
        *,
        adapter_id: str,
        task_type: str,
        surface: str,
        pair_ids: Sequence[str],
        config: Mapping[str, Any],
        parent_id: str | None = None,
        source_artifact: str | None = None,
        created: int | None = None,
    ) -> dict[str, Any]:
        """Create a candidate LoRA-style adapter bound to preference pairs."""
        pair_list = list(pair_ids)
        if not pair_list:
            raise FormatFail("memory adapter requires at least one preference pair")
        result = await self._submit(
            "create_memory_adapter",
            {
                "adapter_id": adapter_id,
                "task_type": task_type,
                "surface": surface,
                "pair_ids": [{"pair_id": pair_id} for pair_id in pair_list],
                "train_pair_count": len(pair_list),
                "config_json": json.dumps(config, sort_keys=True, separators=(",", ":")),
                "parent_id": parent_id,
                "source_artifact": source_artifact,
                "created": now_ms() if created is None else created,
            },
            rows=len(pair_list) + 1,
        )
        return cast(dict[str, Any], result)

    async def evaluate_memory_adapter(
        self,
        adapter_id: str,
        *,
        eval_score: float,
        golden_rows: int,
        golden_passed: bool,
        baseline_score: float | None = None,
        ship_blocked_reason: str | None = None,
        updated: int | None = None,
    ) -> dict[str, Any]:
        """Record golden-set evaluation for a candidate adapter."""
        result = await self._submit(
            "evaluate_memory_adapter",
            {
                "adapter_id": adapter_id,
                "eval_score": eval_score,
                "baseline_score": baseline_score,
                "golden_rows": golden_rows,
                "golden_passed": golden_passed,
                "ship_blocked_reason": ship_blocked_reason,
                "updated": now_ms() if updated is None else updated,
            },
        )
        return cast(dict[str, Any], result)

    async def ship_memory_adapter(self, adapter_id: str, *, updated: int | None = None) -> dict[str, Any]:
        """Ship one evaluated adapter and atomically retire prior shipped adapters."""
        result = await self._submit(
            "ship_memory_adapter",
            {"adapter_id": adapter_id, "updated": now_ms() if updated is None else updated},
            rows=2,
        )
        return cast(dict[str, Any], result)

    async def set_memory_adapter_state(
        self, adapter_id: str, to_state: str, *, updated: int | None = None
    ) -> bool:
        """Move an adapter to rejected or retired."""
        result = await self._submit(
            "set_memory_adapter_state",
            {
                "adapter_id": adapter_id,
                "to_state": to_state,
                "updated": now_ms() if updated is None else updated,
            },
        )
        return cast(bool, result)

    async def record_memory_sla(
        self,
        surface: str,
        *,
        target_cost_micro: int,
        cost_micro: int,
        created: int | None = None,
    ) -> dict[str, Any]:
        """Record one cost-to-first-valid-PoC observation with monotonic SLA state."""
        at = now_ms() if created is None else created
        result = await self._submit(
            "record_memory_sla",
            {
                "surface": surface,
                "target_cost_micro": target_cost_micro,
                "cost_micro": cost_micro,
                "sla_event_id": self._ids.new("sla"),
                "created": at,
            },
            rows=2,
        )
        return cast(dict[str, Any], result)

    async def record_memory_retrieval(
        self,
        *,
        surface: str,
        prior_ids: Sequence[str],
        pair_ids: Sequence[str] = (),
        run_id: str | None = None,
        task_type: str | None = None,
        packet_sha: str | None = None,
        adapter_id: str | None = None,
        retrieval_id: str | None = None,
        created: int | None = None,
    ) -> str:
        """Record the priors/pairs selected for one retrieval packet."""
        result = await self._submit(
            "record_memory_retrieval",
            {
                "retrieval_id": retrieval_id or self._ids.new("ret"),
                "run_id": run_id,
                "surface": surface,
                "task_type": task_type,
                "packet_sha": packet_sha,
                "adapter_id": adapter_id,
                "prior_ids_json": json.dumps(list(prior_ids), separators=(",", ":")),
                "pair_ids_json": json.dumps(list(pair_ids), separators=(",", ":")),
                "created": now_ms() if created is None else created,
            },
        )
        return cast(str, result)

    async def record_memory_retrieval_relevance(
        self,
        *,
        relevance: float,
        retrieval_id: str | None = None,
        packet_sha: str | None = None,
    ) -> int:
        """Attach citation/retrieval relevance telemetry to a packet."""
        result = await self._submit(
            "update_memory_retrieval_relevance",
            {
                "retrieval_id": retrieval_id,
                "packet_sha": packet_sha,
                "relevance": relevance,
            },
        )
        return cast(int, result)

    # Read-side pass-throughs.
    def get_claim(self, claim_id: str) -> dict[str, Any] | None:
        """Fetch a claim by ID."""
        return self.store.get_claim(claim_id)

    def claim_by_dedup(self, dedup_value: str) -> dict[str, Any] | None:
        """Fetch a claim by dedup key."""
        return self.store.claim_by_dedup(dedup_value)

    def claims_by_state(self, state: str | ClaimState, *, limit: int = 100) -> list[dict[str, Any]]:
        """List claims in a state using ix_claim_state."""
        value = state.value if isinstance(state, ClaimState) else state
        return self.store.claims_by_state(value, limit=limit)

    def claims_by_type(self, claim_type: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """List claims of one type in creation order."""
        return self.store.claims_by_type(claim_type, limit=limit)

    def claim_artifact_count(self, claim_id: str) -> int:
        """Count artifact links for a claim."""
        return self.store.claim_artifact_count(claim_id)

    def claim_artifacts(self, claim_id: str) -> list[dict[str, Any]]:
        """List artifact links for a claim."""
        return self.store.claim_artifacts(claim_id)

    def get_join(self, join_id: str) -> dict[str, Any] | None:
        """Fetch a join row by ID."""
        return self.store.get_join(join_id)

    def joins(
        self,
        *,
        state: str | None = None,
        states: Sequence[str] | None = None,
        a_claim: str | None = None,
        b_claim: str | None = None,
        created_after: int | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List join rows in deterministic order."""
        return self.store.joins(
            state=state,
            states=states,
            a_claim=a_claim,
            b_claim=b_claim,
            created_after=created_after,
            limit=limit,
        )

    def verdicts_for_claim(self, claim_id: str) -> list[dict[str, Any]]:
        """List review verdicts for a claim in creation order."""
        return self.store.verdicts_for_claim(claim_id)

    def get_work_order(self, work_order_id: str) -> dict[str, Any] | None:
        """Fetch a work order."""
        return self.store.get_work_order(work_order_id)

    def ready_work_orders(self, *, limit: int = 64) -> list[dict[str, Any]]:
        """List ready work orders in EV order."""
        return self.store.ready_work_orders(limit=limit)

    def work_orders_for_unit(self, unit: str) -> list[dict[str, Any]]:
        """List work orders for one schedulable unit."""
        return self.store.work_orders_for_unit(unit)

    def spent_usd_micro(self, run_id: str | None = None) -> int:
        """Total recorded spend in integer micro-USD."""
        return self.store.spent_usd_micro(run_id)

    def ring_nodes(self) -> list[dict[str, Any]]:
        """List ring nodes."""
        return self.store.ring_nodes()

    def ring_node(self, node_id: str) -> dict[str, Any] | None:
        """Fetch one ring node."""
        return self.store.ring_node(node_id)

    def entry_points(self, ring_node: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Entry points for one ring node in rank order."""
        return self.store.entry_points(ring_node, limit=limit)

    def memory_prior_row(self, prior_id: str) -> dict[str, Any] | None:
        """Fetch one memory prior."""
        return self.store.memory_prior_row(prior_id)

    def memory_prior_by_key(self, kind: str, surface: str, key: str) -> dict[str, Any] | None:
        """Fetch one memory prior by its natural key."""
        return self.store.memory_prior_by_key(kind, surface, key)

    def memory_priors(
        self,
        surface: str | None = None,
        *,
        kind: str | None = None,
        state: str = "active",
        include_global: bool = True,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List ranked memory priors."""
        return self.store.memory_priors(
            surface, kind=kind, state=state, include_global=include_global, limit=limit
        )

    def memory_preference_row(self, pair_id: str) -> dict[str, Any] | None:
        """Fetch one preference pair."""
        return self.store.memory_preference_row(pair_id)

    def memory_preferences(
        self,
        *,
        task_type: str | None = None,
        surface: str | None = None,
        surfaces: Sequence[str] | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List preference pairs by reward."""
        return self.store.memory_preferences(
            task_type=task_type, surface=surface, surfaces=surfaces, limit=limit
        )

    def memory_adapter_row(self, adapter_id: str) -> dict[str, Any] | None:
        """Fetch one memory adapter."""
        return self.store.memory_adapter_row(adapter_id)

    def memory_adapters(
        self,
        *,
        task_type: str | None = None,
        surface: str | None = None,
        state: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List memory adapters."""
        return self.store.memory_adapters(
            task_type=task_type, surface=surface, state=state, limit=limit
        )

    def memory_active_adapter(self, task_type: str, surface: str) -> dict[str, Any] | None:
        """Fetch the currently shipped adapter for a scope."""
        return self.store.memory_active_adapter(task_type, surface)

    def memory_adapter_pair_ids(self, adapter_id: str) -> list[str]:
        """List preference pair ids bound to an adapter."""
        return self.store.memory_adapter_pair_ids(adapter_id)

    def memory_sla_row(self, surface: str) -> dict[str, Any] | None:
        """Fetch SLA state for one surface."""
        return self.store.memory_sla_row(surface)

    def memory_sla_rows(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        """List SLA rows."""
        return self.store.memory_sla_rows(limit=limit)

    def memory_sla_events(self, surface: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """List SLA observations for one surface."""
        return self.store.memory_sla_events(surface, limit=limit)

    def memory_retrieval_row(self, retrieval_id: str) -> dict[str, Any] | None:
        """Fetch one retrieval telemetry row."""
        return self.store.memory_retrieval_row(retrieval_id)

    def memory_retrievals(
        self,
        *,
        surface: str | None = None,
        task_type: str | None = None,
        packet_sha: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List retrieval telemetry rows."""
        return self.store.memory_retrievals(
            surface=surface, task_type=task_type, packet_sha=packet_sha, limit=limit
        )

    def retention_candidates(
        self, ttl_class: str, *, cutoff: int, limit: int
    ) -> list[dict[str, Any]]:
        """Artifacts eligible for retention deletion."""
        return self.store.retention_candidates(ttl_class, cutoff=cutoff, limit=limit)

    def artifact_count(self) -> int:
        """Total artifact rows."""
        return self.store.artifact_count()

    def invariant_counts(self) -> dict[str, int]:
        """Database-checkable invariant violation counts."""
        return self.store.invariant_counts()

    def artifact_ttl_counts(self) -> dict[str, int]:
        """Artifact counts by TTL class."""
        return self.store.artifact_ttl_counts()

    def oldest_artifact(self, ttl_class: str) -> dict[str, Any] | None:
        """Oldest artifact in a TTL class."""
        return self.store.oldest_artifact(ttl_class)

    def explain(self, sql: str, params: Sequence[object] = ()) -> list[str]:
        """EXPLAIN QUERY PLAN details for index assertions."""
        return self.store.explain(sql, params)

    def counts(self) -> dict[str, int]:
        """Row counts per table."""
        return self.store.counts()

    def table_names(self) -> list[str]:
        """SQLite table names."""
        return self.store.table_names()

    def index_names(self, table: str) -> list[str]:
        """Index names for a table."""
        return self.store.index_names(table)

    def pragma_value(self, name: str) -> object:
        """Read a SQLite pragma."""
        return self.store.pragma_value(name)

    def integrity_check(self) -> str:
        """SQLite integrity check result."""
        return self.store.integrity_check()

    def health(self) -> dict[str, Any]:
        """Health snapshot for /healthz."""
        return {
            "counts": self.counts(),
            "actor": self.actor.stats(),
            "integrity": self.integrity_check(),
            "journal_mode": self.pragma_value("journal_mode"),
            "foreign_keys": self.pragma_value("foreign_keys"),
        }
