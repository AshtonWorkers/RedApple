"""SQLite storage layer for the Claim Ledger.

This is the only module that opens a database connection (RA-TOP-001). All writes
are applied as batched transactions by the single-writer actor.
"""

from __future__ import annotations

import contextlib
import json
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar, cast

from ..errors import DuplicateDedup, FormatFail, RaError
from .ids import UlidFactory  # noqa: F401  (re-exported for callers)
from .models import ClaimInput
from .operations import LedgerOperation
from .schema import SCHEMA_SQL
from .states import ClaimState, can_transition

CLAIM_TYPES = frozenset(
    {"bug_class", "rung", "groom", "join", "gadget_set", "root_cause", "dupe_score", "harness"}
)
TTL_CLASSES = frozenset({"ephemeral", "run", "pinned"})
WORK_ORDER_STATES = frozenset({"ready", "parked", "done"})
WORK_ORDER_TRANSITIONS: dict[str, frozenset[str]] = {
    "ready": frozenset({"parked", "done"}),
    "parked": frozenset(),
    "done": frozenset(),
}
RUN_MODES = frozenset({"macos", "ios"})
RUN_STATES = frozenset({"armed", "running", "drained", "aborted"})
RUN_ACTIVE_STATES = frozenset({"armed", "running"})
RUN_TERMINAL_STATES = frozenset({"drained", "aborted"})
RING_NODE_STATES = frozenset({"active", "current", "bad", "retired"})
DEVICE_STATES = frozenset({"attached", "needs_hand", "ready", "failed"})
DEVICE_THERMAL_STATES = frozenset({"nominal", "serious", "critical"})
_MISSING: Any = object()


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise FormatFail(f"ledger payload {key} must be str")
    return value


def _opt_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise FormatFail(f"ledger payload {key} must be str or None")
    return value


def _int(payload: Mapping[str, Any], key: str) -> int:
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"ledger payload {key} must be int")
    return value


def _float(payload: Mapping[str, Any], key: str) -> float:
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"ledger payload {key} must be number")
    return float(value)


def _bool(payload: Mapping[str, Any], key: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise FormatFail(f"ledger payload {key} must be bool")
    return value


def _list(payload: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = payload[key]
    if not isinstance(value, list):
        raise FormatFail(f"ledger payload {key} must be list")
    out: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise FormatFail(f"ledger payload {key} items must be objects")
        out.append(item)
    return out


def _finite_nonnegative_float(payload: Mapping[str, Any], key: str) -> float:
    value = _float(payload, key)
    if not math.isfinite(value) or value < 0:
        raise FormatFail(f"{key} must be a finite non-negative number")
    return value


def _optional_int_nonnegative(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FormatFail(f"{key} must be a non-negative integer")
    return value


def _optional_bool(payload: Mapping[str, Any], key: str) -> bool | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise FormatFail(f"{key} must be a boolean")
    return value


def _optional_finite_nonnegative_float(payload: Mapping[str, Any], key: str) -> float | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise FormatFail(f"{key} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise FormatFail(f"{key} must be a finite non-negative number")
    return result


def _entry_point_values(payload: Mapping[str, Any]) -> tuple[int, float, float]:
    privilege_delta = _int(payload, "privilege_delta")
    if privilege_delta < 0:
        raise FormatFail("privilege_delta must be non-negative")
    return (
        privilege_delta,
        _finite_nonnegative_float(payload, "parser_complexity"),
        _finite_nonnegative_float(payload, "weight"),
    )


_ThreadFunc = TypeVar("_ThreadFunc", bound=Callable[..., Any])


def _guard_thread(func: _ThreadFunc) -> _ThreadFunc:
    @wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if threading.get_ident() != self._owner_thread:
            raise RaError("ledger store is bound to its opening thread", code="LEDGER_THREAD")
        return func(self, *args, **kwargs)

    return cast(_ThreadFunc, wrapper)


_STORE_GUARDED_METHODS = frozenset(
    {
        "apply_batch",
        "get_claim",
        "claim_by_dedup",
        "claims_by_state",
        "claims_by_type",
        "claim_artifact_count",
        "claim_artifacts",
        "get_work_order",
        "ready_work_orders",
        "work_orders_for_unit",
        "spent_usd_micro",
        "artifact_ttl_counts",
        "oldest_artifact",
        "ring_nodes",
        "ring_node",
        "entry_points",
        "retention_candidates",
        "artifact_count",
        "invariant_counts",
        "explain",
        "counts",
        "table_names",
        "index_names",
        "pragma_value",
        "integrity_check",
    }
)


class LedgerStore:
    """Synchronous SQLite store used only by the ledger actor.

    Reads and writes are bound to the thread that opened the store; call them
    from the ledger's event-loop thread.
    """

    def __getattribute__(self, name: str) -> Any:
        attr = super().__getattribute__(name)
        if name in _STORE_GUARDED_METHODS and callable(attr):
            owner_thread = super().__getattribute__("_owner_thread")
            if threading.get_ident() != owner_thread:
                raise RaError("ledger store is bound to its opening thread", code="LEDGER_THREAD")
        return attr

    def __init__(self, path: str | Path, *, wal_autocheckpoint: int = 1000) -> None:
        self._owner_thread = threading.get_ident()
        expanded = Path(path).expanduser()
        self.path = str(expanded)
        self._wal_autocheckpoint = wal_autocheckpoint
        if self.path != ":memory:":
            expanded.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._initialize_schema()

    def _configure(self) -> None:
        self._conn.execute("PRAGMA busy_timeout=5000")
        for attempt in range(5):
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 4:
                    raise
                time.sleep(0.01 * (attempt + 1))
        pragmas = {
            "foreign_keys": "ON",
            "synchronous": "NORMAL",
            "cache_size": "-262144",
            "mmap_size": "536870912",
            "temp_store": "MEMORY",
            "wal_autocheckpoint": str(self._wal_autocheckpoint),
        }
        for name, value in pragmas.items():
            self._conn.execute(f"PRAGMA {name}={value}")

    def _initialize_schema(self) -> None:
        row = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='run'"
        ).fetchone()
        if row is None:
            self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()

    def apply_batch(self, operations: Sequence[LedgerOperation]) -> list[object]:
        """Apply operations with per-operation savepoints.

        Request-level failures roll back only their own operation; storage
        failures roll back the whole batch and fail every operation in it.
        """
        if not operations:
            return []
        results: list[object] = [_MISSING] * len(operations)
        failures: dict[int, BaseException] = {}
        storage_error: BaseException | None = None
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except Exception as exc:
            for operation in operations:
                self._set_future_exception(operation, exc)
            raise
        for index, operation in enumerate(operations):
            savepoint = f"ra_op_{index}"
            self._conn.execute(f"SAVEPOINT {savepoint}")
            try:
                results[index] = self._apply_operation(operation)
            except RaError as exc:
                self._rollback_to_savepoint(savepoint)
                failures[index] = exc
            except sqlite3.IntegrityError as exc:
                self._rollback_to_savepoint(savepoint)
                failures[index] = FormatFail(f"ledger operation {operation.kind} failed: {exc}")
            except sqlite3.Error as exc:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                storage_error = exc
                break
            except Exception as exc:
                self._rollback_to_savepoint(savepoint)
                failures[index] = exc
            else:
                self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        if storage_error is None:
            try:
                self._conn.execute("COMMIT")
            except Exception as exc:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                storage_error = exc
        if storage_error is not None:
            for operation in operations:
                self._set_future_exception(operation, storage_error)
            raise storage_error
        for index, operation in enumerate(operations):
            if index in failures:
                self._set_future_exception(operation, failures[index])
            elif results[index] is not _MISSING:
                self._set_future_result(operation, results[index])
        return [None if index in failures else results[index] for index in range(len(operations))]

    @staticmethod
    def _set_future_result(operation: LedgerOperation, result: object) -> None:
        if operation.future is not None and not operation.future.done():
            operation.future.set_result(result)

    @staticmethod
    def _set_future_exception(operation: LedgerOperation, exc: BaseException) -> None:
        if operation.future is not None and not operation.future.done():
            operation.future.set_exception(exc)

    def _rollback_to_savepoint(self, savepoint: str) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        with contextlib.suppress(sqlite3.Error):
            self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")

    def _apply_operation(self, operation: LedgerOperation) -> object:
        handler = getattr(self, f"_op_{operation.kind}", None)
        if handler is None:
            raise FormatFail(f"unknown ledger operation {operation.kind}")
        return handler(operation.payload)

    def _op_create_run(self, payload: Mapping[str, Any]) -> str:
        run_id = _text(payload, "run_id")
        mode = _text(payload, "mode")
        state = _text(payload, "state")
        if mode not in RUN_MODES:
            raise FormatFail("run mode must be macos or ios")
        if state not in RUN_STATES:
            raise FormatFail("run state is invalid")
        if state not in RUN_ACTIVE_STATES:
            raise FormatFail("run must be created armed or running")
        self._conn.execute(
            "INSERT INTO run(id, started, ended, mode, budget_json, state) VALUES(?,?,?,?,?,?)",
            (
                run_id,
                _int(payload, "started"),
                payload.get("ended"),
                mode,
                _text(payload, "budget_json"),
                state,
            ),
        )
        return run_id

    def _op_end_run(self, payload: Mapping[str, Any]) -> bool:
        state = _text(payload, "state")
        if state not in RUN_TERMINAL_STATES:
            raise FormatFail("end_run state must be drained or aborted")
        row = self._conn.execute(
            "SELECT state FROM run WHERE id=?", (_text(payload, "run_id"),)
        ).fetchone()
        if row is None:
            return False
        current = str(row["state"])
        if current not in RUN_ACTIVE_STATES:
            raise FormatFail(f"run is already {current}")
        cursor = self._conn.execute(
            "UPDATE run SET ended=?, state=? WHERE id=?",
            (_int(payload, "ended"), state, _text(payload, "run_id")),
        )
        return cursor.rowcount == 1

    def _op_put_artifact(self, payload: Mapping[str, Any]) -> str:
        return self._upsert_artifact_row(payload)

    def _op_create_claim(self, payload: Mapping[str, Any]) -> str:
        claim = _claim_input_from_payload(payload)
        for link in claim["artifacts"]:
            self._insert_artifact_row(link)
        try:
            self._conn.execute(
                """
                INSERT INTO claim(id, run_id, type, value_json, confidence, state, dedup_key, created)
                VALUES(?,?,?,?,?,'limbo',?,?)
                """,
                (
                    claim["claim_id"],
                    claim["run_id"],
                    claim["type"],
                    claim["value_json"],
                    claim["confidence"],
                    claim["dedup_key"],
                    claim["created"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            if "ux_claim_dedup" in str(exc) or "dedup_key" in str(exc):
                raise DuplicateDedup("claim dedup_key already exists") from exc
            raise FormatFail(f"claim insert failed: {exc}") from exc
        for link in claim["artifacts"]:
            self._conn.execute(
                "INSERT INTO claim_artifact(claim_id, artifact_id, role) VALUES(?,?,?)",
                (claim["claim_id"], link["artifact_id"], link["role"]),
            )
        return str(claim["claim_id"])

    def _op_transition_claim(self, payload: Mapping[str, Any]) -> dict[str, object]:
        return self._transition_claim(
            _text(payload, "claim_id"), _text(payload, "to_state"), _int(payload, "created")
        )

    def _transition_claim(self, claim_id: str, to_state: str, created: int) -> dict[str, object]:
        row = self._conn.execute("SELECT state FROM claim WHERE id=?", (claim_id,)).fetchone()
        if row is None:
            raise FormatFail("claim does not exist")
        try:
            current = ClaimState(str(row["state"]))
            target = ClaimState(to_state)
        except ValueError as exc:
            raise FormatFail("claim state is invalid") from exc
        idem = self._conn.execute(
            "SELECT 1 FROM idem WHERE entity='claim' AND entity_id=? AND to_state=?",
            (claim_id, target.value),
        ).fetchone()
        if idem is not None:
            return {
                "claim_id": claim_id,
                "from_state": current.value,
                "to_state": target.value,
                "changed": False,
            }
        if not can_transition(current, target):
            raise FormatFail(f"illegal claim transition {current.value} -> {target.value}")
        if current is ClaimState.LIMBO and target is ClaimState.BOUND:
            count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM claim_artifact WHERE claim_id=?", (claim_id,)
            ).fetchone()
            if int(count["n"]) == 0:
                raise FormatFail("claim with zero artifact links cannot leave limbo")
        if target is ClaimState.PROMOTED:
            count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM claim_artifact WHERE claim_id=?", (claim_id,)
            ).fetchone()
            if int(count["n"]) == 0:
                raise FormatFail("promoted claim requires artifact links")
        self._conn.execute("UPDATE claim SET state=? WHERE id=?", (target.value, claim_id))
        self._conn.execute(
            "INSERT INTO audit(entity, entity_id, from_state, to_state, created) VALUES(?,?,?,?,?)",
            ("claim", claim_id, current.value, target.value, created),
        )
        self._conn.execute(
            "INSERT INTO idem(entity, entity_id, to_state, created) VALUES('claim',?,?,?)",
            (claim_id, target.value, created),
        )
        return {
            "claim_id": claim_id,
            "from_state": current.value,
            "to_state": target.value,
            "changed": True,
        }

    def _op_record_decision(self, payload: Mapping[str, Any]) -> int:
        spent = _int(payload, "spent_usd_micro")
        if spent < 0:
            raise FormatFail("spent_usd_micro must be non-negative")
        cursor = self._conn.execute(
            """
            INSERT INTO decision(run_id, wo_id, trigger_metric, observed, expected, spent_usd_micro, created)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                _opt_text(payload, "run_id"),
                _opt_text(payload, "wo_id"),
                _text(payload, "trigger_metric"),
                _float(payload, "observed"),
                _text(payload, "expected"),
                spent,
                _int(payload, "created"),
            ),
        )
        return int(cursor.lastrowid or 0)

    def _op_enqueue_work_order(self, payload: Mapping[str, Any]) -> str:
        work_order_id = _text(payload, "work_order_id")
        action = _text(payload, "action")
        state = _text(payload, "state")
        allowed = {
            "retarget",
            "reweight",
            "spawn_subfactory",
            "widen_dialect",
            "force_groom",
            "try_gadget_set",
            "escalate_model",
            "demote",
            "park",
        }
        if action not in allowed:
            raise FormatFail("work_order action is off-vocabulary")
        if state not in WORK_ORDER_STATES:
            raise FormatFail("work_order state is invalid")
        try:
            self._conn.execute(
                """
                INSERT INTO work_order(id, run_id, action, unit, payload_json, ev_cost, state, created)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    work_order_id,
                    _opt_text(payload, "run_id"),
                    action,
                    _text(payload, "unit"),
                    _opt_text(payload, "payload_json"),
                    _finite_nonnegative_float(payload, "ev_cost"),
                    state,
                    _int(payload, "created"),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise FormatFail(f"work_order insert failed: {exc}") from exc
        return work_order_id

    def _op_update_work_order_state(self, payload: Mapping[str, Any]) -> bool:
        work_order_id = _text(payload, "work_order_id")
        state = _text(payload, "state")
        if state not in WORK_ORDER_STATES:
            raise FormatFail("work_order state is invalid")
        row = self._conn.execute(
            "SELECT state FROM work_order WHERE id=?", (work_order_id,)
        ).fetchone()
        if row is None:
            return False
        current = str(row["state"])
        if current != state and state not in WORK_ORDER_TRANSITIONS.get(current, frozenset()):
            raise FormatFail(f"work_order transition {current} -> {state} is not allowed")
        cursor = self._conn.execute(
            "UPDATE work_order SET state=?, payload_json=COALESCE(?, payload_json) WHERE id=?",
            (
                state,
                _opt_text(payload, "payload_json"),
                work_order_id,
            ),
        )
        return cursor.rowcount == 1

    def _op_dispatch_work_order(self, payload: Mapping[str, Any]) -> dict[str, object]:
        work_order_id = _text(payload, "work_order_id")
        row = self._conn.execute(
            "SELECT id, run_id, action, ev_cost, state FROM work_order WHERE id=?",
            (work_order_id,),
        ).fetchone()
        if row is None:
            return {"dispatched": False, "reason": "missing", "work_order_id": work_order_id}
        state = str(row["state"])
        run_id_value = row["run_id"]
        scope_run_id = str(run_id_value) if run_id_value is not None else None
        if state != "ready":
            return {
                "dispatched": False,
                "reason": "not_ready",
                "state": state,
                "work_order_id": work_order_id,
            }
        budget = _int(payload, "budget_usd_micro")
        cost = _int(payload, "spent_usd_micro")
        if budget < 0 or cost < 0:
            raise FormatFail("dispatch money values must be non-negative")
        spent = self._spent_for_scope(scope_run_id)
        if spent + cost > budget:
            return {
                "dispatched": False,
                "reason": "budget",
                "spent_usd_micro": spent,
                "budget_usd_micro": budget,
                "work_order_id": work_order_id,
            }
        cursor = self._conn.execute(
            "UPDATE work_order SET state='done' WHERE id=? AND state='ready'",
            (work_order_id,),
        )
        if cursor.rowcount != 1:
            return {
                "dispatched": False,
                "reason": "not_ready",
                "state": "done",
                "work_order_id": work_order_id,
            }
        self._conn.execute(
            """
            INSERT INTO decision(run_id, wo_id, trigger_metric, observed, expected, spent_usd_micro, created)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                scope_run_id,
                work_order_id,
                _text(payload, "trigger_metric"),
                _float(payload, "observed"),
                _text(payload, "expected"),
                cost,
                _int(payload, "created"),
            ),
        )
        return {
            "dispatched": True,
            "cost_usd_micro": cost,
            "run_id": scope_run_id,
            "work_order_id": work_order_id,
        }

    def _op_record_packet_log(self, payload: Mapping[str, Any]) -> str:
        packet_id = _text(payload, "packet_id")
        self._conn.execute(
            """
            INSERT INTO packet_log(id, run_id, task_type, sha, tokens_in, tokens_out, latency_ms,
              schema_ok, bound_ok, relevance, created)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                packet_id,
                _opt_text(payload, "run_id"),
                _opt_text(payload, "task_type"),
                _text(payload, "sha"),
                _optional_int_nonnegative(payload, "tokens_in"),
                _optional_int_nonnegative(payload, "tokens_out"),
                _optional_int_nonnegative(payload, "latency_ms"),
                _optional_bool(payload, "schema_ok"),
                _optional_bool(payload, "bound_ok"),
                _optional_finite_nonnegative_float(payload, "relevance"),
                _int(payload, "created"),
            ),
        )
        return packet_id

    def _op_upsert_ring_node(self, payload: Mapping[str, Any]) -> str:
        node_id = _text(payload, "ring_node_id")
        state = _text(payload, "state")
        epoch = _int(payload, "epoch")
        if state not in RING_NODE_STATES:
            raise FormatFail("ring node state is invalid")
        if epoch < 0:
            raise FormatFail("ring node epoch must be non-negative")
        self._conn.execute(
            """
            INSERT INTO ring_node(id, ipsw_sha, build, xcode, sdk, webkit_commit, state, epoch)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET ipsw_sha=excluded.ipsw_sha, build=excluded.build,
              xcode=excluded.xcode, sdk=excluded.sdk, webkit_commit=excluded.webkit_commit,
              state=excluded.state, epoch=excluded.epoch
            """,
            (
                node_id,
                _text(payload, "ipsw_sha"),
                _text(payload, "build"),
                _text(payload, "xcode"),
                _text(payload, "sdk"),
                _text(payload, "webkit_commit"),
                state,
                epoch,
            ),
        )
        return node_id

    def _op_advance_ring(self, payload: Mapping[str, Any]) -> int:
        epoch = _int(payload, "epoch")
        if epoch < 0:
            raise FormatFail("ring epoch must be non-negative")
        current = self._conn.execute("SELECT COALESCE(MAX(epoch), -1) AS epoch FROM ring_node").fetchone()
        if epoch <= int(current["epoch"]):
            raise FormatFail("ring epoch must increase")
        nodes = _list(payload, "nodes")
        ids: list[str] = []
        for node in nodes:
            ids.append(_text(node, "ring_node_id"))
            self._op_upsert_ring_node(node)
        if ids:
            placeholders = ",".join("?" for _ in ids)
            self._conn.execute(
                f"UPDATE ring_node SET state='retired' WHERE epoch < ? AND id NOT IN ({placeholders})",
                (epoch, *ids),
            )
        else:
            self._conn.execute("UPDATE ring_node SET state='retired' WHERE epoch < ?", (epoch,))
        return epoch

    def _op_upsert_device_profile(self, payload: Mapping[str, Any]) -> str:
        udid = _text(payload, "udid")
        state = _text(payload, "state")
        thermal = _opt_text(payload, "thermal")
        crashes = _int(payload, "crashes")
        if state not in DEVICE_STATES:
            raise FormatFail("device state is invalid")
        if thermal is not None and thermal not in DEVICE_THERMAL_STATES:
            raise FormatFail("device thermal is invalid")
        if crashes < 0:
            raise FormatFail("device crashes must be non-negative")
        self._conn.execute(
            """
            INSERT INTO device_profile(udid, build, tier, state, thermal, crashes, exclusion_window, ring_node)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(udid) DO UPDATE SET build=excluded.build, tier=excluded.tier,
              state=excluded.state, thermal=excluded.thermal, crashes=excluded.crashes,
              exclusion_window=excluded.exclusion_window, ring_node=excluded.ring_node
            """,
            (
                udid,
                _opt_text(payload, "build"),
                _opt_text(payload, "tier"),
                state,
                thermal,
                crashes,
                _opt_text(payload, "exclusion_window"),
                _opt_text(payload, "ring_node"),
            ),
        )
        return udid

    def _op_insert_verdict(self, payload: Mapping[str, Any]) -> int:
        cursor = self._conn.execute(
            "INSERT INTO verdict(claim_id, reviewer, agree, reason, created) VALUES(?,?,?,?,?)",
            (
                _text(payload, "claim_id"),
                _text(payload, "reviewer"),
                1 if _bool(payload, "agree") else 0,
                _opt_text(payload, "reason"),
                _int(payload, "created"),
            ),
        )
        return int(cursor.lastrowid or 0)

    def _op_insert_join(self, payload: Mapping[str, Any]) -> str:
        join_id = _text(payload, "join_id")
        self._conn.execute(
            """
            INSERT INTO "join"(id, a_claim, b_claim, invariants_json, reliability, lower_bound, state, created)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                join_id,
                _text(payload, "a_claim"),
                _text(payload, "b_claim"),
                _text(payload, "invariants_json"),
                payload.get("reliability"),
                payload.get("lower_bound"),
                _text(payload, "state"),
                _int(payload, "created"),
            ),
        )
        return join_id

    def _op_insert_entry_point(self, payload: Mapping[str, Any]) -> str:
        entry_id = _text(payload, "entry_point_id")
        privilege_delta, parser_complexity, weight = _entry_point_values(payload)
        self._conn.execute(
            """
            INSERT INTO entry_point(id, name, reach_from_json, privilege_delta, parser_complexity, weight, ring_node)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                entry_id,
                _text(payload, "name"),
                _text(payload, "reach_from_json"),
                privilege_delta,
                parser_complexity,
                weight,
                _text(payload, "ring_node"),
            ),
        )
        return entry_id

    def _op_replace_entry_points(self, payload: Mapping[str, Any]) -> int:
        ring_node = _text(payload, "ring_node")
        rows = _list(payload, "rows")
        self._conn.execute("DELETE FROM entry_point WHERE ring_node=?", (ring_node,))
        for row in rows:
            privilege_delta, parser_complexity, weight = _entry_point_values(row)
            self._conn.execute(
                """
                INSERT INTO entry_point(id, name, reach_from_json, privilege_delta, parser_complexity, weight, ring_node)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    _text(row, "entry_point_id"),
                    _text(row, "name"),
                    _text(row, "reach_from_json"),
                    privilege_delta,
                    parser_complexity,
                    weight,
                    ring_node,
                ),
            )
        return len(rows)

    def _op_sweep_artifacts(self, payload: Mapping[str, Any]) -> int:
        # Retention deletes are executed as part of a ledger batch so they share
        # the single-writer mailbox and one transaction (RA-RET-003).
        ttl_class = _text(payload, "ttl_class")
        if ttl_class not in TTL_CLASSES:
            raise FormatFail("artifact ttl_class is invalid")
        if ttl_class == "pinned":
            raise FormatFail("pinned artifacts are not retention-eligible")
        limit = _int(payload, "limit")
        if limit < 0:
            raise FormatFail("retention limit must be >= 0")
        rows = self._conn.execute(
            """
            SELECT id FROM artifact
            WHERE ttl_class=?
              AND NOT EXISTS (
                SELECT 1 FROM claim_artifact ca
                JOIN claim c ON c.id = ca.claim_id
                WHERE ca.artifact_id = artifact.id
                  AND (
                    c.state = 'promoted'
                    OR c.id IN (SELECT a_claim FROM "join" WHERE state='live')
                    OR c.id IN (SELECT b_claim FROM "join" WHERE state='live')
                  )
              )
            ORDER BY created, id LIMIT ?
            """,
            (ttl_class, limit),
        ).fetchall()
        ids = [{"artifact_id": str(row["id"])} for row in rows]
        return self._op_delete_artifacts(
            {"artifact_ids": ids, "min_set": _int(payload, "min_set")}
        )

    def _artifact_protected(self, artifact_id_value: str) -> bool:
        row = self._conn.execute(
            """
            SELECT 1 FROM claim_artifact ca
            JOIN claim c ON c.id = ca.claim_id
            WHERE ca.artifact_id=?
              AND (
                c.state = 'promoted'
                OR c.id IN (SELECT a_claim FROM "join" WHERE state='live')
                OR c.id IN (SELECT b_claim FROM "join" WHERE state='live')
              )
            LIMIT 1
            """,
            (artifact_id_value,),
        ).fetchone()
        return row is not None

    def _op_delete_artifacts(self, payload: Mapping[str, Any]) -> int:
        ids = _list(payload, "artifact_ids")
        min_set = _int(payload, "min_set")
        if min_set < 0:
            raise FormatFail("retention min_set must be >= 0")
        deleted = 0
        for item in ids:
            artifact_id_value = _text(item, "artifact_id")
            row = self._conn.execute(
                "SELECT ttl_class FROM artifact WHERE id=?", (artifact_id_value,)
            ).fetchone()
            if row is None or str(row["ttl_class"]) == "pinned":
                continue
            if self._artifact_protected(artifact_id_value):
                continue
            if self.artifact_count() <= min_set:
                break
            self._conn.execute(
                "DELETE FROM claim_artifact WHERE artifact_id=?", (artifact_id_value,)
            )
            cursor = self._conn.execute("DELETE FROM artifact WHERE id=?", (artifact_id_value,))
            deleted += int(cursor.rowcount)
        return deleted

    def _upsert_artifact_row(self, artifact: Mapping[str, Any]) -> str:
        artifact_id_value = _text(artifact, "artifact_id")
        sha256 = _text(artifact, "sha256")
        ttl_class = _text(artifact, "ttl_class")
        if ttl_class not in TTL_CLASSES:
            raise FormatFail("artifact ttl_class is invalid")
        if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
            raise FormatFail("artifact sha256 must be lowercase hex")
        if artifact_id_value != f"art_{sha256}":
            raise FormatFail("artifact id must be content-addressed")
        self._conn.execute(
            """
            INSERT INTO artifact(id, kind, sha256, bytes, created, ttl_class)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET ttl_class = CASE
              WHEN artifact.ttl_class = 'pinned' OR excluded.ttl_class = 'pinned' THEN 'pinned'
              WHEN artifact.ttl_class = 'run' OR excluded.ttl_class = 'run' THEN 'run'
              ELSE 'ephemeral'
            END
            """,
            (
                artifact_id_value,
                _text(artifact, "kind"),
                sha256,
                _int(artifact, "bytes"),
                _int(artifact, "created"),
                ttl_class,
            ),
        )
        return artifact_id_value

    def _insert_artifact_row(self, artifact: Mapping[str, Any]) -> None:
        self._upsert_artifact_row(artifact)

    # Read-side helpers (same connection, still no direct module access).
    def get_claim(self, claim_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT id, run_id, type, value_json, confidence, state, dedup_key, created FROM claim WHERE id=?",
            (claim_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def claim_by_dedup(self, dedup_key_value: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT id, run_id, type, value_json, confidence, state, dedup_key, created FROM claim WHERE dedup_key=?",
            (dedup_key_value,),
        ).fetchone()
        return None if row is None else dict(row)

    def claims_by_state(self, state: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT id, run_id, type, value_json, confidence, state, dedup_key, created
            FROM claim WHERE state=? ORDER BY created, id LIMIT ?
            """,
            (state, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def claims_by_type(self, claim_type: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT id, run_id, type, value_json, confidence, state, dedup_key, created
            FROM claim WHERE type=? ORDER BY created, id LIMIT ?
            """,
            (claim_type, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def claim_artifact_count(self, claim_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM claim_artifact WHERE claim_id=?", (claim_id,)
        ).fetchone()
        return int(row["n"])

    def claim_artifacts(self, claim_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT ca.claim_id, ca.artifact_id, ca.role, a.kind, a.sha256, a.bytes, a.created, a.ttl_class
            FROM claim_artifact ca JOIN artifact a ON a.id = ca.artifact_id
            WHERE ca.claim_id=? ORDER BY ca.artifact_id, ca.role
            """,
            (claim_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_work_order(self, work_order_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT id, run_id, action, unit, payload_json, ev_cost, state, created FROM work_order WHERE id=?",
            (work_order_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def ready_work_orders(self, *, limit: int = 64) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT id, run_id, action, unit, payload_json, ev_cost, state, created
            FROM work_order WHERE state='ready' ORDER BY ev_cost DESC, created, id LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def work_orders_for_unit(self, unit: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT id, run_id, action, unit, payload_json, ev_cost, state, created
            FROM work_order WHERE unit=? ORDER BY created, id
            """,
            (unit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def spent_usd_micro(self, run_id: str | None = None) -> int:
        if run_id is None:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(spent_usd_micro),0) AS n FROM decision"
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(spent_usd_micro),0) AS n FROM decision WHERE run_id=?",
                (run_id,),
            ).fetchone()
        return int(row["n"])

    def _spent_for_scope(self, run_id: str | None) -> int:
        if run_id is None:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(spent_usd_micro),0) AS n FROM decision WHERE run_id IS NULL"
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(spent_usd_micro),0) AS n FROM decision WHERE run_id=?",
                (run_id,),
            ).fetchone()
        return int(row["n"])

    def artifact_ttl_counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT ttl_class, COUNT(*) AS n FROM artifact GROUP BY ttl_class ORDER BY ttl_class"
        ).fetchall()
        return {str(row["ttl_class"]): int(row["n"]) for row in rows}

    def oldest_artifact(self, ttl_class: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT id, kind, sha256, bytes, created, ttl_class FROM artifact WHERE ttl_class=? ORDER BY created, id LIMIT 1",
            (ttl_class,),
        ).fetchone()
        return None if row is None else dict(row)

    def ring_nodes(self) -> list[dict[str, Any]]:
        """List ring nodes in epoch order."""
        rows = self._conn.execute(
            "SELECT id, ipsw_sha, build, xcode, sdk, webkit_commit, state, epoch "
            "FROM ring_node ORDER BY epoch, id"
        ).fetchall()
        return [dict(row) for row in rows]

    def ring_node(self, node_id: str) -> dict[str, Any] | None:
        """Fetch one ring node."""
        row = self._conn.execute(
            "SELECT id, ipsw_sha, build, xcode, sdk, webkit_commit, state, epoch "
            "FROM ring_node WHERE id=?",
            (node_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def entry_points(self, ring_node: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Entry points for one ring node in deterministic rank order."""
        sql = """
            SELECT id, name, reach_from_json, privilege_delta,
                   parser_complexity, weight, ring_node
            FROM entry_point
            WHERE ring_node = ?
            ORDER BY weight DESC, id ASC
        """
        if limit is None:
            rows = self._conn.execute(sql, (ring_node,)).fetchall()
        else:
            rows = self._conn.execute(sql + " LIMIT ?", (ring_node, limit)).fetchall()
        return [dict(row) for row in rows]

    def retention_candidates(
        self, ttl_class: str, *, cutoff: int, limit: int
    ) -> list[dict[str, Any]]:
        """Artifacts eligible for retention deletion, oldest first (I12)."""
        rows = self._conn.execute(
            """
            SELECT a.id, a.kind, a.sha256, a.bytes, a.created, a.ttl_class
            FROM artifact a
            WHERE a.ttl_class=? AND a.created < ?
              AND NOT EXISTS (
                SELECT 1 FROM claim_artifact ca
                JOIN claim c ON c.id = ca.claim_id
                WHERE ca.artifact_id = a.id
                  AND (
                    c.state = 'promoted'
                    OR c.id IN (SELECT a_claim FROM "join" WHERE state='live')
                    OR c.id IN (SELECT b_claim FROM "join" WHERE state='live')
                  )
              )
            ORDER BY a.created, a.id
            LIMIT ?
            """,
            (ttl_class, cutoff, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def artifact_count(self) -> int:
        """Total artifact rows."""
        row = self._conn.execute("SELECT COUNT(*) AS n FROM artifact").fetchone()
        return int(row["n"])

    def invariant_counts(self) -> dict[str, int]:
        """Database-checkable invariant violation counts (I1-I4, I6)."""
        counts: dict[str, int] = {}
        row = self._conn.execute(
            """
            SELECT COUNT(*) AS n FROM claim c
            WHERE c.state='promoted'
              AND NOT EXISTS (SELECT 1 FROM claim_artifact ca WHERE ca.claim_id=c.id)
            """
        ).fetchone()
        counts["i1"] = int(row["n"])
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM artifact WHERE id <> ('art_' || sha256)"
        ).fetchone()
        counts["i2"] = int(row["n"])
        row = self._conn.execute(
            """
            SELECT COUNT(*) AS n FROM audit a
            WHERE a.entity='claim' AND a.to_state IS NOT NULL
              AND NOT EXISTS (
                SELECT 1 FROM idem i
                WHERE i.entity=a.entity AND i.entity_id=a.entity_id AND i.to_state=a.to_state
              )
            """
        ).fetchone()
        counts["i3"] = int(row["n"])
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM decision WHERE typeof(spent_usd_micro) <> 'integer'"
        ).fetchone()
        counts["i4"] = int(row["n"])
        plans = [
            (
                "SELECT id, run_id, type, value_json, confidence, state, dedup_key, created "
                "FROM claim WHERE state=? ORDER BY created, id LIMIT ?",
                ("reviewed", 10),
                "claim",
            ),
            (
                "SELECT id, run_id, type, value_json, confidence, state, dedup_key, created "
                "FROM claim WHERE dedup_key=?",
                ("missing",),
                "claim",
            ),
            (
                "SELECT id, run_id, action, unit, payload_json, ev_cost, state, created "
                "FROM work_order WHERE state='ready' ORDER BY ev_cost DESC, created, id LIMIT ?",
                (64,),
                "work_order",
            ),
        ]
        scans = 0
        for sql, params, table in plans:
            details = self.explain(sql, params)
            if any(f"SCAN {table}" in detail.upper() for detail in details):
                scans += 1
        counts["i6"] = scans
        return counts

    def explain(self, sql: str, params: Sequence[object] = ()) -> list[str]:
        """Return EXPLAIN QUERY PLAN detail strings for CI index assertions."""
        rows = self._conn.execute("EXPLAIN QUERY PLAN " + sql, tuple(params)).fetchall()
        return [str(row["detail"]) for row in rows]

    def counts(self) -> dict[str, int]:
        tables = [
            "run",
            "artifact",
            "claim",
            "claim_artifact",
            "verdict",
            "join",
            "work_order",
            "decision",
            "idem",
            "entry_point",
            "ring_node",
            "device_profile",
            "golden_row",
            "packet_log",
            "audit",
        ]
        out: dict[str, int] = {}
        for table in tables:
            row = self._conn.execute(f'SELECT COUNT(*) AS n FROM "{table}"').fetchone()
            out[table] = int(row["n"])
        return out

    def table_names(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return [str(row["name"]) for row in rows]

    def index_names(self, table: str) -> list[str]:
        rows = self._conn.execute(f"PRAGMA index_list({table})").fetchall()
        return [str(row["name"]) for row in rows]

    def pragma_value(self, name: str) -> object:
        row = self._conn.execute(f"PRAGMA {name}").fetchone()
        if row is None:
            return None
        return row[0]

    def integrity_check(self) -> str:
        row = self._conn.execute("PRAGMA integrity_check").fetchone()
        return str(row[0])


def claim_input_to_payload(
    claim: ClaimInput, artifacts: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Serialize a ClaimInput plus resolved artifact rows for the ledger operation."""
    return {
        "claim_id": claim.claim_id,
        "run_id": claim.run_id,
        "type": claim.type,
        "value_json": claim.value_json,
        "confidence": claim.confidence,
        "dedup_key": claim.dedup_key,
        "created": claim.created,
        "artifacts": list(artifacts),
    }


def _claim_input_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    claim_type = _text(payload, "type")
    if claim_type not in CLAIM_TYPES:
        raise FormatFail("claim type is off-vocabulary")
    confidence = _float(payload, "confidence")
    if not 0.0 <= confidence <= 1.0:
        raise FormatFail("claim confidence must be in [0,1]")
    try:
        json.loads(_text(payload, "value_json"))
    except json.JSONDecodeError as exc:
        raise FormatFail("claim value_json must be JSON") from exc
    artifacts = _list(payload, "artifacts")
    if not artifacts:
        raise FormatFail("claim requires at least one artifact link")
    return {
        "claim_id": _text(payload, "claim_id"),
        "run_id": _opt_text(payload, "run_id"),
        "type": claim_type,
        "value_json": _text(payload, "value_json"),
        "confidence": confidence,
        "dedup_key": _text(payload, "dedup_key"),
        "created": _int(payload, "created"),
        "artifacts": artifacts,
    }


__all__ = ["LedgerStore", "ClaimInput", "claim_input_to_payload", "RaError"]
