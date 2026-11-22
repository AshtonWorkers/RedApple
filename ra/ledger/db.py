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

from ..errors import AdapterShipBlocked, DuplicateDedup, FormatFail, RaError
from .ids import UlidFactory  # noqa: F401  (re-exported for callers)
from .models import ClaimInput
from .operations import LedgerOperation
from .schema import MEMORY_SCHEMA_SQL, RING_SCHEMA_SQL, SCHEMA_SQL
from .states import ClaimState, can_transition

CLAIM_TYPES = frozenset(
    {
        "bug_class",
        "rung",
        "groom",
        "join",
        "gadget_set",
        "root_cause",
        "dupe_score",
        "foundry_state",
        "harness",
        "discovery_crash",
        "discovery_campaign",
        "discovery_state",
        "race",
        "race_state",
        "advisory_snapshot",
        "advisory_priorities",
        "review",
        "crash",
    }
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
DEVICE_STATES = frozenset(
    {
        "attached",
        "needs_hand",
        "ready",
        "failed",
        "completed",
        "drained",
        "thermal_pause",
        "budget_exhausted",
    }
)
DEVICE_THERMAL_STATES = frozenset({"nominal", "serious", "critical"})
_MISSING: Any = object()
RING_INGEST_KINDS = frozenset({"ipsw", "oss_tarball", "webkit", "security_notes"})
RING_CORPUS_STATES = frozenset({"active", "revoked"})
RING_REPLAY_STATUSES = frozenset({"pass", "fail", "error", "skipped"})
RING_MIN_PINNED_NODES = 6
RING_MIN_CURRENT_NODES = 2
RING_HISTORY_CAPACITY_MIN = 2
RING_HISTORY_CAPACITY_MAX = 1024
RING_DEFAULT_HISTORY_CAPACITY = 8
RING_VERSION_ORIGINS = frozenset({"advance", "attach", "promote", "rollback"})
_RING_NODE_KEYS = (
    "ring_node_id",
    "ipsw_sha",
    "build",
    "xcode",
    "sdk",
    "webkit_commit",
    "state",
    "epoch",
)


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


def _opt_int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"ledger payload {key} must be int or None")
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


def _json_text(payload: Mapping[str, Any], key: str) -> str:
    value = _text(payload, key)
    try:
        json.loads(value)
    except json.JSONDecodeError as exc:
        raise FormatFail(f"ledger payload {key} must be JSON") from exc
    return value


def _score(payload: Mapping[str, Any], key: str) -> float:
    value = _float(payload, key)
    if not 0.0 <= value <= 1.0:
        raise FormatFail(f"ledger payload {key} must be in [0,1]")
    return value


def _mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise FormatFail(f"ledger payload {key} must be object")
    return value


def _ring_history_capacity(payload: Mapping[str, Any]) -> int:
    value = payload.get("history_capacity", RING_DEFAULT_HISTORY_CAPACITY)
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail("ring history_capacity must be int")
    if not RING_HISTORY_CAPACITY_MIN <= value <= RING_HISTORY_CAPACITY_MAX:
        raise FormatFail("ring history_capacity is out of range")
    return value


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
        else:
            self._conn.executescript(MEMORY_SCHEMA_SQL)
        self._conn.executescript(RING_SCHEMA_SQL)

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

    @staticmethod
    def _ring_node_values(
        payload: Mapping[str, Any], *, epoch: int | None = None
    ) -> tuple[str, str, str, str, str, str, str, int]:
        node_id = _text(payload, "ring_node_id")
        state = _text(payload, "state")
        if state not in RING_NODE_STATES:
            raise FormatFail("ring node state is invalid")
        node_epoch = _int(payload, "epoch") if epoch is None else epoch
        if node_epoch < 0:
            raise FormatFail("ring node epoch must be non-negative")
        fields = {
            "ipsw_sha": _text(payload, "ipsw_sha"),
            "build": _text(payload, "build"),
            "xcode": _text(payload, "xcode"),
            "sdk": _text(payload, "sdk"),
            "webkit_commit": _text(payload, "webkit_commit"),
        }
        for name, value in fields.items():
            if not value:
                raise FormatFail(f"ring node {name} must be non-empty")
        return (
            node_id,
            fields["ipsw_sha"],
            fields["build"],
            fields["xcode"],
            fields["sdk"],
            fields["webkit_commit"],
            state,
            node_epoch,
        )

    def _upsert_ring_node_row(self, payload: Mapping[str, Any], *, epoch: int | None = None) -> str:
        values = list(self._ring_node_values(payload, epoch=epoch))
        existing = self._conn.execute(
            "SELECT state FROM ring_node WHERE id=?", (values[0],)
        ).fetchone()
        if existing is not None and str(existing["state"]) == "bad" and values[6] != "bad":
            values[6] = "bad"
        self._conn.execute(
            """
            INSERT INTO ring_node(id, ipsw_sha, build, xcode, sdk, webkit_commit, state, epoch)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET ipsw_sha=excluded.ipsw_sha, build=excluded.build,
              xcode=excluded.xcode, sdk=excluded.sdk, webkit_commit=excluded.webkit_commit,
              state=excluded.state, epoch=excluded.epoch
            """,
            tuple(values),
        )
        return str(values[0])

    def _op_upsert_ring_node(self, payload: Mapping[str, Any]) -> str:
        return self._upsert_ring_node_row(payload)

    def _ring_current_epoch(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(epoch), 0) AS epoch FROM ring_node"
        ).fetchone()
        version_row = self._conn.execute(
            "SELECT COALESCE(MAX(epoch), 0) AS epoch FROM ring_version"
        ).fetchone()
        return max(int(row["epoch"]), int(version_row["epoch"]))

    def _clean_ring_nodes(
        self, nodes: Sequence[Mapping[str, Any]], *, epoch: int
    ) -> list[dict[str, Any]]:
        if not nodes:
            raise FormatFail("ring version requires at least one node")
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for node in nodes:
            values = self._ring_node_values(node, epoch=epoch)
            node_id = values[0]
            if node_id in seen:
                raise FormatFail("ring node ids must be unique")
            seen.add(node_id)
            if values[6] == "retired":
                raise FormatFail("ring version nodes cannot be retired")
            out.append(dict(zip(_RING_NODE_KEYS, values, strict=True)))
        return out

    def _apply_bad_quarantine(self, nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            node_id = str(node["ring_node_id"])
            row = self._conn.execute(
                "SELECT state FROM ring_node WHERE id=?", (node_id,)
            ).fetchone()
            existing = None if row is None else str(row["state"])
            state = str(node["state"])
            if existing == "bad":
                if state != "bad":
                    node["state"] = "bad"
            elif state == "bad":
                raise FormatFail(f"ring node {node_id} cannot be marked bad by ring version")

    def _validate_ring_snapshot(self, nodes: Sequence[Mapping[str, Any]]) -> None:
        if len(nodes) < RING_MIN_PINNED_NODES:
            raise FormatFail(f"ring requires at least {RING_MIN_PINNED_NODES} pinned nodes")
        current = sum(1 for node in nodes if node["state"] == "current")
        if current < RING_MIN_CURRENT_NODES:
            raise FormatFail(f"ring requires at least {RING_MIN_CURRENT_NODES} current nodes")

    def _write_ring_version(
        self,
        epoch: int,
        nodes: Sequence[Mapping[str, Any]],
        *,
        created: int | None = None,
        origin: str = "advance",
        restored_from_epoch: int | None = None,
        history_capacity: int = RING_DEFAULT_HISTORY_CAPACITY,
    ) -> int:
        if origin not in RING_VERSION_ORIGINS:
            raise FormatFail("ring version origin is invalid")
        current_epoch = self._ring_current_epoch()
        if epoch <= current_epoch:
            raise FormatFail("ring epoch must increase")
        clean = self._clean_ring_nodes(nodes, epoch=epoch)
        self._apply_bad_quarantine(clean)
        self._validate_ring_snapshot(clean)
        nodes_json = json.dumps(clean, sort_keys=True, separators=(",", ":"))
        self._conn.execute(
            """
            INSERT INTO ring_version(epoch, nodes_json, node_count, created, origin, restored_from_epoch)
            VALUES(?,?,?,?,?,?)
            """,
            (epoch, nodes_json, len(clean), 0 if created is None else created, origin, restored_from_epoch),
        )
        ids: list[str] = []
        for node in clean:
            node_id = self._upsert_ring_node_row(node, epoch=epoch)
            ids.append(node_id)
        placeholders = ",".join("?" for _ in ids)
        self._conn.execute(
            f"UPDATE ring_node SET state='retired' WHERE epoch < ? AND state <> 'bad' "
            f"AND id NOT IN ({placeholders})",
            (epoch, *ids),
        )
        self._evict_ring_versions(history_capacity)
        return epoch

    def _evict_ring_versions(self, history_capacity: int) -> list[int]:
        rows = self._conn.execute(
            "SELECT epoch FROM ring_version ORDER BY epoch DESC"
        ).fetchall()
        evicted = [int(row["epoch"]) for row in rows[history_capacity:]]
        for epoch in evicted:
            self._conn.execute("DELETE FROM ring_version WHERE epoch=?", (epoch,))
        return evicted

    def _advance_ring(
        self,
        epoch: int,
        nodes: Sequence[Mapping[str, Any]],
        *,
        history_capacity: int = RING_DEFAULT_HISTORY_CAPACITY,
        created: int | None = None,
    ) -> int:
        return self._write_ring_version(
            epoch,
            nodes,
            created=created,
            origin="advance",
            history_capacity=history_capacity,
        )

    def _op_advance_ring(self, payload: Mapping[str, Any]) -> int:
        return self._advance_ring(
            _int(payload, "epoch"),
            _list(payload, "nodes"),
            history_capacity=_ring_history_capacity(payload),
            created=_opt_int(payload, "created"),
        )

    def _op_advance_ring_auto(self, payload: Mapping[str, Any]) -> int:
        return self._advance_ring(
            self._ring_current_epoch() + 1,
            _list(payload, "nodes"),
            history_capacity=_ring_history_capacity(payload),
            created=_opt_int(payload, "created"),
        )

    def _ring_version_row(self, epoch: int) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT epoch, nodes_json, node_count, created, origin, restored_from_epoch "
                "FROM ring_version WHERE epoch=?",
                (epoch,),
            ).fetchone(),
        )

    def _latest_ring_version_row(self) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT epoch, nodes_json, node_count, created, origin, restored_from_epoch "
                "FROM ring_version ORDER BY epoch DESC LIMIT 1"
            ).fetchone(),
        )

    def _ring_version_epochs(self) -> list[int]:
        rows = self._conn.execute("SELECT epoch FROM ring_version ORDER BY epoch").fetchall()
        return [int(row["epoch"]) for row in rows]

    def _decode_ring_version_nodes(self, row: sqlite3.Row) -> list[dict[str, Any]]:
        try:
            data = json.loads(str(row["nodes_json"]))
        except json.JSONDecodeError as exc:
            raise RaError("ring version snapshot is corrupt") from exc
        if not isinstance(data, list):
            raise RaError("ring version snapshot is corrupt")
        out: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                raise RaError("ring version snapshot is corrupt")
            values = self._ring_node_values({key: item.get(key) for key in _RING_NODE_KEYS})
            out.append(dict(zip(_RING_NODE_KEYS, values, strict=True)))
        return out

    def _current_snapshot_nodes(self) -> tuple[int, list[dict[str, Any]]]:
        row = self._latest_ring_version_row()
        if row is not None:
            return int(row["epoch"]), self._decode_ring_version_nodes(row)
        epoch = self._ring_current_epoch()
        rows = self._conn.execute(
            "SELECT id, ipsw_sha, build, xcode, sdk, webkit_commit, state, epoch "
            "FROM ring_node WHERE epoch=? AND state IN ('active','current','bad') ORDER BY id",
            (epoch,),
        ).fetchall()
        nodes: list[dict[str, Any]] = []
        for row in rows:
            values = self._ring_node_values(
                {
                    "ring_node_id": row["id"],
                    "ipsw_sha": row["ipsw_sha"],
                    "build": row["build"],
                    "xcode": row["xcode"],
                    "sdk": row["sdk"],
                    "webkit_commit": row["webkit_commit"],
                    "state": row["state"],
                    "epoch": row["epoch"],
                }
            )
            nodes.append(dict(zip(_RING_NODE_KEYS, values, strict=True)))
        return epoch, nodes

    def _op_attach_ring_node(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        node = _mapping(payload, "node")
        epoch, nodes = self._current_snapshot_nodes()
        if not nodes:
            raise FormatFail("cannot attach before initial ring advance")
        node_id = _text(node, "ring_node_id")
        if any(str(item["ring_node_id"]) == node_id for item in nodes):
            raise FormatFail(f"ring node {node_id} already exists")
        state = _text(node, "state")
        if state not in {"active", "current"}:
            raise FormatFail("attached ring node must be active or current")
        new_node = dict(node)
        new_node["state"] = state
        new_node["epoch"] = epoch
        new_epoch = self._write_ring_version(
            self._ring_current_epoch() + 1,
            [*nodes, new_node],
            created=_opt_int(payload, "created"),
            origin="attach",
            history_capacity=_ring_history_capacity(payload),
        )
        return {
            "epoch": new_epoch,
            "node_id": node_id,
            "state": state,
            "node_count": len(nodes) + 1,
        }

    def _op_promote_ring_node(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        node_id = _text(payload, "ring_node_id")
        _, nodes = self._current_snapshot_nodes()
        if not nodes:
            raise FormatFail("cannot promote before initial ring advance")
        index = next(
            (i for i, node in enumerate(nodes) if str(node["ring_node_id"]) == node_id),
            None,
        )
        if index is None:
            raise FormatFail(f"unknown ring node {node_id}")
        state = str(nodes[index]["state"])
        if state == "bad":
            raise FormatFail(f"ring node {node_id} is bad")
        if state == "current":
            return {
                "epoch": self._ring_current_epoch(),
                "node_id": node_id,
                "state": "current",
                "changed": False,
                "node_count": len(nodes),
            }
        promoted = [dict(node) for node in nodes]
        promoted[index]["state"] = "current"
        new_epoch = self._write_ring_version(
            self._ring_current_epoch() + 1,
            promoted,
            created=_opt_int(payload, "created"),
            origin="promote",
            history_capacity=_ring_history_capacity(payload),
        )
        return {
            "epoch": new_epoch,
            "node_id": node_id,
            "state": "current",
            "changed": True,
            "node_count": len(promoted),
        }

    def _op_rollback_ring(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        target = _int(payload, "epoch")
        if target < 0:
            raise FormatFail("ring rollback epoch must be non-negative")
        epochs = self._ring_version_epochs()
        if not epochs:
            raise FormatFail("ring has no versions to roll back")
        if target not in epochs:
            if target < min(epochs):
                raise FormatFail("rollback target is older than retained ring history")
            raise FormatFail(f"unknown ring version epoch {target}")
        row = self._ring_version_row(target)
        if row is None:
            raise RaError("ring version snapshot is missing")
        nodes = self._decode_ring_version_nodes(row)
        current_epoch = self._ring_current_epoch()
        if target == current_epoch:
            return {
                "epoch": current_epoch,
                "restored_from_epoch": target,
                "changed": False,
                "node_count": len(nodes),
            }
        new_epoch = self._write_ring_version(
            current_epoch + 1,
            nodes,
            created=_opt_int(payload, "created"),
            origin="rollback",
            restored_from_epoch=target,
            history_capacity=_ring_history_capacity(payload),
        )
        return {
            "epoch": new_epoch,
            "restored_from_epoch": target,
            "changed": True,
            "node_count": len(nodes),
        }

    def _op_record_ring_boot_failure(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        node_id = _text(payload, "ring_node_id")
        threshold = _int(payload, "threshold")
        if threshold <= 0:
            raise FormatFail("ring boot failure threshold must be positive")
        node = self.ring_node(node_id)
        if node is None:
            raise FormatFail(f"unknown ring node {node_id}")
        row = self._conn.execute(
            "SELECT failures, bad_marked FROM ring_health WHERE ring_node_id=?",
            (node_id,),
        ).fetchone()
        failures = int(row["failures"]) if row is not None else 0
        bad_marked = int(row["bad_marked"]) if row is not None else 0
        failures += 1
        state = str(node["state"])
        alert = False
        if failures >= threshold and state != "bad":
            self._conn.execute("UPDATE ring_node SET state='bad' WHERE id=?", (node_id,))
            bad_marked = 1
            state = "bad"
            alert = True
        self._conn.execute(
            """
            INSERT INTO ring_health(ring_node_id, failures, bad_marked, updated)
            VALUES(?,?,?,?)
            ON CONFLICT(ring_node_id) DO UPDATE SET failures=excluded.failures,
              bad_marked=excluded.bad_marked, updated=excluded.updated
            """,
            (node_id, failures, bad_marked, _int(payload, "updated")),
        )
        return {
            "node_id": node_id,
            "failures": failures,
            "state": state,
            "bad_marked": bool(bad_marked),
            "alert": alert,
        }

    def _op_record_ring_ingest(self, payload: Mapping[str, Any]) -> str:
        kind = _text(payload, "kind")
        if kind not in RING_INGEST_KINDS:
            raise FormatFail("ring ingest kind is invalid")
        sha256 = _text(payload, "sha256")
        if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
            raise FormatFail("ring ingest sha256 must be lowercase hex")
        size_bytes = _int(payload, "bytes")
        if size_bytes < 0:
            raise FormatFail("ring ingest bytes must be non-negative")
        epoch = _int(payload, "epoch")
        if epoch < 0:
            raise FormatFail("ring ingest epoch must be non-negative")
        self._conn.execute(
            """
            INSERT INTO ring_ingest(id, kind, uri, sha256, bytes, artifact_id, epoch, created)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(kind, sha256, epoch) DO NOTHING
            """,
            (
                _text(payload, "ingest_id"),
                kind,
                _text(payload, "uri"),
                sha256,
                size_bytes,
                _opt_text(payload, "artifact_id"),
                epoch,
                _int(payload, "created"),
            ),
        )
        row = self._conn.execute(
            "SELECT id FROM ring_ingest WHERE kind=? AND sha256=? AND epoch=?",
            (kind, sha256, epoch),
        ).fetchone()
        if row is None:
            raise RaError("ring ingest registration failed")
        return str(row["id"])

    def _op_register_ring_corpus(self, payload: Mapping[str, Any]) -> str:
        corpus_key = _text(payload, "corpus_key")
        if not corpus_key:
            raise FormatFail("ring corpus key must be non-empty")
        ring_node_id = _text(payload, "ring_node_id")
        if self.ring_node(ring_node_id) is None:
            raise FormatFail(f"unknown ring node {ring_node_id}")
        epoch = _int(payload, "epoch")
        if epoch < 0:
            raise FormatFail("ring corpus epoch must be non-negative")
        self._conn.execute(
            """
            INSERT INTO ring_corpus(id, corpus_key, ring_node_id, epoch, state, artifact_id, created, updated)
            VALUES(?,?,?,?,'active',?,?,?)
            ON CONFLICT(corpus_key, ring_node_id, epoch) DO UPDATE SET
              state='active', artifact_id=COALESCE(excluded.artifact_id, ring_corpus.artifact_id),
              updated=excluded.updated
            """,
            (
                _text(payload, "corpus_id"),
                corpus_key,
                ring_node_id,
                epoch,
                _opt_text(payload, "artifact_id"),
                _int(payload, "created"),
                _int(payload, "updated"),
            ),
        )
        row = self._conn.execute(
            "SELECT id FROM ring_corpus WHERE corpus_key=? AND ring_node_id=? AND epoch=?",
            (corpus_key, ring_node_id, epoch),
        ).fetchone()
        if row is None:
            raise RaError("ring corpus registration failed")
        return str(row["id"])

    def _op_revoke_ring_corpus(self, payload: Mapping[str, Any]) -> int:
        corpus_key = _opt_text(payload, "corpus_key")
        ring_node_id = _opt_text(payload, "ring_node_id")
        epoch = _opt_int(payload, "epoch")
        if corpus_key is None and ring_node_id is None and epoch is None:
            raise FormatFail("ring corpus revocation requires a filter")
        if epoch is not None and epoch < 0:
            raise FormatFail("ring corpus epoch must be non-negative")
        sql = "UPDATE ring_corpus SET state='revoked', updated=? WHERE state='active'"
        params: list[object] = [_int(payload, "updated")]
        if corpus_key is not None:
            sql += " AND corpus_key=?"
            params.append(corpus_key)
        if ring_node_id is not None:
            sql += " AND ring_node_id=?"
            params.append(ring_node_id)
        if epoch is not None:
            sql += " AND epoch=?"
            params.append(epoch)
        cursor = self._conn.execute(sql, tuple(params))
        return int(cursor.rowcount)

    def _op_record_ring_replay(self, payload: Mapping[str, Any]) -> str:
        status = _text(payload, "status")
        if status not in RING_REPLAY_STATUSES:
            raise FormatFail("ring replay status is invalid")
        detail_json = _text(payload, "detail_json")
        try:
            json.loads(detail_json)
        except json.JSONDecodeError as exc:
            raise FormatFail("ring replay detail_json must be valid JSON") from exc
        epoch = _int(payload, "epoch")
        if epoch < 0:
            raise FormatFail("ring replay epoch must be non-negative")
        ring_node_id = _text(payload, "ring_node_id")
        if self.ring_node(ring_node_id) is None:
            raise FormatFail(f"unknown ring node {ring_node_id}")
        corpus_key = _text(payload, "corpus_key")
        finding_id = _text(payload, "finding_id")
        if not corpus_key or not finding_id:
            raise FormatFail("ring replay corpus_key and finding_id must be non-empty")
        self._conn.execute(
            """
            INSERT INTO ring_replay(id, run_id, epoch, ring_node_id, corpus_key, finding_id, status, detail_json, created)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id, ring_node_id, corpus_key, finding_id) DO NOTHING
            """,
            (
                _text(payload, "replay_id"),
                _text(payload, "run_id"),
                epoch,
                ring_node_id,
                corpus_key,
                finding_id,
                status,
                detail_json,
                _int(payload, "created"),
            ),
        )
        row = self._conn.execute(
            "SELECT id FROM ring_replay WHERE run_id=? AND ring_node_id=? AND corpus_key=? AND finding_id=?",
            (_text(payload, "run_id"), ring_node_id, corpus_key, finding_id),
        ).fetchone()
        if row is None:
            raise RaError("ring replay registration failed")
        return str(row["id"])

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

    def _op_link_claim_artifact(self, payload: Mapping[str, Any]) -> bool:
        claim_id = _text(payload, "claim_id")
        row = self._conn.execute("SELECT id FROM claim WHERE id=?", (claim_id,)).fetchone()
        if row is None:
            raise FormatFail("claim does not exist")
        artifact_id_value = _text(payload, "artifact_id")
        self._insert_artifact_row(
            {
                "artifact_id": artifact_id_value,
                "kind": _text(payload, "kind"),
                "sha256": _text(payload, "sha256"),
                "bytes": _int(payload, "bytes"),
                "created": _int(payload, "created"),
                "ttl_class": _text(payload, "ttl_class"),
            }
        )
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO claim_artifact(claim_id, artifact_id, role) VALUES(?,?,?)",
            (claim_id, artifact_id_value, _text(payload, "role")),
        )
        return cursor.rowcount == 1

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

    def _op_update_join(self, payload: Mapping[str, Any]) -> bool:
        updates = ["state=?"]
        params: list[object] = [_text(payload, "state")]
        for key in ("reliability", "lower_bound"):
            if key in payload:
                value = payload[key]
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, (int, float))
                ):
                    raise FormatFail(f"join {key} must be a number or None")
                updates.append(f"{key}=?")
                params.append(value)
        if "invariants_json" in payload:
            updates.append("invariants_json=?")
            params.append(_text(payload, "invariants_json"))
        params.append(_text(payload, "join_id"))
        cursor = self._conn.execute(
            f'UPDATE "join" SET {", ".join(updates)} WHERE id=?', tuple(params)
        )
        return cursor.rowcount == 1

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

    def _op_upsert_memory_prior(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        kind = _text(payload, "kind")
        surface = _text(payload, "surface")
        key = _text(payload, "key")
        value_json = _json_text(payload, "value_json")
        score = _score(payload, "score")
        support = _int(payload, "support")
        confidence = _score(payload, "confidence")
        if support < 0:
            raise FormatFail("memory prior support must be >= 0")
        self._conn.execute(
            """
            INSERT INTO memory_prior(
              id, kind, surface, key, value_json, score, support, confidence, state,
              revision, source_claim, source_artifact, created, updated
            ) VALUES(?,?,?,?,?,?,?,?,'active',1,?,?,?,?)
            ON CONFLICT(kind,surface,key) DO UPDATE SET
              value_json=CASE
                WHEN excluded.score >= memory_prior.score THEN excluded.value_json
                ELSE memory_prior.value_json END,
              score=MAX(memory_prior.score, excluded.score),
              support=memory_prior.support + excluded.support,
              confidence=MAX(memory_prior.confidence, excluded.confidence),
              state='active',
              revision=memory_prior.revision + 1,
              source_claim=excluded.source_claim,
              source_artifact=excluded.source_artifact,
              updated=excluded.updated
            """,
            (
                _text(payload, "prior_id"),
                kind,
                surface,
                key,
                value_json,
                score,
                support,
                confidence,
                _opt_text(payload, "source_claim"),
                _opt_text(payload, "source_artifact"),
                _int(payload, "created"),
                _int(payload, "updated"),
            ),
        )
        row = self._conn.execute(
            "SELECT * FROM memory_prior WHERE kind=? AND surface=? AND key=?",
            (kind, surface, key),
        ).fetchone()
        if row is None:
            raise FormatFail("memory prior upsert did not persist")
        return dict(row)

    def _op_retire_memory_prior(self, payload: Mapping[str, Any]) -> bool:
        cursor = self._conn.execute(
            "UPDATE memory_prior SET state='retired', updated=? WHERE id=?",
            (_int(payload, "updated"), _text(payload, "prior_id")),
        )
        return cursor.rowcount == 1

    def _op_ensure_memory_preference(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        pair_id = _text(payload, "pair_id")
        chosen_json = _json_text(payload, "chosen_json")
        rejected_json = _json_text(payload, "rejected_json")
        reward = _score(payload, "reward")
        cursor = self._conn.execute(
            """
            INSERT INTO memory_preference(
              id, task_type, surface, prompt_sha, chosen_json, rejected_json, reward,
              rationale, source_claim, source_artifact, created
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                pair_id,
                _text(payload, "task_type"),
                _text(payload, "surface"),
                _text(payload, "prompt_sha"),
                chosen_json,
                rejected_json,
                reward,
                _opt_text(payload, "rationale"),
                _opt_text(payload, "source_claim"),
                _opt_text(payload, "source_artifact"),
                _int(payload, "created"),
            ),
        )
        row = self._conn.execute("SELECT * FROM memory_preference WHERE id=?", (pair_id,)).fetchone()
        if row is None:
            raise FormatFail("memory preference insert failed")
        return {"inserted": int(cursor.rowcount), "row": dict(row)}

    def _op_create_memory_adapter(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        task_type = _text(payload, "task_type")
        surface = _text(payload, "surface")
        config_json = _json_text(payload, "config_json")
        pair_rows = _list(payload, "pair_ids")
        pair_ids = [_text(row, "pair_id") for row in pair_rows]
        train_pair_count = _int(payload, "train_pair_count")
        if train_pair_count != len(pair_ids):
            raise FormatFail("adapter train_pair_count must match pair_ids")
        for pair_id in pair_ids:
            exists = self._conn.execute(
                "SELECT 1 FROM memory_preference WHERE id=?", (pair_id,)
            ).fetchone()
            if exists is None:
                raise FormatFail("adapter references unknown preference pair")
        version_row = self._conn.execute(
            """
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM memory_adapter WHERE task_type=? AND surface=?
            """,
            (task_type, surface),
        ).fetchone()
        version = int(version_row["version"])
        adapter_id = _text(payload, "adapter_id")
        created = _int(payload, "created")
        self._conn.execute(
            """
            INSERT INTO memory_adapter(
              id, task_type, surface, version, parent_id, state, config_json,
              train_pair_count, eval_score, baseline_score, golden_rows, golden_passed,
              ship_blocked_reason, source_artifact, created, updated
            ) VALUES(?,?,?,?,?,'candidate',?,?,NULL,NULL,NULL,NULL,NULL,?,?,?)
            """,
            (
                adapter_id,
                task_type,
                surface,
                version,
                _opt_text(payload, "parent_id"),
                config_json,
                train_pair_count,
                _opt_text(payload, "source_artifact"),
                created,
                created,
            ),
        )
        for pair_id in pair_ids:
            self._conn.execute(
                "INSERT INTO memory_adapter_pair(adapter_id, pair_id) VALUES(?,?)",
                (adapter_id, pair_id),
            )
        row = self._conn.execute(
            "SELECT * FROM memory_adapter WHERE id=?", (adapter_id,)
        ).fetchone()
        if row is None:
            raise FormatFail("memory adapter insert failed")
        return dict(row)

    def _op_evaluate_memory_adapter(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        adapter_id = _text(payload, "adapter_id")
        row = self._conn.execute(
            "SELECT state FROM memory_adapter WHERE id=?", (adapter_id,)
        ).fetchone()
        if row is None:
            raise FormatFail("memory adapter does not exist")
        if str(row["state"]) not in {"candidate", "evaluated", "rejected"}:
            raise FormatFail("memory adapter cannot be evaluated from its state")
        baseline = payload.get("baseline_score")
        baseline_score = None if baseline is None else _score(payload, "baseline_score")
        blocked = _opt_text(payload, "ship_blocked_reason")
        self._conn.execute(
            """
            UPDATE memory_adapter
            SET state='evaluated', eval_score=?, baseline_score=?, golden_rows=?,
                golden_passed=?, ship_blocked_reason=?, updated=?
            WHERE id=?
            """,
            (
                _score(payload, "eval_score"),
                baseline_score,
                _int(payload, "golden_rows"),
                1 if _bool(payload, "golden_passed") else 0,
                blocked,
                _int(payload, "updated"),
                adapter_id,
            ),
        )
        updated_row = self._conn.execute(
            "SELECT * FROM memory_adapter WHERE id=?", (adapter_id,)
        ).fetchone()
        if updated_row is None:
            raise FormatFail("memory adapter update failed")
        return dict(updated_row)

    def _op_ship_memory_adapter(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        adapter_id = _text(payload, "adapter_id")
        updated = _int(payload, "updated")
        row = self._conn.execute(
            "SELECT * FROM memory_adapter WHERE id=?", (adapter_id,)
        ).fetchone()
        if row is None:
            raise FormatFail("memory adapter does not exist")
        adapter = dict(row)
        if adapter["state"] == "shipped":
            return {"changed": False, "row": adapter}
        shippable = (
            adapter["state"] == "evaluated"
            and adapter["golden_passed"] == 1
            and adapter["eval_score"] is not None
        )
        if not shippable:
            raise AdapterShipBlocked("memory adapter is not shippable")
        self._conn.execute(
            """
            UPDATE memory_adapter SET state='retired', updated=?
            WHERE task_type=? AND surface=? AND state='shipped' AND id<>?
            """,
            (updated, adapter["task_type"], adapter["surface"], adapter_id),
        )
        self._conn.execute(
            "UPDATE memory_adapter SET state='shipped', updated=? WHERE id=?",
            (updated, adapter_id),
        )
        shipped = self._conn.execute(
            "SELECT * FROM memory_adapter WHERE id=?", (adapter_id,)
        ).fetchone()
        if shipped is None:
            raise FormatFail("memory adapter ship failed")
        return {"changed": True, "row": dict(shipped)}

    def _op_set_memory_adapter_state(self, payload: Mapping[str, Any]) -> bool:
        to_state = _text(payload, "to_state")
        if to_state not in {"rejected", "retired"}:
            raise FormatFail("memory adapter state update is off-vocabulary")
        cursor = self._conn.execute(
            "UPDATE memory_adapter SET state=?, updated=? WHERE id=? AND state<>?",
            (to_state, _int(payload, "updated"), _text(payload, "adapter_id"), to_state),
        )
        return cursor.rowcount == 1

    def _op_record_memory_sla(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        surface = _text(payload, "surface")
        if not surface:
            raise FormatFail("memory SLA surface must be non-empty")
        target = _int(payload, "target_cost_micro")
        cost = _int(payload, "cost_micro")
        at = _int(payload, "created")
        if target < 0 or cost < 0:
            raise FormatFail("memory SLA costs must be >= 0")
        existing = self._conn.execute(
            "SELECT * FROM memory_sla WHERE surface=?", (surface,)
        ).fetchone()
        if existing is None:
            met = cost <= target
            best = cost
            last = cost
            met_at = at if met else None
            observations = 1
            regressions = 0
            flagged = 0
            violation_json = None
            self._conn.execute(
                """
                INSERT INTO memory_sla(
                  surface, target_cost_micro, best_cost_micro, last_cost_micro, met,
                  met_at, observations, regressions, flagged, violation_json,
                  created, updated
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    surface,
                    target,
                    best,
                    last,
                    1 if met else 0,
                    met_at,
                    observations,
                    regressions,
                    flagged,
                    violation_json,
                    at,
                    at,
                ),
            )
        else:
            row = dict(existing)
            if int(row["target_cost_micro"]) != target:
                raise FormatFail("memory SLA target is immutable")
            previous_last = int(row["last_cost_micro"])
            regression = cost > previous_last
            best = min(int(row["best_cost_micro"]), cost)
            was_met = int(row["met"]) == 1
            met = was_met or cost <= target
            met_at = row["met_at"] if was_met else (at if met else None)
            observations = int(row["observations"]) + 1
            regressions = int(row["regressions"]) + (1 if regression else 0)
            flagged = int(row["flagged"]) or (1 if regression else 0)
            violation_json = row["violation_json"]
            if regression:
                violation = {
                    "at": at,
                    "cost_micro": cost,
                    "previous_cost_micro": previous_last,
                    "target_cost_micro": target,
                    "best_after_micro": best,
                    "reason": "cost_regression",
                }
                violation_json = json.dumps(
                    violation, sort_keys=True, separators=(",", ":")
                )
            self._conn.execute(
                """
                UPDATE memory_sla
                SET best_cost_micro=?, last_cost_micro=?, met=?, met_at=?, observations=?,
                    regressions=?, flagged=?, violation_json=?, updated=?
                WHERE surface=?
                """,
                (
                    best,
                    cost,
                    1 if met else 0,
                    met_at,
                    observations,
                    regressions,
                    flagged,
                    violation_json,
                    at,
                    surface,
                ),
            )
        self._conn.execute(
            """
            INSERT INTO memory_sla_event(
              id, surface, cost_micro, target_cost_micro, best_after_micro,
              last_after_micro, met_after, flagged_after, regression, created
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                _text(payload, "sla_event_id"),
                surface,
                cost,
                target,
                best,
                cost,
                1 if (existing is None and cost <= target) or (existing is not None and met) else 0,
                flagged,
                1 if existing is not None and cost > int(dict(existing)["last_cost_micro"]) else 0,
                at,
            ),
        )
        saved = self._conn.execute(
            "SELECT * FROM memory_sla WHERE surface=?", (surface,)
        ).fetchone()
        if saved is None:
            raise FormatFail("memory SLA write failed")
        return dict(saved)

    def _op_record_memory_retrieval(self, payload: Mapping[str, Any]) -> str:
        retrieval_id = _text(payload, "retrieval_id")
        self._conn.execute(
            """
            INSERT INTO memory_retrieval(
              id, run_id, surface, task_type, packet_sha, adapter_id, prior_ids_json,
              pair_ids_json, relevance, created
            ) VALUES(?,?,?,?,?,?,?,?,NULL,?)
            """,
            (
                retrieval_id,
                _opt_text(payload, "run_id"),
                _text(payload, "surface"),
                _opt_text(payload, "task_type"),
                _opt_text(payload, "packet_sha"),
                _opt_text(payload, "adapter_id"),
                _json_text(payload, "prior_ids_json"),
                _json_text(payload, "pair_ids_json"),
                _int(payload, "created"),
            ),
        )
        return retrieval_id

    def _op_update_memory_retrieval_relevance(self, payload: Mapping[str, Any]) -> int:
        relevance = _score(payload, "relevance")
        retrieval_id = _opt_text(payload, "retrieval_id")
        packet_sha = _opt_text(payload, "packet_sha")
        if retrieval_id is None and packet_sha is None:
            raise FormatFail("memory relevance update requires retrieval_id or packet_sha")
        if retrieval_id is not None:
            cursor = self._conn.execute(
                "UPDATE memory_retrieval SET relevance=? WHERE id=?",
                (relevance, retrieval_id),
            )
        else:
            cursor = self._conn.execute(
                "UPDATE memory_retrieval SET relevance=? WHERE packet_sha=?",
                (relevance, packet_sha),
            )
        return int(cursor.rowcount)

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

    def get_join(self, join_id: str) -> dict[str, Any] | None:
        """Fetch one join row."""
        row = self._conn.execute(
            'SELECT id, a_claim, b_claim, invariants_json, reliability, lower_bound, state, created '
            'FROM "join" WHERE id=?',
            (join_id,),
        ).fetchone()
        return None if row is None else dict(row)

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
        """List join rows with deterministic ordering."""
        if states is not None and not states:
            return []
        conditions: list[str] = []
        params: list[object] = []
        if state is not None:
            conditions.append("state=?")
            params.append(state)
        if states is not None:
            placeholders = ",".join("?" for _ in states)
            conditions.append(f"state IN ({placeholders})")
            params.extend(states)
        if a_claim is not None:
            conditions.append("a_claim=?")
            params.append(a_claim)
        if b_claim is not None:
            conditions.append("b_claim=?")
            params.append(b_claim)
        if created_after is not None:
            conditions.append("created>=?")
            params.append(created_after)
        sql = (
            'SELECT id, a_claim, b_claim, invariants_json, reliability, lower_bound, state, created '
            'FROM "join"'
        )
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY created, id LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def verdicts_for_claim(self, claim_id: str) -> list[dict[str, Any]]:
        """List review verdicts for a claim in creation order."""
        rows = self._conn.execute(
            """
            SELECT id, claim_id, reviewer, agree, reason, created
            FROM verdict WHERE claim_id=? ORDER BY created, id
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

    def _ring_version_public(self, row: sqlite3.Row) -> dict[str, Any]:
        restored = row["restored_from_epoch"]
        return {
            "epoch": int(row["epoch"]),
            "nodes": self._decode_ring_version_nodes(row),
            "node_count": int(row["node_count"]),
            "created": int(row["created"]),
            "origin": str(row["origin"]),
            "restored_from_epoch": None if restored is None else int(restored),
        }

    def ring_versions(self) -> list[dict[str, Any]]:
        """List retained ring version snapshots in epoch order."""
        rows = self._conn.execute(
            "SELECT epoch, nodes_json, node_count, created, origin, restored_from_epoch "
            "FROM ring_version ORDER BY epoch"
        ).fetchall()
        return [self._ring_version_public(row) for row in rows]

    def ring_version(self, epoch: int) -> dict[str, Any] | None:
        """Fetch one retained ring version snapshot."""
        row = self._ring_version_row(epoch)
        return None if row is None else self._ring_version_public(row)

    def ring_ingests(
        self, *, epoch: int | None = None, kind: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        """List ring ingest records in deterministic order."""
        sql = (
            "SELECT id, kind, uri, sha256, bytes, artifact_id, epoch, created "
            "FROM ring_ingest WHERE 1=1"
        )
        params: list[object] = []
        if epoch is not None:
            sql += " AND epoch=?"
            params.append(epoch)
        if kind is not None:
            sql += " AND kind=?"
            params.append(kind)
        sql += " ORDER BY epoch, created, id LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def ring_ingest(self, ingest_id: str) -> dict[str, Any] | None:
        """Fetch one ring ingest record."""
        row = self._conn.execute(
            "SELECT id, kind, uri, sha256, bytes, artifact_id, epoch, created "
            "FROM ring_ingest WHERE id=?",
            (ingest_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def ring_corpora(
        self,
        *,
        corpus_key: str | None = None,
        ring_node_id: str | None = None,
        state: str | None = None,
        epoch: int | None = None,
    ) -> list[dict[str, Any]]:
        """List ring corpus bindings in deterministic order."""
        sql = (
            "SELECT id, corpus_key, ring_node_id, epoch, state, artifact_id, created, updated "
            "FROM ring_corpus WHERE 1=1"
        )
        params: list[object] = []
        if corpus_key is not None:
            sql += " AND corpus_key=?"
            params.append(corpus_key)
        if ring_node_id is not None:
            sql += " AND ring_node_id=?"
            params.append(ring_node_id)
        if state is not None:
            sql += " AND state=?"
            params.append(state)
        if epoch is not None:
            sql += " AND epoch=?"
            params.append(epoch)
        sql += " ORDER BY corpus_key, ring_node_id, epoch, id"
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def ring_corpus(self, corpus_id: str) -> dict[str, Any] | None:
        """Fetch one ring corpus binding."""
        row = self._conn.execute(
            "SELECT id, corpus_key, ring_node_id, epoch, state, artifact_id, created, updated "
            "FROM ring_corpus WHERE id=?",
            (corpus_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def ring_replays(
        self,
        *,
        run_id: str | None = None,
        epoch: int | None = None,
        ring_node_id: str | None = None,
        corpus_key: str | None = None,
        finding_id: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List ring replay records in deterministic order."""
        sql = (
            "SELECT id, run_id, epoch, ring_node_id, corpus_key, finding_id, status, detail_json, created "
            "FROM ring_replay WHERE 1=1"
        )
        params: list[object] = []
        if run_id is not None:
            sql += " AND run_id=?"
            params.append(run_id)
        if epoch is not None:
            sql += " AND epoch=?"
            params.append(epoch)
        if ring_node_id is not None:
            sql += " AND ring_node_id=?"
            params.append(ring_node_id)
        if corpus_key is not None:
            sql += " AND corpus_key=?"
            params.append(corpus_key)
        if finding_id is not None:
            sql += " AND finding_id=?"
            params.append(finding_id)
        sql += " ORDER BY epoch, created, id LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def ring_replay(self, replay_id: str) -> dict[str, Any] | None:
        """Fetch one ring replay record."""
        row = self._conn.execute(
            "SELECT id, run_id, epoch, ring_node_id, corpus_key, finding_id, status, detail_json, created "
            "FROM ring_replay WHERE id=?",
            (replay_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def ring_health(self, ring_node_id: str) -> dict[str, Any] | None:
        """Fetch ring health counters for one node."""
        row = self._conn.execute(
            "SELECT ring_node_id, failures, bad_marked, updated FROM ring_health WHERE ring_node_id=?",
            (ring_node_id,),
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

    def memory_prior_row(self, prior_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM memory_prior WHERE id=?", (prior_id,)).fetchone()
        return None if row is None else dict(row)

    def memory_prior_by_key(self, kind: str, surface: str, key: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM memory_prior WHERE kind=? AND surface=? AND key=?",
            (kind, surface, key),
        ).fetchone()
        return None if row is None else dict(row)

    def memory_priors(
        self,
        surface: str | None = None,
        *,
        kind: str | None = None,
        state: str = "active",
        include_global: bool = True,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if state not in {"active", "retired"}:
            raise FormatFail("memory prior state is invalid")
        clauses = ["state=?"]
        params: list[object] = [state]
        if surface is not None:
            if include_global:
                clauses.append("(surface=? OR surface='*')")
            else:
                clauses.append("surface=?")
            params.append(surface)
        if kind is not None:
            clauses.append("kind=?")
            params.append(kind)
        sql = (
            "SELECT * FROM memory_prior WHERE "
            + " AND ".join(clauses)
            + " ORDER BY score DESC, support DESC, updated DESC, id ASC LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def memory_preference_row(self, pair_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM memory_preference WHERE id=?", (pair_id,)
        ).fetchone()
        return None if row is None else dict(row)

    def memory_preferences(
        self,
        *,
        task_type: str | None = None,
        surface: str | None = None,
        surfaces: Sequence[str] | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if surfaces is not None and not surfaces:
            return []
        clauses: list[str] = []
        params: list[object] = []
        if task_type is not None:
            clauses.append("task_type=?")
            params.append(task_type)
        if surfaces is not None:
            placeholders = ",".join("?" for _ in surfaces)
            clauses.append(f"surface IN ({placeholders})")
            params.extend(surfaces)
        elif surface is not None:
            clauses.append("surface=?")
            params.append(surface)
        sql = "SELECT * FROM memory_preference"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY reward DESC, created DESC, id ASC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def memory_adapter_row(self, adapter_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM memory_adapter WHERE id=?", (adapter_id,)
        ).fetchone()
        return None if row is None else dict(row)

    def memory_adapters(
        self,
        *,
        task_type: str | None = None,
        surface: str | None = None,
        state: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if state is not None and state not in {
            "candidate",
            "evaluated",
            "shipped",
            "rejected",
            "retired",
        }:
            raise FormatFail("memory adapter state is invalid")
        clauses: list[str] = []
        params: list[object] = []
        if task_type is not None:
            clauses.append("task_type=?")
            params.append(task_type)
        if surface is not None:
            clauses.append("surface=?")
            params.append(surface)
        if state is not None:
            clauses.append("state=?")
            params.append(state)
        sql = "SELECT * FROM memory_adapter"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY version DESC, created DESC, id ASC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def memory_active_adapter(self, task_type: str, surface: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT * FROM memory_adapter
            WHERE task_type=? AND surface=? AND state='shipped'
            ORDER BY version DESC, created DESC, id ASC LIMIT 1
            """,
            (task_type, surface),
        ).fetchone()
        return None if row is None else dict(row)

    def memory_adapter_pair_ids(self, adapter_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT pair_id FROM memory_adapter_pair WHERE adapter_id=? ORDER BY pair_id",
            (adapter_id,),
        ).fetchall()
        return [str(row["pair_id"]) for row in rows]

    def memory_sla_row(self, surface: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM memory_sla WHERE surface=?", (surface,)
        ).fetchone()
        return None if row is None else dict(row)

    def memory_sla_rows(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM memory_sla ORDER BY surface ASC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def memory_sla_events(self, surface: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT * FROM memory_sla_event
            WHERE surface=? ORDER BY created ASC, id ASC LIMIT ?
            """,
            (surface, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def memory_retrieval_row(self, retrieval_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM memory_retrieval WHERE id=?", (retrieval_id,)
        ).fetchone()
        return None if row is None else dict(row)

    def memory_retrievals(
        self,
        *,
        surface: str | None = None,
        task_type: str | None = None,
        packet_sha: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if surface is not None:
            clauses.append("surface=?")
            params.append(surface)
        if task_type is not None:
            clauses.append("task_type=?")
            params.append(task_type)
        if packet_sha is not None:
            clauses.append("packet_sha=?")
            params.append(packet_sha)
        sql = "SELECT * FROM memory_retrieval"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
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
            "memory_prior",
            "memory_preference",
            "memory_adapter",
            "memory_adapter_pair",
            "memory_sla",
            "memory_sla_event",
            "memory_retrieval",
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
