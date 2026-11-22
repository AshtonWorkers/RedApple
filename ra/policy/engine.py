"""Policy engine: EV routing, cap gates, remedy failure state, shedding."""

from __future__ import annotations

import asyncio
import json
import math
import time
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from ..errors import BudgetGate, FormatFail
from ..ledger import Ledger
from ..ledger.ids import now_ms
from ..ledger.operations import LedgerOperation
from .actions import ACTION_COST_USD_MICRO, Action, parse_action
from .handlers import ActionHandler, NullActionHandler
from .models import (
    SQLITE_INT_MAX,
    ActionOutcome,
    ActionResult,
    EVInputs,
    LaneAvailability,
)
from .providers import (
    EVInputProvider,
    LaneStateProvider,
    StaticEVInputProvider,
    StaticLaneStateProvider,
)
from .ranking import WorkOrderCandidate, ev_score, rank, shed_budget

__all__ = [
    "Executor",
    "ExecutorCaps",
    "PolicyEngine",
    "DispatchReport",
    "candidates_from_rows",
]

_EMPTY_EV_INPUTS = EVInputs(probability_join=0.0)


@dataclass(frozen=True)
class ExecutorCaps:
    """Hard caps checked before any side effect (I8)."""

    spend_usd_micro: int
    cas_bytes: int = 60 * 1024 * 1024 * 1024
    corpus_max: int = 250_000
    crashes_per_device: int = 400
    escalations: int = 120
    backlog_limit: int = 5000

    def __post_init__(self) -> None:
        """Reject non-integer or ledger-overflowing caps."""
        for name in (
            "spend_usd_micro",
            "cas_bytes",
            "corpus_max",
            "crashes_per_device",
            "escalations",
            "backlog_limit",
        ):
            _validate_ledger_int(name, getattr(self, name))


@dataclass(frozen=True)
class DispatchReport:
    """One bounded policy dispatch tick."""

    dispatched: int
    refusals: tuple[str, ...]
    requeued: tuple[str, ...]
    shed: int
    tick_ms: float
    within_budget: bool


def _cast_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _finite(value: object, fallback: float = 0.0) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return fallback
    return number if math.isfinite(number) else fallback


def _validate_ledger_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"{name} must be int")
    if value < 0 or value > SQLITE_INT_MAX:
        raise FormatFail(f"{name} must be within ledger integer range")


def _payload_float(payload: Mapping[str, Any], key: str, default: float) -> float:
    if key not in payload:
        return default
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise FormatFail(f"work_order payload {key} must be numeric")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise FormatFail(f"work_order payload {key} must be numeric") from exc


def _payload_int(payload: Mapping[str, Any], key: str, default: int) -> int:
    if key not in payload:
        return default
    value = payload[key]
    if isinstance(value, bool):
        raise FormatFail(f"work_order payload {key} must be int")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError as exc:
            raise FormatFail(f"work_order payload {key} must be int") from exc
    raise FormatFail(f"work_order payload {key} must be int")


def _payload_str(payload: Mapping[str, Any], key: str, default: str) -> str:
    value = payload.get(key, default)
    if not isinstance(value, str):
        raise FormatFail(f"work_order payload {key} must be str")
    return value


def _row_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    raw = row.get("payload_json")
    if raw is None:
        return {}
    if not isinstance(raw, str):
        raise FormatFail(f"work_order payload must be str or None: {row.get('id')}")
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FormatFail(f"work_order payload is invalid JSON: {row.get('id')}") from exc
    if not isinstance(loaded, dict):
        raise FormatFail(f"work_order payload must be an object: {row.get('id')}")
    return cast(dict[str, Any], loaded)


def _required_str(row: Mapping[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise FormatFail(f"work_order {key} must be a non-empty string")
    return value


def _candidate_from_row(row: Mapping[str, Any]) -> WorkOrderCandidate:
    payload = _row_payload(row)
    cas_bytes = payload.get("cas_bytes", 0)
    if isinstance(cas_bytes, bool) or not isinstance(cas_bytes, int):
        raise FormatFail(f"work_order payload cas_bytes invalid: {row.get('id')}")
    ev_cost = row.get("ev_cost")
    if isinstance(ev_cost, bool) or not isinstance(ev_cost, (int, float)):
        raise FormatFail(f"work_order ev_cost must be numeric: {row.get('id')}")
    created = row.get("created")
    if isinstance(created, bool) or not isinstance(created, int):
        raise FormatFail(f"work_order created must be int: {row.get('id')}")
    state = row.get("state", "ready")
    if not isinstance(state, str):
        raise FormatFail(f"work_order state must be str: {row.get('id')}")
    lane_id = payload.get("lane_id")
    return WorkOrderCandidate(
        id=_required_str(row, "id"),
        action=_required_str(row, "action"),
        unit=_required_str(row, "unit"),
        ev_cost=float(ev_cost),
        created=created,
        state=state,
        join_live=payload.get("join_live") is True,
        cas_bytes=cas_bytes,
        lane_id=lane_id if isinstance(lane_id, str) and lane_id else None,
        requires_lane=payload.get("requires_lane") is True,
    )


class Executor:
    """Cap gate for policy actions."""

    def __init__(self, caps: ExecutorCaps, *, spent_usd_micro: int = 0) -> None:
        self.caps = caps
        self.sync_spent(spent_usd_micro)
        self.corpus_rows = 0
        self.crashes = 0
        self.escalations = 0

    def sync_spent(self, spent_usd_micro: int) -> None:
        """Synchronize ledger-reported spend under the same integer bounds."""
        _validate_ledger_int("spent_usd_micro", spent_usd_micro)
        self.spent_usd_micro = spent_usd_micro

    def admits(self, action: Action) -> bool:
        """Return whether an action may execute under caps."""
        cost = ACTION_COST_USD_MICRO[action]
        if self.spent_usd_micro + cost > self.caps.spend_usd_micro:
            return False
        if action is Action.SPAWN_SUBFACTORY and self.corpus_rows >= self.caps.corpus_max:
            return False
        if action is Action.FORCE_GROOM and self.crashes >= self.caps.crashes_per_device:
            return False
        return not (action is Action.ESCALATE_MODEL and self.escalations >= self.caps.escalations)

    def gate(self, action: Action) -> None:
        """Raise BUDGET_GATE before any action side effect."""
        if self.admits(action):
            return
        cost = ACTION_COST_USD_MICRO[action]
        if self.spent_usd_micro + cost > self.caps.spend_usd_micro:
            reason = "spend_cap"
            cap = self.caps.spend_usd_micro
        elif action is Action.SPAWN_SUBFACTORY:
            reason = "corpus_cap"
            cap = self.caps.corpus_max
        elif action is Action.FORCE_GROOM:
            reason = "crash_cap"
            cap = self.caps.crashes_per_device
        else:
            reason = "escalation_cap"
            cap = self.caps.escalations
        raise BudgetGate(
            f"{reason}: action={action.value} spent={self.spent_usd_micro} "
            f"cost={cost} cap={cap}"
        )

    def reserve(self, action: Action) -> int:
        """Gate and atomically reserve one action's spend in memory."""
        self.gate(action)
        cost = ACTION_COST_USD_MICRO[action]
        self.spent_usd_micro += cost
        if action is Action.SPAWN_SUBFACTORY:
            self.corpus_rows += 1
        elif action is Action.FORCE_GROOM:
            self.crashes += 1
        elif action is Action.ESCALATE_MODEL:
            self.escalations += 1
        return cost

    def release(self, action: Action, cost: int) -> None:
        """Release a reservation after a failed or malformed handler result."""
        expected = ACTION_COST_USD_MICRO[action]
        if cost != expected:
            raise FormatFail("released spend must match action cost")
        if self.spent_usd_micro < cost:
            raise FormatFail("cannot release spend above reserved spend")
        if action is Action.SPAWN_SUBFACTORY and self.corpus_rows < 1:
            raise FormatFail("cannot release missing corpus reservation")
        if action is Action.FORCE_GROOM and self.crashes < 1:
            raise FormatFail("cannot release missing crash reservation")
        if action is Action.ESCALATE_MODEL and self.escalations < 1:
            raise FormatFail("cannot release missing escalation reservation")
        self.spent_usd_micro -= cost
        if action is Action.SPAWN_SUBFACTORY:
            self.corpus_rows -= 1
        elif action is Action.FORCE_GROOM:
            self.crashes -= 1
        elif action is Action.ESCALATE_MODEL:
            self.escalations -= 1

    def record_spend(self, action: Action) -> int:
        """Record one execution and return its Appendix D cost."""
        return self.reserve(action)


_DISPATCH_LOCKS: weakref.WeakKeyDictionary[Ledger, asyncio.Lock] = weakref.WeakKeyDictionary()


def _dispatch_lock(ledger: Ledger) -> asyncio.Lock:
    """Serialize dispatch ticks per ledger so reservations cannot race."""
    lock = _DISPATCH_LOCKS.get(ledger)
    if lock is None:
        lock = asyncio.Lock()
        _DISPATCH_LOCKS[ledger] = lock
    return lock


class PolicyEngine:
    """Budget-routing policy engine over the M0 claim ledger."""

    def __init__(
        self,
        ledger: Ledger,
        caps: ExecutorCaps,
        *,
        ev_provider: EVInputProvider | None = None,
        lane_provider: LaneStateProvider | None = None,
        handlers: Mapping[Action, ActionHandler] | None = None,
        tick_budget_ms: float = 5.0,
    ) -> None:
        if isinstance(tick_budget_ms, bool) or not math.isfinite(tick_budget_ms) or tick_budget_ms <= 0:
            raise FormatFail("tick_budget_ms must be finite and > 0")
        self.ledger = ledger
        self.caps = caps
        self.executor = Executor(caps, spent_usd_micro=ledger.spent_usd_micro())
        self.ev_provider = ev_provider or StaticEVInputProvider()
        self.lane_provider = lane_provider or StaticLaneStateProvider()
        self.handlers: dict[Action, ActionHandler] = dict(handlers or {})
        self.tick_budget_ms = tick_budget_ms
        self.backlog_limit = caps.backlog_limit
        self.cas_bytes_limit = caps.cas_bytes
        self._null_handler = NullActionHandler()

    async def inputs_for(self, action: Action, unit: str, *, run_id: str | None) -> EVInputs:
        """Fetch and validate EV inputs for an action."""
        inputs = await self.ev_provider.inputs_for(action=action, unit=unit, run_id=run_id)
        if not isinstance(inputs, EVInputs):
            raise FormatFail("EV provider must return EVInputs")
        inputs.validate()
        return inputs

    async def plan_action(
        self,
        action: str,
        unit: str,
        *,
        probability_join: float | None = None,
        chain_bonus: float = 1.0,
        ingress_weight: float = 1.0,
        lane_id: str | None = None,
        requires_lane: bool = False,
        join_live: bool = False,
        cas_bytes: int = 0,
        run_id: str | None = None,
        trigger_metric: str = "policy",
        observed: float = 0.0,
        expected: str = "",
    ) -> str:
        """Validate, EV-rank, and enqueue one work order."""
        if not isinstance(unit, str) or not unit:
            raise FormatFail("unit must be a non-empty string")
        if run_id is not None and (not isinstance(run_id, str) or not run_id):
            raise FormatFail("run_id must be a non-empty string when set")
        parsed = parse_action(action)
        if probability_join is None:
            inputs = await self.inputs_for(parsed, unit, run_id=run_id)
        else:
            inputs = EVInputs(
                probability_join=probability_join,
                chain_bonus=chain_bonus,
                ingress_weight=ingress_weight,
                lane_id=lane_id,
                requires_lane=requires_lane,
                join_live=join_live,
                cas_bytes=cas_bytes,
                trigger_metric=trigger_metric,
                observed=observed,
                expected=expected,
            )
            inputs.validate()
        failures = await self.unit_failure_count(unit)
        parked = failures >= 3 and parsed is not Action.PARK
        effective = Action.PARK if parked else parsed
        if parked:
            await self.park_unit(unit, reason="TRIPLE_FAILURE")
        cost = ACTION_COST_USD_MICRO[effective]
        ev = ev_score(inputs.probability_join, inputs.chain_bonus, inputs.ingress_weight, cost)
        if not math.isfinite(ev) or ev <= 0:
            raise FormatFail("work_order ev_cost must be finite and > 0")
        expected_value = inputs.expected or effective.value
        payload = {
            "probability_join": inputs.probability_join,
            "chain_bonus": inputs.chain_bonus,
            "ingress_weight": inputs.ingress_weight,
            "cost_usd_micro": cost,
            "lane_id": inputs.lane_id,
            "requires_lane": inputs.requires_lane,
            "join_live": inputs.join_live,
            "cas_bytes": inputs.cas_bytes,
            "trigger_metric": inputs.trigger_metric,
            "observed": inputs.observed,
            "expected": expected_value,
            "failure_count": failures,
        }
        return await self.ledger.enqueue_work_order(
            action=effective.value,
            unit=unit,
            ev_cost=ev,
            state="parked" if parked else "ready",
            run_id=run_id,
            payload_json=json.dumps(payload, sort_keys=True),
            decision={
                "run_id": run_id,
                "unit": unit,
                "trigger_metric": inputs.trigger_metric,
                "observed": inputs.observed,
                "expected": expected_value,
                "spent_usd_micro": 0,
            },
        )

    async def unit_failure_count(self, unit: str) -> int:
        """Return the persisted consecutive remedy-failure count for a unit."""
        count = 0
        for row in reversed(self.ledger.decision_rows(unit=unit, limit=1000)):
            trigger = str(row.get("trigger_metric", ""))
            if trigger == "remedy_failure":
                count += 1
            elif trigger == "remedy_success":
                break
        return count

    async def record_failure(
        self, unit: str, *, run_id: str | None = None, wo_id: str | None = None
    ) -> int:
        """Persist one failed remedy; three consecutive failures park the unit."""
        count = await self.unit_failure_count(unit) + 1
        await self.ledger.record_decision(
            trigger_metric="remedy_failure",
            observed=float(count),
            expected="remedy_success",
            spent_usd_micro=0,
            run_id=run_id,
            wo_id=wo_id,
            unit=unit,
        )
        if count >= 3:
            await self.park_unit(unit, reason="TRIPLE_FAILURE")
        return count

    async def record_success(
        self, unit: str, *, run_id: str | None = None, wo_id: str | None = None
    ) -> None:
        """Persist a successful remedy and reset the failure streak."""
        await self.ledger.record_decision(
            trigger_metric="remedy_success",
            observed=1.0,
            expected="remedy_success",
            spent_usd_micro=0,
            run_id=run_id,
            wo_id=wo_id,
            unit=unit,
        )

    async def park_unit(self, unit: str, *, reason: str = "policy") -> int:
        """Park every ready work order for a unit; return rows changed."""
        operations: list[LedgerOperation] = []
        for row in self.ledger.work_orders_for_unit(unit):
            if str(row.get("state")) != "ready":
                continue
            payload = _row_payload(row)
            payload["park_reason"] = reason
            operations.append(
                LedgerOperation(
                    "shed_work_order",
                    {
                        "work_order_id": str(row["id"]),
                        "state": "parked",
                        "payload_json": json.dumps(payload, sort_keys=True),
                    },
                    rows=1,
                )
            )
        if not operations:
            return 0
        results = await self.ledger.submit_batch(operations)
        return sum(1 for result in results if result is True)

    async def dispatch_ready(self, *, limit: int = 64) -> tuple[int, list[str]]:
        """Compatibility wrapper around one dispatch tick."""
        report = await self.dispatch_tick(limit=limit)
        return report.dispatched, list(report.refusals)

    async def dispatch_tick(self, *, limit: int = 64) -> DispatchReport:
        """Run one bounded dispatch tick and report budget/tick telemetry."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise FormatFail("dispatch limit must be an int >= 0")
        async with _dispatch_lock(self.ledger):
            return await self._dispatch_tick_locked(limit=limit)

    async def _dispatch_tick_locked(self, *, limit: int) -> DispatchReport:
        """Dispatch body executed under the per-ledger tick lock."""
        self.executor.sync_spent(self.ledger.spent_usd_micro())
        start = time.perf_counter()
        shed_count = await self.shed_backlog()
        dispatched = 0
        refusals: list[str] = []
        requeued: list[str] = []
        operations: list[LedgerOperation] = []
        success_reserved: list[tuple[Action, int]] = []
        failure_counts: dict[str, int] = {}
        park_after: set[str] = set()
        for row in self.ledger.ready_work_orders(limit=limit):
            wo_id = str(row.get("id"))
            unit = str(row.get("unit"))
            run_id = _cast_str(row.get("run_id"))
            payload: dict[str, Any] = {}
            reserved_cost: int | None = None
            ev_cost = 0.0
            try:
                wo_id = _required_str(row, "id")
                unit = _required_str(row, "unit")
                if run_id is not None and not run_id:
                    raise FormatFail("work_order run_id must be non-empty when set")
                raw_ev_cost = row.get("ev_cost")
                if isinstance(raw_ev_cost, bool) or not isinstance(raw_ev_cost, (int, float)):
                    raise FormatFail("work_order ev_cost must be numeric")
                ev_cost = float(raw_ev_cost)
                if not math.isfinite(ev_cost) or ev_cost < 0.0:
                    raise FormatFail("work_order ev_cost must be finite and >= 0")
                action = parse_action(_required_str(row, "action"))
                payload = _row_payload(row)
                inputs = self._inputs_from_payload(row, payload) if payload else _EMPTY_EV_INPUTS
                lane_state = (
                    await self._lane_state(inputs)
                    if inputs.requires_lane and inputs.lane_id is not None
                    else None
                )
                if lane_state is not None and lane_state.busy:
                    operations.append(self._requeue_operation(row, lane_state, payload))
                    requeued.append(wo_id)
                    continue
                reserved_cost = self.executor.reserve(action)
            except BudgetGate as exc:
                operations.extend(self._budget_refusal_operations(row, str(exc), payload))
                refusals.append(wo_id)
                continue
            except FormatFail as exc:
                operations.append(self._format_fail_operation(row, str(exc)))
                refusals.append(wo_id)
                continue
            assert reserved_cost is not None
            try:
                result = await self._run_handler(action, row, payload)
            except BaseException:
                self.executor.release(action, reserved_cost)
                raise
            cost = reserved_cost
            observed = float(result.observed)
            expected = result.expected or inputs.expected or action.value
            detail = result.detail or ("handler failure" if result.outcome is ActionOutcome.FAILURE else "ok")
            if result.outcome is ActionOutcome.FAILURE:
                self.executor.release(action, reserved_cost)
                state = "failed"
                spent_usd_micro = 0
                trigger_metric = "remedy_failure"
                count = await self._failure_count_for_tick(unit, failure_counts) + 1
                failure_counts[unit] = count
                if count >= 3:
                    park_after.add(unit)
            else:
                state = "done"
                spent_usd_micro = cost
                trigger_metric = "dispatch" if action is Action.PARK else "remedy_success"
                if action is not Action.PARK:
                    failure_counts[unit] = 0
                dispatched += 1
            payload["last_detail"] = detail
            operations.append(
                LedgerOperation(
                    "settle_work_order",
                    {
                        "work_order_id": wo_id,
                        "state": state,
                        "payload_json": json.dumps(payload, sort_keys=True),
                        "decision": {
                            "run_id": run_id,
                            "unit": unit,
                            "trigger_metric": trigger_metric,
                            "observed": observed,
                            "expected": expected,
                            "spent_usd_micro": spent_usd_micro,
                            "created": now_ms(),
                        },
                    },
                    rows=2,
                )
            )
            if state == "done":
                success_reserved.append((action, cost))
        if operations:
            try:
                await self.ledger.submit_batch(operations)
            except BaseException:
                for reserved_action, reserved in success_reserved:
                    self.executor.release(reserved_action, reserved)
                success_reserved.clear()
                raise
        for unit in sorted(park_after):
            await self.park_unit(unit, reason="TRIPLE_FAILURE")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return DispatchReport(
            dispatched=dispatched,
            refusals=tuple(refusals),
            requeued=tuple(requeued),
            shed=shed_count,
            tick_ms=elapsed_ms,
            within_budget=elapsed_ms <= self.tick_budget_ms,
        )

    def rank_candidates(
        self, candidates: Sequence[WorkOrderCandidate]
    ) -> list[WorkOrderCandidate]:
        """Rank work-order candidates by policy EV."""
        return rank(list(candidates))

    def shed_candidates(
        self,
        candidates: Sequence[WorkOrderCandidate],
        *,
        backlog_limit: int = 5000,
        cas_bytes_limit: int | None = None,
    ) -> tuple[list[WorkOrderCandidate], list[WorkOrderCandidate]]:
        """Pure shedding pass for load tests and callers."""
        return shed_budget(
            list(candidates),
            backlog_limit=backlog_limit,
            cas_bytes_limit=self.cas_bytes_limit if cas_bytes_limit is None else cas_bytes_limit,
        )

    async def shed_backlog(self) -> int:
        """Persist CAS/backlog shedding for ready work; return dropped count."""
        count, cas_bytes = self.ledger.ready_work_order_budget()
        if count <= self.backlog_limit and cas_bytes <= self.cas_bytes_limit:
            return 0
        rows = self.ledger.ready_work_orders(limit=max(count, 1))
        candidates: list[WorkOrderCandidate] = []
        malformed_ids: set[str] = set()
        for row in rows:
            try:
                candidates.append(_candidate_from_row(row))
            except FormatFail:
                try:
                    malformed_ids.add(_required_str(row, "id"))
                except FormatFail:
                    continue
        operations: list[LedgerOperation] = []
        malformed_payload = json.dumps({"shed_reason": "malformed_work_order"}, sort_keys=True)
        for wo_id in sorted(malformed_ids):
            operations.append(
                LedgerOperation(
                    "shed_work_order",
                    {
                        "work_order_id": wo_id,
                        "state": "shed",
                        "payload_json": malformed_payload,
                    },
                    rows=1,
                )
            )
        kept_ids: set[str] = set()
        if candidates:
            kept, _dropped = shed_budget(
                candidates,
                backlog_limit=self.backlog_limit,
                cas_bytes_limit=self.cas_bytes_limit,
            )
            kept_ids = {candidate.id for candidate in kept}
        candidate_ids = {candidate.id for candidate in candidates}
        for row in rows:
            try:
                wo_id = _required_str(row, "id")
            except FormatFail:
                continue
            if wo_id in malformed_ids or wo_id in kept_ids or wo_id not in candidate_ids:
                continue
            payload = _row_payload(row)
            payload["shed_reason"] = "backlog_budget"
            operations.append(
                LedgerOperation(
                    "shed_work_order",
                    {
                        "work_order_id": wo_id,
                        "state": "shed",
                        "payload_json": json.dumps(payload, sort_keys=True),
                    },
                    rows=1,
                )
            )
        if not operations:
            return 0
        results = await self.ledger.submit_batch(operations)
        return sum(1 for result in results if result is True)

    async def _run_handler(
        self, action: Action, row: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> ActionResult:
        handler = self.handlers.get(action, self._null_handler)
        order = dict(row)
        order["payload"] = payload
        try:
            result = await handler(order)
            result.validate()
            return result
        except Exception as exc:  # noqa: BLE001 - dispatch must isolate handler faults
            return ActionResult(
                outcome=ActionOutcome.FAILURE,
                observed=_finite(row.get("ev_cost"), 0.0),
                expected=action.value,
                detail=f"{type(exc).__name__}: {exc}",
            )

    async def _failure_count_for_tick(
        self, unit: str, counts: dict[str, int]
    ) -> int:
        if unit not in counts:
            counts[unit] = await self.unit_failure_count(unit)
        return counts[unit]

    def _requeue_operation(
        self,
        row: Mapping[str, Any],
        lane_state: LaneAvailability,
        payload: dict[str, Any],
    ) -> LedgerOperation:
        payload["requeue_count"] = _payload_int(payload, "requeue_count", 0) + 1
        payload["last_lane_id"] = lane_state.lane_id
        payload["last_lane_reason"] = lane_state.reason or "busy"
        payload["last_requeue_at_ms"] = time.time_ns() // 1_000_000
        return LedgerOperation(
            "shed_work_order",
            {
                "work_order_id": str(row["id"]),
                "state": "ready",
                "payload_json": json.dumps(payload, sort_keys=True),
            },
            rows=1,
        )

    def _budget_refusal_operations(
        self, row: Mapping[str, Any], detail: str, payload: dict[str, Any]
    ) -> list[LedgerOperation]:
        payload["last_budget_gate"] = detail
        created = now_ms()
        return [
            LedgerOperation(
                "record_decision",
                {
                    "run_id": _cast_str(row.get("run_id")),
                    "wo_id": str(row["id"]),
                    "unit": str(row["unit"]),
                    "trigger_metric": "budget_gate",
                    "observed": float(row["ev_cost"]),
                    "expected": "BUDGET_GATE",
                    "spent_usd_micro": 0,
                    "created": created,
                },
                rows=1,
            ),
            LedgerOperation(
                "shed_work_order",
                {
                    "work_order_id": str(row["id"]),
                    "state": "ready",
                    "payload_json": json.dumps(payload, sort_keys=True),
                },
                rows=1,
            ),
        ]

    def _format_fail_operation(self, row: Mapping[str, Any], detail: str) -> LedgerOperation:
        return LedgerOperation(
            "settle_work_order",
            {
                "work_order_id": str(row["id"]),
                "state": "failed",
                "payload_json": None,
                "decision": {
                    "run_id": _cast_str(row.get("run_id")),
                    "unit": str(row["unit"]),
                    "trigger_metric": "format_fail",
                    "observed": _finite(row.get("ev_cost"), 0.0),
                    "expected": "FORMAT_FAIL",
                    "spent_usd_micro": 0,
                    "created": now_ms(),
                },
            },
            rows=2,
        )

    def _inputs_from_payload(
        self, row: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> EVInputs:
        try:
            inputs = EVInputs(
                probability_join=_payload_float(payload, "probability_join", 0.0),
                chain_bonus=_payload_float(payload, "chain_bonus", 1.0),
                ingress_weight=_payload_float(payload, "ingress_weight", 1.0),
                lane_id=(
                    payload["lane_id"]
                    if isinstance(payload.get("lane_id"), str) and payload.get("lane_id")
                    else None
                ),
                requires_lane=payload.get("requires_lane") is True,
                join_live=payload.get("join_live") is True,
                cas_bytes=_payload_int(payload, "cas_bytes", 0),
                trigger_metric=_payload_str(payload, "trigger_metric", "dispatch"),
                observed=_payload_float(payload, "observed", 0.0),
                expected=_payload_str(payload, "expected", str(row.get("action", ""))),
            )
        except FormatFail as exc:
            raise FormatFail(f"work_order payload inputs invalid: {row.get('id')}") from exc
        inputs.validate()
        return inputs

    async def _lane_state(self, inputs: EVInputs) -> LaneAvailability | None:
        if not inputs.requires_lane or inputs.lane_id is None:
            return None
        try:
            state = await self.lane_provider.availability(inputs.lane_id)
        except Exception as exc:  # noqa: BLE001 - lane faults must not crash dispatch
            raise FormatFail(f"lane provider failed: {exc}") from exc
        if not isinstance(state, LaneAvailability):
            raise FormatFail("lane provider must return LaneAvailability")
        state.validate()
        return state


def candidates_from_rows(rows: Sequence[Mapping[str, Any]]) -> list[WorkOrderCandidate]:
    """Convert ledger rows to rankable candidates."""
    return [_candidate_from_row(row) for row in rows]
