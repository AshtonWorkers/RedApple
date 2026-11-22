"""ImageIO/HEIF discovery campaign orchestration."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Sequence
from typing import Any, Protocol, cast

from ..errors import FormatFail, NotProvisioned
from .models import (
    CampaignConfig,
    CampaignResult,
    CampaignState,
    CrashRefLike,
    MutationCase,
    now_ms,
)
from .mutate import MutationEngine
from .store import LedgerDiscoveryStore

_FATAL_CODES = frozenset(
    {
        "ARM_BLOCKED",
        "BUDGET_EXHAUSTED",
        "BUDGET_GATE",
        "CAS_CORRUPT",
        "DEVICE_LOST",
        "DIALECT_DEFECT",
        "FORMAT_FAIL",
        "HARNESS_REJECTED",
        "INVARIANT_BREACH",
        "NOT_PROVISIONED",
        "OUT_OF_RING",
        "THERMAL_DRAIN",
    }
)


class DiscoveryLane(Protocol):
    """Lane protocol consumed by discovery without importing ``ra.lanes``."""

    name: str

    async def provision(self, profile: Any) -> Any: ...

    async def assert_ready(self) -> None: ...

    async def launch(self, target: str, harness: Any) -> Any: ...

    async def feed(self, handle: Any, data: bytes) -> Any: ...

    async def collect_crashes(self, handle: Any) -> Sequence[CrashRefLike]: ...

    async def thermal(self) -> Any: ...

    async def reset(self, handle: Any) -> None: ...

    async def teardown(self) -> None: ...


class DiscoveryCampaign:
    """Run a deterministic mutation campaign through a lane and ledger store."""

    def __init__(self, store: LedgerDiscoveryStore, *, monotonic: Any = time.monotonic) -> None:
        self._store = store
        self._monotonic = monotonic

    async def run(
        self,
        lane: DiscoveryLane,
        profile: Any,
        harness: Any,
        corpus: Sequence[bytes],
        config: CampaignConfig | None = None,
    ) -> CampaignResult:
        """Run or resume ``config.campaign_id`` over ``corpus``."""
        cfg = config or CampaignConfig()
        try:
            cfg.validate()
        except ValueError as exc:
            raise FormatFail(str(exc)) from exc
        if harness is None:
            harness = cfg.harness_ref()
        engine = MutationEngine(corpus, seed=cfg.seed, max_input_bytes=cfg.max_input_bytes)
        state = await self._load_or_create_state(cfg, engine.seed_count)
        if state.status == "completed" and state.next_case_index >= cfg.max_cases:
            return CampaignResult(state=state, crashes=[], cases=[])

        crashes: list[CrashRefLike] = []
        fed_cases: list[MutationCase] = []
        handle: Any | None = None
        started = float(self._monotonic())

        await self._store.save(state)
        try:
            await self._prepare_lane(lane, profile)
            handle = await lane.launch(cfg.target, harness)
            cases_on_handle = 0
            for index in range(state.next_case_index, cfg.max_cases):
                if self._budget_exceeded(cfg, started):
                    state.status = "paused"
                    state.last_error = {"reason": "time_budget"}
                    break
                if index and index % cfg.thermal_check_every == 0:
                    thermal_name = _thermal_name(await lane.thermal())
                    if thermal_name != "nominal":
                        state.status = "paused"
                        state.last_error = {"reason": "thermal", "thermal": thermal_name}
                        break

                case = engine.plan(index, cfg.campaign_id)
                case_crashes, case_error, feed_name = await self._feed_and_collect(
                    lane, handle, case
                )
                if feed_name is not None:
                    self._count_feed(state, feed_name)
                if case_error is not None and not case_crashes:
                    state.consecutive_errors += 1
                    state.last_error = _error_payload(case_error)
                    state.next_case_index = index + 1
                    state.last_case_index = index
                    state.updated_ms = now_ms()
                    if self._fatal(case_error) or state.consecutive_errors >= cfg.max_consecutive_errors:
                        state.status = "failed"
                        state.finished_ms = now_ms()
                        await self._store.save(state)
                        raise case_error
                    handle = await self._cycle_handle(lane, handle, cfg.target, harness)
                    cases_on_handle = 0
                    await self._checkpoint(state, cfg)
                    continue

                await self._record_crashes(state, crashes, case=case, refs=case_crashes)
                state.cases_fed += 1
                if case.gate_pass:
                    state.gate_passes += 1
                state.next_case_index = index + 1
                state.last_case_index = index
                state.consecutive_errors = 0
                state.last_error = None
                state.updated_ms = now_ms()
                fed_cases.append(case)
                cases_on_handle += 1

                if case_crashes or cases_on_handle >= cfg.max_cases_per_handle:
                    handle = await self._cycle_handle(lane, handle, cfg.target, harness)
                    cases_on_handle = 0
                await self._checkpoint(state, cfg)
        except Exception as exc:
            state.status = "failed"
            state.last_error = _error_payload(exc)
            state.finished_ms = now_ms()
            state.updated_ms = now_ms()
            await self._store.save(state)
            raise

        if state.status == "running":
            state.status = "completed" if state.next_case_index >= cfg.max_cases else "paused"
            if state.status == "completed":
                state.finished_ms = now_ms()
            state.updated_ms = now_ms()
        await self._store.save(state)
        return CampaignResult(state=state, crashes=crashes, cases=fed_cases)

    async def _load_or_create_state(self, cfg: CampaignConfig, seed_count: int) -> CampaignState:
        state = await self._store.load(cfg.campaign_id)
        if state is None:
            return CampaignState(
                campaign_id=cfg.campaign_id,
                surface=cfg.surface,
                format=cfg.format,
                status="running",
                config=cfg.to_dict(),
                seed_count=seed_count,
                cases_planned=cfg.max_cases,
                created_ms=now_ms(),
                updated_ms=now_ms(),
            )
        if state.config != cfg.to_dict():
            raise FormatFail("campaign config does not match persisted state")
        if state.status == "completed" and state.next_case_index >= cfg.max_cases:
            return state
        state.status = "running"
        state.updated_ms = now_ms()
        return state

    @staticmethod
    async def _prepare_lane(lane: DiscoveryLane, profile: Any) -> None:
        if profile is not None:
            result = await lane.provision(profile)
            if not getattr(result, "ready", True):
                raise NotProvisioned("lane provision returned not ready")
        await lane.assert_ready()

    def _budget_exceeded(self, cfg: CampaignConfig, started: float) -> bool:
        return cfg.time_budget_s is not None and (float(self._monotonic()) - started) > cfg.time_budget_s

    @staticmethod
    async def _feed_and_collect(
        lane: DiscoveryLane,
        handle: Any,
        case: MutationCase,
    ) -> tuple[list[CrashRefLike], Exception | None, str | None]:
        refs: list[CrashRefLike] = []
        try:
            result = await lane.feed(handle, case.data)
            feed_name = _feed_result_name(result)
        except Exception as exc:
            ref = _crash_ref_from_exception(exc)
            if ref is not None:
                refs.append(ref)
                with contextlib.suppress(Exception):
                    refs.extend(await lane.collect_crashes(handle))
            return refs, exc, None
        try:
            refs.extend(await lane.collect_crashes(handle))
        except Exception as exc:
            return refs, exc, feed_name
        return refs, None, feed_name

    @staticmethod
    def _count_feed(state: CampaignState, feed_name: str) -> None:
        if feed_name == "ACCEPTED":
            state.feeds_accepted += 1
        elif feed_name == "SATURATED":
            state.feeds_saturated += 1
        else:
            state.feeds_rejected += 1

    async def _record_crashes(
        self,
        state: CampaignState,
        out: list[CrashRefLike],
        *,
        case: MutationCase,
        refs: Sequence[CrashRefLike],
    ) -> None:
        for ref in refs:
            state.crashes_seen += 1
            record = await self._store.record_crash(
                campaign_id=case.campaign_id,
                case_id=case.case_id,
                crash=ref,
                input_digest=case.digest,
                strategy=case.strategy,
                seed_index=case.seed_index,
                case_index=case.index,
                created_ms=state.updated_ms,
            )
            if record.claim_id is None:
                state.crashes_deduped += 1
            else:
                state.crashes_recorded += 1
                state.last_crash_claim_id = record.claim_id
            out.append(ref)

    async def _cycle_handle(self, lane: DiscoveryLane, handle: Any, target: str, harness: Any) -> Any:
        with contextlib.suppress(Exception):
            await lane.collect_crashes(handle)
        await lane.reset(handle)
        return await lane.launch(target, harness)

    async def _checkpoint(self, state: CampaignState, cfg: CampaignConfig) -> None:
        if state.next_case_index % cfg.state_checkpoint_every == 0:
            await self._store.save(state)

    @staticmethod
    def _fatal(exc: Exception) -> bool:
        code = getattr(exc, "code", None)
        if code is not None and str(code) in _FATAL_CODES:
            return True
        return getattr(exc, "retryable", None) is False


def _feed_result_name(result: Any) -> str:
    value = getattr(result, "value", result)
    if not isinstance(value, str):
        value = str(value)
    return value.upper()


def _thermal_name(thermal: Any) -> str:
    value = getattr(thermal, "value", thermal)
    if not isinstance(value, str):
        value = str(value)
    return value.lower()


def _error_payload(exc: Exception) -> dict[str, Any]:
    code = getattr(exc, "code", None)
    return {
        "type": type(exc).__name__,
        "message": str(exc)[:500],
        "code": None if code is None else str(code),
    }


def _crash_ref_from_exception(exc: Exception) -> CrashRefLike | None:
    ref = getattr(exc, "crash_ref", None)
    if ref is None:
        return None
    if all(hasattr(ref, name) for name in ("id", "kind", "payload")):
        return cast(CrashRefLike, ref)
    return None
