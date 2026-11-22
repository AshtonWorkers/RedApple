"""Campaign memory service over the M0 claim ledger (RA-MEM)."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, cast

from ..errors import AdapterShipBlocked, FormatFail
from ..ledger import Ledger
from ..ledger.ids import now_ms, sha256_hex
from ..press.golden import GoldenCase, check_golden
from ..press.packets import Packet, PacketCompiler
from ..press.routing import TaskType
from .models import (
    ADAPTER_STATES,
    GLOBAL_SURFACE,
    MEMORY_META_KEY,
    PRIOR_KINDS,
    MemoryAdapter,
    MemoryPrior,
    PreferencePair,
    RetrievalContext,
    SlaStatus,
    _json_dict,
)

_LEARNABLE_CLAIM_TYPES = {
    "root_cause": "root_cause",
    "bug_class": "bug_class",
    "gadget_set": "gadget_set",
    "join": "join",
    "groom": "groom",
}
_MAX_JSON_BYTES = 1_000_000
_MAX_CLAIM_VALUE_BYTES = 262_144
_MAX_SURFACE_CHARS = 512
_MAX_PROMPT_CHARS = 100_000
_MAX_TEXT_CHARS = 10_000
_MAX_ID_CHARS = 256
_MAX_KEY_CHARS = 256
_MAX_CONTRIBUTORS = 128
_MAX_LIMIT = 1_000
_MAX_PAIRS = 1_000
_INT64_MAX = (1 << 63) - 1
_SLA_MAX_FUTURE_MS = 5 * 60 * 1000
_MEMORY_LOCK_ATTR = "_ra_memory_write_lock"


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{field} must be a number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise FormatFail(f"{field} must be finite") from exc
    if not math.isfinite(number):
        raise FormatFail(f"{field} must be finite")
    return number


def _strict01(value: object, field: str) -> float:
    number = _finite_number(value, field)
    if not 0.0 <= number <= 1.0:
        raise FormatFail(f"{field} must be in [0,1]")
    return number


def _require_int(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"{field} must be int")
    if value < minimum or value > _INT64_MAX:
        raise FormatFail(f"{field} is out of range")
    return value


def _validate_limit(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"{field} must be int")
    if value < 0 or value > _MAX_LIMIT:
        raise FormatFail(f"{field} is out of range")
    return value


def _bounded_text(value: object, field: str, *, max_chars: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise FormatFail(f"{field} must be str")
    text = value.strip()
    if not text and not allow_empty:
        raise FormatFail(f"{field} must be non-empty")
    if len(text) > max_chars:
        raise FormatFail(f"{field} exceeds {max_chars} chars")
    return text


def _optional_text(value: object, field: str, *, max_chars: int = _MAX_ID_CHARS) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, field, max_chars=max_chars, allow_empty=True) or None


def _require_id(value: object, field: str) -> str:
    return _bounded_text(value, field, max_chars=_MAX_ID_CHARS)


def _task_type(value: TaskType | str) -> str:
    try:
        return TaskType(value).value
    except (TypeError, ValueError) as exc:
        raise FormatFail("task_type is invalid") from exc


def _optional_task_type(value: TaskType | str | None) -> str | None:
    return None if value is None else _task_type(value)


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_json_bounded(
    value: Mapping[str, Any], field: str, *, max_bytes: int = _MAX_JSON_BYTES
) -> str:
    try:
        text = _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise FormatFail(f"{field} must be JSON serializable") from exc
    if len(text.encode("utf-8")) > max_bytes:
        raise FormatFail(f"{field} exceeds {max_bytes} bytes")
    return text


def _validated_mapping(value: object, field: str, *, max_bytes: int = _MAX_JSON_BYTES) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatFail(f"{field} must be an object")
    data = cast(dict[str, Any], dict(value))
    _canonical_json_bounded(data, field, max_bytes=max_bytes)
    return data


def _short_hash(material: str) -> str:
    return sha256_hex(material.encode("utf-8"))[:32]


def _bounded_key(text: str) -> str:
    if len(text) <= _MAX_KEY_CHARS:
        return text
    return text[:128] + "~" + _short_hash(text)


def _rank_key(contributor: Mapping[str, Any]) -> tuple[float, float, int, str]:
    return (
        float(contributor["score"]),
        float(contributor["confidence"]),
        int(contributor["created"]),
        str(contributor["id"]),
    )


def _contributors_from_value(value: Mapping[str, Any]) -> list[dict[str, Any]]:
    meta = value.get(MEMORY_META_KEY)
    if meta is None:
        return []
    if not isinstance(meta, Mapping):
        raise FormatFail("memory prior metadata is malformed")
    raw = meta.get("contributors")
    if not isinstance(raw, list):
        raise FormatFail("memory prior contributors are malformed")
    contributors: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise FormatFail("memory prior contributor is malformed")
        contributors.append(
            {
                "id": _require_id(item.get("id"), "prior contributor id"),
                "score": _strict01(item.get("score"), "prior contributor score"),
                "confidence": _strict01(item.get("confidence"), "prior contributor confidence"),
                "created": _require_int(item.get("created"), "prior contributor created"),
                "sha": _optional_text(item.get("sha"), "prior contributor sha", max_chars=64) or "",
                "artifact": _optional_text(item.get("artifact"), "prior contributor artifact"),
            }
        )
    return contributors


def _public_prior_value(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != MEMORY_META_KEY}


class _LockStore:
    def __init__(self) -> None:
        self.write = asyncio.Lock()


def _lock_store(ledger: Ledger) -> _LockStore:
    store = getattr(ledger, _MEMORY_LOCK_ATTR, None)
    if not isinstance(store, _LockStore):
        store = _LockStore()
        setattr(ledger, _MEMORY_LOCK_ATTR, store)
    return store


class AdapterTrainer(Protocol):
    """Interface for the not-yet-built LoRA trainer."""

    def train(
        self,
        task_type: str,
        surface: str,
        pairs: Sequence[PreferencePair],
        *,
        parent: MemoryAdapter | None,
    ) -> Mapping[str, Any]:
        """Return config for one candidate adapter."""
        ...  # pragma: no cover


class StubAdapterTrainer:
    """Deterministic no-op trainer used until a real LoRA trainer lands."""

    def train(
        self,
        task_type: str,
        surface: str,
        pairs: Sequence[PreferencePair],
        *,
        parent: MemoryAdapter | None,
    ) -> Mapping[str, Any]:
        del pairs
        return {
            "stub": True,
            "task_type": task_type,
            "surface": surface,
            "parent_id": None if parent is None else parent.id,
            "rank": 8,
            "note": "LoRA trainer is stubbed; config is lifecycle metadata only.",
        }


class CampaignMemory:
    """Persistent campaign memory: priors, preferences, adapters, SLA, telemetry."""

    def __init__(self, ledger: Ledger, *, trainer: AdapterTrainer | None = None) -> None:
        self._ledger = ledger
        self._trainer = trainer or StubAdapterTrainer()
        self._write_lock = _lock_store(ledger).write

    # -- learning ---------------------------------------------------------

    async def learn_from_claim(
        self,
        claim: Mapping[str, Any],
        *,
        source_artifact: str | None = None,
        include_reviewed: bool = False,
    ) -> list[MemoryPrior]:
        """Learn priors from promoted (optionally reviewed) ledger claims.

        The ledger claim row is authoritative; caller-supplied copies cannot
        change state, type, value, confidence, dedup key, or creation time.
        Re-learning the same claim is idempotent and does not bump revision.
        """
        claim_id = self._claim_id_from(claim)
        artifact = _optional_text(source_artifact, "source_artifact")
        async with self._write_lock:
            stored = self._ledger.get_claim(claim_id)
            if stored is None:
                raise FormatFail("memory claim does not exist")
            return await self._learn_claim_row(
                stored, source_artifact=artifact, include_reviewed=include_reviewed
            )

    @staticmethod
    def _claim_id_from(claim: Mapping[str, Any]) -> str:
        raw = claim.get("id") or claim.get("claim_id")
        if not isinstance(raw, str) or not raw:
            raise FormatFail("claim id is required")
        return _require_id(raw, "claim id")

    async def _learn_claim_row(
        self,
        claim: Mapping[str, Any],
        *,
        source_artifact: str | None,
        include_reviewed: bool,
    ) -> list[MemoryPrior]:
        claim_id = str(claim["id"])
        state = str(claim.get("state", ""))
        if state != "promoted" and not (include_reviewed and state == "reviewed"):
            return []
        claim_type = str(claim.get("type", ""))
        kind = _LEARNABLE_CLAIM_TYPES.get(claim_type)
        if kind is None or kind not in PRIOR_KINDS:
            return []
        value = _validated_mapping(
            self._claim_value(claim), "claim value", max_bytes=_MAX_CLAIM_VALUE_BYTES
        )
        value = {key: item for key, item in value.items() if key != MEMORY_META_KEY}
        surface = _bounded_text(
            self._surface_for(value), "prior surface", max_chars=_MAX_SURFACE_CHARS
        )
        key = self._prior_key(value, claim, claim_id)
        claim_confidence = _strict01(claim.get("confidence"), "claim confidence")
        score = _strict01(value["score"], "prior score") if "score" in value else claim_confidence
        confidence = (
            _strict01(value["confidence"], "prior confidence")
            if "confidence" in value
            else claim_confidence
        )
        claim_created = _require_int(claim.get("created"), "claim created")
        public = dict(value)
        public.update(
            {
                "claim_id": claim_id,
                "dedup_key": claim.get("dedup_key"),
                "learned_from": "claim",
            }
        )
        candidate_sha = _short_hash(_canonical_json_bounded(public, "prior payload"))
        existing = self._ledger.memory_prior_by_key(kind, surface, key)
        if existing is not None and str(existing.get("state")) == "retired":
            return []
        existing_value = {} if existing is None else _json_dict(existing.get("value_json", "{}"))
        contributors = [] if existing is None else _contributors_from_value(existing_value)
        base_support = 0 if existing is None else _require_int(existing.get("support"), "prior support")
        if existing is not None and not contributors:
            legacy_claim = existing.get("source_claim")
            if isinstance(legacy_claim, str) and legacy_claim:
                contributors = [
                    {
                        "id": _require_id(legacy_claim, "prior contributor id"),
                        "score": _strict01(existing.get("score"), "prior score"),
                        "confidence": _strict01(existing.get("confidence"), "prior confidence"),
                        "created": _require_int(existing.get("created"), "prior created"),
                        "sha": "",
                        "artifact": _optional_text(existing.get("source_artifact"), "source_artifact"),
                    }
                ]
        existing_contributor = next(
            (item for item in contributors if str(item["id"]) == claim_id), None
        )
        if existing_contributor is not None:
            old_sha = str(existing_contributor.get("sha") or "")
            if old_sha and old_sha != candidate_sha:
                raise FormatFail("conflicting memory claim payload")
        else:
            contributors.append(
                {
                    "id": claim_id,
                    "score": score,
                    "confidence": confidence,
                    "created": claim_created,
                    "sha": candidate_sha,
                    "artifact": source_artifact,
                }
            )
        contributors = sorted(contributors, key=_rank_key, reverse=True)[:_MAX_CONTRIBUTORS]
        winner = max(contributors, key=_rank_key)
        winner_id = str(winner["id"])
        existing_winner = ""
        if existing is not None:
            existing_public = _public_prior_value(existing_value)
            raw_winner = existing_public.get("claim_id") or existing.get("source_claim") or ""
            existing_winner = str(raw_winner)
        desired_support = max(base_support, len(contributors))
        candidates_changed = (
            existing_contributor is None and any(str(item["id"]) == claim_id for item in contributors)
        )
        no_op = (
            existing is not None
            and not candidates_changed
            and winner_id == existing_winner
            and desired_support == base_support
        )
        if no_op:
            assert existing is not None
            return [MemoryPrior.from_row(existing)]
        winner_public = public if winner_id == claim_id else _public_prior_value(existing_value)
        learned_value = dict(winner_public)
        learned_value[MEMORY_META_KEY] = {"contributors": contributors}
        _canonical_json_bounded(learned_value, "memory prior value")
        existing_score = 0.0 if existing is None else _strict01(existing.get("score"), "prior score")
        aggregate_confidence = max(float(item["confidence"]) for item in contributors)
        row = await self._ledger.upsert_memory_prior(
            kind=kind,
            surface=surface,
            key=key,
            value=learned_value,
            score=max(existing_score, float(winner["score"])),
            support=desired_support - base_support,
            confidence=aggregate_confidence,
            source_claim=winner_id,
            source_artifact=winner.get("artifact"),
            prior_id="mem_" + _short_hash(f"{kind}|{surface}|{key}"),
            created=claim_created or None,
        )
        return [MemoryPrior.from_row(row)]

    @staticmethod
    def _claim_value(claim: Mapping[str, Any]) -> dict[str, Any]:
        if "value" in claim and isinstance(claim.get("value"), Mapping):
            return dict(claim["value"])
        raw = claim.get("value_json", "{}")
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise FormatFail("claim value_json is not JSON") from exc
        else:
            parsed = raw
        if isinstance(parsed, Mapping):
            return dict(parsed)
        return {"value": parsed}

    @staticmethod
    def _surface_for(value: Mapping[str, Any]) -> str:
        for field in ("surface", "ring_node", "target"):
            raw = value.get(field)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
        return GLOBAL_SURFACE

    @staticmethod
    def _prior_key(value: Mapping[str, Any], claim: Mapping[str, Any], claim_id: str) -> str:
        for field in ("prior_key", "key", "dedup_key", "bug_class", "root_cause"):
            raw = value.get(field)
            if isinstance(raw, str) and raw.strip():
                return _bounded_key(raw.strip())
        dedup = claim.get("dedup_key")
        if isinstance(dedup, str) and dedup.strip():
            return _bounded_key(dedup.strip())
        return _bounded_key(claim_id)

    # -- preferences and adapters ----------------------------------------

    async def record_preference_pair(
        self,
        *,
        task_type: TaskType | str,
        surface: str,
        prompt: str,
        chosen: Mapping[str, Any],
        rejected: Mapping[str, Any],
        reward: float,
        rationale: str | None = None,
        source_claim: str | None = None,
        source_artifact: str | None = None,
    ) -> PreferencePair:
        """Record one chosen/rejected pair idempotently for adapter training."""
        tt = _task_type(task_type)
        surface_text = _bounded_text(surface, "preference surface", max_chars=_MAX_SURFACE_CHARS)
        prompt_text = _bounded_text(prompt, "preference prompt", max_chars=_MAX_PROMPT_CHARS)
        chosen_data = _validated_mapping(chosen, "preference chosen")
        rejected_data = _validated_mapping(rejected, "preference rejected")
        reward_value = _strict01(reward, "preference reward")
        rationale_text = _optional_text(rationale, "preference rationale", max_chars=_MAX_TEXT_CHARS)
        source_claim_text = _optional_text(source_claim, "source_claim")
        source_artifact_text = _optional_text(source_artifact, "source_artifact")
        if source_claim_text is not None and self._ledger.get_claim(source_claim_text) is None:
            raise FormatFail("preference source_claim does not exist")
        prompt_sha = sha256_hex(prompt_text.encode("utf-8"))
        pair_id = "pref_" + _short_hash(
            "|".join(
                [
                    tt,
                    surface_text,
                    prompt_sha,
                    _canonical_json_bounded(chosen_data, "preference chosen"),
                    _canonical_json_bounded(rejected_data, "preference rejected"),
                    f"{reward_value:.6f}",
                    "" if rationale_text is None else rationale_text,
                    "" if source_claim_text is None else source_claim_text,
                ]
            )
        )
        result = await self._ledger.ensure_memory_preference(
            pair_id=pair_id,
            task_type=tt,
            surface=surface_text,
            prompt_sha=prompt_sha,
            chosen=chosen_data,
            rejected=rejected_data,
            reward=reward_value,
            rationale=rationale_text,
            source_claim=source_claim_text,
            source_artifact=source_artifact_text,
        )
        return PreferencePair.from_row(result["row"])

    def preference_pairs(
        self,
        *,
        task_type: TaskType | str | None = None,
        surface: str | None = None,
        surfaces: Sequence[str] | None = None,
        limit: int = 1000,
    ) -> list[PreferencePair]:
        """List preference pairs by reward."""
        tt = _optional_task_type(task_type)
        surface_text = None if surface is None else _bounded_text(surface, "surface", max_chars=_MAX_SURFACE_CHARS)
        surface_list = None
        if surfaces is not None:
            if len(surfaces) > _MAX_LIMIT:
                raise FormatFail("surfaces is out of range")
            surface_list = [
                _bounded_text(item, "surface", max_chars=_MAX_SURFACE_CHARS) for item in surfaces
            ]
        rows = self._ledger.memory_preferences(
            task_type=tt,
            surface=surface_text,
            surfaces=surface_list,
            limit=_validate_limit(limit, "limit"),
        )
        return [PreferencePair.from_row(row) for row in rows]

    @staticmethod
    def _canonical_pair_ids(pair_ids: Sequence[str]) -> list[str]:
        if isinstance(pair_ids, (str, bytes)):
            raise FormatFail("adapter pair_ids must be a sequence of ids")
        ids = [_require_id(pair_id, "preference pair id") for pair_id in pair_ids]
        if not ids or len(ids) > _MAX_PAIRS:
            raise FormatFail("adapter requires between 1 and 1000 preference pairs")
        return sorted(set(ids))

    async def propose_adapter(
        self,
        task_type: TaskType | str,
        surface: str,
        *,
        pair_ids: Sequence[str] | None = None,
        max_pairs: int = 50,
        parent_id: str | None = None,
        salt: str | None = None,
        source_artifact: str | None = None,
    ) -> MemoryAdapter:
        """Create or reuse a candidate adapter from preference pairs."""
        tt = _task_type(task_type)
        surface_text = _bounded_text(surface, "adapter surface", max_chars=_MAX_SURFACE_CHARS)
        parent_text = _optional_text(parent_id, "parent_id")
        salt_text = _optional_text(salt, "salt", max_chars=1024)
        artifact_text = _optional_text(source_artifact, "source_artifact")
        explicit = None if pair_ids is None else self._canonical_pair_ids(pair_ids)
        async with self._write_lock:
            if pair_ids is None:
                pair_limit = _validate_limit(max_pairs, "max_pairs")
                if pair_limit < 1:
                    raise FormatFail("max_pairs must be >= 1")
                train_pairs = self._select_pairs(tt, surface_text, limit=pair_limit)
                selected = [pair.id for pair in train_pairs]
            else:
                assert explicit is not None
                selected = explicit
                train_pairs = self._pairs_for_ids(selected)
            self._validate_pair_scope(tt, surface_text, train_pairs)
            parent = None if parent_text is None else self._adapter_or_raise(parent_text)
            if parent is not None and (parent.task_type != tt or parent.surface != surface_text):
                raise FormatFail("adapter parent is outside the adapter scope")
            config = _validated_mapping(
                self._trainer.train(tt, surface_text, train_pairs, parent=parent),
                "adapter config",
            )
            config_json = _canonical_json_bounded(config, "adapter config")
            material = "|".join(
                [tt, surface_text, "" if parent_text is None else parent_text, config_json, ",".join(selected)]
            )
            if salt_text is not None:
                material += "|" + salt_text
            adapter_id = "mem_" + _short_hash(material)
            existing = self._ledger.memory_adapter_row(adapter_id)
            if existing is not None:
                return MemoryAdapter.from_row(existing)
            row = await self._ledger.create_memory_adapter(
                adapter_id=adapter_id,
                task_type=tt,
                surface=surface_text,
                pair_ids=selected,
                config=config,
                parent_id=parent_text,
                source_artifact=artifact_text,
            )
            return MemoryAdapter.from_row(row)

    @staticmethod
    def _validate_pair_scope(
        task_type: str, surface: str, pairs: Sequence[PreferencePair]
    ) -> None:
        allowed = {surface, GLOBAL_SURFACE}
        for pair in pairs:
            if pair.task_type != task_type or pair.surface not in allowed:
                raise FormatFail("preference pair is outside adapter scope")

    async def evaluate_adapter(
        self,
        adapter_id: str,
        cases: Sequence[GoldenCase],
        responder: Callable[[GoldenCase], Mapping[str, Any]],
        *,
        baseline: float | None = None,
    ) -> MemoryAdapter:
        """Evaluate one adapter on the golden set and record the gate result."""
        adapter_key = _require_id(adapter_id, "adapter id")
        baseline_value = None if baseline is None else _strict01(baseline, "baseline")
        async with self._write_lock:
            adapter = self._adapter_or_raise(adapter_key)
            if adapter.state not in {"candidate", "evaluated"}:
                raise FormatFail(f"memory adapter cannot be evaluated from state {adapter.state}")
            if baseline_value is None:
                active = self._ledger.memory_active_adapter(adapter.task_type, adapter.surface)
                baseline_value = (
                    None if active is None else _strict01(active.get("eval_score"), "baseline")
                )
            report = check_golden(list(cases), responder, baseline=baseline_value)
            blocked = None if report.passed else "golden_gate_failed"
            if report.drop is not None:
                blocked = blocked or f"golden_drop={report.drop:.6f}"
            row = await self._ledger.evaluate_memory_adapter(
                adapter_key,
                eval_score=report.score,
                golden_rows=report.rows,
                golden_passed=report.passed,
                baseline_score=baseline_value,
                ship_blocked_reason=blocked,
            )
            return MemoryAdapter.from_row(row)

    async def ship_adapter(self, adapter_id: str) -> MemoryAdapter:
        """Ship an evaluated adapter; golden failures raise ``AdapterShipBlocked``."""
        adapter_key = _require_id(adapter_id, "adapter id")
        async with self._write_lock:
            adapter = self._adapter_or_raise(adapter_key)
            if adapter.state == "shipped":
                return adapter
            if adapter.state != "evaluated":
                raise AdapterShipBlocked(f"adapter {adapter_key} is {adapter.state}, not evaluated")
            if adapter.golden_passed is not True or adapter.eval_score is None:
                reason = adapter.ship_blocked_reason or "golden_gate_failed"
                raise AdapterShipBlocked(f"adapter {adapter_key} is not shippable: {reason}")
            result = await self._ledger.ship_memory_adapter(adapter_key)
            return MemoryAdapter.from_row(result["row"])

    async def reject_adapter(self, adapter_id: str) -> bool:
        """Reject a candidate/evaluated adapter."""
        adapter_key = _require_id(adapter_id, "adapter id")
        async with self._write_lock:
            adapter = self._adapter_or_raise(adapter_key)
            if adapter.state == "rejected":
                return False
            if adapter.state not in {"candidate", "evaluated"}:
                raise FormatFail(f"memory adapter cannot be rejected from state {adapter.state}")
            return await self._ledger.set_memory_adapter_state(adapter_key, "rejected")

    async def retire_adapter(self, adapter_id: str) -> bool:
        """Retire an adapter without deleting its audit trail."""
        adapter_key = _require_id(adapter_id, "adapter id")
        async with self._write_lock:
            adapter = self._adapter_or_raise(adapter_key)
            if adapter.state == "retired":
                return False
            return await self._ledger.set_memory_adapter_state(adapter_key, "retired")

    def adapter(self, adapter_id: str) -> MemoryAdapter | None:
        row = self._ledger.memory_adapter_row(_require_id(adapter_id, "adapter id"))
        return None if row is None else MemoryAdapter.from_row(row)

    def active_adapter(self, task_type: TaskType | str, surface: str) -> MemoryAdapter | None:
        tt = _task_type(task_type)
        surface_text = _bounded_text(surface, "surface", max_chars=_MAX_SURFACE_CHARS)
        row = self._ledger.memory_active_adapter(tt, surface_text)
        return None if row is None else MemoryAdapter.from_row(row)

    def adapters(
        self,
        *,
        task_type: TaskType | str | None = None,
        surface: str | None = None,
        state: str | None = None,
        limit: int = 1000,
    ) -> list[MemoryAdapter]:
        tt = _optional_task_type(task_type)
        surface_text = None if surface is None else _bounded_text(surface, "surface", max_chars=_MAX_SURFACE_CHARS)
        if state is not None and state not in ADAPTER_STATES:
            raise FormatFail("adapter state is invalid")
        rows = self._ledger.memory_adapters(
            task_type=tt,
            surface=surface_text,
            state=state,
            limit=_validate_limit(limit, "limit"),
        )
        return [MemoryAdapter.from_row(row) for row in rows]

    def _adapter_or_raise(self, adapter_id: str) -> MemoryAdapter:
        adapter = self.adapter(adapter_id)
        if adapter is None:
            raise FormatFail(f"memory adapter does not exist: {adapter_id}")
        return adapter

    def _select_pairs(self, task_type: str, surface: str, *, limit: int) -> list[PreferencePair]:
        surfaces = [surface] if surface == GLOBAL_SURFACE else [surface, GLOBAL_SURFACE]
        rows = self._ledger.memory_preferences(task_type=task_type, surfaces=surfaces, limit=limit * 2)
        return [PreferencePair.from_row(row) for row in rows[:limit]]

    def _pairs_for_ids(self, pair_ids: Sequence[str]) -> list[PreferencePair]:
        pairs: list[PreferencePair] = []
        for pair_id in pair_ids:
            pair_key = _require_id(pair_id, "preference pair id")
            row = self._ledger.memory_preference_row(pair_key)
            if row is None:
                raise FormatFail(f"unknown preference pair: {pair_key}")
            pairs.append(PreferencePair.from_row(row))
        return pairs

    # -- retrieval ---------------------------------------------------------

    def _select_memory(
        self,
        surface: str,
        task_type: str | None,
        *,
        kinds: Sequence[str] | None = None,
        limit: int = 5,
        pair_limit: int = 3,
    ) -> tuple[list[MemoryPrior], list[PreferencePair], MemoryAdapter | None]:
        limit_value = _validate_limit(limit, "limit")
        pair_limit_value = _validate_limit(pair_limit, "pair_limit")
        kind_list = None if kinds is None else list(kinds)
        if kind_list is not None:
            for kind in kind_list:
                if kind not in PRIOR_KINDS:
                    raise FormatFail("memory prior kind is invalid")
        surface_text = _bounded_text(surface, "retrieval surface", max_chars=_MAX_SURFACE_CHARS)
        rows = (
            []
            if limit_value == 0
            else self._ledger.memory_priors(surface_text, state="active", include_global=True, limit=limit_value)
        )
        priors: list[MemoryPrior] = []
        for row in rows:
            prior = MemoryPrior.from_row(row)
            if kind_list is not None and prior.kind not in kind_list:
                continue
            priors.append(prior)
            if len(priors) >= limit_value:
                break
        pairs: list[PreferencePair] = []
        if task_type is not None and pair_limit_value > 0:
            surfaces = [surface_text] if surface_text == GLOBAL_SURFACE else [surface_text, GLOBAL_SURFACE]
            pair_rows = self._ledger.memory_preferences(
                task_type=task_type, surfaces=surfaces, limit=pair_limit_value * 2
            )
            pairs = [PreferencePair.from_row(row) for row in pair_rows[:pair_limit_value]]
        adapter = None if task_type is None else self.active_adapter(task_type, surface_text)
        return priors, pairs, adapter

    async def retrieve(
        self,
        surface: str,
        task_type: TaskType | str | None = None,
        *,
        kinds: Sequence[str] | None = None,
        limit: int = 5,
        pair_limit: int = 3,
        run_id: str | None = None,
        packet_sha: str | None = None,
    ) -> RetrievalContext:
        """Retrieve ranked priors/pairs/adapter and record citation telemetry."""
        tt = _optional_task_type(task_type)
        run_id_text = _optional_text(run_id, "run_id")
        packet_sha_text = _optional_text(packet_sha, "packet_sha", max_chars=128)
        priors, pairs, adapter = self._select_memory(
            surface, tt, kinds=kinds, limit=limit, pair_limit=pair_limit
        )
        retrieval_id = await self._record_selection(
            surface=surface.strip(),
            task_type=tt,
            priors=priors,
            pairs=pairs,
            adapter=adapter,
            run_id=run_id_text,
            packet_sha=packet_sha_text,
        )
        return RetrievalContext(
            surface=surface.strip(),
            task_type=tt,
            priors=tuple(priors),
            pairs=tuple(pairs),
            adapter=adapter,
            packet_sha=packet_sha_text,
            retrieval_id=retrieval_id,
        )

    async def _record_selection(
        self,
        *,
        surface: str,
        task_type: str | None,
        priors: Sequence[MemoryPrior],
        pairs: Sequence[PreferencePair],
        adapter: MemoryAdapter | None,
        run_id: str | None,
        packet_sha: str | None,
    ) -> str:
        return await self._ledger.record_memory_retrieval(
            surface=surface,
            prior_ids=[prior.id for prior in priors],
            pair_ids=[pair.id for pair in pairs],
            run_id=run_id,
            task_type=task_type,
            packet_sha=packet_sha,
            adapter_id=None if adapter is None else adapter.id,
        )

    @staticmethod
    def memory_context_text(context: RetrievalContext) -> str:
        """Render retrieval citations for a PRESS packet exemplar."""
        lines: list[str] = []
        for prior in context.priors:
            citation = prior.source_claim or prior.source_artifact or "ledger"
            value = _canonical_json(prior.value)
            if len(value) > 240:
                value = value[:237] + "..."
            lines.append(
                f"[prior {prior.id} {prior.kind}/{prior.surface} "
                f"score={prior.score:.3f} support={prior.support} cite={citation}] "
                f"{prior.key}: {value}"
            )
        for pair in context.pairs:
            lines.append(
                f"[pref {pair.id} reward={pair.reward:.3f} cite={pair.source_claim or 'ledger'}] "
                f"chosen={_canonical_json(pair.chosen)} rejected={_canonical_json(pair.rejected)}"
            )
        if context.adapter is not None:
            lines.append(
                f"[adapter {context.adapter.id} v{context.adapter.version} "
                f"state={context.adapter.state} eval={context.adapter.eval_score}]"
            )
        return "\n".join(lines)

    async def press_packet(
        self,
        task_type: TaskType | str,
        goal: str,
        *,
        surface: str,
        artifacts: tuple[str, ...] = (),
        vocab: tuple[str, ...] = (),
        exemplar: str = "",
        near_miss: str = "",
        run_id: str | None = None,
        compiler: PacketCompiler | None = None,
        kinds: Sequence[str] | None = None,
        limit: int = 5,
        pair_limit: int = 3,
    ) -> tuple[Packet, RetrievalContext]:
        """Build a PRESS packet enriched with cited campaign memory."""
        tt = TaskType(_task_type(task_type))
        run_id_text = _optional_text(run_id, "run_id")
        priors, pairs, adapter = self._select_memory(
            surface, tt.value, kinds=kinds, limit=limit, pair_limit=pair_limit
        )
        context_without_id = RetrievalContext(
            surface=surface.strip(),
            task_type=tt.value,
            priors=tuple(priors),
            pairs=tuple(pairs),
            adapter=adapter,
            packet_sha=None,
            retrieval_id="",
        )
        memory_text = self.memory_context_text(context_without_id)
        packet = Packet(
            tt,
            goal,
            artifacts,
            vocab,
            exemplar if exemplar else memory_text,
            near_miss,
        )
        packet_sha = None
        if compiler is not None:
            packet_sha = compiler.compile(packet).sha
        retrieval_id = await self._record_selection(
            surface=surface.strip(),
            task_type=tt.value,
            priors=priors,
            pairs=pairs,
            adapter=adapter,
            run_id=run_id_text,
            packet_sha=packet_sha,
        )
        context = RetrievalContext(
            surface=surface.strip(),
            task_type=tt.value,
            priors=tuple(priors),
            pairs=tuple(pairs),
            adapter=adapter,
            packet_sha=packet_sha,
            retrieval_id=retrieval_id,
        )
        return packet, context

    # -- SLA and relevance telemetry ---------------------------------------

    async def record_cost_to_first_valid_poc(
        self,
        surface: str,
        *,
        cost_micro: int,
        target_cost_micro: int | None = None,
        created: int | None = None,
    ) -> SlaStatus:
        """Record one cost observation; target is immutable once set."""
        surface_text = _bounded_text(surface, "SLA surface", max_chars=_MAX_SURFACE_CHARS)
        cost = _require_int(cost_micro, "cost_micro")
        target = None if target_cost_micro is None else _require_int(target_cost_micro, "target_cost_micro")
        at = now_ms() if created is None else _require_int(created, "created")
        if at > now_ms() + _SLA_MAX_FUTURE_MS:
            raise FormatFail("SLA created is too far in the future")
        async with self._write_lock:
            existing = self._ledger.memory_sla_row(surface_text)
            if target is None:
                if existing is None:
                    raise FormatFail("target_cost_micro is required for a new SLA")
                target = _require_int(existing.get("target_cost_micro"), "target_cost_micro")
            elif existing is not None:
                current_target = _require_int(existing.get("target_cost_micro"), "target_cost_micro")
                if current_target != target:
                    raise FormatFail("memory SLA target is immutable")
            if existing is not None:
                last_updated = _require_int(existing.get("updated"), "SLA updated")
                if at < last_updated:
                    raise FormatFail("SLA created must be non-decreasing")
            row = await self._ledger.record_memory_sla(
                surface_text,
                target_cost_micro=target,
                cost_micro=cost,
                created=at,
            )
            return SlaStatus.from_row(row)

    def sla_status(self, surface: str) -> SlaStatus | None:
        surface_text = _bounded_text(surface, "SLA surface", max_chars=_MAX_SURFACE_CHARS)
        row = self._ledger.memory_sla_row(surface_text)
        return None if row is None else SlaStatus.from_row(row)

    def sla_statuses(self, *, limit: int = 1000) -> list[SlaStatus]:
        return [SlaStatus.from_row(row) for row in self._ledger.memory_sla_rows(limit=_validate_limit(limit, "limit"))]

    def sla_events(self, surface: str, *, limit: int = 100) -> list[dict[str, Any]]:
        surface_text = _bounded_text(surface, "SLA surface", max_chars=_MAX_SURFACE_CHARS)
        return self._ledger.memory_sla_events(surface_text, limit=_validate_limit(limit, "limit"))

    def sla_violations(self, *, limit: int = 1000) -> list[SlaStatus]:
        return [status for status in self.sla_statuses(limit=limit) if status.flagged]

    async def record_relevance(
        self,
        relevance: float,
        *,
        retrieval_id: str | None = None,
        packet_sha: str | None = None,
    ) -> int:
        """Record citation/retrieval relevance for one packet."""
        relevance_value = _strict01(relevance, "relevance")
        retrieval_id_text = _optional_text(retrieval_id, "retrieval_id")
        packet_sha_text = _optional_text(packet_sha, "packet_sha", max_chars=128)
        if retrieval_id_text is None and packet_sha_text is None:
            raise FormatFail("relevance requires retrieval_id or packet_sha")
        return await self._ledger.record_memory_retrieval_relevance(
            relevance=relevance_value, retrieval_id=retrieval_id_text, packet_sha=packet_sha_text
        )

    # -- reporting -----------------------------------------------------------

    def prior(self, prior_id: str) -> MemoryPrior | None:
        row = self._ledger.memory_prior_row(_require_id(prior_id, "prior id"))
        return None if row is None else MemoryPrior.from_row(row)

    def priors(
        self,
        surface: str | None = None,
        *,
        kind: str | None = None,
        state: str = "active",
        include_global: bool = True,
        limit: int = 1000,
    ) -> list[MemoryPrior]:
        if kind is not None and kind not in PRIOR_KINDS:
            raise FormatFail("memory prior kind is invalid")
        if state not in {"active", "retired"}:
            raise FormatFail("memory prior state is invalid")
        surface_text = None if surface is None else _bounded_text(surface, "surface", max_chars=_MAX_SURFACE_CHARS)
        rows = self._ledger.memory_priors(
            surface_text,
            kind=kind,
            state=state,
            include_global=include_global,
            limit=_validate_limit(limit, "limit"),
        )
        return [MemoryPrior.from_row(row) for row in rows]

    async def retire_prior(self, prior_id: str) -> bool:
        """Retire one prior without deleting its audit trail."""
        prior_key = _require_id(prior_id, "prior id")
        async with self._write_lock:
            if self._ledger.memory_prior_row(prior_key) is None:
                raise FormatFail(f"memory prior does not exist: {prior_key}")
            return await self._ledger.retire_memory_prior(prior_key)

    def retrievals(
        self,
        *,
        surface: str | None = None,
        task_type: TaskType | str | None = None,
        packet_sha: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        tt = _optional_task_type(task_type)
        surface_text = None if surface is None else _bounded_text(surface, "surface", max_chars=_MAX_SURFACE_CHARS)
        packet_sha_text = _optional_text(packet_sha, "packet_sha", max_chars=128)
        return self._ledger.memory_retrievals(
            surface=surface_text,
            task_type=tt,
            packet_sha=packet_sha_text,
            limit=_validate_limit(limit, "limit"),
        )

    def memory_report(self) -> dict[str, int]:
        """Counts for memory tables from the ledger."""
        counts = self._ledger.counts()
        return {
            "priors": counts.get("memory_prior", 0),
            "preferences": counts.get("memory_preference", 0),
            "adapters": counts.get("memory_adapter", 0),
            "adapter_pairs": counts.get("memory_adapter_pair", 0),
            "slas": counts.get("memory_sla", 0),
            "sla_events": counts.get("memory_sla_event", 0),
            "retrievals": counts.get("memory_retrieval", 0),
        }


__all__ = ["AdapterTrainer", "CampaignMemory", "StubAdapterTrainer"]
