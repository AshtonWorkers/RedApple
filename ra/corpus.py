"""Coverage-guided corpus scheduler for discovery lanes.

State is stored only in the M0 ledger: one parked ``work_order`` row per corpus
slot, with the bounded seed payload in ``payload_json``. No side store is used.
"""

from __future__ import annotations

import json
import math
import random
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from .errors import FormatFail
from .ledger import Ledger
from .ledger.ids import now_ms

STORE_KIND = "ra.corpus.scheduler.v1"
WORK_ORDER_ACTION = "park"
WORK_ORDER_STATE = "parked"
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_INT = 2**53 - 1
_MAX_WEIGHT = 1_000_000.0


@dataclass(frozen=True)
class SeedEnergyPolicy:
    """Finite, non-negative energy weights for the power schedule."""

    base_energy: float = 1.0
    novelty_weight: float = 2.0
    rarity_weight: float = 1.0
    new_edge_weight: float = 0.25
    execution_decay: float = 0.10
    new_edge_cap: int = 64

    def __post_init__(self) -> None:
        for name in (
            "base_energy",
            "novelty_weight",
            "rarity_weight",
            "new_edge_weight",
            "execution_decay",
        ):
            _require_finite_float(getattr(self, name), name, minimum=0.0, maximum=_MAX_WEIGHT)
        if (
            isinstance(self.new_edge_cap, bool)
            or not isinstance(self.new_edge_cap, int)
            or not 1 <= self.new_edge_cap <= 1_000_000
        ):
            raise FormatFail("new_edge_cap must be an integer in [1, 1000000]")

    def energy(
        self, *, covered_edges: int, last_new_edges: int, runs: int, rarity: float
    ) -> float:
        """Return finite non-negative energy for one seed."""
        covered = _require_int(covered_edges, "covered_edges")
        last_new = _require_int(last_new_edges, "last_new_edges")
        run_count = _require_int(runs, "runs")
        rare = _require_finite_float(rarity, "rarity", minimum=0.0, maximum=1.0)
        denominator = max(1, covered, last_new)
        novelty = min(1.0, last_new / denominator)
        freshness = 1.0 / (1.0 + self.execution_decay * run_count)
        boost = min(last_new, self.new_edge_cap) / self.new_edge_cap
        value = (
            self.base_energy
            * (1.0 + self.novelty_weight * novelty + self.rarity_weight * rare)
            * freshness
        ) + self.new_edge_weight * boost
        return float(value)


@dataclass(frozen=True)
class CorpusSeedSpec:
    """Registration input for one corpus seed."""

    seed_id: str
    lane: str
    edges: Iterable[str] = ()
    target: str | None = None
    artifact_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CorpusSeedView:
    """Ledger-backed view of one active seed with computed telemetry."""

    seed_id: str
    lane: str
    slot: int
    edges: tuple[str, ...]
    runs: int
    covered_edges: int
    new_edges: int
    last_new_edges: int
    rarity: float
    energy: float
    created: int
    updated: int
    last_seen: int
    last_run_id: str | None = None
    target: str | None = None
    artifact_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CorpusMinimizationResult:
    """Outcome of one corpus minimization pass."""

    dropped: tuple[str, ...]
    kept: tuple[str, ...]
    freed_slots: int
    changed: bool


@dataclass
class _SeedState:
    seed_id: str
    lane: str
    edges: tuple[str, ...]
    runs: int
    new_edges: int
    last_new_edges: int
    created: int
    updated: int
    last_seen: int
    target: str | None = None
    artifact_id: str | None = None
    last_run_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed_id": self.seed_id,
            "lane": self.lane,
            "target": self.target,
            "artifact_id": self.artifact_id,
            "metadata": dict(self.metadata),
            "edges": list(self.edges),
            "runs": self.runs,
            "new_edges": self.new_edges,
            "last_new_edges": self.last_new_edges,
            "last_run_id": self.last_run_id,
            "last_seen": self.last_seen,
            "created": self.created,
            "updated": self.updated,
            "status": "active",
        }


@dataclass
class _Slot:
    slot: int
    row_id: str | None
    state: _SeedState | None


class CorpusScheduler:
    """Bounded, deterministic, ledger-backed corpus scheduler."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        namespace: str = "default",
        max_corpus_size: int = 512,
        max_edges_per_seed: int = 512,
        max_total_edges: int = 262_144,
        policy: SeedEnergyPolicy | None = None,
    ) -> None:
        if not isinstance(namespace, str) or not _NAMESPACE_RE.fullmatch(namespace):
            raise FormatFail("namespace must match [A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
        self._ledger = ledger
        self._namespace = namespace
        self._unit = f"ra.corpus.{namespace}"
        self._max_corpus_size = _require_int(
            max_corpus_size, "max_corpus_size", minimum=1, maximum=4096
        )
        self._max_edges_per_seed = _require_int(
            max_edges_per_seed, "max_edges_per_seed", minimum=1, maximum=4096
        )
        self._max_total_edges = _require_int(
            max_total_edges, "max_total_edges", minimum=1, maximum=1_000_000
        )
        self._policy = SeedEnergyPolicy() if policy is None else policy
        if not isinstance(self._policy, SeedEnergyPolicy):
            raise FormatFail("policy must be a SeedEnergyPolicy")

    async def register_seed(self, spec: CorpusSeedSpec, *, created: int | None = None) -> str:
        """Create or refresh one seed, bounded by the corpus slot budget."""
        when = _timestamp(created)
        seed_id = _require_str(spec.seed_id, "seed_id")
        lane = _require_str(spec.lane, "lane")
        target = _optional_str(spec.target, "target")
        artifact_id = _optional_str(spec.artifact_id, "artifact_id", max_length=256)
        edges = _validate_edges(spec.edges, max_edges=self._max_edges_per_seed)
        metadata = _validate_metadata(spec.metadata, max_bytes=8192)

        slots = self._load_slots()
        found = self._find_active(slots, seed_id)
        if found is not None:
            slot, state = found
            merged = tuple(sorted(set(state.edges) | set(edges)))
            if len(merged) > self._max_edges_per_seed:
                raise FormatFail("seed edge set exceeds max_edges_per_seed")
            edge_delta = len(merged) - len(state.edges)
            self._check_edge_budget(slots, edge_delta)
            frequencies = self._edge_frequencies(slots)
            old_edges = set(state.edges)
            added = [edge for edge in edges if edge not in old_edges]
            last_new = sum(1 for edge in added if frequencies.get(edge, 0) == 0)
            state.edges = merged
            state.lane = lane
            state.target = target
            state.artifact_id = artifact_id
            state.metadata = metadata
            state.updated = when
            if added:
                state.last_new_edges = last_new
                state.new_edges = _require_int(state.new_edges + last_new, "new_edges")
            else:
                state.last_new_edges = 0
            await self._save_slot(slot, created=when)
            return seed_id

        slot = self._allocate_slot(slots)
        frequencies = self._edge_frequencies(slots)
        initial_new = sum(1 for edge in edges if frequencies.get(edge, 0) == 0)
        self._check_edge_budget(slots, len(edges))
        state = _SeedState(
            seed_id=seed_id,
            lane=lane,
            edges=edges,
            runs=0,
            new_edges=initial_new,
            last_new_edges=initial_new,
            last_seen=when,
            created=when,
            updated=when,
            target=target,
            artifact_id=artifact_id,
            metadata=metadata,
        )
        slot.state = state
        await self._save_slot(slot, created=when)
        return seed_id

    async def record_coverage(
        self,
        seed_id: str,
        covered_edges: Iterable[str],
        *,
        run_id: str | None = None,
        created: int | None = None,
    ) -> CorpusSeedView:
        """Merge one coverage report into a seed and update novelty telemetry."""
        when = _timestamp(created)
        seed = _require_str(seed_id, "seed_id")
        run = _optional_str(run_id, "run_id", max_length=256)
        edges = _validate_edges(covered_edges, max_edges=self._max_edges_per_seed)
        slots = self._load_slots()
        found = self._find_active(slots, seed)
        if found is None:
            raise FormatFail(f"unknown corpus seed: {seed}")
        slot, state = found
        frequencies = self._edge_frequencies(slots)
        last_new = sum(1 for edge in edges if frequencies.get(edge, 0) == 0)
        merged = tuple(sorted(set(state.edges) | set(edges)))
        if len(merged) > self._max_edges_per_seed:
            raise FormatFail("seed edge set exceeds max_edges_per_seed")
        edge_delta = len(merged) - len(state.edges)
        self._check_edge_budget(slots, edge_delta)
        state.edges = merged
        state.runs = _require_int(state.runs + 1, "runs")
        state.new_edges = _require_int(state.new_edges + last_new, "new_edges")
        state.last_new_edges = last_new
        state.last_run_id = run
        state.last_seen = when
        state.updated = when
        await self._save_slot(slot, created=when)
        frequencies = self._edge_frequencies(slots)
        return self._view(slot, state, frequencies)

    async def minimize(self, *, created: int | None = None) -> CorpusMinimizationResult:
        """Drop seeds dominated by a superset-covering seed with no less energy."""
        when = _timestamp(created)
        slots = self._load_slots()
        active = self._active_slots(slots)
        if len(active) < 2:
            kept = tuple(sorted(state.seed_id for _, state in active))
            return CorpusMinimizationResult((), kept, 0, False)
        frequencies = self._edge_frequencies(slots)
        views = {
            state.seed_id: self._view(slot, state, frequencies) for slot, state in active
        }
        edge_sets = {state.seed_id: frozenset(state.edges) for _, state in active}
        dominated: set[str] = set()
        for _, candidate in active:
            candidate_edges = edge_sets[candidate.seed_id]
            candidate_view = views[candidate.seed_id]
            for _, other in active:
                if other.seed_id == candidate.seed_id:
                    continue
                if not edge_sets[other.seed_id].issuperset(candidate_edges):
                    continue
                other_view = views[other.seed_id]
                if other_view.energy > candidate_view.energy or (
                    other_view.energy == candidate_view.energy
                    and other_view.seed_id < candidate_view.seed_id
                ):
                    dominated.add(candidate.seed_id)
                    break
        if not dominated:
            kept = tuple(sorted(state.seed_id for _, state in active))
            return CorpusMinimizationResult((), kept, 0, False)
        for slot, state in active:
            if state.seed_id in dominated:
                slot.state = None
                await self._save_slot(slot, created=when)
        kept = tuple(
            sorted(state.seed_id for _, state in active if state.seed_id not in dominated)
        )
        return CorpusMinimizationResult(
            tuple(sorted(dominated)), kept, len(dominated), True
        )

    def active_seeds(self, *, lane: str | None = None) -> list[CorpusSeedView]:
        """Return active seeds in deterministic energy order."""
        wanted = _optional_str(lane, "lane") if lane is not None else None
        slots = self._load_slots()
        frequencies = self._edge_frequencies(slots)
        views = [
            self._view(slot, state, frequencies)
            for slot, state in self._active_slots(slots)
            if wanted is None or state.lane == wanted
        ]
        return sorted(views, key=lambda view: (-view.energy, view.seed_id))

    def next_batch(
        self,
        *,
        lane: str | None = None,
        batch_size: int = 32,
        schedule_seed: int = 0,
        exclude: Iterable[str] = (),
    ) -> list[CorpusSeedView]:
        """Return a deterministic energy-weighted batch for one discovery lane."""
        size = _require_int(
            batch_size, "batch_size", minimum=1, maximum=self._max_corpus_size
        )
        seed = _require_int(schedule_seed, "schedule_seed")
        excluded = _validate_seed_ids(exclude, "exclude")
        candidates = [
            view
            for view in self.active_seeds(lane=lane)
            if view.seed_id not in excluded
        ]
        if not candidates:
            return []
        remaining = list(candidates)
        total = sum(view.energy for view in remaining)
        if not math.isfinite(total) or total <= 0.0:
            return remaining[:size]
        rng = random.Random(seed)
        chosen: list[CorpusSeedView] = []
        for _ in range(min(size, len(remaining))):
            threshold = rng.random() * total
            cumulative = 0.0
            selected = len(remaining) - 1
            for index, view in enumerate(remaining):
                cumulative += view.energy
                if cumulative > threshold:
                    selected = index
                    break
            view = remaining.pop(selected)
            total = max(0.0, total - view.energy)
            chosen.append(view)
        return chosen

    def stats(self) -> dict[str, int]:
        """Return bounded corpus occupancy counters."""
        slots = self._load_slots()
        active = self._active_slots(slots)
        return {
            "slots": len(slots),
            "active": len(active),
            "empty": len(slots) - len(active),
            "total_edges": sum(len(state.edges) for _, state in active),
            "max_corpus_size": self._max_corpus_size,
            "max_total_edges": self._max_total_edges,
        }

    def _load_slots(self) -> dict[int, _Slot]:
        rows = self._ledger.work_orders_for_unit(self._unit)
        slots: dict[int, _Slot] = {}
        for row in rows:
            payload_json = row.get("payload_json")
            if not isinstance(payload_json, str):
                raise FormatFail("corpus work order payload_json must be str")
            try:
                payload_obj = json.loads(payload_json)
            except json.JSONDecodeError as exc:
                raise FormatFail("corpus work order payload is not JSON") from exc
            if not isinstance(payload_obj, dict):
                raise FormatFail("corpus work order payload must be an object")
            payload = cast(dict[str, Any], payload_obj)
            if payload.get("store") != STORE_KIND or payload.get("namespace") != self._namespace:
                raise FormatFail("corpus work order namespace mismatch")
            slot_index = _require_int(payload.get("slot"), "slot", maximum=self._max_corpus_size - 1)
            if slot_index in slots:
                raise FormatFail("duplicate corpus slot")
            if "seed" not in payload:
                raise FormatFail("corpus payload missing seed")
            seed_obj = payload["seed"]
            state = (
                None
                if seed_obj is None
                else _seed_state_from_dict(
                    seed_obj, max_edges=self._max_edges_per_seed
                )
            )
            slots[slot_index] = _Slot(
                slot=slot_index,
                row_id=_require_str(row.get("id"), "work_order_id", max_length=256),
                state=state,
            )
        return slots

    def _slot_id(self, slot: int) -> str:
        return f"corpus_{self._namespace}_{slot:06d}"

    def _slot_payload(self, slot: int, state: _SeedState | None) -> str:
        payload: dict[str, Any] = {
            "store": STORE_KIND,
            "namespace": self._namespace,
            "slot": slot,
            "seed": None if state is None else state.to_dict(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)

    async def _save_slot(self, slot: _Slot, *, created: int) -> None:
        payload = self._slot_payload(slot.slot, slot.state)
        if slot.row_id is None:
            result = await self._ledger.enqueue_work_order(
                work_order_id=self._slot_id(slot.slot),
                action=WORK_ORDER_ACTION,
                unit=self._unit,
                payload_json=payload,
                ev_cost=0.0,
                state=WORK_ORDER_STATE,
                created=created,
            )
            slot.row_id = _require_str(result, "work_order_id", max_length=256)
            return
        updated = await self._ledger.update_work_order_state(
            slot.row_id, WORK_ORDER_STATE, payload_json=payload
        )
        if updated is not True:
            raise FormatFail("corpus work order disappeared")

    def _allocate_slot(self, slots: dict[int, _Slot]) -> _Slot:
        for slot in sorted(slots.values(), key=lambda item: item.slot):
            if slot.state is None:
                return slot
        for index in range(self._max_corpus_size):
            if index not in slots:
                return _Slot(slot=index, row_id=None, state=None)
        raise FormatFail("corpus is full")

    def _active_slots(self, slots: dict[int, _Slot]) -> list[tuple[_Slot, _SeedState]]:
        active: list[tuple[_Slot, _SeedState]] = []
        for slot in slots.values():
            state = slot.state
            if state is not None:
                active.append((slot, state))
        return sorted(active, key=lambda item: item[0].slot)

    def _find_active(
        self, slots: dict[int, _Slot], seed_id: str
    ) -> tuple[_Slot, _SeedState] | None:
        matches = [
            (slot, state)
            for slot, state in self._active_slots(slots)
            if state.seed_id == seed_id
        ]
        if len(matches) > 1:
            raise FormatFail(f"duplicate corpus seed: {seed_id}")
        return matches[0] if matches else None

    def _edge_frequencies(self, slots: dict[int, _Slot]) -> dict[str, int]:
        frequencies: dict[str, int] = {}
        for _, state in self._active_slots(slots):
            for edge in state.edges:
                frequencies[edge] = frequencies.get(edge, 0) + 1
        return frequencies

    def _total_edges(self, slots: dict[int, _Slot]) -> int:
        return sum(len(state.edges) for _, state in self._active_slots(slots))

    def _check_edge_budget(self, slots: dict[int, _Slot], delta: int) -> None:
        if self._total_edges(slots) + delta > self._max_total_edges:
            raise FormatFail("corpus edge budget exceeded")

    def _rarity(self, edges: tuple[str, ...], frequencies: Mapping[str, int]) -> float:
        if not edges:
            return 0.0
        total = sum(1.0 / frequencies.get(edge, 1) for edge in edges)
        return min(1.0, max(0.0, total / len(edges)))

    def _view(
        self,
        slot: _Slot,
        state: _SeedState,
        frequencies: Mapping[str, int],
    ) -> CorpusSeedView:
        rarity = self._rarity(state.edges, frequencies)
        energy = self._policy.energy(
            covered_edges=len(state.edges),
            last_new_edges=state.last_new_edges,
            runs=state.runs,
            rarity=rarity,
        )
        return CorpusSeedView(
            seed_id=state.seed_id,
            lane=state.lane,
            slot=slot.slot,
            edges=state.edges,
            runs=state.runs,
            covered_edges=len(state.edges),
            new_edges=state.new_edges,
            last_new_edges=state.last_new_edges,
            rarity=rarity,
            energy=energy,
            created=state.created,
            updated=state.updated,
            last_seen=state.last_seen,
            last_run_id=state.last_run_id,
            target=state.target,
            artifact_id=state.artifact_id,
            metadata=dict(state.metadata),
        )


def _require_int(
    value: object, name: str, *, minimum: int = 0, maximum: int = _MAX_INT
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise FormatFail(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _require_finite_float(
    value: object,
    name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise FormatFail(f"{name} must be a finite number")
    if minimum is not None and result < minimum:
        raise FormatFail(f"{name} must be >= {minimum}")
    if maximum is not None and result > maximum:
        raise FormatFail(f"{name} must be <= {maximum}")
    return result


def _require_str(value: object, name: str, *, max_length: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or _CONTROL_RE.search(value) is not None
    ):
        raise FormatFail(f"{name} must be a non-empty string of at most {max_length} chars")
    return value


def _optional_str(value: object, name: str, *, max_length: int = 256) -> str | None:
    if value is None:
        return None
    return _require_str(value, name, max_length=max_length)


def _timestamp(value: int | None) -> int:
    if value is None:
        return now_ms()
    return _require_int(value, "created")


def _validate_edges(edges: Iterable[object], *, max_edges: int) -> tuple[str, ...]:
    if isinstance(edges, (str, bytes)):
        raise FormatFail("edges must be an iterable of edge ids, not text")
    try:
        items = list(edges)
    except TypeError as exc:
        raise FormatFail("edges must be iterable") from exc
    if len(items) > max_edges:
        raise FormatFail("too many edges for one seed")
    cleaned: list[str] = []
    for item in items:
        cleaned.append(_require_str(item, "edge", max_length=256))
    return tuple(sorted(set(cleaned)))


def _validate_metadata(metadata: Mapping[str, Any] | None, *, max_bytes: int) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise FormatFail("metadata must be a mapping")
    for key in metadata:
        if not isinstance(key, str) or not key or _CONTROL_RE.search(key) is not None:
            raise FormatFail("metadata keys must be non-empty strings")
    try:
        encoded = json.dumps(
            dict(metadata), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise FormatFail("metadata must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > max_bytes:
        raise FormatFail("metadata exceeds size budget")
    return dict(metadata)


def _validate_seed_ids(values: Iterable[object], name: str) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise FormatFail(f"{name} must be an iterable of seed ids, not text")
    try:
        items = list(values)
    except TypeError as exc:
        raise FormatFail(f"{name} must be iterable") from exc
    return frozenset(_require_str(item, name) for item in items)


def _seed_state_from_dict(data: object, *, max_edges: int) -> _SeedState:
    if not isinstance(data, Mapping):
        raise FormatFail("corpus seed payload must be an object")
    mapping = cast(Mapping[str, Any], data)
    status = mapping.get("status")
    if status != "active":
        raise FormatFail("corpus seed status must be active")
    edges_obj = mapping.get("edges")
    if not isinstance(edges_obj, list):
        raise FormatFail("corpus seed edges must be a list")
    metadata_obj = mapping.get("metadata")
    return _SeedState(
        seed_id=_require_str(mapping.get("seed_id"), "seed.seed_id"),
        lane=_require_str(mapping.get("lane"), "seed.lane"),
        edges=_validate_edges(edges_obj, max_edges=max_edges),
        runs=_require_int(mapping.get("runs"), "seed.runs"),
        new_edges=_require_int(mapping.get("new_edges"), "seed.new_edges"),
        last_new_edges=_require_int(mapping.get("last_new_edges"), "seed.last_new_edges"),
        last_seen=_require_int(mapping.get("last_seen"), "seed.last_seen"),
        created=_require_int(mapping.get("created"), "seed.created"),
        updated=_require_int(mapping.get("updated"), "seed.updated"),
        target=_optional_str(mapping.get("target"), "seed.target"),
        artifact_id=_optional_str(mapping.get("artifact_id"), "seed.artifact_id", max_length=256),
        last_run_id=_optional_str(mapping.get("last_run_id"), "seed.last_run_id"),
        metadata=_validate_metadata(
            cast(Mapping[str, Any] | None, metadata_obj), max_bytes=8192
        ),
    )


__all__ = [
    "CorpusMinimizationResult",
    "CorpusScheduler",
    "CorpusSeedSpec",
    "CorpusSeedView",
    "SeedEnergyPolicy",
]
