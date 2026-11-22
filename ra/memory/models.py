"""Data-transfer objects for compounding campaign memory (RA-MEM)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

GLOBAL_SURFACE = "*"
PRIOR_KINDS = frozenset(
    {"root_cause", "bug_class", "gadget_set", "join", "groom", "entry_point", "verdict"}
)
ADAPTER_STATES = frozenset({"candidate", "evaluated", "shipped", "rejected", "retired"})
MEMORY_META_KEY = "_memory"


def _json_dict(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    return {}


def _json_list(value: object) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return list(parsed)
    return []


def _public_value(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != MEMORY_META_KEY}


@dataclass(frozen=True)
class MemoryPrior:
    """One ranked learned prior over the ledger."""

    id: str
    kind: str
    surface: str
    key: str
    value: Mapping[str, Any]
    score: float
    support: int
    confidence: float
    state: str
    revision: int
    source_claim: str | None
    source_artifact: str | None
    created: int
    updated: int

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> MemoryPrior:
        return cls(
            id=str(row["id"]),
            kind=str(row["kind"]),
            surface=str(row["surface"]),
            key=str(row["key"]),
            value=_public_value(_json_dict(row.get("value_json", "{}"))),
            score=float(row["score"]),
            support=int(row["support"]),
            confidence=float(row["confidence"]),
            state=str(row["state"]),
            revision=int(row["revision"]),
            source_claim=None if row.get("source_claim") is None else str(row["source_claim"]),
            source_artifact=(
                None if row.get("source_artifact") is None else str(row["source_artifact"])
            ),
            created=int(row["created"]),
            updated=int(row["updated"]),
        )


@dataclass(frozen=True)
class PreferencePair:
    """One chosen/rejected preference pair for LoRA-style adapter training."""

    id: str
    task_type: str
    surface: str
    prompt_sha: str
    chosen: Mapping[str, Any]
    rejected: Mapping[str, Any]
    reward: float
    rationale: str | None
    source_claim: str | None
    source_artifact: str | None
    created: int

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> PreferencePair:
        return cls(
            id=str(row["id"]),
            task_type=str(row["task_type"]),
            surface=str(row["surface"]),
            prompt_sha=str(row["prompt_sha"]),
            chosen=_json_dict(row.get("chosen_json", "{}")),
            rejected=_json_dict(row.get("rejected_json", "{}")),
            reward=float(row["reward"]),
            rationale=None if row.get("rationale") is None else str(row["rationale"]),
            source_claim=None if row.get("source_claim") is None else str(row["source_claim"]),
            source_artifact=(
                None if row.get("source_artifact") is None else str(row["source_artifact"])
            ),
            created=int(row["created"]),
        )


@dataclass(frozen=True)
class MemoryAdapter:
    """One LoRA-style adapter lifecycle record."""

    id: str
    task_type: str
    surface: str
    version: int
    parent_id: str | None
    state: str
    config: Mapping[str, Any]
    train_pair_count: int
    eval_score: float | None
    baseline_score: float | None
    golden_rows: int | None
    golden_passed: bool | None
    ship_blocked_reason: str | None
    source_artifact: str | None
    created: int
    updated: int

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> MemoryAdapter:
        golden_passed = row.get("golden_passed")
        return cls(
            id=str(row["id"]),
            task_type=str(row["task_type"]),
            surface=str(row["surface"]),
            version=int(row["version"]),
            parent_id=None if row.get("parent_id") is None else str(row["parent_id"]),
            state=str(row["state"]),
            config=_json_dict(row.get("config_json", "{}")),
            train_pair_count=int(row["train_pair_count"]),
            eval_score=None if row.get("eval_score") is None else float(row["eval_score"]),
            baseline_score=(
                None if row.get("baseline_score") is None else float(row["baseline_score"])
            ),
            golden_rows=None if row.get("golden_rows") is None else int(row["golden_rows"]),
            golden_passed=None if golden_passed is None else bool(golden_passed),
            ship_blocked_reason=(
                None if row.get("ship_blocked_reason") is None else str(row["ship_blocked_reason"])
            ),
            source_artifact=(
                None if row.get("source_artifact") is None else str(row["source_artifact"])
            ),
            created=int(row["created"]),
            updated=int(row["updated"]),
        )


@dataclass(frozen=True)
class SlaStatus:
    """Monotonic SLA state for one surface."""

    surface: str
    target_cost_micro: int
    best_cost_micro: int | None
    last_cost_micro: int | None
    met: bool
    met_at: int | None
    observations: int
    regressions: int
    flagged: bool
    violation_json: str | None
    created: int
    updated: int

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> SlaStatus:
        violation = row.get("violation_json")
        return cls(
            surface=str(row["surface"]),
            target_cost_micro=int(row["target_cost_micro"]),
            best_cost_micro=(
                None if row.get("best_cost_micro") is None else int(row["best_cost_micro"])
            ),
            last_cost_micro=(
                None if row.get("last_cost_micro") is None else int(row["last_cost_micro"])
            ),
            met=bool(row["met"]),
            met_at=None if row.get("met_at") is None else int(row["met_at"]),
            observations=int(row["observations"]),
            regressions=int(row["regressions"]),
            flagged=bool(row["flagged"]),
            violation_json=None if violation is None else str(violation),
            created=int(row["created"]),
            updated=int(row["updated"]),
        )


@dataclass(frozen=True)
class RetrievalContext:
    """Memory selected for one PRESS retrieval."""

    surface: str
    task_type: str | None
    priors: tuple[MemoryPrior, ...]
    pairs: tuple[PreferencePair, ...]
    adapter: MemoryAdapter | None
    packet_sha: str | None
    retrieval_id: str


__all__ = [
    "ADAPTER_STATES",
    "GLOBAL_SURFACE",
    "PRIOR_KINDS",
    "MemoryAdapter",
    "MemoryPrior",
    "MEMORY_META_KEY",
    "PreferencePair",
    "RetrievalContext",
    "SlaStatus",
    "_json_dict",
    "_json_list",
]
