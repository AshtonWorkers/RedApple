"""Data models for the ImageIO/HEIF discovery campaign."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


def now_ms() -> int:
    """Current Unix time in integer milliseconds."""
    return time.time_ns() // 1_000_000


@runtime_checkable
class CrashRefLike(Protocol):
    """Structural view of a lane crash reference (RA-LAN CrashRef)."""

    id: str
    kind: str
    handle_id: str | None
    path: str | None
    digest: str | None
    payload: bytes
    context: str
    created_ms: int
    metadata: Mapping[str, Any]


@dataclass
class DiscoveryHarnessRef:
    """Harness reference consumed by lane adapters without importing ra.lanes."""

    name: str
    kind: str = "command"
    argv: Sequence[str] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CampaignConfig:
    """Deterministic configuration for one discovery campaign."""

    campaign_id: str = "imageio_heif"
    surface: str = "imageio.heif"
    format: str = "heif"
    harness_name: str = "imageio_heif"
    target: str = "imageio_heif"
    seed: int = 0x52414450
    max_cases: int = 256
    max_input_bytes: int = 4096
    state_checkpoint_every: int = 25
    thermal_check_every: int = 16
    max_cases_per_handle: int = 64
    max_consecutive_errors: int = 8
    time_budget_s: float | None = None

    def validate(self) -> None:
        """Reject configurations that cannot produce a deterministic campaign."""
        if not self.campaign_id or not self.surface or not self.format:
            raise ValueError("campaign_id, surface and format must be non-empty")
        if self.max_cases < 1:
            raise ValueError("max_cases must be >= 1")
        if self.max_input_bytes < 8:
            raise ValueError("max_input_bytes must be >= 8")
        if self.state_checkpoint_every < 1:
            raise ValueError("state_checkpoint_every must be >= 1")
        if self.thermal_check_every < 1:
            raise ValueError("thermal_check_every must be >= 1")
        if self.max_cases_per_handle < 1:
            raise ValueError("max_cases_per_handle must be >= 1")
        if self.max_consecutive_errors < 1:
            raise ValueError("max_consecutive_errors must be >= 1")
        if self.time_budget_s is not None and self.time_budget_s < 0:
            raise ValueError("time_budget_s must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe configuration snapshot."""
        return {
            "campaign_id": self.campaign_id,
            "surface": self.surface,
            "format": self.format,
            "harness_name": self.harness_name,
            "target": self.target,
            "seed": self.seed,
            "max_cases": self.max_cases,
            "max_input_bytes": self.max_input_bytes,
            "state_checkpoint_every": self.state_checkpoint_every,
            "thermal_check_every": self.thermal_check_every,
            "max_cases_per_handle": self.max_cases_per_handle,
            "max_consecutive_errors": self.max_consecutive_errors,
            "time_budget_s": self.time_budget_s,
        }

    def harness_ref(self) -> DiscoveryHarnessRef:
        """Build the default harness reference for this campaign."""
        return DiscoveryHarnessRef(
            name=self.harness_name,
            kind="command",
            argv=(),
            env={},
            metadata={"surface": self.surface, "format": self.format},
        )


@dataclass(frozen=True)
class MutationCase:
    """One deterministic mutated input planned for the campaign."""

    campaign_id: str
    index: int
    case_id: str
    seed_index: int
    strategy: str
    data: bytes
    digest: str
    gate_pass: bool


@dataclass
class CampaignState:
    """Ledger-persisted discovery campaign state."""

    campaign_id: str
    surface: str
    format: str
    status: str = "planned"
    config: dict[str, Any] = field(default_factory=dict)
    seed_count: int = 0
    cases_planned: int = 0
    cases_fed: int = 0
    feeds_accepted: int = 0
    feeds_rejected: int = 0
    feeds_saturated: int = 0
    gate_passes: int = 0
    crashes_seen: int = 0
    crashes_recorded: int = 0
    crashes_deduped: int = 0
    next_case_index: int = 0
    last_case_index: int = -1
    consecutive_errors: int = 0
    last_error: dict[str, Any] | None = None
    last_crash_claim_id: str | None = None
    created_ms: int = field(default_factory=now_ms)
    updated_ms: int = field(default_factory=now_ms)
    finished_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe state snapshot."""
        return {
            "campaign_id": self.campaign_id,
            "surface": self.surface,
            "format": self.format,
            "status": self.status,
            "config": dict(self.config),
            "seed_count": self.seed_count,
            "cases_planned": self.cases_planned,
            "cases_fed": self.cases_fed,
            "feeds_accepted": self.feeds_accepted,
            "feeds_rejected": self.feeds_rejected,
            "feeds_saturated": self.feeds_saturated,
            "gate_passes": self.gate_passes,
            "crashes_seen": self.crashes_seen,
            "crashes_recorded": self.crashes_recorded,
            "crashes_deduped": self.crashes_deduped,
            "next_case_index": self.next_case_index,
            "last_case_index": self.last_case_index,
            "consecutive_errors": self.consecutive_errors,
            "last_error": self.last_error,
            "last_crash_claim_id": self.last_crash_claim_id,
            "created_ms": self.created_ms,
            "updated_ms": self.updated_ms,
            "finished_ms": self.finished_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CampaignState:
        """Rebuild state from a ledger claim value."""
        config = data.get("config", {})
        if not isinstance(config, dict):
            raise ValueError("campaign state config must be an object")
        last_error = data.get("last_error")
        if last_error is not None and not isinstance(last_error, dict):
            raise ValueError("campaign state last_error must be an object or null")
        return cls(
            campaign_id=str(data["campaign_id"]),
            surface=str(data["surface"]),
            format=str(data["format"]),
            status=str(data.get("status", "planned")),
            config=dict(config),
            seed_count=int(data.get("seed_count", 0)),
            cases_planned=int(data.get("cases_planned", 0)),
            cases_fed=int(data.get("cases_fed", 0)),
            feeds_accepted=int(data.get("feeds_accepted", 0)),
            feeds_rejected=int(data.get("feeds_rejected", 0)),
            feeds_saturated=int(data.get("feeds_saturated", 0)),
            gate_passes=int(data.get("gate_passes", 0)),
            crashes_seen=int(data.get("crashes_seen", 0)),
            crashes_recorded=int(data.get("crashes_recorded", 0)),
            crashes_deduped=int(data.get("crashes_deduped", 0)),
            next_case_index=int(data.get("next_case_index", 0)),
            last_case_index=int(data.get("last_case_index", -1)),
            consecutive_errors=int(data.get("consecutive_errors", 0)),
            last_error=None if last_error is None else dict(last_error),
            last_crash_claim_id=(
                None if data.get("last_crash_claim_id") is None else str(data["last_crash_claim_id"])
            ),
            created_ms=int(data.get("created_ms", now_ms())),
            updated_ms=int(data.get("updated_ms", now_ms())),
            finished_ms=None if data.get("finished_ms") is None else int(data["finished_ms"]),
        )


@dataclass(frozen=True)
class CrashRecord:
    """Ledger claim handle returned after recording one crash."""

    claim_id: str | None
    campaign_id: str
    case_id: str
    crash_id: str
    kind: str
    dedup_key: str
    value: dict[str, Any]


@dataclass(frozen=True)
class CampaignResult:
    """Outcome of one campaign run."""

    state: CampaignState
    crashes: Sequence[CrashRefLike]
    cases: Sequence[MutationCase]
