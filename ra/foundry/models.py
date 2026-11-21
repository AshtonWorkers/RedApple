"""Foundry data model.

Invariants touched: I2 (CAS artifacts are content addressed), I3 (attempts are
append-only and idempotent by attempt id), I5 (state ordering ends in id).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def now_ms() -> int:
    """Current time as int64 milliseconds (RA-REP-004)."""
    return int(time.time() * 1000)


@dataclass(frozen=True)
class HarnessSpec:
    """Location and identity of one candidate harness."""

    id: str
    format: str
    directory: Path
    source: str
    dialect: str
    manifest: Optional[str] = None

    def source_path(self) -> Path:
        return self.directory / self.source

    def dialect_path(self) -> Path:
        return self.directory / self.dialect

    def manifest_path(self) -> Optional[Path]:
        if self.manifest is None:
            return None
        return self.directory / self.manifest

    def bundle_files(self) -> Dict[str, bytes]:
        """Return the immutable harness inputs stored in CAS."""
        files: Dict[str, bytes] = {
            self.source: self.source_path().read_bytes(),
            self.dialect: self.dialect_path().read_bytes(),
        }
        manifest_path = self.manifest_path()
        if manifest_path is not None and manifest_path.exists():
            files[self.manifest or "harness.json"] = manifest_path.read_bytes()
        return files


@dataclass(frozen=True)
class AcceptanceMeasurements:
    """Mechanical RA-FND-001 measurements for one dry run."""

    compiled: bool
    edges_per_sec: float
    surface_median_edges_per_sec: float
    coverage_map: str
    parser_malloc_symbol: str = "parser_malloc"
    dry_run_seconds: float = 600.0
    compile_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compiled": self.compiled,
            "edges_per_sec": self.edges_per_sec,
            "surface_median_edges_per_sec": self.surface_median_edges_per_sec,
            "coverage_map": self.coverage_map,
            "parser_malloc_symbol": self.parser_malloc_symbol,
            "dry_run_seconds": self.dry_run_seconds,
            "compile_seconds": self.compile_seconds,
        }


@dataclass(frozen=True)
class AcceptanceDecision:
    """Result of the mechanical acceptance gate."""

    accepted: bool
    checks: Dict[str, bool]
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "checks": dict(self.checks),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class Dialect:
    """Validated groom dialect (RA-FND-002)."""

    format: str
    data: Dict[str, Any]
    validator: str
    validator_requirement: str


@dataclass
class AttemptRecord:
    """One acceptance attempt, append-only (I3)."""

    id: str
    harness_id: str
    accepted: bool
    created_ms: int
    measurements: Dict[str, Any]
    artifact_ids: List[str]
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "harness_id": self.harness_id,
            "accepted": self.accepted,
            "created_ms": self.created_ms,
            "measurements": dict(self.measurements),
            "artifact_ids": list(self.artifact_ids),
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttemptRecord":
        return cls(
            id=str(data["id"]),
            harness_id=str(data["harness_id"]),
            accepted=bool(data["accepted"]),
            created_ms=int(data["created_ms"]),
            measurements=dict(data.get("measurements", {})),
            artifact_ids=list(data.get("artifact_ids", [])),
            reasons=list(data.get("reasons", [])),
        )


@dataclass
class FoundryState:
    """Persistent Foundry state for one harness."""

    harness_id: str
    format: str
    state: str = "candidate"
    foundry_defect: int = 0
    attempts: List[AttemptRecord] = field(default_factory=list)
    last_good_artifact_id: Optional[str] = None
    created_ms: int = field(default_factory=now_ms)
    updated_ms: int = field(default_factory=now_ms)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "harness_id": self.harness_id,
            "format": self.format,
            "state": self.state,
            "foundry_defect": self.foundry_defect,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "last_good_artifact_id": self.last_good_artifact_id,
            "created_ms": self.created_ms,
            "updated_ms": self.updated_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FoundryState":
        return cls(
            harness_id=str(data["harness_id"]),
            format=str(data["format"]),
            state=str(data.get("state", "candidate")),
            foundry_defect=int(data.get("foundry_defect", 0)),
            attempts=[AttemptRecord.from_dict(a) for a in data.get("attempts", [])],
            last_good_artifact_id=data.get("last_good_artifact_id"),
            created_ms=int(data.get("created_ms", now_ms())),
            updated_ms=int(data.get("updated_ms", now_ms())),
        )


@dataclass(frozen=True)
class FoundryOutcome:
    """Result of submitting measurements for a harness."""

    status: str
    harness_id: str
    decision: AcceptanceDecision
    reprompt: Optional[Dict[str, Any]]
    artifact_ids: List[str]
    state: FoundryState


@dataclass(frozen=True)
class RollbackResult:
    """Result of restoring the last-good harness artifact."""

    harness_id: str
    artifact_id: str
    elapsed_ms: int
