"""Data models for the Harness Foundry (RA-FND)."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def now_ms() -> int:
    """Return the current Unix time in milliseconds."""
    return int(time.time() * 1000)


def _validate_safe_relative_path(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must be non-empty")
    if _CONTROL_CHARS_RE.search(value):
        raise ValueError(f"{field_name} contains control characters")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field_name} must be a safe relative path")


@dataclass(frozen=True)
class Dialect:
    """A validated groom dialect."""

    format: str
    data: dict[str, Any]
    validator: str
    validator_requirement: str


@dataclass(frozen=True)
class HarnessSpec:
    """A harness candidate submitted to the Foundry."""

    id: str
    format: str
    directory: Path
    source: str
    dialect: str
    manifest: str | None = None

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.id):
            raise ValueError(f"invalid harness id: {self.id!r}")
        if not self.format or _CONTROL_CHARS_RE.search(self.format):
            raise ValueError(f"invalid harness format: {self.format!r}")
        _validate_safe_relative_path(self.source, "source")
        _validate_safe_relative_path(self.dialect, "dialect")
        if self.manifest is not None:
            _validate_safe_relative_path(self.manifest, "manifest")

    def _resolve(self, relative_path: str) -> Path:
        root = self.directory.resolve()
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"path escapes harness directory: {relative_path!r}") from exc
        return candidate

    @property
    def source_path(self) -> Path:
        """Resolved harness source path."""
        return self._resolve(self.source)

    @property
    def dialect_path(self) -> Path:
        """Resolved groom dialect path."""
        return self._resolve(self.dialect)

    @property
    def manifest_path(self) -> Path | None:
        """Resolved optional manifest path."""
        if self.manifest is None:
            return None
        return self._resolve(self.manifest)

    def bundle_files(self) -> dict[str, bytes]:
        """Return the harness files that belong in the CAS bundle."""
        files = {
            self.source: self.source_path.read_bytes(),
            self.dialect: self.dialect_path.read_bytes(),
        }
        manifest_path = self.manifest_path
        manifest_name = self.manifest
        if manifest_path is not None and manifest_name is not None:
            files[manifest_name] = manifest_path.read_bytes()
        return files

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage or wire transfer."""
        payload: dict[str, Any] = {
            "id": self.id,
            "format": self.format,
            "directory": str(self.directory),
            "source": self.source,
            "dialect": self.dialect,
        }
        if self.manifest is not None:
            payload["manifest"] = self.manifest
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HarnessSpec:
        """Deserialize from :meth:`to_dict`."""
        return cls(
            id=str(data["id"]),
            format=str(data["format"]),
            directory=Path(str(data["directory"])),
            source=str(data["source"]),
            dialect=str(data["dialect"]),
            manifest=(
                str(data["manifest"]) if data.get("manifest") is not None else None
            ),
        )


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
    dry_run_completed: bool = True
    covered_edges: int = 0
    total_edges: int = 0
    baseline_covered_edges: int = 0
    new_covered_edges: int = 0
    throughput_metric: str = "coverage_edges_per_sec"
    throughput_caveat: str = (
        "edges_per_sec counts newly covered edges from libFuzzer coverage output "
        "over dry-run wall time"
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize measurements for storage."""
        return {
            "compiled": self.compiled,
            "edges_per_sec": self.edges_per_sec,
            "surface_median_edges_per_sec": self.surface_median_edges_per_sec,
            "coverage_map": self.coverage_map,
            "parser_malloc_symbol": self.parser_malloc_symbol,
            "dry_run_seconds": self.dry_run_seconds,
            "compile_seconds": self.compile_seconds,
            "dry_run_completed": self.dry_run_completed,
            "covered_edges": self.covered_edges,
            "total_edges": self.total_edges,
            "baseline_covered_edges": self.baseline_covered_edges,
            "new_covered_edges": self.new_covered_edges,
            "throughput_metric": self.throughput_metric,
            "throughput_caveat": self.throughput_caveat,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AcceptanceMeasurements:
        """Deserialize measurements."""
        return cls(**data)


@dataclass(frozen=True)
class AcceptanceDecision:
    """Result of the RA-FND-001 gate."""

    accepted: bool
    checks: dict[str, bool]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the decision."""
        return {
            "accepted": self.accepted,
            "checks": dict(self.checks),
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AcceptanceDecision:
        """Deserialize a decision."""
        return cls(
            accepted=bool(data["accepted"]),
            checks=dict(data.get("checks", {})),
            reasons=tuple(str(reason) for reason in data.get("reasons", [])),
        )


@dataclass
class AttemptRecord:
    """One Foundry submission attempt."""

    attempt_id: str
    harness_id: str
    measurements: AcceptanceMeasurements
    decision: AcceptanceDecision
    measurement_artifact_id: str
    created_at: int = 0
    bundle_artifact_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the attempt."""
        payload = {
            "attempt_id": self.attempt_id,
            "harness_id": self.harness_id,
            "measurements": self.measurements.to_dict(),
            "decision": self.decision.to_dict(),
            "measurement_artifact_id": self.measurement_artifact_id,
            "created_at": self.created_at,
        }
        if self.bundle_artifact_id is not None:
            payload["bundle_artifact_id"] = self.bundle_artifact_id
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttemptRecord:
        """Deserialize an attempt."""
        return cls(
            attempt_id=str(data["attempt_id"]),
            harness_id=str(data["harness_id"]),
            measurements=AcceptanceMeasurements.from_dict(data["measurements"]),
            decision=AcceptanceDecision.from_dict(data["decision"]),
            measurement_artifact_id=str(data["measurement_artifact_id"]),
            created_at=int(data.get("created_at", 0)),
            bundle_artifact_id=(
                str(data["bundle_artifact_id"])
                if data.get("bundle_artifact_id") is not None
                else None
            ),
        )


@dataclass
class FoundryState:
    """Persistent state for one harness id."""

    harness_id: str
    format: str
    state: str = "candidate"
    attempts: list[AttemptRecord] | None = None
    last_good_artifact_id: str | None = None
    reprompt_count: int = 0
    foundry_defect_count: int = 0
    updated_at: int = 0

    def __post_init__(self) -> None:
        if self.attempts is None:
            self.attempts = []

    @property
    def attempt_count(self) -> int:
        """Number of recorded attempts."""
        return len(self.attempts or [])

    def to_dict(self) -> dict[str, Any]:
        """Serialize state."""
        return {
            "harness_id": self.harness_id,
            "format": self.format,
            "state": self.state,
            "attempts": [attempt.to_dict() for attempt in (self.attempts or [])],
            "last_good_artifact_id": self.last_good_artifact_id,
            "reprompt_count": self.reprompt_count,
            "foundry_defect_count": self.foundry_defect_count,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FoundryState:
        """Deserialize state."""
        return cls(
            harness_id=str(data["harness_id"]),
            format=str(data["format"]),
            state=str(data.get("state", "candidate")),
            attempts=[AttemptRecord.from_dict(item) for item in data.get("attempts", [])],
            last_good_artifact_id=(
                str(data["last_good_artifact_id"])
                if data.get("last_good_artifact_id") is not None
                else None
            ),
            reprompt_count=int(data.get("reprompt_count", 0)),
            foundry_defect_count=int(data.get("foundry_defect_count", 0)),
            updated_at=int(data.get("updated_at", 0)),
        )


def dumps_json(payload: dict[str, Any]) -> bytes:
    """Stable JSON bytes for CAS storage."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
