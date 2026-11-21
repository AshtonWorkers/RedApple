"""Ledger data-transfer objects."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ArtifactInput:
    """Bytes to store in the content-addressed artifact table."""

    kind: str
    data: bytes
    ttl_class: str = "run"


@dataclass(frozen=True)
class ClaimArtifactInput:
    """Artifact link attached to a claim at creation time."""

    artifact: ArtifactInput
    role: str = "evidence"


@dataclass(frozen=True)
class ClaimInput:
    """Input for a new limbo claim (RA-LED-001)."""

    claim_id: str
    type: str
    value_json: str
    confidence: float
    dedup_key: str
    created: int
    run_id: str | None = None
    artifacts: tuple[ClaimArtifactInput, ...] = field(default_factory=tuple)
