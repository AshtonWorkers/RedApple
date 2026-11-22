"""Value objects for the RedApple version ring."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..errors import FormatFail
from ..ledger.db import RING_INGEST_KINDS


def _require_text(name: str, value: str) -> None:
    if not value:
        raise FormatFail(f"{name} must be non-empty")


def _require_sha256(value: str) -> None:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise FormatFail("sha256 must be lowercase hex")


@dataclass(frozen=True)
class RingNodeSpec:
    """One immutable ring node descriptor."""

    node_id: str
    ipsw_sha: str
    build: str
    xcode: str
    sdk: str
    webkit_commit: str
    current: bool = False

    def __post_init__(self) -> None:
        for name in ("node_id", "ipsw_sha", "build", "xcode", "sdk", "webkit_commit"):
            _require_text(name, str(getattr(self, name)))

    def payload(self, *, state: str, epoch: int) -> dict[str, Any]:
        """Ledger payload for this node."""
        return {
            "ring_node_id": self.node_id,
            "ipsw_sha": self.ipsw_sha,
            "build": self.build,
            "xcode": self.xcode,
            "sdk": self.sdk,
            "webkit_commit": self.webkit_commit,
            "state": state,
            "epoch": epoch,
        }


@dataclass(frozen=True)
class RingSource:
    """One fetchable ring input (IPSW, OSS tarball, WebKit checkout, security notes)."""

    kind: str
    uri: str
    expected_sha256: str | None = None
    epoch: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in RING_INGEST_KINDS:
            raise FormatFail(f"unknown ring ingest kind {self.kind}")
        _require_text("uri", self.uri)
        if self.expected_sha256 is not None:
            _require_sha256(self.expected_sha256)
        if self.epoch is not None and self.epoch < 0:
            raise FormatFail("epoch must be non-negative")


@dataclass(frozen=True)
class IngestedSource:
    """Ledger-backed record of one verified ingest."""

    ingest_id: str
    kind: str
    uri: str
    sha256: str
    size_bytes: int
    epoch: int
    artifact_id: str | None = None

    def __post_init__(self) -> None:
        _require_text("ingest_id", self.ingest_id)
        _require_text("uri", self.uri)
        _require_sha256(self.sha256)
        if self.size_bytes < 0:
            raise FormatFail("size_bytes must be non-negative")
        if self.epoch < 0:
            raise FormatFail("epoch must be non-negative")
