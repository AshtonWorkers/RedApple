"""Feeds that hand ranked surface targets to discovery lanes and chain search.

Both consumers are external components. This module defines clean async feed
interfaces plus ledger-backed implementations; the chain-search side is a
documented stub until RA-CHN lands.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Protocol

from .models import SurfaceTarget
from .rank import thin_targets_from_rows
from .store import SurfaceStore


class LaneFeed(Protocol):
    """Interface discovery lanes use to pull ranked targets."""

    async def feed(self, ring_node: str, *, limit: int | None = None) -> tuple[Any, ...]: ...  # pragma: no cover


class ChainFeed(Protocol):
    """Interface chain search uses to pull ranked targets and their reach."""

    async def feed(self, ring_node: str, *, limit: int | None = None) -> tuple[SurfaceTarget, ...]: ...  # pragma: no cover


class LaneTarget:
    """Minimal target descriptor consumed by discovery lanes."""

    __slots__ = (
        "target_id",
        "name",
        "ring_node",
        "weight",
        "tier",
        "rank",
        "privilege_delta",
        "ingress",
        "capabilities",
    )

    def __init__(
        self,
        *,
        target_id: str,
        name: str,
        ring_node: str,
        weight: float,
        tier: str,
        rank: int,
        privilege_delta: int,
        ingress: str,
        capabilities: tuple[str, ...],
    ) -> None:
        self.target_id = target_id
        self.name = name
        self.ring_node = ring_node
        self.weight = weight
        self.tier = tier
        self.rank = rank
        self.privilege_delta = privilege_delta
        self.ingress = ingress
        self.capabilities = capabilities

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "name": self.name,
            "ring_node": self.ring_node,
            "weight": self.weight,
            "tier": self.tier,
            "rank": self.rank,
            "privilege_delta": self.privilege_delta,
            "ingress": self.ingress,
            "capabilities": list(self.capabilities),
        }


def lane_targets_from_surface(
    targets: Sequence[SurfaceTarget], *, limit: int | None = None
) -> tuple[LaneTarget, ...]:
    """Project ranked surface targets into lane-consumable descriptors."""
    selected = list(targets)
    if limit is not None:
        selected = selected[: max(0, limit)]
    return tuple(
        LaneTarget(
            target_id=t.id,
            name=t.name,
            ring_node=t.ring_node,
            weight=t.weight,
            tier=t.tier.value,
            rank=t.rank,
            privilege_delta=t.privilege_delta,
            ingress=t.ingress.value,
            capabilities=tuple(c.value for c in t.capabilities),
        )
        for t in selected
    )


class StaticLaneFeed:
    """In-memory lane feed for tests and dry runs."""

    def __init__(self, targets: Sequence[SurfaceTarget]) -> None:
        self._targets = tuple(targets)

    async def feed(self, ring_node: str, *, limit: int | None = None) -> tuple[LaneTarget, ...]:
        scoped = [t for t in self._targets if t.ring_node == ring_node]
        return lane_targets_from_surface(scoped, limit=limit)


class StaticChainFeed:
    """In-memory chain feed for tests and dry runs."""

    def __init__(self, targets: Sequence[SurfaceTarget]) -> None:
        self._targets = tuple(targets)

    async def feed(
        self, ring_node: str, *, limit: int | None = None
    ) -> tuple[SurfaceTarget, ...]:
        scoped = [t for t in self._targets if t.ring_node == ring_node]
        if limit is None:
            return tuple(scoped)
        return tuple(scoped[: max(0, limit)])


class LedgerLaneFeed:
    """Lane feed backed by persisted ranked targets."""

    def __init__(self, store: SurfaceStore) -> None:
        self._store = store

    async def feed(self, ring_node: str, *, limit: int | None = None) -> tuple[LaneTarget, ...]:
        rows = self._store.read_targets(ring_node)
        return lane_targets_from_surface(thin_targets_from_rows(rows), limit=limit)


class LedgerChainFeed:
    """Chain-search feed backed by persisted ranked targets."""

    def __init__(self, store: SurfaceStore) -> None:
        self._store = store

    async def feed(
        self, ring_node: str, *, limit: int | None = None
    ) -> tuple[SurfaceTarget, ...]:
        rows = self._store.read_targets(ring_node)
        targets = thin_targets_from_rows(rows)
        if limit is None:
            return targets
        return targets[: max(0, limit)]


class StubChainSearch:
    """Placeholder chain-search consumer until RA-CHN is implemented.

    Records the ranked targets it would chain from and returns an empty plan,
    keeping the interface stable for downstream wiring.
    """

    def __init__(self) -> None:
        self.seen: list[SurfaceTarget] = []

    def search(self, targets: Iterable[SurfaceTarget]) -> tuple[()]:
        self.seen.extend(targets)
        return ()


def feed_dicts(targets: Iterable[SurfaceTarget]) -> list[dict[str, Any]]:
    """Serialize ranked targets for work-order payloads or lane messages."""
    return [t.to_dict() for t in targets]


def rows_to_lane_targets(rows: Iterable[dict[str, Any]]) -> tuple[LaneTarget, ...]:
    """Derive lane targets directly from persisted ``entry_point`` rows."""
    return lane_targets_from_surface(thin_targets_from_rows(rows))


__all__ = [
    "ChainFeed",
    "LaneFeed",
    "LaneTarget",
    "LedgerChainFeed",
    "LedgerLaneFeed",
    "StaticChainFeed",
    "StaticLaneFeed",
    "StubChainSearch",
    "feed_dicts",
    "lane_targets_from_surface",
    "rows_to_lane_targets",
]
