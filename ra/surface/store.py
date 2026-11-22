"""Persistence for ranked attack-surface targets through the M0 claim ledger."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol

from ..ledger import Ledger
from ..srf.store import ledger_entry_point_payload
from .models import SurfaceTarget, TargetList
from .rank import thin_targets_from_rows


class SurfaceStore(Protocol):
    """Storage contract for ranked target lists."""

    async def replace_targets(self, target_list: TargetList) -> None: ...  # pragma: no cover

    def read_targets(self, ring_node: str) -> list[dict[str, Any]]: ...  # pragma: no cover


class InMemorySurfaceStore:
    """Deterministic in-memory store for tests and dry runs."""

    def __init__(self) -> None:
        self._rows: dict[str, list[dict[str, Any]]] = {}

    async def replace_targets(self, target_list: TargetList) -> None:
        self._rows[target_list.ring_node] = [dict(row) for row in target_list.rows]

    def read_targets(self, ring_node: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self._rows.get(ring_node, [])]


class LedgerSurfaceStore:
    """Ledger-backed store over ``entry_point`` rows.

    Ranked targets are persisted with ``Ledger.replace_entry_points`` and read
    back in weight-descending order. Rich ranking metadata (tier, rank,
    capabilities, rationale) is derived on read via
    :func:`ra.surface.rank.thin_targets_from_rows`.
    """

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    async def replace_targets(self, target_list: TargetList) -> None:
        payload = [ledger_entry_point_payload(row) for row in target_list.rows]
        await self._ledger.replace_entry_points(target_list.ring_node, payload)

    def read_targets(self, ring_node: str) -> list[dict[str, Any]]:
        return list(self._ledger.entry_points(ring_node))


def surface_targets_from_rows(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[SurfaceTarget, ...]:
    """Re-derive ranked surface targets from ``entry_point`` rows."""
    return thin_targets_from_rows(rows)


def feed_payload(targets: Sequence[SurfaceTarget]) -> list[dict[str, Any]]:
    """JSON-able target payloads for work-order or feed handoff."""
    return [t.to_dict() for t in targets]
