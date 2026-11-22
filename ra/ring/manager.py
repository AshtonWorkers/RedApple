"""Version ring management (RA-RING)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from ..errors import ArmBlocked, FormatFail, OutOfRing
from ..ledger import Ledger
from ..ledger.db import (
    RING_DEFAULT_HISTORY_CAPACITY,
    RING_HISTORY_CAPACITY_MAX,
    RING_HISTORY_CAPACITY_MIN,
    RING_MIN_CURRENT_NODES,
    RING_MIN_PINNED_NODES,
)
from .models import RingNodeSpec

MIN_PINNED_NODES = RING_MIN_PINNED_NODES
MIN_CURRENT_NODES = RING_MIN_CURRENT_NODES
BOOT_FAILURE_THRESHOLD = 2
DEFAULT_HISTORY_CAPACITY = RING_DEFAULT_HISTORY_CAPACITY


class RingManager:
    """Ring node registry, atomic advance, and arm-time build gate."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        on_alert: Callable[[str, str], None] | None = None,
        boot_failure_threshold: int = BOOT_FAILURE_THRESHOLD,
        history_capacity: int = DEFAULT_HISTORY_CAPACITY,
    ) -> None:
        if boot_failure_threshold <= 0:
            raise FormatFail("boot_failure_threshold must be positive")
        if not RING_HISTORY_CAPACITY_MIN <= history_capacity <= RING_HISTORY_CAPACITY_MAX:
            raise FormatFail("history_capacity is out of range")
        self.ledger = ledger
        self.boot_failure_threshold = boot_failure_threshold
        self.history_capacity = history_capacity
        self._on_alert = on_alert or (lambda kind, detail: None)

    async def advance(self, nodes: Sequence[RingNodeSpec]) -> int:
        """Atomically advance the ring to the next ledger-computed epoch (RA-RING-004)."""
        node_list = list(nodes)
        if len(node_list) < MIN_PINNED_NODES:
            raise FormatFail(f"ring requires at least {MIN_PINNED_NODES} pinned nodes")
        if sum(1 for node in node_list if node.current) < MIN_CURRENT_NODES:
            raise FormatFail(f"ring requires at least {MIN_CURRENT_NODES} current nodes")
        ids = [node.node_id for node in node_list]
        if len(set(ids)) != len(ids):
            raise FormatFail("ring node ids must be unique")
        payloads = [
            node.payload(state="current" if node.current else "active", epoch=0)
            for node in node_list
        ]
        result = await self.ledger.advance_ring_auto(
            payloads, history_capacity=self.history_capacity
        )
        return int(result)

    async def attach(self, spec: RingNodeSpec) -> int:
        """Attach one node to the current ring version as a new epoch."""
        state = "current" if spec.current else "active"
        result = await self.ledger.attach_ring_node(
            spec.payload(state=state, epoch=0),
            history_capacity=self.history_capacity,
        )
        return int(result["epoch"])

    async def promote(self, node_id: str) -> int:
        """Promote one active ring node to current as a new epoch."""
        result = await self.ledger.promote_ring_node(
            node_id, history_capacity=self.history_capacity
        )
        return int(result["epoch"])

    async def rollback(self, epoch: int) -> int:
        """Roll back to a retained ring version as a new monotonic epoch."""
        result = await self.ledger.rollback_ring(epoch, history_capacity=self.history_capacity)
        return int(result["epoch"])

    def current_epoch(self) -> int:
        """Return the maximum ring epoch present in the ledger."""
        epochs = [int(row["epoch"]) for row in self.ledger.ring_nodes()]
        version_epochs = [int(row["epoch"]) for row in self.ledger.ring_versions()]
        return max([*epochs, *version_epochs], default=0)

    def active_nodes(self, epoch: int | None = None) -> list[dict[str, Any]]:
        """Return active/current ring nodes for one epoch in deterministic order."""
        resolved = self.current_epoch() if epoch is None else epoch
        nodes = [
            row
            for row in self.ledger.ring_nodes()
            if int(row["epoch"]) == resolved and str(row["state"]) in {"active", "current"}
        ]
        return sorted(nodes, key=lambda row: str(row["id"]))

    def versions(self) -> list[dict[str, Any]]:
        """Return retained ring version snapshots in epoch order."""
        return self.ledger.ring_versions()

    def version(self, epoch: int) -> dict[str, Any] | None:
        """Return one retained ring version snapshot."""
        return self.ledger.ring_version(epoch)

    def assert_in_ring(
        self,
        build: str,
        *,
        ipsw_sha: str | None = None,
        xcode: str | None = None,
        sdk: str | None = None,
        webkit_commit: str | None = None,
    ) -> dict[str, Any]:
        """Return the matching ring node or raise OUT_OF_RING (RA-RING-003)."""
        for row in self.ledger.ring_nodes():
            state = str(row["state"])
            if state in {"retired", "bad"}:
                continue
            if str(row["build"]) != build:
                continue
            if ipsw_sha is not None and str(row["ipsw_sha"]) != ipsw_sha:
                continue
            if xcode is not None and str(row["xcode"]) != xcode:
                continue
            if sdk is not None and str(row["sdk"]) != sdk:
                continue
            if webkit_commit is not None and str(row["webkit_commit"]) != webkit_commit:
                continue
            return row
        raise OutOfRing(f"build {build} is outside the version ring")

    def allows(self, ring_node: str, build: str | None = None) -> bool:
        """Lane-gate check: node is active/current and optionally matches build."""
        row = self.ledger.ring_node(ring_node)
        if row is None or str(row["state"]) not in {"active", "current"}:
            return False
        return build is None or str(row["build"]) == build

    async def record_boot_failure(self, node_id: str) -> str:
        """Record a boot failure and mark the node bad at the threshold (RA-RING-002)."""
        if self.ledger.ring_node(node_id) is None:
            raise FormatFail(f"unknown ring node {node_id}")
        result = await self.ledger.record_ring_boot_failure(
            node_id, threshold=self.boot_failure_threshold
        )
        if bool(result["alert"]):
            self._on_alert("ring_node_bad", node_id)
        return str(result["state"])

    def corpus_key(self, epoch: int) -> str:
        """Corpus key for a ring epoch (RA-RING-005)."""
        return f"ring_{epoch}"

    def assert_corpus_epoch(self, epoch: int, *, cross_epoch_opt_in: bool = False) -> str:
        """Return the corpus key or refuse cross-epoch reuse."""
        current = self.current_epoch()
        if epoch != current and not cross_epoch_opt_in:
            raise ArmBlocked(f"corpus epoch {epoch} is stale; current epoch is {current}")
        return self.corpus_key(epoch)
