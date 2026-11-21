"""Version ring management (RA-RING)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ..errors import ArmBlocked, FormatFail, OutOfRing
from ..ledger import Ledger

MIN_PINNED_NODES = 6
MIN_CURRENT_NODES = 2


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


class RingManager:
    """Ring node registry, atomic advance, and arm-time build gate."""

    def __init__(
        self, ledger: Ledger, *, on_alert: Callable[[str, str], None] | None = None
    ) -> None:
        self.ledger = ledger
        self._boot_failures: dict[str, int] = {}
        self._on_alert = on_alert or (lambda kind, detail: None)

    async def advance(self, nodes: Sequence[RingNodeSpec]) -> int:
        """Atomically advance the ring to a new epoch (RA-RING-004)."""
        if len(nodes) < MIN_PINNED_NODES:
            raise FormatFail(f"ring requires at least {MIN_PINNED_NODES} pinned nodes")
        if sum(1 for node in nodes if node.current) < MIN_CURRENT_NODES:
            raise FormatFail(f"ring requires at least {MIN_CURRENT_NODES} current nodes")
        ids = [node.node_id for node in nodes]
        if len(set(ids)) != len(ids):
            raise FormatFail("ring node ids must be unique")
        current_epoch = self.current_epoch()
        new_epoch = current_epoch + 1
        payloads = [
            node.payload(state="current" if node.current else "active", epoch=new_epoch)
            for node in nodes
        ]
        result = await self.ledger.advance_ring(new_epoch, payloads)
        return int(result)

    def current_epoch(self) -> int:
        """Return the maximum ring epoch present in the ledger."""
        epochs = [int(row["epoch"]) for row in self.ledger.ring_nodes()]
        return max(epochs, default=0)

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

    async def record_boot_failure(self, node_id: str) -> str:
        """Mark a node bad after two boot failures and alert (RA-RING-002)."""
        node = self.ledger.ring_node(node_id)
        if node is None:
            raise FormatFail(f"unknown ring node {node_id}")
        failures = self._boot_failures.get(node_id, 0) + 1
        self._boot_failures[node_id] = failures
        if failures >= 2 and str(node["state"]) != "bad":
            payload = {
                "ring_node_id": node_id,
                "ipsw_sha": str(node["ipsw_sha"]),
                "build": str(node["build"]),
                "xcode": str(node["xcode"]),
                "sdk": str(node["sdk"]),
                "webkit_commit": str(node["webkit_commit"]),
                "state": "bad",
                "epoch": int(node["epoch"]),
            }
            await self.ledger.upsert_ring_node(payload)
            self._on_alert("ring_node_bad", node_id)
            return "bad"
        return str(node["state"])

    def corpus_key(self, epoch: int) -> str:
        """Corpus key for a ring epoch (RA-RING-005)."""
        return f"ring_{epoch}"

    def assert_corpus_epoch(self, epoch: int, *, cross_epoch_opt_in: bool = False) -> str:
        """Return the corpus key or refuse cross-epoch reuse."""
        current = self.current_epoch()
        if epoch != current and not cross_epoch_opt_in:
            raise ArmBlocked(f"corpus epoch {epoch} is stale; current epoch is {current}")
        return self.corpus_key(epoch)
