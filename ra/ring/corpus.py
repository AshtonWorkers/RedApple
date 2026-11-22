"""Epoch-keyed corpus registry with revocation for the version ring."""

from __future__ import annotations

from typing import Any

from ..errors import ArmBlocked, FormatFail
from ..ledger import Ledger


class CorpusRegistry:
    """Ledger-backed corpus bindings for ring nodes."""

    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    async def register(
        self,
        *,
        corpus_key: str,
        ring_node_id: str,
        epoch: int,
        artifact_id: str | None = None,
        corpus_id: str | None = None,
        created: int | None = None,
        updated: int | None = None,
    ) -> str:
        """Register or reactivate one corpus binding."""
        if not corpus_key:
            raise FormatFail("corpus_key must be non-empty")
        if epoch < 0:
            raise FormatFail("epoch must be non-negative")
        node = self.ledger.ring_node(ring_node_id)
        if node is None:
            raise FormatFail(f"unknown ring node {ring_node_id}")
        if str(node["state"]) not in {"active", "current"}:
            raise FormatFail("corpus cannot bind retired or bad ring node")
        if int(node["epoch"]) != epoch:
            raise FormatFail("corpus epoch must match the ring node epoch")
        return await self.ledger.register_ring_corpus(
            corpus_key=corpus_key,
            ring_node_id=ring_node_id,
            epoch=epoch,
            artifact_id=artifact_id,
            corpus_id=corpus_id,
            created=created,
            updated=updated,
        )

    async def revoke(
        self,
        *,
        corpus_key: str | None = None,
        ring_node_id: str | None = None,
        epoch: int | None = None,
        updated: int | None = None,
    ) -> int:
        """Revoke active corpus bindings in the requested scope."""
        return await self.ledger.revoke_ring_corpus(
            corpus_key=corpus_key,
            ring_node_id=ring_node_id,
            epoch=epoch,
            updated=updated,
        )

    async def revoke_node(self, ring_node_id: str, *, epoch: int | None = None) -> int:
        """Revoke every active corpus bound to one ring node."""
        return await self.revoke(ring_node_id=ring_node_id, epoch=epoch)

    async def revoke_epoch(self, epoch: int) -> int:
        """Revoke every active corpus bound to one ring epoch."""
        if epoch < 0:
            raise FormatFail("epoch must be non-negative")
        return await self.revoke(epoch=epoch)

    def active_bindings(
        self,
        *,
        corpus_key: str | None = None,
        ring_node_id: str | None = None,
        epoch: int | None = None,
    ) -> list[dict[str, Any]]:
        """List active corpus bindings in deterministic order."""
        rows = self.ledger.ring_corpora(
            corpus_key=corpus_key,
            ring_node_id=ring_node_id,
            state="active",
            epoch=epoch,
        )
        return [dict(row) for row in rows]

    def binding_for(self, corpus_key: str, ring_node_id: str, epoch: int) -> dict[str, Any] | None:
        """Return the active binding for one corpus/node/epoch, if present."""
        rows = self.active_bindings(corpus_key=corpus_key, ring_node_id=ring_node_id, epoch=epoch)
        return rows[0] if rows else None

    def resolve_binding(
        self,
        corpus_key: str,
        ring_node_id: str,
        epoch: int,
        *,
        cross_epoch_opt_in: bool = False,
    ) -> dict[str, Any] | None:
        """Resolve an active binding, optionally allowing cross-epoch reuse."""
        exact = self.binding_for(corpus_key, ring_node_id, epoch)
        if exact is not None or not cross_epoch_opt_in:
            return exact
        candidates = self.active_bindings(corpus_key=corpus_key, ring_node_id=ring_node_id)
        if not candidates:
            return None
        return max(candidates, key=lambda row: (int(row["epoch"]), str(row["id"])))

    def assert_usable(
        self,
        corpus_key: str,
        ring_node_id: str,
        epoch: int,
        *,
        cross_epoch_opt_in: bool = False,
    ) -> dict[str, Any]:
        """Return the resolved binding or raise ARM_BLOCKED."""
        binding = self.resolve_binding(
            corpus_key,
            ring_node_id,
            epoch,
            cross_epoch_opt_in=cross_epoch_opt_in,
        )
        if binding is None:
            raise ArmBlocked(
                f"corpus {corpus_key} is not active for ring node {ring_node_id} epoch {epoch}"
            )
        return binding
