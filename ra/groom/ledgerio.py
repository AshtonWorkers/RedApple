"""Ledger persistence helpers for groom/ladder claims."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from ..errors import DuplicateDedup
from ..ledger import ClaimArtifactInput, ClaimInput, ClaimState, Ledger
from ..ledger.models import ArtifactInput
from .models import canonical_json, now_ms


async def create_claim_once(
    ledger: Ledger,
    *,
    claim_id: str,
    claim_type: str,
    value: dict[str, Any],
    confidence: float,
    dedup: str,
    artifacts: Sequence[tuple[str, bytes]],
    run_id: str | None = None,
    created: int | None = None,
) -> str:
    """Create a claim once per dedup key, returning the existing ID on replay."""
    existing = ledger.claim_by_dedup(dedup)
    if existing is not None:
        return str(existing["id"])
    seen: set[str] = set()
    unique_artifacts: list[tuple[str, bytes]] = []
    for kind, data in artifacts:
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unique_artifacts.append((kind, data))
    artifact_inputs = tuple(
        ClaimArtifactInput(
            artifact=ArtifactInput(kind=kind, data=data, ttl_class="run"),
            role="evidence",
        )
        for kind, data in unique_artifacts
    )
    claim = ClaimInput(
        claim_id=claim_id,
        type=claim_type,
        value_json=canonical_json(value),
        confidence=confidence,
        dedup_key=dedup,
        created=now_ms() if created is None else created,
        run_id=run_id,
        artifacts=artifact_inputs,
    )
    try:
        return await ledger.create_claim(claim)
    except DuplicateDedup:
        replay = ledger.claim_by_dedup(dedup)
        if replay is None:
            raise
        return str(replay["id"])


async def create_reviewed_claim(
    ledger: Ledger,
    *,
    claim_id: str,
    claim_type: str,
    value: dict[str, Any],
    confidence: float,
    dedup: str,
    artifacts: Sequence[tuple[str, bytes]],
    run_id: str | None = None,
    created: int | None = None,
) -> str:
    """Create a claim and advance it limbo -> bound -> reviewed."""
    claim = await create_claim_once(
        ledger,
        claim_id=claim_id,
        claim_type=claim_type,
        value=value,
        confidence=confidence,
        dedup=dedup,
        artifacts=artifacts,
        run_id=run_id,
        created=created,
    )
    await transition_if_needed(ledger, claim, ClaimState.LIMBO, ClaimState.BOUND)
    await transition_if_needed(ledger, claim, ClaimState.BOUND, ClaimState.REVIEWED)
    return claim


async def transition_if_needed(
    ledger: Ledger,
    claim_id: str,
    from_state: ClaimState,
    to_state: ClaimState,
) -> None:
    """Apply a claim transition only when the claim is currently in ``from_state``."""
    row = ledger.get_claim(claim_id)
    if row is None:
        return
    if str(row.get("state")) != from_state.value:
        return
    await ledger.transition_claim(claim_id, to_state)


async def finalize_claim(
    ledger: Ledger,
    claim_id: str,
    *,
    promoted: bool,
    demoted: bool = False,
) -> str:
    """Move a reviewed claim to its terminal state when requested."""
    row = ledger.get_claim(claim_id)
    if row is None or str(row.get("state")) != ClaimState.REVIEWED.value:
        return str(row.get("state", "missing")) if row is not None else "missing"
    if promoted:
        await ledger.transition_claim(claim_id, ClaimState.PROMOTED)
        return ClaimState.PROMOTED.value
    if demoted:
        await ledger.transition_claim(claim_id, ClaimState.DEMOTED)
        return ClaimState.DEMOTED.value
    return ClaimState.REVIEWED.value
