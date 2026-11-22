"""Ledger emission for deterministic escalation claims."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

from ..errors import DuplicateDedup, FormatFail
from ..ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    Ledger,
    UlidFactory,
    dedup_key,
)
from ..ledger.ids import now_ms
from .graph import EscalationResult
from .models import EscalationPath

ESCALATION_SCHEMA = "ra.escalation.v1"
ESCALATION_CLAIM_KIND = "escalation_path"
ESCALATION_LEDGER_TYPE = "join"


@dataclass(frozen=True)
class EscalationEmitResult:
    """Claim ids created by an emission run, plus dedup hits."""

    emitted: tuple[str, ...]
    skipped: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"emitted": list(self.emitted), "skipped": list(self.skipped)}


class EscalationLedgerEmitter:
    """Persist escalation paths as ledger claims without duplicating paths."""

    def __init__(self, ledger: Ledger, *, claim_type: str = ESCALATION_LEDGER_TYPE) -> None:
        self._ledger = ledger
        self._ids = UlidFactory()
        self._claim_type = claim_type

    async def emit(
        self,
        result: EscalationResult,
        *,
        run_id: str | None = None,
        created: int | None = None,
        ttl_class: str = "run",
        limit: int | None = None,
    ) -> EscalationEmitResult:
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
        ):
            raise FormatFail("limit must be a positive integer")
        if not isinstance(result, EscalationResult):
            raise FormatFail("escalation emission requires an EscalationResult")
        paths = result.paths if limit is None else result.paths[:limit]
        for path in paths:
            _validate_claim_path(path)
        emitted: list[str] = []
        skipped: list[str] = []
        created_ms = now_ms() if created is None else created
        for rank, path in enumerate(paths, start=1):
            value_json = _claim_value_json(result, path, rank)
            data = value_json.encode("utf-8")
            dedup = dedup_key(ESCALATION_CLAIM_KIND, path.dedup_material(), ESCALATION_SCHEMA)
            existing = self._ledger.claim_by_dedup(dedup)
            if existing is not None:
                skipped.append(str(existing["id"]))
                continue
            claim_id = self._ids.new("cl")
            try:
                await self._ledger.create_claim(
                    ClaimInput(
                        claim_id=claim_id,
                        type=self._claim_type,
                        value_json=value_json,
                        confidence=path.reliability,
                        dedup_key=dedup,
                        created=created_ms,
                        run_id=run_id,
                        artifacts=(
                            ClaimArtifactInput(
                                artifact=ArtifactInput(
                                    kind="escalation_path",
                                    data=data,
                                    ttl_class=ttl_class,
                                ),
                                role="evidence",
                            ),
                        ),
                    )
                )
            except DuplicateDedup:
                existing = self._ledger.claim_by_dedup(dedup)
                if existing is None:
                    raise
                skipped.append(str(existing["id"]))
                continue
            emitted.append(claim_id)
        return EscalationEmitResult(tuple(emitted), tuple(skipped))


def _validate_claim_path(path: EscalationPath) -> None:
    if not isinstance(path, EscalationPath):
        raise FormatFail("escalation result paths must be EscalationPath values")
    privilege_gain = 0.0
    impact_gain = 0.0
    impact_score = 0.0
    reliability = 1.0
    cost = 0.0
    for edge in path.edges:
        privilege_gain += edge.privilege_delta
        impact_gain += edge.impact_delta
        impact_score += edge.impact_score()
        reliability *= edge.reliability
        cost += edge.cost
    expected = {
        "privilege_gain": privilege_gain,
        "impact_gain": impact_gain,
        "impact_score": impact_score,
        "reliability": reliability,
        "cost": cost,
    }
    actual = {
        "privilege_gain": path.privilege_gain,
        "impact_gain": path.impact_gain,
        "impact_score": path.impact_score,
        "reliability": path.reliability,
        "cost": path.cost,
    }
    for field, expected_value in expected.items():
        actual_value = actual[field]
        if not math.isclose(actual_value, expected_value, rel_tol=1e-9, abs_tol=1e-9):
            raise FormatFail(f"escalation path {field} is inconsistent with its edges")


def _claim_value_json(result: EscalationResult, path: EscalationPath, rank: int) -> str:
    payload = {
        "schema": ESCALATION_SCHEMA,
        "kind": ESCALATION_CLAIM_KIND,
        "claim_kind": "escalation",
        "rank": rank,
        "path": path.to_dict(),
        "analysis": {
            "nodes_considered": result.nodes_considered,
            "edges_considered": result.edges_considered,
            "expansions": result.expansions,
            "relaxations": result.relaxations,
            "truncated": result.truncated,
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


__all__ = [
    "ESCALATION_CLAIM_KIND",
    "ESCALATION_LEDGER_TYPE",
    "ESCALATION_SCHEMA",
    "EscalationEmitResult",
    "EscalationLedgerEmitter",
]
