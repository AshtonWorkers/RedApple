"""Retention sweep (RA-RET-001..003, I12)."""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import FormatFail
from ..ledger import Ledger
from ..ledger.ids import now_ms

_MS_PER_DAY = 86_400_000
MAX_SWEEP_BATCH = 500


@dataclass(frozen=True)
class RetentionPolicy:
    """TTL classes and corpus min-set floor."""

    ephemeral_days: int = 30
    run_days: int = 90
    batch_size: int = MAX_SWEEP_BATCH
    min_set: int = 0

    def __post_init__(self) -> None:
        if self.ephemeral_days < 1 or self.run_days < 1:
            raise FormatFail("retention TTL days must be positive")
        if self.batch_size < 1 or self.batch_size > MAX_SWEEP_BATCH:
            raise FormatFail(f"retention batch size must be 1..{MAX_SWEEP_BATCH}")
        if self.min_set < 0:
            raise FormatFail("retention min_set must be >= 0")


async def sweep(
    ledger: Ledger, policy: RetentionPolicy, *, now: int | None = None
) -> dict[str, int]:
    """Sweep ephemeral then run artifacts oldest-first, stopping at the min-set floor."""
    current = now_ms() if now is None else now
    cutoffs = {
        "ephemeral": current - policy.ephemeral_days * _MS_PER_DAY,
        "run": current - policy.run_days * _MS_PER_DAY,
    }
    deleted = {"ephemeral": 0, "run": 0, "batches": 0, "remaining": ledger.artifact_count()}
    for ttl_class in ("ephemeral", "run"):
        while True:
            allowance = ledger.artifact_count() - policy.min_set
            if allowance <= 0:
                deleted["remaining"] = ledger.artifact_count()
                return deleted
            candidates = ledger.retention_candidates(
                ttl_class, cutoff=cutoffs[ttl_class], limit=min(policy.batch_size, allowance)
            )
            if not candidates:
                break
            ids = [str(row["id"]) for row in candidates]
            removed = await ledger.delete_artifacts(ids, min_set=policy.min_set)
            deleted[ttl_class] += removed
            deleted["batches"] += 1
            deleted["remaining"] = ledger.artifact_count()
            if removed == 0:
                break
    return deleted
