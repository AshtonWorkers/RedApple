"""Join-density monitoring for chain search (RA-CHN-004)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..errors import DensityLow, FormatFail
from ..ledger import Ledger
from ..ledger.ids import now_ms
from .models import DENSITY_FLOOR_PER_HOUR, DENSITY_WINDOW_MS, DensityReport

_MS_PER_HOUR = 3_600_000


def density_report(
    rows: Sequence[Mapping[str, Any]],
    *,
    now: int,
    ingress_count: int,
    window_ms: int = DENSITY_WINDOW_MS,
    floor_per_hour: float = DENSITY_FLOOR_PER_HOUR,
) -> DensityReport:
    """Compute joins per ingress per hour over a trailing window."""
    if window_ms <= 0:
        raise FormatFail("density window must be positive")
    if ingress_count < 0:
        raise FormatFail("ingress count must be non-negative")
    cutoff = now - window_ms
    count = sum(1 for row in rows if int(row.get("created", 0)) >= cutoff)
    hours = window_ms / _MS_PER_HOUR
    denominator = max(1, ingress_count) * hours
    density = count / denominator
    return DensityReport(
        join_count=count,
        ingress_count=ingress_count,
        window_ms=window_ms,
        density_per_hour=density,
        floor_per_hour=floor_per_hour,
        low=density < floor_per_hour,
    )


async def check_join_density(
    ledger: Ledger,
    *,
    now: int | None = None,
    ingress_count: int,
    window_ms: int = DENSITY_WINDOW_MS,
    floor_per_hour: float = DENSITY_FLOOR_PER_HOUR,
    limit: int = 100_000,
) -> DensityReport:
    """Raise DENSITY_LOW when join density per ingress is below floor."""
    at = now_ms() if now is None else now
    cutoff = at - window_ms
    rows = ledger.joins(created_after=cutoff, limit=limit)
    report = density_report(
        rows,
        now=at,
        ingress_count=ingress_count,
        window_ms=window_ms,
        floor_per_hour=floor_per_hour,
    )
    if report.low:
        raise DensityLow(
            "join density "
            f"{report.density_per_hour:.6f}/h below floor {report.floor_per_hour:.6f}/h "
            f"for {report.window_ms} ms across {report.ingress_count} ingress points"
        )
    return report
