"""Deterministic prioritization of expanded surface targets (RA-SFC-004/005).

The priority score refines the compiler's base weight with sandbox capability
risk, XPC risky-field density, and attacker-ingress class. Ordering is total and
ends in ``id`` (I5); tiers are assigned from absolute score thresholds.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..srf.models import clamp_privilege_delta, reach_from_json
from .expand import capability_risk_total, classify_ingress
from .models import (
    CAPABILITY_RISK_TOTAL,
    ExpandedTarget,
    IngressClass,
    SurfaceTarget,
    SurfaceTier,
    TargetList,
    canonical_sha256,
    clamp_parser_complexity,
    parse_reach_records,
    row_image_paths,
    safe_float,
    safe_int,
    stable_id,
    with_rank,
)


@dataclass(frozen=True)
class RankConfig:
    """Tunable scoring weights; defaults are deterministic and documented."""

    capability_weight: float = 0.30
    xpc_risk_weight: float = 0.20
    zero_click_mult: float = 1.6
    network_mult: float = 1.25
    local_mult: float = 1.0
    unknown_mult: float = 1.0
    xpc_risk_norm: float = 6.0
    capability_norm: float = CAPABILITY_RISK_TOTAL
    tier_thresholds: tuple[tuple[SurfaceTier, float], ...] = (
        (SurfaceTier.S, 1.20),
        (SurfaceTier.A, 0.55),
        (SurfaceTier.B, 0.18),
        (SurfaceTier.C, 0.0),
    )

    def __post_init__(self) -> None:
        for name in (
            "capability_weight",
            "xpc_risk_weight",
            "zero_click_mult",
            "network_mult",
            "local_mult",
            "unknown_mult",
            "xpc_risk_norm",
            "capability_norm",
        ):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value < 0.0:
                object.__setattr__(self, name, 0.0)

    def ingress_multiplier(self, ingress: IngressClass) -> float:
        if ingress is IngressClass.ZERO_CLICK:
            return self.zero_click_mult
        if ingress is IngressClass.NETWORK:
            return self.network_mult
        if ingress is IngressClass.LOCAL:
            return self.local_mult
        return self.unknown_mult


def _capability_mass(config: RankConfig, risk_total: float) -> float:
    if config.capability_norm <= 0:
        return 0.0
    return min(1.0, risk_total / config.capability_norm)


def _xpc_mass(config: RankConfig, risky_fields: int) -> float:
    if config.xpc_risk_norm <= 0:
        return 0.0
    return min(1.0, max(0, risky_fields) / config.xpc_risk_norm)


def _base_weight(target: ExpandedTarget) -> float:
    return max(0.0, safe_float(target.base_weight))


def score_target(target: ExpandedTarget, config: RankConfig) -> tuple[float, IngressClass]:
    """Priority score and ingress class for one expanded target."""
    ingress = classify_ingress(target.image_paths)
    cap_mass = _capability_mass(config, capability_risk_total(target.capabilities))
    xpc_mass = _xpc_mass(config, target.xpc_risky_fields)
    score = (
        _base_weight(target)
        * (1.0 + config.capability_weight * cap_mass)
        * (1.0 + config.xpc_risk_weight * xpc_mass)
        * config.ingress_multiplier(ingress)
    )
    return score, ingress


def tier_for_score(score: float, config: RankConfig) -> SurfaceTier:
    """Highest tier whose threshold ``score`` meets; ``C`` when none match."""
    best = SurfaceTier.C
    best_threshold = float("-inf")
    for tier, threshold in config.tier_thresholds:
        if score >= threshold and threshold > best_threshold:
            best = tier
            best_threshold = threshold
    return best


def _rationale(
    target: ExpandedTarget,
    score: float,
    ingress: IngressClass,
    tier: SurfaceTier,
) -> str:
    caps = ",".join(sorted(c.value for c in target.capabilities)) or "-"
    return (
        f"score={score:.6f} base={target.base_weight:.6f} "
        f"priv={target.privilege_delta} hops={target.hops} "
        f"caps={caps} xpc_risk={target.xpc_risky_fields} "
        f"ingress={ingress.value} tier={tier.value}"
    )


def _surface_sort_key(target: SurfaceTarget) -> tuple[object, ...]:
    return (
        -target.weight,
        target.id,
        target.name,
        target.ring_node,
        target.base_weight,
        target.privilege_delta,
        target.parser_complexity,
        target.hops,
        target.xpc_risky_fields,
        target.ingress.value,
        tuple(c.value for c in target.capabilities),
        target.entry_point_id,
        reach_from_json(target.reach_from),
    )


def _to_surface_target(
    target: ExpandedTarget, config: RankConfig, rank: int
) -> SurfaceTarget:
    score, ingress = score_target(target, config)
    tier = tier_for_score(score, config)
    return SurfaceTarget(
        ring_node=target.ring_node,
        name=target.name,
        id=target.id,
        weight=score,
        base_weight=_base_weight(target),
        tier=tier,
        rank=rank,
        privilege_delta=clamp_privilege_delta(safe_int(target.privilege_delta)),
        parser_complexity=clamp_parser_complexity(target.parser_complexity),
        hops=target.hops,
        capabilities=tuple(sorted(target.capabilities, key=lambda c: c.value)),
        xpc_risky_fields=max(0, safe_int(target.xpc_risky_fields)),
        ingress=ingress,
        rationale=_rationale(target, score, ingress, tier),
        entry_point_id=target.entry_point_id,
        reach_from=target.reach_from,
    )


def rank_targets(
    expanded: Iterable[ExpandedTarget],
    config: RankConfig | None = None,
    *,
    ring_node: str = "",
) -> TargetList:
    """Score, tier, and totally order expanded targets (RA-SFC-004).

    The final sort key is ``(-weight, id)`` so ordering is total (I5). ``ring_node``
    is only needed when ``expanded`` is empty.
    """
    cfg = config or RankConfig()
    materialized = list(expanded)
    node = materialized[0].ring_node if materialized else ring_node
    scored = [_to_surface_target(t, cfg, rank=0) for t in materialized]
    scored.sort(key=_surface_sort_key)
    final = tuple(with_rank(s, rank=i + 1) for i, s in enumerate(scored))
    rows = [s.to_row() for s in final]
    return TargetList(ring_node=node, targets=final, sha256=canonical_sha256(rows))


def thin_targets_from_rows(
    rows: Iterable[Mapping[str, Any]], config: RankConfig | None = None
) -> tuple[SurfaceTarget, ...]:
    """Re-derive ranked targets from persisted ``entry_point`` rows.

    Persisted rows carry the priority score in ``weight``; capabilities and XPC
    detail are compile-time-only and come back empty here. Ordering and tiers are
    recomputed deterministically.
    """
    cfg = config or RankConfig()
    parsed: list[SurfaceTarget] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        reach = parse_reach_records(row.get("reach_from_json"))
        images = row_image_paths(reach)
        weight = max(0.0, safe_float(row.get("weight")))
        hops = max(1, min((r.hops for r in reach), default=1))
        ingress = classify_ingress(images)
        tier = tier_for_score(weight, cfg)
        priv = safe_int(row.get("privilege_delta"))
        complexity = safe_float(row.get("parser_complexity"))
        entry_id = str(row.get("id", ""))
        node = str(row.get("ring_node", ""))
        parsed.append(
            SurfaceTarget(
                ring_node=node,
                name=name,
                id=entry_id or stable_id("surf", node, name),
                weight=weight,
                base_weight=weight,
                tier=tier,
                rank=0,
                privilege_delta=clamp_privilege_delta(priv),
                parser_complexity=clamp_parser_complexity(complexity),
                hops=hops,
                capabilities=(),
                xpc_risky_fields=0,
                ingress=ingress,
                rationale=(
                    f"score={weight:.6f} base={weight:.6f} priv={priv} hops={hops} "
                    f"caps=- xpc_risk=0 ingress={ingress.value} tier={tier.value}"
                ),
                entry_point_id=entry_id,
                reach_from=reach,
            )
        )
    parsed.sort(key=_surface_sort_key)
    return tuple(with_rank(s, rank=i + 1) for i, s in enumerate(parsed))
