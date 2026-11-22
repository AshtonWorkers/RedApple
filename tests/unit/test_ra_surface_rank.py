"""Ranking tests for RA-SFC-004/005: scoring, tiers, total deterministic order."""

import random

from ra.srf.models import ReachRecord
from ra.surface.models import (
    CAPABILITY_RISK_TOTAL,
    Capability,
    ExpandedTarget,
    IngressClass,
    SurfaceTier,
)
from ra.surface.rank import (
    RankConfig,
    rank_targets,
    score_target,
    thin_targets_from_rows,
    tier_for_score,
)


def _expanded(
    name: str,
    *,
    base_weight: float = 1.0,
    capabilities: frozenset = frozenset(),
    xpc_risky_fields: int = 0,
    image_paths: tuple = (),
    ring_node: str = "ring",
) -> ExpandedTarget:
    return ExpandedTarget(
        ring_node=ring_node,
        name=name,
        reach_from=(ReachRecord(source="image:/x", hops=2, via="dyld-cache"),),
        base_weight=base_weight,
        privilege_delta=1,
        parser_complexity=0.5,
        capabilities=capabilities,
        xpc_risky_fields=xpc_risky_fields,
        image_paths=image_paths,
    )


def test_RA_SFC_004_score_target_components():
    config = RankConfig()
    plain = _expanded("plain", base_weight=1.0)
    score_plain, ingress_plain = score_target(plain, config)
    assert ingress_plain == IngressClass.UNKNOWN
    assert score_plain == 1.0

    risky = _expanded(
        "risky",
        base_weight=1.0,
        capabilities=frozenset({Capability.NETWORK_INBOUND, Capability.MACH_PRIV}),
        xpc_risky_fields=6,
        image_paths=("/System/Library/Safari.framework/Safari",),
    )
    score_risky, ingress_risky = score_target(risky, config)
    assert ingress_risky == IngressClass.ZERO_CLICK
    cap_mass = (3.0 + 3.0) / CAPABILITY_RISK_TOTAL
    expected = 1.0 * (1 + 0.30 * cap_mass) * (1 + 0.20 * 1.0) * 1.6
    assert abs(score_risky - expected) < 1e-9
    assert score_risky > score_plain


def test_RA_SFC_004_zero_norm_config_disables_multipliers():
    config = RankConfig(capability_norm=0.0, xpc_risk_norm=0.0)
    target = _expanded(
        "plain",
        base_weight=1.0,
        capabilities=frozenset({Capability.NETWORK_INBOUND}),
        xpc_risky_fields=6,
        image_paths=("/System/Library/Safari.framework/Safari",),
    )
    score, ingress = score_target(target, config)
    # capability/xpc masses are 0; only the zero-click ingress multiplier remains
    assert ingress == IngressClass.ZERO_CLICK
    assert abs(score - 1.0 * 1.6) < 1e-9


def test_RA_SFC_004_ingress_multipliers():
    config = RankConfig()
    cases = {
        IngressClass.ZERO_CLICK: config.zero_click_mult,
        IngressClass.NETWORK: config.network_mult,
        IngressClass.LOCAL: config.local_mult,
        IngressClass.UNKNOWN: config.unknown_mult,
    }
    for ingress, mult in cases.items():
        assert config.ingress_multiplier(ingress) == mult


def test_RA_SFC_004_tier_thresholds():
    config = RankConfig()
    assert tier_for_score(1.2, config) == SurfaceTier.S
    assert tier_for_score(0.55, config) == SurfaceTier.A
    assert tier_for_score(0.18, config) == SurfaceTier.B
    assert tier_for_score(0.0, config) == SurfaceTier.C
    assert tier_for_score(-1.0, config) == SurfaceTier.C
    assert tier_for_score(100.0, config) == SurfaceTier.S


def test_RA_SFC_004_rank_targets_total_order_and_ranks():
    targets = [
        _expanded("com.apple.c", base_weight=0.1),
        _expanded("com.apple.a", base_weight=3.0),
        _expanded("com.apple.b", base_weight=1.0),
    ]
    result = rank_targets(targets)
    assert result.ring_node == "ring"
    assert [t.rank for t in result.targets] == [1, 2, 3]
    weights = [t.weight for t in result.targets]
    assert weights == sorted(weights, reverse=True)
    assert result.targets[0].name == "com.apple.a"
    assert result.sha256 == rank_targets(targets).sha256


def test_RA_SFC_005_tie_break_ends_in_id():
    # identical scores force the id tiebreak
    t1 = _expanded("com.apple.one", base_weight=1.0)
    t2 = _expanded("com.apple.two", base_weight=1.0)
    result = rank_targets([t2, t1])
    ids = [t.id for t in result.targets]
    assert ids == sorted(ids)  # ascending id among equal weights
    assert result.targets[0].weight == result.targets[1].weight


def test_RA_SFC_005_empty_input_uses_ring_node():
    result = rank_targets([], ring_node="empty-ring")
    assert result.targets == ()
    assert result.ring_node == "empty-ring"
    assert result.rows == ()
    assert result.sha256


def test_RA_SFC_005_property_determinism_under_shuffle():
    rng = random.Random(20261122)
    pool_caps = [
        frozenset(),
        frozenset({Capability.NETWORK_OUTBOUND}),
        frozenset({Capability.NETWORK_INBOUND, Capability.MACH_PRIV}),
        frozenset({Capability.FILE_WRITE, Capability.IOKIT, Capability.PROCESS_EXEC}),
    ]
    pool_paths = [
        (),
        ("/usr/lib/system/libxpc.dylib",),
        ("/System/Library/Bluetooth.framework/Bluetooth",),
        ("/System/Library/Safari.framework/Safari",),
    ]
    targets = [
        _expanded(
            f"com.apple.prop.{i:03d}",
            base_weight=rng.uniform(0.0, 4.0),
            capabilities=rng.choice(pool_caps),
            xpc_risky_fields=rng.randint(0, 8),
            image_paths=rng.choice(pool_paths),
        )
        for i in range(60)
    ]
    first = rank_targets(targets)
    shuffled = list(targets)
    rng.shuffle(shuffled)
    second = rank_targets(shuffled)
    assert first.sha256 == second.sha256
    assert [t.id for t in first.targets] == [t.id for t in second.targets]
    assert [t.rank for t in first.targets] == list(range(1, 61))
    # total order: for every adjacent pair, (-weight, id) is non-increasing
    keys = [(-t.weight, t.id) for t in first.targets]
    assert keys == sorted(keys)


def test_RA_SFC_005_thin_targets_from_rows_round_trip():
    safari_reach = (ReachRecord(source="image:/System/Library/Safari.framework/Safari", hops=2),)
    targets = [
        ExpandedTarget(
            ring_node="ring",
            name="com.apple.high",
            reach_from=safari_reach,
            base_weight=2.0,
            privilege_delta=1,
            parser_complexity=0.5,
            image_paths=("/System/Library/Safari.framework/Safari",),
        ),
        _expanded("com.apple.low", base_weight=0.05),
    ]
    ranked = rank_targets(targets)
    rows = list(ranked.rows)
    thin = thin_targets_from_rows(rows)
    assert [t.id for t in thin] == [t.id for t in ranked.targets]
    assert [t.weight for t in thin] == [t.weight for t in ranked.targets]
    assert [t.rank for t in thin] == [1, 2]
    # persisted rows carry no capability/XPC detail
    assert all(t.capabilities == () for t in thin)
    assert all(t.xpc_risky_fields == 0 for t in thin)
    # ingress is re-derived from reach records
    assert thin[0].ingress == IngressClass.ZERO_CLICK


def test_RA_SFC_005_thin_targets_failure_injection():
    rows = [
        "not-a-mapping",
        {},
        {"name": 7},
        {"name": "com.apple.bad", "reach_from_json": "not json"},
        {"name": "com.apple.good", "weight": "NaN", "privilege_delta": None},
    ]
    thin = thin_targets_from_rows(rows)
    assert len(thin) == 2
    assert all(t.weight == 0.0 for t in thin)
    assert thin_targets_from_rows([]) == ()
