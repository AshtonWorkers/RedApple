"""Model tests for RA-SFC: ids, serialization, tolerant parsing."""

import json

from ra.srf.models import ReachRecord
from ra.surface.models import (
    CAPABILITY_RISK,
    CAPABILITY_RISK_TOTAL,
    XPC_RISKY_TYPES,
    Capability,
    ExpandedTarget,
    IngressClass,
    SurfaceTarget,
    SurfaceTier,
    TargetList,
    base_weight_for,
    canonical_sha256,
    parse_reach_records,
    row_image_paths,
    stable_id,
    with_rank,
)


def test_RA_SFC_stable_id_is_deterministic():
    assert stable_id("surf", "ring", "name") == stable_id("surf", "ring", "name")
    assert stable_id("surf", "ring", "name") != stable_id("surf", "ring", "other")
    assert stable_id("surf", "ring", "name").startswith("surf_")


def _expanded(name: str = "com.apple.test.service") -> ExpandedTarget:
    return ExpandedTarget(
        ring_node="ring",
        name=name,
        reach_from=(ReachRecord(source="image:/x", hops=2, via="dyld-cache"),),
        base_weight=0.5,
        privilege_delta=1,
        parser_complexity=0.5,
    )


def test_RA_SFC_surface_target_dict_round_trip():
    target = SurfaceTarget(
        ring_node="ring",
        name="com.apple.test.service",
        id=stable_id("surf", "ring", "com.apple.test.service"),
        weight=1.5,
        base_weight=0.5,
        tier=SurfaceTier.A,
        rank=3,
        privilege_delta=2,
        parser_complexity=0.25,
        hops=1,
        capabilities=(Capability.FILE_WRITE, Capability.NETWORK_OUTBOUND),
        xpc_risky_fields=2,
        ingress=IngressClass.NETWORK,
        rationale="score=1.5",
        entry_point_id="ep_abc",
        reach_from=(ReachRecord(source="sandbox-profile:p", hops=1, via="src"),),
    )
    data = target.to_dict()
    json.dumps(data)  # must be JSON-able
    rebuilt = SurfaceTarget.from_dict(data)
    assert rebuilt == target


def test_RA_SFC_target_list_tier_counts_and_rows():
    t1 = with_rank(
        SurfaceTarget(
            ring_node="ring",
            name="a",
            id="surf_1",
            weight=2.0,
            base_weight=2.0,
            tier=SurfaceTier.S,
            rank=1,
            privilege_delta=1,
            parser_complexity=0.5,
            hops=1,
            capabilities=(),
            xpc_risky_fields=0,
            ingress=IngressClass.LOCAL,
            rationale="r",
            entry_point_id="",
            reach_from=(),
        ),
        1,
    )
    t2 = with_rank(
        SurfaceTarget(
            ring_node="ring",
            name="b",
            id="surf_2",
            weight=0.1,
            base_weight=0.1,
            tier=SurfaceTier.C,
            rank=2,
            privilege_delta=0,
            parser_complexity=0.5,
            hops=1,
            capabilities=(),
            xpc_risky_fields=0,
            ingress=IngressClass.UNKNOWN,
            rationale="r",
            entry_point_id="",
            reach_from=(),
        ),
        2,
    )
    tl = TargetList(ring_node="ring", targets=(t1, t2), sha256="deadbeef")
    assert tl.tier_counts() == {"S": 1, "A": 0, "B": 0, "C": 1}
    rows = tl.rows
    assert [r["id"] for r in rows] == ["surf_1", "surf_2"]
    assert rows[0]["weight"] == 2.0
    assert tl.to_dict()["count"] == 2


def test_RA_SFC_canonical_sha256_is_order_sensitive():
    rows = [{"id": "a", "weight": 1.0}, {"id": "b", "weight": 2.0}]
    # same order -> same hash (mirrors compiler digest over sorted rows)
    assert canonical_sha256(rows) == canonical_sha256([dict(r) for r in rows])
    # different order or content -> different hash
    assert canonical_sha256(rows) != canonical_sha256(list(reversed(rows)))
    assert canonical_sha256(rows) != canonical_sha256([rows[0]])


def test_RA_SFC_base_weight_matches_compiler_formula():
    assert base_weight_for(1, 0.5, 2) == (1 + 1) * 0.5 * (0.7**2)


def test_RA_SFC_parse_reach_records_valid():
    raw = json.dumps(
        [
            {"source": "image:/x", "hops": 2, "via": "dyld-cache"},
            {"source": "sandbox-profile:p", "hops": 1},
        ]
    )
    records = parse_reach_records(raw)
    assert records == (
        ReachRecord(source="image:/x", hops=2, via="dyld-cache"),
        ReachRecord(source="sandbox-profile:p", hops=1, via=""),
    )


def test_RA_SFC_parse_reach_records_malformed_inputs():
    assert parse_reach_records(None) == ()
    assert parse_reach_records("") == ()
    assert parse_reach_records(123) == ()
    assert parse_reach_records("not json") == ()
    assert parse_reach_records('{"source": "x"}') == ()
    assert parse_reach_records('["just-a-string"]') == ()
    assert parse_reach_records('[{"source": "x", "hops": true}]') == ()
    assert parse_reach_records('[{"source": 1, "hops": 2}]') == ()


def test_RA_SFC_row_image_paths():
    reach = (
        ReachRecord(source="image:/System/Library/Safari.framework/Safari", hops=2),
        ReachRecord(source="image:/usr/lib/system/libxpc.dylib", hops=2),
        ReachRecord(source="sandbox-profile:p", hops=1),
    )
    assert row_image_paths(reach) == (
        "/System/Library/Safari.framework/Safari",
        "/usr/lib/system/libxpc.dylib",
    )
    assert row_image_paths(()) == ()


def test_RA_SFC_expanded_target_id_and_hops():
    target = _expanded()
    assert target.id == stable_id("surf", "ring", "com.apple.test.service")
    assert target.hops == 2
    empty = ExpandedTarget(
        ring_node="ring", name="n", reach_from=(), base_weight=0.0,
        privilege_delta=0, parser_complexity=0.0,
    )
    assert empty.hops == 1


def test_RA_SFC_enums_and_constants():
    assert {t.value for t in SurfaceTier} == {"S", "A", "B", "C"}
    assert {i.value for i in IngressClass} == {"zero-click", "network", "local", "unknown"}
    assert Capability.NETWORK_INBOUND.value == "network-inbound"
    assert frozenset({"endpoint", "data", "uuid", "int64", "uint64"}) == XPC_RISKY_TYPES
    assert CAPABILITY_RISK_TOTAL == sum(CAPABILITY_RISK.values()) > 0
