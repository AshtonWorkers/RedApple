"""RA-SRF model and scoring tests."""

from ra.srf.models import (
    REACH_DECAY,
    EntryPoint,
    ReachRecord,
    compute_weight,
    parser_complexity,
    sort_entry_points,
)


def test_RA_SRF_002_weight_formula_and_bounds():
    # w = (1 + privilege_delta) * parser_complexity * reach_decay^hops
    assert compute_weight(0, 0.5, 1) == (1 + 0) * 0.5 * REACH_DECAY
    assert compute_weight(2, 1.0, 2) == (1 + 2) * 1.0 * (REACH_DECAY**2)
    assert compute_weight(99, 2.0, 0) == (1 + 5) * 1.0 * (REACH_DECAY**1)
    assert 0.0 <= parser_complexity("xpc-dictionary[a:string,b:int64]", 2) <= 1.0
    assert parser_complexity("xpc-dictionary[]", 0) == 0.0


def test_RA_SRF_005_deterministic_sort_and_json():
    ep1 = EntryPoint(
        ring_node="ring",
        name="com.apple.one",
        format_spec="xpc-dictionary[a:string]",
        reach_from=(ReachRecord("image:/a", 2, "dyld-cache"),),
        privilege_delta=1,
        parser_complexity=0.5,
    )
    ep2 = EntryPoint(
        ring_node="ring",
        name="com.apple.two",
        format_spec="xpc-dictionary[a:string,b:int64]",
        reach_from=(ReachRecord("sandbox-profile:p", 1, "src"),),
        privilege_delta=4,
        parser_complexity=0.5,
    )
    rows = [ep2.to_row(), ep1.to_row()]
    first = sort_entry_points(rows)
    second = sort_entry_points(list(reversed(rows)))
    assert first == second
    assert first[0]["name"] == "com.apple.two"
    assert [r["weight"] for r in first] == sorted([r["weight"] for r in first], reverse=True)
    assert ep1.id == ep1.id and ep1.id.startswith("ep_")
    assert ep1.to_row()["reach_from_json"].find('"hops":2') != -1
