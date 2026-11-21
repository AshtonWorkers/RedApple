"""RA-SRF model and scoring tests."""

from ra.srf.models import (
    REACH_DECAY,
    EntryPoint,
    ReachRecord,
    XPCField,
    XPCShape,
    clamp_privilege_delta,
    compute_weight,
    parser_complexity,
    reach_from_json,
    shannon_entropy,
    sort_entry_points,
    xpc_format_spec,
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


def test_RA_SRF_002_reach_json_entropy_and_complexity_edges():
    records = [
        ReachRecord("image:/b", 2),
        ReachRecord("image:/a", 1, "via-z"),
        ReachRecord("image:/a", 1),
    ]
    assert reach_from_json(records) == (
        '[{"hops":1,"source":"image:/a","via":""},'
        '{"hops":1,"source":"image:/a","via":"via-z"},'
        '{"hops":2,"source":"image:/b","via":""}]'
    )
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-12
    assert parser_complexity("abcdefghij", 10000) == 1.0
    assert parser_complexity("", 5) == 0.0
    assert clamp_privilege_delta(-2) == 0
    assert clamp_privilege_delta(9) == 5


def test_RA_SRF_002_weight_clamps_and_empty_reach_defaults():
    assert compute_weight(-1, -1, -5) == 0.0
    assert compute_weight(2, 2.0, 0) == (1 + 2) * 1.0 * REACH_DECAY
    ep = EntryPoint(
        ring_node="ring",
        name="com.apple.empty",
        format_spec="xpc-dictionary[]",
        reach_from=(),
        privilege_delta=0,
        parser_complexity=0.5,
    )
    assert ep.hops == 3
    assert ep.weight == compute_weight(0, 0.5, 3)
    assert ep.to_row()["reach_from_json"] == "[]"


def test_RA_SRF_002_xpc_shape_properties_and_spec_sorting():
    shape = XPCShape(
        image_path="/img",
        fields=(XPCField("b", "int64"), XPCField("a", "string")),
    )
    assert shape.format_spec == "xpc-dictionary[a:string,b:int64]"
    assert shape.field_count == 2
    assert shape.parser_complexity == parser_complexity(shape.format_spec, 2)
    assert xpc_format_spec([]) == "xpc-dictionary[]"
    empty = XPCShape(image_path="/img", fields=())
    assert empty.field_count == 1
