import json
import math
import random

import pytest

from ra.chain import (
    MAX_ESCALATION_DELTA,
    MAX_PRICING_FACTOR,
    ChainEdge,
    ChainGraph,
    ChainNode,
    ChainPath,
    ChainSearchConfig,
    DefaultPolicyAdvisor,
    JoinAssertion,
    JoinPricer,
    JoinProgram,
    NullPrimitiveProvider,
    PrimitiveProfile,
    StaticDupeOracle,
    StaticPrimitiveProvider,
    build_graph,
    check_join_density,
    density_report,
    price_chain_path,
    price_chain_paths,
    price_join_row,
    price_join_rows,
    search_chain,
    select_subfactory_candidates,
)
from ra.chain.ports import DupeOracle, PolicyAdvisor, PrimitiveProvider
from ra.chain.pricing import _path_escalation
from ra.chain.search import (
    _as_object,
    _bool_field,
    _entry_references,
    _float_field,
    _int_field,
    _join_edge,
    _linked_zero_click_entry,
    _node_from_claim,
    _protection_flags,
    _reach_records,
)
from ra.errors import FormatFail
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger
from ra.ledger.ids import dedup_key
from tests.conftest import run


def node(
    node_id: str,
    *,
    zero_click: bool = False,
    persistence: bool = False,
    privilege: int = 0,
    impact: int = 0,
    pac: bool = False,
    sptm: bool = False,
    ingress: float = 1.0,
) -> ChainNode:
    return ChainNode(
        id=node_id,
        claim_id=node_id,
        claim_type="rung",
        privilege_delta=privilege,
        impact_delta=impact,
        pac=pac,
        sptm=sptm,
        persistence=persistence,
        zero_click=zero_click,
        ingress_weight=ingress,
    )


def edge(edge_id: str, a: str, b: str, lower: float = 1.0) -> ChainEdge:
    return ChainEdge(id=edge_id, a_claim=a, b_claim=b, lower_bound=lower, state="live")


def path(node_ids: tuple[str, ...], edge_ids: tuple[str, ...], **kwargs) -> ChainPath:
    values = {
        "cost": 1.0,
        "join_count": len(edge_ids),
        "ingress_weight": 1.0,
        "min_lower_bound": 1.0,
        "weakest_join_id": edge_ids[0] if edge_ids else None,
        "total_privilege_delta": 0,
        "total_impact_delta": 0,
    }
    values.update(kwargs)
    return ChainPath(node_ids=node_ids, edge_ids=edge_ids, **values)


def join_row(join_id: str, lower: float = 0.5, created: int = 1) -> dict:
    return {
        "id": join_id,
        "a_claim": "a",
        "b_claim": "b",
        "state": "research",
        "created": created,
        "reliability": lower,
        "lower_bound": lower,
    }


def claim_input(claim_id: str, value: object, claim_type: str = "rung") -> ClaimInput:
    raw = value if isinstance(value, str) else json.dumps(value)
    return ClaimInput(
        claim_id=claim_id,
        type=claim_type,
        value_json=raw,
        confidence=0.5,
        dedup_key=dedup_key("bug_class", "b" * 64, claim_id),
        created=1,
        artifacts=(ClaimArtifactInput(ArtifactInput(kind="crash", data=b"chain"), role="evidence"),),
    )


def test_model_properties_and_escalation_score():
    prog = JoinProgram(
        "j",
        "a",
        "b",
        (JoinAssertion("address_validity", "addr"),),
        "repro",
    )
    assert prog.assertion_kinds == ("address_validity",)
    item = path(("s", "t"), ("e",), total_privilege_delta=2, total_impact_delta=3)
    assert item.source == "s" and item.target == "t"
    assert item.total_escalation_delta == 5
    assert item.escalation_score == pytest.approx(5 * 1.0 * 1.0)
    assert node("n", pac=True).protected and node("m", sptm=True).protected
    assert node("d", privilege=1, impact=2).escalation_delta == 3


def test_protocol_and_stub_bodies():
    assert PrimitiveProvider.profile(object(), "c", "t", {}) is None
    assert DupeOracle.score(object(), "c") is None
    assert PolicyAdvisor.join_cost_usd_micro(object()) is None
    assert PolicyAdvisor.subfactory_cost_usd_micro(object()) is None
    assert PolicyAdvisor.subfactory_floor(object()) is None
    assert NullPrimitiveProvider().profile("c", "t", {}) is None
    with pytest.raises(FormatFail):
        StaticDupeOracle({"x": 2.0}).score("x")
    policy = DefaultPolicyAdvisor()
    assert policy.subfactory_cost_usd_micro() == 300_000
    assert policy.subfactory_floor() == pytest.approx(0.90)


def test_density_window_validation_and_success():
    with pytest.raises(FormatFail):
        density_report([], now=1, ingress_count=1, window_ms=0)

    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            now = 10_000_000
            left = await ledger.create_claim(claim_input("cl_a", {}, "rung"))
            right = await ledger.create_claim(claim_input("cl_b", {}, "rung"))
            await ledger.insert_join(
                {
                    "join_id": "j_density",
                    "a_claim": left,
                    "b_claim": right,
                    "invariants_json": "[]",
                    "reliability": 1.0,
                    "lower_bound": 1.0,
                    "state": "live",
                    "created": now,
                }
            )
            report = await check_join_density(
                ledger, now=now, ingress_count=1, window_ms=90 * 60 * 1000
            )
            assert not report.low and report.join_count == 1
        finally:
            await ledger.close()

    run(body())


def test_chain_search_config_validation():
    valid = ChainSearchConfig(max_joins=3, max_paths=2, dead_end_pruning=False)
    valid.validate()
    bad = [
        {"max_nodes": 0},
        {"deadline_s": 0.0},
        {"edge_floor": -0.1},
        {"pac_sptm_multiplier": 0.9},
        {"max_joins": 0},
        {"max_paths": 0},
        {"edge_floor": math.inf},
        {"pac_sptm_multiplier": math.inf},
    ]
    for kwargs in bad:
        with pytest.raises(FormatFail):
            ChainSearchConfig(**kwargs).validate()


def test_search_value_parsers():
    assert _as_object(None) == {} and _as_object("") == {} and _as_object("null") == {}
    assert _as_object("[1]") == {} and _as_object('{"a": 1}') == {"a": 1}
    with pytest.raises(FormatFail):
        _as_object("{bad")
    value = {"flag": "yes", "off": "false", "num": 1, "text": "x", "inf": math.inf}
    assert _bool_field(value, "flag") and _bool_field(value, "num") is False
    assert _bool_field(value, "off") is False and _bool_field(value, "text") is False
    assert _int_field(value, "num") == 1 and _int_field(value, "flag") is None
    assert _float_field(value, "num") == 1.0 and _float_field(value, "flag") is None
    assert _float_field(value, "text") is None and _float_field(value, "inf") is None
    assert _protection_flags({}) == (False, False)
    assert _protection_flags({"pac": True}) == (True, False)
    assert _protection_flags({"sptm": "on"}) == (False, True)
    assert _protection_flags({"protections": ["PAC", "pointer_authentication"]}) == (
        True,
        False,
    )
    assert _protection_flags({"protections": ["sptm_protect"]}) == (False, True)
    assert _protection_flags({"protections": "pac"}) == (False, False)
    assert _reach_records({}) == []
    assert _reach_records({"reach_from_json": 1}) == []
    assert _reach_records({"reach_from_json": ""}) == []
    assert _reach_records({"reach_from_json": "{bad"}) == []
    assert _reach_records({"reach_from_json": json.dumps({"x": 1})}) == []
    assert _reach_records(
        {"reach_from_json": json.dumps([{"source": "net", "via": "zero-click", "hops": 1}])}
    ) == [{"source": "net", "via": "zero-click", "hops": 1}]
    entry = {"id": "ep", "name": "zero"}
    assert _entry_references({"entry_point_id": "ep"}, entry)
    assert _entry_references({"entryPointId": "ep"}, entry)
    assert _entry_references({"entry_point": "zero"}, entry)
    assert _entry_references({"entry_point_name": "zero"}, entry)
    assert _entry_references({"surface": "zero"}, entry)
    assert _entry_references({"entry_points": ["ep"]}, entry)
    assert _entry_references({"entryPoints": ["zero"]}, entry)
    assert not _entry_references({"entry_point_id": "other"}, entry)
    zero = {"id": "z", "reach_from_json": json.dumps([{"source": "x", "via": "zero_click"}])}
    click = {"id": "c", "reach_from_json": json.dumps([{"source": "x", "via": "click"}])}
    assert _linked_zero_click_entry({"entry_point_id": "z"}, [click, zero]) == zero
    assert _linked_zero_click_entry({"entry_point_id": "c"}, [click, zero]) is None


def test_join_edge_validation():
    base = {"id": "j", "a_claim": "a", "b_claim": "b", "state": "live"}
    for lower in (None, True, 0, 1.2, "1"):
        assert _join_edge({**base, "lower_bound": lower}) is None
    edge_row = _join_edge(
        {**base, "lower_bound": 0.5, "reliability": "bad", "created": True}
    )
    assert edge_row is not None and edge_row.reliability is None and edge_row.created == 0


def test_node_from_claim_profiles_entry_points_and_clamps():
    claim = {"id": "cl", "type": "rung", "value_json": json.dumps({"impact_delta": "bad"})}
    profile = PrimitiveProfile(privilege_delta=2, impact_delta=3, ingress_weight=2e6)
    built = _node_from_claim(claim, StaticPrimitiveProvider({"cl": profile}), [])
    assert built.privilege_delta == 2 and built.impact_delta == 3
    assert built.ingress_weight == pytest.approx(MAX_PRICING_FACTOR)
    ep = {
        "id": "ep1",
        "reach_from_json": json.dumps([{"source": "net", "via": "zero_click", "hops": 0}]),
        "privilege_delta": 7,
        "weight": 10.0,
    }
    linked = _node_from_claim(
        {"id": "cl2", "type": "bug_class", "value_json": json.dumps({"entry_point_id": "ep1"})},
        NullPrimitiveProvider(),
        [ep],
    )
    assert linked.zero_click and linked.entry_point_id == "ep1"
    assert linked.privilege_delta == 7 and linked.ingress_weight == pytest.approx(10.0)
    clamped = _node_from_claim(
        {
            "id": "cl3",
            "type": "rung",
            "value_json": json.dumps(
                {"privilege_delta": MAX_ESCALATION_DELTA + 5, "impact_delta": -3}
            ),
        },
        NullPrimitiveProvider(),
        [],
    )
    assert clamped.privilege_delta == MAX_ESCALATION_DELTA and clamped.impact_delta == 0

    flagged = PrimitiveProfile(
        privilege_delta=1,
        impact_delta=2,
        pac=True,
        sptm=True,
        persistence=True,
        zero_click=True,
        ingress_weight=0.5,
    )
    flagged_provider = StaticPrimitiveProvider({"pf": flagged})
    for raw, expected in (
        ({"privilege_delta": 5}, (5, 2)),
        ({"impact_delta": 6}, (1, 6)),
        ({"privilege_delta": 5, "impact_delta": 6}, (5, 6)),
        ({}, (1, 2)),
    ):
        built = _node_from_claim(
            {"id": "pf", "type": "rung", "value_json": json.dumps(raw)},
            flagged_provider,
            [],
        )
        assert (built.privilege_delta, built.impact_delta) == expected
        assert built.zero_click and built.persistence and built.protected
        assert built.ingress_weight == pytest.approx(0.5)

    bad_entries = [
        {
            "id": "ep_bad1",
            "reach_from_json": json.dumps([{"source": "net", "via": "zero_click"}]),
            "privilege_delta": True,
            "weight": "bad",
        },
        {
            "id": "ep_bad2",
            "reach_from_json": json.dumps([{"source": "net", "via": "zero_click"}]),
            "privilege_delta": "bad",
            "weight": -1.0,
        },
    ]
    for entry_row in bad_entries:
        built = _node_from_claim(
            {
                "id": f"cl_{entry_row['id']}",
                "type": "rung",
                "value_json": json.dumps({"entry_point_id": entry_row["id"]}),
            },
            NullPrimitiveProvider(),
            bad_entries,
        )
        assert built.entry_point_id == entry_row["id"]
        assert built.privilege_delta == 0 and built.ingress_weight == pytest.approx(1.0)


def test_search_dead_end_pruning_cycles_and_join_cap():
    graph = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "a": node("a"),
            "b": node("b"),
            "t": node("t", persistence=True),
            "dead": node("dead"),
            "x": node("x"),
        },
        edges=(
            edge("e_sa", "s", "a"),
            edge("e_ab", "a", "b"),
            edge("e_ba", "b", "a"),
            edge("e_bt", "b", "t"),
            edge("e_ss", "s", "s"),
            edge("e_sd", "s", "dead"),
            edge("e_dx", "dead", "x"),
        ),
    )
    result = search_chain(graph)
    assert result.path is not None and result.path.node_ids == ("s", "a", "b", "t")
    assert result.pruned_edges == 2
    unpruned = search_chain(graph, ChainSearchConfig(dead_end_pruning=False))
    assert unpruned.path is not None and unpruned.pruned_edges == 0

    capped = search_chain(graph, ChainSearchConfig(max_joins=2))
    assert capped.path is None and capped.stop_reason == "no_path"
    allowed = search_chain(graph, ChainSearchConfig(max_joins=3))
    assert allowed.path is not None and allowed.path.join_count == 3


def test_search_edge_costs_stay_finite_on_extreme_bounds():
    nodes = {
        "s": node("s", zero_click=True),
        "t": node("t", persistence=True, privilege=10**30, impact=10**30, pac=True),
    }
    extreme = search_chain(
        ChainGraph(nodes=nodes, edges=(edge("e_extreme", "s", "t", 1e-320),))
    )
    assert extreme.path is not None and math.isfinite(extreme.path.cost)
    assert math.isfinite(extreme.path.escalation_score)

    zero = search_chain(ChainGraph(nodes=nodes, edges=(edge("e_zero", "s", "t", 0.0),)))
    assert zero.path is not None and math.isfinite(zero.path.cost)


def test_search_multi_path_custom_endpoints_and_partial_cap():
    multi = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "a": node("a"),
            "b": node("b"),
            "t1": node("t1", persistence=True),
            "t2": node("t2", persistence=True),
        },
        edges=(
            edge("e_sa", "s", "a", 1.0),
            edge("e_at", "a", "t1", 1.0),
            edge("e_sb", "s", "b", 0.5),
            edge("e_bt", "b", "t2", 1.0),
        ),
    )
    many = search_chain(multi, ChainSearchConfig(max_paths=2))
    assert many.path is not None and len(many.paths) == 2
    assert [item.target for item in many.paths] == ["t1", "t2"]

    custom = ChainGraph(
        nodes={"s": node("s"), "t": node("t")},
        edges=(edge("e_st", "s", "t"),),
    )
    explicit = search_chain(custom, sources=["s"], targets=["t"])
    assert explicit.path is not None and explicit.stop_reason == "found"

    invalid = search_chain(custom, sources=["s"], targets=["missing"])
    assert invalid.path is None and invalid.stop_reason == "no_path" and invalid.pruned_edges == 1

    capped_graph = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "a": node("a"),
            "b": node("b"),
            "t": node("t", persistence=True),
        },
        edges=(
            edge("e_sa", "s", "a", 1.0),
            edge("e_at", "a", "t", 1.0),
            edge("e_sb", "s", "b", 0.2),
            edge("e_bt", "b", "t", 1.0),
        ),
    )
    partial = search_chain(capped_graph, ChainSearchConfig(max_nodes=2, max_paths=2))
    assert partial.stop_reason == "node_cap" and partial.path is not None
    assert partial.path.target == "t" and len(partial.paths) == 1


def test_search_adversarial_graphs_terminate_deterministically():
    rng = random.Random(0)
    for _trial in range(6):
        count = 24
        nodes = {
            "n0": node("n0", zero_click=True),
            **{f"n{i}": node(f"n{i}") for i in range(1, count - 1)},
            f"n{count - 1}": node(f"n{count - 1}", persistence=True),
        }
        edges = []
        for i in range(count * 3):
            a = f"n{rng.randrange(count)}"
            b = f"n{rng.randrange(count)}"
            lower = rng.choice([0.2, 0.5, 1.0])
            edges.append(ChainEdge(id=f"e{i}", a_claim=a, b_claim=b, lower_bound=lower, state="live"))
        graph = ChainGraph(nodes=nodes, edges=tuple(edges))
        config = ChainSearchConfig(max_nodes=400, deadline_s=1.0, max_paths=3, max_joins=8)
        first = search_chain(graph, config)
        second = search_chain(graph, config)
        assert first.stop_reason in {"found", "no_path", "deadline", "node_cap"}
        assert first.stop_reason == second.stop_reason
        assert first.edges_relaxed == second.edges_relaxed
        first_paths = [(p.node_ids, p.edge_ids) for p in first.paths]
        second_paths = [(p.node_ids, p.edge_ids) for p in second.paths]
        assert first_paths == second_paths


def test_join_pricing_validation_escalation_and_finite_bounds():
    row = join_row("j")
    with pytest.raises(FormatFail):
        price_join_row(row, cost_usd_micro=100, chain_bonus=-1.0)
    with pytest.raises(FormatFail):
        price_join_row(row, cost_usd_micro=100, chain_bonus=MAX_PRICING_FACTOR + 1.0)
    with pytest.raises(FormatFail):
        price_join_row(row, cost_usd_micro=100, ingress_weight=MAX_PRICING_FACTOR + 1.0)
    with pytest.raises(FormatFail):
        price_join_row(row, cost_usd_micro=100, dupe_score=-0.1)
    with pytest.raises(FormatFail):
        price_join_row(row, cost_usd_micro=100, escalation_weight=MAX_PRICING_FACTOR + 1.0)
    for bad in (True, -1, 1.5):
        with pytest.raises(FormatFail):
            price_join_row(row, cost_usd_micro=100, privilege_delta=bad)
        with pytest.raises(FormatFail):
            price_join_row(row, cost_usd_micro=100, impact_delta=bad)

    base = price_join_row(row, cost_usd_micro=100)
    assert base.probability_join == pytest.approx(0.5) and base.benefit == pytest.approx(0.5)
    assert base.escalation_score == 0.0
    unknown = price_join_row(
        {"id": "u", "a_claim": "a", "b_claim": "b", "state": "candidate", "created": 1,
         "reliability": None, "lower_bound": None},
        cost_usd_micro=100,
    )
    assert unknown.probability_join == 0.0 and unknown.benefit == 0.0

    low = price_join_row(row, cost_usd_micro=100, privilege_delta=1, impact_delta=1)
    high = price_join_row(row, cost_usd_micro=100, privilege_delta=3, impact_delta=3)
    maxed = price_join_row(
        row,
        cost_usd_micro=1,
        chain_bonus=MAX_PRICING_FACTOR,
        ingress_weight=MAX_PRICING_FACTOR,
        dupe_score=1.0,
        privilege_delta=MAX_ESCALATION_DELTA,
        impact_delta=MAX_ESCALATION_DELTA,
        escalation_weight=MAX_PRICING_FACTOR,
    )
    assert 0.0 < low.escalation_score < high.escalation_score <= 1.0
    assert low.benefit < high.benefit
    assert math.isfinite(maxed.benefit) and math.isfinite(maxed.ev_cost)
    ordered = price_join_rows([row, {**row, "id": "j2", "created": 0}], cost_usd_micro=100,
                              privilege_delta=1, impact_delta=1)
    assert [item.join_id for item in ordered] == ["j2", "j"]


def test_chain_path_pricing_no_double_counting_and_order():
    prices = {
        "e1": price_join_row({**join_row("e1", 0.8), "b_claim": "x"}, cost_usd_micro=10),
        "e2": price_join_row({**join_row("e2", 0.5), "b_claim": "t"}, cost_usd_micro=20),
    }
    nodes = {
        "s": node("s", privilege=99, impact=99),
        "x": node("x", privilege=2, impact=1),
        "t": node("t", privilege=1, impact=0),
    }
    item = path(("s", "x", "t"), ("e1", "e2"), cost=3.0, ingress_weight=2.0)
    priced = price_chain_path(item, prices, nodes=nodes)
    assert priced.join_cost_usd_micro == 30
    assert priced.probability == pytest.approx(0.8 * 0.5)
    assert priced.privilege_delta == 3 and priced.impact_delta == 1
    priv_delta, impact_delta = _path_escalation(item, nodes)
    assert priced.escalation_score == pytest.approx(
        (priv_delta + impact_delta) / (1 + priv_delta + impact_delta)
    )
    assert priced.ev_cost == pytest.approx(priced.benefit / 30)

    repeated = path(("s", "x", "x", "t"), ("e1", "e1", "e2"), ingress_weight=2.0)
    dup = price_chain_path(repeated, prices, nodes=nodes)
    assert dup.join_cost_usd_micro == 30 and dup.probability == pytest.approx(0.8 * 0.5)
    assert dup.privilege_delta == 3

    with pytest.raises(FormatFail):
        price_chain_path(item, {"e1": prices["e1"]}, nodes=nodes)
    with pytest.raises(FormatFail):
        price_chain_path(
            item,
            prices,
            nodes={"s": nodes["s"], "x": nodes["x"]},
        )
    empty = path((), (), ingress_weight=1.0)
    with pytest.raises(FormatFail):
        _path_escalation(empty, {})
    with pytest.raises(FormatFail):
        price_chain_path(path(("s", "missing"), ("e1",), ingress_weight=1.0), prices, nodes=nodes)
    with pytest.raises(FormatFail):
        price_chain_path(item, prices, nodes=nodes, escalation_weight=-1.0)
    bad_ingress = path(("s", "t"), ("e1",), ingress_weight=MAX_PRICING_FACTOR + 1.0)
    with pytest.raises(FormatFail):
        price_chain_path(bad_ingress, prices)

    other = path(("s", "t"), ("e2",), cost=1.0, ingress_weight=1.0)
    ranked = price_chain_paths([other, item], prices, nodes={**nodes, "t": nodes["t"]})
    assert [entry.path.edge_ids for entry in ranked] == [("e1", "e2"), ("e2",)]


def test_join_pricer_escalation_from_ledger_claims():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            a = await ledger.create_claim(claim_input("cl_a", [1, 2], "bug_class"))
            b = await ledger.create_claim(
                claim_input(
                    "cl_b",
                    {
                        "privilege_delta": "bad",
                        "impact_delta": 4,
                        "ingress_weight": 2.0,
                    },
                    "rung",
                )
            )
            c = await ledger.create_claim(
                claim_input("cl_c", {"privilege_delta": 1, "impact_delta": 2}, "rung")
            )
            for join_id, left, right in (("j_b", a, b), ("j_c", a, c)):
                await ledger.insert_join(
                    {
                        "join_id": join_id,
                        "a_claim": left,
                        "b_claim": right,
                        "invariants_json": "[]",
                        "reliability": 0.5,
                        "lower_bound": 0.5,
                        "state": "research",
                        "created": 1,
                    }
                )
            profile = PrimitiveProfile(
                privilege_delta=2, impact_delta=5, ingress_weight=3.0
            )
            pricer = JoinPricer(
                ledger,
                primitives=StaticPrimitiveProvider({b: profile}),
                dupe=StaticDupeOracle({a: 0.5, b: 1.0, c: 1.0}),
            )
            prices = {item.join_id: item for item in await pricer.price_ledger(states=["research"])}
            assert prices["j_b"].privilege_delta == 2
            assert prices["j_b"].impact_delta == 4
            assert prices["j_b"].ingress_weight == pytest.approx(3.0)
            assert prices["j_b"].dupe_score == pytest.approx(0.5)
            assert prices["j_c"].privilege_delta == 1
            assert prices["j_c"].impact_delta == 2
            assert prices["j_c"].escalation_score > 0.0
        finally:
            await ledger.close()

    run(body())


def test_search_source_pruning_edge_cases():
    unreachable = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "dead": node("dead"),
            "t": node("t", persistence=True),
        },
        edges=(edge("e_sd", "s", "dead"),),
    )
    result = search_chain(unreachable)
    assert result.stop_reason == "no_path" and result.path is None and result.pruned_edges == 1

    custom = ChainGraph(nodes={"s": node("s"), "t": node("t")}, edges=(edge("e_st", "s", "t"),))
    assert search_chain(custom, sources=["missing"], targets=["t"]).stop_reason == "no_ingress"

    split = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "s2": node("s2", zero_click=True),
            "dead": node("dead"),
            "t": node("t", persistence=True),
        },
        edges=(
            edge("e_sd", "s", "dead"),
            edge("e_s2t", "s2", "t"),
            edge("e_dx", "dead", "x"),
        ),
    )
    found = search_chain(split)
    assert found.path is not None and found.path.source == "s2" and found.pruned_edges == 2


def test_build_graph_fetches_claims_outside_chain_types():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            left = await ledger.create_claim(claim_input("cl_a", {}, "bug_class"))
            right = await ledger.create_claim(claim_input("cl_b", {}, "dupe_score"))
            await ledger.insert_join(
                {
                    "join_id": "j_fetch",
                    "a_claim": left,
                    "b_claim": right,
                    "invariants_json": "[]",
                    "reliability": 0.5,
                    "lower_bound": 0.5,
                    "state": "research",
                    "created": 1,
                }
            )
            graph = build_graph(ledger)
            assert right in graph.nodes and graph.edges
            assert graph.edges[0].a_claim == left and graph.edges[0].b_claim == right
        finally:
            await ledger.close()

    run(body())


def test_build_graph_missing_join_claims_are_skipped():
    class GraphLedger:
        def claims_by_type(self, claim_type: str, limit: int = 10_000):
            return []

        def ring_nodes(self):
            return []

        def entry_points(self, ring_id: str, limit: int = 1_000):
            return []

        def joins(self, states=None, limit: int = 50_000):
            return [
                {
                    "id": "j_ghost",
                    "a_claim": "ghost_a",
                    "b_claim": "ghost_b",
                    "state": "research",
                    "created": 1,
                    "reliability": 0.5,
                    "lower_bound": 0.5,
                }
            ]

        def get_claim(self, claim_id: str):
            return None

    graph = build_graph(GraphLedger())
    assert not graph.nodes and graph.skipped_edges == 1


def test_join_pricer_claim_value_and_delta_branches():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ids = {
                "dp": await ledger.create_claim(
                    claim_input("cl_dp", {"privilege_delta": 5}, "rung")
                ),
                "ep": await ledger.create_claim(
                    claim_input("cl_ep", {"impact_delta": 6}, "rung")
                ),
                "fp": await ledger.create_claim(
                    claim_input("cl_fp", {"privilege_delta": 5, "impact_delta": 6}, "rung")
                ),
                "gp": await ledger.create_claim(claim_input("cl_gp", {}, "rung")),
            }
            profiles = {
                "cl_dp": PrimitiveProfile(impact_delta=9),
                "cl_ep": PrimitiveProfile(privilege_delta=1),
                "cl_fp": PrimitiveProfile(privilege_delta=1, impact_delta=2),
                "cl_gp": PrimitiveProfile(privilege_delta=7, impact_delta=8),
            }
            pricer = JoinPricer(ledger, primitives=StaticPrimitiveProvider(profiles))
            pricer._claim_cache["cl_empty"] = {
                "id": "cl_empty",
                "type": "rung",
                "value_json": "",
            }
            assert pricer._claim_value("cl_empty") == {}
            assert pricer._claim_deltas("missing") == (0, 0)
            assert pricer._claim_deltas(ids["dp"]) == (5, 9)
            assert pricer._claim_deltas(ids["ep"]) == (1, 6)
            assert pricer._claim_deltas(ids["fp"]) == (5, 6)
            assert pricer._claim_deltas(ids["gp"]) == (7, 8)
        finally:
            await ledger.close()

    run(body())


def test_subfactory_candidate_keeps_lowest_cost_path():
    weak_price = price_join_row({**join_row("weak", 0.1), "b_claim": "t"}, cost_usd_micro=10)
    prices = {"weak": weak_price}
    cheap = path(
        ("s", "t"),
        ("weak",),
        cost=1.0,
        min_lower_bound=0.1,
        weakest_join_id="weak",
    )
    dear = path(
        ("s", "x", "t"),
        ("mid", "weak"),
        cost=2.0,
        join_count=2,
        min_lower_bound=0.1,
        weakest_join_id="weak",
    )
    candidates = select_subfactory_candidates([cheap, dear], prices, floor=0.5)
    assert len(candidates) == 1 and candidates[0].path is cheap
