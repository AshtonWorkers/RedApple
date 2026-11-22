import json

import pytest

from ra.chain import (
    ChainEdge,
    ChainGraph,
    ChainNode,
    ChainPath,
    ChainSearchConfig,
    DefaultPolicyAdvisor,
    JoinAssertion,
    JoinPricer,
    JoinProgram,
    JoinState,
    PrimitiveProfile,
    StaticDupeOracle,
    StaticPrimitiveProvider,
    assert_join_source,
    build_graph,
    check_join_density,
    classify_join_state,
    density_report,
    is_zero_click_entry_point,
    join_invariants_json,
    measure_join,
    price_join_row,
    price_join_rows,
    register_join,
    reliability,
    render_join_source,
    run_join,
    search_chain,
    select_subfactory_candidates,
    source_assertion_kinds,
    validate_join_program,
    wilson_lower_bound,
)
from ra.errors import DensityLow, FormatFail
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger
from ra.ledger.ids import dedup_key
from tests.conftest import run


def program(join_id: str = "j1", a: str = "cl_a", b: str = "cl_b") -> JoinProgram:
    return JoinProgram(
        join_id=join_id,
        a_claim=a,
        b_claim=b,
        assertions=(
            JoinAssertion("address_validity", "addr_ok"),
            JoinAssertion("right_liveness", "right_ok"),
            JoinAssertion("signature_validity", "sig_ok"),
            JoinAssertion("sandbox_state", "sandbox_ok"),
        ),
        repro="repro join",
    )


def claim_input(claim_id: str, claim_type: str, value: dict) -> ClaimInput:
    return ClaimInput(
        claim_id=claim_id,
        type=claim_type,
        value_json=json.dumps(value),
        confidence=0.5,
        dedup_key=dedup_key("bug_class", "a" * 64, claim_id),
        created=1,
        artifacts=(ClaimArtifactInput(ArtifactInput(kind="crash", data=b"chain"), role="evidence"),),
    )


def node(
    node_id: str,
    *,
    zero_click: bool = False,
    persistence: bool = False,
    privilege: int = 0,
    pac: bool = False,
    ingress: float = 1.0,
) -> ChainNode:
    return ChainNode(
        id=node_id,
        claim_id=node_id,
        claim_type="rung",
        privilege_delta=privilege,
        pac=pac,
        persistence=persistence,
        zero_click=zero_click,
        ingress_weight=ingress,
    )


def edge(edge_id: str, a: str, b: str, lower: float = 1.0) -> ChainEdge:
    return ChainEdge(id=edge_id, a_claim=a, b_claim=b, lower_bound=lower, state="live")


def test_RA_JON_001_join_program_is_one_source_file_with_assertions():
    prog = program()
    validate_join_program(prog)
    source = render_join_source(prog)
    assert compile(source, "join.py", "exec")
    assert set(source_assertion_kinds(source)) == {
        "address_validity",
        "right_liveness",
        "signature_validity",
        "sandbox_state",
    }
    result = run_join(
        prog,
        {"address_valid": True, "right_live": True, "signature_valid": True, "sandbox_ok": True},
    )
    assert result.passed and result.checked == 4


def test_RA_JON_002_removed_assertion_fails_red():
    source = render_join_source(program())
    mutated = "\n".join(
        line for line in source.splitlines() if "ra-join-assert:signature_validity" not in line
    )
    with pytest.raises(FormatFail):
        assert_join_source(mutated, program())
    wrong_id = source.replace("# ra-join:id:j1", "# ra-join:id:other")
    with pytest.raises(FormatFail):
        assert_join_source(wrong_id, program())
    bad = JoinProgram(
        "jbad",
        "cl_a",
        "cl_b",
        (JoinAssertion("address_validity", "addr"),),
        "repro",
    )
    with pytest.raises(FormatFail):
        validate_join_program(bad)


def test_RA_JON_003_wilson_reliability_states_and_boundaries():
    assert reliability(9_900) == pytest.approx(0.99)
    assert wilson_lower_bound(10_000) == pytest.approx(wilson_lower_bound(10_000))
    live = measure_join(program(), 10_000)
    research = measure_join(program(), 9_900)
    candidate = measure_join(program(), 9_000)
    assert live.state is JoinState.LIVE and live.reliability == 1.0
    assert research.state is JoinState.RESEARCH
    assert candidate.state is JoinState.CANDIDATE
    assert classify_join_state(0.99) is JoinState.LIVE
    assert classify_join_state(0.989_999) is JoinState.RESEARCH
    assert classify_join_state(0.90) is JoinState.RESEARCH
    assert classify_join_state(0.899_999) is JoinState.CANDIDATE
    bounds = [wilson_lower_bound(passes) for passes in range(0, 10_001, 500)]
    assert bounds == sorted(bounds)


def test_RA_JON_004_register_join_updates_ledger_join_table():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            a = await ledger.create_claim(claim_input("cl_ja", "bug_class", {}))
            b = await ledger.create_claim(claim_input("cl_jb", "bug_class", {}))
            prog = program("j_meas", a, b)
            first = await register_join(ledger, prog, 10_000)
            assert first.state is JoinState.LIVE
            row = ledger.get_join("j_meas")
            assert row is not None and row["state"] == "live"
            assert ledger.joins(state="live")[0]["id"] == "j_meas"
            second = await register_join(ledger, prog, 9_900)
            updated = ledger.get_join("j_meas")
            assert second.state is JoinState.RESEARCH
            assert updated is not None and updated["state"] == "research"
            assert updated["reliability"] == pytest.approx(0.99)
            assert updated["lower_bound"] == pytest.approx(second.lower_bound)
        finally:
            await ledger.close()

    run(body())


def test_RA_JON_validation_edges_and_reliability_inputs():
    good = program()
    with pytest.raises(FormatFail):
        validate_join_program(JoinProgram(" ", "a", "b", good.assertions, "repro"))
    with pytest.raises(FormatFail):
        validate_join_program(JoinProgram("j", "a", "a", good.assertions, "repro"))
    with pytest.raises(FormatFail):
        validate_join_program(JoinProgram("j", "a", "b", good.assertions, "repro", trials=9_999))
    with pytest.raises(FormatFail):
        validate_join_program(JoinProgram("j", "a", "b", (), "repro"))
    with pytest.raises(FormatFail):
        validate_join_program(
            JoinProgram("j", "a", "b", (JoinAssertion("bogus", "x"),), "repro")
        )
    with pytest.raises(FormatFail):
        validate_join_program(
            JoinProgram("j", "a", "b", (JoinAssertion("address_validity", " "),), "repro")
        )
    with pytest.raises(FormatFail):
        validate_join_program(
            JoinProgram(
                "j",
                "a",
                "b",
                (
                    JoinAssertion("address_validity", "same"),
                    JoinAssertion("right_liveness", "same"),
                    JoinAssertion("signature_validity", "sig"),
                ),
                "repro",
            )
        )
    failed = run_join(good, {})
    assert not failed.passed and failed.failures == ("addr_ok", "right_ok", "sig_ok", "sandbox_ok")
    with pytest.raises(FormatFail):
        wilson_lower_bound(True)
    with pytest.raises(FormatFail):
        wilson_lower_bound(1, trials=0)
    with pytest.raises(FormatFail):
        wilson_lower_bound(-1)
    with pytest.raises(FormatFail):
        wilson_lower_bound(1, z=0.0)
    with pytest.raises(FormatFail):
        reliability(-1)
    with pytest.raises(FormatFail):
        classify_join_state(1.2)
    with pytest.raises(FormatFail):
        measure_join(good, 0, trials=9_999)
    with pytest.raises(FormatFail):
        measure_join(good, 10_001)
    payload = json.loads(join_invariants_json(good))
    assert "artifact_id" not in payload and payload["code_sha256"]


def test_RA_CHN_001_search_cost_formula_floor_and_pac_multiplier():
    graph = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "m": node("m"),
            "t": node("t", persistence=True, privilege=1, pac=True),
        },
        edges=(edge("e1", "s", "m", 1.0), edge("e2", "m", "t", 0.5)),
    )
    result = search_chain(graph)
    path = result.path
    assert path is not None and result.stop_reason == "found"
    assert path.cost == pytest.approx(10.0)
    assert path.join_count == 2 and path.weakest_join_id == "e2"
    floor_graph = ChainGraph(
        nodes={"s": node("s", zero_click=True), "t": node("t", persistence=True, privilege=9)},
        edges=(edge("e1", "s", "t", 1.0),),
    )
    floored = search_chain(floor_graph).path
    assert floored is not None and floored.cost == pytest.approx(0.1)


def test_RA_CHN_002_dijkstra_path_tie_break_and_bounds():
    graph = ChainGraph(
        nodes={
            "s": node("s", zero_click=True),
            "a": node("a"),
            "b": node("b"),
            "t": node("t", persistence=True),
        },
        edges=(
            edge("e_sa", "s", "a", 1.0),
            edge("e_sb", "s", "b", 1.0),
            edge("e_at", "a", "t", 1.0),
            edge("e_bt", "b", "t", 1.0),
        ),
    )
    first = search_chain(graph)
    second = search_chain(graph)
    assert first.path is not None and second.path is not None
    assert first.path.node_ids == second.path.node_ids == ("s", "a", "t")
    assert first.path.edge_ids == ("e_sa", "e_at")
    assert first.stop_reason == "found"

    capped = search_chain(graph, ChainSearchConfig(max_nodes=1))
    assert capped.path is None and capped.stop_reason == "node_cap"

    ticks = iter([0.0, 100.0, 100.0, 100.0])
    timed = search_chain(graph, ChainSearchConfig(deadline_s=5.0, clock=lambda: next(ticks)))
    assert timed.path is None and timed.stop_reason == "deadline"

    no_ingress = search_chain(ChainGraph(nodes={"t": node("t", persistence=True)}, edges=()))
    assert no_ingress.stop_reason == "no_ingress"
    no_target = search_chain(ChainGraph(nodes={"s": node("s", zero_click=True)}, edges=()))
    assert no_target.stop_reason == "no_persistence"


def test_RA_CHN_003_build_graph_from_ledger_and_entry_points():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.upsert_ring_node(
                {
                    "ring_node_id": "ring",
                    "ipsw_sha": "ipsw",
                    "build": "build",
                    "xcode": "xcode",
                    "sdk": "sdk",
                    "webkit_commit": "webkit",
                    "state": "current",
                    "epoch": 1,
                }
            )
            ep = {
                "id": "ep1",
                "entry_point_id": "ep1",
                "name": "zero",
                "reach_from_json": json.dumps([{"source": "network", "via": "zero_click", "hops": 0}]),
                "privilege_delta": 2,
                "parser_complexity": 1.0,
                "weight": 4.0,
            }
            await ledger.replace_entry_points("ring", [ep])
            s = await ledger.create_claim(
                claim_input("cl_s", "bug_class", {"entry_point_id": "ep1", "privilege_delta": 1})
            )
            m = await ledger.create_claim(claim_input("cl_m", "rung", {}))
            t = await ledger.create_claim(
                claim_input("cl_t", "root_cause", {"persistence": True, "privilege_delta": 3, "pac": True})
            )
            for row in (
                {
                    "join_id": "j_sm",
                    "a_claim": s,
                    "b_claim": m,
                    "invariants_json": "[]",
                    "reliability": 0.85,
                    "lower_bound": 0.8,
                    "state": "research",
                    "created": 1,
                },
                {
                    "join_id": "j_mt",
                    "a_claim": m,
                    "b_claim": t,
                    "invariants_json": "[]",
                    "reliability": 0.99,
                    "lower_bound": 0.95,
                    "state": "live",
                    "created": 2,
                },
                {
                    "join_id": "j_bad",
                    "a_claim": s,
                    "b_claim": t,
                    "invariants_json": "[]",
                    "reliability": None,
                    "lower_bound": None,
                    "state": "research",
                    "created": 3,
                },
            ):
                await ledger.insert_join(row)
            graph = build_graph(
                ledger,
                primitives=StaticPrimitiveProvider({s: PrimitiveProfile(ingress_weight=3.0)}),
            )
            source = graph.nodes[s]
            assert source.zero_click and source.entry_point_id == "ep1"
            assert source.privilege_delta == 2 and source.ingress_weight == 4.0
            assert graph.nodes[t].persistence and graph.nodes[t].pac
            assert len(graph.edges) == 2 and graph.skipped_edges == 1
            result = search_chain(graph)
            assert result.path is not None and result.path.node_ids == (s, m, t)
            assert result.path.min_lower_bound == pytest.approx(0.8)
        finally:
            await ledger.close()

    run(body())


def test_RA_CHN_004_density_floor_raises_density_low():
    now = 10_000_000
    window = 90 * 60 * 1000
    empty = density_report([], now=now, ingress_count=2, window_ms=window)
    assert empty.low and empty.density_per_hour == 0.0

    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(DensityLow):
                await check_join_density(ledger, now=now, ingress_count=1, window_ms=window)
        finally:
            await ledger.close()

    run(body())
    with pytest.raises(FormatFail):
        density_report([], now=now, ingress_count=-1)


def test_join_pricing_order_and_validation():
    rows = [
        {"id": "j_low", "a_claim": "a", "b_claim": "b", "state": "research", "created": 2,
         "reliability": 0.8, "lower_bound": 0.8},
        {"id": "j_high_old", "a_claim": "a", "b_claim": "b", "state": "live", "created": 2,
         "reliability": 0.99, "lower_bound": 0.99},
        {"id": "j_high_new", "a_claim": "a", "b_claim": "b", "state": "live", "created": 1,
         "reliability": 0.99, "lower_bound": 0.99},
    ]
    priced = price_join_rows(rows, cost_usd_micro=100)
    assert [row.join_id for row in priced] == ["j_high_new", "j_high_old", "j_low"]
    row = price_join_row(rows[0], cost_usd_micro=100, chain_bonus=2.0, ingress_weight=3.0,
                         dupe_score=0.5)
    assert row.probability_join == pytest.approx(0.8)
    assert row.benefit == pytest.approx(0.8 * 2.0 * 3.0 * 0.5)
    assert row.ev_cost == pytest.approx(row.benefit / 100)
    with pytest.raises(FormatFail):
        price_join_row(rows[0], cost_usd_micro=-1)
    with pytest.raises(FormatFail):
        price_join_row(rows[0], cost_usd_micro=100, dupe_score=1.1)
    with pytest.raises(FormatFail):
        price_join_row({**rows[0], "lower_bound": 1.2}, cost_usd_micro=100)


def test_join_pricer_uses_ledger_claims_and_stubbed_dependencies():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            a = await ledger.create_claim(
                claim_input("cl_pa", "bug_class", {"ingress_weight": 2.0})
            )
            b = await ledger.create_claim(claim_input("cl_pb", "rung", {}))
            await ledger.insert_join(
                {
                    "join_id": "j_price",
                    "a_claim": a,
                    "b_claim": b,
                    "invariants_json": "[]",
                    "reliability": 0.5,
                    "lower_bound": 0.5,
                    "state": "research",
                    "created": 7,
                }
            )
            pricer = JoinPricer(
                ledger,
                primitives=StaticPrimitiveProvider({b: PrimitiveProfile(ingress_weight=3.0)}),
                dupe=StaticDupeOracle({a: 0.5, b: 1.0}),
                policy=DefaultPolicyAdvisor(),
            )
            prices = await pricer.price_ledger(states=["research"])
            assert len(prices) == 1
            price = prices[0]
            assert price.ingress_weight == pytest.approx(3.0)
            assert price.dupe_score == pytest.approx(0.5)
            assert price.cost_usd_micro == 120_000
            assert price.probability_join == pytest.approx(0.5)
        finally:
            await ledger.close()

    run(body())


def test_subfactory_candidates_one_per_join_below_floor():
    low = ChainPath(
        node_ids=("s", "t"),
        edge_ids=("e1",),
        cost=2.0,
        join_count=1,
        ingress_weight=1.0,
        min_lower_bound=0.8,
        weakest_join_id="e1",
        total_privilege_delta=1,
    )
    lower_cost = ChainPath(
        node_ids=("s", "x", "t"),
        edge_ids=("e2", "e3"),
        cost=1.0,
        join_count=2,
        ingress_weight=1.0,
        min_lower_bound=0.8,
        weakest_join_id="e1",
        total_privilege_delta=1,
    )
    high = ChainPath(
        node_ids=("s", "t"),
        edge_ids=("e4",),
        cost=1.0,
        join_count=1,
        ingress_weight=1.0,
        min_lower_bound=0.95,
        weakest_join_id="e4",
        total_privilege_delta=1,
    )
    prices = {
        "e1": price_join_row(
            {"id": "e1", "a_claim": "a", "b_claim": "b", "state": "candidate", "created": 1,
             "reliability": None, "lower_bound": 0.8},
            cost_usd_micro=100,
        ),
        "e4": price_join_row(
            {"id": "e4", "a_claim": "a", "b_claim": "b", "state": "live", "created": 1,
             "reliability": None, "lower_bound": 0.95},
            cost_usd_micro=100,
        ),
    }
    candidates = select_subfactory_candidates([low, lower_cost, high], prices, floor=0.9)
    assert len(candidates) == 1
    assert candidates[0].join_id == "e1"
    assert candidates[0].path.cost == pytest.approx(1.0)
    with pytest.raises(FormatFail):
        select_subfactory_candidates([low], prices, floor=1.1)


def test_entry_point_zero_click_detection():
    assert is_zero_click_entry_point(
        {"reach_from_json": json.dumps([{"source": "ipc", "via": "zero-click", "hops": 1}])}
    )
    assert not is_zero_click_entry_point(
        {"reach_from_json": json.dumps([{"source": "ipc", "via": "user_click", "hops": 1}])}
    )
