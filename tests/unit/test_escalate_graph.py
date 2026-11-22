"""Graph construction, adapters, and adversarial search tests."""

import math
import random

import pytest

from ra.errors import FormatFail
from ra.escalate import (
    EscalationEdge,
    EscalationGraph,
    EscalationNode,
    EscalationStage,
    analyze_escalations,
    graph_from_chain_outputs,
    graph_from_entry_points,
    graph_from_mappings,
    graph_from_surface_rows,
)
from ra.srf.models import EntryPoint, ReachRecord


def _node(node_id: str, stage: str, privilege: float = 0.0, impact: float = 0.0) -> dict[str, object]:
    return {"id": node_id, "stage": stage, "privilege": privilege, "impact": impact}


def _edge(source: str, target: str, **kwargs: object) -> dict[str, object]:
    return {"source": source, "target": target, **kwargs}


def test_graph_from_mappings_builds_deterministic_graph():
    graph = graph_from_mappings(
        [_node("b", "service"), _node("a", "sandbox_profile", 1, 0.1), _node("a", "sandbox_profile", 1, 0.1)],
        [_edge("a", "b", privilege_delta=1, impact_delta=0.25, cost=2, reliability=0.8, evidence="x")],
    )
    assert [node.id for node in graph.nodes] == ["a", "b"]
    assert graph.nodes[0].stage is EscalationStage.SANDBOX_PROFILE
    assert graph.edges[0].evidence == ("x",)
    assert graph.sources() == ("a",)
    assert graph.targets() == ("b",)

    with pytest.raises(FormatFail):
        graph_from_mappings([{"id": "a", "stage": "bogus"}], [])
    merged = graph_from_mappings(
        [{"id": "a", "stage": "service"}, {"id": "a", "stage": "kernel", "impact": 0.5}],
        [],
    )
    assert len(merged.nodes) == 1
    assert merged.nodes[0].stage is EscalationStage.KERNEL
    assert merged.nodes[0].impact == 0.5
    with pytest.raises(FormatFail):
        graph_from_mappings([], [{"source": "a", "target": "b"}])
    with pytest.raises(FormatFail):
        graph_from_mappings([], [{"target": "b"}])
    deduped = graph_from_mappings(
        [_node("a", "sandbox_profile"), _node("b", "root")],
        [{"source": "a", "target": "b"}, {"source": "a", "target": "b", "impact_delta": 1}],
    )
    assert len(deduped.edges) == 1
    assert deduped.edges[0].impact_delta == 1.0


def test_graph_rejects_invalid_topology_and_values():
    node_a = EscalationNode(id="a", stage=EscalationStage.SANDBOX_PROFILE)
    node_b = EscalationNode(id="b", stage=EscalationStage.ROOT)
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(node_a, "bad"), edges=())  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(node_a,), edges=("bad",))  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(node_a,), edges=(EscalationEdge(source="a", target="missing"),))
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(node_a, node_b), edges=(EscalationEdge(source="a", target="a"),))
    with pytest.raises(FormatFail):
        EscalationGraph(
            nodes=(node_a, node_b),
            edges=(
                EscalationEdge(source="a", target="b"),
                EscalationEdge(source="a", target="b", relation="other"),
                EscalationEdge(source="a", target="b", relation="other"),
            ),
        )
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(node_a, node_a), edges=())


def test_surface_rows_and_entry_points_adapters():
    ep = EntryPoint(
        ring_node="app",
        name="com.apple.Parser",
        format_spec="plist",
        reach_from=(ReachRecord(source="webcontent", hops=1, via="ipc"),),
        privilege_delta=2,
        parser_complexity=128.0,
    )
    graph = graph_from_entry_points([ep])
    assert len(graph.nodes) == 2
    assert graph.edges[0].source.startswith("sandbox:")
    assert graph.edges[0].target == ep.id
    assert graph.edges[0].relation == "surface_reach"
    assert graph.edges[0].reliability == pytest.approx(0.7)

    row_graph = graph_from_surface_rows(
        [
            {
                "id": "row1",
                "name": "kernel_task",
                "ring_node": "kernel",
                "reach_from_json": '[{"source":"x","hops":2,"via":"syscall"}]',
                "privilege_delta": 4,
                "parser_complexity": 200,
                "weight": 6,
            }
        ]
    )
    assert next(node for node in row_graph.nodes if node.id == "row1").stage is EscalationStage.KERNEL
    assert row_graph.edges[0].reliability == pytest.approx(0.49)

    isolated = graph_from_surface_rows([{"id": "lonely", "name": "service"}])
    assert isolated.sources() == ()
    assert isolated.targets() == ()

    explicit = graph_from_surface_rows(
        [
            {
                "id": "svc",
                "name": "service",
                "reach_from": [{"source": "web", "hops": 0, "reliability": 0.9, "join_count": 2}],
            }
        ]
    )
    assert explicit.edges[0].reliability == 0.9
    assert explicit.edges[0].join_count == 2

    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "bad", "name": "x", "reach_from_json": "not-json"}])
    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "bad", "name": "x", "reach_from": [{"hops": 1}]}])
    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "bad", "name": "x", "reach_from": [3]}])
    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "bad", "name": "x", "reach_from_json": "null"}])


def test_chain_outputs_adapter_shapes():
    assert graph_from_chain_outputs(None).nodes == ()
    existing = graph_from_mappings([_node("a", "sandbox_profile"), _node("b", "root")], [_edge("a", "b")])
    assert graph_from_chain_outputs(existing) is existing

    nodes_edges = graph_from_chain_outputs(
        {"nodes": [_node("a", "sandbox_profile"), _node("b", "service")], "edges": [_edge("a", "b", impact_delta=1)]}
    )
    assert len(nodes_edges.edges) == 1

    path_steps = graph_from_chain_outputs(
        {"path": {"steps": ["a->b", {"source": "b", "target": "c", "impact_delta": 0.5}]}}
    )
    assert [edge.relation for edge in path_steps.edges] == ["chain_step", "escalates"]
    assert [node.id for node in path_steps.nodes] == ["a", "b", "c"]

    paths_list = graph_from_chain_outputs(
        {"paths": [{"nodes": ["x", "y"], "edges": [{"source": "x", "target": "y"}]}, {"steps": ["x->y"]}]}
    )
    assert len(paths_list.edges) == 2

    single_edge = graph_from_chain_outputs({"source": "a", "target": "b", "impact_delta": 0.2})
    assert single_edge.edges[0].impact_delta == 0.2

    single_node = graph_from_chain_outputs({"id": "z", "stage": "kernel"})
    assert single_node.nodes[0].id == "z"

    with pytest.raises(FormatFail):
        graph_from_chain_outputs(3)
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"edges": [{"source": "a"}]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"edges": [{"target": "b"}]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"edges": ["a"]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"edges": [3]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"path": {"steps": [3]}})
    assert graph_from_chain_outputs({"path": {"steps": []}}).edges == ()
    assert graph_from_chain_outputs({"path": []}).edges == ()
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"path": [3]})


def _chain_graph() -> EscalationGraph:
    return graph_from_mappings(
        [
            _node("sandbox:a", "sandbox_profile"),
            _node("ent:x", "entitlement"),
            _node("svc:y", "service"),
            _node("kernel:z", "kernel"),
            _node("root:r", "root"),
        ],
        [
            _edge("sandbox:a", "ent:x", privilege_delta=1, impact_delta=0.2, cost=1, reliability=1.0),
            _edge("ent:x", "svc:y", privilege_delta=1, impact_delta=0.3, cost=1, reliability=0.8),
            _edge("svc:y", "kernel:z", privilege_delta=2, impact_delta=0.4, cost=2, reliability=0.9),
            _edge("kernel:z", "root:r", privilege_delta=1, impact_delta=0.5, cost=1, reliability=1.0),
            _edge("sandbox:a", "svc:y", privilege_delta=0.5, impact_delta=0.1, cost=4, reliability=0.5),
        ],
    )


def test_analyze_escalations_ranks_simple_paths_and_is_deterministic():
    graph = _chain_graph()
    first = analyze_escalations(graph, max_paths=10)
    second = analyze_escalations(graph, max_paths=10)
    assert first.to_dict() == second.to_dict()
    assert first.nodes_considered == 5
    assert first.edges_considered == 5
    assert first.truncated is False
    top = first.to_dict()["highest_impact"]
    assert top["nodes"] == ["sandbox:a", "ent:x", "svc:y", "kernel:z", "root:r"]
    assert top["impact_score"] == pytest.approx(3.2)
    assert [path.hop_count for path in first.paths] == [4, 3, 3, 2]

    limited = analyze_escalations(graph, max_paths=1, sources=["sandbox:a"], targets=["root:r"])
    assert len(limited.paths) == 1
    assert limited.paths[0].target == "root:r"

    with pytest.raises(FormatFail):
        analyze_escalations(graph, max_paths=0)
    with pytest.raises(FormatFail):
        analyze_escalations(graph, max_paths=-1)
    with pytest.raises(FormatFail):
        analyze_escalations(graph, max_expansions=0)
    with pytest.raises(FormatFail):
        analyze_escalations(graph, max_relaxations=0)
    with pytest.raises(FormatFail):
        analyze_escalations(graph, sources=["missing"])
    with pytest.raises(FormatFail):
        analyze_escalations(graph, targets=["missing"])


def test_analyze_escalations_terminates_on_cycles_and_reports_truncation():
    nodes = [
        _node("a", "sandbox_profile"),
        _node("b", "service"),
        _node("c", "kernel"),
        _node("d", "root"),
    ]
    edges = [
        _edge("a", "b", impact_delta=1, privilege_delta=1),
        _edge("b", "c", impact_delta=1, privilege_delta=1),
        _edge("c", "b", impact_delta=1, privilege_delta=1),
        _edge("c", "d", impact_delta=2, privilege_delta=2),
    ]
    graph = graph_from_mappings(nodes, edges)
    result = analyze_escalations(graph, max_paths=5, max_expansions=100, max_relaxations=1000)
    assert result.truncated is False
    assert all(len(set(path.nodes)) == len(path.nodes) for path in result.paths)

    cyclic_dense = graph_from_mappings(
        [_node(str(i), "service") for i in range(8)],
        [_edge(str(i), str((i + 1) % 8), impact_delta=1, privilege_delta=1) for i in range(8)],
    )
    truncated = analyze_escalations(cyclic_dense, max_paths=4, max_expansions=3, max_relaxations=10)
    assert truncated.truncated is True
    assert truncated.expansions <= 3

    empty = EscalationGraph(nodes=(), edges=())
    empty_result = analyze_escalations(empty)
    assert empty_result.paths == ()
    assert empty_result.to_dict()["highest_impact"] is None


def test_escalation_properties_random_dags_and_no_double_counting():
    rng = random.Random(1337)
    for _case in range(20):
        node_count = rng.randint(3, 9)
        nodes = [
            _node(f"n{i}", rng.choice(["sandbox_profile", "entitlement", "service", "kernel", "root"]), i, i / 10)
            for i in range(node_count)
        ]
        edges = []
        for i in range(node_count):
            for j in range(i + 1, node_count):
                if rng.random() < 0.25:
                    edges.append(
                        _edge(
                            f"n{i}",
                            f"n{j}",
                            privilege_delta=rng.random() * 2,
                            impact_delta=rng.random(),
                            cost=rng.random() * 3,
                            reliability=0.5 + rng.random() * 0.5,
                        )
                    )
        graph = graph_from_mappings(nodes, edges)
        result = analyze_escalations(graph, max_paths=17, max_expansions=2000, max_relaxations=5000)
        assert result.nodes_considered == len(graph.nodes)
        assert result.edges_considered == len(graph.edges)
        for path in result.paths:
            assert len(set(path.nodes)) == len(path.nodes)
            assert path.hop_count <= 8
            assert math.isfinite(path.impact_score)
            assert 0.0 <= path.reliability <= 1.0
            assert path.cost >= 0.0
            expected_impact = sum(edge.impact_score() for edge in path.edges)
            assert path.impact_score == pytest.approx(expected_impact)
        assert result.to_dict() == analyze_escalations(graph, max_paths=17, max_expansions=2000, max_relaxations=5000).to_dict()

    single = graph_from_mappings(
        [_node("a", "sandbox_profile"), _node("b", "root", impact=1)],
        [_edge("a", "b", privilege_delta=1, impact_delta=0.5, cost=1, reliability=1), _edge("a", "b", privilege_delta=1, impact_delta=0.5, cost=1, reliability=1)],
    )
    assert len(single.edges) == 1
    result = analyze_escalations(single)
    assert len(result.paths) == 1
    assert result.paths[0].impact_score == pytest.approx(1.0)
    assert result.edges_considered == 1


def test_edge_value_failures_and_reach_helpers():
    with pytest.raises(FormatFail):
        graph_from_mappings([], [_edge("a", "b", privilege_delta=math.nan)])
    with pytest.raises(FormatFail):
        graph_from_mappings([], [_edge("a", "b", impact_delta=math.inf)])
    with pytest.raises(FormatFail):
        graph_from_mappings([], [_edge("a", "b", reliability=-1)])
    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "x", "name": "y", "reach_from": [{"source": "s", "hops": "bad"}]}])
    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "x", "name": "y", "reach_from": [{"source": "s", "hops": 1, "join_count": 1.5}]}])
    with pytest.raises(FormatFail):
        graph_from_surface_rows([{"id": "x", "name": "y", "reach_from": [{"source": "s", "hops": 1, "evidence": 3}]}])
