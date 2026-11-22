"""Extra branch coverage for ra.escalate adapters and search bounds."""

import pytest

import ra.escalate.graph as graph_module
from ra.errors import FormatFail
from ra.escalate import (
    EscalationEdge,
    EscalationGraph,
    EscalationNode,
    EscalationStage,
    analyze_escalations,
    graph_from_chain_outputs,
    graph_from_mappings,
    graph_from_surface_rows,
)
from ra.srf.models import ReachRecord


def test_graph_size_bounds(monkeypatch: pytest.MonkeyPatch):
    a = EscalationNode(id="a", stage=EscalationStage.SANDBOX_PROFILE)
    b = EscalationNode(id="b", stage=EscalationStage.ROOT)
    edge = EscalationEdge(source="a", target="b")
    monkeypatch.setattr(graph_module, "MAX_GRAPH_NODES", 1)
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(a, b), edges=())
    monkeypatch.setattr(graph_module, "MAX_GRAPH_NODES", 10)
    monkeypatch.setattr(graph_module, "MAX_GRAPH_EDGES", 0)
    with pytest.raises(FormatFail):
        EscalationGraph(nodes=(a, b), edges=(edge,))


def test_mapping_and_evidence_validation():
    with pytest.raises(FormatFail):
        graph_from_mappings([3], [])  # type: ignore[list-item]
    nodes = [
        {"id": "a", "stage": "sandbox_profile"},
        {"id": "b", "stage": "root"},
    ]
    with pytest.raises(FormatFail):
        graph_from_mappings(nodes, [{"source": "a", "target": "b", "join_count": "x"}])
    ok = graph_from_mappings(nodes, [{"source": "a", "target": "b", "evidence": ["b", "a", "a"]}])
    assert ok.edges[0].evidence == ("a", "b")
    with pytest.raises(FormatFail):
        graph_from_mappings(nodes, [{"source": "a", "target": "b", "evidence": ["ok", 2]}])
    with pytest.raises(FormatFail):
        graph_from_mappings(nodes, [{"source": "a", "target": "b", "evidence": 3}])


def test_surface_reach_adapter_branches():
    graph = graph_from_surface_rows(
        [
            {"id": "map", "name": "service", "reach_from": {"source": "web", "hops": 1}},
            {"id": "str", "name": "service", "reach_from": ["web"]},
            {
                "id": "rec",
                "name": "service",
                "reach_from": [ReachRecord(source="sandbox:app", hops=0, via="x")],
            },
            {"id": "conf", "name": "service", "reach_from": [{"source": "s", "confidence": 0.4}]},
            {"id": "noname", "reach_from": ["web"]},
        ]
    )
    assert len(graph.edges) == 5
    assert graph.edges[0].relation == "surface_reach"
    assert any(node.id == "sandbox:app" for node in graph.nodes)
    assert all(edge.reliability >= 0.0 for edge in graph.edges)


def test_chain_adapter_fallbacks_and_path_sequences():
    seq = graph_from_chain_outputs([{"source": "a", "target": "b", "impact_delta": 1}])
    assert seq.edges[0].impact_delta == 1.0

    wrapped = graph_from_chain_outputs({"value": {"source": "a", "target": "b"}})
    assert wrapped.edges[0].relation == "escalates"

    path = graph_from_chain_outputs(
        {
            "path": [
                {"id": "a", "stage": "sandbox_profile"},
                {
                    "id": "b",
                    "stage": "root",
                    "privilege": 4,
                    "impact": 0.5,
                    "edge": {"impact_delta": 0.7, "relation": "chain", "join_count": 2},
                },
            ]
        }
    )
    assert path.edges[0].relation == "chain"
    assert path.edges[0].join_count == 2
    assert next(node for node in path.nodes if node.id == "b").privilege == 4.0

    strings = graph_from_chain_outputs({"path": ["a", "b"]})
    assert strings.edges[0].relation == "chain_step"
    assert graph_from_chain_outputs({}).edges == ()
    assert graph_from_chain_outputs({"paths": ["solo"]}).nodes[0].id == "solo"

    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"foo": "bar"})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"nodes": 3})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"edges": 3})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"edges": ["ab"]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"paths": 3})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"path": 3})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"paths": [3]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"nodes": [" "]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"path": [{"id": "a"}, {"id": "b", "edge": 3}]})
    with pytest.raises(FormatFail):
        graph_from_chain_outputs({"path": [["a", 3]]})


def test_analyze_search_bound_edges():
    chain_nodes = [{"id": f"n{i}", "stage": "service"} for i in range(9)]
    chain_nodes[0]["stage"] = "sandbox_profile"
    chain_nodes[-1]["stage"] = "root"
    chain_edges = [{"source": f"n{i}", "target": f"n{i + 1}", "impact_delta": 1} for i in range(8)]
    long_graph = graph_from_mappings(chain_nodes, chain_edges)
    long_result = analyze_escalations(long_graph, max_paths=3)
    assert long_result.paths
    assert long_result.expansions > 0

    branch = graph_from_mappings(
        [
            {"id": "a", "stage": "sandbox_profile"},
            {"id": "b", "stage": "service"},
            {"id": "c", "stage": "root"},
        ],
        [
            {"source": "a", "target": "b", "impact_delta": 1},
            {"source": "a", "target": "c", "impact_delta": 0.1},
        ],
    )
    relaxed = analyze_escalations(branch, max_paths=1, max_relaxations=1)
    assert relaxed.truncated is True
    replaced = analyze_escalations(branch, max_paths=1)
    assert len(replaced.paths) == 1
    assert replaced.paths[0].target == "c"

    diamond = graph_from_mappings(
        [
            {"id": "a", "stage": "sandbox_profile"},
            {"id": "b", "stage": "service"},
            {"id": "c", "stage": "service"},
            {"id": "d", "stage": "root"},
        ],
        [
            {"source": "a", "target": "b", "impact_delta": 1},
            {"source": "a", "target": "c", "impact_delta": 0.9},
            {"source": "b", "target": "d", "impact_delta": 1},
            {"source": "c", "target": "d", "impact_delta": 0.8},
            {"source": "a", "target": "d", "impact_delta": 0.1},
        ],
    )
    diamond_result = analyze_escalations(diamond, max_paths=2)
    assert len(diamond_result.paths) == 2
