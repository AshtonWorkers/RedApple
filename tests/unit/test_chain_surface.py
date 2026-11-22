"""Cross-surface chain enumeration, affinity scoring, ranking, and emission."""

import json
import random
from dataclasses import replace

import pytest

from ra.chain import (
    StaticDupeOracle,
    SurfaceCategory,
    SurfaceChainConfig,
    SurfaceChainEmitter,
    SurfaceChainPath,
    SurfaceChainQuality,
    SurfaceEdge,
    SurfaceGraph,
    SurfaceHopKind,
    SurfaceNode,
    SurfaceQualityWeights,
    SurfaceSearchAlgorithm,
    enumerate_surface_chains,
    parse_search_algorithm,
    parse_surface_category,
    parse_surface_hop_kind,
    rank_surface_chains,
    surface_affinity,
    surface_graph_from_rows,
)
from ra.errors import FormatFail
from ra.escalate import analyze_escalations, graph_from_chain_outputs
from ra.ledger import Ledger
from tests.conftest import run


def node(node_id: str, category: str, **kwargs: object) -> SurfaceNode:
    return SurfaceNode(id=node_id, category=category, **kwargs)  # type: ignore[arg-type]


def edge(edge_id: str, source: str, target: str, **kwargs: object) -> SurfaceEdge:
    return SurfaceEdge(id=edge_id, source=source, target=target, **kwargs)  # type: ignore[arg-type]


def test_surface_parsing_and_affinity_scoring():
    assert parse_surface_category("CoreMedia") is SurfaceCategory.MEDIA
    assert parse_surface_category("VideoToolbox") is SurfaceCategory.CODEC
    assert parse_surface_category("JavaScriptCore") is SurfaceCategory.JSC
    assert parse_surface_category("not-a-surface") is SurfaceCategory.OTHER
    with pytest.raises(FormatFail):
        parse_surface_category(3)  # type: ignore[arg-type]

    assert parse_surface_hop_kind("crash") is SurfaceHopKind.CRASH_FEEDS_ENTRY
    assert parse_surface_hop_kind("sandbox_escape") is SurfaceHopKind.SANDBOX_ESCAPE
    with pytest.raises(FormatFail):
        parse_surface_hop_kind("not-a-hop")

    assert parse_search_algorithm("breadth-first") is SurfaceSearchAlgorithm.BFS
    assert parse_search_algorithm("depth_first") is SurfaceSearchAlgorithm.DFS
    with pytest.raises(FormatFail):
        parse_search_algorithm("random")

    assert surface_affinity("media", "codec") == pytest.approx(0.95)
    assert surface_affinity("media", "codec", "codec_handoff") == pytest.approx(1.0)
    assert surface_affinity("font", "render") == pytest.approx(0.95)
    assert surface_affinity("xpc", "sandbox") == pytest.approx(0.90)
    assert surface_affinity("kernel", "kernel") == pytest.approx(0.30)
    assert surface_affinity("media", "iokit") == pytest.approx(0.20)
    assert surface_affinity("iokit", "kernel", "iokit_kernel") == pytest.approx(1.0)
    assert surface_affinity("kernel", "sandbox", "persistence") == pytest.approx(0.25)


def test_surface_models_validate_and_clamp_values():
    bad_node_values = [
        {"id": "", "category": "media"},
        {"id": "n", "category": 3},
        {"id": "n", "category": "media", "impact": True},
        {"id": "n", "category": "media", "impact": float("nan")},
        {"id": "n", "category": "media", "zero_click": "yes"},
    ]
    for kwargs in bad_node_values:
        with pytest.raises(FormatFail):
            SurfaceNode(**kwargs)  # type: ignore[arg-type]

    clamped = node("n", "media", impact=2.0, feasibility=-1.0, privilege=99.0)
    assert clamped.impact == 1.0 and clamped.feasibility == 0.0 and clamped.privilege == 8.0
    assert clamped.is_ingress is False and clamped.is_target is False
    assert node("k", "kernel").is_target is True
    assert node("p", "other", persistence=True, terminal=True).is_target is True

    bad_edge_values = [
        {"id": "", "source": "a", "target": "b"},
        {"id": "e", "source": "a", "target": "b", "kind": "bad-kind"},
        {"id": "e", "source": "a", "target": "b", "privilege_delta": float("nan")},
        {"id": "e", "source": "a", "target": "b", "join_count": True},
        {"id": "e", "source": "a", "target": "b", "join_count": -1},
        {"id": "e", "source": "a", "target": "b", "evidence": 3},
        {"id": "e", "source": "a", "target": "b", "evidence": ["ok", 3]},
    ]
    for kwargs in bad_edge_values:
        with pytest.raises(FormatFail):
            SurfaceEdge(**kwargs)  # type: ignore[arg-type]

    resolved = edge("e", "a", "b", kind="codec_handoff", evidence="x")
    assert resolved.key == ("a", "b", SurfaceHopKind.CODEC_HANDOFF)
    assert resolved.evidence == ("x",)


def test_surface_graph_resolves_affinity_and_rejects_bad_topology():
    nodes = (
        node("a", "media", zero_click=True),
        node("b", "codec"),
        node("c", "kernel", persistence=True),
    )
    edges = (
        edge("e1", "a", "b", kind="codec_handoff", reliability=0.9, cost=2.0),
        edge("e2", "b", "c", kind="iokit_kernel", reliability=0.8, cost=1.0),
        edge("e3", "a", "c", kind="generic", reliability=0.7, cost=0.5),
    )
    graph = SurfaceGraph(nodes=nodes, edges=edges)
    assert graph.edges[0].affinity == pytest.approx(1.0)
    assert graph.edges[1].affinity == pytest.approx(0.25)
    assert [item.id for item in graph.adjacency()["a"]] == ["e1", "e3"]

    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=(nodes[0], nodes[0]), edges=())
    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=nodes, edges=("bad",))  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=nodes, edges=(edge("e", "a", "missing"),))
    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=nodes, edges=(edge("e", "a", "a"),))
    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=nodes, edges=(edges[0], edges[0]))


def test_surface_chain_path_validation_and_dict_round_trip():
    path_edges = (
        edge("e1", "a", "b", kind="codec_handoff", privilege_delta=1, impact_delta=0.5),
        edge("e2", "b", "c", kind="jsc_bridge", privilege_delta=2, impact_delta=0.25),
    )
    path = SurfaceChainPath(
        nodes=("a", "b", "c"),
        edges=path_edges,
        categories=(SurfaceCategory.MEDIA, SurfaceCategory.CODEC, SurfaceCategory.KERNEL),
        privilege_gain=3.0,
        impact=0.75,
        feasibility=0.5,
        reliability=0.4,
        affinity=0.6,
        cost=3.0,
    )
    assert path.source == "a" and path.target == "c"
    assert path.hop_count == 2 and path.category_count == 3 and path.cross_surface is True
    assert path.edge_ids == ("e1", "e2")
    payload = path.to_dict()
    assert payload["nodes"] == ["a", "b", "c"]
    assert payload["categories"] == ["media", "codec", "kernel"]
    assert json.loads(path.dedup_material()) == {
        "nodes": ["a", "b", "c"],
        "edge_ids": ["e1", "e2"],
        "categories": ["media", "codec", "kernel"],
    }

    with pytest.raises(FormatFail):
        SurfaceChainPath(nodes=(), edges=(), categories=())
    with pytest.raises(FormatFail):
        SurfaceChainPath(nodes=("a", "a"), edges=(path_edges[0],), categories=("media", "codec"))
    with pytest.raises(FormatFail):
        SurfaceChainPath(nodes=("a", "b"), edges=path_edges[:1], categories=("media",))
    with pytest.raises(FormatFail):
        SurfaceChainPath(nodes=("a", "b", "c"), edges=path_edges[:1], categories=("media", "codec", "kernel"))
    disconnected = edge("bad", "b", "c")
    with pytest.raises(FormatFail):
        SurfaceChainPath(nodes=("a", "b"), edges=(disconnected,), categories=("media", "codec"))


def test_surface_graph_from_rows_builds_catalog_hops():
    graph = surface_graph_from_rows(
        [
            {
                "id": "media-entry",
                "surface": "coremedia",
                "impact": 0.8,
                "feasibility": 0.9,
                "privilege": 1,
                "reach_from_json": json.dumps(
                    [{"source": "network", "via": "zero_click", "hops": 0}]
                ),
                "feeds": ["codec-entry"],
            },
            {
                "id": "codec-entry",
                "category": "VideoToolbox",
                "impact": 0.7,
                "hops": [{"target": "render-entry", "kind": "render_pipeline", "impact_delta": 0.4}],
            },
            {"id": "render-entry", "family": "metal", "reliability": 0.8, "feeds": "jsc-entry"},
            {"id": "jsc-entry", "family_name": "webkit", "persistence": True},
        ]
    )
    assert [item.id for item in graph.nodes] == [
        "media-entry",
        "codec-entry",
        "render-entry",
        "jsc-entry",
    ]
    assert graph.node_map["media-entry"].category is SurfaceCategory.MEDIA
    assert graph.node_map["media-entry"].is_ingress is True
    assert graph.node_map["jsc-entry"].is_target is True
    assert graph.node_map["render-entry"].feasibility == pytest.approx(0.8)
    assert [(item.source, item.target, item.kind) for item in graph.edges] == [
        ("media-entry", "codec-entry", SurfaceHopKind.CRASH_FEEDS_ENTRY),
        ("codec-entry", "render-entry", SurfaceHopKind.RENDER_PIPELINE),
        ("render-entry", "jsc-entry", SurfaceHopKind.CRASH_FEEDS_ENTRY),
    ]
    assert graph.edges[0].affinity == pytest.approx(1.0)

    explicit = surface_graph_from_rows(
        [
            {"id": "a", "category": "xpc", "zero_click": True},
            {"id": "b", "category": "sandbox", "persistence": True},
        ],
        [
            {
                "source": "a",
                "target": "b",
                "kind": "xpc_dispatch",
                "privilege_delta": 2,
                "impact_delta": 0.6,
                "feasibility": 0.7,
                "reliability": 0.8,
                "cost": 3,
                "join_count": 2,
                "evidence": ["dispatch", "sandbox"],
            }
        ],
    )
    assert explicit.edges[0].kind is SurfaceHopKind.XPC_DISPATCH
    assert explicit.edges[0].affinity == pytest.approx(0.95)
    assert explicit.edges[0].join_count == 2
    assert explicit.edges[0].evidence == ("dispatch", "sandbox")

    with pytest.raises(FormatFail):
        surface_graph_from_rows([3])  # type: ignore[list-item]
    with pytest.raises(FormatFail):
        surface_graph_from_rows([], [3])  # type: ignore[list-item]
    with pytest.raises(FormatFail):
        surface_graph_from_rows([{"id": "a", "feeds": 3}])
    with pytest.raises(FormatFail):
        surface_graph_from_rows([{"id": "a", "feeds": [3]}])
    with pytest.raises(FormatFail):
        surface_graph_from_rows([{"id": "a", "category": "media"}], [{"source": "a"}])


def _chain_graph() -> SurfaceGraph:
    return SurfaceGraph(
        nodes=(
            node("iokit-entry", "iokit", zero_click=True, impact=0.9, feasibility=0.9, privilege=1),
            node("xpc-service", "xpc", impact=0.6, feasibility=0.8),
            node("sandbox-profile", "sandbox", impact=0.7, feasibility=0.7),
            node("kernel-task", "kernel", impact=1.0, feasibility=1.0, privilege=4, persistence=True),
            node("media-entry", "media", zero_click=True, impact=0.8, feasibility=0.9),
            node("codec-entry", "codec", impact=0.7, feasibility=0.9),
            node("render-entry", "render", impact=0.6, feasibility=0.8),
            node("jsc-entry", "jsc", impact=0.9, feasibility=0.7),
        ),
        edges=(
            edge("e1", "iokit-entry", "xpc-service", kind="xpc_dispatch", privilege_delta=1, impact_delta=0.4, feasibility=0.9, reliability=0.9, cost=1),
            edge("e2", "xpc-service", "sandbox-profile", kind="xpc_dispatch", privilege_delta=2, impact_delta=0.5, feasibility=0.8, reliability=0.8, cost=1),
            edge("e3", "sandbox-profile", "kernel-task", kind="sandbox_escape", privilege_delta=3, impact_delta=0.8, feasibility=0.7, reliability=0.7, cost=2),
            edge("m1", "media-entry", "codec-entry", kind="codec_handoff", privilege_delta=1, impact_delta=0.5, feasibility=0.9, reliability=0.9, cost=1),
            edge("m2", "codec-entry", "render-entry", kind="render_pipeline", privilege_delta=1, impact_delta=0.5, feasibility=0.8, reliability=0.8, cost=1),
            edge("m3", "render-entry", "jsc-entry", kind="jsc_bridge", privilege_delta=1, impact_delta=0.5, feasibility=0.7, reliability=0.7, cost=1),
            edge("m4", "jsc-entry", "kernel-task", kind="iokit_kernel", privilege_delta=2, impact_delta=0.9, feasibility=0.6, reliability=0.6, cost=2),
        ),
    )


def test_enumerate_surface_chains_finds_multi_hop_cross_surface_paths():
    graph = _chain_graph()
    config = SurfaceChainConfig(min_hops=3, max_hops=5, max_paths=16)
    bfs = enumerate_surface_chains(graph, config)
    dfs = enumerate_surface_chains(graph, replace(config, algorithm=SurfaceSearchAlgorithm.DFS))
    assert bfs.stop_reason == "found"
    assert bfs.truncated is False
    assert len(bfs.paths) == 2
    assert {path.dedup_material() for path in bfs.paths} == {
        path.dedup_material() for path in dfs.paths
    }
    assert all(path.cross_surface for path in bfs.paths)
    assert all(path.hop_count >= 3 for path in bfs.paths)
    assert all(path.target == "kernel-task" for path in bfs.paths)
    assert len({path.dedup_material() for path in bfs.paths}) == len(bfs.paths)
    assert enumerate_surface_chains(graph, config).to_dict() == bfs.to_dict()
    assert {path.nodes for path in bfs.paths} == {
        ("iokit-entry", "xpc-service", "sandbox-profile", "kernel-task"),
        ("media-entry", "codec-entry", "render-entry", "jsc-entry", "kernel-task"),
    }


def test_enumerate_surface_chains_honors_scope_bounds_and_pruning():
    graph = _chain_graph()
    scoped = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, max_hops=5, max_paths=4),
        sources=["media-entry"],
        targets=["kernel-task"],
    )
    assert len(scoped.paths) == 1
    assert scoped.paths[0].source == "media-entry"
    assert scoped.paths[0].hop_count == 4

    with pytest.raises(FormatFail):
        enumerate_surface_chains(graph, sources=["missing"])
    with pytest.raises(FormatFail):
        enumerate_surface_chains(graph, targets=["missing"])

    empty_sources = SurfaceGraph(
        nodes=(node("a", "media"), node("b", "kernel", persistence=True)),
        edges=(edge("e", "a", "b"),),
    )
    assert enumerate_surface_chains(empty_sources).stop_reason == "no_ingress"
    no_target = SurfaceGraph(
        nodes=(node("a", "media", zero_click=True), node("b", "codec")),
        edges=(edge("e", "a", "b"),),
    )
    assert enumerate_surface_chains(no_target).stop_reason == "no_target"

    same_category = SurfaceGraph(
        nodes=(node("a", "media", zero_click=True), node("b", "media", persistence=True)),
        edges=(edge("e", "a", "b"),),
    )
    assert enumerate_surface_chains(same_category, SurfaceChainConfig(min_hops=1)).paths == ()
    allowed = enumerate_surface_chains(
        same_category,
        SurfaceChainConfig(min_hops=1, require_cross_surface=False),
    )
    assert len(allowed.paths) == 1 and allowed.paths[0].cross_surface is False

    ticks = iter([0.0, 10.0])
    deadline = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, deadline_s=1.0, clock=lambda: next(ticks)),
    )
    assert deadline.truncated is True and deadline.stop_reason == "deadline"

    relaxation = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, max_expansions=100, max_relaxations=2),
    )
    assert relaxation.truncated is True and relaxation.stop_reason == "relaxation_cap"
    expansion = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, max_expansions=1, max_relaxations=100),
    )
    assert expansion.truncated is True and expansion.stop_reason == "expansion_cap"


def test_surface_chain_config_validation():
    config = SurfaceChainConfig()
    config.validate()
    bad_configs = [
        {"min_hops": 0},
        {"min_hops": True},
        {"min_hops": 9, "max_hops": 8},
        {"max_hops": 9},
        {"max_paths": 0},
        {"max_paths": True},
        {"max_paths": 1025},
        {"max_expansions": 0},
        {"max_relaxations": 0},
        {"deadline_s": 0.0},
        {"deadline_s": float("inf")},
        {"require_cross_surface": "yes"},
        {"dead_end_pruning": 1},
        {"algorithm": "random"},
    ]
    for kwargs in bad_configs:
        with pytest.raises(FormatFail):
            SurfaceChainConfig(**kwargs).validate()  # type: ignore[arg-type]


def _path(nodes: tuple[str, ...], edges: tuple[SurfaceEdge, ...], **kwargs: object) -> SurfaceChainPath:
    values: dict[str, object] = {
        "categories": tuple(SurfaceCategory.OTHER for _ in nodes),
        "privilege_gain": 0.0,
        "impact": 0.5,
        "feasibility": 0.5,
        "reliability": 0.8,
        "affinity": 0.5,
        "cost": 1.0,
    }
    values.update(kwargs)
    return SurfaceChainPath(nodes=nodes, edges=edges, **values)  # type: ignore[arg-type]


def test_rank_surface_chains_scores_monotonic_quality_and_novelty():
    edges = (
        edge("e1", "a", "b", kind="codec_handoff"),
        edge("e2", "b", "c", kind="jsc_bridge"),
    )
    base = _path(
        ("a", "b", "c"),
        edges,
        categories=(SurfaceCategory.MEDIA, SurfaceCategory.CODEC, SurfaceCategory.JSC),
        impact=0.4,
        feasibility=0.6,
        affinity=0.7,
    )
    low = replace(base, impact=0.2, feasibility=0.3, affinity=0.4)
    high = replace(base, impact=0.8, feasibility=0.9, affinity=0.9)
    novelty = {"a": 0.9, "b": 0.7, "c": 0.8}
    ranked = rank_surface_chains([low, high, base], novelty_scores=novelty)
    assert [item.path for item in ranked] == [high, base, low]
    assert [item.rank for item in ranked] == [1, 2, 3]
    top = ranked[0]
    assert top.novelty_score == pytest.approx(0.7)
    assert top.quality_score == pytest.approx(
        0.40 * 0.8 + 0.25 * 0.9 + 0.20 * 0.9 + 0.15 * 0.7
    )
    assert top.impact_score == 0.8 and top.feasibility_score == 0.9
    assert top.affinity_score == 0.9

    custom_weights = SurfaceQualityWeights(impact=0.5, feasibility=0.2, affinity=0.2, novelty=0.1)
    custom = rank_surface_chains([base], novelty_scores=novelty, weights=custom_weights)[0]
    assert custom.quality_score == pytest.approx(0.5 * 0.4 + 0.2 * 0.6 + 0.2 * 0.7 + 0.1 * 0.7)

    dupe_ranked = rank_surface_chains(
        [base], dupe=StaticDupeOracle({"a": 0.1, "b": 0.2, "c": 0.3}), default_novelty=0.9
    )[0]
    assert dupe_ranked.novelty_score == pytest.approx(0.1)

    with pytest.raises(FormatFail):
        SurfaceQualityWeights(impact=0.7, feasibility=0.7)
    with pytest.raises(FormatFail):
        SurfaceQualityWeights(impact=-0.1, feasibility=0.5, affinity=0.3, novelty=0.3)
    with pytest.raises(FormatFail):
        rank_surface_chains([base], novelty_scores=novelty, dupe=StaticDupeOracle())
    with pytest.raises(FormatFail):
        rank_surface_chains([object()], novelty_scores=novelty)  # type: ignore[list-item]
    with pytest.raises(FormatFail):
        rank_surface_chains([base], novelty_scores={"a": 2.0})
    with pytest.raises(FormatFail):
        replace(top, rank=-1)


def test_surface_chain_emitter_persists_and_deduplicates_claims():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.create_run("macos", run_id="run-surface")
            result = enumerate_surface_chains(_chain_graph(), SurfaceChainConfig(min_hops=3, max_hops=5))
            ranked = rank_surface_chains(result.paths, novelty_scores={"kernel-task": 0.9})
            emitter = SurfaceChainEmitter(ledger)
            first = await emitter.emit(ranked, run_id="run-surface", created=123)
            assert len(first.emitted) == len(ranked)
            assert first.skipped == ()
            assert first.to_dict() == {"emitted": list(first.emitted), "skipped": []}
            second = await emitter.emit(ranked, run_id="run-surface", created=124)
            assert second.emitted == ()
            assert second.skipped == first.emitted
            with pytest.raises(FormatFail):
                await emitter.emit(ranked, limit=0)
            with pytest.raises(FormatFail):
                await emitter.emit([object()], limit=1)  # type: ignore[list-item]
        finally:
            await ledger.close()

    run(body())


def test_surface_enumeration_properties_terminate_and_do_not_duplicate():
    rng = random.Random(20260318)
    for case in range(20):
        node_count = rng.randint(5, 9)
        categories = [
            SurfaceCategory.MEDIA,
            SurfaceCategory.CODEC,
            SurfaceCategory.FONT,
            SurfaceCategory.RENDER,
            SurfaceCategory.XPC,
            SurfaceCategory.SANDBOX,
            SurfaceCategory.IOKIT,
            SurfaceCategory.JSC,
            SurfaceCategory.KERNEL,
        ]
        nodes = [
            node(
                f"n{i}",
                categories[(i + case) % len(categories)].value,
                zero_click=(i == 0),
                persistence=(i == node_count - 1),
                impact=rng.random(),
                feasibility=rng.random(),
            )
            for i in range(node_count)
        ]
        edges = []
        for source in range(node_count - 1):
            for target in range(source + 1, node_count):
                if rng.random() < 0.45:
                    edges.append(
                        edge(
                            f"e{source}-{target}",
                            f"n{source}",
                            f"n{target}",
                            kind=rng.choice(list(SurfaceHopKind)),
                            privilege_delta=rng.random(),
                            impact_delta=rng.random(),
                            feasibility=rng.random(),
                            reliability=rng.random(),
                            cost=rng.random(),
                        )
                    )
        graph = SurfaceGraph(nodes=tuple(nodes), edges=tuple(edges))
        result = enumerate_surface_chains(
            graph,
            SurfaceChainConfig(min_hops=3, max_hops=6, max_paths=64, max_expansions=20_000),
        )
        assert result.expansions <= 20_000
        dedup_keys = [path.dedup_material() for path in result.paths]
        assert len(dedup_keys) == len(set(dedup_keys))
        for path in result.paths:
            assert len(path.nodes) == len(set(path.nodes))
            assert path.hop_count == len(path.edges) == len(path.nodes) - 1
            assert path.hop_count >= 3
            assert path.cross_surface is True


def test_surface_chain_quality_is_monotonic_under_component_increases():
    edges = (edge("e1", "a", "b"), edge("e2", "b", "c"))
    base = _path(("a", "b", "c"), edges, impact=0.4, feasibility=0.5, affinity=0.6)
    for field_name, lower, higher in (
        ("impact", 0.1, 0.9),
        ("feasibility", 0.1, 0.9),
        ("affinity", 0.1, 0.9),
    ):
        low_path = replace(base, **{field_name: lower})
        high_path = replace(base, **{field_name: higher})
        low = rank_surface_chains([low_path], novelty_scores={"a": 0.5, "b": 0.5, "c": 0.5})[0]
        high = rank_surface_chains([high_path], novelty_scores={"a": 0.5, "b": 0.5, "c": 0.5})[0]
        assert high.quality_score > low.quality_score


def test_escalation_reasoner_consumes_cross_surface_chain_output():
    result = enumerate_surface_chains(_chain_graph(), SurfaceChainConfig(min_hops=3, max_hops=5))
    assert result.paths
    escalation_graph = graph_from_chain_outputs(result.to_dict())
    assert len(escalation_graph.nodes) == 8
    assert len(escalation_graph.edges) == 7
    for path in result.paths:
        analysis = analyze_escalations(
            escalation_graph,
            sources=[path.source],
            targets=[path.target],
            max_paths=4,
        )
        assert any(candidate.nodes == path.nodes for candidate in analysis.paths)


def test_surface_validation_adapter_and_reach_edge_cases(monkeypatch: pytest.MonkeyPatch):
    assert parse_surface_category("   ") is SurfaceCategory.OTHER
    assert parse_surface_hop_kind("   ") is SurfaceHopKind.GENERIC
    with pytest.raises(FormatFail):
        parse_surface_hop_kind(3)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        SurfaceNode(id=3, category="media")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        SurfaceNode(id="n", category="media", name=3)  # type: ignore[arg-type]
    assert SurfaceNode(id="n", category="media", name=None).name == ""  # type: ignore[arg-type]

    with pytest.raises(FormatFail):
        surface_graph_from_rows([{"id": "a", "category": "media", "privilege": -1}])
    with pytest.raises(FormatFail):
        surface_graph_from_rows(
            [{"id": "a", "category": "media"}, {"id": "b", "category": "codec"}],
            [{"source": "a", "target": "b", "privilege_delta": -1}],
        )
    with pytest.raises(FormatFail):
        surface_graph_from_rows(
            [{"id": "a", "category": "media"}, {"id": "b", "category": "codec"}],
            [{"source": "a", "target": "b", "join_count": "2"}],
        )
    with pytest.raises(FormatFail):
        surface_graph_from_rows(
            [{"id": "a", "category": "media"}, {"id": "b", "category": "codec"}],
            [{"source": "a", "target": "b", "join_count": 2.5}],
        )

    relation = surface_graph_from_rows(
        [{"id": "a", "category": "media"}, {"id": "b", "category": "codec"}],
        [{"source": "a", "target": "b", "relation": "codec_handoff"}],
    )
    assert relation.edges[0].kind is SurfaceHopKind.CODEC_HANDOFF
    typed = surface_graph_from_rows(
        [{"id": "a", "category": "jsc"}, {"id": "b", "category": "kernel"}],
        [{"source": "a", "target": "b", "type": "jsc_bridge"}],
    )
    assert typed.edges[0].kind is SurfaceHopKind.JSC_BRIDGE
    explicit_affinity = SurfaceGraph(
        nodes=(node("a", "media"), node("b", "codec")),
        edges=(edge("e", "a", "b", affinity=0.42),),
    )
    assert explicit_affinity.edges[0].affinity == pytest.approx(0.42)

    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=("bad",), edges=())  # type: ignore[arg-type]
    truthy = surface_graph_from_rows([{"id": "a", "category": "media", "zero_click": "yes"}])
    assert truthy.node_map["a"].is_ingress is True
    reach = surface_graph_from_rows(
        [
            {"id": "bad-json", "category": "media", "reach_from_json": "not-json"},
            {"id": "map", "category": "media", "reach_from": {"via": "zero_click"}},
            {"id": "list", "category": "media", "reach_from": [1, {"hops": 0}]},
            {"id": "json-map", "category": "media", "reach_from_json": '{"via":"zero_click"}'},
            {"id": "other", "category": "media", "reach_from": 3},
        ]
    )
    assert reach.node_map["bad-json"].is_ingress is False
    assert reach.node_map["map"].is_ingress is True
    assert reach.node_map["list"].is_ingress is True
    assert reach.node_map["json-map"].is_ingress is True
    assert reach.node_map["other"].is_ingress is False

    monkeypatch.setattr("ra.chain.surface.MAX_SURFACE_NODES", 1)
    with pytest.raises(FormatFail):
        SurfaceGraph(nodes=(node("a", "media"), node("b", "codec")), edges=())


def test_surface_chain_model_quality_and_emit_result_edge_cases():
    edges = (edge("e1", "a", "b"), edge("e2", "b", "c"))
    path = _path(("a", "b", "c"), edges)
    assert path.rank_key == (-path.impact, -path.feasibility, -path.affinity, -path.reliability, path.cost)
    with pytest.raises(FormatFail):
        SurfaceChainPath(nodes=("a", "b"), edges=("bad",), categories=("media", "codec"))  # type: ignore[arg-type]

    defaulted = rank_surface_chains([path])[0]
    assert defaulted.novelty_score == pytest.approx(1.0)
    assert defaulted.dedup_material == path.dedup_material()
    assert defaulted.to_dict()["path"]["nodes"] == ["a", "b", "c"]
    assert defaulted.to_dict()["rank"] == 1
    with pytest.raises(FormatFail):
        SurfaceChainQuality(
            path=object(),  # type: ignore[arg-type]
            impact_score=0.0,
            feasibility_score=0.0,
            affinity_score=0.0,
            novelty_score=0.0,
            quality_score=0.0,
        )


def test_enumerate_surface_chains_rejects_non_graph_and_dfs_truncation():
    with pytest.raises(FormatFail):
        enumerate_surface_chains(object())  # type: ignore[arg-type]
    graph = _chain_graph()
    dfs = SurfaceSearchAlgorithm.DFS
    deadline_ticks = iter([0.0, 10.0])
    deadline = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, deadline_s=1.0, algorithm=dfs, clock=lambda: next(deadline_ticks)),
    )
    assert deadline.truncated is True and deadline.stop_reason == "deadline"
    expansion = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, max_expansions=1, max_relaxations=100, algorithm=dfs),
    )
    assert expansion.truncated is True and expansion.stop_reason == "expansion_cap"
    relaxation = enumerate_surface_chains(
        graph,
        SurfaceChainConfig(min_hops=3, max_expansions=100, max_relaxations=2, algorithm=dfs),
    )
    assert relaxation.truncated is True and relaxation.stop_reason == "relaxation_cap"


def test_enumerate_surface_chains_prunes_cycles_and_dead_ends():
    graph = SurfaceGraph(
        nodes=(
            node("a", "media", zero_click=True),
            node("b", "codec"),
            node("c", "kernel", persistence=True),
            node("d", "codec"),
        ),
        edges=(
            edge("ab", "a", "b"),
            edge("ba", "b", "a"),
            edge("bd", "b", "d"),
            edge("bc", "b", "c"),
        ),
    )
    result = enumerate_surface_chains(graph, SurfaceChainConfig(min_hops=2, max_hops=3))
    assert len(result.paths) == 1
    assert result.paths[0].nodes == ("a", "b", "c")


def test_surface_enumeration_honors_max_paths_on_dense_graph():
    nodes = (
        [node("s", "media", zero_click=True)]
        + [node(f"a{i}", "codec") for i in range(4)]
        + [node(f"b{i}", "render") for i in range(4)]
        + [node("t", "kernel", persistence=True)]
    )
    edges = (
        [edge(f"s-a{i}", "s", f"a{i}") for i in range(4)]
        + [edge(f"a{i}-b{j}", f"a{i}", f"b{j}") for i in range(4) for j in range(4)]
        + [edge(f"b{j}-t", f"b{j}", "t") for j in range(4)]
    )
    result = enumerate_surface_chains(
        SurfaceGraph(nodes=tuple(nodes), edges=tuple(edges)),
        SurfaceChainConfig(min_hops=3, max_hops=3, max_paths=3, max_expansions=10_000, max_relaxations=100_000),
    )
    assert result.stop_reason == "found"
    assert len(result.paths) == 3
    assert len({path.dedup_material() for path in result.paths}) == 3
    assert all(path.hop_count == 3 and path.cross_surface for path in result.paths)


def test_surface_enumeration_pending_cap_truncates(monkeypatch: pytest.MonkeyPatch):
    import ra.chain.surface as surface_module

    monkeypatch.setattr(surface_module, "MAX_SURFACE_PENDING_STATES", 1)
    graph = SurfaceGraph(
        nodes=(
            node("s", "media", zero_click=True),
            node("a", "codec"),
            node("b", "render"),
            node("t", "kernel", persistence=True),
        ),
        edges=(
            edge("sa", "s", "a"),
            edge("sb", "s", "b"),
            edge("at", "a", "t"),
            edge("bt", "b", "t"),
        ),
    )
    for algorithm in (SurfaceSearchAlgorithm.BFS, SurfaceSearchAlgorithm.DFS):
        result = enumerate_surface_chains(
            graph,
            SurfaceChainConfig(min_hops=2, max_hops=3, max_paths=8, algorithm=algorithm),
        )
        assert result.truncated is True
        assert result.stop_reason == "pending_cap"


def test_surface_enumeration_rejects_non_string_node_ids():
    graph = _chain_graph()
    with pytest.raises(FormatFail):
        enumerate_surface_chains(graph, SurfaceChainConfig(), sources=(1,))  # type: ignore[arg-type]


def test_surface_emitter_validates_all_claims_before_writes(tmp_path):
    async def main() -> None:
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        try:
            await ledger.create_run("macos", run_id="run-1")
            path = enumerate_surface_chains(
                _chain_graph(), SurfaceChainConfig(min_hops=3, max_hops=5, max_paths=2)
            ).paths[0]
            good = rank_surface_chains([path])[0]
            bad_path = replace(path, impact=0.0)
            bad = rank_surface_chains([bad_path])[0]
            with pytest.raises(FormatFail):
                await SurfaceChainEmitter(ledger).emit([good, bad], run_id="run-1")
            assert ledger.claims_by_type("bug_class", limit=10) == []
        finally:
            await ledger.close()

    run(main())
