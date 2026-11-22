"""Model validation and scoring tests for ra.escalate."""

import math

import pytest

from ra.errors import FormatFail
from ra.escalate import (
    EscalationEdge,
    EscalationNode,
    EscalationPath,
    EscalationStage,
    default_privilege,
    edge_impact_score,
    parse_stage,
    stage_for_name,
)


def test_stage_classification_and_defaults():
    assert stage_for_name("sandbox:app") is EscalationStage.SANDBOX_PROFILE
    assert stage_for_name("ent:com.apple.private") is EscalationStage.ENTITLEMENT
    assert stage_for_name("com.apple.service") is EscalationStage.SERVICE
    assert stage_for_name("xnu.kernel") is EscalationStage.KERNEL
    assert stage_for_name("uid0:daemon") is EscalationStage.ROOT
    assert default_privilege(EscalationStage.KERNEL) == 4.0
    assert parse_stage("svc") is EscalationStage.SERVICE
    assert parse_stage(EscalationStage.ROOT) is EscalationStage.ROOT
    with pytest.raises(FormatFail):
        parse_stage("unknown")
    with pytest.raises(FormatFail):
        parse_stage(3)


def test_node_validation_and_clamping():
    node = EscalationNode(id=" svc ", stage="service", privilege=99, impact=-1, name=None)
    assert node.id == "svc"
    assert node.stage is EscalationStage.SERVICE
    assert node.privilege == 5.0
    assert node.impact == 0.0
    assert node.name == ""
    with pytest.raises(FormatFail):
        EscalationNode(id="", stage=EscalationStage.SERVICE)
    with pytest.raises(FormatFail):
        EscalationNode(id=1, stage=EscalationStage.SERVICE)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationNode(id="x", stage=EscalationStage.SERVICE, privilege=math.nan)
    with pytest.raises(FormatFail):
        EscalationNode(id="x", stage=EscalationStage.SERVICE, impact=math.inf)
    with pytest.raises(FormatFail):
        EscalationNode(id="x", stage=EscalationStage.SERVICE, name=3)  # type: ignore[arg-type]


def test_edge_validation_scoring_and_evidence():
    edge = EscalationEdge(
        source="a",
        target="b",
        relation="hop",
        privilege_delta=2,
        impact_delta=0.5,
        cost=3,
        reliability=2,
        join_count=-4,
        evidence=[" z ", "a", "z", "  "],
    )
    assert edge.privilege_delta == 2.0
    assert edge.reliability == 1.0
    assert edge.join_count == 0
    assert edge.evidence == ("a", "z")
    assert edge_impact_score(edge) == pytest.approx(1.5)
    assert edge.impact_score() == pytest.approx(1.5)
    assert edge.key == ("a", "b", "hop")

    with pytest.raises(FormatFail):
        EscalationEdge(source="", target="b")
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="")
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", relation=" ")
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", privilege_delta="x")  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", impact_delta=math.inf)
    negative_cost = EscalationEdge(source="a", target="b", cost=-1)
    assert negative_cost.cost == 0.0
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", reliability=math.nan)
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", join_count=True)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", join_count=1.5)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", evidence=3)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationEdge(source="a", target="b", evidence=["ok", 2])  # type: ignore[list-item]


def _path() -> EscalationPath:
    edge = EscalationEdge(
        source="sandbox:a", target="root:r", privilege_delta=1, impact_delta=0.25
    )
    return EscalationPath(
        nodes=("sandbox:a", "root:r"),
        edges=(edge,),
        privilege_gain=1,
        impact_gain=0.25,
        impact_score=0.5,
        reliability=0.5,
        cost=2,
        stage_progress=4,
    )


def test_path_properties_and_dict():
    path = _path()
    assert path.source == "sandbox:a"
    assert path.target == "root:r"
    assert path.hop_count == 1
    assert path.edge_keys == (("sandbox:a", "root:r", "escalates"),)
    assert path.rank_key[0] == pytest.approx(-0.5)
    data = path.to_dict()
    assert data["nodes"] == ["sandbox:a", "root:r"]
    assert data["edges"][0]["impact_score"] == pytest.approx(0.5)
    assert path.dedup_material()

    with pytest.raises(FormatFail):
        EscalationPath(nodes=(), edges=(), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0)
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", ""), edges=(), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0)
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", "a"), edges=(), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0)
    bad_edge = EscalationEdge(source="x", target="y")
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", "b"), edges=(), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0)
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", "b"), edges=(bad_edge,), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0)
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", "b"), edges=(), privilege_gain=math.nan, impact_gain=0, impact_score=0, reliability=1, cost=0)
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", "b"), edges=(), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0, stage_progress=True)  # type: ignore[arg-type]


def test_model_branch_coverage_edges():
    edge = EscalationEdge(source="a", target="b", evidence=None)  # type: ignore[arg-type]
    assert edge.evidence == ()
    assert EscalationEdge(source="a", target="b", evidence="x").evidence == ("x",)
    with pytest.raises(FormatFail):
        EscalationPath(nodes=("a", "b"), edges=("bad",), privilege_gain=0, impact_gain=0, impact_score=0, reliability=1, cost=0)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        EscalationPath(
            nodes=("a", "b"),
            edges=(EscalationEdge(source="a", target="b"),),
            privilege_gain=0,
            impact_gain=0,
            impact_score=0,
            reliability=1,
            cost=0,
            stage_progress=1.5,
        )  # type: ignore[arg-type]
