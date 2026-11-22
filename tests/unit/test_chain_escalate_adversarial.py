"""Adversarial bounds and claim-validation tests for chain/escalation search."""

from dataclasses import replace
from pathlib import Path

import pytest

from ra.errors import FormatFail
from ra.escalate import (
    EscalationLedgerEmitter,
    EscalationResult,
    analyze_escalations,
    graph_from_mappings,
)
from ra.ledger import Ledger
from tests.conftest import run


def _graph():
    return graph_from_mappings(
        [
            {"id": "sandbox:a", "stage": "sandbox_profile"},
            {"id": "ent:x", "stage": "entitlement"},
            {"id": "root:r", "stage": "root"},
        ],
        [
            {"source": "sandbox:a", "target": "ent:x", "privilege_delta": 1, "impact_delta": 0.25, "reliability": 0.8},
            {"source": "ent:x", "target": "root:r", "privilege_delta": 2, "impact_delta": 0.5, "reliability": 1.0},
        ],
    )


def test_analyze_escalations_rejects_adversarial_parameters():
    graph = _graph()
    bad_calls = [
        {"max_paths": True},
        {"max_paths": 1.5},
        {"max_expansions": True},
        {"max_relaxations": 1.5},
        {"sources": (1,)},
    ]
    for kwargs in bad_calls:
        with pytest.raises(FormatFail):
            analyze_escalations(graph, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(FormatFail):
        analyze_escalations(object())  # type: ignore[arg-type]


def test_analyze_escalations_stack_cap_truncates(monkeypatch: pytest.MonkeyPatch):
    import ra.escalate.graph as graph_module

    monkeypatch.setattr(graph_module, "MAX_SEARCH_STACK", 1)
    nodes = [{"id": "a", "stage": "sandbox_profile"}, {"id": "r", "stage": "root"}]
    nodes.extend({"id": f"f{i}", "stage": "entitlement"} for i in range(4))
    edges = [{"source": "a", "target": f"f{i}"} for i in range(4)]
    edges.extend({"source": f"f{i}", "target": "r"} for i in range(4))
    result = analyze_escalations(
        graph_from_mappings(nodes, edges),
        max_paths=2,
        max_expansions=100,
        max_relaxations=1000,
    )
    assert result.truncated is True


def test_escalation_emitter_validates_claims_before_writes(tmp_path: Path):
    async def main() -> None:
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        try:
            await ledger.create_run("macos", run_id="run-1")
            result = analyze_escalations(_graph(), max_paths=1)
            bad_path = replace(result.paths[0], impact_score=0.0)
            bad_result = EscalationResult(
                paths=(bad_path,),
                nodes_considered=0,
                edges_considered=0,
                expansions=0,
                relaxations=0,
                truncated=False,
            )
            with pytest.raises(FormatFail):
                await EscalationLedgerEmitter(ledger).emit(bad_result, run_id="run-1")
            assert ledger.claims_by_type("join", limit=10) == []
        finally:
            await ledger.close()

    run(main())
