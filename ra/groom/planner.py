"""Groom planner: search allocator-aware candidates for retained crashes."""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..errors import DialectDefect
from ..ledger import Ledger
from .allocators import (
    AllocatorModelSet,
    adjacent_size_classes,
    is_valid_size_class,
    load_allocator_models,
    size_class_for_kb,
)
from .foundry import FoundryDialectGate, LedgerFoundryDefectSink
from .interfaces import FoundryDefectSink, FoundryDialectValidator, PressAdvisor, TriageService
from .ledgerio import create_reviewed_claim
from .models import (
    MAX_GROOM_CANDIDATES,
    MAX_GROOM_DEPTH,
    CrashCase,
    GroomCandidate,
    GroomPlan,
    GroomPlanOutcome,
    TriageResult,
    canonical_json,
    now_ms,
    sha256_text,
)
from .stubs import NullPressAdvisor, StaticTriage

BEAM_WIDTH = 16
ISOHEAP_PER_TYPE = "per_type"
STRUCTURE_TRANSITION = "transition"


@dataclass(frozen=True)
class _SearchNode:
    """Allocator-state node in the bounded groom search."""

    size_class: str
    cage: str
    isoheap: str
    structure_id: str
    depth: int
    score: float

    def key(self) -> tuple[str, str, str, str]:
        return (self.size_class, self.cage, self.isoheap, self.structure_id)


class GroomPlanner:
    """Plan groom dialect candidates and persist the plan in the ledger."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        models: AllocatorModelSet | None = None,
        triage: TriageService | None = None,
        gate: FoundryDialectValidator | None = None,
        defect_sink: FoundryDefectSink | None = None,
        advisor: PressAdvisor | None = None,
    ) -> None:
        self._ledger = ledger
        self._models = models or load_allocator_models()
        self._triage = triage or StaticTriage()
        self._gate = gate or FoundryDialectGate()
        self._defect_sink = defect_sink or LedgerFoundryDefectSink(ledger)
        self._advisor = advisor or NullPressAdvisor()

    async def plan(
        self,
        case: CrashCase,
        *,
        triage: TriageResult | None = None,
    ) -> GroomPlanOutcome:
        """Classify, search, validate, and ledger-persist groom candidates."""
        result = triage if triage is not None else await self._triage.classify(case)
        advice = await self._advisor.advise_groom(case=case, triage=result)
        nodes, stats = self._search(case, result, advice)
        candidates: list[GroomCandidate] = []
        defects: list[str] = []
        for node in nodes[:MAX_GROOM_CANDIDATES]:
            candidate = self._candidate(node, case)
            try:
                self._gate.validate(candidate.dialect)
            except DialectDefect as exc:
                defects.append(f"{candidate.candidate_id}: {exc}")
                await self._defect_sink.report_dialect_defect(
                    candidate=candidate,
                    case=case,
                    error=str(exc),
                )
                continue
            candidates.append(candidate)
        stats["candidates_validated"] = len(nodes[:MAX_GROOM_CANDIDATES])
        stats["candidates_kept"] = len(candidates)
        stats["defects"] = len(defects)
        plan = self._make_plan(case, tuple(candidates), stats)
        artifacts = self._artifacts(case, result, plan)
        claim_id = await create_reviewed_claim(
            self._ledger,
            claim_id=self._claim_id(plan),
            claim_type="groom",
            value={
                "status": "planned" if candidates else ("defect" if defects else "no_candidates"),
                "crash_id": case.id,
                "plan_id": plan.plan_id,
                "candidate_count": len(candidates),
                "defects": defects,
                "stats": dict(stats),
            },
            confidence=0.5 + min(0.4, 0.05 * len(candidates)),
            dedup=self._dedup_key(case, plan),
            artifacts=artifacts,
            run_id=case.run_id,
            created=plan.created_ms,
        )
        return GroomPlanOutcome(
            case=case,
            triage=result,
            plan=plan,
            claim_id=claim_id,
            defects=tuple(defects),
        )

    def _search(
        self,
        case: CrashCase,
        triage: TriageResult,
        advice: Mapping[str, Any] | None,
    ) -> tuple[list[_SearchNode], dict[str, int]]:
        """Beam-search allocator states within depth/candidate caps."""
        seeds = self._seed_size_classes(case, triage, advice)
        initial = [
            _SearchNode(
                size_class=size_class,
                cage="",
                isoheap="",
                structure_id="",
                depth=0,
                score=self._score(size_class, "", "", "", 0, triage, advice),
            )
            for size_class in seeds
        ]
        initial.sort(key=lambda node: (-node.score, node.key()))
        beam = initial[:BEAM_WIDTH]
        selected: list[_SearchNode] = list(beam)
        seen = {node.key() for node in selected}
        expanded = 0
        memo_hits = 0
        for depth in range(1, MAX_GROOM_DEPTH + 1):
            neighbors: list[_SearchNode] = []
            for node in beam:
                expanded += 1
                for neighbor in self._neighbors(node, depth, triage, advice):
                    key = neighbor.key()
                    if key in seen:
                        memo_hits += 1
                        continue
                    seen.add(key)
                    neighbors.append(neighbor)
            neighbors.sort(key=lambda node: (-node.score, node.key()))
            beam = neighbors[:BEAM_WIDTH]
            selected.extend(beam)
            if not beam:
                break
        selected.sort(key=lambda node: (-node.score, node.depth, node.key()))
        selected = selected[:MAX_GROOM_CANDIDATES]
        stats = {
            "seeds": len(seeds),
            "expanded": expanded,
            "memo_hits": memo_hits,
            "generated": len(selected),
            "max_depth": MAX_GROOM_DEPTH,
            "beam_width": BEAM_WIDTH,
        }
        return selected, stats

    def _neighbors(
        self,
        node: _SearchNode,
        depth: int,
        triage: TriageResult,
        advice: Mapping[str, Any] | None,
    ) -> list[_SearchNode]:
        """Return one-step allocator-state mutations for ``node``."""
        out: list[_SearchNode] = []
        try:
            prev_class, next_class = adjacent_size_classes(node.size_class, self._models)
        except Exception:
            prev_class = next_class = node.size_class
        for size_class in {prev_class, next_class}:
            if size_class != node.size_class:
                out.append(self._node(node, size_class=size_class, depth=depth, triage=triage, advice=advice))
        cages = self._cage_values()
        for cage in cages:
            if cage != node.cage:
                out.append(self._node(node, cage=cage, depth=depth, triage=triage, advice=advice))
        for isoheap in ("", ISOHEAP_PER_TYPE):
            if isoheap != node.isoheap:
                out.append(self._node(node, isoheap=isoheap, depth=depth, triage=triage, advice=advice))
        for structure_id in ("", STRUCTURE_TRANSITION):
            if structure_id != node.structure_id:
                out.append(
                    self._node(
                        node,
                        structure_id=structure_id,
                        depth=depth,
                        triage=triage,
                        advice=advice,
                    )
                )
        return out

    def _node(
        self,
        parent: _SearchNode,
        *,
        size_class: str | None = None,
        cage: str | None = None,
        isoheap: str | None = None,
        structure_id: str | None = None,
        depth: int,
        triage: TriageResult,
        advice: Mapping[str, Any] | None,
    ) -> _SearchNode:
        new_size = parent.size_class if size_class is None else size_class
        new_cage = parent.cage if cage is None else cage
        new_iso = parent.isoheap if isoheap is None else isoheap
        new_structure = parent.structure_id if structure_id is None else structure_id
        return _SearchNode(
            size_class=new_size,
            cage=new_cage,
            isoheap=new_iso,
            structure_id=new_structure,
            depth=depth,
            score=self._score(new_size, new_cage, new_iso, new_structure, depth, triage, advice),
        )

    def _score(
        self,
        size_class: str,
        cage: str,
        isoheap: str,
        structure_id: str,
        depth: int,
        triage: TriageResult,
        advice: Mapping[str, Any] | None,
    ) -> float:
        score = 0.0 - (1.25 * depth)
        hinted = self._hinted_size_class(triage)
        if hinted is not None and size_class == hinted:
            score += 5.0
        if advice is not None:
            advice_class = advice.get("size_class")
            if isinstance(advice_class, str) and size_class == advice_class:
                score += 3.0
            if advice.get("prefer_cage") and cage:
                score += 0.5
            if advice.get("prefer_isoheap") and isoheap:
                score += 0.5
            if advice.get("prefer_structure_transition") and structure_id:
                score += 0.5
        if cage:
            score += 0.25
        if isoheap:
            score += 0.5
        if structure_id:
            score += 0.5
        return score

    def _seed_size_classes(
        self,
        case: CrashCase,
        triage: TriageResult,
        advice: Mapping[str, Any] | None,
    ) -> tuple[str, ...]:
        seeds: list[str] = []
        hinted = self._hinted_size_class(triage)
        if hinted is not None:
            seeds.append(hinted)
        advice_class = advice.get("size_class") if advice is not None else None
        if isinstance(advice_class, str) and is_valid_size_class(advice_class):
            seeds.append(advice_class)
        size_kb = case.metadata.get("size_kb")
        if isinstance(size_kb, int) and not isinstance(size_kb, bool) and size_kb > 0:
            with contextlib.suppress(Exception):
                seeds.append(size_class_for_kb(size_kb, self._models))
        for fallback in ("kalloc_1024", "kalloc_2048", "kalloc_512"):
            seeds.append(fallback)
        out: list[str] = []
        for seed in seeds:
            if is_valid_size_class(seed) and seed not in out:
                out.append(seed)
        if not out:
            out = list(self._models.libpas().size_classes()[:2])
        return tuple(out[:4])

    def _hinted_size_class(self, triage: TriageResult) -> str | None:
        for value in (triage.primitive_hint, triage.bug_class):
            if value is None:
                continue
            text = str(value)
            for token in text.replace(",", " ").split():
                if is_valid_size_class(token) and self._models.is_known_size_class(token):
                    return token
        return None

    def _cage_values(self) -> tuple[str, ...]:
        try:
            cages = self._models.get("gigacage").cages
        except Exception:
            cages = ()
        return ("", *cages)

    def _candidate(self, node: _SearchNode, case: CrashCase) -> GroomCandidate:
        size_class = node.size_class
        dialect: dict[str, Any] = {
            "format": self._models.format,
            "pre_seed": [
                {"box": "meta", "pad_to_class": size_class, "count": 2 + node.depth}
            ],
            "victim_pad": "align_to_class",
            "victim_class": size_class,
            "post": {"free": "ipco_before_victim"},
            "validator": "heap_diff.class_stable",
        }
        candidate_key = canonical_json(
            {
                "size_class": size_class,
                "cage": node.cage,
                "isoheap": node.isoheap,
                "structure_id": node.structure_id,
            }
        )
        candidate_id = "groom_" + sha256_text(candidate_key)[:16]
        rationale = (
            f"libpas={size_class}; depth={node.depth}; "
            f"cage={node.cage or 'none'}; isoheap={node.isoheap or 'none'}; "
            f"structure_id={node.structure_id or 'none'}"
        )
        return GroomCandidate(
            candidate_id=candidate_id,
            depth=node.depth,
            score=node.score,
            dialect=dialect,
            size_class=size_class,
            cage=node.cage,
            isoheap=node.isoheap,
            structure_id=node.structure_id,
            provenance=self._models.provenance_for(
                size_class,
                cage=node.cage,
                isoheap=node.isoheap,
                structure_id=node.structure_id,
            ),
            rationale=rationale,
        )

    def _make_plan(
        self,
        case: CrashCase,
        candidates: tuple[GroomCandidate, ...],
        stats: dict[str, int],
    ) -> GroomPlan:
        digest = sha256_text(
            canonical_json(
                {
                    "crash_id": case.id,
                    "stats": dict(stats),
                    "candidates": [candidate.to_dict() for candidate in candidates],
                }
            )
        )[:24]
        return GroomPlan(
            plan_id=f"gplan_{digest}",
            crash_id=case.id,
            candidates=candidates,
            created_ms=now_ms(),
            stats=stats,
        )

    def _artifacts(
        self,
        case: CrashCase,
        triage: TriageResult,
        plan: GroomPlan,
    ) -> tuple[tuple[str, bytes], ...]:
        artifacts: list[tuple[str, bytes]] = [("groom_plan", canonical_json(plan.to_dict()).encode())]
        if case.payload:
            artifacts.append(("crash", case.payload))
        for index, blob in enumerate(triage.artifacts):
            artifacts.append((f"triage_{index}", blob))
        return tuple(artifacts)

    def _claim_id(self, plan: GroomPlan) -> str:
        return "groom_claim_" + sha256_text(plan.plan_id)[:24]

    def _dedup_key(self, case: CrashCase, plan: GroomPlan) -> str:
        return f"groom_plan:{case.id}:{sha256_text(plan.plan_id)[:16]}"
