"""End-to-end groom service: triage -> plan -> ladder."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..ledger import Ledger
from .allocators import AllocatorModelSet
from .interfaces import (
    FoundryDefectSink,
    FoundryDialectValidator,
    PressAdvisor,
    PrimitiveAttemptPort,
    TriageService,
)
from .ladder import LadderRunner
from .models import CrashCase, GroomPlanOutcome, LadderOutcome, TriageResult
from .planner import GroomPlanner


@dataclass(frozen=True)
class GroomProcessResult:
    """Combined groom planning and ladder outcome for one crash."""

    case: CrashCase
    triage: TriageResult
    plan: GroomPlanOutcome
    ladder: LadderOutcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.to_dict(),
            "triage": self.triage.to_dict(),
            "plan": self.plan.to_dict(),
            "ladder": self.ladder.to_dict(),
        }


class GroomService:
    """Wire triage, foundry dialect validation, groom planning, and ladder runs."""

    def __init__(self, ledger: Ledger, planner: GroomPlanner, ladder: LadderRunner) -> None:
        self._ledger = ledger
        self._planner = planner
        self._ladder = ladder

    @classmethod
    def create(
        cls,
        ledger: Ledger,
        *,
        models: AllocatorModelSet | None = None,
        triage: TriageService | None = None,
        gate: FoundryDialectValidator | None = None,
        defect_sink: FoundryDefectSink | None = None,
        advisor: PressAdvisor | None = None,
        attempt_port: PrimitiveAttemptPort | None = None,
    ) -> GroomService:
        """Build a service with default planner/ladder dependencies."""
        planner = GroomPlanner(
            ledger,
            models=models,
            triage=triage,
            gate=gate,
            defect_sink=defect_sink,
            advisor=advisor,
        )
        ladder = LadderRunner(
            ledger,
            attempt_port=attempt_port,
            triage=triage,
            gate=gate,
            defect_sink=defect_sink,
            advisor=advisor,
        )
        return cls(ledger, planner, ladder)

    async def process(self, case: CrashCase, *, triage: TriageResult | None = None) -> GroomProcessResult:
        """Plan grooms for ``case`` and run the primitive ladder."""
        plan_outcome = await self._planner.plan(case, triage=triage)
        ladder_outcome = await self._ladder.run(case, plan_outcome.plan, triage=plan_outcome.triage)
        return GroomProcessResult(
            case=case,
            triage=plan_outcome.triage,
            plan=plan_outcome,
            ladder=ladder_outcome,
        )

    async def process_mapping(self, value: Mapping[str, Any]) -> GroomProcessResult:
        """Process a lane/triage-shaped mapping without importing lane types."""
        return await self.process(CrashCase.from_mapping(value))
