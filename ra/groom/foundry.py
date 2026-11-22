"""Foundry integration for groom dialect validation and defect reporting."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..errors import DialectDefect as RaDialectDefect
from ..foundry.dialect import validate_dialect
from ..foundry.errors import DialectDefect as FoundryDialectDefect
from ..ledger import Ledger
from .allocators import AllocatorModelSet, load_allocator_models
from .models import CrashCase, GroomCandidate, canonical_json


class FoundryDialectGate:
    """Validate groom dialects through the foundry schema/§11 rules."""

    def __init__(self, allocator_models: AllocatorModelSet | None = None) -> None:
        self._allocator_models = allocator_models

    def validate(self, dialect: Mapping[str, Any]) -> None:
        """Raise ``ra.errors.DialectDefect`` for invalid groom dialects."""
        try:
            validate_dialect(dict(dialect))
        except FoundryDialectDefect as exc:
            raise RaDialectDefect(str(exc)) from exc
        models = self._allocator_models or load_allocator_models()
        victim_class = dialect.get("victim_class")
        if not models.is_libpas_size_class(str(victim_class)):
            raise RaDialectDefect(f"unknown libpas victim size class {victim_class!r}")
        pre_seed = dialect.get("pre_seed", [])
        if isinstance(pre_seed, list):
            for item in pre_seed:
                if not isinstance(item, Mapping):
                    continue
                pad_to_class = item.get("pad_to_class")
                if pad_to_class is not None and not models.is_libpas_size_class(str(pad_to_class)):
                    raise RaDialectDefect(f"unknown libpas pad size class {pad_to_class!r}")


class LedgerFoundryDefectSink:
    """Persist invalid-groom reports as ledger work orders for foundry."""

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    async def report_dialect_defect(
        self,
        *,
        candidate: GroomCandidate,
        case: CrashCase,
        error: str,
    ) -> None:
        """Enqueue a ``widen_dialect`` work order carrying the defect."""
        payload = {
            "crash_id": case.id,
            "candidate": candidate.to_dict(),
            "error": error,
        }
        await self._ledger.enqueue_work_order(
            action="widen_dialect",
            unit=f"groom:{candidate.candidate_id}",
            ev_cost=0.0,
            state="dialect_defect",
            run_id=case.run_id,
            payload_json=canonical_json(payload),
        )
