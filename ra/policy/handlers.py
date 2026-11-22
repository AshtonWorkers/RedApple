"""Action handler protocol and deterministic stub."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .models import ActionOutcome, ActionResult


class ActionHandler(Protocol):
    """Execute one admitted policy action.

    Real retarget/reweight/foundry/groom/gadget/model handlers are owned by
    their components; policy only routes and gates the work order.
    """

    async def __call__(self, order: Mapping[str, Any]) -> ActionResult: ...


class NullActionHandler:
    """No-op handler used until action executors are integrated."""

    async def __call__(self, order: Mapping[str, Any]) -> ActionResult:
        return ActionResult(
            outcome=ActionOutcome.SUCCESS,
            observed=float(order.get("ev_cost", 0.0)),
            detail="stub",
        )
