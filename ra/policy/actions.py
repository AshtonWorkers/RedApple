"""Policy action vocabulary and Appendix D planning costs."""

from __future__ import annotations

from enum import StrEnum


class Action(StrEnum):
    """Closed policy action vocabulary (RA-POL-001)."""

    RETARGET = "retarget"
    REWEIGHT = "reweight"
    SPAWN_SUBFACTORY = "spawn_subfactory"
    WIDEN_DIALECT = "widen_dialect"
    FORCE_GROOM = "force_groom"
    TRY_GADGET_SET = "try_gadget_set"
    ESCALATE_MODEL = "escalate_model"
    DEMOTE = "demote"
    PARK = "park"


ACTIONS = frozenset(Action)
ACTION_COST_USD_MICRO: dict[Action, int] = {
    Action.RETARGET: 20_000,
    Action.REWEIGHT: 10_000,
    Action.SPAWN_SUBFACTORY: 300_000,
    Action.WIDEN_DIALECT: 50_000,
    Action.FORCE_GROOM: 20_000,
    Action.TRY_GADGET_SET: 120_000,
    Action.ESCALATE_MODEL: 400_000,
    Action.DEMOTE: 0,
    Action.PARK: 0,
}


def parse_action(value: str) -> Action:
    """Parse an action or raise FORMAT_FAIL for off-vocabulary input."""
    try:
        return Action(value)
    except ValueError as exc:
        from ..errors import FormatFail

        raise FormatFail(f"off-vocabulary policy action: {value}") from exc
