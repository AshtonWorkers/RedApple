"""Policy value objects shared by routing, gates, and tests."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

from ..errors import FormatFail

SQLITE_INT_MAX = 2**63 - 1


@dataclass(frozen=True)
class EVInputs:
    """Expected-value inputs for one policy decision.

    ``probability_join`` is P(join), ``chain_bonus`` and ``ingress_weight`` are
    the chain/dupe and surface-graph multipliers from the EV contract.
    """

    probability_join: float
    chain_bonus: float = 1.0
    ingress_weight: float = 1.0
    lane_id: str | None = None
    requires_lane: bool = False
    join_live: bool = False
    cas_bytes: int = 0
    trigger_metric: str = "policy"
    observed: float = 0.0
    expected: str = ""

    def validate(self) -> None:
        """Reject non-finite or out-of-range EV inputs before any ledger write."""
        values = {
            "probability_join": self.probability_join,
            "chain_bonus": self.chain_bonus,
            "ingress_weight": self.ingress_weight,
            "observed": self.observed,
        }
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise FormatFail(f"EV input {name} must be a number")
            if not math.isfinite(float(value)):
                raise FormatFail(f"EV input {name} must be finite")
        if not 0.0 <= float(self.probability_join) <= 1.0:
            raise FormatFail("probability_join must be in [0,1]")
        if float(self.chain_bonus) < 0.0 or float(self.ingress_weight) < 0.0:
            raise FormatFail("chain_bonus and ingress_weight must be >= 0")
        if isinstance(self.cas_bytes, bool) or not isinstance(self.cas_bytes, int):
            raise FormatFail("cas_bytes must be int")
        if self.cas_bytes < 0:
            raise FormatFail("cas_bytes must be >= 0")
        if self.cas_bytes > SQLITE_INT_MAX:
            raise FormatFail("cas_bytes exceeds ledger integer range")
        if not isinstance(self.requires_lane, bool):
            raise FormatFail("requires_lane must be bool")
        if not isinstance(self.join_live, bool):
            raise FormatFail("join_live must be bool")
        if self.lane_id is not None and (
            not isinstance(self.lane_id, str) or not self.lane_id
        ):
            raise FormatFail("lane_id must be a non-empty string when set")
        if not isinstance(self.trigger_metric, str) or not self.trigger_metric:
            raise FormatFail("trigger_metric must be a non-empty string")
        if not isinstance(self.expected, str):
            raise FormatFail("expected must be a string")


@dataclass(frozen=True)
class LaneAvailability:
    """Runtime lane state consumed by the policy gate."""

    lane_id: str
    busy: bool = False
    reason: str = ""
    retry_after_ms: int = 0

    def validate(self) -> None:
        """Reject malformed lane state before dispatch decisions."""
        if not isinstance(self.lane_id, str) or not self.lane_id:
            raise FormatFail("lane_id must be a non-empty string")
        if not isinstance(self.busy, bool):
            raise FormatFail("lane busy must be bool")
        if not isinstance(self.reason, str):
            raise FormatFail("lane reason must be a string")
        if isinstance(self.retry_after_ms, bool) or not isinstance(self.retry_after_ms, int):
            raise FormatFail("retry_after_ms must be int")
        if self.retry_after_ms < 0:
            raise FormatFail("retry_after_ms must be >= 0")


class ActionOutcome(StrEnum):
    """Terminal outcome reported by an action handler."""

    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(frozen=True)
class ActionResult:
    """Result returned by an action handler after it runs."""

    outcome: ActionOutcome = ActionOutcome.SUCCESS
    observed: float = 0.0
    expected: str = ""
    detail: str = ""

    def validate(self) -> None:
        """Reject malformed handler results before they reach the ledger."""
        if not isinstance(self.outcome, ActionOutcome):
            raise FormatFail("action outcome must be ActionOutcome")
        if isinstance(self.observed, bool) or not isinstance(self.observed, (int, float)):
            raise FormatFail("action observed must be a number")
        if not math.isfinite(float(self.observed)):
            raise FormatFail("action observed must be finite")
        if not isinstance(self.expected, str):
            raise FormatFail("action expected must be a string")
        if not isinstance(self.detail, str):
            raise FormatFail("action detail must be a string")
