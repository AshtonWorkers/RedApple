"""Join cost/benefit pricing over ledger join rows."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..errors import FormatFail
from ..ledger import Ledger
from .models import (
    MAX_ESCALATION_DELTA,
    MAX_PRICING_FACTOR,
    ChainNode,
    ChainPath,
    JoinPrice,
    SubfactoryCandidate,
)
from .ports import DupeOracle, PolicyAdvisor, PrimitiveProvider
from .stubs import DefaultPolicyAdvisor, NullPrimitiveProvider, StaticDupeOracle


def _finite_nonnegative(
    name: str, value: float, *, maximum: float | None = None
) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or value < 0:
        raise FormatFail(f"{name} must be a finite non-negative number")
    if maximum is not None and value > maximum:
        raise FormatFail(f"{name} must be <= {maximum}")
    return float(value)


def _nonnegative_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FormatFail(f"{name} must be a non-negative int")
    return min(value, MAX_ESCALATION_DELTA)


def _escalation_score(privilege_delta: int, impact_delta: int) -> float:
    delta = privilege_delta + impact_delta
    if delta <= 0:
        return 0.0
    if delta >= MAX_ESCALATION_DELTA:
        return 1.0
    return delta / (1.0 + delta)


def _probability(row: Mapping[str, Any]) -> tuple[float | None, float | None]:
    reliability = row.get("reliability")
    lower_bound = row.get("lower_bound")
    for name, value in (("reliability", reliability), ("lower_bound", lower_bound)):
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0.0 <= value <= 1.0
        ):
            raise FormatFail(f"join {name} must be in [0, 1] or None")
    return (
        None if reliability is None else float(reliability),
        None if lower_bound is None else float(lower_bound),
    )


def price_join_row(
    row: Mapping[str, Any],
    *,
    cost_usd_micro: int,
    chain_bonus: float = 1.0,
    ingress_weight: float = 1.0,
    dupe_score: float = 1.0,
    privilege_delta: int = 0,
    impact_delta: int = 0,
    escalation_weight: float = 1.0,
) -> JoinPrice:
    """Price one ledger join row as benefit/cost with policy EV ordering inputs."""
    if (
        isinstance(cost_usd_micro, bool)
        or not isinstance(cost_usd_micro, int)
        or cost_usd_micro < 0
    ):
        raise FormatFail("join cost_usd_micro must be a non-negative int")
    chain_bonus = _finite_nonnegative(
        "chain_bonus", chain_bonus, maximum=MAX_PRICING_FACTOR
    )
    ingress_weight = _finite_nonnegative(
        "ingress_weight", ingress_weight, maximum=MAX_PRICING_FACTOR
    )
    dupe_score = _finite_nonnegative("dupe_score", dupe_score)
    escalation_weight = _finite_nonnegative(
        "escalation_weight", escalation_weight, maximum=MAX_PRICING_FACTOR
    )
    if dupe_score > 1.0:
        raise FormatFail("dupe_score must be in [0, 1]")
    privilege = _nonnegative_int("privilege_delta", privilege_delta)
    impact = _nonnegative_int("impact_delta", impact_delta)
    reliability, lower_bound = _probability(row)
    probability = lower_bound if lower_bound is not None else reliability
    if probability is None:
        probability = 0.0
    score = _escalation_score(privilege, impact)
    benefit = (
        probability
        * chain_bonus
        * ingress_weight
        * dupe_score
        * (1.0 + escalation_weight * score)
    )
    ev_cost = benefit / cost_usd_micro if cost_usd_micro > 0 else benefit
    return JoinPrice(
        join_id=str(row["id"]),
        a_claim=str(row["a_claim"]),
        b_claim=str(row["b_claim"]),
        state=str(row["state"]),
        created=int(row["created"]),
        reliability=reliability,
        lower_bound=lower_bound,
        probability_join=probability,
        chain_bonus=chain_bonus,
        ingress_weight=ingress_weight,
        dupe_score=dupe_score,
        cost_usd_micro=cost_usd_micro,
        benefit=benefit,
        ev_cost=ev_cost,
        privilege_delta=privilege,
        impact_delta=impact,
        escalation_score=score,
    )


def price_join_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    cost_usd_micro: int,
    chain_bonus: float = 1.0,
    ingress_weight: float = 1.0,
    dupe_score: float = 1.0,
    privilege_delta: int = 0,
    impact_delta: int = 0,
    escalation_weight: float = 1.0,
) -> tuple[JoinPrice, ...]:
    """Price rows and return policy order: EV desc, created asc, id asc (I5)."""
    priced = [
        price_join_row(
            row,
            cost_usd_micro=cost_usd_micro,
            chain_bonus=chain_bonus,
            ingress_weight=ingress_weight,
            dupe_score=dupe_score,
            privilege_delta=privilege_delta,
            impact_delta=impact_delta,
            escalation_weight=escalation_weight,
        )
        for row in rows
    ]
    return tuple(sorted(priced, key=lambda item: (-item.ev_cost, item.created, item.join_id)))


@dataclass(frozen=True)
class ChainPathPrice:
    """Cost/benefit price for one candidate chain path."""

    path: ChainPath
    join_cost_usd_micro: int
    probability: float
    benefit: float
    ev_cost: float
    privilege_delta: int
    impact_delta: int
    escalation_score: float


def _path_escalation(
    path: ChainPath, nodes: Mapping[str, ChainNode] | None
) -> tuple[int, int]:
    if nodes is None:
        return max(0, path.total_privilege_delta), max(0, path.total_impact_delta)
    if not path.node_ids:
        raise FormatFail("chain path must contain at least one node")
    privilege = 0
    impact = 0
    seen: set[str] = set()
    for node_id in path.node_ids[1:]:
        if node_id in seen:
            continue
        seen.add(node_id)
        node = nodes.get(node_id)
        if node is None:
            raise FormatFail(f"chain path node missing from graph: {node_id}")
        privilege += max(0, node.privilege_delta)
        impact += max(0, node.impact_delta)
    return privilege, impact


def price_chain_path(
    path: ChainPath,
    prices: Mapping[str, JoinPrice],
    *,
    nodes: Mapping[str, ChainNode] | None = None,
    escalation_weight: float = 1.0,
) -> ChainPathPrice:
    """Price a chain path without double-counting shared joins or nodes."""
    escalation_weight = _finite_nonnegative(
        "escalation_weight", escalation_weight, maximum=MAX_PRICING_FACTOR
    )
    edge_ids = tuple(dict.fromkeys(path.edge_ids))
    missing = [edge_id for edge_id in edge_ids if edge_id not in prices]
    if missing:
        raise FormatFail(f"missing join price for chain edge: {missing[0]}")
    cost = sum(prices[edge_id].cost_usd_micro for edge_id in edge_ids)
    probability = 1.0
    for edge_id in edge_ids:
        probability *= prices[edge_id].probability_join
    privilege, impact = _path_escalation(path, nodes)
    score = _escalation_score(privilege, impact)
    ingress = _finite_nonnegative(
        "path ingress_weight", path.ingress_weight, maximum=MAX_PRICING_FACTOR
    )
    benefit = probability * ingress * (1.0 + escalation_weight * score)
    ev_cost = benefit / cost if cost > 0 else benefit
    return ChainPathPrice(
        path=path,
        join_cost_usd_micro=cost,
        probability=probability,
        benefit=benefit,
        ev_cost=ev_cost,
        privilege_delta=privilege,
        impact_delta=impact,
        escalation_score=score,
    )


def price_chain_paths(
    paths: Sequence[ChainPath],
    prices: Mapping[str, JoinPrice],
    *,
    nodes: Mapping[str, ChainNode] | None = None,
    escalation_weight: float = 1.0,
) -> tuple[ChainPathPrice, ...]:
    """Price paths and return deterministic EV/cost order."""
    priced = [
        price_chain_path(path, prices, nodes=nodes, escalation_weight=escalation_weight)
        for path in paths
    ]
    return tuple(
        sorted(
            priced,
            key=lambda item: (
                -item.ev_cost,
                item.path.cost,
                item.path.join_count,
                item.path.node_ids,
                item.path.edge_ids,
                item.path.weakest_join_id or "",
            ),
        )
    )


class JoinPricer:
    """Ledger-backed join pricer with stubbed ladder/groom, dupe, and policy inputs."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        primitives: PrimitiveProvider | None = None,
        dupe: DupeOracle | None = None,
        policy: PolicyAdvisor | None = None,
    ) -> None:
        self._ledger = ledger
        self._primitives = primitives or NullPrimitiveProvider()
        self._dupe = dupe or StaticDupeOracle()
        self._policy = policy or DefaultPolicyAdvisor()
        self._claim_cache: dict[str, dict[str, Any] | None] = {}
        self._value_cache: dict[str, Mapping[str, Any]] = {}

    def _claim(self, claim_id: str) -> dict[str, Any] | None:
        if claim_id not in self._claim_cache:
            self._claim_cache[claim_id] = self._ledger.get_claim(claim_id)
        return self._claim_cache[claim_id]

    def _claim_value(self, claim_id: str) -> Mapping[str, Any]:
        if claim_id in self._value_cache:
            return self._value_cache[claim_id]
        row = self._claim(claim_id)
        value: Mapping[str, Any] = {}
        if row is not None:
            raw = row.get("value_json")
            if isinstance(raw, str) and raw:
                parsed = json.loads(raw)
                if isinstance(parsed, Mapping):
                    value = parsed
        self._value_cache[claim_id] = value
        return value

    @staticmethod
    def _claim_int(value: Mapping[str, Any], key: str) -> int | None:
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, int):
            return None
        return item

    def _claim_deltas(self, claim_id: str) -> tuple[int, int]:
        claim = self._claim(claim_id) or {}
        value = self._claim_value(claim_id)
        profile = self._primitives.profile(claim_id, str(claim.get("type", "")), value)
        privilege = self._claim_int(value, "privilege_delta")
        impact = self._claim_int(value, "impact_delta")
        if profile is not None:
            if privilege is None:
                privilege = profile.privilege_delta
            if impact is None:
                impact = profile.impact_delta
        return (
            0 if privilege is None else max(0, min(privilege, MAX_ESCALATION_DELTA)),
            0 if impact is None else max(0, min(impact, MAX_ESCALATION_DELTA)),
        )

    def _ingress_weight(self, row: Mapping[str, Any]) -> float:
        weights: list[float] = []
        for key in ("a_claim", "b_claim"):
            claim_id = str(row[key])
            claim = self._claim(claim_id) or {}
            value = self._claim_value(claim_id)
            profile = self._primitives.profile(claim_id, str(claim.get("type", "")), value)
            raw = value.get("ingress_weight")
            if (
                isinstance(raw, (int, float))
                and not isinstance(raw, bool)
                and math.isfinite(float(raw))
                and raw > 0
            ):
                weights.append(min(float(raw), MAX_PRICING_FACTOR))
            if (
                profile is not None
                and profile.ingress_weight is not None
                and math.isfinite(profile.ingress_weight)
                and profile.ingress_weight > 0
            ):
                weights.append(min(float(profile.ingress_weight), MAX_PRICING_FACTOR))
        return max(weights, default=1.0)

    def _dupe_score(self, row: Mapping[str, Any]) -> float:
        scores = [self._dupe.score(str(row[key])) for key in ("a_claim", "b_claim")]
        return min(scores) if scores else 1.0

    def price_row(
        self,
        row: Mapping[str, Any],
        *,
        chain_bonus: float = 1.0,
        escalation_weight: float = 1.0,
    ) -> JoinPrice:
        """Price one row using ledger claims plus stubbed dependency inputs."""
        privilege, impact = self._claim_deltas(str(row["b_claim"]))
        return price_join_row(
            row,
            cost_usd_micro=self._policy.join_cost_usd_micro(),
            chain_bonus=chain_bonus,
            ingress_weight=self._ingress_weight(row),
            dupe_score=self._dupe_score(row),
            privilege_delta=privilege,
            impact_delta=impact,
            escalation_weight=escalation_weight,
        )

    def price_rows(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        chain_bonus: float = 1.0,
        escalation_weight: float = 1.0,
    ) -> tuple[JoinPrice, ...]:
        """Price rows with per-row dependency inputs and policy ordering."""
        priced = [
            self.price_row(row, chain_bonus=chain_bonus, escalation_weight=escalation_weight)
            for row in rows
        ]
        return tuple(sorted(priced, key=lambda item: (-item.ev_cost, item.created, item.join_id)))

    async def price_ledger(
        self,
        *,
        states: Sequence[str] | None = None,
        limit: int = 1000,
        chain_bonus: float = 1.0,
        escalation_weight: float = 1.0,
    ) -> tuple[JoinPrice, ...]:
        """Read the ledger join table and return priced joins."""
        rows = self._ledger.joins(states=states, limit=limit)
        return self.price_rows(
            rows, chain_bonus=chain_bonus, escalation_weight=escalation_weight
        )


def select_subfactory_candidates(
    paths: Sequence[ChainPath],
    prices: Mapping[str, JoinPrice],
    *,
    floor: float,
) -> tuple[SubfactoryCandidate, ...]:
    """Select below-floor paths, at most one subfactory candidate per join.

    A path is below floor when its weakest join lower bound is under ``floor``.
    For each weakest join, the lowest-cost path wins; ties use join count and
    node/edge ids so the choice is deterministic.
    """
    if not 0.0 <= floor <= 1.0:
        raise FormatFail("subfactory floor must be in [0, 1]")
    best: dict[str, tuple[tuple[object, ...], ChainPath, float]] = {}
    for path in paths:
        weakest = path.weakest_join_id
        if weakest is None or path.min_lower_bound >= floor:
            continue
        price = prices.get(weakest)
        ev = price.ev_cost if price is not None else 0.0
        key = (
            path.cost,
            path.join_count,
            path.node_ids,
            path.edge_ids,
        )
        current = best.get(weakest)
        if current is None or key < current[0]:
            best[weakest] = (key, path, ev)
    candidates = [
        SubfactoryCandidate(join_id=join_id, path=item[1], price_ev_cost=item[2])
        for join_id, item in best.items()
    ]
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                item.path.cost,
                item.path.join_count,
                item.path.node_ids,
                item.path.edge_ids,
                item.join_id,
            ),
        )
    )
