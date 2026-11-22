"""Nightly whole-ring replay scheduling and ledger-backed results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..errors import FormatFail, RaError
from ..ledger import Ledger
from ..ledger.db import RING_REPLAY_STATUSES
from ..ledger.ids import UlidFactory, now_ms
from .corpus import CorpusRegistry
from .models import RingNodeSpec  # noqa: F401  (re-exported for callers)


@dataclass(frozen=True)
class ReplayFinding:
    """One finding to replay across the ring."""

    finding_id: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_id:
            raise FormatFail("finding_id must be non-empty")


@dataclass(frozen=True)
class ReplayResult:
    """Backend result for one finding on one ring node."""

    status: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in RING_REPLAY_STATUSES:
            raise FormatFail("replay status is invalid")


class ReplayBackend(Protocol):
    """Execute one finding replay against one ring node."""

    async def replay(
        self, *, node: Mapping[str, Any], corpus_key: str, finding: ReplayFinding
    ) -> ReplayResult:
        """Return pass/fail/error/skipped for this replay."""
        ...  # pragma: no cover


class FindingSource(Protocol):
    """Provide the findings that must replay across the ring."""

    async def findings(self) -> Sequence[ReplayFinding]:
        """Return findings in deterministic order."""
        ...  # pragma: no cover


class LedgerFindingSource:
    """Default finding source: non-terminal bug_class claims in the claim ledger."""

    def __init__(self, ledger: Ledger, *, claim_type: str = "bug_class", limit: int = 1000) -> None:
        self.ledger = ledger
        self.claim_type = claim_type
        self.limit = limit

    async def findings(self) -> list[ReplayFinding]:
        rows = self.ledger.claims_by_type(self.claim_type, limit=self.limit)
        out: list[ReplayFinding] = []
        for row in rows:
            state = str(row["state"])
            if state in {"demoted", "parked"}:
                continue
            out.append(
                ReplayFinding(
                    finding_id=str(row["id"]),
                    detail={
                        "claim_type": str(row["type"]),
                        "claim_state": state,
                        "dedup_key": str(row["dedup_key"]),
                    },
                )
            )
        return sorted(out, key=lambda finding: finding.finding_id)


@dataclass(frozen=True)
class ReplayOutcome:
    """One recorded replay outcome."""

    run_id: str
    epoch: int
    ring_node_id: str
    corpus_key: str
    finding_id: str
    status: str
    replay_id: str
    skipped_existing: bool = False


@dataclass(frozen=True)
class ReplayRunSummary:
    """Aggregate result for one nightly replay run."""

    run_id: str
    epoch: int
    corpus_key: str
    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    outcomes: tuple[ReplayOutcome, ...] = ()


class NightlyReplayScheduler:
    """Replay every finding across every active ring node and persist results."""

    def __init__(
        self,
        ledger: Ledger,
        backend: ReplayBackend,
        *,
        corpus_registry: CorpusRegistry | None = None,
        id_factory: UlidFactory | None = None,
    ) -> None:
        self.ledger = ledger
        self.backend = backend
        self.corpus = corpus_registry or CorpusRegistry(ledger)
        self._ids = id_factory or UlidFactory()

    async def run_nightly(
        self,
        findings: Sequence[ReplayFinding],
        *,
        epoch: int | None = None,
        run_id: str | None = None,
        corpus_key: str | None = None,
        cross_epoch_opt_in: bool = False,
        created: int | None = None,
    ) -> ReplayRunSummary:
        """Run one deterministic whole-ring replay pass."""
        resolved_epoch = self._resolve_epoch(epoch)
        key = corpus_key if corpus_key is not None else f"ring_{resolved_epoch}"
        if not key:
            raise FormatFail("corpus_key must be non-empty")
        nodes = self._active_nodes(resolved_epoch)
        ordered_findings = self._ordered_findings(findings)
        rid = run_id or self._ids.new("ring_run")
        outcomes: list[ReplayOutcome] = []
        for finding in ordered_findings:
            for node in nodes:
                node_id = str(node["id"])
                binding = self.corpus.resolve_binding(
                    key,
                    node_id,
                    resolved_epoch,
                    cross_epoch_opt_in=cross_epoch_opt_in,
                )
                existing = self._existing_replay(rid, node_id, key, finding.finding_id)
                if existing is not None:
                    outcomes.append(
                        ReplayOutcome(
                            run_id=rid,
                            epoch=resolved_epoch,
                            ring_node_id=node_id,
                            corpus_key=key,
                            finding_id=finding.finding_id,
                            status=str(existing["status"]),
                            replay_id=str(existing["id"]),
                            skipped_existing=True,
                        )
                    )
                    continue
                if binding is None:
                    detail: dict[str, Any] = {"reason": "corpus_missing"}
                    status = "skipped"
                    replay_id = await self._record(
                        rid,
                        resolved_epoch,
                        node_id,
                        key,
                        finding,
                        status,
                        detail,
                        created=created,
                    )
                else:
                    status, detail, replay_id = await self._execute(
                        rid,
                        resolved_epoch,
                        node,
                        node_id,
                        key,
                        finding,
                        int(binding["epoch"]),
                        created=created,
                    )
                outcomes.append(
                    ReplayOutcome(
                        run_id=rid,
                        epoch=resolved_epoch,
                        ring_node_id=node_id,
                        corpus_key=key,
                        finding_id=finding.finding_id,
                        status=status,
                        replay_id=replay_id,
                    )
                )
        return self._summary(rid, resolved_epoch, key, tuple(outcomes))

    def _resolve_epoch(self, epoch: int | None) -> int:
        if epoch is not None:
            if epoch < 0:
                raise FormatFail("epoch must be non-negative")
            return epoch
        epochs = [int(row["epoch"]) for row in self.ledger.ring_nodes()]
        if not epochs:
            raise FormatFail("ring has no nodes")
        return max(epochs)

    def _active_nodes(self, epoch: int) -> list[dict[str, Any]]:
        nodes = [
            row
            for row in self.ledger.ring_nodes()
            if int(row["epoch"]) == epoch and str(row["state"]) in {"active", "current"}
        ]
        if not nodes:
            raise FormatFail(f"ring has no active nodes for epoch {epoch}")
        return sorted(nodes, key=lambda row: str(row["id"]))

    @staticmethod
    def _ordered_findings(findings: Sequence[ReplayFinding]) -> list[ReplayFinding]:
        unique: dict[str, ReplayFinding] = {}
        for finding in findings:
            unique[finding.finding_id] = finding
        return [unique[key] for key in sorted(unique)]

    def _existing_replay(
        self, run_id: str, node_id: str, corpus_key: str, finding_id: str
    ) -> dict[str, Any] | None:
        rows = self.ledger.ring_replays(
            run_id=run_id,
            ring_node_id=node_id,
            corpus_key=corpus_key,
            finding_id=finding_id,
            limit=1,
        )
        return rows[0] if rows else None

    async def _execute(
        self,
        run_id: str,
        epoch: int,
        node: Mapping[str, Any],
        node_id: str,
        corpus_key: str,
        finding: ReplayFinding,
        corpus_epoch: int,
        *,
        created: int | None,
    ) -> tuple[str, dict[str, Any], str]:
        try:
            result = await self.backend.replay(node=node, corpus_key=corpus_key, finding=finding)
        except RaError as exc:
            status = "error"
            detail: dict[str, Any] = {"error": exc.code, "message": str(exc)}
        except Exception as exc:  # failure-injection boundary: backend crashes become ledger rows
            status = "error"
            detail = {"error": type(exc).__name__, "message": str(exc)}
        else:
            status = result.status
            detail = dict(result.detail)
            detail.setdefault("corpus_epoch", corpus_epoch)
        replay_id = await self._record(
            run_id, epoch, node_id, corpus_key, finding, status, detail, created=created
        )
        return status, detail, replay_id

    async def _record(
        self,
        run_id: str,
        epoch: int,
        node_id: str,
        corpus_key: str,
        finding: ReplayFinding,
        status: str,
        detail: Mapping[str, Any],
        *,
        created: int | None,
    ) -> str:
        return await self.ledger.record_ring_replay(
            run_id=run_id,
            epoch=epoch,
            ring_node_id=node_id,
            corpus_key=corpus_key,
            finding_id=finding.finding_id,
            status=status,
            detail=detail,
            replay_id=self._ids.new("ring_replay"),
            created=now_ms() if created is None else created,
        )

    @staticmethod
    def _summary(
        run_id: str, epoch: int, corpus_key: str, outcomes: tuple[ReplayOutcome, ...]
    ) -> ReplayRunSummary:
        counts = {"pass": 0, "fail": 0, "error": 0, "skipped": 0}
        for outcome in outcomes:
            counts[outcome.status] += 1
        return ReplayRunSummary(
            run_id=run_id,
            epoch=epoch,
            corpus_key=corpus_key,
            total=len(outcomes),
            passed=counts["pass"],
            failed=counts["fail"],
            errors=counts["error"],
            skipped=counts["skipped"],
            outcomes=outcomes,
        )


__all__ = [
    "FindingSource",
    "LedgerFindingSource",
    "NightlyReplayScheduler",
    "ReplayBackend",
    "ReplayFinding",
    "ReplayOutcome",
    "ReplayResult",
    "ReplayRunSummary",
    "RingNodeSpec",
]
