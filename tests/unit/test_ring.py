import asyncio
import json
import random

import pytest

from ra.errors import ArmBlocked, FormatFail, IngestHashMismatch, OutOfRing, RaError
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger
from ra.ledger.ids import artifact_id, sha256_hex
from ra.ring import (
    CorpusRegistry,
    IngestedSource,
    LedgerFindingSource,
    NightlyReplayScheduler,
    ReplayFinding,
    ReplayResult,
    RingIngester,
    RingManager,
    RingNodeSpec,
    RingSource,
)
from tests.conftest import run


def node(index: int, *, current: bool = False) -> RingNodeSpec:
    return RingNodeSpec(
        node_id=f"node-{index}",
        ipsw_sha=f"ipsw-{index}",
        build=f"build-{index}",
        xcode="xcode",
        sdk="sdk",
        webkit_commit="webkit",
        current=current,
    )


def nodes(count: int = 6, *, current_ids: set[int] | None = None) -> list[RingNodeSpec]:
    current = current_ids or {0, 1}
    return [node(i, current=i in current) for i in range(count)]


class FakeFetcher:
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    async def fetch(self, uri: str) -> bytes:
        self.calls.append(uri)
        if uri not in self.payloads:
            raise KeyError(uri)
        return self.payloads[uri]


class FailingFetcher:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    async def fetch(self, uri: str) -> bytes:
        self.calls += 1
        raise self.error


class RaFailingBackend:
    async def replay(self, *, node, corpus_key: str, finding: ReplayFinding) -> ReplayResult:
        raise RaError("backend refused", code="BACKEND_RA")


class FakeReplayBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_on: set[tuple[str, str]] = set()
        self.error_on: set[tuple[str, str]] = set()

    async def replay(self, *, node, corpus_key: str, finding: ReplayFinding) -> ReplayResult:
        node_id = str(node["id"])
        key = (finding.finding_id, node_id)
        self.calls.append(key)
        if key in self.error_on:
            raise RuntimeError("backend boom")
        if key in self.fail_on:
            return ReplayResult("fail", {"reason": "replay failed"})
        return ReplayResult("pass", {"node": node_id, "corpus": corpus_key})


async def open_ring_ledger() -> tuple[Ledger, RingManager]:
    ledger = await Ledger.open(":memory:")
    return ledger, RingManager(ledger)


async def ready_ring(ledger: Ledger, ring: RingManager, epoch_nodes: list[RingNodeSpec]) -> int:
    epoch = await ring.advance(epoch_nodes)
    registry = CorpusRegistry(ledger)
    for spec in epoch_nodes:
        await registry.register(
            corpus_key=ring.corpus_key(epoch),
            ring_node_id=spec.node_id,
            epoch=epoch,
        )
    return epoch


def test_ring_advance_validation_and_ordering():
    async def body():
        ledger, ring = await open_ring_ledger()
        try:
            with pytest.raises(FormatFail):
                await ring.advance(nodes(count=5))
            with pytest.raises(FormatFail):
                await ring.advance(nodes(count=6, current_ids={0}))
            duplicate = nodes(count=6)
            duplicate[5] = RingNodeSpec(
                node_id=duplicate[0].node_id,
                ipsw_sha="ipsw-dup",
                build="build-dup",
                xcode="xcode",
                sdk="sdk",
                webkit_commit="webkit",
                current=True,
            )
            with pytest.raises(FormatFail):
                await ring.advance(duplicate)
            assert ring.current_epoch() == 0
            assert ledger.ring_nodes() == []

            epoch = await ring.advance(nodes(count=6))
            assert epoch == 1
            rows = ledger.ring_nodes()
            assert len(rows) == 6
            assert sum(1 for row in rows if row["state"] == "current") == 2
            assert sum(1 for row in rows if row["state"] == "active") == 4
            assert [row["id"] for row in ring.active_nodes(1)] == [f"node-{i}" for i in range(6)]
        finally:
            await ledger.close()

    run(body())


def test_ring_advance_retires_previous_epoch():
    async def body():
        ledger, ring = await open_ring_ledger()
        try:
            await ring.advance(nodes(count=6))
            second = [
                RingNodeSpec(
                    node_id=f"node-{i}",
                    ipsw_sha=f"ipsw-{i}",
                    build=f"build-{i}",
                    xcode="xcode",
                    sdk="sdk",
                    webkit_commit="webkit",
                    current=i in {6, 7},
                )
                for i in range(6, 12)
            ]
            assert await ring.advance(second) == 2
            rows = ledger.ring_nodes()
            assert len(rows) == 12
            assert all(row["state"] == "retired" for row in rows if row["epoch"] == 1)
            assert [row["id"] for row in ring.active_nodes(2)] == sorted(
                f"node-{i}" for i in range(6, 12)
            )
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0")
            assert ring.assert_in_ring("build-6")["epoch"] == 2
            assert ring.current_epoch() == 2
        finally:
            await ledger.close()

    run(body())


def test_RA_RING_003_out_of_ring_refusal():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            await ring.advance(nodes(count=6))
            assert ring.assert_in_ring("build-0")["id"] == "node-0"
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-999")
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0", ipsw_sha="wrong")
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0", xcode="other")
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0", sdk="other")
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0", webkit_commit="other")
            assert ring.allows("node-0") is True
            assert ring.allows("node-0", "build-0") is True
            assert ring.allows("node-0", "build-999") is False
            assert ring.allows("node-999") is False
        finally:
            await ledger.close()

    run(body())


def test_RA_RING_004_atomic_advance_rolls_back():
    async def body():
        ledger, ring = await open_ring_ledger()
        try:
            specs = nodes(count=6)
            bad = specs[1].payload(state="bogus", epoch=1)
            with pytest.raises(FormatFail):
                await ledger.advance_ring(1, [specs[0].payload(state="active", epoch=1), bad])
            assert ledger.ring_nodes() == []

            assert await ring.advance(specs) == 1
            with pytest.raises(FormatFail):
                await ledger.advance_ring(
                    1, [spec.payload(state="active", epoch=1) for spec in specs]
                )
            rows = ledger.ring_nodes()
            assert len(rows) == 6
            assert all(row["epoch"] == 1 for row in rows)
        finally:
            await ledger.close()

    run(body())


def test_ring_concurrent_advances_get_distinct_ledger_epochs():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            first = RingManager(ledger)
            second = RingManager(ledger)
            specs = nodes(count=6)
            epochs = await asyncio.gather(first.advance(specs), second.advance(specs))
            assert sorted(epochs) == [1, 2]
            assert first.current_epoch() == 2
            rows = ledger.ring_nodes()
            assert len(rows) == 6
            assert all(row["epoch"] == 2 for row in rows)
        finally:
            await ledger.close()

    run(body())


def test_RA_RING_002_bad_node_alert_after_two_failures():
    async def body():
        ledger = await Ledger.open(":memory:")
        alerts: list[tuple[str, str]] = []
        ring = RingManager(ledger, on_alert=lambda kind, detail: alerts.append((kind, detail)))
        try:
            await ring.advance(nodes(count=6))
            assert await ring.record_boot_failure("node-0") == "current"
            health = ledger.ring_health("node-0")
            assert health is not None
            assert health["failures"] == 1
            assert health["bad_marked"] == 0

            second_alerts: list[tuple[str, str]] = []
            restarted = RingManager(
                ledger, on_alert=lambda kind, detail: second_alerts.append((kind, detail))
            )
            assert await restarted.record_boot_failure("node-0") == "bad"
            assert second_alerts == [("ring_node_bad", "node-0")]
            node_row = ledger.ring_node("node-0")
            assert node_row is not None and node_row["state"] == "bad"
            assert restarted.allows("node-0") is False
            with pytest.raises(OutOfRing):
                restarted.assert_in_ring("build-0")
            assert await restarted.record_boot_failure("node-0") == "bad"
            assert second_alerts == [("ring_node_bad", "node-0")]
            health = ledger.ring_health("node-0")
            assert health is not None
            assert health["failures"] == 3
            assert health["bad_marked"] == 1
        finally:
            await ledger.close()

    run(body())


def test_ring_ingest_hash_parity_and_idempotency():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            data = b"ipsw-bytes"
            digest = sha256_hex(data)
            fetcher = FakeFetcher({"ipsw://one": data})
            ingester = RingIngester(ledger, fetcher, artifact_store=ledger)
            source = RingSource(kind="ipsw", uri="ipsw://one", expected_sha256=digest, epoch=1)
            first = await ingester.ingest_source(source, epoch=1, created=100)
            assert first.sha256 == digest
            assert first.size_bytes == len(data)
            assert first.artifact_id == artifact_id(data)
            rows = ledger.ring_ingests(epoch=1)
            assert len(rows) == 1
            assert rows[0]["sha256"] == digest
            assert rows[0]["artifact_id"] == artifact_id(data)
            assert ledger.artifact_count() == 1

            second = await ingester.ingest_source(source, epoch=1, created=101)
            assert second.ingest_id == first.ingest_id
            assert len(ledger.ring_ingests(epoch=1)) == 1
            assert ledger.artifact_count() == 1
        finally:
            await ledger.close()

    run(body())


def test_ring_ingest_many_preserves_order():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            payloads = {
                "oss://a": b"aaa",
                "webkit://b": b"bbb",
                "notes://c": b"ccc",
            }
            ingester = RingIngester(ledger, FakeFetcher(payloads), artifact_store=ledger)
            sources = [
                RingSource(kind="oss_tarball", uri="oss://a", epoch=2),
                RingSource(kind="webkit", uri="webkit://b", epoch=2),
                RingSource(kind="security_notes", uri="notes://c", epoch=2),
            ]
            ingested = await ingester.ingest_many(sources, epoch=2, created=50)
            assert [item.uri for item in ingested] == [
                "oss://a",
                "webkit://b",
                "notes://c",
            ]
            assert [row["kind"] for row in ledger.ring_ingests(epoch=2)] == [
                "oss_tarball",
                "webkit",
                "security_notes",
            ]
        finally:
            await ledger.close()

    run(body())


def test_ring_ingest_rejects_bad_hash_fetch_failure_and_conflicts():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            data = b"payload"
            digest = sha256_hex(data)
            ingester = RingIngester(ledger, FakeFetcher({"bad://one": data}))
            with pytest.raises(FormatFail):
                RingSource(kind="unknown", uri="bad://one")
            with pytest.raises(FormatFail):
                RingSource(kind="ipsw", uri="bad://one", expected_sha256="A" * 64)
            with pytest.raises(FormatFail):
                RingSource(kind="ipsw", uri="bad://one", epoch=-1)

            mismatch = RingSource(kind="ipsw", uri="bad://one", expected_sha256="0" * 64, epoch=1)
            with pytest.raises(IngestHashMismatch):
                await ingester.ingest_source(mismatch, epoch=1)
            assert ledger.ring_ingests() == []
            assert ledger.artifact_count() == 0

            conflict = RingSource(kind="ipsw", uri="bad://one", expected_sha256=digest)
            with pytest.raises(FormatFail):
                await ingester.ingest_source(conflict, epoch=1, expected_sha256="1" * 64)

            failing = RingIngester(
                ledger, FailingFetcher(RuntimeError("fetch failed")), artifact_store=ledger
            )
            with pytest.raises(RuntimeError):
                await failing.ingest_source(RingSource(kind="ipsw", uri="missing://one"), epoch=1)
            assert ledger.ring_ingests() == []
        finally:
            await ledger.close()

    run(body())


def test_RA_RING_005_corpus_epoch_keyed_opt_in_reuse():
    async def body():
        ledger, ring = await open_ring_ledger()
        try:
            epoch = await ring.advance(nodes(count=6))
            registry = CorpusRegistry(ledger)
            key = ring.corpus_key(epoch)
            corpus_id = await registry.register(
                corpus_key=key, ring_node_id="node-0", epoch=epoch, created=10, updated=10
            )
            binding = registry.binding_for(key, "node-0", epoch)
            assert binding is not None and binding["state"] == "active"
            assert registry.assert_usable(key, "node-0", epoch)["id"] == corpus_id

            assert await registry.revoke_node("node-0", epoch=epoch) == 1
            assert registry.binding_for(key, "node-0", epoch) is None
            with pytest.raises(ArmBlocked):
                registry.assert_usable(key, "node-0", epoch)

            again = await registry.register(
                corpus_key=key, ring_node_id="node-0", epoch=epoch, created=20, updated=20
            )
            assert again == corpus_id
            assert registry.binding_for(key, "node-0", epoch) is not None

            await registry.register(
                corpus_key="custom", ring_node_id="node-1", epoch=epoch, created=30, updated=30
            )
            assert registry.resolve_binding("custom", "node-1", epoch + 1) is None
            cross = registry.resolve_binding("custom", "node-1", epoch + 1, cross_epoch_opt_in=True)
            assert cross is not None and cross["epoch"] == epoch
            assert (
                registry.assert_usable("custom", "node-1", epoch + 1, cross_epoch_opt_in=True)[
                    "corpus_key"
                ]
                == "custom"
            )

            assert await registry.revoke_epoch(epoch) == 2
            assert registry.active_bindings(epoch=epoch) == []
        finally:
            await ledger.close()

    run(body())


def test_ring_replay_scheduler_orders_and_is_idempotent():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            epoch = await ready_ring(ledger, ring, nodes(count=6))
            backend = FakeReplayBackend()
            scheduler = NightlyReplayScheduler(ledger, backend)
            findings = [ReplayFinding("f2"), ReplayFinding("f1", detail={"x": 1})]
            summary = await scheduler.run_nightly(
                findings, run_id="run-1", epoch=epoch, created=100
            )
            assert summary.total == 12
            assert summary.passed == 12
            assert summary.failed == summary.errors == summary.skipped == 0
            expected = [
                (finding, f"node-{node_index}")
                for finding in ("f1", "f2")
                for node_index in range(6)
            ]
            assert backend.calls == expected
            rows = ledger.ring_replays(run_id="run-1", limit=100)
            assert len(rows) == 12
            assert all(row["status"] == "pass" for row in rows)
            assert json.loads(rows[0]["detail_json"])["corpus_epoch"] == epoch

            again = await scheduler.run_nightly(findings, run_id="run-1", epoch=epoch, created=200)
            assert again.total == 12
            assert all(outcome.skipped_existing for outcome in again.outcomes)
            assert len(backend.calls) == 12
            assert len(ledger.ring_replays(run_id="run-1", limit=100)) == 12
        finally:
            await ledger.close()

    run(body())


def test_ring_replay_scheduler_records_missing_corpus_and_backend_failures():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            epoch = await ready_ring(ledger, ring, nodes(count=6))
            registry = CorpusRegistry(ledger)
            assert await registry.revoke_node("node-3", epoch=epoch) == 1
            backend = FakeReplayBackend()
            backend.fail_on.add(("f1", "node-1"))
            backend.error_on.add(("f1", "node-2"))
            scheduler = NightlyReplayScheduler(ledger, backend)
            summary = await scheduler.run_nightly(
                [ReplayFinding("f1")], run_id="run-2", epoch=epoch, created=300
            )
            assert summary.total == 6
            assert summary.passed == 3
            assert summary.failed == 1
            assert summary.errors == 1
            assert summary.skipped == 1
            assert len(backend.calls) == 5

            by_node = {row["ring_node_id"]: row for row in ledger.ring_replays(run_id="run-2")}
            assert by_node["node-1"]["status"] == "fail"
            assert by_node["node-2"]["status"] == "error"
            assert json.loads(by_node["node-2"]["detail_json"])["error"] == "RuntimeError"
            assert by_node["node-3"]["status"] == "skipped"
            assert json.loads(by_node["node-3"]["detail_json"])["reason"] == "corpus_missing"
        finally:
            await ledger.close()

    run(body())


def test_ring_replay_cross_epoch_requires_opt_in():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            first_specs = nodes(count=6)
            epoch1 = await ready_ring(ledger, ring, first_specs)
            second_specs = [
                RingNodeSpec(
                    node_id=spec.node_id,
                    ipsw_sha=spec.ipsw_sha,
                    build=spec.build,
                    xcode=spec.xcode,
                    sdk=spec.sdk,
                    webkit_commit=spec.webkit_commit,
                    current=spec.current,
                )
                for spec in first_specs
            ]
            epoch2 = await ring.advance(second_specs)
            assert epoch2 == epoch1 + 1
            backend = FakeReplayBackend()
            scheduler = NightlyReplayScheduler(ledger, backend)
            findings = [ReplayFinding("f1")]

            blocked = await scheduler.run_nightly(
                findings, run_id="run-blocked", epoch=epoch2, created=400
            )
            assert blocked.total == 6
            assert blocked.skipped == 6
            assert backend.calls == []

            opted = await scheduler.run_nightly(
                findings,
                run_id="run-opted",
                epoch=epoch2,
                corpus_key=ring.corpus_key(epoch1),
                cross_epoch_opt_in=True,
                created=500,
            )
            assert opted.total == 6
            assert opted.passed == 6
            rows = ledger.ring_replays(run_id="run-opted")
            assert len(rows) == 6
            assert all(row["epoch"] == epoch2 for row in rows)
            assert all(json.loads(row["detail_json"])["corpus_epoch"] == epoch1 for row in rows)
        finally:
            await ledger.close()

    run(body())


def test_ledger_finding_source_filters_terminal_claims():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:

            async def make_claim(claim_id: str, key: str, data: bytes) -> str:
                return await ledger.create_claim(
                    ClaimInput(
                        claim_id=claim_id,
                        type="bug_class",
                        value_json=json.dumps({"answer": "insufficient_evidence"}),
                        confidence=0.5,
                        dedup_key=key,
                        created=1,
                        artifacts=(
                            ClaimArtifactInput(
                                ArtifactInput(kind="crash", data=data), role="evidence"
                            ),
                        ),
                    )
                )

            limbo = await make_claim("cl_limbo", "key-limbo", b"limbo")
            promoted = await make_claim("cl_promoted", "key-promoted", b"promoted")
            demoted = await make_claim("cl_demoted", "key-demoted", b"demoted")
            for claim_id in (promoted, demoted):
                await ledger.transition_claim(claim_id, "bound")
                await ledger.transition_claim(claim_id, "reviewed")
            await ledger.transition_claim(promoted, "promoted")
            await ledger.transition_claim(demoted, "demoted")

            source = LedgerFindingSource(ledger)
            findings = await source.findings()
            assert [finding.finding_id for finding in findings] == [limbo, promoted]
            assert demoted not in {finding.finding_id for finding in findings}
        finally:
            await ledger.close()

    run(body())


def test_ring_value_objects_validate():
    with pytest.raises(FormatFail):
        RingNodeSpec(
            node_id="",
            ipsw_sha="ipsw",
            build="build",
            xcode="x",
            sdk="sdk",
            webkit_commit="w",
        )
    with pytest.raises(FormatFail):
        RingSource(kind="ipsw", uri="", epoch=0)
    with pytest.raises(FormatFail):
        ReplayFinding("")
    with pytest.raises(FormatFail):
        ReplayResult("maybe")
    with pytest.raises(FormatFail):
        IngestedSource(
            ingest_id="ingest",
            kind="ipsw",
            uri="ipsw://one",
            sha256="0" * 64,
            size_bytes=-1,
            epoch=0,
        )
    with pytest.raises(FormatFail):
        IngestedSource(
            ingest_id="ingest",
            kind="ipsw",
            uri="ipsw://one",
            sha256="0" * 64,
            size_bytes=0,
            epoch=-1,
        )


def test_ring_manager_threshold_and_corpus_epoch_gate():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail):
                RingManager(ledger, boot_failure_threshold=0)
            ring = RingManager(ledger)
            assert ring.current_epoch() == 0
            assert ring.assert_corpus_epoch(0) == "ring_0"
            with pytest.raises(ArmBlocked):
                ring.assert_corpus_epoch(1)
            assert ring.assert_corpus_epoch(1, cross_epoch_opt_in=True) == "ring_1"
            with pytest.raises(FormatFail):
                await ring.record_boot_failure("missing")

            await ring.advance(nodes(count=6))
            with pytest.raises(ArmBlocked):
                ring.assert_corpus_epoch(0)
            assert ring.assert_corpus_epoch(0, cross_epoch_opt_in=True) == "ring_0"
        finally:
            await ledger.close()

    run(body())


def test_ring_corpus_validation_edges():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            registry = CorpusRegistry(ledger)
            with pytest.raises(FormatFail):
                await registry.register(corpus_key="", ring_node_id="node-0", epoch=0)
            with pytest.raises(FormatFail):
                await registry.register(corpus_key="ring_0", ring_node_id="node-0", epoch=-1)
            with pytest.raises(FormatFail):
                await registry.revoke_epoch(-1)
            assert registry.resolve_binding("missing", "node-0", 0, cross_epoch_opt_in=True) is None
        finally:
            await ledger.close()

    run(body())


def test_ring_ingest_validation_edges():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            data = b"ring-source"
            fetcher = FakeFetcher({"ipsw://edge": data})
            ingester = RingIngester(ledger, fetcher)
            source = RingSource(kind="ipsw", uri="ipsw://edge", epoch=1)
            with pytest.raises(FormatFail):
                await ingester.ingest_source(source, epoch=-1)
            with pytest.raises(FormatFail):
                await ingester.ingest_source(source, epoch=2)
            with pytest.raises(FormatFail):
                await ingester.ingest_many([source], epoch=1, expected_sha256=["0" * 64, "1" * 64])

            result = await ingester.ingest_source(source, epoch=1, created=5)
            assert result.artifact_id is None
            rows = ledger.ring_ingests(epoch=1)
            assert len(rows) == 1
            assert rows[0]["artifact_id"] is None
        finally:
            await ledger.close()

    run(body())


def test_ring_replay_validation_and_ra_error_edges():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            scheduler = NightlyReplayScheduler(ledger, FakeReplayBackend())
            with pytest.raises(FormatFail):
                await scheduler.run_nightly([], epoch=-1)
            with pytest.raises(FormatFail):
                await scheduler.run_nightly([], epoch=1, corpus_key="")
            with pytest.raises(FormatFail):
                await scheduler.run_nightly([])

            epoch = await ready_ring(ledger, ring, nodes(count=6))
            with pytest.raises(FormatFail):
                await scheduler.run_nightly([], epoch=epoch + 1)
            default_summary = await scheduler.run_nightly([], run_id="run-default", created=1)
            assert default_summary.epoch == epoch
            assert default_summary.total == 0

            ra_scheduler = NightlyReplayScheduler(ledger, RaFailingBackend())
            summary = await ra_scheduler.run_nightly(
                [ReplayFinding("finding-ra")], epoch=epoch, run_id="run-ra", created=1
            )
            assert summary.errors == 6
            assert summary.total == 6
            assert all(outcome.status == "error" for outcome in summary.outcomes)
            rows = ledger.ring_replays(run_id="run-ra")
            assert len(rows) == 6
            assert json.loads(rows[0]["detail_json"])["error"] == "BACKEND_RA"
        finally:
            await ledger.close()

    run(body())


def assert_ring_invariants(ring: RingManager) -> None:
    versions = ring.versions()
    assert versions
    epochs = [int(version["epoch"]) for version in versions]
    assert epochs == sorted(epochs)
    assert epochs == list(range(epochs[0], epochs[-1] + 1))
    for version in versions:
        rows = version["nodes"]
        ids = [str(row["ring_node_id"]) for row in rows]
        assert len(ids) == len(set(ids))
        assert len(rows) >= 6
        assert sum(1 for row in rows if row["state"] == "current") >= 2
        assert all(row["state"] in {"active", "current", "bad"} for row in rows)
        assert int(version["node_count"]) == len(rows)
    assert epochs[-1] == ring.current_epoch()


def test_ring_attach_promote_rollback_and_bad_quarantine():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            alerts: list[tuple[str, str]] = []
            ring = RingManager(ledger, on_alert=lambda kind, detail: alerts.append((kind, detail)))

            epoch1 = await ring.advance(nodes())
            assert epoch1 == 1
            attached = await ring.attach(node(6))
            assert attached == 2
            assert ring.version(2) is not None
            assert ring.version(2)["origin"] == "attach"
            assert ring.version(2)["node_count"] == 7
            assert [row["id"] for row in ring.active_nodes(2)][-1] == "node-6"

            promoted = await ring.promote("node-6")
            assert promoted == 3
            assert ring.version(3)["origin"] == "promote"
            assert ring.active_nodes(3)[-1]["id"] == "node-6"
            assert ring.active_nodes(3)[-1]["state"] == "current"
            assert await ring.promote("node-6") == 3
            assert len(ring.versions()) == 3

            rolled = await ring.rollback(epoch1)
            assert rolled == 4
            assert ring.version(4)["origin"] == "rollback"
            assert ring.version(4)["restored_from_epoch"] == epoch1
            current_ids = {row["id"] for row in ring.active_nodes(4)}
            assert current_ids == {f"node-{i}" for i in range(6)}
            assert ring.active_nodes(4)[0]["state"] == "current"

            assert await ring.record_boot_failure("node-0") == "current"
            assert await ring.record_boot_failure("node-0") == "bad"
            assert alerts == [("ring_node_bad", "node-0")]
            with pytest.raises(FormatFail, match="current nodes"):
                await ring.advance(nodes())
            assert ring.current_epoch() == 4
            assert ledger.integrity_check() == "ok"
        finally:
            await ledger.close()

    run(body())


def test_ring_history_wraparound_and_rollback_past_oldest():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger, history_capacity=3)
            assert await ring.advance(nodes()) == 1
            assert await ring.attach(node(6)) == 2
            assert await ring.promote("node-2") == 3
            assert await ring.attach(node(7)) == 4
            versions = ring.versions()
            assert [version["epoch"] for version in versions] == [2, 3, 4]
            assert ring.version(1) is None

            rolled = await ring.rollback(2)
            assert rolled == 5
            assert ring.version(5)["restored_from_epoch"] == 2
            assert [version["epoch"] for version in ring.versions()] == [3, 4, 5]
            assert await ring.rollback(5) == 5
            assert len(ring.versions()) == 3
            with pytest.raises(FormatFail, match="older than retained"):
                await ring.rollback(1)
            with pytest.raises(FormatFail, match="unknown ring version"):
                await ring.rollback(99)
        finally:
            await ledger.close()

    run(body())


def test_ring_concurrent_attach_promote_rollback_are_serialized():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            assert await ring.advance(nodes()) == 1
            await asyncio.gather(
                ring.attach(node(6)),
                ring.attach(node(7)),
                ring.promote("node-2"),
                ring.promote("node-3"),
                ring.rollback(1),
            )
            assert_ring_invariants(ring)
            assert ring.current_epoch() == 6
            assert [version["epoch"] for version in ring.versions()] == [1, 2, 3, 4, 5, 6]
            assert ledger.integrity_check() == "ok"
        finally:
            await ledger.close()

    run(body())


def test_ring_property_random_mutations_preserve_invariants():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger, history_capacity=5)
            assert await ring.advance(nodes()) == 1
            rng = random.Random(1337)
            next_attach = 100

            for _ in range(40):
                versions = ring.versions()
                current_nodes = versions[-1]["nodes"]
                active = [row for row in current_nodes if row["state"] == "active"]
                choice = rng.randrange(3)
                if choice == 0 or not active:
                    await ring.attach(node(next_attach))
                    next_attach += 1
                elif choice == 1:
                    target = rng.choice(active)
                    await ring.promote(str(target["ring_node_id"]))
                else:
                    target_epoch = rng.choice([version["epoch"] for version in versions])
                    await ring.rollback(target_epoch)
                assert_ring_invariants(ring)

            oldest = ring.versions()[0]["epoch"]
            assert oldest > 1
            with pytest.raises(FormatFail, match="older than retained"):
                await ring.rollback(oldest - 1)
            assert ledger.integrity_check() == "ok"
        finally:
            await ledger.close()

    run(body())


def test_ring_ingest_is_epoch_scoped():
    async def body():
        ledger, ring = await open_ring_ledger()
        try:
            ingester = RingIngester(
                ring.ledger,
                fetcher=FakeFetcher(
                    {"https://example.com/a.bin": b"same", "https://example.com/b.bin": b"same"}
                ),
            )
            first = await ingester.ingest_source(
                RingSource(uri="https://example.com/a.bin", kind="ipsw"), epoch=1
            )
            second = await ingester.ingest_source(
                RingSource(uri="https://example.com/b.bin", kind="ipsw"), epoch=2
            )
            replay = await ingester.ingest_source(
                RingSource(uri="https://example.com/b.bin", kind="ipsw"), epoch=2
            )
            assert first.epoch == 1
            assert second.ingest_id != first.ingest_id
            assert second.ingest_id == replay.ingest_id
            assert len(ledger.ring_ingests(epoch=1)) == 1
            assert len(ledger.ring_ingests(epoch=2)) == 1
        finally:
            await ledger.close()

    run(body())


def test_ring_corpus_rejects_bad_retired_and_epoch_mismatch():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            corpus = CorpusRegistry(ledger)
            assert await ring.advance(nodes()) == 1

            with pytest.raises(FormatFail, match="unknown ring node"):
                await corpus.register(corpus_key="missing", ring_node_id="node-404", epoch=1)
            with pytest.raises(FormatFail, match="epoch must match"):
                await corpus.register(corpus_key="bad-epoch", ring_node_id="node-0", epoch=0)
            corpus_id = await corpus.register(
                corpus_key="ok", ring_node_id="node-0", epoch=1
            )
            assert ledger.ring_corpus(corpus_id) is not None

            assert await ring.record_boot_failure("node-0") == "current"
            assert await ring.record_boot_failure("node-0") == "bad"
            with pytest.raises(FormatFail, match="retired or bad"):
                await corpus.register(corpus_key="bad-node", ring_node_id="node-0", epoch=1)

            second = [node(i, current=i in {6, 7}) for i in range(6, 12)]
            assert await ring.advance(second) == 2
            with pytest.raises(FormatFail, match="retired or bad"):
                await corpus.register(corpus_key="retired", ring_node_id="node-0", epoch=1)
        finally:
            await ledger.close()

    run(body())


def test_ring_history_capacity_validation_and_bad_advance_payload():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail, match="history_capacity"):
                RingManager(ledger, history_capacity=1)
            with pytest.raises(FormatFail, match="history_capacity"):
                RingManager(ledger, history_capacity=2000)

            ring = RingManager(ledger)
            valid = [node(i, current=i in {0, 1}) for i in range(6)]
            payloads = [
                item.payload(state="current" if item.current else "active", epoch=0)
                for item in valid
            ]
            with pytest.raises(FormatFail, match="history_capacity"):
                await ledger.advance_ring_auto(payloads, history_capacity=1)
            assert await ring.advance(valid) == 1

            bad_payload = dict(payloads[0])
            bad_payload["state"] = "bogus"
            with pytest.raises(FormatFail, match="ring node state is invalid"):
                await ledger.advance_ring_auto([*payloads[1:], bad_payload])
            assert ring.current_epoch() == 1
        finally:
            await ledger.close()

    run(body())
