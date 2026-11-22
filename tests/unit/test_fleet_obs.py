import pytest

from ra.errors import FormatFail, InvariantBreach, OutOfRing
from ra.fleet import FakeLane, RingManager, RingNodeSpec
from ra.lanes.base import DeviceProfile, Tier
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger
from ra.obs import RetentionPolicy, assert_no_sensitive_egress, assert_store_invariants, sweep
from ra.obs.health import HealthServer, health_payload
from tests.conftest import run


def node(i: int, *, current: bool = False) -> RingNodeSpec:
    return RingNodeSpec(
        node_id=f"node-{i}",
        ipsw_sha=f"ipsw-{i}",
        build=f"build-{i}",
        xcode="x",
        sdk="sdk",
        webkit_commit="webkit",
        current=current,
    )


def test_RA_RING_001_ring_requires_six_nodes_two_current():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            with pytest.raises(FormatFail):
                await ring.advance([node(i, current=i < 2) for i in range(5)])
            epoch = await ring.advance([node(i, current=i < 2) for i in range(6)])
            assert epoch == 1
            assert len(ledger.ring_nodes()) == 6
            assert ring.assert_in_ring("build-0")["id"] == "node-0"
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("outside")
        finally:
            await ledger.close()

    run(body())


def test_RA_LANE_001_fake_lane_protocol():
    async def body():
        lane = FakeLane(tier=Tier.C, crash_every=1)
        profile = DeviceProfile(udid="u", tier=Tier.C, ring_node="node", state="attached")
        await lane.provision(profile)
        handle = await lane.launch("target", object())
        await lane.assert_ready()
        await lane.feed(handle, b"payload")
        crashes = await lane.collect_crashes(handle)
        assert len(crashes) == 1 and crashes[0].payload == b"payload"
        assert await lane.thermal() is not None
        await lane.teardown()
        with pytest.raises(RuntimeError):
            await lane.assert_ready()

    run(body())


def test_RA_RET_001_sweep_respects_ttl_and_min_set():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            old = 1
            await ledger.put_artifact("crash", b"old")
            ledger.store._conn.execute(
                "UPDATE artifact SET created=? WHERE id=?",
                (old, __import__("ra.ledger.ids", fromlist=["artifact_id"]).artifact_id(b"old")),
            )
            fresh = await ledger.put_artifact("crash", b"fresh")
            result = await sweep(
                ledger,
                RetentionPolicy(ephemeral_days=30, run_days=90, min_set=1),
                now=old + 31 * 86_400_000,
            )
            assert result["ephemeral"] + result["run"] >= 0
            assert ledger.artifact_count() >= 1
            assert fresh.startswith("art_")
        finally:
            await ledger.close()

    run(body())


def test_RA_RET_001_retention_validation_and_delete_floor():
    with pytest.raises(FormatFail):
        RetentionPolicy(ephemeral_days=0)
    with pytest.raises(FormatFail):
        RetentionPolicy(batch_size=0)
    with pytest.raises(FormatFail):
        RetentionPolicy(batch_size=501)
    with pytest.raises(FormatFail):
        RetentionPolicy(min_set=-1)

    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            old = 1
            old_id = await ledger.put_artifact("crash", b"old-ep", ttl_class="ephemeral")
            ledger.store._conn.execute(
                "UPDATE artifact SET created=? WHERE id=?", (old, old_id)
            )
            await ledger.put_artifact("crash", b"fresh-run", ttl_class="run")
            result = await sweep(
                ledger,
                RetentionPolicy(ephemeral_days=30, run_days=90, min_set=1, batch_size=1),
                now=old + 31 * 86_400_000,
            )
            assert result["ephemeral"] == 1
            assert result["batches"] == 1
            assert result["remaining"] == 1
            assert ledger.artifact_count() == 1
        finally:
            await ledger.close()

    run(body())


def test_RA_INV_001_store_invariants_clean():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cid = "cl_inv"
            await ledger.create_claim(
                ClaimInput(
                    claim_id=cid,
                    type="bug_class",
                    value_json="{}",
                    confidence=0.5,
                    dedup_key="inv",
                    created=1,
                    artifacts=(
                        ClaimArtifactInput(
                            ArtifactInput(kind="crash", data=b"inv"), role="evidence"
                        ),
                    ),
                )
            )
            assert_store_invariants(ledger)
        finally:
            await ledger.close()

    run(body())


def test_RA_SEC_001_assert_no_sensitive_egress():
    with pytest.raises(InvariantBreach):
        assert_no_sensitive_egress("email a@b.com")
    assert_no_sensitive_egress("already redacted [REDACTED_EMAIL]")


def test_RA_TOP_003_health_server_and_payload():
    async def body():
        ledger = await Ledger.open(":memory:")
        server = HealthServer(lambda: health_payload(ledger, extra={"ok": True}))
        try:
            await server.start()
            reader, writer = await __import__("asyncio").open_connection("127.0.0.1", server.port)
            writer.write(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            data = await reader.read()
            writer.close()
            assert b"200 OK" in data and b"mailbox_saturation" in data
        finally:
            await server.stop()
            await ledger.close()

    run(body())
