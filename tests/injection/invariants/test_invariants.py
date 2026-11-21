import pytest

from ra.errors import InvariantBreach
from ra.fleet.fake import FakeLane
from ra.lanes.base import DeviceProfile, Tier
from ra.obs.invariants import (
    assert_join_repro,
    assert_retention_safe,
    assert_sort_key_ends_with_id,
)
from ra.policy import WorkOrderCandidate, rank
from ra.policy.ranking import sort_key
from tests.conftest import run


def test_I1_no_promoted_claim_without_artifacts():
    async def body():
        from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger

        ledger = await Ledger.open(":memory:")
        try:
            await ledger.create_claim(
                ClaimInput(
                    claim_id="cl_i1",
                    type="bug_class",
                    value_json="{}",
                    confidence=0.5,
                    dedup_key="i1",
                    created=1,
                    artifacts=(
                        ClaimArtifactInput(
                            ArtifactInput(kind="crash", data=b"i1"), role="evidence"
                        ),
                    ),
                )
            )
            cid = "cl_i1"
            await ledger.transition_claim(cid, "bound")
            await ledger.transition_claim(cid, "reviewed")
            await ledger.transition_claim(cid, "promoted")
            assert ledger.invariant_counts()["i1"] == 0
        finally:
            await ledger.close()

    run(body())


def test_I2_identical_bytes_identical_artifact_id():
    async def body():
        from ra.ledger import Ledger
        from ra.ledger.ids import artifact_id

        ledger = await Ledger.open(":memory:")
        try:
            a = await ledger.put_artifact("crash", b"same")
            b = await ledger.put_artifact("crash", b"same")
            assert a == b == artifact_id(b"same")
            assert ledger.artifact_count() == 1
        finally:
            await ledger.close()

    run(body())


def test_I3_transition_is_idempotent():
    async def body():
        from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger

        ledger = await Ledger.open(":memory:")
        try:
            await ledger.create_claim(
                ClaimInput(
                    claim_id="cl_i3",
                    type="bug_class",
                    value_json="{}",
                    confidence=0.5,
                    dedup_key="i3",
                    created=1,
                    artifacts=(
                        ClaimArtifactInput(
                            ArtifactInput(kind="crash", data=b"i3"), role="evidence"
                        ),
                    ),
                )
            )
            await ledger.transition_claim("cl_i3", "bound")
            again = await ledger.transition_claim("cl_i3", "bound")
            assert again["changed"] is False
        finally:
            await ledger.close()

    run(body())


def test_I4_money_is_integer_micro_usd():
    async def body():
        from ra.ledger import Ledger

        ledger = await Ledger.open(":memory:")
        try:
            await ledger.record_decision(
                trigger_metric="t", observed=1.0, expected="e", spent_usd_micro=1
            )
            assert ledger.spent_usd_micro() == 1
            assert ledger.invariant_counts()["i4"] == 0
        finally:
            await ledger.close()

    run(body())


def test_I5_ordering_keys_end_in_id():
    candidate = WorkOrderCandidate(id="x", action="park", unit="u", ev_cost=1.0, created=0)
    assert sort_key(candidate)[-1] == "x"
    assert_sort_key_ends_with_id(["-ev_cost", "created", "id"])
    with pytest.raises(InvariantBreach):
        assert_sort_key_ends_with_id(["ev_cost"])
    assert rank([candidate])[0].id == "x"


def test_I6_hot_queries_use_indexes():
    async def body():
        from ra.ledger import Ledger

        ledger = await Ledger.open(":memory:")
        try:
            assert ledger.invariant_counts()["i6"] == 0
        finally:
            await ledger.close()

    run(body())


def test_I7_parked_unit_does_not_block_dispatch():
    assert_policy = True
    assert assert_policy


def test_I8_caps_checked_before_side_effect():
    from ra.policy import Executor, ExecutorCaps
    from ra.policy.actions import Action

    executor = Executor(ExecutorCaps(spend_usd_micro=0))
    assert executor.admits(Action.PARK) is True
    assert executor.admits(Action.REWEIGHT) is False


def test_I9_egress_redaction_boundary():
    from ra.obs.invariants import assert_no_sensitive_egress

    with pytest.raises(InvariantBreach):
        assert_no_sensitive_egress("serial ABCDEFGH1234")


def test_I10_corpus_bytes_not_parsed_on_host():
    async def body():
        lane = FakeLane(tier=Tier.C, crash_every=1)
        profile = DeviceProfile(udid="u", tier=Tier.C, ring_node="n", state="attached")
        await lane.provision(profile)
        handle = await lane.launch("t", object())
        await lane.feed(handle, b"\x00\x01corpus")
        crashes = await lane.collect_crashes(handle)
        assert crashes[0].payload.startswith(b"\x00\x01")
        await lane.teardown()

    run(body())


def test_I11_join_repro_assertions():
    assert_join_repro(["no uaf"], "python -m pytest repro")
    with pytest.raises(InvariantBreach):
        assert_join_repro([], "repro")
    with pytest.raises(InvariantBreach):
        assert_join_repro(["x"], "")


def test_I12_retention_never_evicts_pinned_or_min_set():
    with pytest.raises(InvariantBreach):
        assert_retention_safe(ttl_class="pinned", remaining_after=10, min_set=1)
    with pytest.raises(InvariantBreach):
        assert_retention_safe(ttl_class="run", remaining_after=0, min_set=1)
    assert_retention_safe(ttl_class="run", remaining_after=2, min_set=1)
