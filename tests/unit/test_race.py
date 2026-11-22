"""Unit, property, edge, and failure-injection tests for ra.race (RA-RACE-*)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from ra.errors import BudgetExhausted, FormatFail, OutOfRing
from ra.fleet.fake import FakeLane
from ra.fleet.race import LaneRaceBackend
from ra.foundry.cas import CasCorrupt, ContentAddressedStore
from ra.lanes.base import DeviceProfile, HarnessRef, Tier
from ra.ledger import Ledger
from ra.race import (
    DeterministicRaceBackend,
    FixedSeedDistribution,
    RaceBudget,
    RaceCrash,
    RaceHarness,
    RaceRng,
    RaceSchedule,
    RaceState,
    RaceTarget,
    ScriptedRaceBackend,
    UniformSeedDistribution,
    WeightedSeedDistribution,
    build_schedule,
    normalize_seed,
    parse_seed_hex,
    seed_hex,
)
from ra.race.errors import RaceBackendError
from ra.race.models import CrashSummary, RaceClaimRecord


def make_target(**overrides: Any) -> RaceTarget:
    values: dict[str, Any] = {
        "name": "kernel/toctou",
        "ring_node": "node-a",
        "build": "24A1",
        "corpus_digest": "ab" * 32,
        "ops": ("read", "write", "rename"),
        "workers": 2,
        "steps": 8,
        "max_delay_us": 500,
    }
    values.update(overrides)
    return RaceTarget(**values)


class RacePrngTest(unittest.TestCase):
    """Property tests for the deterministic race DRBG."""

    def test_ra_race_prng_001_same_key_same_stream(self) -> None:
        a = RaceRng("key")
        b = RaceRng("key")
        assert [a.next_u64() for _ in range(64)] == [b.next_u64() for _ in range(64)]
        assert RaceRng("key").randbelow(100) == RaceRng("key").randbelow(100)

    def test_ra_race_prng_002_different_keys_differ(self) -> None:
        a = RaceRng("key-a")
        b = RaceRng("key-b")
        assert [a.next_u64() for _ in range(8)] != [b.next_u64() for _ in range(8)]

    def test_ra_race_prng_003_randbelow_bounds_and_rejection(self) -> None:
        rng = RaceRng("bounds")
        for n in (1, 2, 3, 7, 1000, 1 << 32):
            for _ in range(50):
                value = rng.randbelow(n)
                assert 0 <= value < n

    def test_ra_race_prng_004_seed_normalization(self) -> None:
        assert normalize_seed(7) == 7
        assert normalize_seed("0x10") == 16
        assert normalize_seed("0o17") == 15
        assert normalize_seed("0b101") == 5
        assert normalize_seed("42") == 42
        assert seed_hex(255) == "00000000000000ff"
        assert parse_seed_hex(seed_hex(123456789)) == 123456789
        for bad in (-1, (1 << 63), True, 1.5, "", "xyz", "ff" * 8, "A" * 16):
            try:
                normalize_seed(bad)  # type: ignore[arg-type]
            except FormatFail:
                continue
            raise AssertionError(f"expected FormatFail for {bad!r}")
        for bad_hex in ("", "abc", "0" * 15, "0" * 17, "g" * 16, "A" * 16):
            try:
                parse_seed_hex(bad_hex)
            except FormatFail:
                continue
            raise AssertionError(f"expected FormatFail for {bad_hex!r}")

    def test_ra_race_prng_005_rng_key_validation(self) -> None:
        for bad in ("", b""):
            try:
                RaceRng(bad)  # type: ignore[arg-type]
            except FormatFail:
                continue
            raise AssertionError(f"expected FormatFail for empty key {bad!r}")
        assert RaceRng(b"bytes-key").next_u64() == RaceRng("bytes-key").next_u64()


class RaceScheduleTest(unittest.TestCase):
    """RA-RACE-001: deterministic schedule construction."""

    def test_ra_race_001_deterministic_schedule(self) -> None:
        target = make_target()
        first = build_schedule(target, 42, iteration=0)
        second = build_schedule(target, 42, iteration=0)
        assert first.to_bytes() == second.to_bytes()
        assert first.digest == second.digest
        assert first.seed_hex == "000000000000002a"

    def test_ra_race_001_schedule_varies_with_inputs(self) -> None:
        target = make_target()
        base = build_schedule(target, 42, iteration=0)
        assert build_schedule(target, 43, iteration=0).digest != base.digest
        assert build_schedule(target, 42, iteration=1).digest != base.digest
        other = make_target(name="kernel/other")
        assert build_schedule(other, 42, iteration=0).digest != base.digest

    def test_ra_race_001_schedule_roundtrip(self) -> None:
        target = make_target()
        schedule = build_schedule(target, 7, iteration=3)
        parsed = RaceSchedule.from_bytes(schedule.to_bytes())
        assert parsed == schedule
        assert RaceSchedule.from_dict(schedule.to_dict()) == schedule
        for tampered in (
            {**schedule.to_dict(), "format": "ra.race.schedule.v0"},
            {**schedule.to_dict(), "steps": []},
            {**schedule.to_dict(), "seed": "not-hex!"},
        ):
            try:
                RaceSchedule.from_dict(tampered)
            except FormatFail:
                continue
            raise AssertionError(f"expected FormatFail for {tampered}")

    def test_ra_race_001_schedule_validation(self) -> None:
        target = make_target()
        schedule = build_schedule(target, 1, iteration=0)
        try:
            RaceSchedule(seed=1, iteration=0, target=make_target(), steps=())
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for empty steps")
        from ra.race.models import RaceStep

        try:
            RaceSchedule(
                seed=1,
                iteration=0,
                target=make_target(),
                steps=(RaceStep(worker=9, op="read", delay_us=0),),
            )
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for out-of-range worker")
        assert schedule.steps


class RaceSeedDistributionTest(unittest.TestCase):
    """RA-RACE-002: seeds are scored as a distribution, not a sole input."""

    def test_ra_race_002_uniform_bounds(self) -> None:
        dist = UniformSeedDistribution(lo=10, hi=20)
        rng = RaceRng("uniform")
        for _ in range(200):
            assert 10 <= dist.sample(rng) <= 20
        assert dist.describe() == {"hi": 20, "kind": "uniform", "lo": 10}
        try:
            UniformSeedDistribution(lo=21, hi=20)
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for lo > hi")

    def test_ra_race_002_weighted_and_fixed(self) -> None:
        dist = WeightedSeedDistribution(weights=((5, 3), (9, 1)))
        rng = RaceRng("weighted")
        counts = {5: 0, 9: 0}
        for _ in range(400):
            counts[dist.sample(rng)] += 1
        assert counts[5] > counts[9]
        fixed = FixedSeedDistribution(seed=77)
        assert fixed.sample(RaceRng("anything")) == 77
        try:
            WeightedSeedDistribution(weights=())
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for empty weights")
        try:
            WeightedSeedDistribution(weights=((1, 0),))
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for zero weight")
        try:
            WeightedSeedDistribution(weights=((1, 1), (1, 1)))
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for duplicate seeds")

    def test_ra_race_002_distribution_vs_seed_regression(self) -> None:
        """Same master seed reproduces the identical seed stream and claims."""
        rng_a = RaceRng("ra.race.probe|" + seed_hex(99) + "|t|0")
        rng_b = RaceRng("ra.race.probe|" + seed_hex(99) + "|t|0")
        dist = UniformSeedDistribution(lo=0, hi=1000)
        assert [dist.sample(rng_a) for _ in range(16)] == [
            dist.sample(rng_b) for _ in range(16)
        ]

    def test_ra_race_002_state_crash_rate_and_scores(self) -> None:
        state = RaceState.initial(
            target="t", master_seed=1, distribution={}, updated_ms=0
        )
        assert state.crash_rate == 0.0
        updated = state.record_probe(5, 1).record_probe(5, 1).record_probe(6, 0)
        assert updated.probes == 3
        assert updated.crashes == 2
        assert updated.crash_rate == 2 / 3
        scores = {score.seed_hex: score for score in updated.seed_scores}
        assert scores[seed_hex(5)].crashes == 2
        assert scores[seed_hex(5)].probes == 2
        assert scores[seed_hex(6)].crashes == 0


class RaceHarnessAsyncTest(unittest.IsolatedAsyncioTestCase):
    """End-to-end harness tests over the in-memory ledger and fake CAS."""

    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = await Ledger.open(self.root / "ledger.sqlite")
        self.cas = ContentAddressedStore(self.root / "cas")
        self.target = make_target()

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def make_harness(
        self,
        backend: Any,
        *,
        budget: RaceBudget | None = None,
        ring: Any = None,
    ) -> RaceHarness:
        return RaceHarness(self.ledger, backend, cas=self.cas, budget=budget, ring=ring)

    async def test_ra_race_003_probe_records_cas_bound_claims(self) -> None:
        backend = DeterministicRaceBackend(crash_threshold=256)
        harness = self.make_harness(backend)
        report = await harness.probe(
            self.target,
            UniformSeedDistribution(lo=0, hi=50),
            iterations=4,
            master_seed=1234,
        )
        assert report.iterations_completed == 4
        assert len(report.claims) == 4
        rows = await harness.store.load_state(self.target.name)
        assert rows is not None
        assert rows.probes == 4
        assert rows.crashes == 4
        claim_row = self.ledger.get_claim(report.claims[0])
        assert claim_row is not None
        assert claim_row["type"] == "race"
        artifacts = self.ledger.claim_artifacts(report.claims[0])
        roles = {str(link["role"]) for link in artifacts}
        assert {"schedule", "repro", "crash_meta"} <= roles
        record = harness.store.race_claims(target=self.target.name)[0]["record"]
        assert record.seed_hex == seed_hex(record.seed)
        assert record.outcome == "reproduced"
        # Crash metadata carries the schedule seed/digest for CrashRef-style repro.
        assert record.crash.metadata["seed"] == record.seed_hex
        assert record.crash.metadata["schedule_digest"] == record.schedule_digest

    async def test_ra_race_003_idempotent_reprobe_same_claim(self) -> None:
        """Saving the same crash record twice resolves to one claim (dedup)."""
        backend = DeterministicRaceBackend(crash_threshold=256)
        harness = self.make_harness(backend)
        report = await harness.probe(
            self.target, FixedSeedDistribution(seed=11), iterations=1, master_seed=5
        )
        claim_id = report.claims[0]
        row = self.ledger.get_claim(claim_id)
        assert row is not None
        record = harness.store.race_claims(target=self.target.name)[0]["record"]
        schedule = build_schedule(self.target, record.seed, iteration=record.iteration)
        # Remove the earlier hand-built crash; rebuild from the deterministic
        # backend's payload formula so digests match the stored record.
        from dataclasses import replace

        twin = replace(record, created_ms=record.created_ms)
        crash = RaceCrash(
            id=record.crash.id,
            kind=record.crash.kind,
            context=record.crash.context,
            handle_id=record.crash.handle_id,
            path=record.crash.path,
            digest=record.crash.digest,
            payload=b"race-crash\x00" + schedule.digest.encode("ascii"),
            metadata=dict(record.crash.metadata),
        )
        again = await harness.store.save_crash_claim(
            twin, schedule=schedule, crash=crash, run_id=None
        )
        assert again == claim_id

    async def test_ra_race_004_deterministic_replay_from_claim(self) -> None:
        backend = DeterministicRaceBackend(crash_threshold=256)
        harness = self.make_harness(backend)
        report = await harness.probe(
            self.target, FixedSeedDistribution(seed=3), iterations=1, master_seed=9
        )
        claim_id = report.claims[0]
        replay = await harness.replay_claim(claim_id, attempts=1)
        assert replay.reproduced is True
        assert replay.attempts == 1
        assert replay.schedule_digest == replay_claim_digest(harness, claim_id)

    async def test_ra_race_004_replay_detects_flaky_claim(self) -> None:
        # Crash only on first execution of each schedule: probe sees it, replay misses.
        calls: dict[str, int] = {}

        def flaky_rule(schedule: RaceSchedule) -> tuple[RaceCrash, ...]:
            seen = calls.get(schedule.digest, 0)
            calls[schedule.digest] = seen + 1
            if seen == 0:
                return (RaceCrash(id="c1", kind="race_toctou", payload=b"x"),)
            return ()

        backend = DeterministicRaceBackend(crash_rule=flaky_rule)
        harness = self.make_harness(backend, budget=RaceBudget(flake_budget=5, repro_budget=2))
        report = await harness.probe(
            self.target, FixedSeedDistribution(seed=4), iterations=1, master_seed=9
        )
        claim_id = report.claims[0]
        record = harness.store.race_claims(target=self.target.name)[0]["record"]
        assert record.outcome == "flaky"
        assert record.reproduced is False
        replay = await harness.replay_claim(claim_id, attempts=2)
        assert replay.reproduced is False
        assert replay.attempts == 2

    async def test_ra_race_005_flakiness_budget_parks_target(self) -> None:
        calls: dict[str, int] = {}

        def always_flaky(schedule: RaceSchedule) -> tuple[RaceCrash, ...]:
            seen = calls.get(schedule.digest, 0)
            calls[schedule.digest] = seen + 1
            if seen == 0:
                return (RaceCrash(id="c1", kind="race_toctou", payload=b"x"),)
            return ()

        backend = DeterministicRaceBackend(crash_rule=always_flaky)
        budget = RaceBudget(flake_budget=2, repro_budget=1, max_probes=50)
        harness = self.make_harness(backend, budget=budget)
        dist = UniformSeedDistribution(lo=0, hi=1000)
        # Each probe iteration uses a fresh schedule digest, so each crash is flaky.
        report = await harness.probe(self.target, dist, iterations=3, master_seed=1)
        assert report.parked is True
        assert report.parked_reason == "flake_budget"
        state = await harness.state_for_target(self.target.name)
        assert state is not None and state.parked is True
        with self.assertRaises(BudgetExhausted):
            await harness.probe(self.target, dist, iterations=1, master_seed=2)

    async def test_ra_race_006_repro_budget_caps_attempts(self) -> None:
        schedule_calls: list[str] = []

        def late_crash(schedule: RaceSchedule) -> tuple[RaceCrash, ...]:
            seen = schedule_calls.count(schedule.digest) + 1
            schedule_calls.append(schedule.digest)
            # Crash on the probe run (1st) and on the 3rd repro attempt (4th).
            if seen in (1, 4):
                return (RaceCrash(id="late", kind="race_toctou", payload=b"late"),)
            return ()

        backend = DeterministicRaceBackend(crash_rule=late_crash)
        budget = RaceBudget(flake_budget=10, repro_budget=3, max_probes=10)
        harness = self.make_harness(backend, budget=budget)
        await harness.probe(
            self.target, FixedSeedDistribution(seed=8), iterations=1, master_seed=2
        )
        # Probe run itself is call 1; repro attempts 2..4 hit the crash on the
        # 4th execution (attempt 3 of repro) -> reproduced within budget 3.
        record = harness.store.race_claims(target=self.target.name)[0]["record"]
        assert record.outcome == "reproduced"
        assert record.replay_attempts == 3
        assert record.replay_attempts <= budget.repro_budget

    async def test_ra_race_007_cas_binding_tamper_detected(self) -> None:
        backend = DeterministicRaceBackend(crash_threshold=256)
        harness = self.make_harness(backend)
        report = await harness.probe(
            self.target, FixedSeedDistribution(seed=6), iterations=1, master_seed=3
        )
        claim_id = report.claims[0]
        record = harness.store.race_claims(target=self.target.name)[0]["record"]
        # Corrupt the CAS bytes backing the schedule artifact -> integrity failure.
        cas_path = self.cas._path_for(record.schedule_digest)
        cas_path.write_bytes(b"corrupted")
        with self.assertRaises(CasCorrupt):
            await harness.store.verify_claim(claim_id)
        # Unknown claim and wrong claim type are FormatFail.
        with self.assertRaises(FormatFail):
            await harness.store.verify_claim("claim_missing")
        state_id = await harness.store.save_state(
            await harness.state_for_target(self.target.name)  # type: ignore[arg-type]
        )
        with self.assertRaises(FormatFail):
            await harness.store.verify_claim(state_id)

    async def test_ra_race_007_missing_claim_and_wrong_type(self) -> None:
        harness = self.make_harness(DeterministicRaceBackend())
        with self.assertRaises(FormatFail):
            await harness.store.verify_claim("claim_missing")

    async def test_ra_race_008_ring_binding(self) -> None:
        class GoodRing:
            def assert_in_ring(self, build: str, **kwargs: Any) -> dict[str, Any]:
                return {"id": "node-a", "build": build}

        class BadRing:
            def assert_in_ring(self, build: str, **kwargs: Any) -> dict[str, Any]:
                return {"id": "node-z", "build": build}

        class NoRing:
            def assert_in_ring(self, build: str, **kwargs: Any) -> dict[str, Any]:
                raise OutOfRing(f"no ring node for {build}")

        backend = DeterministicRaceBackend(crash_threshold=256)
        good = self.make_harness(backend, ring=GoodRing())
        report = await good.probe(
            self.target, FixedSeedDistribution(seed=1), iterations=1, master_seed=1
        )
        assert report.iterations_completed == 1

        bad = self.make_harness(backend, ring=BadRing())
        with self.assertRaises(OutOfRing):
            await bad.probe(self.target, FixedSeedDistribution(seed=1), iterations=1, master_seed=1)

        missing = self.make_harness(backend, ring=NoRing())
        with self.assertRaises(OutOfRing):
            await missing.probe(
                self.target, FixedSeedDistribution(seed=1), iterations=1, master_seed=1
            )

    async def test_ra_race_budget_max_probes_truncation(self) -> None:
        backend = DeterministicRaceBackend()
        budget = RaceBudget(max_probes=3)
        harness = self.make_harness(backend, budget=budget)
        report = await harness.probe(
            self.target, UniformSeedDistribution(lo=0, hi=10), iterations=10, master_seed=4
        )
        assert report.truncated_by_budget is True
        assert report.iterations_completed == 3
        state = await harness.state_for_target(self.target.name)
        assert state is not None and state.probes == 3
        with self.assertRaises(BudgetExhausted):
            await harness.probe(self.target, UniformSeedDistribution(lo=0, hi=10), iterations=1, master_seed=5)

    async def test_ra_race_state_persists_across_probe_calls(self) -> None:
        backend = DeterministicRaceBackend()
        harness = self.make_harness(backend)
        dist = UniformSeedDistribution(lo=0, hi=10)
        first = await harness.probe(self.target, dist, iterations=2, master_seed=7)
        second = await harness.probe(self.target, dist, iterations=3, master_seed=8)
        state = await harness.state_for_target(self.target.name)
        assert state is not None
        assert state.probes == 5
        assert state.session == second.session
        assert state.attempts == 5
        assert state.master_seed == 7  # first-seen master seed is retained
        assert first.state.session != second.state.session

    async def test_ra_race_failure_injection_backend_errors(self) -> None:
        class ExplodingBackend:
            name = "exploding"
            deterministic = True

            async def run_schedule(self, schedule: RaceSchedule) -> Any:
                raise RuntimeError("boom")

        budget = RaceBudget(max_consecutive_errors=2, max_probes=100)
        harness = self.make_harness(ExplodingBackend(), budget=budget)
        with self.assertRaises(RaceBackendError):
            await harness.probe(
                self.target, UniformSeedDistribution(lo=0, hi=5), iterations=5, master_seed=1
            )
        state = await harness.state_for_target(self.target.name)
        assert state is not None
        assert state.errors == 2
        assert self.ledger.claims_by_type("race", limit=10) == []

    async def test_ra_race_scripted_backend_exhaustion(self) -> None:
        backend = ScriptedRaceBackend()
        budget = RaceBudget(max_consecutive_errors=1)
        harness = self.make_harness(backend, budget=budget)
        with self.assertRaises(RaceBackendError):
            await harness.probe(
                self.target, FixedSeedDistribution(seed=1), iterations=1, master_seed=1
            )

    async def test_ra_race_probe_validation(self) -> None:
        harness = self.make_harness(DeterministicRaceBackend())
        for bad in (0, -1, True, "4"):
            with self.assertRaises(FormatFail):
                await harness.probe(
                    self.target,
                    FixedSeedDistribution(seed=1),
                    iterations=bad,  # type: ignore[arg-type]
                    master_seed=1,
                )
        with self.assertRaises(FormatFail):
            await harness.probe(
                self.target, FixedSeedDistribution(seed=1), iterations=1, master_seed=-1
            )

    async def test_ra_race_reproduce_and_replay_attempts_validation(self) -> None:
        harness = self.make_harness(DeterministicRaceBackend())
        schedule = build_schedule(self.target, 1, iteration=0)
        crash = RaceCrash(id="c", kind="k")
        for bad in (0, -1, True, "2"):
            with self.assertRaises(FormatFail):
                await harness.reproduce(schedule, crash, attempts=bad)  # type: ignore[arg-type]
        with self.assertRaises(FormatFail):
            await harness.replay_claim("claim_x", attempts=0)

    async def test_ra_race_lane_backend_end_to_end(self) -> None:
        lane = FakeLane(tier=Tier.C, crash_every=1)
        profile = DeviceProfile(udid="udid-1", ring_node="node-a", state="ready", tier=Tier.C)
        await lane.provision(profile)
        backend = LaneRaceBackend(lane, harness=HarnessRef(name="probe", kind="command"))
        harness = self.make_harness(backend, budget=RaceBudget(max_probes=4))
        report = await harness.probe(
            make_target(steps=2, max_delay_us=0),
            FixedSeedDistribution(seed=2),
            iterations=2,
            master_seed=6,
        )
        assert report.iterations_completed == 2
        # Every feed crashes (crash_every=1): 2 steps -> 2 crashes per schedule.
        assert len(report.claims) == 4
        record = harness.store.race_claims(target=self.target.name)[0]["record"]
        assert record.backend == "lane"
        assert record.deterministic is False
        # Replay through the same lane backend finds the crash again.
        replay = await harness.replay_claim(report.claims[0], attempts=1)
        assert replay.reproduced is True


def replay_claim_digest(harness: RaceHarness, claim_id: str) -> str:
    rows = harness.store.race_claims()
    for row in rows:
        if row["id"] == claim_id:
            return str(row["record"].schedule_digest)
    raise AssertionError("claim not found")


class RaceModelEdgeTest(unittest.TestCase):
    """Edge-case validation for race models."""

    def test_ra_race_model_rejects_bool_and_bad_types(self) -> None:
        with self.assertRaises(FormatFail):
            RaceBudget(flake_budget=True)  # type: ignore[arg-type]
        with self.assertRaises(FormatFail):
            RaceBudget(repro_budget=0)
        with self.assertRaises(FormatFail):
            make_target(ops=("a", "a"))
        with self.assertRaises(FormatFail):
            make_target(steps=0)
        with self.assertRaises(FormatFail):
            make_target(workers=0)

    def test_ra_race_state_parked_invariant(self) -> None:
        state = RaceState.initial(target="t", master_seed=1, distribution={}, updated_ms=0)
        parked = state.park("flake_budget")
        assert parked.parked is True
        assert parked.parked_reason == "flake_budget"
        raw = parked.to_dict()
        try:
            RaceState.from_dict({**raw, "parked": True, "parked_reason": None})
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for parked without reason")
        try:
            RaceState.from_dict({**raw, "flakes": raw["crashes"] + 1})
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for flakes > crashes")

    def test_ra_race_claim_record_invariants(self) -> None:
        crash = RaceCrash(id="c1", kind="k", payload=b"data")
        base = dict(
            target="t",
            target_digest="ab" * 32,
            ring_node="n",
            build="24A1",
            corpus_digest="cd" * 32,
            seed=1,
            seed_hex=seed_hex(1),
            iteration=0,
            schedule_digest="ef" * 32,
            outcome="reproduced",
            reproduced=True,
            replay_attempts=2,
            backend="deterministic",
            deterministic=True,
            flake_budget=3,
            repro_budget=5,
            crash=crash.summary(),
            created_ms=0,
        )
        record = RaceClaimRecord(**base)
        assert record.to_json()
        assert RaceClaimRecord.from_json(record.to_json()) == record
        try:
            RaceClaimRecord(**{**base, "outcome": "flaky", "reproduced": True})
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for inconsistent outcome")
        try:
            RaceClaimRecord(**{**base, "replay_attempts": 6})
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for replay_attempts > repro_budget")
        try:
            RaceClaimRecord(**{**base, "seed_hex": seed_hex(2)})
        except FormatFail:
            pass
        else:
            raise AssertionError("expected FormatFail for seed_hex mismatch")
        summary = CrashSummary.from_dict(crash.summary().to_dict())
        assert summary.signature() == crash.signature()

    def test_ra_race_run_result_and_state_validation(self) -> None:
        from ra.race import RaceRunResult

        schedule = build_schedule(make_target(), 1, iteration=0)
        ok = RaceRunResult.for_schedule(schedule, crashes=(), duration_ms=0)
        assert ok.schedule_digest == schedule.digest
        for kwargs in (
            {"schedule_digest": "not-hex", "crashes": (), "steps_executed": 0, "duration_ms": 0},
            {"schedule_digest": "00" * 32, "crashes": [], "steps_executed": 0, "duration_ms": 0},
            {"schedule_digest": "00" * 32, "crashes": (), "steps_executed": -1, "duration_ms": 0},
            {"schedule_digest": "00" * 32, "crashes": (), "steps_executed": 0, "duration_ms": 0, "errors": ["x"]},
        ):
            with self.assertRaises(FormatFail):
                RaceRunResult(**kwargs)  # type: ignore[arg-type]
        with self.assertRaises(FormatFail):
            RaceState.initial(
                target="t", master_seed=1, distribution={"bad": object()}, updated_ms=0
            )

    def test_ra_race_lane_backend_config_validation(self) -> None:
        lane = FakeLane(tier=Tier.C)
        harness_ref = HarnessRef(name="probe", kind="command")
        for bad_scale in (float("nan"), float("inf"), -1.0, True, "1"):
            with self.assertRaises(FormatFail):
                LaneRaceBackend(
                    lane,
                    harness=harness_ref,
                    delay_scale=bad_scale,  # type: ignore[arg-type]
                )
        for bad_steps in (0, -1, True, 1.5):
            with self.assertRaises(FormatFail):
                LaneRaceBackend(lane, harness=harness_ref, max_steps=bad_steps)  # type: ignore[arg-type]


class RaceScheduleStrategyCoverageTest(unittest.TestCase):
    """Schedule-exploration strategies, seed derivation, and coverage gaps."""

    def test_ra_race_strategy_deterministic_distinct_and_validated(self) -> None:
        from ra.race import SCHEDULE_STRATEGIES, build_schedule, normalize_strategy

        target = make_target(workers=3, steps=12, ops=("read", "write", "rename"))
        seen: dict[str, str] = {}
        for strategy in SCHEDULE_STRATEGIES:
            first = build_schedule(target, 42, iteration=1, strategy=strategy)
            second = build_schedule(target, 42, iteration=1, strategy=strategy)
            assert first.to_bytes() == second.to_bytes()
            assert first.digest == second.digest
            seen[strategy] = first.digest
        assert len(set(seen.values())) >= 3
        assert normalize_strategy("pairwise") == "pairwise"
        for bad in ("", "bogus", "RANDOM"):
            with self.assertRaises(FormatFail):
                build_schedule(target, 42, iteration=1, strategy=bad)

    def test_ra_race_interleaving_coverage_gaps_and_merge(self) -> None:
        from ra.race import InterleavingCoverage, build_schedule

        target = make_target(workers=2, ops=("read", "write"), steps=8)
        schedules = [
            build_schedule(target, 7, iteration=0, strategy=strategy)
            for strategy in ("pairwise", "round_robin", "delay_pulse")
        ]
        coverage = InterleavingCoverage.from_schedules(schedules)
        assert coverage.schedule_count == 3
        assert coverage.step_count == 24
        assert coverage.worker_op_counts
        assert coverage.worker_transition_counts
        assert coverage.gaps(workers=2, ops=target.ops, require_worker_transitions=True) == ()
        payload = coverage.to_dict()
        assert payload["schedule_count"] == 3
        empty = InterleavingCoverage.from_schedules([])
        gaps = empty.gaps(workers=2, ops=("read", "write"), require_worker_transitions=True)
        assert len(gaps) == 6
        merged = empty.merge(coverage)
        assert merged.schedule_count == coverage.schedule_count
        assert merged.step_count == coverage.step_count

    def test_ra_race_seed_derivation_and_scoring(self) -> None:
        from ra.race import index_seed, score_seed_outcomes, seed_sequence

        assert index_seed(9, 0) == index_seed(9, 0)
        assert index_seed(9, 0) != index_seed(9, 1)
        assert index_seed("0x10", 2, salt="a") == index_seed(16, 2, salt="a")
        sequence = seed_sequence(3, 4, start=2, salt="s")
        assert sequence == seed_sequence(3, 4, start=2, salt="s")
        assert len(set(sequence)) == 4
        for bad in ((-1,), (True,)):
            with self.assertRaises(FormatFail):
                index_seed(1, bad[0])
        with self.assertRaises(FormatFail):
            seed_sequence(1, -1)
        scores = score_seed_outcomes(
            [(1, True), (1, False), (2, False), (3, True), (3, True)], max_seeds=2
        )
        assert [score.seed for score in scores] == [3, 1]
        assert scores[0].rate == 1.0
        assert scores[1].rate == 0.5
        with self.assertRaises(FormatFail):
            score_seed_outcomes([(1, "yes")])  # type: ignore[list-item]
        with self.assertRaises(FormatFail):
            score_seed_outcomes([], max_seeds=0)


class RaceHarnessStrategyBackendTest(unittest.IsolatedAsyncioTestCase):
    """Harness strategy selection and backend-result validation."""

    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = await Ledger.open(self.root / "ledger.sqlite")
        self.cas = ContentAddressedStore(self.root / "cas")
        self.target = make_target()

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    async def test_ra_race_probe_uses_schedule_strategies(self) -> None:
        backend = DeterministicRaceBackend(crash_threshold=256)
        harness = RaceHarness(
            self.ledger,
            backend,
            cas=self.cas,
            strategies=("pairwise", "round_robin", "op_focus", "delay_pulse"),
        )
        report = await harness.probe(
            self.target,
            FixedSeedDistribution(seed=3),
            iterations=6,
            master_seed=9,
        )
        assert report.iterations_completed == 6
        assert len(report.claims) == 6
        for bad in ((), ("bogus",)):
            with self.assertRaises(FormatFail):
                RaceHarness(self.ledger, backend, cas=self.cas, strategies=bad)

    async def test_ra_race_backend_digest_mismatch_rejected(self) -> None:
        from ra.race import RaceRunResult

        class BadBackend:
            name = "bad"
            deterministic = True

            async def run_schedule(self, schedule: RaceSchedule) -> RaceRunResult:
                return RaceRunResult(
                    schedule_digest="00" * 32,
                    crashes=(),
                    steps_executed=1,
                    duration_ms=0,
                )

        harness = RaceHarness(self.ledger, BadBackend(), cas=self.cas)
        schedule = build_schedule(self.target, 1, iteration=0)
        crash = RaceCrash(id="c", kind="k")
        with self.assertRaises(RaceBackendError):
            await harness.reproduce(schedule, crash, attempts=1)


if __name__ == "__main__":
    unittest.main()
