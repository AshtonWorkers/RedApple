"""Tests for the coverage-guided corpus scheduler (ra.corpus)."""

from __future__ import annotations

import json
import math
import random
from typing import Any

import pytest

from ra.corpus import CorpusScheduler, CorpusSeedSpec, SeedEnergyPolicy
from ra.errors import FormatFail
from ra.ledger import Ledger
from tests.conftest import run

STORE_KIND = "ra.corpus.scheduler.v1"


def spec(seed_id: str, edges: Any = (), lane: str = "lane-a", **kwargs: Any) -> CorpusSeedSpec:
    return CorpusSeedSpec(seed_id=seed_id, lane=lane, edges=edges, **kwargs)


def seed_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "seed_id": "s1",
        "lane": "lane-a",
        "target": None,
        "artifact_id": None,
        "metadata": {},
        "edges": ["e1"],
        "runs": 0,
        "new_edges": 1,
        "last_new_edges": 1,
        "last_run_id": None,
        "last_seen": 1,
        "created": 1,
        "updated": 1,
        "status": "active",
    }
    base.update(overrides)
    return base


def slot_payload(seed: Any, *, slot: int = 0, store: str = STORE_KIND, namespace: str = "default") -> str:
    return json.dumps(
        {"store": store, "namespace": namespace, "slot": slot, "seed": seed},
        sort_keys=True,
        separators=(",", ":"),
    )


def test_policy_rejects_invalid_values():
    for field in (
        "base_energy",
        "novelty_weight",
        "rarity_weight",
        "new_edge_weight",
        "execution_decay",
    ):
        for bad in (True, "1", -0.5, math.inf, -math.inf, math.nan, 1_000_001.0):
            with pytest.raises(FormatFail):
                SeedEnergyPolicy(**{field: bad})
    for bad in (True, 1.5, 0, -1, 1_000_001, "8"):
        with pytest.raises(FormatFail):
            SeedEnergyPolicy(new_edge_cap=bad)


def test_policy_energy_is_finite_non_negative_and_monotone():
    rng = random.Random(20261122)
    policy = SeedEnergyPolicy(
        base_energy=1.5, novelty_weight=2.0, rarity_weight=1.0,
        new_edge_weight=0.5, execution_decay=0.25, new_edge_cap=8,
    )
    for _ in range(500):
        covered = rng.randint(0, 200)
        last_new = rng.randint(0, 200)
        runs = rng.randint(0, 500)
        rarity = rng.random()
        value = policy.energy(
            covered_edges=covered, last_new_edges=last_new, runs=runs, rarity=rarity
        )
        assert math.isfinite(value)
        assert value >= 0.0
    base = dict(covered_edges=10, last_new_edges=5, runs=3, rarity=0.5)
    more_new = policy.energy(covered_edges=10, last_new_edges=6, runs=3, rarity=0.5)
    more_runs = policy.energy(covered_edges=10, last_new_edges=5, runs=4, rarity=0.5)
    more_rare = policy.energy(covered_edges=10, last_new_edges=5, runs=3, rarity=0.9)
    plain = policy.energy(**base)  # type: ignore[arg-type]
    assert more_new >= plain
    assert more_runs <= plain
    assert more_rare >= plain


def test_policy_energy_rejects_bad_inputs():
    policy = SeedEnergyPolicy()
    with pytest.raises(FormatFail):
        policy.energy(covered_edges=True, last_new_edges=0, runs=0, rarity=0.5)
    with pytest.raises(FormatFail):
        policy.energy(covered_edges=-1, last_new_edges=0, runs=0, rarity=0.5)
    with pytest.raises(FormatFail):
        policy.energy(covered_edges=1, last_new_edges=0, runs=0, rarity=1.5)
    with pytest.raises(FormatFail):
        policy.energy(covered_edges=1, last_new_edges=0, runs=0, rarity=-0.1)
    with pytest.raises(FormatFail):
        policy.energy(covered_edges=1, last_new_edges=0, runs=0, rarity=math.nan)


def test_scheduler_rejects_bad_construction():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            for bad in ("", "-lead", "a" * 64, "has space", 1, None):
                with pytest.raises(FormatFail):
                    CorpusScheduler(ledger, namespace=bad)  # type: ignore[arg-type]
            for kwargs in (
                {"max_corpus_size": 0},
                {"max_corpus_size": 4097},
                {"max_corpus_size": True},
                {"max_edges_per_seed": 0},
                {"max_total_edges": -1},
                {"policy": object()},
            ):
                with pytest.raises(FormatFail):
                    CorpusScheduler(ledger, **kwargs)  # type: ignore[arg-type]
            ok = CorpusScheduler(ledger, namespace="lane.alpha_1", policy=SeedEnergyPolicy())
            assert ok.stats()["active"] == 0
        finally:
            await ledger.close()

    run(body())


def test_register_view_and_stats_roundtrip():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger, max_corpus_size=8)
            await scheduler.register_seed(
                spec(
                    "seed-1",
                    edges=["e2", "e1", "e1"],
                    lane="lane-b",
                    target="com.apple.test",
                    artifact_id="art_1",
                    metadata={"family": "webkit"},
                ),
                created=1000,
            )
            views = scheduler.active_seeds()
            assert len(views) == 1
            view = views[0]
            assert view.seed_id == "seed-1"
            assert view.lane == "lane-b"
            assert view.edges == ("e1", "e2")
            assert view.covered_edges == 2
            assert view.new_edges == 2
            assert view.last_new_edges == 2
            assert view.runs == 0
            assert view.created == 1000 and view.updated == 1000 and view.last_seen == 1000
            assert view.target == "com.apple.test"
            assert view.artifact_id == "art_1"
            assert view.metadata == {"family": "webkit"}
            assert 0.0 <= view.energy < math.inf and math.isfinite(view.energy)
            stats = scheduler.stats()
            assert stats == {
                "slots": 1,
                "active": 1,
                "empty": 0,
                "total_edges": 2,
                "max_corpus_size": 8,
                "max_total_edges": 262_144,
            }
            filtered = scheduler.active_seeds(lane="lane-b")
            assert [v.seed_id for v in filtered] == ["seed-1"]
            assert scheduler.active_seeds(lane="lane-z") == []
        finally:
            await ledger.close()

    run(body())


def test_register_refresh_merges_telemetry():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("s1", edges=["a", "b"]), created=1)
            view = await scheduler.record_coverage("s1", ["b", "c"], run_id="run-1", created=2)
            assert view.runs == 1
            assert view.new_edges == 3
            assert view.last_new_edges == 1
            assert view.last_run_id == "run-1"
            assert view.last_seen == 2 and view.updated == 2
            assert view.edges == ("a", "b", "c")

            await scheduler.register_seed(spec("s1", edges=["c", "d"], lane="lane-c"), created=3)
            view = scheduler.active_seeds()[0]
            assert view.edges == ("a", "b", "c", "d")
            assert view.new_edges == 4
            assert view.last_new_edges == 1
            assert view.runs == 1
            assert view.lane == "lane-c"

            await scheduler.register_seed(spec("s1", edges=["a"]), created=4)
            view = scheduler.active_seeds()[0]
            assert view.last_new_edges == 0
            assert view.new_edges == 4
            assert scheduler.stats()["active"] == 1
        finally:
            await ledger.close()

    run(body())


def test_record_coverage_unknown_seed_and_bad_input():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            with pytest.raises(FormatFail):
                await scheduler.record_coverage("ghost", ["e1"])
            await scheduler.register_seed(spec("s1", edges=["e1"]), created=1)
            with pytest.raises(FormatFail):
                await scheduler.record_coverage("s1", "e1")  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                await scheduler.record_coverage("s1", [""], created=-1)
            with pytest.raises(FormatFail):
                await scheduler.record_coverage("s1", ["e1"], run_id="bad\x00id")
        finally:
            await ledger.close()

    run(body())


def test_seed_without_edges_has_zero_rarity():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("empty", edges=[]))
            view = scheduler.active_seeds()[0]
            assert view.edges == ()
            assert view.covered_edges == 0
            assert view.rarity == 0.0
            assert view.last_new_edges == 0
            assert math.isfinite(view.energy) and view.energy >= 0.0
        finally:
            await ledger.close()

    run(body())


def test_record_coverage_rejects_edge_overflow():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger, max_edges_per_seed=3)
            await scheduler.register_seed(spec("s1", edges=["a", "b"]))
            with pytest.raises(FormatFail, match="edge set exceeds"):
                await scheduler.record_coverage("s1", ["b", "c", "d"])
            view = scheduler.active_seeds()[0]
            assert view.edges == ("a", "b")
            assert view.runs == 0
        finally:
            await ledger.close()

    run(body())


def test_next_batch_zero_energy_tail_uses_last_slot():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            policy = SeedEnergyPolicy(
                base_energy=0.0,
                novelty_weight=0.0,
                rarity_weight=0.0,
                new_edge_weight=1.0,
                execution_decay=0.0,
                new_edge_cap=64,
            )
            scheduler = CorpusScheduler(ledger, policy=policy)
            await scheduler.register_seed(spec("cold", edges=["shared"]))
            await scheduler.record_coverage("cold", ["shared"])
            await scheduler.register_seed(spec("hot", edges=[f"h-{i}" for i in range(64)]))
            views = {v.seed_id: v for v in scheduler.active_seeds()}
            assert views["hot"].energy == 1.0
            assert views["cold"].energy == 0.0
            batch = scheduler.next_batch(batch_size=2, schedule_seed=0)
            assert [v.seed_id for v in batch] == ["hot", "cold"]
        finally:
            await ledger.close()

    run(body())


def test_register_rejects_bad_specs():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            bad_specs = [
                spec("", edges=["e"]),
                spec("s" * 200, edges=["e"]),
                spec("ok", edges=["e"], lane=""),
                spec("ok", edges=["e"], target="bad\nname"),
                spec("ok", edges=["e"], artifact_id="a" * 300),
                spec("ok", edges="e1"),
                spec("ok", edges=object()),
                spec("ok", edges=["e" * 300]),
                spec("ok", edges=[1]),
                spec("ok", edges=["e"], metadata=["not-a-mapping"]),  # type: ignore[arg-type]
                spec("ok", edges=["e"], metadata={"": "x"}),
                spec("ok", edges=["e"], metadata={"k": object()}),
                spec("ok", edges=["e"], metadata={"k": "x" * 9000}),
            ]
            for bad in bad_specs:
                with pytest.raises(FormatFail):
                    await scheduler.register_seed(bad)
            with pytest.raises(FormatFail):
                await scheduler.register_seed(spec("ok", edges=["e"]), created=-5)
            assert scheduler.stats()["active"] == 0
        finally:
            await ledger.close()

    run(body())


def test_corpus_growth_is_bounded():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger, max_corpus_size=3)
            for index in range(3):
                await scheduler.register_seed(spec(f"s{index}", edges=[f"e{index}"]))
            assert scheduler.stats()["active"] == 3
            with pytest.raises(FormatFail, match="corpus is full"):
                await scheduler.register_seed(spec("s3", edges=["e3"]))
            # Refreshing an existing seed still works when the corpus is full.
            await scheduler.register_seed(spec("s0", edges=["e0", "e0b"]))
            assert scheduler.stats()["total_edges"] == 4
        finally:
            await ledger.close()

    run(body())


def test_edge_budget_is_bounded():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger, max_edges_per_seed=6, max_total_edges=5)
            await scheduler.register_seed(spec("s1", edges=["a", "b", "c"]))
            with pytest.raises(FormatFail, match="edge budget"):
                await scheduler.register_seed(spec("s2", edges=["d", "e", "f"]))
            with pytest.raises(FormatFail, match="too many edges"):
                await scheduler.register_seed(spec("s2", edges=["d", "e", "f", "g", "h", "i", "j"]))
            await scheduler.register_seed(spec("s1", edges=["a", "b", "c", "d"]))
            assert scheduler.stats()["total_edges"] == 4
            with pytest.raises(FormatFail, match="edge budget"):
                await scheduler.register_seed(spec("s1", edges=["e", "f"]))
            with pytest.raises(FormatFail, match="edge set exceeds"):
                await scheduler.register_seed(spec("s1", edges=["e", "f", "g"]))
            assert scheduler.stats()["total_edges"] == 4
            with pytest.raises(FormatFail):
                await scheduler.register_seed(spec("s3", edges="not-a-list"))
        finally:
            await ledger.close()

    run(body())


def test_next_batch_is_deterministic_and_filtered():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            for index in range(6):
                await scheduler.register_seed(
                    spec(
                        f"s{index}",
                        edges=[f"e{index}", f"shared-{index % 2}"],
                        lane="lane-a" if index % 2 == 0 else "lane-b",
                    )
                )
                await scheduler.record_coverage(f"s{index}", [f"extra-{index}"], created=index + 1)
            first = scheduler.next_batch(batch_size=4, schedule_seed=7)
            second = scheduler.next_batch(batch_size=4, schedule_seed=7)
            assert [v.seed_id for v in first] == [v.seed_id for v in second]
            assert len(first) == 4
            assert len({v.seed_id for v in first}) == 4

            twin = CorpusScheduler(ledger)
            assert [v.seed_id for v in twin.next_batch(batch_size=4, schedule_seed=7)] == [
                v.seed_id for v in first
            ]

            lane_batch = scheduler.next_batch(lane="lane-a", batch_size=10, schedule_seed=7)
            assert {v.seed_id for v in lane_batch} == {"s0", "s2", "s4"}

            excluded = scheduler.next_batch(batch_size=10, schedule_seed=7, exclude=[first[0].seed_id])
            assert first[0].seed_id not in {v.seed_id for v in excluded}
            assert len(excluded) == 5

            assert scheduler.next_batch(lane="ghost", schedule_seed=1) == []
            assert scheduler.next_batch(exclude=[v.seed_id for v in scheduler.active_seeds()]) == []
        finally:
            await ledger.close()

    run(body())


def test_next_batch_validation():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger, max_corpus_size=4)
            await scheduler.register_seed(spec("s1", edges=["e1"]))
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=0)
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=5)
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=True)
            with pytest.raises(FormatFail):
                scheduler.next_batch(schedule_seed=-1)
            with pytest.raises(FormatFail):
                scheduler.next_batch(schedule_seed="7")  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=1, exclude="s1")  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=1, exclude=[""])
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=1, exclude=object())  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                scheduler.next_batch(batch_size=1, lane="")
            empty = CorpusScheduler(ledger, namespace="empty-ns")
            assert empty.next_batch() == []
        finally:
            await ledger.close()

    run(body())


def test_next_batch_favours_high_energy_seed():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            policy = SeedEnergyPolicy(
                base_energy=1.0,
                novelty_weight=100.0,
                rarity_weight=0.0,
                new_edge_weight=100.0,
                execution_decay=10.0,
                new_edge_cap=64,
            )
            scheduler = CorpusScheduler(ledger, policy=policy)
            await scheduler.register_seed(spec("stale", edges=["old"]))
            for _ in range(100):
                await scheduler.record_coverage("stale", ["old"])
            await scheduler.register_seed(spec("fresh", edges=[f"new-{i}" for i in range(64)]))
            views = {v.seed_id: v for v in scheduler.active_seeds()}
            assert views["fresh"].energy > views["stale"].energy * 1000
            batch = scheduler.next_batch(batch_size=1, schedule_seed=0)
            assert [v.seed_id for v in batch] == ["fresh"]
        finally:
            await ledger.close()

    run(body())


def test_next_batch_zero_energy_is_deterministic():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            policy = SeedEnergyPolicy(
                base_energy=0.0, novelty_weight=0.0, rarity_weight=0.0,
                new_edge_weight=0.0, execution_decay=0.0,
            )
            scheduler = CorpusScheduler(ledger, policy=policy)
            for seed_id in ("s2", "s1", "s3"):
                await scheduler.register_seed(spec(seed_id, edges=[seed_id]))
            batch = scheduler.next_batch(batch_size=2, schedule_seed=99)
            assert [v.seed_id for v in batch] == ["s1", "s2"]
            assert all(v.energy == 0.0 for v in scheduler.active_seeds())
        finally:
            await ledger.close()

    run(body())


def test_minimize_drops_dominated_and_reuses_slot():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("big", edges=["x", "y", "z"]))
            await scheduler.register_seed(spec("small", edges=["x", "y"]))
            await scheduler.register_seed(spec("unique", edges=["y", "w"]))
            result = await scheduler.minimize(created=10)
            assert result.changed is True
            assert result.dropped == ("small",)
            assert result.kept == ("big", "unique")
            assert result.freed_slots == 1
            assert scheduler.stats()["empty"] == 1
            assert {v.seed_id for v in scheduler.active_seeds()} == {"big", "unique"}

            await scheduler.register_seed(spec("new", edges=["n"]))
            stats = scheduler.stats()
            assert stats["slots"] == 3 and stats["active"] == 3 and stats["empty"] == 0

            again = await scheduler.minimize()
            assert again.changed is False and again.dropped == ()
        finally:
            await ledger.close()

    run(body())


def test_minimize_never_drops_uniquely_covering_seed():
    rng = random.Random(777)
    for trial in range(60):
        async def body(trial=trial, rng=rng):
            ledger = await Ledger.open(":memory:")
            try:
                scheduler = CorpusScheduler(ledger, max_corpus_size=32)
                universe = [f"edge-{i}" for i in range(rng.randint(2, 12))]
                count = rng.randint(2, 10)
                ids = [f"s{index:02d}" for index in range(count)]
                for seed_id in ids:
                    edges = sorted(rng.sample(universe, rng.randint(1, len(universe))))
                    await scheduler.register_seed(spec(seed_id, edges=edges))
                # Coverage reports create varied novelty so energies differ.
                for index, seed_id in enumerate(ids):
                    await scheduler.record_coverage(seed_id, [f"cov-{trial}-{index}"])
                before = {v.seed_id: set(v.edges) for v in scheduler.active_seeds()}
                result = await scheduler.minimize()
                after = {v.seed_id for v in scheduler.active_seeds()}
                assert set(result.dropped) == set(before) - after
                for seed_id, edges in before.items():
                    unique = edges - set().union(
                        *(other for sid, other in before.items() if sid != seed_id)
                    )
                    if unique and seed_id in result.dropped:
                        raise AssertionError(f"uniquely-covering seed dropped: {seed_id}")
                assert after == set(before) - set(result.dropped)
                for seed_id in after:
                    assert before[seed_id] <= set(
                        next(v.edges for v in scheduler.active_seeds() if v.seed_id == seed_id)
                    )
            finally:
                await ledger.close()

        run(body())


def test_minimize_tie_break_and_single_seed():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            zero = SeedEnergyPolicy(
                base_energy=0.0, novelty_weight=0.0, rarity_weight=0.0,
                new_edge_weight=0.0, execution_decay=0.0,
            )
            scheduler = CorpusScheduler(ledger, policy=zero)
            alone = await scheduler.minimize()
            assert alone.changed is False and alone.kept == ()
            await scheduler.register_seed(spec("solo", edges=["e"]))
            single = await scheduler.minimize()
            assert single.changed is False and single.kept == ("solo",)

            await scheduler.register_seed(spec("a-seed", edges=["x", "y"]))
            await scheduler.register_seed(spec("b-seed", edges=["x", "y"]))
            result = await scheduler.minimize()
            assert result.dropped == ("b-seed",)
            assert result.kept == ("a-seed", "solo")
        finally:
            await ledger.close()

    run(body())


def test_state_survives_ledger_reopen(tmp_path):
    async def body():
        path = tmp_path / "corpus.sqlite"
        ledger = await Ledger.open(path)
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("persist", edges=["p1", "p2"]), created=5)
            await scheduler.record_coverage("persist", ["p3"], run_id="r1", created=6)
            batch_before = scheduler.next_batch(batch_size=2, schedule_seed=3)
        finally:
            await ledger.close()

        again = await Ledger.open(path)
        try:
            scheduler = CorpusScheduler(again)
            views = scheduler.active_seeds()
            assert [v.seed_id for v in views] == ["persist"]
            view = views[0]
            assert view.edges == ("p1", "p2", "p3")
            assert view.runs == 1 and view.last_run_id == "r1" and view.created == 5
            batch_after = scheduler.next_batch(batch_size=2, schedule_seed=3)
            assert [v.seed_id for v in batch_after] == [v.seed_id for v in batch_before]
        finally:
            await again.close()

    run(body())


def test_load_rejects_tampered_payloads():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("s1", edges=["e1"]), created=1)

            def tamper(payload: Any) -> None:
                ledger.store._conn.execute(
                    "UPDATE work_order SET payload_json=? WHERE unit=?",
                    (payload, "ra.corpus.default"),
                )

            cases: list[Any] = [
                None,
                "{not-json",
                "[1, 2]",
                slot_payload(None, store="other.store"),
                slot_payload(None, namespace="other"),
                json.dumps({"store": STORE_KIND, "namespace": "default", "slot": 0}),
                slot_payload(5),
                slot_payload(seed_dict(status="dropped")),
                slot_payload(seed_dict(edges="abc")),
                slot_payload(seed_dict(seed_id="")),
                slot_payload(seed_dict(runs=-1)),
                slot_payload(seed_dict(new_edges=-2)),
                slot_payload(seed_dict(last_new_edges=1.5)),
                slot_payload(seed_dict(last_seen=-3)),
                slot_payload(seed_dict(created="soon")),
                slot_payload(seed_dict(metadata=["x"])),
                slot_payload(seed_dict(metadata={"k": "x" * 9000})),
                slot_payload(seed_dict(last_run_id="bad\x00id")),
                slot_payload(seed_dict(target="bad\nid")),
                slot_payload(seed_dict(), slot=9999),
                json.dumps(
                    {
                        "store": STORE_KIND,
                        "namespace": "default",
                        "slot": 0,
                        "seed": seed_dict(metadata={"x": math.nan}),
                    },
                    sort_keys=True,
                ),
            ]
            for payload in cases:
                tamper(payload)
                with pytest.raises(FormatFail):
                    scheduler.active_seeds()
        finally:
            await ledger.close()

    run(body())


def test_load_rejects_duplicate_slot():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("s1", edges=["e1"]))
            await scheduler.register_seed(spec("s2", edges=["e2"]))
            rows = ledger.store.work_orders_for_unit("ra.corpus.default")
            assert len(rows) == 2
            # Rewrite the second slot's payload to claim slot 0 as well.
            ledger.store._conn.execute(
                "UPDATE work_order SET payload_json=? WHERE id=?",
                (slot_payload(seed_dict(seed_id="s2"), slot=0), rows[1]["id"]),
            )
            with pytest.raises(FormatFail, match="duplicate corpus slot"):
                scheduler.active_seeds()
        finally:
            await ledger.close()

    run(body())


def test_load_rejects_duplicate_seed_id():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("s1", edges=["e1"]))
            await scheduler.register_seed(spec("s2", edges=["e2"]))
            rows = ledger.store.work_orders_for_unit("ra.corpus.default")
            ledger.store._conn.execute(
                "UPDATE work_order SET payload_json=? WHERE id=?",
                (
                    slot_payload(seed_dict(seed_id="s1", edges=["e2"]), slot=1),
                    rows[1]["id"],
                ),
            )
            with pytest.raises(FormatFail, match="duplicate corpus seed"):
                await scheduler.record_coverage("s1", ["e3"])
        finally:
            await ledger.close()

    run(body())


def test_load_accepts_payload_without_metadata():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("s1", edges=["e1"]), created=1)
            seed = seed_dict(metadata=None)
            del seed["metadata"]
            ledger.store._conn.execute(
                "UPDATE work_order SET payload_json=? WHERE unit=?",
                (slot_payload(seed), "ra.corpus.default"),
            )
            view = scheduler.active_seeds()[0]
            assert view.metadata == {}
            assert view.seed_id == "s1"
        finally:
            await ledger.close()

    run(body())


def test_save_slot_failure_is_reported():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            scheduler = CorpusScheduler(ledger)
            await scheduler.register_seed(spec("s1", edges=["e1"]), created=1)

            async def missing(_work_order_id: str, _state: str, *, payload_json: str | None = None) -> bool:
                return False

            ledger.update_work_order_state = missing  # type: ignore[method-assign]
            with pytest.raises(FormatFail, match="disappeared"):
                await scheduler.record_coverage("s1", ["e2"])
        finally:
            await ledger.close()

    run(body())


def test_minimize_with_lanes_isolated_by_namespace():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            alpha = CorpusScheduler(ledger, namespace="alpha")
            beta = CorpusScheduler(ledger, namespace="beta")
            await alpha.register_seed(spec("shared-id", edges=["a1"]))
            await beta.register_seed(spec("shared-id", edges=["b1", "b2"]))
            assert [v.seed_id for v in alpha.active_seeds()] == ["shared-id"]
            assert beta.stats()["total_edges"] == 2
            assert alpha.stats()["max_corpus_size"] == 512
            # Namespaces never see each other's slots.
            beta_batch = beta.next_batch(schedule_seed=1)
            assert [v.seed_id for v in beta_batch] == ["shared-id"]
        finally:
            await ledger.close()

    run(body())
