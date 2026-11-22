"""RA-DISC ImageIO/HEIF discovery campaign tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ra.discovery import (
    IMAGE_FORMATS,
    STRUCTURE_OPS,
    CampaignConfig,
    CampaignState,
    DiscoveryCampaign,
    DiscoveryHarnessRef,
    LedgerDiscoveryStore,
    MacOSUnavailable,
    MutationEngine,
    build_image_seed,
    classify_crash,
    detect_image_format,
    image_gate,
    imageio_heif_feed_manifest,
    imageio_heif_feed_source,
    imageio_heif_harness_ref,
    iter_box_nodes,
    macos_available,
    macos_verification_checklist,
    mutate_image_structure,
    parse_box_tree,
    require_macos,
)
from ra.discovery.heif import (
    find_box_nodes,
    heif_gate,
    is_heif_brand,
    parse_boxes,
    read_u32,
    read_u64,
)
from ra.discovery.images import PNG_SIGNATURE, default_imageio_seeds
from ra.discovery.models import CrashRecord
from ra.discovery.mutate import MUTATION_STRATEGIES, DeterministicRng, load_corpus, mutate_bytes
from ra.errors import DeviceLost, FormatFail, NotProvisioned
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger


def box(box_type: bytes, payload: bytes = b"", declared_size: int | None = None) -> bytes:
    size = 8 + len(payload) if declared_size is None else declared_size
    return size.to_bytes(4, "big") + box_type + payload


def heif_sample(
    brand: bytes = b"heic",
    compatible: tuple[bytes, ...] = (b"mif1",),
    meta_payload: bytes = b"\x00\x00\x00\x00",
) -> bytes:
    ftyp_payload = brand + (0).to_bytes(4, "big") + b"".join(compatible)
    return box(b"ftyp", ftyp_payload) + box(b"meta", meta_payload)


def rich_heif_sample() -> bytes:
    ispe = box(b"ispe", b"\x00\x00\x00\x00" + (16).to_bytes(4, "big") * 2)
    ipco = box(b"ipco", ispe)
    iprp = box(b"iprp", ipco)
    return heif_sample(meta_payload=b"\x00\x00\x00\x00" + iprp)


@dataclass(frozen=True)
class FakeCrash:
    id: str
    kind: str = "fake"
    handle_id: str | None = None
    path: str | None = None
    digest: str | None = None
    payload: bytes = b""
    context: str = "app"
    created_ms: int = 1
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class FakeHandle:
    handle_id: str


class FakeLane:
    def __init__(
        self,
        *,
        feed_failures: dict[int, Exception] | None = None,
        fail_all_error: Exception | None = None,
        crash_on_feed: int | None = None,
        thermal_value: Any = "nominal",
        ready: bool = True,
        feed_results: dict[int, Any] | None = None,
        collect_failures: dict[int, Exception] | None = None,
        duplicate_crash: bool = False,
    ) -> None:
        self.name = "fake"
        self.feed_failures = dict(feed_failures or {})
        self.fail_all_error = fail_all_error
        self.crash_on_feed = crash_on_feed
        self.thermal_value = thermal_value
        self.ready = ready
        self.feed_results = dict(feed_results or {})
        self.collect_failures = dict(collect_failures or {})
        self.duplicate_crash = duplicate_crash
        self.profile: Any = None
        self.feeds: list[bytes] = []
        self.launches = 0
        self.resets = 0
        self.teardowns = 0
        self._feeds = 0
        self._collect_calls = 0
        self._crashes: dict[str, list[FakeCrash]] = {}

    async def provision(self, profile: Any) -> Any:
        self.profile = profile
        return SimpleNamespace(ready=self.ready)

    async def assert_ready(self) -> None:
        if not self.ready:
            raise NotProvisioned("fake lane not ready")

    async def launch(self, target: str, harness: Any) -> FakeHandle:
        self.launches += 1
        return FakeHandle(f"handle_{self.launches}")

    async def feed(self, handle: FakeHandle, data: bytes) -> str:
        self._feeds += 1
        self.feeds.append(data)
        if self.fail_all_error is not None:
            raise self.fail_all_error
        failure = self.feed_failures.get(self._feeds)
        if failure is not None:
            raise failure
        if self.crash_on_feed == self._feeds:
            crash = FakeCrash(
                id=f"crash_{handle.handle_id}_{self._feeds}",
                handle_id=handle.handle_id,
                path=f"/fake/{handle.handle_id}/{self._feeds}.ips",
                payload=data,
            )
            self._crashes.setdefault(handle.handle_id, []).append(crash)
            if self.duplicate_crash:
                self._crashes[handle.handle_id].append(crash)
        return self.feed_results.get(self._feeds, "accepted")

    async def collect_crashes(self, handle: FakeHandle) -> list[FakeCrash]:
        self._collect_calls += 1
        failure = self.collect_failures.get(self._collect_calls)
        if failure is not None:
            raise failure
        return self._crashes.pop(handle.handle_id, [])

    async def thermal(self) -> Any:
        return self.thermal_value

    async def reset(self, handle: FakeHandle) -> None:
        self.resets += 1

    async def teardown(self) -> None:
        self.teardowns += 1


class TestDiscoveryHeif(unittest.TestCase):
    def test_RA_DISC_HEIF_001_gate_and_brands(self) -> None:
        data = heif_sample()
        gate = heif_gate(data)
        self.assertTrue(gate.passes)
        self.assertTrue(gate.has_ftyp_heif)
        self.assertTrue(gate.has_meta)
        self.assertEqual(gate.major_brand, b"heic")

        compatible_only = heif_sample(brand=b"xxxx", compatible=(b"mif1",))
        self.assertTrue(heif_gate(compatible_only).has_ftyp_heif)
        self.assertFalse(heif_gate(compatible_only).has_ftyp_heif is False)

        non_heif = heif_sample(brand=b"avif", compatible=(b"avis",))
        self.assertFalse(heif_gate(non_heif).passes)
        self.assertFalse(heif_gate(b"short").passes)
        self.assertFalse(is_heif_brand(b"heicx"))
        self.assertTrue(is_heif_brand(b"msf1"))

    def test_RA_DISC_HEIF_002_box_parser_edges(self) -> None:
        data = heif_sample()
        boxes = parse_boxes(data)
        self.assertEqual([box_item.type for box_item in boxes], [b"ftyp", b"meta"])
        self.assertEqual(boxes[0].payload_offset, 8)
        self.assertEqual(read_u32(data, 0), boxes[0].size)
        self.assertEqual(read_u64(b"\x00" * 8, 0), 0)

        extended_payload = b"payload"
        extended = (1).to_bytes(4, "big") + b"free" + (16).to_bytes(8, "big") + extended_payload
        parsed = parse_boxes(extended)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].header_size, 16)
        self.assertEqual(parsed[0].size, 16)

        self.assertEqual(parse_boxes(b""), [])
        self.assertEqual(parse_boxes(b"\x00" * 7), [])
        self.assertEqual(parse_boxes(b"\x00\x00\x00\x04ftyp"), [])
        self.assertEqual(parse_boxes(box(b"free", b"x") + b"\x00\x00"), [parse_boxes(box(b"free", b"x"))[0]])


class TestDiscoveryMutation(unittest.TestCase):
    def test_RA_DISC_MUT_001_rng_and_strategies(self) -> None:
        rng = DeterministicRng(123)
        first = rng.next_u64()
        self.assertEqual(first, DeterministicRng(123).next_u64())
        self.assertNotEqual(first, rng.next_u64())
        for _ in range(100):
            self.assertTrue(0 <= rng.randbelow(97) < 97)
        self.assertIn(rng.choice([1, 2, 3]), [1, 2, 3])
        self.assertEqual(len(rng.randbytes(19)), 19)
        with self.assertRaises(ValueError):
            rng.randbelow(0)
        with self.assertRaises(ValueError):
            rng.choice([])
        with self.assertRaises(ValueError):
            rng.randrange(2, 2)
        with self.assertRaises(ValueError):
            rng.randbytes(-1)

        seed = heif_sample() + b"A" * 64
        for strategy in MUTATION_STRATEGIES:
            mutated = mutate_bytes(seed, strategy, DeterministicRng(7), max_bytes=128)
            self.assertLessEqual(len(mutated), 128)
            self.assertIsInstance(mutated, bytes)
        self.assertEqual(mutate_bytes(b"", "bitflip", DeterministicRng(1), max_bytes=8), b"")
        self.assertLessEqual(len(mutate_bytes(b"", "extend", DeterministicRng(1), max_bytes=8)), 8)
        with self.assertRaises(FormatFail):
            mutate_bytes(seed, "not_a_strategy", DeterministicRng(1), max_bytes=128)

    def test_RA_DISC_MUT_002_engine_determinism_property(self) -> None:
        seeds = [heif_sample(), heif_sample(brand=b"mif1", compatible=(b"heic",)) + b"B" * 32]
        engine = MutationEngine(seeds, seed=42, max_input_bytes=96)
        self.assertEqual(engine.seed_count, 2)
        for index in range(80):
            first = engine.plan(index, "imageio_heif")
            second = engine.plan(index, "imageio_heif")
            self.assertEqual(first, second)
            self.assertEqual(first.digest, hashlib.sha256(first.data).hexdigest())
            self.assertLessEqual(len(first.data), 96)
            self.assertEqual(first.seed_index, index % 2)
            self.assertEqual(first.strategy, MUTATION_STRATEGIES[index % len(MUTATION_STRATEGIES)])
        self.assertEqual(engine.plan(15, "imageio_heif").strategy, "bitflip")

    def test_RA_DISC_MUT_003_engine_edges_and_corpus(self) -> None:
        with self.assertRaises(FormatFail):
            MutationEngine([], seed=1, max_input_bytes=16)
        self.assertEqual(MutationEngine([b"", b"x"], seed=1, max_input_bytes=16).seed_count, 1)
        with self.assertRaises(FormatFail):
            MutationEngine([b"", b""], seed=1, max_input_bytes=16)
        with self.assertRaises(FormatFail):
            MutationEngine([b"123456789"], seed=1, max_input_bytes=8)
        with self.assertRaises(ValueError):
            MutationEngine([b"x"], seed=1, max_input_bytes=16).plan(-1, "c")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "b.bin").write_bytes(b"BBBB")
            (root / "a.bin").write_bytes(b"AA")
            (root / "empty.bin").write_bytes(b"")
            (root / "ignored").mkdir()
            seeds = load_corpus([str(root)], max_input_bytes=3)
            self.assertEqual(seeds, [b"AA", b"BBB"])
            self.assertEqual(load_corpus([str(root / "a.bin")]), [b"AA"])
            with self.assertRaises(FormatFail):
                load_corpus([str(root / "missing")])

    def test_RA_DISC_MUT_004_mutation_edges_and_config_validation(self) -> None:
        long_seed = heif_sample() + b"A" * 200
        for strategy in MUTATION_STRATEGIES:
            mutated = mutate_bytes(long_seed, strategy, DeterministicRng(7), max_bytes=32)
            self.assertLessEqual(len(mutated), 32)

        self.assertEqual(mutate_bytes(b"", "byte_set", DeterministicRng(1), max_bytes=16), b"")
        self.assertEqual(mutate_bytes(b"x", "truncate", DeterministicRng(1), max_bytes=16), b"x")
        self.assertEqual(mutate_bytes(b"x" * 32, "extend", DeterministicRng(1), max_bytes=32), b"x" * 32)
        self.assertEqual(mutate_bytes(b"", "splice", DeterministicRng(1), max_bytes=8), b"")

        no_boxes = b"\x00\x00\x00\x04free"
        for strategy in ("box_size", "box_type", "arith"):
            with self.subTest(strategy=strategy):
                self.assertEqual(len(mutate_bytes(no_boxes, strategy, DeterministicRng(2), max_bytes=16)), 8)
        self.assertNotEqual(mutate_bytes(no_boxes, "dictionary", DeterministicRng(2), max_bytes=16), no_boxes)

        extended = (1).to_bytes(4, "big") + b"free" + (16).to_bytes(8, "big") + b"payload"
        self.assertLessEqual(len(mutate_bytes(extended, "box_size", DeterministicRng(3), max_bytes=64)), 64)
        meta_box = box(b"meta", b"x")
        self.assertEqual(len(mutate_bytes(meta_box, "brand", DeterministicRng(4), max_bytes=32)), len(meta_box))

        token_data = b"ftyp" * 80
        self.assertEqual(len(mutate_bytes(token_data, "dictionary", DeterministicRng(5), max_bytes=400)), len(token_data))
        self.assertEqual(len(mutate_bytes(b"\x00" * 16, "dictionary", DeterministicRng(5), max_bytes=16)), 16)
        for seed in range(200):
            mutate_bytes(b"zzzzftypzzzz", "dictionary", DeterministicRng(seed), max_bytes=32)

        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.bin"
            empty.write_bytes(b"")
            with self.assertRaises(FormatFail):
                load_corpus([str(empty)], max_input_bytes=16)

        invalid = {
            "campaign_id": "",
            "max_cases": 0,
            "max_input_bytes": 7,
            "state_checkpoint_every": 0,
            "thermal_check_every": 0,
            "max_cases_per_handle": 0,
            "max_consecutive_errors": 0,
            "time_budget_s": -1.0,
        }
        for field, value in invalid.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                CampaignConfig(**{field: value}).validate()


class DiscoveryStoreCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = await Ledger.open(self.root / "ledger.sqlite")
        self.store = LedgerDiscoveryStore(self.ledger)

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def make_state(self, campaign_id: str = "imageio_heif", updated_ms: int = 1000) -> CampaignState:
        return CampaignState(
            campaign_id=campaign_id,
            surface="imageio.heif",
            format="heif",
            status="running",
            config=CampaignConfig(campaign_id=campaign_id, max_cases=4).to_dict(),
            seed_count=1,
            cases_planned=4,
            next_case_index=1,
            created_ms=updated_ms - 1,
            updated_ms=updated_ms,
        )

    async def test_RA_DISC_STORE_001_state_roundtrip_and_latest(self) -> None:
        first = self.make_state(updated_ms=1000)
        second = self.make_state(updated_ms=1001)
        second.cases_fed = 3
        second.last_error = {"reason": "thermal", "thermal": "warm"}
        await self.store.save(first)
        await self.store.save(second)
        loaded = await self.store.load("imageio_heif")
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.cases_fed, 3)
        self.assertEqual(loaded.last_error, {"reason": "thermal", "thermal": "warm"})
        self.assertEqual(await self.store.list_ids(), ["imageio_heif"])
        self.assertIsNone(await self.store.load("other"))
        self.assertEqual(len(self.ledger.claims_by_type("discovery_state")), 2)

    async def test_RA_DISC_STORE_002_crash_dedup_and_claim_links(self) -> None:
        crash = FakeCrash(
            id="crash_1",
            handle_id="h1",
            path="/tmp/a.ips",
            payload=b"payload",
            metadata={"vm": "ra-macos-1"},
        )
        kwargs = {
            "campaign_id": "imageio_heif",
            "case_id": "imageio_heif-case-00000001",
            "crash": crash,
            "input_digest": "a" * 64,
            "strategy": "bitflip",
            "seed_index": 0,
            "case_index": 1,
            "created_ms": 1234,
        }
        first = await self.store.record_crash(**kwargs)
        second = await self.store.record_crash(**kwargs)
        self.assertIsInstance(first, CrashRecord)
        self.assertIsNotNone(first.claim_id)
        self.assertIsNone(second.claim_id)
        self.assertEqual(first.dedup_key, second.dedup_key)
        claim = self.ledger.claim_by_dedup(first.dedup_key)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim["type"], "discovery_crash")
        self.assertEqual(self.ledger.claim_artifact_count(str(claim["id"])), 1)
        value = json.loads(str(claim["value_json"]))
        self.assertEqual(value["crash_id"], "crash_1")
        self.assertEqual(value["payload_sha256"], hashlib.sha256(b"payload").hexdigest())
        self.assertEqual(value["path"], "/tmp/a.ips")

        different_path = FakeCrash(
            id="crash_2",
            handle_id="h2",
            path="/tmp/b.ips",
            payload=b"payload",
            metadata={"vm": "ra-macos-1"},
        )
        deduped = await self.store.record_crash(**{**kwargs, "crash": different_path})
        self.assertIsNone(deduped.claim_id)

        # Same crash class found by a different case/input/payload dedups too.
        other_case = FakeCrash(
            id="crash_3",
            handle_id="h3",
            path="/tmp/c.ips",
            payload=b"other",
            metadata={"vm": "ra-macos-2"},
        )
        cross_case = await self.store.record_crash(
            **{
                **kwargs,
                "crash": other_case,
                "case_id": "imageio_heif-case-00000099",
                "input_digest": "b" * 64,
                "strategy": "box_nest",
                "case_index": 99,
            }
        )
        self.assertIsNone(cross_case.claim_id)
        self.assertEqual(cross_case.dedup_key, first.dedup_key)
        self.assertEqual(len(self.ledger.claims_by_type("discovery_crash")), 1)

        # A different signal is a different crash class and records a new claim.
        segv = FakeCrash(
            id="crash_4",
            kind="macos_vm_crash",
            handle_id="h1",
            payload=b"SIGSEGV at 0xdeadbeef",
        )
        recorded = await self.store.record_crash(**{**kwargs, "crash": segv})
        self.assertIsNotNone(recorded.claim_id)
        self.assertNotEqual(recorded.dedup_key, first.dedup_key)
        value = json.loads(str(self.ledger.claim_by_dedup(recorded.dedup_key)["value_json"]))
        self.assertEqual(value["signal"], "SIGSEGV")
        self.assertEqual(value["category"], "native_crash")
        self.assertEqual(len(self.ledger.claims_by_type("discovery_crash")), 2)

        # Image format is part of the crash class signature.
        png_crash = FakeCrash(id="crash_5", kind="macos_vm_crash", payload=b"SIGSEGV")
        png_variant = await self.store.record_crash(
            **{**kwargs, "crash": png_crash, "image_format": "png"}
        )
        self.assertIsNotNone(png_variant.claim_id)
        self.assertEqual(len(self.ledger.claims_by_type("discovery_crash")), 3)

    async def test_RA_DISC_STORE_003_state_from_dict_edges(self) -> None:
        state = self.make_state()
        roundtrip = CampaignState.from_dict(state.to_dict())
        self.assertEqual(roundtrip.campaign_id, state.campaign_id)
        self.assertEqual(roundtrip.config, state.config)
        bad_config = state.to_dict()
        bad_config["config"] = []
        with self.assertRaises(ValueError):
            CampaignState.from_dict(bad_config)
        bad_error = state.to_dict()
        bad_error["last_error"] = "boom"
        with self.assertRaises(ValueError):
            CampaignState.from_dict(bad_error)

    async def test_RA_DISC_STORE_004_malformed_state_rows_are_ignored(self) -> None:
        await self.store.save(self.make_state(updated_ms=1000))
        for index, value_json in enumerate(("[]", "{}")):
            artifact = ArtifactInput(kind="discovery_state", data=value_json.encode(), ttl_class="run")
            await self.ledger.create_claim(
                ClaimInput(
                    claim_id=f"bad_state_{index}",
                    type="discovery_state",
                    value_json=value_json,
                    confidence=1.0,
                    dedup_key=f"bad_state_{index}",
                    created=1,
                    artifacts=(ClaimArtifactInput(artifact=artifact, role="state"),),
                )
            )
        loaded = await self.store.load("imageio_heif")
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.status, "running")
        self.assertEqual(await self.store.list_ids(), ["imageio_heif"])


class TestDiscoveryCampaign(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = await Ledger.open(self.root / "ledger.sqlite")
        self.store = LedgerDiscoveryStore(self.ledger)
        self.campaign = DiscoveryCampaign(self.store)

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def config(self, **overrides: Any) -> CampaignConfig:
        values: dict[str, Any] = {
            "campaign_id": "imageio_heif",
            "surface": "imageio.heif",
            "format": "heif",
            "harness_name": "imageio_heif_feed",
            "max_cases": 5,
            "max_input_bytes": 256,
            "state_checkpoint_every": 1,
            "thermal_check_every": 3,
            "max_cases_per_handle": 2,
            "max_consecutive_errors": 2,
        }
        values.update(overrides)
        return CampaignConfig(**values)

    async def test_RA_DISC_CAMP_001_completed_campaign_and_resume(self) -> None:
        profile = object()
        lane = FakeLane()
        result = await self.campaign.run(
            lane,
            profile,
            None,
            [heif_sample()],
            self.config(),
        )
        self.assertEqual(result.state.status, "completed")
        self.assertEqual(result.state.cases_fed, 5)
        self.assertEqual(result.state.feeds_accepted, 5)
        self.assertEqual(result.state.next_case_index, 5)
        self.assertEqual(len(result.cases), 5)
        self.assertEqual(lane.launches, 3)
        self.assertEqual(lane.resets, 2)
        self.assertEqual(lane.teardowns, 0)
        self.assertIs(lane.profile, profile)

        feeds_before_resume = list(lane.feeds)
        launches_before_resume = lane.launches
        again = await self.campaign.run(lane, profile, None, [heif_sample()], self.config())
        self.assertEqual(again.state.status, "completed")
        self.assertEqual(again.cases, [])
        self.assertEqual(again.crashes, [])
        self.assertEqual(lane.feeds, feeds_before_resume)
        self.assertEqual(lane.launches, launches_before_resume)

        loaded = await self.store.load("imageio_heif")
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.status, "completed")
        self.assertEqual(loaded.seed_count, 1)

    async def test_RA_DISC_CAMP_002_crash_recording_and_handle_cycle(self) -> None:
        lane = FakeLane(crash_on_feed=2)
        result = await self.campaign.run(
            lane,
            None,
            None,
            [heif_sample()],
            self.config(
                max_cases=3,
                max_cases_per_handle=10,
                thermal_check_every=100,
                state_checkpoint_every=3,
            ),
        )
        self.assertEqual(result.state.status, "completed")
        self.assertEqual(result.state.crashes_seen, 1)
        self.assertEqual(result.state.crashes_recorded, 1)
        self.assertEqual(result.state.crashes_deduped, 0)
        self.assertIsNotNone(result.state.last_crash_claim_id)
        self.assertEqual(len(result.crashes), 1)
        self.assertEqual(result.crashes[0].payload, result.cases[1].data)
        self.assertEqual(len(self.ledger.claims_by_type("discovery_crash")), 1)
        self.assertEqual(lane.launches, 2)
        self.assertEqual(lane.resets, 1)

    async def test_RA_DISC_CAMP_003_feed_errors_failure_injection(self) -> None:
        lane = FakeLane(fail_all_error=RuntimeError("feed boom"))
        with self.assertRaises(RuntimeError):
            await self.campaign.run(
                lane,
                None,
                None,
                [heif_sample()],
                self.config(max_cases=5, max_consecutive_errors=2),
            )
        loaded = await self.store.load("imageio_heif")
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.status, "failed")
        self.assertEqual(loaded.consecutive_errors, 2)
        self.assertEqual(loaded.cases_fed, 0)
        self.assertEqual(loaded.feeds_accepted, 0)
        self.assertEqual(loaded.last_error, {"type": "RuntimeError", "message": "feed boom", "code": None})

        fatal = FakeLane(fail_all_error=DeviceLost("device gone"))
        with self.assertRaises(DeviceLost):
            await self.campaign.run(
                fatal,
                None,
                None,
                [heif_sample()],
                self.config(campaign_id="imageio_heif_fatal", max_cases=5),
            )
        fatal_state = await self.store.load("imageio_heif_fatal")
        self.assertIsNotNone(fatal_state)
        assert fatal_state is not None
        self.assertEqual(fatal_state.status, "failed")
        self.assertEqual(fatal_state.consecutive_errors, 1)

    async def test_RA_DISC_CAMP_004_crash_ref_exception_counts_as_crash(self) -> None:
        crash = FakeCrash(id="hang_crash", payload=b"hang", handle_id="h1")
        err = RuntimeError("hang")
        err.crash_ref = crash  # type: ignore[attr-defined]
        lane = FakeLane(feed_failures={1: err})
        result = await self.campaign.run(
            lane,
            None,
            None,
            [heif_sample()],
            self.config(max_cases=2, max_cases_per_handle=10, thermal_check_every=100),
        )
        self.assertEqual(result.state.status, "completed")
        self.assertEqual(result.state.cases_fed, 2)
        self.assertEqual(result.state.crashes_recorded, 1)
        self.assertEqual(result.state.feeds_accepted, 1)
        self.assertEqual(len(result.crashes), 1)
        self.assertEqual(result.crashes[0].id, "hang_crash")
        self.assertEqual(lane.resets, 1)

    async def test_RA_DISC_CAMP_005_thermal_budget_and_validation(self) -> None:
        thermal_lane = FakeLane(thermal_value="warm")
        paused = await self.campaign.run(
            thermal_lane,
            None,
            None,
            [heif_sample()],
            self.config(max_cases=5, thermal_check_every=2, max_cases_per_handle=10),
        )
        self.assertEqual(paused.state.status, "paused")
        self.assertEqual(paused.state.cases_fed, 2)
        self.assertEqual(paused.state.last_error, {"reason": "thermal", "thermal": "warm"})

        clock = iter([0.0, 1.0, 2.0, 3.0, 4.0])
        budgeted = DiscoveryCampaign(self.store, monotonic=lambda: next(clock))
        budget_lane = FakeLane()
        budgeted_result = await budgeted.run(
            budget_lane,
            None,
            None,
            [heif_sample()],
            self.config(campaign_id="imageio_heif_budget", max_cases=5, time_budget_s=0.0),
        )
        self.assertEqual(budgeted_result.state.status, "paused")
        self.assertEqual(budgeted_result.state.cases_fed, 0)
        self.assertEqual(budget_lane.feeds, [])

        with self.assertRaises(FormatFail):
            await self.campaign.run(
                FakeLane(),
                None,
                None,
                [heif_sample()],
                self.config(max_cases=0),
            )
        with self.assertRaises(FormatFail):
            await self.campaign.run(
                FakeLane(),
                None,
                None,
                [],
                self.config(campaign_id="imageio_heif_empty", max_cases=1),
            )

        mismatch = await self.store.load("imageio_heif")
        self.assertIsNotNone(mismatch)
        assert mismatch is not None
        with self.assertRaises(FormatFail):
            await self.campaign.run(
                FakeLane(),
                None,
                None,
                [heif_sample()],
                self.config(max_cases=6),
            )

    async def test_RA_DISC_CAMP_006_provision_gate_and_teardown(self) -> None:
        not_ready = FakeLane(ready=False)
        profile = object()
        with self.assertRaises(NotProvisioned):
            await self.campaign.run(
                not_ready,
                profile,
                None,
                [heif_sample()],
                self.config(campaign_id="imageio_heif_not_ready", max_cases=1),
            )
        self.assertEqual(not_ready.profile, profile)
        state = await self.store.load("imageio_heif_not_ready")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(state.status, "failed")
        self.assertEqual(state.last_error["code"], "NOT_PROVISIONED")

    async def test_RA_DISC_CAMP_007_feed_result_counts(self) -> None:
        lane = FakeLane(feed_results={1: "saturated", 2: "rejected", 3: "rejected", 4: "accepted"})
        result = await self.campaign.run(
            lane,
            None,
            None,
            [heif_sample()],
            self.config(max_cases=4, max_cases_per_handle=10, thermal_check_every=100),
        )
        self.assertEqual(result.state.status, "completed")
        self.assertEqual(result.state.feeds_saturated, 1)
        self.assertEqual(result.state.feeds_rejected, 2)
        self.assertEqual(result.state.feeds_accepted, 1)
        self.assertEqual(result.state.cases_fed, 4)

    async def test_RA_DISC_CAMP_008_collect_failure_recovery(self) -> None:
        lane = FakeLane(collect_failures={1: RuntimeError("collect boom")})
        result = await self.campaign.run(
            lane,
            None,
            None,
            [heif_sample()],
            self.config(max_cases=2, max_cases_per_handle=10, thermal_check_every=100),
        )
        self.assertEqual(result.state.status, "completed")
        self.assertEqual(result.state.cases_fed, 1)
        self.assertEqual(result.state.feeds_accepted, 2)
        self.assertEqual(result.state.consecutive_errors, 0)
        self.assertEqual(result.state.last_error, None)

    async def test_RA_DISC_CAMP_009_duplicate_crash_dedup(self) -> None:
        lane = FakeLane(crash_on_feed=1, duplicate_crash=True)
        result = await self.campaign.run(
            lane,
            None,
            None,
            [heif_sample()],
            self.config(max_cases=1, max_cases_per_handle=10, thermal_check_every=100),
        )
        self.assertEqual(result.state.crashes_seen, 2)
        self.assertEqual(result.state.crashes_recorded, 1)
        self.assertEqual(result.state.crashes_deduped, 1)
        self.assertEqual(len(result.crashes), 2)
        self.assertEqual(len(self.ledger.claims_by_type("discovery_crash")), 1)

    async def test_RA_DISC_CAMP_010_invalid_crash_ref_and_thermal_object(self) -> None:
        bad = RuntimeError("bad ref")
        bad.crash_ref = object()  # type: ignore[attr-defined]
        with self.assertRaises(RuntimeError):
            await self.campaign.run(
                FakeLane(feed_failures={1: bad}),
                None,
                None,
                [heif_sample()],
                self.config(
                    campaign_id="imageio_heif_badref",
                    max_cases=1,
                    max_consecutive_errors=1,
                    max_cases_per_handle=10,
                    thermal_check_every=100,
                ),
            )
        bad_state = await self.store.load("imageio_heif_badref")
        self.assertIsNotNone(bad_state)
        assert bad_state is not None
        self.assertEqual(bad_state.status, "failed")
        self.assertEqual(bad_state.crashes_seen, 0)

        thermal_lane = FakeLane(thermal_value=SimpleNamespace(value=1))
        thermal_result = await self.campaign.run(
            thermal_lane,
            None,
            None,
            [heif_sample()],
            self.config(
                campaign_id="imageio_heif_thermal_obj",
                max_cases=2,
                thermal_check_every=1,
                max_cases_per_handle=10,
                state_checkpoint_every=1,
            ),
        )
        self.assertEqual(thermal_result.state.status, "paused")
        self.assertEqual(thermal_result.state.cases_fed, 1)
        self.assertEqual(thermal_result.state.last_error["thermal"], "1")

    async def test_RA_DISC_CAMP_011_mixed_format_campaign_replay(self) -> None:
        seeds = [build_image_seed(image_format) for image_format in IMAGE_FORMATS]
        config = self.config(campaign_id="imageio_mixed", max_cases=12)
        lane = FakeLane()
        first = await self.campaign.run(lane, None, None, seeds, config)
        self.assertEqual(first.state.status, "completed")
        self.assertEqual(first.state.cases_fed, 12)
        self.assertEqual({case.image_format for case in first.cases}, set(IMAGE_FORMATS))

        # Replaying the same seed in a fresh ledger reproduces identical feeds.
        other_ledger = await Ledger.open(self.root / "replay" / "ledger.sqlite")
        try:
            other_store = LedgerDiscoveryStore(other_ledger)
            other_campaign = DiscoveryCampaign(other_store)
            replay_lane = FakeLane()
            second = await other_campaign.run(replay_lane, None, None, seeds, config)
            self.assertEqual(second.state.status, "completed")
            self.assertEqual([case.digest for case in first.cases], [case.digest for case in second.cases])
            self.assertEqual(lane.feeds, replay_lane.feeds)
        finally:
            await other_ledger.close()


class TestDiscoveryMacOSGate(unittest.TestCase):
    def test_RA_DISC_MAC_001_platform_gate_and_harness_ref(self) -> None:
        self.assertFalse(macos_available(platform="linux"))
        self.assertTrue(macos_available(platform="darwin"))
        require_macos("test", platform="darwin")
        with self.assertRaises(MacOSUnavailable) as raised:
            require_macos("test", platform="linux")
        self.assertEqual(raised.exception.code, "MACOS_UNAVAILABLE")
        self.assertFalse(raised.exception.retryable)

        harness = imageio_heif_harness_ref(Path("/tmp/imageio_heif_feed"), name="feed")
        self.assertIsInstance(harness, DiscoveryHarnessRef)
        self.assertEqual(harness.argv, ["/tmp/imageio_heif_feed"])
        self.assertEqual(harness.metadata["surface"], "imageio.heif")
        self.assertEqual(harness.metadata["feed_argv"], ["/tmp/imageio_heif_feed"])

        checklist = macos_verification_checklist()
        self.assertGreater(len(checklist), 0)
        self.assertTrue(any("tart" in item for item in checklist))
        self.assertTrue(imageio_heif_feed_source().name == "feed.cc")
        manifest = json.loads(imageio_heif_feed_manifest().read_text(encoding="utf-8"))
        self.assertEqual(manifest["id"], "imageio_heif_feed")
        self.assertTrue(manifest["stdin_feed"])
        self.assertIn("LLVMFuzzerTestOneInput.cc", manifest["source"])

    def test_RA_DISC_MAC_002_multiformat_harness_metadata_and_linux_gate(self) -> None:
        harness = imageio_heif_harness_ref(Path("/tmp/imageio_heif_feed"))
        self.assertEqual(harness.metadata["format"], "heif")
        self.assertEqual(harness.metadata["image_formats"], list(IMAGE_FORMATS))
        checklist = macos_verification_checklist()
        self.assertTrue(any("PNG/JPEG/GIF/BMP/TIFF/WebP" in item for item in checklist))
        # Linux CI imports and gates safely: discovery never touches ImageIO.
        self.assertFalse(macos_available(platform="linux"))
        with self.assertRaises(MacOSUnavailable):
            require_macos("imageio_heif", platform="linux")


class TestDiscoveryHeifTree(unittest.TestCase):
    def test_RA_DISC_TREE_001_nested_containers(self) -> None:
        data = rich_heif_sample()
        tree = parse_box_tree(data)
        self.assertEqual([node.box.type for node in tree], [b"ftyp", b"meta"])
        nodes = list(iter_box_nodes(tree))
        self.assertEqual(len(nodes), 5)
        self.assertEqual([node.depth for node in nodes], [0, 0, 1, 2, 3])
        ispe_nodes = find_box_nodes(tree, b"ispe")
        self.assertEqual(len(ispe_nodes), 1)
        self.assertEqual(ispe_nodes[0].box.payload_size, 12)
        self.assertLessEqual(ispe_nodes[0].box.offset + ispe_nodes[0].box.size, len(data))

    def test_RA_DISC_TREE_002_malformed_and_bounds(self) -> None:
        # A child with an absurd declared size stops that container only.
        bad_child = (0xFFFFFFF0).to_bytes(4, "big") + b"free" + b"x" * 4
        ftyp = box(b"ftyp", b"heic" + (0).to_bytes(4, "big") + b"mif1")
        meta = box(b"meta", b"\x00\x00\x00\x00" + bad_child)
        tail = box(b"free", b"tail")
        tree = parse_box_tree(ftyp + meta + tail)
        top_types = [node.box.type for node in tree]
        self.assertIn(b"meta", top_types)
        self.assertIn(b"free", top_types)
        meta_node = tree[top_types.index(b"meta")]
        self.assertEqual(meta_node.children, ())

        # Size zero extends to end of file.
        zero_box = b"\x00\x00\x00\x00" + b"free"
        nodes = list(iter_box_nodes(parse_box_tree(zero_box)))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].box.size, len(zero_box))

        # Extended 64-bit sizes are honored.
        ext = (1).to_bytes(4, "big") + b"free" + (16).to_bytes(8, "big") + b"payload"
        nodes = list(iter_box_nodes(parse_box_tree(ext)))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].box.size, 16)

        # uuid boxes skip the 16-byte usertype before payload.
        uuid_box = (28).to_bytes(4, "big") + b"uuid" + b"u" * 16 + b"data"
        nodes = list(iter_box_nodes(parse_box_tree(uuid_box)))
        self.assertEqual(nodes[0].box.payload_offset, 24)
        self.assertEqual(nodes[0].box.payload_size, 4)

        # Empty and short inputs parse to nothing.
        self.assertEqual(parse_box_tree(b""), [])
        self.assertEqual(parse_box_tree(b"\x00" * 7), [])
        self.assertEqual(parse_box_tree(rich_heif_sample(), max_depth=0), [])

    def test_RA_DISC_TREE_003_parse_budget_and_depth_cap(self) -> None:
        data = rich_heif_sample()
        nodes = list(iter_box_nodes(parse_box_tree(data, max_boxes=2)))
        self.assertLessEqual(len(nodes), 2)

        inner = box(b"free", b"x")
        for _ in range(12):
            inner = box(b"grpl", inner)
        data = box(b"ftyp", b"heic" + (0).to_bytes(4, "big") + b"mif1") + inner
        nodes = list(iter_box_nodes(parse_box_tree(data)))
        self.assertEqual(max(node.depth for node in nodes), 8)

    def test_RA_DISC_TREE_004_box_edge_cases(self) -> None:
        # Extended-size header truncated at end of input.
        self.assertEqual(parse_boxes(b"\x00\x00\x00\x01ftypab"), [])
        # Same truncation inside a container child range.
        child = (1).to_bytes(4, "big") + b"free" + b"x" * 4
        meta = box(b"meta", b"\x00\x00\x00\x00" + child)
        nodes = list(iter_box_nodes(parse_box_tree(meta)))
        self.assertEqual([node.box.type for node in nodes], [b"meta"])
        # A meta box with a too-small FullBox payload has no child range.
        tiny_meta = box(b"meta", b"\x00\x00\x00")
        nodes = list(iter_box_nodes(parse_box_tree(tiny_meta)))
        self.assertEqual([node.box.type for node in nodes], [b"meta"])
        self.assertEqual(nodes[0].children, ())
        # iinf version 0 uses a 16-bit entry count before children.
        child_box = box(b"free", b"x")
        iinf_v0 = box(b"iinf", b"\x00\x00\x00\x00" + (1).to_bytes(2, "big") + child_box)
        nodes = list(iter_box_nodes(parse_box_tree(iinf_v0)))
        self.assertEqual([node.box.type for node in nodes], [b"iinf", b"free"])
        # iinf version 2 uses a 32-bit entry count before children.
        iinf_v2 = box(b"iinf", b"\x02\x00\x00\x00" + (1).to_bytes(4, "big") + child_box)
        nodes = list(iter_box_nodes(parse_box_tree(iinf_v2)))
        self.assertEqual([node.box.type for node in nodes], [b"iinf", b"free"])
        # A truncated iinf entry count yields no children.
        iinf_trunc = box(b"iinf", b"\x00\x00\x00\x00" + b"\x00")
        nodes = list(iter_box_nodes(parse_box_tree(iinf_trunc)))
        self.assertEqual([node.box.type for node in nodes], [b"iinf"])
        # The gate tolerates a tiny ftyp payload.
        gate = heif_gate(box(b"ftyp", b"heic") + box(b"meta", b"\x00\x00\x00\x00"))
        self.assertFalse(gate.has_ftyp_heif)
        self.assertTrue(gate.has_meta)


class TestDiscoveryImages(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.seeds = {image_format: build_image_seed(image_format) for image_format in IMAGE_FORMATS}

    def test_RA_DISC_IMG_001_detection_and_gate(self) -> None:
        for image_format, data in self.seeds.items():
            with self.subTest(image_format=image_format):
                self.assertEqual(detect_image_format(data), image_format)
                gate = image_gate(data)
                self.assertTrue(gate.passes)
                self.assertEqual(gate.image_format, image_format)
        self.assertIsNone(detect_image_format(b""))
        self.assertIsNone(detect_image_format(b"\x00" * 64))
        self.assertEqual(detect_image_format(PNG_SIGNATURE), "png")
        self.assertEqual(image_gate(b"").image_format, None)

        # A bare HEIF ftyp box is detected but fails the full HEIF gate.
        ftyp_only = box(b"ftyp", b"heic" + (0).to_bytes(4, "big") + b"mif1")
        self.assertEqual(detect_image_format(ftyp_only), "heif")
        gate = image_gate(ftyp_only)
        self.assertFalse(gate.passes)
        self.assertEqual(gate.detail, "heif_gate_failed")

    def test_RA_DISC_IMG_002_seed_builders_deterministic(self) -> None:
        for image_format in IMAGE_FORMATS:
            with self.subTest(image_format=image_format):
                self.assertEqual(build_image_seed(image_format), self.seeds[image_format])
        self.assertEqual(set(default_imageio_seeds()), set(IMAGE_FORMATS))
        with self.assertRaises(FormatFail):
            build_image_seed("bmp2")
        with self.assertRaises(ValueError):
            build_image_seed("png", width=0)
        with self.assertRaises(ValueError):
            build_image_seed("png", height=4097)
        with self.assertRaises(ValueError):
            build_image_seed("jpeg", width=-1)
        with self.assertRaises(ValueError):
            build_image_seed("bmp", height=0)
        with self.assertRaises(ValueError):
            build_image_seed("tiff", width=5000)

    def test_RA_DISC_IMG_003_mutators_deterministic_and_bounded(self) -> None:
        for image_format, seed_data in self.seeds.items():
            for strategy in MUTATION_STRATEGIES:
                for rng_seed in (0, 1, 7):
                    with self.subTest(image_format=image_format, strategy=strategy, rng_seed=rng_seed):
                        first = mutate_bytes(seed_data, strategy, DeterministicRng(rng_seed), max_bytes=512)
                        second = mutate_bytes(seed_data, strategy, DeterministicRng(rng_seed), max_bytes=512)
                        self.assertEqual(first, second)
                        self.assertLessEqual(len(first), 512)
                        # A second mutation generation stays bounded too.
                        again = mutate_bytes(
                            first, "image_structure", DeterministicRng(rng_seed + 1), max_bytes=512
                        )
                        self.assertLessEqual(len(again), 512)

    def test_RA_DISC_IMG_004_malformed_truncated_huge_inputs(self) -> None:
        strategies = (
            "box_size",
            "box_type",
            "box_field",
            "box_insert",
            "box_delete",
            "box_nest",
            "image_structure",
            "bitflip",
        )
        for image_format, seed_data in self.seeds.items():
            cuts = sorted({0, 1, 2, 7, 8, 9, 12, 13, 20} | set(range(0, min(len(seed_data), 33), 4)))
            for cut in cuts:
                prefix = seed_data[:cut]
                for strategy in strategies:
                    with self.subTest(image_format=image_format, cut=cut, strategy=strategy):
                        out = mutate_bytes(prefix, strategy, DeterministicRng(cut + 1), max_bytes=64)
                        self.assertIsInstance(out, bytes)
                        self.assertLessEqual(len(out), 64)

        # Random garbage never crashes the engine.
        rng = DeterministicRng(0xC0FFEE)
        for index in range(40):
            junk = rng.randbytes(rng.randrange(0, 200))
            for strategy in MUTATION_STRATEGIES:
                out = mutate_bytes(junk, strategy, DeterministicRng(index), max_bytes=128)
                self.assertLessEqual(len(out), 128)

        # Absurd declared sizes inside otherwise valid headers stay bounded.
        blobs = (
            PNG_SIGNATURE + (0xFFFFFFFF).to_bytes(4, "big") + b"IHDR" + b"x" * 16,
            b"\xff\xd8\xff\xe0" + (0xFFFF).to_bytes(2, "big") + b"JFIF\x00" + b"y" * 8,
            b"BM" + b"\xff" * 30,
            b"II*\x00" + b"\xff" * 60,
            b"RIFF\xff\xff\xff\xffWEBP" + b"z" * 20,
        )
        for blob in blobs:
            for strategy in MUTATION_STRATEGIES:
                with self.subTest(blob=blob[:8], strategy=strategy):
                    out = mutate_bytes(blob, strategy, DeterministicRng(5), max_bytes=96)
                    self.assertLessEqual(len(out), 96)

    def test_RA_DISC_IMG_005_mutation_sweep_bounds(self) -> None:
        # A broad deterministic sweep exercises the random branches of every
        # per-format mutator without ever exceeding the byte budget.
        for image_format, seed_data in self.seeds.items():
            for strategy in MUTATION_STRATEGIES:
                for rng_seed in range(20):
                    with self.subTest(image_format=image_format, strategy=strategy, rng_seed=rng_seed):
                        out = mutate_bytes(
                            seed_data,
                            strategy,
                            DeterministicRng(1000 + rng_seed),
                            max_bytes=1024,
                        )
                        self.assertIsInstance(out, bytes)
                        self.assertLessEqual(len(out), 1024)

    def test_RA_DISC_IMG_006_webp_vp8x_field_mutation(self) -> None:
        payload = b"\x00" * 10
        chunk = b"VP8X" + len(payload).to_bytes(4, "little") + payload
        riff_payload = b"WEBP" + chunk
        seed_data = b"RIFF" + len(riff_payload).to_bytes(4, "little") + riff_payload
        self.assertEqual(detect_image_format(seed_data), "webp")
        outputs = {
            mutate_bytes(seed_data, "box_field", DeterministicRng(seed), max_bytes=256)
            for seed in range(12)
        }
        self.assertGreater(len(outputs), 1)
        for out in outputs:
            self.assertLessEqual(len(out), 256)

    def test_RA_DISC_IMG_007_bounded_and_fallback_edges(self) -> None:
        # A negative budget clamps to empty output.
        out = mutate_image_structure(
            build_image_seed("png"), "png", "box_size", DeterministicRng(0), max_bytes=-3
        )
        self.assertEqual(out, b"")
        # Empty input falls back to empty output.
        self.assertEqual(
            mutate_image_structure(b"", "png", "box_size", DeterministicRng(0), max_bytes=8), b""
        )
        # Unknown formats are only bounded, never parsed.
        self.assertEqual(
            mutate_image_structure(b"not-an-image", None, "bitflip", DeterministicRng(0), max_bytes=8),
            b"not-an-i",
        )

    def test_RA_DISC_IMG_008_direct_dispatch_edges(self) -> None:
        # The meta strategy recurses into a concrete structure op per format.
        # Unknown strategies hit each format's bounded fallback.
        for image_format in IMAGE_FORMATS:
            if image_format == "heif":
                continue
            seed_data = build_image_seed(image_format)
            for strategy in ("image_structure", "bitflip", "unknown_op"):
                with self.subTest(image_format=image_format, strategy=strategy):
                    out = mutate_image_structure(
                        seed_data, image_format, strategy, DeterministicRng(3), max_bytes=1024
                    )
                    self.assertIsInstance(out, bytes)
                    self.assertLessEqual(len(out), 1024)


class TestDiscoveryStructureMutation(unittest.TestCase):
    def test_RA_DISC_STRUCT_001_heif_structure_ops(self) -> None:
        seed_data = rich_heif_sample()
        for op in STRUCTURE_OPS + ("image_structure",):
            with self.subTest(op=op):
                outputs = [
                    mutate_bytes(seed_data, op, DeterministicRng(rng_seed), max_bytes=2048)
                    for rng_seed in range(6)
                ]
                for out in outputs:
                    self.assertIsInstance(out, bytes)
                    self.assertLessEqual(len(out), 2048)
                self.assertTrue(any(out != seed_data for out in outputs), op)

    def test_RA_DISC_STRUCT_002_raster_structure_ops(self) -> None:
        for image_format in IMAGE_FORMATS:
            if image_format == "heif":
                continue
            seed_data = build_image_seed(image_format)
            for op in STRUCTURE_OPS:
                with self.subTest(image_format=image_format, op=op):
                    outputs = [
                        mutate_bytes(seed_data, op, DeterministicRng(rng_seed), max_bytes=2048)
                        for rng_seed in range(4)
                    ]
                    for out in outputs:
                        self.assertIsInstance(out, bytes)
                        self.assertLessEqual(len(out), 2048)

    def test_RA_DISC_STRUCT_003_engine_format_attribution_and_replay(self) -> None:
        seeds = [build_image_seed(image_format) for image_format in IMAGE_FORMATS]
        engine = MutationEngine(seeds, seed=1234, max_input_bytes=4096)
        replay = MutationEngine(seeds, seed=1234, max_input_bytes=4096)
        for index in range(140):
            case = engine.plan(index, "mixed")
            self.assertLessEqual(len(case.data), 4096)
            self.assertEqual(case.image_format, IMAGE_FORMATS[index % len(IMAGE_FORMATS)])
            self.assertEqual(case, replay.plan(index, "mixed"))


class TestDiscoveryCorpusHardening(unittest.TestCase):
    def test_RA_DISC_CORPUS_001_recursive_dedup_and_caps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "c").mkdir()
            (root / "empty").mkdir()
            (root / "a" / "x.bin").write_bytes(b"AA")
            (root / "b" / "y.bin").write_bytes(b"AA")
            (root / "c" / "z.bin").write_bytes(b"BBBB")
            (root / "big.bin").write_bytes(b"K" * 100)
            (root / "empty" / "e.bin").write_bytes(b"")

            seeds = load_corpus([str(root)], max_input_bytes=4)
            self.assertEqual(seeds, [b"AA", b"KKKK", b"BBBB"])
            # Deterministic across repeated loads.
            self.assertEqual(load_corpus([str(root)], max_input_bytes=4), seeds)
            # Nested directory and mixed file/dir paths work.
            self.assertEqual(load_corpus([str(root / "a")], max_input_bytes=4), [b"AA"])
            both = load_corpus([str(root / "a" / "x.bin"), str(root / "c")], max_input_bytes=4)
            self.assertEqual(both, [b"AA", b"BBBB"])

    def test_RA_DISC_CORPUS_002_failures_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sub").mkdir()
            with self.assertRaises(FormatFail):
                load_corpus([str(root / "sub")])
            (root / "only_empty.bin").write_bytes(b"")
            with self.assertRaises(FormatFail):
                load_corpus([str(root / "only_empty.bin")])

            huge = root / "huge.bin"
            huge.write_bytes(b"H" * (2 * 1024 * 1024))
            seeds = load_corpus([str(huge)], max_input_bytes=16)
            self.assertEqual(seeds, [b"H" * 16])

            # An unreadable file surfaces as FormatFail, not a raw OSError.
            bad = root / "bad.bin"
            bad.write_bytes(b"data")
            bad.chmod(0)
            try:
                with self.assertRaises(FormatFail):
                    load_corpus([str(bad)])
            finally:
                bad.chmod(0o644)


class TestDiscoveryCrashClassification(unittest.TestCase):
    def test_RA_DISC_SIG_001_categories_signals_and_bounds(self) -> None:
        native = classify_crash(
            FakeCrash(id="c1", kind="macos_vm_crash", path="/tmp/x.ips", metadata={"vm": "v"})
        )
        self.assertEqual(native.category, "native_crash")
        self.assertIsNone(native.signal)

        segv = classify_crash(FakeCrash(id="c2", kind="ios_crash", payload=b"terminating due to SIGSEGV"))
        self.assertEqual(segv.signal, "SIGSEGV")
        self.assertEqual(segv.category, "native_crash")

        exc = classify_crash(FakeCrash(id="c3", kind="macos_vm_crash", payload=b"NSInvalidArgumentException"))
        self.assertEqual(exc.exception, "NSInvalidArgumentException")
        self.assertEqual(exc.category, "native_crash")

        timeout = classify_crash(FakeCrash(id="c4", kind="hang", metadata={"feed_timeout_s": 30}))
        self.assertEqual(timeout.category, "timeout")
        meta_timeout = classify_crash(FakeCrash(id="c5", metadata={"timeout_s": 3}))
        self.assertEqual(meta_timeout.category, "timeout")

        unknown = classify_crash(FakeCrash(id="c6"))
        self.assertEqual(unknown.category, "unknown")
        self.assertEqual(unknown.kind, "fake")
        self.assertEqual(unknown.context, "app")

        fmt = classify_crash(FakeCrash(id="c7"), image_format="png")
        self.assertEqual(fmt.image_format, "png")
        signature = fmt.signature("camp")
        self.assertEqual(
            set(signature),
            {"campaign_id", "kind", "context", "category", "signal", "exception", "image_format"},
        )
        self.assertEqual(signature["campaign_id"], "camp")

        # Evidence scans are bounded: tokens past the cap are ignored.
        far = FakeCrash(id="c8", payload=b"x" * 70000 + b"SIGSEGV")
        self.assertIsNone(classify_crash(far).signal)
        near = FakeCrash(id="c9", payload=b"x" * 100 + b"SIGBUS")
        self.assertEqual(classify_crash(near).signal, "SIGBUS")
