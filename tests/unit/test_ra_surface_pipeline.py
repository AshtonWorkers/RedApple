"""Pipeline tests: scan_surface_inputs and compile_and_rank end to end."""

import asyncio

from ra.srf.dyld import MachOImage
from ra.surface.expand import expand_surface
from ra.surface.pipeline import compile_and_rank, scan_surface_inputs
from ra.surface.store import InMemorySurfaceStore, LedgerSurfaceStore

PROFILE_LITERAL = """
(version 1)
(deny default)
(allow mach-lookup (global-name "com.apple.runningboardd"))
(allow network-outbound)
(allow xpc-message-send)
"""

PROFILE_REGEX = """
(version 1)
(deny default)
(allow mach-lookup (global-name-regex #"^com\\.apple\\.demo\\..*"))
(allow network-inbound)
"""

XPC_STRINGS = [
    "xpc_connection_create_mach_service",
    "com.apple.runningboardd",
    "com.apple.demo.alpha",
    "routine",
    "identifier",
    "authToken",
    "payloadData",
    "endpoint",
    "isEnabled",
    "createdAt",
]


class FakeCache:
    def __init__(self, strings_by_path):
        self.images = [
            MachOImage(address=0, path=path, filetype=6, flags=0, sections=())
            for path in sorted(strings_by_path)
        ]
        self._strings = strings_by_path
        self.path = "fake-dyld-cache"

    async def image_strings(self, image, names=None):
        return list(self._strings.get(image.path, []))


def _strings():
    path = "/System/Library/PrivateFrameworks/RunningBoard.framework/Versions/A/RunningBoard"
    return {
        path: XPC_STRINGS + [PROFILE_LITERAL, PROFILE_REGEX],
        "/usr/lib/system/libxpc.dylib": ["com.apple.demo.beta", "xpc_connection_create"],
    }


def test_RA_SFC_pipeline_scan_inputs():
    inputs = asyncio.run(scan_surface_inputs(FakeCache(_strings()), ring_node="ring"))
    assert inputs.ring_node == "ring"
    assert len(inputs.profiles) == 2
    assert "com.apple.demo.alpha" in inputs.service_names
    assert "com.apple.demo.beta" in inputs.service_names
    assert inputs.shapes  # XPC markers present in RunningBoard strings


def test_RA_SFC_pipeline_compile_and_rank_persists_ranked_targets():
    async def body() -> None:
        store = InMemorySurfaceStore()
        result = await compile_and_rank(FakeCache(_strings()), store, ring_node="ring")
        assert result.persisted is True
        assert result.rows_written == len(result.target_list.targets)
        assert result.rows_written > 0
        names = {t.name for t in result.target_list.targets}
        assert "com.apple.runningboardd" in names
        # regex-expanded targets from the harvested corpus
        assert "com.apple.demo.alpha" in names
        assert "com.apple.demo.beta" in names
        # deterministic order and ranks
        ranks = [t.rank for t in result.target_list.targets]
        assert ranks == list(range(1, len(ranks) + 1))
        # persisted rows round-trip through the store
        rows = store.read_targets("ring")
        assert [r["id"] for r in rows] == [t.id for t in result.target_list.targets]

    asyncio.run(body())


def test_RA_SFC_pipeline_is_deterministic_across_runs():
    async def body() -> None:
        first = await compile_and_rank(FakeCache(_strings()), InMemorySurfaceStore(), ring_node="ring")
        second = await compile_and_rank(FakeCache(_strings()), InMemorySurfaceStore(), ring_node="ring")
        assert first.target_list.sha256 == second.target_list.sha256
        assert first.target_list.to_dict() == second.target_list.to_dict()

    asyncio.run(body())


def test_RA_SFC_pipeline_empty_cache_is_failure_injection_safe():
    async def body() -> None:
        store = InMemorySurfaceStore()
        result = await compile_and_rank(FakeCache({}), store, ring_node="empty")
        assert result.rows_written == 0
        assert store.read_targets("empty") == []

    asyncio.run(body())


def test_RA_SFC_pipeline_image_limit_bounds_scan():
    async def body() -> None:
        inputs = await scan_surface_inputs(FakeCache(_strings()), ring_node="ring", image_limit=1)
        # only the first image (RunningBoard) is scanned
        assert "com.apple.demo.beta" not in inputs.service_names
        assert "com.apple.demo.alpha" in inputs.service_names

    asyncio.run(body())


def test_RA_SFC_pipeline_path_hint_triggers_shape_extraction():
    # image path looks like a service but strings carry no XPC markers:
    # extract_xpc_shape runs and returns None; _path_hint branch is covered.
    strings = {
        "/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices": [
            "plain-string-one",
            "plain-string-two",
        ]
    }
    inputs = asyncio.run(scan_surface_inputs(FakeCache(strings), ring_node="ring"))
    assert inputs.shapes == ()


def test_RA_SFC_pipeline_ledger_store_constructor(tmp_path):
    from ra.ledger import Ledger
    from ra.srf.models import ReachRecord
    from ra.surface.models import ExpandedTarget
    from ra.surface.pipeline import ledger_store
    from ra.surface.rank import rank_targets

    async def body() -> None:
        ledger = await Ledger.open(tmp_path / "ledger.sqlite")
        store = ledger_store(ledger)
        assert isinstance(store, LedgerSurfaceStore)
        target = ExpandedTarget(
            ring_node="ring",
            name="com.apple.via.ledger",
            reach_from=(ReachRecord(source="image:/x", hops=1),),
            base_weight=1.0,
            privilege_delta=1,
            parser_complexity=0.5,
        )
        await store.replace_targets(rank_targets([target], ring_node="ring"))
        assert [r["name"] for r in store.read_targets("ring")] == ["com.apple.via.ledger"]
        await ledger.close()

    asyncio.run(body())


def test_RA_SFC_pipeline_expand_surface_direct_with_scan_inputs():
    inputs = asyncio.run(scan_surface_inputs(FakeCache(_strings()), ring_node="ring"))
    compiled_rows = [
        {
            "id": "ep_1",
            "name": "com.apple.runningboardd",
            "reach_from_json": '[{"source":"image:/x","hops":2,"via":"dyld-cache"}]',
            "privilege_delta": 2,
            "parser_complexity": 0.4,
            "weight": 1.5,
            "ring_node": "ring",
        }
    ]
    expanded = expand_surface(
        compiled_rows,
        inputs.profiles,
        ring_node="ring",
        service_names=inputs.service_names,
        shapes=inputs.shapes,
    )
    names = {t.name for t in expanded}
    assert "com.apple.runningboardd" in names
    assert "com.apple.demo.alpha" in names
