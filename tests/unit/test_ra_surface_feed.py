"""Feed tests: lane/chain handoff interfaces and stubs."""

import asyncio

from ra.srf.models import ReachRecord
from ra.surface.feed import (
    LedgerChainFeed,
    LedgerLaneFeed,
    StaticChainFeed,
    StaticLaneFeed,
    StubChainSearch,
    feed_dicts,
    lane_targets_from_surface,
    rows_to_lane_targets,
)
from ra.surface.models import Capability, ExpandedTarget
from ra.surface.rank import rank_targets
from ra.surface.store import InMemorySurfaceStore


def _ranked():
    targets = [
        ExpandedTarget(
            ring_node="ring",
            name=name,
            reach_from=(ReachRecord(source="image:/x", hops=2, via="dyld-cache"),),
            base_weight=weight,
            privilege_delta=1,
            parser_complexity=0.5,
            capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
        )
        for name, weight in (("com.apple.a", 2.0), ("com.apple.b", 1.0), ("com.apple.c", 0.5))
    ]
    return rank_targets(targets)


def test_RA_SFC_lane_projection_and_limit():
    ranked = _ranked()
    lanes = lane_targets_from_surface(list(ranked.targets), limit=2)
    assert len(lanes) == 2
    assert lanes[0].target_id == ranked.targets[0].id
    assert lanes[0].tier == ranked.targets[0].tier.value
    assert lanes[0].capabilities == ("network-outbound",)
    assert lanes[0].to_dict()["rank"] == 1
    assert lane_targets_from_surface([], limit=0) == ()


def test_RA_SFC_static_feeds_filter_ring_and_limit():
    ranked = _ranked()
    other = rank_targets(
        [
            ExpandedTarget(
                ring_node="other",
                name="com.apple.z",
                reach_from=(),
                base_weight=9.0,
                privilege_delta=1,
                parser_complexity=0.5,
            )
        ],
        ring_node="other",
    )
    all_targets = list(ranked.targets) + list(other.targets)

    async def body() -> None:
        lane_feed = StaticLaneFeed(all_targets)
        chain_feed = StaticChainFeed(all_targets)
        lanes = await lane_feed.feed("ring")
        assert {lt.name for lt in lanes} == {"com.apple.a", "com.apple.b", "com.apple.c"}
        limited = await lane_feed.feed("ring", limit=1)
        assert len(limited) == 1
        chains = await chain_feed.feed("ring", limit=2)
        assert [t.name for t in chains] == ["com.apple.a", "com.apple.b"]
        assert await chain_feed.feed("missing") == ()

    asyncio.run(body())


def test_RA_SFC_ledger_feeds_read_persisted_rows():
    async def body() -> None:
        store = InMemorySurfaceStore()
        ranked = _ranked()
        await store.replace_targets(ranked)
        lane_feed = LedgerLaneFeed(store)
        chain_feed = LedgerChainFeed(store)
        lanes = await lane_feed.feed("ring", limit=2)
        assert [lt.name for lt in lanes] == ["com.apple.a", "com.apple.b"]
        chains = await chain_feed.feed("ring")
        assert [t.name for t in chains] == ["com.apple.a", "com.apple.b", "com.apple.c"]
        limited_chains = await chain_feed.feed("ring", limit=2)
        assert [t.name for t in limited_chains] == ["com.apple.a", "com.apple.b"]
        assert await lane_feed.feed("missing") == ()

    asyncio.run(body())


def test_RA_SFC_stub_chain_search_records_targets():
    ranked = _ranked()
    stub = StubChainSearch()
    result = stub.search(ranked.targets)
    assert result == ()
    assert [t.name for t in stub.seen] == ["com.apple.a", "com.apple.b", "com.apple.c"]


def test_RA_SFC_feed_dicts_and_rows_to_lane_targets():
    ranked = _ranked()
    dicts = feed_dicts(ranked.targets)
    assert dicts[0]["id"] == ranked.targets[0].id
    lanes = rows_to_lane_targets(list(ranked.rows))
    assert [lt.name for lt in lanes] == ["com.apple.a", "com.apple.b", "com.apple.c"]
    assert rows_to_lane_targets([]) == ()
