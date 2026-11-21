"""Compiler acceptance tests for RA-SRF-001/002/003/005."""

import asyncio

from ra.srf.compile import compile_surface
from ra.srf.dyld import MachOImage
from ra.srf.store import InMemoryEntryPointStore

PROFILE = """
(version 1)
(deny default)
(allow mach-lookup (global-name "com.apple.runningboardd"))
(allow network-outbound)
(allow xpc-message-send)
"""

XPC_STRINGS = [
    "xpc_connection_create_mach_service",
    "com.apple.runningboardd",
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


def _compile(strings_by_path, store=None):
    return asyncio.run(
        compile_surface(FakeCache(strings_by_path), ring_node="test-ring", store=store)
    )


def test_RA_SRF_001_002_compiles_grants_and_xpc_shapes():
    path = "/System/Library/PrivateFrameworks/RunningBoard.framework/Versions/A/RunningBoard"
    result = _compile({path: XPC_STRINGS + [PROFILE]})
    assert result.service_candidates >= 1
    assert result.profiles
    row = next(r for r in result.rows if r["name"] == "com.apple.runningboardd")
    assert row["privilege_delta"] > 0
    assert 0.0 <= row["parser_complexity"] <= 1.0
    assert "sandbox-profile:" in row["reach_from_json"]
    assert "image:" in row["reach_from_json"]
    weights = [r["weight"] for r in result.rows]
    assert weights == sorted(weights, reverse=True)


def test_RA_SRF_003_removed_entitlement_drops_node():
    path = "/usr/lib/system/libxpc.dylib"
    store = InMemoryEntryPointStore()
    with_profile = _compile({path: [PROFILE]}, store=store)
    assert any(r["name"] == "com.apple.runningboardd" for r in with_profile.rows)

    without = _compile({path: []}, store=store)
    assert without.rows == ()
    assert asyncio.run(store.read_ring_node("test-ring")) == []


def test_RA_SRF_005_two_compiles_are_byte_identical():
    path = "/System/Library/PrivateFrameworks/RunningBoard.framework/Versions/A/RunningBoard"
    strings = {path: XPC_STRINGS + [PROFILE]}
    first = _compile(strings)
    second = _compile(strings)
    assert first.sha256 == second.sha256
    assert [dict(r) for r in first.rows] == [dict(r) for r in second.rows]
