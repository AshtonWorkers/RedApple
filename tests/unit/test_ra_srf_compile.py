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
        self.names = []

    async def image_strings(self, image, names=None):
        self.names.append(names)
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


def test_RA_SRF_001_service_candidate_filters_and_mach_suffixes():
    path = "/usr/libexec/ServiceHost"
    strings = [
        "xpc_connection_create",
        "com.apple.runningboardd",
        "com.apple.security.bad",
        "com.apple.fooError",
        "com.apple.plainname",
        "com.apple.short",
    ]
    result = _compile({path: strings})
    names = {r["name"] for r in result.rows}
    assert "com.apple.runningboardd" in names
    assert "com.apple.security.bad" not in names
    assert "com.apple.fooError" not in names
    assert "com.apple.plainname" not in names
    assert "com.apple.short" not in names
    assert result.service_candidates == 3


def test_RA_SRF_001_profile_literals_create_candidates_and_private_delta():
    profile = """
(version 1)
(deny default)
(allow mach-lookup (global-name "com.apple.allowedservice"))
(allow mach-lookup (global-name "com.apple.private.foo"))
"""
    result = _compile({"/usr/lib/libSystem.dylib": [profile]})
    rows = {r["name"]: r for r in result.rows}
    assert set(rows) == {"com.apple.allowedservice", "com.apple.private.foo"}
    assert rows["com.apple.allowedservice"]["parser_complexity"] > 0.0
    assert "sandbox-profile:" in rows["com.apple.allowedservice"]["reach_from_json"]
    assert rows["com.apple.private.foo"]["privilege_delta"] == (
        rows["com.apple.allowedservice"]["privilege_delta"] + 1
    )


def test_RA_SRF_001_deny_regex_blocks_non_literal_grant():
    profile = """
(version 1)
(deny default)
(allow mach-lookup (global-name-regex #"^com\\.apple\\."))
(deny mach-lookup (global-name-regex #"^com\\.apple\\.private"))
"""
    strings = [
        profile,
        "xpc_connection_create",
        "com.apple.publicfoo",
        "com.apple.privatefoo",
    ]
    result = _compile({"/usr/lib/libSystem.dylib": strings})
    assert {r["name"] for r in result.rows} == {"com.apple.publicfoo"}


def test_RA_SRF_005_image_order_limit_and_section_names_are_deterministic():
    path_a = "/usr/lib/aService"
    path_b = "/usr/lib/bService"
    strings = {
        path_a: [PROFILE, "com.apple.runningboardd"],
        path_b: XPC_STRINGS + [PROFILE],
    }
    normal = FakeCache(strings)
    reversed_cache = FakeCache(strings)
    reversed_cache.images.reverse()
    first = asyncio.run(compile_surface(normal, ring_node="order-ring"))
    second = asyncio.run(compile_surface(reversed_cache, ring_node="order-ring"))
    assert first.sha256 == second.sha256
    assert [dict(r) for r in first.rows] == [dict(r) for r in second.rows]

    limited = FakeCache(strings)
    limited_result = asyncio.run(
        compile_surface(
            limited,
            ring_node="limit-ring",
            image_limit=1,
            section_names={"__TEXT", "__cstring"},
        )
    )
    assert limited_result.images_scanned == 1
    assert limited_result.strings_scanned == len(strings[path_a])
    assert limited.names == [{"__TEXT", "__cstring"}]
