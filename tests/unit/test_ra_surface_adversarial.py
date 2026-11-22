"""Adversarial hardening tests for SBPL/XPC/mach-lookup surface expansion."""

import asyncio
from typing import Any

import pytest

from ra.srf.dyld import MachOImage
from ra.srf.models import ReachRecord, reach_from_json
from ra.srf.sbpl import SandboxProfile
from ra.surface.expand import (
    classify_ingress,
    expand_surface,
    profile_capabilities,
    xpc_risk_from_spec,
    xpc_risky_fields_for,
)
from ra.surface.models import Capability, ExpandedTarget, IngressClass
from ra.surface.pipeline import compile_and_rank, scan_surface_inputs
from ra.surface.rank import RankConfig, rank_targets, score_target, thin_targets_from_rows
from ra.surface.regexsafety import (
    MAX_SBPL_DEPTH,
    MAX_SBPL_PROFILE_CHARS,
    regex_pattern_is_safe,
    sbpl_profile_is_safe,
)
from ra.surface.store import InMemorySurfaceStore


def _profile(
    name: str,
    *,
    operations: tuple[Any, ...] = (),
    allow: tuple[str, ...] = (),
    deny: tuple[str, ...] = (),
    high_risk: tuple[str, ...] = (),
    source: str = "test-src",
) -> SandboxProfile:
    return SandboxProfile(
        name=name,
        source=source,
        operations=tuple(operations),
        mach_lookup_allow=tuple(sorted(allow)),
        mach_lookup_deny=tuple(sorted(deny)),
        xpc_message_ops=(),
        high_risk_ops=tuple(sorted(high_risk)),
        sha256=f"sha-{name}",
    )


def _row(name: str, **overrides: Any) -> dict[str, Any]:
    row = {
        "id": f"ep_{name}",
        "name": name,
        "reach_from_json": reach_from_json(
            (ReachRecord(source="image:/System/Library/Foo.framework/Foo", hops=2),)
        ),
        "privilege_delta": 1,
        "parser_complexity": 0.5,
        "weight": 1.0,
        "ring_node": "ring",
    }
    row.update(overrides)
    return row


class _Cache:
    def __init__(self, strings: Any) -> None:
        self.images = [
            MachOImage(address=0, path="/img/test", filetype=6, flags=0, sections=())
        ]
        self._strings = strings
        self.path = "fake-cache"

    async def image_strings(self, image: Any, names: Any = None) -> Any:
        return self._strings


def test_regex_pattern_is_safe_accepts_bounded_service_grants() -> None:
    safe = [
        "^com\\.apple\\.demo\\..*",
        "^[a-z]+$",
        "(?:com\\.apple\\.)+x?",
        "(?i)^com\\.apple\\.demo",
        "(?i:com\\.apple\\.demo)",
        "(?P<svc>com\\.apple\\.demo)",
        "a{2,3}",
        "a{2,}",
        "a{2,3}?",
        "[A-Za-z0-9_.-]{3,118}",
        "a{2}",
        "a{1,2x",
        "a{1x",
        "[a\\]b]",
        "[^a]",
        "[]a]",
        "[^]a]",
        "((a)b)c",
        "a{", "a{,}", "a{1,", "a{1,x}", "a*+", "a??",
    ]
    for pattern in safe:
        assert regex_pattern_is_safe(pattern), pattern


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "x" * 257,
        "a\\",
        "a\\1",
        "[unterminated",
        "(a",
        ")",
        "(a+)+",
        "(a|aa)*",
        "(.*)*",
        "(a?)*",
        "((a|a))*",
        "(?=a)b",
        "(?!a)b",
        "(?<=a)b",
        "(?<!a)b",
        "(?P=name)",
        "(?P<>a)",
        "(?z)a",
        "(?i",
        "a?" * 25,
        "a?" * 24 + "(b)?",
        "a|" * 13,
        "(" * 17 + ")" * 17,
        "((a)?b)?",
    ],
)
def test_regex_pattern_is_safe_rejects_pathological_grants(pattern: str) -> None:
    assert not regex_pattern_is_safe(pattern)


def test_sbpl_profile_is_safe_balanced_regex_and_malformed() -> None:
    q = chr(34)
    safe_pattern = "^com\\.apple\\.demo\\..*"
    safe = f"(version 1)(deny default)(allow mach-lookup (global-name-regex #{q}{safe_pattern}{q}))"
    assert sbpl_profile_is_safe(safe)

    unsafe_pattern = "^com\\.apple\\.(a+)+"
    unsafe = f"(version 1)(deny default)(allow mach-lookup (global-name-regex #{q}{unsafe_pattern}{q}))"
    assert not sbpl_profile_is_safe(unsafe)

    assert not sbpl_profile_is_safe("(version 1)(deny default")
    assert not sbpl_profile_is_safe(")")
    assert not sbpl_profile_is_safe("(" * (MAX_SBPL_DEPTH + 1) + ")" * (MAX_SBPL_DEPTH + 1))
    # Unsafe literals are ignored when the profile has no mach-lookup regex grant.
    assert sbpl_profile_is_safe('(version 1)(deny default)(allow file-read* (literal "(a+)+"))')
    # Comments, strings, regex strings, and escapes are scanned without crashing.
    tricky = (
        "(version 1) ; comment with ( paren\n"
        '(deny default) (allow mach-lookup (global-name-regex #"^com\\.apple\\.ok\\..*")'
        ' (global-name "escaped\\"quote") (local-name-regex "^ok\\..*"))'
    )
    assert sbpl_profile_is_safe(tricky)
    assert not sbpl_profile_is_safe('(version 1)(allow mach-lookup (global-name "unterminated)')


def test_expand_filters_invalid_service_names() -> None:
    profile = _profile("demo", allow=("regex:^com\\.apple\\.ok\\..*",))
    targets = expand_surface(
        [],
        [profile],
        ring_node="ring",
        service_names=["com.apple.ok.one", "bad name", 123, "x" * 200, "com.apple.ok.two"],  # type: ignore[list-item]
    )
    assert {t.name for t in targets} == {"com.apple.ok.one", "com.apple.ok.two"}


def test_expand_regex_match_and_candidate_budgets_are_enforced() -> None:
    profile = _profile("demo", allow=("regex:^com\\.apple\\.demo\\.",))
    names = [f"com.apple.demo.{i:03d}" for i in range(10)]
    limited = expand_surface(
        [],
        [profile],
        ring_node="ring",
        service_names=names,
        max_regex_per_pattern=10,
        max_regex_checks=3,
    )
    assert [t.name for t in limited] == names[:3]
    assert expand_surface([], [profile], ring_node="ring", service_names=names, max_regex_checks=0) == ()
    assert expand_surface([], [profile], ring_node="ring") == ()


def test_expand_rejects_regex_compile_errors() -> None:
    profile = _profile("invalid", allow=("regex:a**",))
    assert expand_surface([], [profile], ring_node="ring", service_names=["com.apple.a", "com.apple.b"]) == ()


@pytest.mark.parametrize(
    "pattern",
    ["(a+)+", "(a|aa)*", "(.*)*", "(a?)*", "((a|a))*", "(?<=x)y", "\\\\1", "x" * 257],
)
def test_expand_rejects_pathological_regex_grants(pattern: str) -> None:
    profile = _profile("bad", allow=(f"regex:{pattern}",))
    assert expand_surface([], [profile], ring_node="ring", service_names=["aaaa", "com.apple.demo.a"]) == ()


def test_expand_rows_clamp_metadata_and_filter_names() -> None:
    reach = reach_from_json((ReachRecord(source="image:/x", hops=-2),))
    targets = expand_surface(
        [
            "not-a-row",
            {"name": "bad name"},
            _row(
                "com.apple.clamped",
                reach_from_json=reach,
                privilege_delta=999,
                parser_complexity=2.5,
                weight=-1.0,
            ),
        ],
        [],
        ring_node="ring",
    )
    assert len(targets) == 1
    target = targets[0]
    assert target.privilege_delta == 5
    assert target.parser_complexity == 1.0
    assert target.base_weight == 0.0
    assert target.hops == 1


def test_profile_capabilities_skips_non_string_operations() -> None:
    profile = _profile("mixed", operations=("network-outbound", 123))
    assert profile_capabilities(profile) == frozenset({Capability.NETWORK_OUTBOUND})


def test_xpc_risk_from_spec_dedupes_risky_names() -> None:
    assert xpc_risk_from_spec("xpc-dictionary[a:endpoint,a:data,b:string,:uint64]") == 1
    assert xpc_risk_from_spec("xpc-dictionary[a:string]") == 0
    assert xpc_risk_from_spec(None) == 0  # type: ignore[arg-type]


def test_xpc_risky_fields_for_uses_risk_precedence_and_tolerates_bad_shapes() -> None:
    fields = {
        "/a": {"token": "string"},
        "/b": {"token": "data", "other": "uint64"},
        "/bad": None,
        "/list": [],
    }
    got = xpc_risky_fields_for(["/a", "/b", "/bad", "/list", "/missing", 123], fields)  # type: ignore[arg-type]
    assert got == 2


def test_classify_ingress_tolerates_non_string_paths() -> None:
    assert classify_ingress([123, "/System/Library/Safari.framework/Safari"]) == IngressClass.ZERO_CLICK  # type: ignore[list-item]
    assert classify_ingress([123]) == IngressClass.UNKNOWN  # type: ignore[list-item]


def _expanded(name: str, **overrides: Any) -> ExpandedTarget:
    kwargs: dict[str, Any] = {
        "ring_node": "ring",
        "name": name,
        "reach_from": (ReachRecord(source="image:/x", hops=2),),
        "base_weight": 1.0,
        "privilege_delta": 1,
        "parser_complexity": 0.5,
    }
    kwargs.update(overrides)
    return ExpandedTarget(**kwargs)


def test_rank_config_sanitizes_invalid_floats() -> None:
    config = RankConfig(
        capability_weight=float("nan"),
        xpc_risk_weight=-1.0,
        zero_click_mult=float("inf"),
        network_mult=-0.5,
        local_mult=1.0,
        unknown_mult=1.0,
        xpc_risk_norm=float("nan"),
        capability_norm=-1.0,
    )
    assert config.capability_weight == 0.0
    assert config.xpc_risk_weight == 0.0
    assert config.zero_click_mult == 0.0
    assert config.network_mult == 0.0
    assert config.xpc_risk_norm == 0.0
    assert config.capability_norm == 0.0
    score, _ = score_target(_expanded("bad", base_weight=float("inf")), config)
    assert score == 0.0
    score, _ = score_target(_expanded("bad", base_weight=-2.0), config)
    assert score == 0.0


def test_rank_targets_total_tie_break_is_input_order_independent() -> None:
    close = _expanded(
        "com.apple.tie",
        reach_from=(ReachRecord(source="image:/a", hops=1),),
        image_paths=("/a",),
    )
    far = _expanded(
        "com.apple.tie",
        reach_from=(ReachRecord(source="image:/b", hops=2),),
        image_paths=("/b",),
    )
    first = rank_targets([far, close])
    second = rank_targets([close, far])
    assert first.sha256 == second.sha256
    assert [t.reach_from[0].source for t in first.targets] == ["image:/a", "image:/b"]


def test_thin_targets_from_rows_clamps_malformed_metadata() -> None:
    rows = [
        _row(
            "com.apple.thin",
            weight=-1.0,
            privilege_delta=999,
            parser_complexity=2.5,
            reach_from_json=reach_from_json((ReachRecord(source="image:/x", hops=-3),)),
        )
    ]
    targets = thin_targets_from_rows(rows)
    assert len(targets) == 1
    target = targets[0]
    assert target.weight == 0.0
    assert target.privilege_delta == 5
    assert target.parser_complexity == 1.0
    assert target.hops == 1


def test_scan_surface_inputs_sanitizes_hostile_cache_strings() -> None:
    async def body() -> None:
        assert (await scan_surface_inputs(_Cache("raw-string"), ring_node="ring")).service_names == ()
        assert (await scan_surface_inputs(_Cache(object()), ring_node="ring")).profiles == ()
        mixed = await scan_surface_inputs(
            _Cache([123, "x" * (MAX_SBPL_PROFILE_CHARS + 1), "com.apple.ok.service"]),
            ring_node="ring",
        )
        assert mixed.service_names == ("com.apple.ok.service",)
        q = chr(34)
        unsafe = f"(version 1)(allow mach-lookup (global-name-regex #{q}(a+)+{q}))"
        hostile = await scan_surface_inputs(_Cache([unsafe]), ring_node="ring")
        assert hostile.profiles == ()
        result = await compile_and_rank(_Cache([unsafe]), InMemorySurfaceStore(), ring_node="ring")
        assert result.rows_written == 0

    asyncio.run(body())
