"""Expansion tests for RA-SFC-001/002/003: regex grants, capabilities, XPC risk."""

from ra.srf.models import ReachRecord, XPCField, XPCShape, reach_from_json
from ra.srf.sbpl import SandboxProfile
from ra.surface.expand import (
    capability_risk_total,
    classify_ingress,
    expand_surface,
    harvest_service_names,
    profile_capabilities,
    shape_risk_from_fields,
    xpc_risk_from_spec,
    xpc_risky_fields_for,
)
from ra.surface.models import Capability, IngressClass


def _profile(
    name: str,
    *,
    operations: tuple[str, ...] = (),
    allow: tuple[str, ...] = (),
    deny: tuple[str, ...] = (),
    high_risk: tuple[str, ...] = (),
    source: str = "test-src",
) -> SandboxProfile:
    return SandboxProfile(
        name=name,
        source=source,
        operations=tuple(sorted(operations)),
        mach_lookup_allow=tuple(sorted(allow)),
        mach_lookup_deny=tuple(sorted(deny)),
        xpc_message_ops=(),
        high_risk_ops=tuple(sorted(high_risk)),
        sha256=f"sha-{name}",
    )


def _row(name: str, *, weight: float = 1.0, priv: int = 1, reach: tuple = ()) -> dict:
    records = reach or (ReachRecord(source="image:/System/Library/Foo.framework/Foo", hops=2, via="dyld-cache"),)
    return {
        "id": f"ep_{name}",
        "name": name,
        "reach_from_json": reach_from_json(records),
        "privilege_delta": priv,
        "parser_complexity": 0.5,
        "weight": weight,
        "ring_node": "ring",
    }


def test_RA_SFC_001_harvest_service_names_filters_and_sorts():
    strings = [
        "com.apple.test.service",
        "com.apple.test.service",  # duplicate
        "com.apple.security.bad",  # denied substring
        "ab",  # too short
        "no spaces allowed!!",
        "testd",  # mach-like suffix
        "com.apple.another.daemon",
        "plainname",  # no com.apple prefix, no mach hint
    ]
    got = harvest_service_names(strings)
    assert got == tuple(sorted(got))
    assert "com.apple.test.service" in got
    assert "com.apple.another.daemon" in got
    assert "testd" in got
    assert "com.apple.security.bad" not in got
    assert "plainname" not in got
    assert "ab" not in got


def test_RA_SFC_001_harvest_service_names_empty_and_bounds():
    assert harvest_service_names([]) == ()
    assert harvest_service_names(["x" * 200]) == ()


def test_RA_SFC_002_profile_capabilities_maps_operations():
    profile = _profile(
        "p",
        operations=(
            "network-outbound",
            "network-inbound",
            "file-write*",
            "iokit-open",
            "mach-priv*",
            "sysctl-write",
            "nvram-*",
            "keychain-*",
            "process-exec",
            "process-fork",
            "xpc-message-send",
            "mach-lookup",
        ),
    )
    caps = profile_capabilities(profile)
    assert caps == frozenset(
        {
            Capability.NETWORK_OUTBOUND,
            Capability.NETWORK_INBOUND,
            Capability.FILE_WRITE,
            Capability.IOKIT,
            Capability.MACH_PRIV,
            Capability.SYSCTL_WRITE,
            Capability.NVRAM,
            Capability.KEYCHAIN,
            Capability.PROCESS_EXEC,
            Capability.XPC_MESSAGE,
        }
    )
    assert profile_capabilities(_profile("empty")) == frozenset()


def test_RA_SFC_002_capability_risk_total():
    assert capability_risk_total([]) == 0.0
    assert capability_risk_total([Capability.NETWORK_INBOUND]) == 3.0
    total = capability_risk_total(list(Capability))
    assert total > 0.0


def test_RA_SFC_003_xpc_risk_from_spec():
    assert xpc_risk_from_spec("xpc-dictionary[a:endpoint,b:string,c:data]") == 2
    assert xpc_risk_from_spec("xpc-dictionary[a:string]") == 0
    assert xpc_risk_from_spec("xpc-dictionary[]") == 0
    assert xpc_risk_from_spec("mach-lookup-service[x]") == 0
    assert xpc_risk_from_spec("xpc-dictionary[unclosed") == 0
    assert xpc_risk_from_spec("") == 0


def test_RA_SFC_003_xpc_risky_fields_for_merges_images():
    fields_by_image = {
        "/img/a": {"endpoint": "endpoint", "name": "string"},
        "/img/b": {"token": "uuid", "count": "uint64"},
    }
    assert xpc_risky_fields_for(["/img/a"], fields_by_image) == 1
    assert xpc_risky_fields_for(["/img/a", "/img/b"], fields_by_image) == 3
    assert xpc_risky_fields_for([], fields_by_image) == 0
    assert xpc_risky_fields_for(["/img/missing"], fields_by_image) == 0


def test_RA_SFC_003_shape_risk_from_fields():
    fields = (
        XPCField(name="endpoint", type="endpoint"),
        XPCField(name="payloadData", type="data"),
        XPCField(name="createdAt", type="date"),
        XPCField(name="isEnabled", type="bool"),
    )
    assert shape_risk_from_fields(fields) == 2


def test_RA_SFC_003_classify_ingress():
    assert classify_ingress([]) == IngressClass.UNKNOWN
    assert classify_ingress(["/System/Library/Safari.framework/Safari"]) == IngressClass.ZERO_CLICK
    assert classify_ingress(["/System/Library/WebKit.framework/WebKit"]) == IngressClass.ZERO_CLICK
    assert classify_ingress(["/System/Library/Bluetooth.framework/Bluetooth"]) == IngressClass.NETWORK
    assert classify_ingress(["/usr/lib/system/libxpc.dylib"]) == IngressClass.LOCAL
    # zero-click wins over network when both hints appear
    assert (
        classify_ingress(["/a/Safari", "/b/bluetooth"])
        == IngressClass.ZERO_CLICK
    )


def test_RA_SFC_001_regex_grant_expansion_creates_targets():
    profile = _profile(
        "demo",
        operations=("mach-lookup", "network-outbound"),
        allow=("regex:^com\\.apple\\.demo\\..*",),
        high_risk=("network-outbound",),
    )
    targets = expand_surface(
        [_row("com.apple.existing.service")],
        [profile],
        ring_node="ring",
        service_names=["com.apple.demo.alpha", "com.apple.demo.beta", "com.apple.other"],
    )
    names = {t.name for t in targets}
    assert "com.apple.demo.alpha" in names
    assert "com.apple.demo.beta" in names
    assert "com.apple.other" not in names
    alpha = next(t for t in targets if t.name == "com.apple.demo.alpha")
    assert alpha.privilege_delta > 0
    assert alpha.base_weight > 0.0
    assert any(r.source.startswith("regex-grant:") for r in alpha.reach_from)
    assert any(r.source.startswith("sandbox-profile:") for r in alpha.reach_from)


def test_RA_SFC_001_regex_expansion_respects_deny():
    profile = _profile(
        "demo",
        allow=("regex:^com\\.apple\\.demo\\..*",),
        deny=("com.apple.demo.secret",),
    )
    targets = expand_surface(
        [],
        [profile],
        ring_node="ring",
        service_names=["com.apple.demo.secret", "com.apple.demo.open"],
    )
    names = {t.name for t in targets}
    assert "com.apple.demo.secret" not in names
    assert "com.apple.demo.open" in names


def test_RA_SFC_001_bad_regex_is_failure_injection_safe():
    profile = _profile("bad", allow=("regex:[unterminated",))
    targets = expand_surface(
        [], [profile], ring_node="ring", service_names=["com.apple.demo.alpha"]
    )
    assert targets == ()


def test_RA_SFC_001_regex_match_limit_is_deterministic():
    profile = _profile("demo", allow=("regex:^com\\.apple\\.demo\\.",))
    names = [f"com.apple.demo.{i:03d}" for i in range(10)]
    limited = expand_surface(
        [], [profile], ring_node="ring", service_names=names, max_regex_per_pattern=3
    )
    assert len(limited) == 3
    assert [t.name for t in limited] == sorted(t.name for t in limited)[:3]


def test_RA_SFC_002_literal_grant_adds_capabilities_and_reach():
    profile = _profile(
        "net",
        operations=("mach-lookup", "network-inbound", "process-exec"),
        allow=("com.apple.literal.service",),
        high_risk=("network-inbound", "process-exec"),
    )
    row = _row("com.apple.literal.service")
    targets = expand_surface([row], [profile], ring_node="ring")
    assert len(targets) == 1
    target = targets[0]
    assert Capability.NETWORK_INBOUND in target.capabilities
    assert Capability.PROCESS_EXEC in target.capabilities
    assert target.entry_point_id == "ep_com.apple.literal.service"
    sources = {r.source for r in target.reach_from}
    assert "sandbox-profile:net" in sources
    assert "image:/System/Library/Foo.framework/Foo" in sources


def test_RA_SFC_002_duplicate_rows_merge_reach():
    row1 = _row("com.apple.merged", weight=1.0, reach=(ReachRecord(source="image:/a", hops=2),))
    row2 = _row("com.apple.merged", weight=0.5, reach=(ReachRecord(source="image:/b", hops=3),))
    targets = expand_surface([row1, row2], [], ring_node="ring")
    assert len(targets) == 1
    target = targets[0]
    assert {r.source for r in target.reach_from} == {"image:/a", "image:/b"}


def test_RA_SFC_003_xpc_shapes_contribute_risky_fields():
    profile = _profile("p", allow=("com.apple.xpc.service",), operations=("mach-lookup",))
    row = _row(
        "com.apple.xpc.service",
        reach=(ReachRecord(source="image:/System/Library/Safari.framework/Safari", hops=2),),
    )
    shape = XPCShape(
        image_path="/System/Library/Safari.framework/Safari",
        fields=(
            XPCField(name="endpoint", type="endpoint"),
            XPCField(name="payloadData", type="data"),
            XPCField(name="createdAt", type="date"),
        ),
    )
    targets = expand_surface([row], [profile], ring_node="ring", shapes=[shape])
    assert targets[0].xpc_risky_fields == 2
    assert targets[0].image_paths == ("/System/Library/Safari.framework/Safari",)


def test_RA_SFC_002_private_name_grant_scores_full_delta():
    profile = _profile(
        "priv",
        operations=("mach-lookup", "network-outbound", "file-write*"),
        allow=("regex:^com\\.apple\\.private\\.demo\\.",),
        high_risk=("network-outbound", "file-write*"),
    )
    targets = expand_surface(
        [],
        [profile],
        ring_node="ring",
        service_names=["com.apple.private.demo.helper"],
    )
    assert len(targets) == 1
    # privilege_score>0 (+1), network op (+1), private prefix (+1) -> 3
    assert targets[0].privilege_delta == 3


def test_RA_SFC_001_literal_grant_without_row_or_denied_is_skipped():
    # "com.apple.missing.service" has no compiled row (elif false branch);
    # "com.apple.denied.service" has a row but is denied (not granted).
    # Note: the compiler's allow-overrides-deny rule means a name in BOTH
    # allow and deny is still granted, so deny here is not overridden.
    profile = _profile(
        "lit",
        operations=("mach-lookup",),
        allow=("com.apple.missing.service",),
        deny=("com.apple.denied.service",),
    )
    row = _row("com.apple.denied.service")
    targets = expand_surface([row], [profile], ring_node="ring")
    assert len(targets) == 1
    target = targets[0]
    assert all(not r.source.startswith("sandbox-profile:") for r in target.reach_from)
    assert target.capabilities == frozenset()


def test_RA_SFC_001_allow_overrides_deny_like_compiler():
    profile = _profile(
        "both",
        operations=("mach-lookup", "network-outbound"),
        allow=("com.apple.both.service",),
        deny=("com.apple.both.service",),
    )
    row = _row("com.apple.both.service")
    targets = expand_surface([row], [profile], ring_node="ring")
    assert any(r.source == "sandbox-profile:both" for r in targets[0].reach_from)


def test_RA_SFC_failure_injection_malformed_rows_and_empty_inputs():
    bad_rows = [
        "not-a-mapping",
        {},
        {"name": 42},
        {"name": "com.apple.bad.reach", "reach_from_json": "not json"},
        {"name": "com.apple.bad.reach2", "reach_from_json": "{}"},
        {"name": "com.apple.bad.types", "weight": "NaN-ish", "privilege_delta": None},
    ]
    targets = expand_surface(bad_rows, [], ring_node="ring")
    assert len(targets) == 3  # all named rows survive; malformed reach degrades
    for target in targets:
        assert target.reach_from == ()
    assert expand_surface([], [], ring_node="ring") == ()
