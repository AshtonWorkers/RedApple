"""SBPL parser tests for RA-SRF-001."""

from ra.srf.sbpl import (
    _lookup_names,
    _tokenize,
    parse_sbpl_profile,
    profile_denies_service,
    profile_grants_service,
    profiles_from_strings,
)

PROFILE = """
(version 1)
(deny default)
(allow mach-lookup (global-name "com.apple.runningboardd"))
(allow mach-lookup (global-name-regex #"^com\\.apple\\.bluetooth.*"))
(deny mach-lookup (global-name "com.apple.denied"))
(allow network-outbound)
(allow xpc-message-send)
"""


def test_RA_SRF_001_parses_sandbox_profile_grants():
    profile = parse_sbpl_profile(PROFILE, source="test.sb", name="test")
    assert profile is not None
    assert "com.apple.runningboardd" in profile.mach_lookup_allow
    assert any(x.startswith("regex:") for x in profile.mach_lookup_allow)
    assert "com.apple.denied" in profile.mach_lookup_deny
    assert "network-outbound" in profile.operations
    assert "xpc-message-send" in profile.xpc_message_ops
    assert profile.privilege_score > 0
    assert profile_grants_service(profile, "com.apple.runningboardd")
    assert profile_grants_service(profile, "com.apple.bluetoothd")
    assert not profile_grants_service(profile, "com.apple.other")


def test_RA_SRF_001_profiles_from_cache_strings_are_deterministic():
    strings = ["not sbpl", PROFILE, "(allow default)"]
    profiles = profiles_from_strings(strings, source="image:/x")
    assert len(profiles) == 1
    assert profiles[0].name.endswith("#str1")
    again = profiles_from_strings(strings, source="image:/x")
    assert [p.sha256 for p in profiles] == [p.sha256 for p in again]


def test_RA_SRF_001_sbpl_regex_literal_groups_and_nested_grants():
    profile = parse_sbpl_profile(
        """
(version 1)
(deny default)
(allow mach-lookup (require-any (global-name "com.apple.foo") (global-name "com.apple.bar")))
(allow mach-lookup (global-name-regex #"^com\\.apple\\.(bluetooth|wifi).*"))
""",
        source="nested.sb",
        name="nested",
    )
    assert profile is not None
    assert "com.apple.foo" in profile.mach_lookup_allow
    assert "com.apple.bar" in profile.mach_lookup_allow
    assert "require-any" not in profile.mach_lookup_allow
    assert "global-name" not in profile.mach_lookup_allow
    assert any("bluetooth|wifi" in x for x in profile.mach_lookup_allow)
    assert profile_grants_service(profile, "com.apple.wifid")
    assert not profile_grants_service(profile, "com.apple.other")


def test_RA_SRF_001_malformed_sbpl_returns_none():
    for text in [
        "(allow mach-lookup",
        "(allow mach-lookup))",
        "(version 1)\n(deny default)\n(allow mach-lookup (global-name",
        "(allow default)",
    ]:
        assert parse_sbpl_profile(text, source="bad.sb", name="bad") is None


def test_RA_SRF_001_sbpl_comments_invalid_regex_and_deny_regex():
    profile = parse_sbpl_profile(
        """
(version 1)
; a comment
(deny default)
(allow mach-lookup (global-name-regex #"["))
(deny mach-lookup (global-name-regex #"["))
(deny mach-lookup (global-name-regex #"^com\\.apple\\.private\\."))
(allow file-write*)
""",
        source="regex.sb",
        name="regex",
    )
    assert profile is not None
    assert "regex:[" in profile.mach_lookup_allow
    assert any(x.startswith("regex:") for x in profile.mach_lookup_deny)
    assert "file-write*" in profile.high_risk_ops
    assert not profile_grants_service(profile, "com.apple.foo")
    assert profile_denies_service(profile, "com.apple.private.x")
    assert not profile_denies_service(profile, "com.apple.public.x")


def test_RA_SRF_001_sbpl_exact_deny_and_default_only_profile():
    profile = parse_sbpl_profile(
        """
(version 1)
(deny default)
(allow mach-lookup (global-name "com.apple.foo"))
(deny mach-lookup (global-name "com.apple.foo"))
""",
        source="deny.sb",
        name="deny",
    )
    assert profile is not None
    assert profile_grants_service(profile, "com.apple.foo")
    assert profile_denies_service(profile, "com.apple.foo")
    assert parse_sbpl_profile("(allow default)", source="default.sb") is None


def test_RA_SRF_001_sbpl_tokenizer_and_lookup_edges():
    assert _tokenize('(global-name "com.apple.foo\\"bar")') == [
        "(",
        "global-name",
        'com.apple.foo"bar',
        ")",
    ]
    assert _tokenize("#bare") == ["#bare"]
    assert _lookup_names(["allow", "mach-lookup", ["global-name-regex", '"foo"']]) == {"regex:foo"}


def test_RA_SRF_001_sbpl_non_profile_and_non_string_operation():
    assert parse_sbpl_profile("not sbpl", source="plain.txt") is None
    assert parse_sbpl_profile('(allow (global-name "com.apple.foo"))', source="bad.sb") is None
