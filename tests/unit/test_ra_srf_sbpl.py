"""SBPL parser tests for RA-SRF-001."""

from ra.srf.sbpl import parse_sbpl_profile, profile_grants_service, profiles_from_strings

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
