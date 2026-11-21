"""XPC shape extraction tests for RA-SRF-002."""

from ra.srf.xpc import (
    _field_type,
    _score_key,
    extract_xpc_shape,
    image_has_xpc_markers,
    probable_xpc_keys,
)

STRINGS = [
    "xpc_connection_create_mach_service",
    "bootstrap_look_up",
    "com.apple.runningboardd",
    "routine",
    "identifier",
    "authToken",
    "payloadData",
    "endpoint",
    "isEnabled",
    "createdAt",
    "this is a sentence with spaces",
    "com.apple.security.app-sandbox",
]


def test_RA_SRF_002_extracts_xpc_dictionary_shape():
    assert image_has_xpc_markers(STRINGS)
    image_path = "/System/Library/PrivateFrameworks/RunningBoard.framework/Versions/A/RunningBoard"
    shape = extract_xpc_shape(image_path, STRINGS)
    assert shape is not None
    names = {f.name for f in shape.fields}
    assert "routine" in names
    assert "identifier" in names
    assert "com.apple.security.app-sandbox" not in names
    assert shape.parser_complexity > 0.0
    assert shape.format_spec.startswith("xpc-dictionary[")


def test_RA_SRF_002_shape_requires_xpc_markers_and_enough_strings():
    assert extract_xpc_shape("/usr/lib/libSystem.dylib", ["routine", "identifier"]) is None
    assert probable_xpc_keys(["xpc_bad", "a", "com.apple.private.x"]) == ()
    assert probable_xpc_keys(["endpoint", "endpoint"]) == probable_xpc_keys(["endpoint"])
    assert extract_xpc_shape("/x", ["xpc_connection_create"] * 7) is None
    assert extract_xpc_shape("/x", ["xpc_connection_create"] + ["a"] * 8) is None


def test_RA_SRF_002_field_scoring_and_type_hints_are_deterministic():
    assert _score_key("ab") == 1
    assert _score_key("ABC") == 4
    assert _score_key("AbC") == 6
    assert _score_key("com.apple.private.x") == -25
    assert _score_key("xpc_foo") == -10
    assert _score_key("someError") == 0
    assert _score_key("foo.dylib") == -45
    assert _score_key("a/b") == -25
    assert _score_key("a b") == -25

    assert _field_type("connectionEndpoint") == "endpoint"
    assert _field_type("payloadData") == "data"
    assert _field_type("createdTimestamp") == "date"
    assert _field_type("auditToken") == "uuid"
    assert _field_type("byteCount") == "uint64"
    assert _field_type("routineIndex") == "int64"
    assert _field_type("isEnabled") == "bool"
    assert _field_type("identifier") == "string"

    fields = probable_xpc_keys(
        [
            "connectionEndpoint",
            "payloadData",
            "createdTimestamp",
            "auditToken",
            "byteCount",
            "routineIndex",
            "isEnabled",
            "identifier",
        ]
    )
    types = {f.name: f.type for f in fields}
    assert types["connectionEndpoint"] == "endpoint"
    assert types["byteCount"] == "uint64"
    assert types["isEnabled"] == "bool"


def test_RA_SRF_002_shape_field_cap_and_ordering():
    strings = ["xpc_connection_create"] + [f"field{i:02d}" for i in range(60)]
    shape = extract_xpc_shape("/x", strings)
    assert shape is not None
    assert len(shape.fields) == 48
    assert shape.fields[0].name == "field00"
    assert shape.fields[-1].name == "field47"
