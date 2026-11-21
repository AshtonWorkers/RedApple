"""XPC shape extraction tests for RA-SRF-002."""

from ra.srf.xpc import extract_xpc_shape, image_has_xpc_markers, probable_xpc_keys

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
