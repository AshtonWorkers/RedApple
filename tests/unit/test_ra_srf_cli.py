"""CLI tests for `python -m ra.srf` on synthetic caches."""

import json
import runpy
import sys

import pytest

from ra.srf.__main__ import main
from tests.unit.srf_cache import cstring, write_minimal_cache

PROFILE = """
(version 1)
(deny default)
(allow mach-lookup (global-name "com.apple.runningboardd"))
(allow network-outbound)
"""


def test_RA_SRF_001_cli_compiles_synthetic_cache(tmp_path, capsys):
    cache = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [
            (
                "/usr/lib/libSystem.dylib",
                [("__TEXT", "__cstring", cstring(PROFILE, "com.apple.runningboardd"))],
            )
        ],
    )
    db = tmp_path / "out" / "entry_points.sqlite3"
    rc = main(
        [
            "--cache",
            str(cache),
            "--db",
            str(db),
            "--ring-node",
            "cli-ring",
            "--top",
            "5",
            "--limit",
            "1",
        ]
    )
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ring_node"] == "cli-ring"
    assert summary["images_scanned"] == 1
    assert summary["strings_scanned"] == 2
    assert summary["sandbox_profiles"] == 1
    assert summary["entry_points"] == 1
    assert summary["top"][0]["name"] == "com.apple.runningboardd"
    assert db.exists()


def test_RA_SRF_001_cli_top_zero_and_validation(tmp_path, capsys):
    cache = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring(PROFILE))])],
    )
    rc = main(["--cache", str(cache), "--db", str(tmp_path / "x.sqlite"), "--top", "0"])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["top"] == []

    with pytest.raises(SystemExit):
        main(["--cache", str(cache), "--top", "-1"])
    with pytest.raises(SystemExit):
        main(["--cache", str(cache), "--limit", "-1"])


def test_RA_SRF_001_cli_module_entrypoint(tmp_path, capsys, monkeypatch):
    cache = write_minimal_cache(
        tmp_path / "dyld_shared_cache_arm64e",
        [("/usr/lib/libSystem.dylib", [("__TEXT", "__cstring", cstring(PROFILE))])],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ra.srf", "--cache", str(cache), "--db", str(tmp_path / "module.sqlite"), "--top", "1"],
    )
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("ra.srf.__main__", run_name="__main__")
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["entry_points"] == 1
