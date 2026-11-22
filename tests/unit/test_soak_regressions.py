"""Regression tests for the hardened-trunk macOS soak findings."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from ra.cli.main import main
from ra.errors import FormatFail, RaError
from ra.ledger import Ledger
from ra.ledger.db import LedgerStore
from tests.conftest import run


def _ring_node(*, epoch: int, state: str = "active", node_id: str = "node") -> dict[str, object]:
    return {
        "ring_node_id": node_id,
        "ipsw_sha": "a" * 64,
        "build": "26.0",
        "xcode": "xcode",
        "sdk": "sdk",
        "webkit_commit": "webkit",
        "state": state,
        "epoch": epoch,
    }


def test_cli_db_directory_is_format_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--mode", "macos", "--db", str(tmp_path)]) == 2
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "FORMAT_FAIL"


def test_replay_type_is_validated(tmp_path: Path) -> None:
    assert main(["replay", "--type", "nope"]) == 2


def test_replay_queue_read_errors_are_format_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(b"\xff")
    assert main(["replay", "--queue", str(bad)]) == 2
    capsys.readouterr()
    assert main(["replay", "--queue", str(tmp_path)]) == 2
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "FORMAT_FAIL"


def test_golden_baseline_must_be_valid_json_score(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{bad", encoding="utf-8")
    assert (
        main(
            [
                "golden",
                "--type",
                "bug_class",
                "--file",
                "tests/golden/bug_class.jsonl",
                "--baseline",
                str(baseline),
            ]
        )
        == 2
    )
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "FORMAT_FAIL"


def test_run_lifecycle_is_guarded() -> None:
    async def body() -> None:
        ledger = await Ledger.open(":memory:")
        try:
            run_id = await ledger.create_run("macos", state="running")
            await ledger.end_run(run_id, "drained")
            with pytest.raises(FormatFail):
                await ledger.end_run(run_id, "armed")
            with pytest.raises(FormatFail):
                await ledger.create_run("macos", state="drained")
        finally:
            await ledger.close()

    run(body())


def test_ring_epoch_is_monotonic_and_state_is_closed() -> None:
    async def body() -> None:
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.upsert_ring_node(_ring_node(epoch=5))
            with pytest.raises(FormatFail):
                await ledger.advance_ring(4, [])
            with pytest.raises(FormatFail):
                await ledger.advance_ring(-1, [])
            with pytest.raises(FormatFail):
                await ledger.upsert_ring_node(_ring_node(epoch=5, state="bogus", node_id="bad"))
        finally:
            await ledger.close()

    run(body())


def test_ledger_values_are_validated() -> None:
    async def body() -> None:
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail):
                await ledger.enqueue_work_order(action="park", unit="u", ev_cost=-1.0)
            with pytest.raises(FormatFail):
                await ledger.enqueue_work_order(action="park", unit="u", ev_cost=float("inf"))
            with pytest.raises(FormatFail):
                await ledger.upsert_device_profile(
                    {"udid": "d", "state": "bogus", "thermal": "nominal", "crashes": 0}
                )
            with pytest.raises(FormatFail):
                await ledger.upsert_device_profile(
                    {"udid": "d", "state": "ready", "thermal": "bogus", "crashes": 0}
                )
            with pytest.raises(FormatFail):
                await ledger.upsert_device_profile(
                    {"udid": "d", "state": "ready", "thermal": "nominal", "crashes": -1}
                )
            with pytest.raises(FormatFail):
                await ledger.record_packet_log(packet_id="p", sha="a" * 64, tokens_in="abc")  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                await ledger.record_packet_log(packet_id="p", sha="a" * 64, tokens_in=-1)
            with pytest.raises(FormatFail):
                await ledger.record_packet_log(packet_id="p", sha="a" * 64, schema_ok="yes")  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                await ledger.record_packet_log(packet_id="p", sha="a" * 64, relevance="high")  # type: ignore[arg-type]
            with pytest.raises(FormatFail):
                await ledger.insert_entry_point(
                    {
                        "entry_point_id": "e",
                        "name": "n",
                        "reach_from_json": "[]",
                        "privilege_delta": -1,
                        "parser_complexity": 0.5,
                        "weight": 1.0,
                        "ring_node": "r",
                    }
                )
        finally:
            await ledger.close()

    run(body())


def test_sync_reads_are_thread_bound() -> None:
    store = LedgerStore(":memory:")
    errors: list[str] = []

    def worker() -> None:
        try:
            store.counts()
        except RaError as exc:
            errors.append(exc.code)

    try:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
    finally:
        store.close()
    assert errors == ["LEDGER_THREAD"]


def test_tilde_db_path_expands_for_connect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    store = LedgerStore("~/x.sqlite")
    try:
        assert store.path == str(tmp_path / "x.sqlite")
        assert store.pragma_value("journal_mode") == "wal"
    finally:
        store.close()
