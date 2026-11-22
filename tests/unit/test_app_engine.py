"""Tests for the native-app engine bridge."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import ra.app_engine.__main__ as app_main
from ra.app_engine import workspace as ws
from ra.app_engine.engine import (
    EngineConfig,
    _crash_leads,
    config_from_env,
    loop_engine,
    resolve_jsc,
    run_engine,
    stop_engine,
    write_proven_findings,
)
from ra.discovery.harness import CrashResult
from ra.discovery.jsc_store import LedgerCrashStore
from ra.ledger import Ledger


def test_config_from_env_reads_engine_json(tmp_path: Path) -> None:
    (tmp_path / "engine.json").write_text(
        json.dumps({"jsc_binary": "/bin/true", "jsc_args": ["--foo"], "time_budget_s": 12}),
        encoding="utf-8",
    )
    config = config_from_env(tmp_path, time_budget_s=3)
    assert config.home == tmp_path
    assert config.db_path == tmp_path / "ledger.sqlite"
    assert config.time_budget_s == 3.0
    assert config.jsc_binary == "/bin/true"
    assert config.jsc_args == ("--foo",)


def test_resolve_jsc_explicit_binary(tmp_path: Path) -> None:
    binary = tmp_path / "jsc"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    config = EngineConfig(home=tmp_path, db_path=tmp_path / "ledger.sqlite", time_budget_s=1.0, jsc_binary=str(binary))
    resolved = resolve_jsc(config)
    assert resolved["binary"] == str(binary)
    assert resolved["source"] == "engine"


def test_run_engine_writes_native_workspace(tmp_path: Path) -> None:
    binary = tmp_path / "jsc"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    home = tmp_path / "workspace"
    config = EngineConfig(
        home=home,
        db_path=home / "ledger.sqlite",
        time_budget_s=1.0,
        jsc_binary=str(binary),
        timeout_s=1.0,
    )
    assert asyncio.run(run_engine(config)) == 0
    status = json.loads((home / "discovery" / "status.json").read_text(encoding="utf-8"))
    assert status["state"] == "complete"
    assert status["executions"] > 0
    leads = json.loads((home / "discovery" / "leads.json").read_text(encoding="utf-8"))
    assert leads
    assert any(lead["source_kind"] in {"chain", "escalation"} for lead in leads)
    assert not asyncio.run(stop_engine(home))


def test_crash_leads_carry_exploitability_grade(tmp_path: Path) -> None:
    async def scenario() -> None:
        home = tmp_path / "crash-workspace"
        home.mkdir()
        run_id = "run-crash-test"
        ledger = await Ledger.open(home / "ledger.sqlite")
        try:
            await ledger.create_run("macos", run_id=run_id, state="running")
            result = CrashResult(
                is_crash=True,
                crash_type="ASSERTION_FAILED",
                signal="SIGSEGV",
                returncode=-11,
                stderr="ASSERTION FAILED: JSC::foo\n#0 JSC::foo\n",
                stack=("JSC::foo",),
                signature="sig-crash-test",
            )
            record = await LedgerCrashStore(ledger).record_crash(
                b"print('x')",
                result,
                {"handle_id": run_id, "run_id": run_id, "target": "WebKit/JavaScriptCore"},
            )
            assert record is not None
            leads = await _crash_leads(ledger, home, run_id=run_id)
            assert len(leads) == 1
            lead = leads[0]
            assert lead["source_kind"] == "fuzzer"
            assert lead["rating"] in {"exploitable", "probably-exploitable", "unknown", "not-exploitable"}
            assert (home / "discovery" / "triage" / f"{lead['crash_id']}.json").exists()
        finally:
            await ledger.end_run(run_id, "drained")
            await ledger.close()

    asyncio.run(scenario())


def test_loop_engine_cycles_until_stop(tmp_path: Path) -> None:
    binary = tmp_path / "jsc"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    home = tmp_path / "workspace"
    config = EngineConfig(
        home=home,
        db_path=home / "ledger.sqlite",
        time_budget_s=1.0,
        jsc_binary=str(binary),
        timeout_s=1.0,
    )

    async def scenario() -> int:
        stop = asyncio.Event()
        task = asyncio.create_task(loop_engine(config, stop))
        for _ in range(300):
            runs = ws.load_json(ws.runs_path(home), [])
            if isinstance(runs, list) and len(runs) >= 2:
                break
            await asyncio.sleep(0.1)
        stop.set()
        return await task

    assert asyncio.run(scenario()) == 130
    status = json.loads((home / "discovery" / "status.json").read_text(encoding="utf-8"))
    assert status["state"] == "stopped"
    assert status["executions"] > 0
    runs = json.loads((home / "discovery" / "runs.json").read_text(encoding="utf-8"))
    assert len(runs) >= 2
    assert runs[0]["iteration"] >= 2
    proven = json.loads((home / "discovery" / "proven.json").read_text(encoding="utf-8"))
    assert proven["findings"]
    assert not asyncio.run(stop_engine(home))


def test_write_proven_findings_selects_and_shapes(tmp_path: Path) -> None:
    home = tmp_path / "workspace"
    ws.ensure_dirs(home)
    triage = {
        "signature": "sig-123",
        "crash_type": "ASSERTION_FAILED",
        "signal": "SIGSEGV",
        "returncode": -11,
        "stack": ["JSC::foo"],
        "repro": {"content": "line1\nline2\n", "size": 12},
        "exploitability": {"exploitability_grade": "exploitable", "confidence": 0.9},
    }
    artifact = ws.write_triage(home, "crash-1", triage)
    leads = [
        {
            "id": "crash-1",
            "title": "WebKit crash",
            "component": "JavaScriptCore",
            "summary": "bad",
            "rating": "exploitable",
            "confidence": 0.9,
            "source_kind": "fuzzer",
            "created_at": "2026-01-01T00:00:00+00:00",
            "run_id": "run-1",
            "artifact_path": str(artifact),
        },
        {
            "id": "chain-1",
            "title": "Cross-surface chain",
            "component": "Chain search",
            "summary": "quality",
            "rating": "chain",
            "confidence": 0.7,
            "source_kind": "chain",
            "created_at": "2026-01-01T00:00:00+00:00",
            "run_id": "run-1",
            "artifact_path": "",
            "quality_score": 0.7,
            "impact": 0.8,
            "feasibility": 0.6,
            "hops": 3,
            "chain_stages": [{"stage": "JavaScriptCore", "status": "confirmed", "detail": "crash"}],
        },
        {
            "id": "crash-2",
            "title": "Weak crash",
            "component": "JavaScriptCore",
            "summary": "meh",
            "rating": "not-exploitable",
            "confidence": 0.1,
            "source_kind": "fuzzer",
            "created_at": "2026-01-01T00:00:00+00:00",
            "run_id": "run-1",
            "artifact_path": "",
        },
    ]
    findings = write_proven_findings(home, leads, run_id="run-1")
    assert [finding["id"] for finding in findings] == ["crash-1", "chain-1"]
    first = findings[0]
    assert first["signature"] == "sig-123"
    assert first["chain"][0]["stage"] == "JavaScriptCore"
    labels = {item["label"] for item in first["evidence"]}
    assert "Reproducible crash" in labels
    assert "Unique crash fingerprint" in labels
    assert findings[1]["next_step"]
    stored = json.loads((home / "discovery" / "proven.json").read_text(encoding="utf-8"))
    assert stored["run_id"] == "run-1"
    assert len(stored["findings"]) == 2


def test_cli_stop_and_status_accept_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "workspace"
    ws.ensure_dirs(home)
    ws.write_status(home, state="complete", run_id="run-test", model="test")
    monkeypatch.setenv("REDAPPLE_HOME", str(home))

    async def fake_stop(root: Path | None = None) -> bool:
        return True

    monkeypatch.setattr(app_main, "stop_engine", fake_stop)

    assert app_main.main(["stop", "--json"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == "complete"
    assert "stopped" not in stopped

    assert app_main.main(["status", "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["state"] == "complete"
