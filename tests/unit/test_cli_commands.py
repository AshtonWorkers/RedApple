import json

from ra.cli.main import main
from ra.press.client import ReplayQueue


def test_cli_run_attach_retain_and_validation(tmp_path, capsys):
    db = tmp_path / "ledger.sqlite"
    assert main(["run", "--mode", "macos", "--db", str(db)]) == 0
    run_payload = json.loads(capsys.readouterr().out)
    assert run_payload["mode"] == "macos" and run_payload["state"] == "drained"

    assert main(["attach", "--udid", "udid-1", "--tier", "A", "--db", str(db)]) == 0
    attach_payload = json.loads(capsys.readouterr().out)
    assert attach_payload == {"udid": "udid-1", "tier": "A", "state": "needs_hand"}

    assert main(["attach", "--udid", "udid-2", "--tier", "B", "--build", "b", "--db", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "attached"

    assert main(["retain", "--sweep", "--db", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["remaining"] == 0

    assert main(["retain", "--db", str(db)]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "FORMAT_FAIL"

    assert main(["run", "--mode", "ios", "--until", "25:00", "--db", str(db)]) == 2
    assert json.loads(capsys.readouterr().err)["message"] == "--until must be HH:MM"


def test_cli_replay_check_and_clear(tmp_path, capsys):
    queue_path = tmp_path / "press.jsonl"
    queue = ReplayQueue(queue_path)
    queue.append({"task_type": "bug_class", "sha": "a" * 64, "packet": {"goal": "g"}})
    with queue_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"task_type": "bug_class", "sha": "bad", "packet": {}}) + "\n")

    assert main(["replay", "--queue", str(queue_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"replayed": 1, "queued": 2, "invalid": 1}
    assert queue_path.exists()

    assert main(["replay", "--queue", str(queue_path), "--check"]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "FORMAT_FAIL"

    queue_path.write_text(
        json.dumps({"task_type": "dedup_match", "sha": "b" * 64, "packet": {}}) + "\n",
        encoding="utf-8",
    )
    assert main(["replay", "--queue", str(queue_path), "--check", "--clear"]) == 0
    assert json.loads(capsys.readouterr().out)["replayed"] == 1
    assert not queue_path.exists()


def test_cli_golden_check(capsys):
    assert main(["golden", "--type", "bug_class", "--check"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["task_type"] == "bug_class"
    assert payload["rows"] == 200
    assert payload["passed"] is True
    assert payload["route_large_model"] is False


def test_cli_clean_errors_for_malformed_inputs(tmp_path, capsys):
    bad_queue = tmp_path / "bad.jsonl"
    bad_queue.write_text("not json\n", encoding="utf-8")
    assert main(["replay", "--queue", str(bad_queue)]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "FORMAT_FAIL"

    assert main(["golden", "--type", "dedup_match", "--check"]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "FORMAT_FAIL"

    assert main(["golden", "--type", "nope", "--check"]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "FORMAT_FAIL"

    db = tmp_path / "ledger.sqlite"
    assert (
        main(
            [
                "attach",
                "--udid",
                "BAD",
                "--tier",
                "C",
                "--ring-node",
                "missing-node",
                "--db",
                str(db),
            ]
        )
        == 2
    )
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "FORMAT_FAIL"
    assert "unknown ring node" in err["message"]
