import asyncio
import io
import json
import urllib.error
import urllib.request

import pytest

from ra.cli.main import layout_check, main
from ra.errors import FormatFail, RaError
from ra.ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    ClaimState,
    Ledger,
    LedgerStore,
)
from ra.ledger.ids import artifact_id, sha256_hex
from ra.ledger.operations import LedgerOperation
from ra.obs.retention import RetentionPolicy, sweep
from ra.policy import ACTION_COST_USD_MICRO, Action, ExecutorCaps, PolicyEngine
from ra.press.client import ChatResponse, DeepSeekClient, DeepSeekError, ReplayQueue
from ra.press.golden import GoldenCase, check_golden, evaluate_cases, load_golden, score_output
from ra.press.harness import PressHarness, validate_output
from ra.press.packets import Packet, PacketCompiler
from ra.press.routing import TaskType
from tests.conftest import run


def claim_input(cid: str, key: str, data: bytes, *, ttl_class: str = "run", created: int = 1):
    return ClaimInput(
        claim_id=cid,
        type="bug_class",
        value_json=json.dumps({"answer": "insufficient_evidence"}),
        confidence=0.5,
        dedup_key=key,
        created=created,
        artifacts=(
            ClaimArtifactInput(
                ArtifactInput(kind="crash", data=data, ttl_class=ttl_class), role="evidence"
            ),
        ),
    )


def artifact_payload(data: bytes, *, ttl_class: str = "run", created: int = 1) -> dict[str, object]:
    return {
        "artifact_id": artifact_id(data),
        "kind": "crash",
        "sha256": sha256_hex(data),
        "bytes": len(data),
        "created": created,
        "ttl_class": ttl_class,
    }


def test_batch_partial_failure_keeps_successful_ops():
    store = LedgerStore(":memory:")
    try:
        data = b"batch-ok"
        good = LedgerOperation("put_artifact", artifact_payload(data), rows=1)
        bad = LedgerOperation(
            "transition_claim", {"claim_id": "missing", "to_state": "bound", "created": 1}, rows=3
        )
        assert store.apply_batch([good, bad]) == [artifact_id(data), None]
        assert store.artifact_count() == 1
    finally:
        store.close()


def test_artifact_upsert_rank_and_content_address():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            data = b"same-bytes"
            first = await ledger.put_artifact("crash", data, ttl_class="ephemeral")
            second = await ledger.put_artifact("crash", data, ttl_class="run")
            third = await ledger.put_artifact("crash", data, ttl_class="pinned")
            assert first == second == third == artifact_id(data)
            assert ledger.artifact_ttl_counts() == {"pinned": 1}
            bad_payload = artifact_payload(data)
            bad_payload["sha256"] = sha256_hex(b"other")
            bad = LedgerOperation("put_artifact", bad_payload, rows=1)
            assert ledger.store.apply_batch([bad]) == [None]
        finally:
            await ledger.close()

    run(body())


def test_delete_artifacts_respects_min_set_and_pinned():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.create_claim(claim_input("cl_a", "key-a", b"a"))
            await ledger.create_claim(claim_input("cl_b", "key-b", b"b"))
            ids = [artifact_id(b"a"), artifact_id(b"b")]
            assert await ledger.delete_artifacts(ids, min_set=1) == 1
            assert ledger.artifact_count() == 1
            pinned = await ledger.put_artifact("crash", b"pin", ttl_class="pinned")
            assert await ledger.delete_artifacts([pinned]) == 0
            assert ledger.artifact_count() == 2
            assert ledger.artifact_ttl_counts()["pinned"] == 1
        finally:
            await ledger.close()

    run(body())


def test_delete_artifacts_skips_promoted_claim_evidence():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cid = await ledger.create_claim(claim_input("cl_p", "key-p", b"promoted"))
            await ledger.transition_claim(cid, ClaimState.BOUND)
            await ledger.transition_claim(cid, ClaimState.REVIEWED)
            await ledger.transition_claim(cid, ClaimState.PROMOTED)
            art = artifact_id(b"promoted")
            assert await ledger.delete_artifacts([art]) == 0
            assert ledger.artifact_count() == 1
            assert ledger.claim_artifact_count(cid) == 1
        finally:
            await ledger.close()

    run(body())


def test_retention_sweep_stops_at_min_set():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            for index, data in enumerate((b"r1", b"r2", b"r3")):
                await ledger.create_claim(claim_input(f"cl_r{index}", f"key-r{index}", data))
            result = await sweep(
                ledger,
                RetentionPolicy(ephemeral_days=1, run_days=1, batch_size=10, min_set=1),
            )
            assert result["run"] == 2
            assert result["remaining"] == 1
            assert ledger.artifact_count() == 1
        finally:
            await ledger.close()

    run(body())


def test_dispatch_work_order_atomic_budget_and_idempotence():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            run_id = await ledger.create_run("macos", budget={"spend_usd_micro": 1000})
            wid = await ledger.enqueue_work_order(
                action="retarget", unit="u", ev_cost=1.0, run_id=run_id
            )
            result = await ledger.dispatch_work_order(
                work_order_id=wid,
                budget_usd_micro=ACTION_COST_USD_MICRO[Action.RETARGET],
                spent_usd_micro=ACTION_COST_USD_MICRO[Action.RETARGET],
                expected="retarget",
            )
            assert result["dispatched"] is True
            assert ledger.get_work_order(wid)["state"] == "done"
            assert ledger.spent_usd_micro(run_id) == ACTION_COST_USD_MICRO[Action.RETARGET]
            again = await ledger.dispatch_work_order(
                work_order_id=wid,
                budget_usd_micro=ACTION_COST_USD_MICRO[Action.RETARGET],
                spent_usd_micro=ACTION_COST_USD_MICRO[Action.RETARGET],
            )
            assert again["dispatched"] is False and again["reason"] == "not_ready"

            wid2 = await ledger.enqueue_work_order(
                action="reweight", unit="u2", ev_cost=1.0, run_id=run_id
            )
            denied = await ledger.dispatch_work_order(
                work_order_id=wid2,
                budget_usd_micro=25_000,
                spent_usd_micro=10_000,
            )
            assert denied["reason"] == "budget"
            assert ledger.get_work_order(wid2)["state"] == "ready"

            run2 = await ledger.create_run("macos", budget={"spend_usd_micro": 1000})
            wid3 = await ledger.enqueue_work_order(
                action="reweight", unit="u3", ev_cost=1.0, run_id=run2
            )
            scoped = await ledger.dispatch_work_order(
                work_order_id=wid3,
                budget_usd_micro=15_000,
                spent_usd_micro=ACTION_COST_USD_MICRO[Action.REWEIGHT],
            )
            assert scoped["dispatched"] is True
            assert ledger.spent_usd_micro(run_id) == ACTION_COST_USD_MICRO[Action.RETARGET]
            assert ledger.spent_usd_micro(run2) == ACTION_COST_USD_MICRO[Action.REWEIGHT]
        finally:
            await ledger.close()

    run(body())


def test_policy_dispatch_ready_atomic_cap():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            run_id = await ledger.create_run("macos")
            engine = PolicyEngine(
                ledger, ExecutorCaps(spend_usd_micro=ACTION_COST_USD_MICRO[Action.RETARGET])
            )
            first = await engine.plan_action(
                "retarget", "unit", probability_join=0.5, run_id=run_id
            )
            second = await engine.plan_action(
                "retarget", "unit", probability_join=0.5, run_id=run_id
            )
            dispatched, refusals = await engine.dispatch_ready()
            assert dispatched == 1
            assert len(refusals) == 1
            states = {ledger.get_work_order(first)["state"], ledger.get_work_order(second)["state"]}
            assert states == {"done", "ready"}
            assert ledger.spent_usd_micro(run_id) == ACTION_COST_USD_MICRO[Action.RETARGET]
        finally:
            await ledger.close()

    run(body())


def test_actor_submit_after_stop_rejected():
    async def body():
        ledger = await Ledger.open(":memory:")
        await ledger.close()
        with pytest.raises(RaError) as excinfo:
            await ledger.put_artifact("crash", b"late")
        assert excinfo.value.code == "LEDGER_STOPPED"

    run(body())


def test_layout_and_cli_doctor():
    assert layout_check() == []
    import ra.cli.main as cli_main

    assert cli_main.worker_formula(ram_gb=32, cores=8)["workers"] == 6
    assert cli_main._detect_ram_gb() is None or isinstance(cli_main._detect_ram_gb(), float)


def test_cli_doctor_layout_json(tmp_path, capsys):
    db = tmp_path / "ledger.sqlite"
    assert main(["doctor", "--layout", "--db", str(db)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["layout"]["ok"] is True
    assert payload["db"]["exists"] is False


def _make_packaged_layout(root) -> None:
    for rel in (
        "ra/ledger",
        "ra/press",
        "ra/policy",
        "ra/fleet",
        "ra/ring",
        "ra/foundry",
        "ra/discovery",
        "ra/triage",
        "ra/ladder",
        "ra/groom",
        "ra/joins",
        "ra/chain",
        "ra/dup",
        "ra/obs",
        "ra/cli",
        "ra/config",
        "ra/lanes",
        "ra/lanes/macos",
        "ra/lanes/ios",
        "grammars",
        "schemas",
        "migrations",
        "models",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)


def test_layout_check_installed_layout_omits_source_tree(tmp_path):
    _make_packaged_layout(tmp_path)
    assert layout_check(tmp_path) == []


def test_layout_check_source_checkout_requires_source_tree(tmp_path):
    _make_packaged_layout(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    for rel in ("docs", "tests/unit", "tests/golden", "tests/fixtures", "tests/injection"):
        (tmp_path / rel).mkdir(parents=True)
    (tmp_path / "redapple.toml").write_text("", encoding="utf-8")
    assert layout_check(tmp_path) == ["missing tests/load"]


def test_replay_queue_skips_blank_and_non_objects(tmp_path):
    path = tmp_path / "queue.jsonl"
    queue = ReplayQueue(path)
    queue.append({"task_type": "bug_class", "sha": "a" * 64})
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n[1, 2]\n{\"task_type\": \"dedup_match\"}\n")
    assert queue.read_all() == [
        {"task_type": "bug_class", "sha": "a" * 64},
        {"task_type": "dedup_match"},
    ]
    queue.clear()
    assert queue.read_all() == []


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_deepseek_client_retries_and_parses(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append(request)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url, 500, "boom", {}, io.BytesIO(b"bad gateway")
            )
        return _FakeResponse(
            {
                "choices": [
                    {
                        "message": {"content": "{\"answer\": \"ok\"}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 4},
            }
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = DeepSeekClient(api_key="key", endpoint="http://example.test", max_retries=1)
    response = client.chat("sys", "user", temperature=0.0, max_tokens=8, json_object=True)
    assert response.text == "{\"answer\": \"ok\"}"
    assert response.tokens_in == 3 and response.tokens_out == 4
    assert len(calls) == 2


def test_deepseek_client_requires_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(DeepSeekError):
        DeepSeekClient()


def test_validate_output_grammars():
    assert validate_output(TaskType.REPORT_TEXT, "prose", " hello ", ()) == {"text": "hello"}
    with pytest.raises(FormatFail):
        validate_output(TaskType.REPORT_TEXT, "prose", "  ", ())
    assert validate_output(TaskType.DEDUP_MATCH, "enum", '{"answer":"x"}', ("x",)) == {
        "answer": "x"
    }
    with pytest.raises(FormatFail):
        validate_output(TaskType.DEDUP_MATCH, "enum", '{"answer":"y"}', ("x",))
    assert validate_output(TaskType.GROOM_FILL, "numeric", '{"value":1}', ()) == {"value": 1}
    with pytest.raises(FormatFail):
        validate_output(TaskType.GROOM_FILL, "numeric", '{"value":true}', ())
    assert validate_output(TaskType.HARNESS_SYNTH, "code", '{"code":"print(1)"}', ()) == {
        "code": "print(1)"
    }
    with pytest.raises(FormatFail):
        validate_output(TaskType.HARNESS_SYNTH, "code", '{"code":" "}', ())
    assert validate_output(TaskType.GADGET_RANK, "ranked", '{"ranking":["a"]}', ()) == {
        "ranking": ["a"]
    }
    with pytest.raises(FormatFail):
        validate_output(TaskType.GADGET_RANK, "ranked", '{"ranking":[1]}', ())
    assert validate_output(TaskType.CHAIN_STRATEGY, "path", '{"path":["a"],"cost":2}', ()) == {
        "path": ["a"],
        "cost": 2,
    }
    with pytest.raises(FormatFail):
        validate_output(TaskType.CHAIN_STRATEGY, "path", '{"path":["a"],"cost":"bad"}', ())
    with pytest.raises(FormatFail):
        validate_output(TaskType.CHAIN_STRATEGY, "path", '{"path":"a"}', ())
    with pytest.raises(FormatFail):
        validate_output(TaskType.BUG_CLASS, "mystery", "{}", ())


def test_press_harness_local_only_queues_packet(tmp_path):
    async def body():
        harness = PressHarness(local_only=True, queue_path=tmp_path / "queue.jsonl")
        result = await harness.complete(
            TaskType.BUG_CLASS, "classify", artifacts=("artifact",), vocab=("x", "y")
        )
        assert result.offline is True
        assert result.schema_ok is True
        assert result.output == {"answer": "insufficient_evidence"}
        assert harness.queue is not None
        assert len(harness.queue.read_all()) == 1

    run(body())


class _ScriptedClient:
    def __init__(self, texts: list[str]) -> None:
        self.texts = list(texts)
        self.calls = 0

    def chat(self, system, user, *, temperature, max_tokens, json_object) -> ChatResponse:
        self.calls += 1
        text = self.texts.pop(0) if self.texts else '{"answer":"x"}'
        return ChatResponse(text=text, tokens_in=1, tokens_out=2, latency_ms=3)


def test_press_harness_call_route_and_repair():
    async def body():
        client = _ScriptedClient(['{"answer":"x"}'])
        harness = PressHarness(client=client, local_only=False)
        result = await harness.complete(
            TaskType.DEDUP_MATCH, "match", vocab=("x",)
        )
        assert result.offline is False
        assert result.repaired is False
        assert result.tokens_in == 1 and result.tokens_out == 2

        repair_client = _ScriptedClient(["not-json", '{"answer":"x"}'])
        repair_harness = PressHarness(client=repair_client, local_only=False)
        repaired = await repair_harness.complete(TaskType.DEDUP_MATCH, "match", vocab=("x",))
        assert repaired.repaired is True
        assert repair_client.calls == 2

    run(body())


def test_golden_helpers_and_gate(tmp_path):
    path = tmp_path / "golden.jsonl"
    path.write_text(
        "\n"
        + json.dumps(
            {
                "task_type": "bug_class",
                "packet": {"goal": "g"},
                "reference": {"answer": "x"},
            }
        )
        + "\n"
        + json.dumps(
            {
                "task_type": "dedup_match",
                "packet": {"goal": "g"},
                "reference": {"answer": "y"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cases = load_golden(path, "bug_class")
    assert len(cases) == 1 and cases[0].task_type is TaskType.BUG_CLASS
    assert len(load_golden(path)) == 2

    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps([1, 2]) + "\n", encoding="utf-8")
    with pytest.raises(FormatFail):
        load_golden(bad)
    missing = tmp_path / "missing.jsonl"
    missing.write_text(json.dumps({"task_type": "bug_class", "packet": {}}) + "\n")
    with pytest.raises(FormatFail):
        load_golden(missing)

    assert score_output({"answer": "x"}, {"answer": "x"}) == 1.0
    assert score_output({"answer": "x"}, {"answer": "insufficient_evidence"}) == 0.5
    assert score_output({"answer": "x"}, {"answer": "y"}) == 0.0
    assert evaluate_cases([], lambda case: {}) == 0.0
    with pytest.raises(FormatFail):
        check_golden([], lambda case: {})

    rows = [
        GoldenCase(TaskType.BUG_CLASS, {}, {"answer": "x"}) for _ in range(200)
    ]
    report = check_golden(rows, lambda case: {"answer": "insufficient_evidence"}, baseline=1.0)
    assert report.rows == 200
    assert report.route_large_model is False
    assert report.passed is False
    assert report.drop == pytest.approx(0.5)


def test_claim_state_validation_and_promotion_evidence():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            cid = await ledger.create_claim(claim_input("cl_state", "key-state", b"state"))
            with pytest.raises(FormatFail):
                await ledger.transition_claim(cid, "bogus")

            ledger.store._conn.execute("UPDATE claim SET state='reviewed' WHERE id=?", (cid,))
            ledger.store._conn.execute("DELETE FROM claim_artifact WHERE claim_id=?", (cid,))
            with pytest.raises(FormatFail):
                await ledger.transition_claim(cid, ClaimState.PROMOTED)
        finally:
            await ledger.close()

    run(body())


def test_packet_compiler_cache_key_includes_task_type():
    compiler = PacketCompiler()
    artifact_ref = "art_" + "1" * 64
    goal = "same goal for cache collision"
    bug = compiler.compile(
        Packet(TaskType.BUG_CLASS, goal, (artifact_ref,), ("oob_read",))
    )
    rung = compiler.compile(
        Packet(TaskType.RUNG_SELECT, goal, (artifact_ref,), ("oob_read",))
    )
    assert bug.task_type is TaskType.BUG_CLASS
    assert rung.task_type is TaskType.RUNG_SELECT
    assert bug.sha == rung.sha
    assert bug.body == rung.body
    assert bug.route.max_bytes == 6000
    assert rung.route.max_bytes == 5000


def test_sweep_artifacts_respects_pinned_and_claim_links():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.put_artifact("crash", b"pinned", ttl_class="pinned")
            with pytest.raises(FormatFail):
                await ledger.sweep_artifacts("pinned", limit=10)
            assert ledger.artifact_count() == 1

            cid = await ledger.create_claim(claim_input("cl_sweep", "key-sweep", b"linked"))
            assert await ledger.sweep_artifacts("run", limit=10) == 1
            assert ledger.claim_artifact_count(cid) == 0
            assert ledger.artifact_count() == 1

            live_a = await ledger.create_claim(claim_input("cl_live_a", "key-live-a", b"live-a"))
            live_b = await ledger.create_claim(claim_input("cl_live_b", "key-live-b", b"live-b"))
            await ledger.insert_join(
                {
                    "join_id": "join_live",
                    "a_claim": live_a,
                    "b_claim": live_b,
                    "invariants_json": "[]",
                    "reliability": 0.5,
                    "lower_bound": 1.0,
                    "state": "live",
                    "created": 1,
                }
            )
            assert await ledger.sweep_artifacts("run", limit=10) == 0
            assert ledger.artifact_count() == 3
        finally:
            await ledger.close()

    run(body())


def test_validate_output_rejects_non_finite_numbers():
    for raw in ('{"value": NaN}', '{"value": Infinity}', '{"value": -Infinity}'):
        with pytest.raises(FormatFail):
            validate_output(TaskType.GROOM_FILL, "numeric", raw, ())
    with pytest.raises(FormatFail):
        validate_output(TaskType.CHAIN_STRATEGY, "path", '{"path":["a"],"cost":NaN}', ())


def test_record_decision_rejects_negative_spend():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail):
                await ledger.record_decision(
                    trigger_metric="t",
                    observed=1.0,
                    expected="x",
                    spent_usd_micro=-5000,
                    created=1,
                )
            assert ledger.spent_usd_micro() == 0
        finally:
            await ledger.close()

    run(body())


def test_work_order_state_validation_and_transitions():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail):
                await ledger.enqueue_work_order(
                    action="park", unit="u", ev_cost=1.0, state="bogus", created=1
                )
            wid = await ledger.enqueue_work_order(
                action="park", unit="u", ev_cost=1.0, state="ready", created=1
            )
            with pytest.raises(FormatFail):
                await ledger.update_work_order_state(wid, "bogus")
            assert await ledger.update_work_order_state(wid, "parked") is True
            with pytest.raises(FormatFail):
                await ledger.update_work_order_state(wid, "done")
            assert ledger.get_work_order(wid)["state"] == "parked"
        finally:
            await ledger.close()

    run(body())


def test_policy_dispatch_ready_concurrent_single_dispatch():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=1_000_000))
            wid = await engine.plan_action("retarget", "race", probability_join=1.0)
            results = await asyncio.gather(engine.dispatch_ready(), engine.dispatch_ready())
            assert sum(dispatched for dispatched, _refusals in results) == 1
            assert ledger.get_work_order(wid)["state"] == "done"
            assert ledger.spent_usd_micro() == ACTION_COST_USD_MICRO[Action.RETARGET]
        finally:
            await ledger.close()

    run(body())


def test_actor_batch_contains_per_operation_failure():
    async def body():
        ledger = await Ledger.open(":memory:", max_batch_ms=1000, max_batch_rows=10)
        try:
            results = await asyncio.gather(
                ledger.create_run("macos"),
                ledger.enqueue_work_order(action="bogus", unit="u", ev_cost=1.0),
                return_exceptions=True,
            )
            assert isinstance(results[0], str)
            assert isinstance(results[1], FormatFail)
            counts = ledger.counts()
            assert counts["run"] == 1
            assert counts["work_order"] == 0
        finally:
            await ledger.close()

    run(body())
