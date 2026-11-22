import random
import threading
import time

import pytest

from ra.errors import FormatFail
from ra.press import (
    ChatResponse,
    DeepSeekClient,
    DeepSeekError,
    EgressGovernor,
    GoldenCase,
    PacketCompiler,
    PressHarness,
    ReplayQueue,
    TaskType,
    check_golden,
    decode_output,
    load_golden,
    redact_text,
    route_for,
    validate_output,
)
from ra.press.harness import MAX_TOOL_HOP_TOKENS, MAX_TOOL_HOPS
from ra.press.packets import Packet
from tests.conftest import run


def test_RA_MDL_001_routing_table_appendix_d():
    assert route_for(TaskType.BUG_CLASS).max_bytes == 6000
    assert route_for(TaskType.DEDUP_MATCH).max_hops == 0
    assert route_for(TaskType.REPORT_TEXT).escalate == "never"
    assert route_for(TaskType.CHAIN_STRATEGY).escalate == "always"


def test_RA_SEC_001_egress_redaction():
    raw = "mail a@b.com /Users/alice/iPhone 123456789ABC"
    redacted = redact_text(raw)
    assert "a@b.com" not in redacted
    assert "/Users/alice" not in redacted
    assert "123456789ABC" not in redacted
    with pytest.raises(FormatFail):
        validate_output(TaskType.BUG_CLASS, "enum", "not json", ("a",))


def test_RA_MDL_002_packet_compile_cache_and_caps():
    compiler = PacketCompiler()
    packet = Packet(
        TaskType.BUG_CLASS,
        "goal",
        tuple(f"art_{i:064x}" for i in range(3)),
        ("a", "b"),
        "exemplar",
        "near",
    )
    compiled = compiler.compile(packet)
    assert compiled.sha == compiler.compile(packet).sha
    assert compiled.packet.artifacts == packet.artifacts
    with pytest.raises(FormatFail):
        compiler.compile(
            Packet(TaskType.BUG_CLASS, "goal", tuple(f"art_{i:064x}" for i in range(4)))
        )
    long_packet = Packet(TaskType.HARNESS_SYNTH, "x" * 20000, (), (), "e" * 1000, "n" * 1000)
    truncated = compiler.compile(long_packet)
    assert len(truncated.body) <= truncated.route.max_bytes
    assert len(truncated.packet.goal) < len(long_packet.goal)


def test_RA_MDL_003_validate_output_grammars():
    assert validate_output(
        TaskType.BUG_CLASS, "enum", '{"answer":"insufficient_evidence"}', ("a",)
    ) == {"answer": "insufficient_evidence"}
    assert validate_output(TaskType.GROOM_FILL, "numeric", '{"value": 1}', ()) == {"value": 1}
    assert validate_output(TaskType.REPORT_TEXT, "prose", "ok", ()) == {"text": "ok"}
    assert validate_output(TaskType.GADGET_RANK, "ranked", '{"ranking":["x"]}', ()) == {
        "ranking": ["x"]
    }
    assert validate_output(TaskType.CHAIN_STRATEGY, "path", '{"path":["a"],"cost":1}', ()) == {
        "path": ["a"],
        "cost": 1,
    }


def test_RA_MDL_004_replay_queue_offline(tmp_path):
    queue = ReplayQueue(tmp_path / "q.jsonl")
    queue.append({"task_type": "bug_class", "sha": "a" * 64, "packet": {"goal": "g"}})
    assert queue.read_all()[0]["sha"] == "a" * 64
    queue.clear()
    assert queue.read_all() == []


def test_RA_MDL_005_press_harness_local_only():
    async def body():
        harness = PressHarness(local_only=True, queue_path=None)
        result = await harness.complete(TaskType.BUG_CLASS, "goal", vocab=("a", "b"))
        assert result.schema_ok is True
        assert result.output["answer"] == "insufficient_evidence"

    run(body())


def test_RA_MDL_006_deepseek_client_requires_key():
    with pytest.raises(DeepSeekError):
        DeepSeekClient(api_key="", model="deepseek-v4.1-flash")


def test_RA_MDL_007_golden_runner_gate():
    cases = load_golden("tests/golden/bug_class.jsonl", "bug_class")
    assert len(cases) == 200
    report = check_golden(cases, lambda case: {"answer": "insufficient_evidence"})
    assert report.passed is True
    assert report.score == 1.0


def test_RA_MDL_007_golden_drop_gate(tmp_path):
    cases = load_golden("tests/golden/bug_class.jsonl", "bug_class")
    report = check_golden(cases, lambda case: {"answer": "wrong"}, baseline=1.0)
    assert report.passed is False


class _ScriptedChatClient:
    def __init__(self, texts: list[str]) -> None:
        self.texts = list(texts)
        self.calls: list[str] = []
        self.kwargs: list[dict[str, object]] = []

    def chat(self, system, user, *, temperature, max_tokens, json_object) -> ChatResponse:
        self.calls.append(user)
        self.kwargs.append(
            {"temperature": temperature, "max_tokens": max_tokens, "json_object": json_object}
        )
        text = self.texts.pop(0) if self.texts else '{"value":0}'
        return ChatResponse(text=text, tokens_in=1, tokens_out=2, latency_ms=1)


def test_RA_MDL_egress_governor_rate_backoff_and_concurrency():
    now = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    governor = EgressGovernor(
        rate_per_s=2.0,
        max_concurrent=1,
        clock=lambda: now[0],
        sleep=sleep,
        rng=random.Random(7),
    )
    with governor.permit():
        assert governor.in_flight == 1
    assert governor.in_flight == 0
    rate_governor = EgressGovernor(
        rate_per_s=2.0,
        max_concurrent=1,
        clock=lambda: now[0],
        sleep=sleep,
        rng=random.Random(7),
    )
    with rate_governor.permit():
        pass
    with rate_governor.permit():
        pass
    with rate_governor.permit():
        pass
    assert sleeps == [0.5]
    delay = governor.backoff_wait(0)
    assert 0.0 <= delay <= 2.0
    assert 0.0 <= governor.backoff_delay(10) <= 60.0


def test_RA_MDL_egress_governor_concurrency_cap():
    governor = EgressGovernor(rate_per_s=1000.0, max_concurrent=1, rng=random.Random(0))
    acquired = threading.Event()
    release = threading.Event()

    def worker() -> None:
        with governor.permit():
            acquired.set()
            release.wait(1)

    with governor.permit():
        thread = threading.Thread(target=worker)
        thread.start()
        assert not acquired.wait(0.1)
    thread.join(1)
    assert acquired.is_set()


def test_RA_MDL_tool_hops_cap_tokens_and_timeout():
    async def body():
        tool_args: list[dict[str, object]] = []

        def lookup(arguments):
            tool_args.append(dict(arguments))
            return {"ok": True}

        client = _ScriptedChatClient(
            [
                '{"tool":"lookup","arguments":{"q":"x"}}',
                '{"tool":"lookup","arguments":{"q":"y"}}',
                '{"value":7}',
            ]
        )
        harness = PressHarness(client=client, tools={"lookup": lookup})
        result = await harness.complete(TaskType.GROOM_FILL, "goal", vocab=())
        assert result.output == {"value": 7}
        assert result.repaired is False
        assert tool_args == [{"q": "x"}, {"q": "y"}]
        assert len(client.calls) == 3
        assert MAX_TOOL_HOPS == 2
        assert MAX_TOOL_HOP_TOKENS == 4000
        assert all(item["max_tokens"] == MAX_TOOL_HOP_TOKENS for item in client.kwargs)

        timed = await harness._run_sample(
            TaskType.GROOM_FILL,
            route_for(TaskType.GROOM_FILL),
            "user",
            (),
            time.perf_counter() - 91.0,
        )
        assert timed.timed_out is True
        assert timed.responses == ()

    run(body())


def test_RA_MDL_decode_time_grammar_constraint():
    fenced = 'prefix ```json\n{"answer":"A"}\n``` suffix'
    assert decode_output(TaskType.BUG_CLASS, "enum", fenced, ("a",)) == {"answer": "a"}
    assert decode_output(TaskType.GROOM_FILL, "numeric", 'noise {"value": 3} trailing', ()) == {
        "value": 3
    }
    with pytest.raises(FormatFail):
        decode_output(TaskType.GROOM_FILL, "numeric", '{"value": NaN}', ())
    with pytest.raises(FormatFail):
        decode_output(TaskType.BUG_CLASS, "enum", '{"answer":"nope"}', ("a",))


@pytest.mark.parametrize(
    "task_type", [task_type for task_type in TaskType if task_type is not TaskType.BUG_CLASS]
)
def test_RA_MDL_007_large_model_route_beyond_bug_class(task_type):
    cases = [GoldenCase(task_type, {"goal": "g"}, {"answer": "insufficient_evidence"})]
    report = check_golden(cases, lambda case: {"answer": "insufficient_evidence"})
    assert report.route_large_model is True
    assert report.passed is True


def test_RA_MDL_010_compile_p99_under_load_percentile():
    from tests.load import harness as load_harness

    compiler = PacketCompiler()
    samples: list[float] = []
    for index in range(2000):
        packet = Packet(
            TaskType.BUG_CLASS,
            f"goal {index}",
            (f"art_{index:064x}",),
            ("oob_read",),
        )
        start = time.perf_counter()
        compiler.compile(packet)
        samples.append((time.perf_counter() - start) * 1000)
    assert load_harness.percentile(samples, 0.99) <= 8.0
