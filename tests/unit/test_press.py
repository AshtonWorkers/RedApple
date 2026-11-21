import pytest

from ra.errors import FormatFail
from ra.press import (
    DeepSeekClient,
    DeepSeekError,
    PacketCompiler,
    PressHarness,
    ReplayQueue,
    TaskType,
    check_golden,
    load_golden,
    redact_text,
    route_for,
    validate_output,
)
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
