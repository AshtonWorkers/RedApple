import json

from ra.ledger import ClaimState, Ledger
from ra.press import ChatResponse, DeepSeekError, PressHarness
from ra.triage import (
    BUG_CLASS_VOCAB,
    CRASH_CLASS_VOCAB,
    DEDUP_THRESHOLD,
    MINHASH_SIZE,
    AssessmentResult,
    ClassifyResult,
    ClassifyStatus,
    CrashEvidence,
    DedupSignature,
    DefaultSymbolicator,
    PocResult,
    PressBugClassClassifier,
    PressTriageAssessor,
    StubLaneSymbolicator,
    TriageService,
    bug_class_hint,
    build_signature,
    crash_class_hint,
    evidence_text,
    exploitability_signals,
    extract_frames,
    heuristic_assessment,
    minhash128,
    minhash_similarity,
    normalize_assessment,
    normalize_frame,
    parse_json_object,
)
from ra.triage.dedup import TriageDeduper
from ra.triage.dedup import signature_elements as dedup_signature_elements
from ra.triage.evidence import metadata_text, normalized_frames, stack_hash, target_dict
from ra.triage.sanitize import (
    clean_text,
    json_dumps_safe,
    json_safe,
    safe_float,
    safe_int,
    safe_int_or_none,
)
from ra.triage.symbolication import coerce_symbolized
from tests.conftest import run

FRAMES = (
    "WebKit::JavaScriptCore::arrayProtoFuncPop(JSC::JSGlobalObject*)",
    "JSC::JITCode::execute(JSC::CallFrame*)",
    "WTF::fastFree(void*)",
)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def chat(self, system, user, *, temperature, max_tokens, json_object):
        self.calls.append(
            {
                "system": system,
                "user": user,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "json_object": json_object,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected model call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return ChatResponse(text=str(item), tokens_in=1, tokens_out=1)


def enum_response(answer):
    return json.dumps({"answer": answer})


def insufficient_responses(count=3):
    return [enum_response("insufficient_evidence") for _ in range(count)]


def assessment_payload(*, variants=None, rating="high"):
    return json.dumps(
        {
            "root_cause": "Array length confusion during pop.",
            "crash_class": "use-after-free",
            "exploitability": {
                "rating": rating,
                "assessment": "Reachable from JS with a controlled free.",
                "primitive": "reclaim after free",
            },
            "impact": "Renderer memory corruption.",
            "variant_ideas": ["shift length by one", "retry after gc"],
            "variants": variants or [],
            "dedup_note": "Same stack as prior JSC pop crash.",
        }
    )


def poc_markdown():
    return "# PoC\n\n## Summary\nUAF in JSC array pop.\n\n## Disclosure note\nReport to Apple."


def make_crash(crash_id="crash-1", *, alloc_site="site-a", payload=b"crash payload"):
    return CrashEvidence(
        id=crash_id,
        kind="webkit_jsc",
        payload=payload,
        path="/tmp/crash.ips",
        context="app",
        created_ms=1_700_000_000_000,
        metadata={
            "frames": list(FRAMES),
            "signal": "SIGSEGV",
            "returncode": -11,
            "crash_type": "EXC_BAD_ACCESS",
            "alloc_site": alloc_site,
            "target": {"revision": "iOS-17-0", "build_type": "release", "sanitizers": ["asan"]},
        },
    )


def test_RA_TRG_evidence_stack_and_hint_helpers():
    text = """
    ==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1234
        #0 0x100 abc in WebKit::JavaScriptCore::arrayProtoFuncPop file.js:10
        #1 0x101 def in JSC::JITCode::execute file.js:20
        #2 0x102 ghi in libsystem_kernel.dylib start_wqthread
    """
    frames = extract_frames(text)
    assert frames[0].startswith("WebKit::JavaScriptCore")
    assert all("libsystem" not in frame.lower() for frame in frames)
    assert normalize_frame("0x100 WebKit::Foo +0x10") == "0x webkit::foo +0x"
    explicit = CrashEvidence(
        id="crash-explicit",
        kind="webkit_jsc",
        metadata={"bug_class": "oob_write", "frames": list(FRAMES)},
    )
    assert bug_class_hint(explicit, FRAMES) == "oob_write"
    hinted = make_crash(crash_id="crash-2", payload=b"heap-use-after-free in jsc")
    hinted = CrashEvidence(
        id="crash-2",
        kind="webkit_jsc",
        payload=b"heap-use-after-free in jsc",
        metadata={"frames": list(FRAMES)},
    )
    assert bug_class_hint(hinted, FRAMES) == "uaf"
    assert evidence_text(hinted).startswith("heap-use-after-free")


def test_RA_TRG_minhash_threshold_and_signature_shape():
    elements = dedup_signature_elements(FRAMES, "stderr")
    signature = minhash128(elements)
    assert len(signature) == MINHASH_SIZE
    assert minhash_similarity(signature, minhash128(elements)) == 1.0
    other = minhash128(("0:completely", "1:different", "pair:a>b"))
    assert minhash_similarity(signature, other) < DEDUP_THRESHOLD
    assert minhash_similarity(signature, ()) == 0.0
    empty = dedup_signature_elements((), "plain stderr 0x1234")
    assert empty[0].startswith("nostack:")
    assert "0x1234" not in empty[0]


def test_RA_TRG_signature_dedup_key_roundtrip():
    crash = make_crash()
    symbolized = run(DefaultSymbolicator().symbolize(crash))
    signature = build_signature(crash, symbolized)
    assert len(signature.signature) == MINHASH_SIZE
    assert signature.frames == tuple(normalize_frame(frame) for frame in FRAMES[:5])
    restored = DedupSignature.from_dict(signature.to_dict())
    assert restored.dedup_key == signature.dedup_key
    assert restored.signature == signature.signature
    bad = DedupSignature.from_dict({"frames": "not-a-list", "signature": {"bad": 1}})
    assert bad.frames == () and bad.signature == ()


def test_RA_TRG_symbolication_metadata_stack_and_stub():
    async def body():
        crash = CrashEvidence(
            id="crash-stack",
            kind="ios_crash",
            metadata={"stack": "frame one\nframe two\n", "signal": "SIGABRT"},
        )
        symbolized = await DefaultSymbolicator().symbolize(crash)
        assert symbolized.frames == ("frame one", "frame two")
        assert symbolized.source == "metadata"
        stub = await StubLaneSymbolicator().symbolize(crash)
        assert stub.crash_id == "crash-stack"
        assert stub.symbolicated is True

    run(body())


def test_RA_TRG_classifier_bound_uses_three_zero_temp_samples():
    async def body():
        client = FakeClient([enum_response("uaf")] * 3)
        harness = PressHarness(client=client)
        classifier = PressBugClassClassifier(harness)
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "bound"
        assert result.answer == "uaf"
        assert result.confidence == 0.9
        assert len(result.packets) == 1
        assert len(client.calls) == 3
        assert {call["temperature"] for call in client.calls} == {0.0}
        assert all(call["json_object"] for call in client.calls)

    run(body())


def test_RA_TRG_classifier_split_without_escalation_parks():
    async def body():
        client = FakeClient(insufficient_responses(3))
        classifier = PressBugClassClassifier(PressHarness(client=client))
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "split"
        assert result.error_code == "TRIAGE_SPLIT"
        assert len(client.calls) == 3

    run(body())


def test_RA_TRG_classifier_disagreement_becomes_insufficient_then_split():
    async def body():
        client = FakeClient(
            [enum_response("uaf"), enum_response("oob_write"), enum_response("uaf")]
        )
        classifier = PressBugClassClassifier(PressHarness(client=client))
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "split"
        assert result.answer == "insufficient_evidence"

    run(body())


def test_RA_TRG_classifier_escalates_once_and_accepts_large_model_answer():
    async def body():
        primary = FakeClient(insufficient_responses(3))
        escalation = FakeClient([enum_response("type_confusion")] * 3)
        classifier = PressBugClassClassifier(
            PressHarness(client=primary),
            escalation_harness=PressHarness(client=escalation),
        )
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "escalated"
        assert result.answer == "type_confusion"
        assert result.confidence == 0.75
        assert len(result.packets) == 2
        assert len(primary.calls) == 3
        assert len(escalation.calls) == 3

    run(body())


def test_RA_TRG_classifier_model_error_is_retryable_error_result():
    async def body():
        client = FakeClient([DeepSeekError("boom")])
        classifier = PressBugClassClassifier(PressHarness(client=client))
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "error"
        assert result.error_code == "MODEL_EGRESS"

    run(body())


def test_RA_TRG_assessment_contract_parse_normalize_and_fallback():
    fenced = "```json\n" + assessment_payload(rating="bogus") + "\n```"
    parsed = parse_json_object(fenced)
    assert parsed is not None and parsed["root_cause"].startswith("Array")
    normalized = normalize_assessment(parsed, "uaf")
    assert normalized["crash_class"] == "use-after-free"
    assert normalized["exploitability"]["rating"] == "high"
    assert len(normalized["variant_ideas"]) == 2
    fallback = heuristic_assessment(make_crash(), run(DefaultSymbolicator().symbolize(make_crash())), "oob_write")
    assert fallback["exploitability"]["rating"] == "high"
    assert fallback["variants"] == []
    bad = normalize_assessment({"exploitability": "bad", "crash_class": "not-a-class"}, "other")
    assert bad["crash_class"] == "other"
    assert bad["exploitability"]["rating"] == "low"


def test_RA_TRG_assessor_local_only_falls_back_and_poc_empty():
    async def body():
        harness = PressHarness(local_only=True)
        assessor = PressTriageAssessor(harness)
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        assessment = await assessor.assess(crash, symbolized, "uaf", artifacts=("art_a", "art_b"))
        assert assessment.source == "fallback"
        assert assessment.error_code == "FORMAT_FAIL"
        assert assessment.data["dedup_note"].startswith("Deterministic fallback")
        poc = await assessor.write_poc(crash, symbolized, assessment.data, "uaf")
        assert poc.markdown == ""
        assert poc.source == "press"

    run(body())


class RecordingReplayer:
    def __init__(self):
        self.calls = []

    async def replay(self, variant):
        self.calls.append(dict(variant))
        return {"result": "crashed", "signature": "sig-1"}


def _bound_responses(assessment=None, poc=None):
    return [
        enum_response("uaf"),
        enum_response("uaf"),
        enum_response("uaf"),
        assessment or assessment_payload(),
        poc or poc_markdown(),
    ]


def test_RA_TRG_service_bound_claim_persists_contract_and_artifacts():
    async def body():
        client = FakeClient(_bound_responses())
        harness = PressHarness(client=client)
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, harness)
            result = await service.triage(make_crash())
            assert result.status.value == "bound"
            assert result.bug_class == "uaf"
            assert result.claim_state == "bound"
            assert len(result.packets) == 3
            assert result.value["root_cause"].startswith("Array")
            assert result.value["poc_writeup_md"].startswith("# PoC")
            assert len(result.value["dedup"]["signature"]) == MINHASH_SIZE
            row = ledger.get_claim(result.claim_id)
            assert row is not None and row["state"] == "bound"
            assert row["type"] == "bug_class"
            assert ledger.claim_artifact_count(result.claim_id) == 3
            assert ledger.integrity_check() == "ok"
            assert len(client.calls) == 5
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_duplicate_exact_and_minhash_link_without_model_calls():
    async def body():
        client = FakeClient(_bound_responses())
        harness = PressHarness(client=client)
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, harness)
            first = await service.triage(make_crash("crash-a", alloc_site="site-a"))
            exact = await service.triage(make_crash("crash-b", alloc_site="site-a"))
            near = await service.triage(make_crash("crash-c", alloc_site="site-b"))
            assert first.status.value == "bound"
            assert exact.status.value == "duplicate"
            assert exact.duplicate_of == first.claim_id
            assert exact.claim_state == "limbo"
            assert near.status.value == "duplicate"
            assert near.duplicate_of == first.claim_id
            assert len(client.calls) == 5
            states = [ledger.get_claim(item.claim_id)["state"] for item in (first, exact, near)]
            assert states == ["bound", "limbo", "limbo"]
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_split_parks_claim_with_triage_split():
    async def body():
        client = FakeClient(insufficient_responses(3))
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(client=client))
            result = await service.triage(make_crash())
            assert result.status.value == "parked"
            assert result.error_code == "TRIAGE_SPLIT"
            assert result.claim_state == "parked"
            assert result.value["park_reason"] == "TRIAGE_SPLIT"
            assert ledger.get_claim(result.claim_id)["state"] == "parked"
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_model_error_parks_claim():
    async def body():
        client = FakeClient([DeepSeekError("down")])
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(client=client))
            result = await service.triage(make_crash())
            assert result.status.value == "parked"
            assert result.error_code == "MODEL_EGRESS"
            assert result.claim_state == "parked"
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_variant_replay_is_recorded_on_claim():
    async def body():
        variants = [
            {"id": "v1", "description": "pop after length shrink", "code": "let a=[1]; a.length=0; a.pop();"}
        ]
        responses = _bound_responses(assessment=assessment_payload(variants=variants))
        replayer = RecordingReplayer()
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(client=FakeClient(responses)), replayer=replayer)
            result = await service.triage(make_crash())
            assert result.status.value == "bound"
            assert replayer.calls[0]["id"] == "v1"
            assert result.value["variants"][0]["replay"]["result"] == "crashed"
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_unavailable_variant_replayer_marks_unverified():
    async def body():
        variants = [{"id": "v1", "description": "variant", "code": "code"}]
        responses = _bound_responses(assessment=assessment_payload(variants=variants))
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(client=FakeClient(responses)))
            result = await service.triage(make_crash())
            assert result.status.value == "bound"
            assert result.value["variants"][0]["replay"]["result"] == "unverified"
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_local_only_packs_offline_packets():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(local_only=True))
            result = await service.triage(make_crash())
            assert result.status.value == "parked"
            assert result.error_code == "TRIAGE_SPLIT"
            assert result.packets[0].offline is True
            assert ledger.get_claim(result.claim_id)["state"] == "parked"
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_contract_vocab_and_parse_edge():
    assert ClaimState.LIMBO.value == "limbo"
    assert set(BUG_CLASS_VOCAB) == {
        "uaf",
        "type_confusion",
        "oob_write",
        "info_leak",
        "oob_read",
        "other",
    }
    assert parse_json_object("not json") is None
    assert parse_json_object('{"answer":"uaf"}') == {"answer": "uaf"}


def test_RA_TRG_evidence_edge_helpers():
    crash = CrashEvidence(
        id="edge",
        kind="kind",
        metadata={"report": "report text", "stderr": "stderr text", "stdout": ""},
    )
    assert metadata_text(crash) == "report text\nstderr text"
    assert normalized_frames(FRAMES, depth=2) == tuple(normalize_frame(frame) for frame in FRAMES[:2])
    assert stack_hash((), "fallback 0x1234") == stack_hash((), "fallback 0x1234")
    target = target_dict(
        crash,
        {"revision": "rev-symbol", "build_type": "release", "sanitizers": ["asan"], "extra": "ignored"},
    )
    assert target == {"revision": "rev-symbol", "build_type": "release", "sanitizers": ["asan"]}


def test_RA_TRG_classifier_escalation_error_and_split():
    async def error_body():
        primary = FakeClient(insufficient_responses(3))
        escalation = FakeClient([DeepSeekError("escalation down")])
        classifier = PressBugClassClassifier(
            PressHarness(client=primary), escalation_harness=PressHarness(client=escalation)
        )
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "error"
        assert result.error_code == "MODEL_EGRESS"
        assert len(result.packets) == 1

    run(error_body())

    async def split_body():
        primary = FakeClient(insufficient_responses(3))
        escalation = FakeClient(insufficient_responses(3))
        classifier = PressBugClassClassifier(
            PressHarness(client=primary), escalation_harness=PressHarness(client=escalation)
        )
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        result = await classifier.classify(crash, symbolized)
        assert result.status.value == "split"
        assert result.error_code == "TRIAGE_SPLIT"
        assert len(result.packets) == 2

    run(split_body())


def test_RA_TRG_assessor_fallback_json_poc_and_variant_errors():
    class RaisingReplayer:
        async def replay(self, variant):
            raise DeepSeekError("replay down")

    async def body():
        crash = make_crash()
        symbolized = await DefaultSymbolicator().symbolize(crash)
        failing = PressTriageAssessor(
            PressHarness(client=FakeClient([DeepSeekError("boom"), DeepSeekError("boom")]))
        )
        assessed = await failing.assess(crash, symbolized, "uaf")
        assert assessed.source == "fallback"
        assert assessed.error_code == "MODEL_EGRESS"
        poc = await failing.write_poc(crash, symbolized, {"root_cause": "x"}, "uaf")
        assert poc.source == "fallback"
        assert poc.error_code == "MODEL_EGRESS"
        assert poc.markdown == ""

        json_poc = PressTriageAssessor(
            PressHarness(client=FakeClient([json.dumps({"poc_writeup_md": "# PoC\n\n## Summary\nok"})]))
        )
        written = await json_poc.write_poc(crash, symbolized, {"root_cause": "x"}, "uaf")
        assert written.source == "press"
        assert written.markdown.startswith("# PoC")

        variants = [{"id": "v1", "description": "one"}, {"id": "v2", "description": "two"}, "skip"]
        replaying = PressTriageAssessor(
            PressHarness(client=FakeClient([assessment_payload(variants=variants)])),
            replayer=RaisingReplayer(),
        )
        annotated = await replaying.assess(crash, symbolized, "uaf")
        assert annotated.data["variants"][0]["replay"] == {"result": "error", "detail": "MODEL_EGRESS"}
        assert annotated.data["variants"][1]["replay"] == {"result": "error", "detail": "MODEL_EGRESS"}

    run(body())


def test_RA_TRG_service_no_payload_uses_metadata_fallback():
    async def body():
        crash = CrashEvidence(
            id="crash-nopayload",
            kind="webkit_jsc",
            metadata={
                "report": "heap-use-after-free in jsc",
                "frames": list(FRAMES),
                "alloc_site": "site-a",
                "target": {"revision": "iOS-17-0", "build_type": "release", "sanitizers": ["asan"]},
            },
        )
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(client=FakeClient(_bound_responses())))
            result = await service.triage(crash)
            assert result.status.value == "bound"
            assert len(result.artifacts) == 3
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_sanitize_helpers_bound_hostile_values():
    noisy = b"\xff\x00A" * 2000
    cleaned = clean_text(noisy, limit=32, keep_newlines=False)
    assert len(cleaned) <= 32
    assert "\x00" not in cleaned and "�" in cleaned
    assert clean_text(object(), limit=12).startswith("<object")
    deep = {}
    cursor = deep
    for _ in range(8):
        cursor["x"] = {}
        cursor = cursor["x"]
    assert json_safe(deep) is not None
    safe = json_safe({"items": [1, 2.5, float("nan"), b"\xffx", {"bad": object()}], "bytes": bytearray(b"ok")})
    assert safe["items"][2] is None and safe["items"][3] == "�x"
    assert json.loads(json_dumps_safe({"ok": object(), "n": float("nan")})) == {"n": None, "ok": None}
    assert safe_int("123") == 123
    assert safe_int("9" * 30, 7) == 7
    assert safe_int(None, 7) == 7
    assert safe_int(float("nan"), 7) == 7
    assert safe_int_or_none("12") == 12
    assert safe_int_or_none(None) is None
    assert safe_float("1.5") == 1.5
    assert safe_float("nan", 2.0) == 2.0
    assert safe_float(object(), 3.0) == 3.0
    assert safe_float(None, 5.0) == 5.0
    assert safe_int(True, 7) == 7
    assert safe_int_or_none(True) is None
    assert safe_int(1.5, 7) == 7
    assert safe_int_or_none(1.5) is None
    assert safe_int("1" * 21, 7) == 7
    assert safe_float("x", 4.0) == 4.0
    assert json_safe({"set": {"b", "a", 1}})["set"] == ["a", "b", 1]
    weird = json_safe({(1, 2): "bad", "": "skip", "ok": (1, 2)})
    assert weird["ok"] == [1, 2] and weird["(1, 2)"] == "bad" and "" not in weird


def test_RA_TRG_adversarial_crash_input_is_bounded_and_deterministic():
    payload = (
        b"\xff\xfe"
        + b"A" * 200_000
        + b"\n#0 0x100 in WebKit::Foo foo.cpp:1\n"
        + b"#1 0x101 in JSC::Bar bar.cpp:2\n" * 5000
    )
    crash = CrashEvidence(
        id="crash-hostile",
        kind="webkit_jsc\x00injected",
        payload=payload,
        path="/tmp/crash.ips",
        context="ctx",
        created_ms="not-an-int",
        metadata={
            "frames": {"bad": "not frames"},
            "report": "use-after-poison " + "x" * 5000,
            "target": ["not", "mapping"],
            "alloc_site": b"\xffalloc",
            "returncode": "bad",
        },
    )
    first_text = evidence_text(crash)
    second_text = evidence_text(crash)
    assert first_text == second_text
    assert len(first_text) <= 20_000
    assert crash_class_hint(crash) in CRASH_CLASS_VOCAB
    assert bug_class_hint(crash) in BUG_CLASS_VOCAB
    symbolized = run(DefaultSymbolicator().symbolize(crash))
    coerced = coerce_symbolized(symbolized, crash)
    first_signature = build_signature(crash, symbolized)
    second_signature = build_signature(crash, coerced)
    assert first_signature.dedup_key == second_signature.dedup_key
    assert first_signature.created_ms == 0
    assert len(coerced.frames) <= 12


def test_RA_TRG_symbolication_coerces_hostile_provider_output():
    crash = make_crash()
    raw = {
        "crash_id": b"\xff" + b"x" * 5000,
        "crash_type": 123,
        "frames": ["ok", {"bad": 1}, b"\xffframe", None, "", "  "],
        "signal": "SIGSEGV",
        "returncode": "bad",
        "stderr": "s" * 5000,
        "repro": object(),
        "target": {"revision": "ios", "evil": object(), "list": [1, object()]},
        "symbolicated": "yes",
        "source": "provider",
    }
    coerced = coerce_symbolized(raw, crash)
    assert coerced.crash_id.startswith("�") and len(coerced.crash_id) <= 128
    assert coerced.crash_type == "EXC_BAD_ACCESS"
    assert coerced.frames[0] == "ok"
    assert coerced.frames[-1].startswith("�")
    assert all(len(frame) <= 240 for frame in coerced.frames)
    assert coerced.returncode == -11
    assert len(coerced.stderr) == 3000
    assert isinstance(coerced.repro, str) and len(coerced.repro) <= 8000
    assert coerced.target["revision"] == "ios"
    assert coerced.target["evil"] is None
    invalid = coerce_symbolized(object(), crash)
    assert invalid.source == "metadata" and invalid.frames[0].startswith("WebKit")
    empty = coerce_symbolized(object(), CrashEvidence(id="empty", kind="k"))
    assert empty.source == "invalid"


def test_RA_TRG_assessment_hostile_model_output_is_bounded():
    assert parse_json_object("{" * 10_000 + "}" * 10_000) is None
    hostile = normalize_assessment(
        {
            "root_cause": "use-after-free " + "x" * 5000,
            "crash_class": "double free",
            "exploitability": {
                "rating": "bogus",
                "assessment": "reachable " + "y" * 5000,
                "primitive": "reclaim",
                "signals": ["js_reachable", "js_reachable", 3, "x" * 2000],
            },
            "impact": "impact " + "z" * 5000,
            "variant_ideas": ["idea", {"bad": 1}, "idea"],
            "variants": [{"id": "v1", "description": "desc", "code": "code"}],
            "signals": ["free_reclaim"],
        },
        "uaf",
    )
    assert hostile["crash_class"] in CRASH_CLASS_VOCAB
    assert hostile["exploitability"]["rating"] in {"low", "medium", "high"}
    assert len(hostile["exploitability"]["assessment"]) <= 1200
    assert hostile["variant_ideas"] == ["idea"]
    assert hostile["variants"][0]["id"] == "v1"
    crash = make_crash()
    symbolized = run(DefaultSymbolicator().symbolize(crash))
    signals = exploitability_signals(crash, symbolized, "uaf")
    assert "js_reachable" in signals and "memory_fault" in signals
    assert exploitability_signals(crash, symbolized, "uaf") == signals


def test_RA_TRG_service_failure_injection_keeps_claim_well_formed():
    class RaisingSymbolicator:
        async def symbolize(self, crash):
            raise RuntimeError("symbolication exploded")

    class RaisingClassifier:
        async def classify(self, crash, symbolized, *, artifacts=()):
            raise RuntimeError("classifier exploded")

    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            harness = PressHarness(client=FakeClient(_bound_responses()))
            service = TriageService(
                ledger,
                harness,
                symbolicator=RaisingSymbolicator(),
                classifier=RaisingClassifier(),
            )
            result = await service.triage(make_crash(crash_id="hostile-claim"))
            assert result.status.value == "parked"
            claim = ledger.get_claim(result.claim_id)
            assert claim is not None
            value = json.loads(claim["value_json"])
            assert value["schema"] == "ra.triage.v1"
            assert value["triage_status"] == "parked"
            assert value["bug_class"] in BUG_CLASS_VOCAB
            assert value["crash_class"] in CRASH_CLASS_VOCAB
            assert isinstance(value["dedup"], dict)
            assert isinstance(value["target"], dict)
            assert value["error_code"] == "MODEL_ERROR"
            assert value["park_reason"] == "MODEL_ERROR"
            assert isinstance(value["packets"], list)
            assert isinstance(value["symbolication"]["frames"], list)
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_service_output_is_deterministic_for_fixed_inputs():
    async def triage_once():
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(ledger, PressHarness(client=FakeClient(_bound_responses())))
            return await service.triage(make_crash(crash_id="deterministic"))
        finally:
            await ledger.close()

    async def body():
        first = await triage_once()
        second = await triage_once()
        assert first.status == second.status
        assert first.value == second.value
        assert first.artifacts == second.artifacts

    run(body())


def test_RA_TRG_service_sanitizes_hostile_classifier_and_assessment():
    class BadBool:
        def __bool__(self):
            raise RuntimeError("bool exploded")

    class HostileClassifier:
        async def classify(self, crash, symbolized, *, artifacts=()):
            return ClassifyResult(
                "not-a-class",
                ClassifyStatus.BOUND,
                float("nan"),
                ({"task_type": "bug_class", "sha": "s" * 64, "offline": BadBool()}, "bad", None),
            )

    class HostileAssessor:
        async def assess(self, crash, symbolized, bug_class, *, artifacts=()):
            return AssessmentResult(
                {
                    "root_cause": b"\xff" * 5000,
                    "crash_class": "not-a-class",
                    "exploitability": {
                        "rating": "bogus",
                        "assessment": "reachable " + "y" * 5000,
                        "primitive": "reclaim",
                        "signals": ["a", 1, "b" * 2000],
                    },
                    "impact": object(),
                    "variant_ideas": "one\ntwo",
                    "variants": [
                        {"id": "v1", "description": "desc", "code": "code", "replay": object()},
                        "bad",
                        {"description": "only"},
                    ],
                    "dedup_note": "note",
                    "signals": "sig",
                },
                (),
                "press",
                None,
            )

        async def write_poc(self, crash, symbolized, assessment, bug_class, *, artifacts=()):
            return PocResult("# PoC\n" + "x" * 50_000, (), "press", None)

    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            service = TriageService(
                ledger,
                PressHarness(client=FakeClient([])),
                classifier=HostileClassifier(),
                assessor=HostileAssessor(),
            )
            result = await service.triage(make_crash(crash_id="hostile-service"))
            assert result.status.value == "bound"
            value = result.value
            assert value["bug_class"] in BUG_CLASS_VOCAB
            assert value["crash_class"] == "other"
            assert value["exploitability"]["rating"] in {"low", "medium", "high"}
            assert len(value["exploitability"]["assessment"]) <= 1200
            assert value["variant_ideas"] == ["one", "two"]
            assert value["variants"][0]["replay"] == {"result": "error", "detail": "REPLAY_SHAPE"}
            assert value["signals"] == ["sig"]
            assert len(value["poc_writeup_md"]) <= 20_000
            packets = value["packets"]
            assert len(packets) == 1
            assert packets[0]["task_type"] == "bug_class"
            assert packets[0]["offline"] is False
        finally:
            await ledger.close()

    run(body())


def test_RA_TRG_deduper_ignores_malformed_ledger_claims():
    crash = make_crash(crash_id="dedup-hostile")
    symbolized = run(DefaultSymbolicator().symbolize(crash))
    signature = build_signature(crash, symbolized)
    rows = [
        {"id": "bad-json", "type": "bug_class", "value_json": "{ "},
        {"id": "bad-list", "type": "bug_class", "value_json": "[1]"},
        {
            "id": "bad-dedup",
            "type": "bug_class",
            "value_json": json.dumps({"triage_status": "bound", "dedup": "nope"}),
        },
        {
            "id": "duplicate",
            "type": "bug_class",
            "value_json": json.dumps({"triage_status": "duplicate", "dedup": signature.to_dict()}),
        },
        {
            "id": "good",
            "type": "bug_class",
            "value_json": json.dumps({"triage_status": "bound", "dedup": signature.to_dict()}),
        },
    ]

    class FakeLedger:
        def claim_by_dedup(self, dedup_key):
            return None

        def claims_by_type(self, claim_type, *, limit=10_000):
            return rows

    assert TriageDeduper(FakeLedger()).find_duplicate(signature) == ("good", 1.0)


def test_RA_TRG_evidence_edge_branches_are_bounded():
    assert metadata_text(make_crash(), limit=0) == ""
    assert extract_frames("", limit=0) == ()
    lines = "\n".join(
        [
            "#1 0x101 def in libsystem_kernel.dylib start_wqthread",
            "#2 0x102 ghi SomeFunc (somefile.cpp:20)",
            "#3 0x103 jkl PlainHashFrame",
            "frame #4: PrefixFrame",
            "main",
        ]
    )
    frames = extract_frames(lines, limit=10)
    assert any("SomeFunc" in frame for frame in frames)
    assert any("PlainHashFrame" in frame for frame in frames)
    assert any("PrefixFrame" in frame for frame in frames)
    assert all("libsystem" not in frame.lower() for frame in frames)
    assert normalized_frames({"not": "frames"}) == ()
    assert normalized_frames([None, "", "ok"], depth=0) == ()
    crash = CrashEvidence(
        id="edge",
        kind="k",
        metadata={
            "bug_class": "oob-write",
            "crash_class": "stack-exhaustion",
            "target": {"": "skip", "revision": object(), "sanitizers": ["asan"]},
            "report": "only metadata",
        },
    )
    assert bug_class_hint(crash) == "oob_write"
    assert crash_class_hint(crash) == "stack-exhaustion"
    assert target_dict(crash) == {"sanitizers": ["asan"]}
    merged = target_dict(crash, {"revision": "r2", "build_type": object(), "sanitizers": "bad"})
    assert merged["revision"] == "r2"
    assert "build_type" not in merged
    assert merged["sanitizers"] == ["asan"]
    bad = CrashEvidence(id="edge2", kind="k", metadata={"bug_class": "bad", "crash_class": "bad", "report": ""})
    assert bug_class_hint(bad) in BUG_CLASS_VOCAB
    assert crash_class_hint(bad) == "other"
    assert bug_class_hint(bad, (), symbolized=True) in BUG_CLASS_VOCAB
    assert crash_class_hint(bad, (), symbolized=True) == "other"
