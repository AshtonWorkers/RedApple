"""PRESS model harness (RA-MDL)."""

from __future__ import annotations

import asyncio
import json
import math
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import FormatFail
from .client import ChatResponse, DeepSeekClient, ModelClient, ReplayQueue
from .packets import CompiledPacket, Packet, PacketCompiler
from .redact import redact_text
from .routing import RouteSpec, TaskType, route_for

MAX_OUTPUT_TOKENS = 4_000
MAX_TASK_SECONDS = 90.0
MAX_TOOL_HOPS = 2
MAX_TOOL_HOP_TOKENS = MAX_OUTPUT_TOKENS
MAX_TOOL_HOP_SECONDS = MAX_TASK_SECONDS


@dataclass(frozen=True)
class ModelResult:
    """One PRESS call result."""

    task_type: TaskType
    output: dict[str, Any]
    raw_text: str
    packet: CompiledPacket
    schema_ok: bool
    repaired: bool
    truncated: bool
    tokens_in: int | None
    tokens_out: int | None
    latency_ms: int
    offline: bool


@dataclass(frozen=True)
class _SampleResult:
    output: dict[str, Any]
    responses: tuple[ChatResponse, ...]
    repaired: bool
    timed_out: bool


SYSTEM_PROMPT = (
    "You are RED APPLE PRESS. Return only the requested JSON object. "
    "Use insufficient_evidence when the artifacts do not prove an answer."
)


class PressHarness:
    """Compile packets, constrain output, and route model calls."""

    def __init__(
        self,
        *,
        local_only: bool = False,
        client: ModelClient | None = None,
        queue_path: str | Path | None = None,
        ledger: Any | None = None,
        compiler: PacketCompiler | None = None,
        tools: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]] | None = None,
    ) -> None:
        self.local_only = local_only
        self.client = client
        self.queue = ReplayQueue(queue_path) if queue_path is not None else None
        self.ledger = ledger
        self.compiler = compiler or PacketCompiler()
        self.tools = dict(tools) if tools is not None else None
        if not local_only and client is None:
            self.client = DeepSeekClient()

    async def complete(
        self,
        task_type: TaskType | str,
        goal: str,
        *,
        artifacts: tuple[str, ...] = (),
        vocab: tuple[str, ...] = (),
        exemplar: str = "",
        near_miss: str = "",
        run_id: str | None = None,
    ) -> ModelResult:
        """Run one compiled packet through the configured transport."""
        tt = TaskType(task_type)
        route = route_for(tt)
        packet = Packet(tt, goal, artifacts, vocab, exemplar, near_miss)
        compiled = self.compiler.compile(packet)
        user = self._prompt(compiled)
        started = time.perf_counter()
        if self.local_only:
            self._queue_packet(compiled)
            output = self._minimal_output(route.grammar, vocab)
            raw = json.dumps(output, sort_keys=True)
            result = ModelResult(
                tt,
                output,
                raw,
                compiled,
                True,
                False,
                False,
                0,
                0,
                int((time.perf_counter() - started) * 1000),
                True,
            )
        else:
            result = await self._call_route(tt, route, compiled, user, vocab)
        await self._log(result, run_id)
        return result

    def _prompt(self, compiled: CompiledPacket) -> str:
        prompt = (
            "Return JSON matching this packet. If evidence is insufficient, answer insufficient_evidence.\n"
            + compiled.body.decode("utf-8")
        )
        if self.tools:
            names = ", ".join(sorted(self.tools))
            prompt += (
                "\nAvailable tools: "
                + names
                + '. To call a tool, return only {"tool":"<name>","arguments":{...}}.'
            )
        return prompt

    def _queue_packet(self, compiled: CompiledPacket) -> None:
        if self.queue is None:
            return
        packet = compiled.packet
        record = {
            "task_type": packet.task_type.value,
            "sha": compiled.sha,
            "packet": {
                "goal": redact_text(packet.goal),
                "artifacts": [redact_text(item) for item in packet.artifacts],
                "vocab": list(packet.vocab),
                "exemplar": redact_text(packet.exemplar),
                "near_miss": redact_text(packet.near_miss),
            },
        }
        self.queue.append(record)

    async def _call_route(
        self,
        task_type: TaskType,
        route: RouteSpec,
        compiled: CompiledPacket,
        user: str,
        vocab: tuple[str, ...],
    ) -> ModelResult:
        if self.client is None:
            raise FormatFail("PRESS client is not configured")
        started = time.perf_counter()
        outputs: list[dict[str, Any]] = []
        responses: list[ChatResponse] = []
        repaired = False
        timed_out = False
        for _ in range(route.samples):
            sample = await self._run_sample(task_type, route, user, vocab, started)
            outputs.append(sample.output)
            responses.extend(sample.responses)
            repaired = repaired or sample.repaired
            timed_out = timed_out or sample.timed_out
        output = self._select_output(outputs)
        elapsed = time.perf_counter() - started
        truncated = (
            any(r.finish_reason == "length" for r in responses)
            or elapsed > MAX_TASK_SECONDS
            or timed_out
        )
        total_in = sum(r.tokens_in or 0 for r in responses) or None
        total_out = sum(r.tokens_out or 0 for r in responses) or None
        raw = (
            json.dumps(output, sort_keys=True)
            if route.grammar != "prose"
            else str(output.get("text", ""))
        )
        return ModelResult(
            task_type,
            output,
            raw,
            compiled,
            True,
            repaired,
            truncated,
            total_in,
            total_out,
            int(elapsed * 1000),
            False,
        )

    async def _run_sample(
        self,
        task_type: TaskType,
        route: RouteSpec,
        user: str,
        vocab: tuple[str, ...],
        started: float,
    ) -> _SampleResult:
        client = self.client
        if client is None:
            raise FormatFail("PRESS client is not configured")
        responses: list[ChatResponse] = []
        tool_notes: list[str] = []
        user_so_far = user
        max_hops = min(route.max_hops, MAX_TOOL_HOPS) if self.tools else 0
        hops = 0
        while True:
            if time.perf_counter() - started > MAX_TOOL_HOP_SECONDS:
                output = self._minimal_output(route.grammar, vocab)
                return _SampleResult(output, tuple(responses), False, True)
            response = await asyncio.to_thread(
                client.chat,
                SYSTEM_PROMPT,
                user_so_far,
                temperature=route.temperature,
                max_tokens=MAX_TOOL_HOP_TOKENS,
                json_object=route.grammar != "prose",
            )
            responses.append(response)
            request = _tool_request(response.text)
            if request is not None and hops < max_hops and self.tools is not None:
                name, arguments = request
                tool = self.tools.get(name)
                if tool is not None:
                    result = await self._run_tool(tool, arguments)
                    hops += 1
                    payload = json.dumps(dict(result), sort_keys=True)
                    tool_notes.append(f"TOOL HOP {hops}/{max_hops} {name} RESULT:\n{payload}")
                    user_so_far = user + "\n\n" + "\n\n".join(tool_notes)
                    continue
            try:
                output = decode_output(task_type, route.grammar, response.text, vocab)
                return _SampleResult(output, tuple(responses), False, False)
            except FormatFail:
                repaired_output = await self._repair(
                    task_type, route, user_so_far, response.text, vocab
                )
                return _SampleResult(repaired_output, tuple(responses), True, False)

    async def _run_tool(
        self,
        tool: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        try:
            result = await asyncio.to_thread(tool, arguments)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        if not isinstance(result, Mapping):
            return {"error": "tool result was not an object"}
        return {str(key): value for key, value in result.items()}

    async def _repair(
        self,
        task_type: TaskType,
        route: RouteSpec,
        user: str,
        bad_text: str,
        vocab: tuple[str, ...],
    ) -> dict[str, Any]:
        if self.client is None:
            raise FormatFail("FORMAT_FAIL: no client for repair")
        try:
            decode_output(task_type, route.grammar, bad_text, vocab)
        except FormatFail as first:
            repair_user = (
                user + "\n\nVALIDATOR ERROR: " + str(first) + "\nReturn corrected output only."
            )
            response = await asyncio.to_thread(
                self.client.chat,
                SYSTEM_PROMPT,
                repair_user,
                temperature=route.temperature,
                max_tokens=MAX_OUTPUT_TOKENS,
                json_object=route.grammar != "prose",
            )
            try:
                return decode_output(task_type, route.grammar, response.text, vocab)
            except FormatFail as second:
                raise FormatFail(f"FORMAT_FAIL after repair: {second}") from second
        raise FormatFail("unreachable")

    def _select_output(self, outputs: list[dict[str, Any]]) -> dict[str, Any]:
        if not outputs:
            raise FormatFail("model returned no outputs")
        if len(outputs) == 1:
            return outputs[0]
        answers = [str(item.get("answer", item.get("value"))) for item in outputs]
        if len(set(answers)) == 1:
            return outputs[0]
        return {"answer": "insufficient_evidence"}

    def _minimal_output(self, grammar: str, vocab: tuple[str, ...]) -> dict[str, Any]:
        if grammar == "enum":
            return {"answer": "insufficient_evidence"}
        if grammar == "numeric":
            return {"value": 0}
        if grammar == "code":
            return {"code": "# offline replay\n"}
        if grammar == "ranked":
            return {"ranking": []}
        if grammar == "path":
            return {"path": [], "cost": 0}
        return {"text": "insufficient_evidence"}

    async def _log(self, result: ModelResult, run_id: str | None) -> None:
        if self.ledger is None:
            return
        try:
            await self.ledger.record_packet_log(
                packet_id=f"pkt_{uuid.uuid4().hex}",
                sha=result.packet.sha,
                task_type=result.task_type.value,
                run_id=run_id,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                latency_ms=result.latency_ms,
                schema_ok=result.schema_ok,
                bound_ok=bool(result.output),
                relevance=None,
            )
        except Exception:
            return


def _finite_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def validate_output(
    task_type: TaskType, grammar: str, text: str, vocab: tuple[str, ...]
) -> dict[str, Any]:
    """Validate grammar-constrained model output (RA-MDL-003)."""
    del task_type
    if grammar == "prose":
        stripped = text.strip()
        if not stripped:
            raise FormatFail("prose output is empty")
        return {"text": stripped}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FormatFail(f"output is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FormatFail("output must be a JSON object")
    if grammar == "enum":
        answer = value.get("answer")
        allowed = set(vocab) | {"insufficient_evidence"}
        if not isinstance(answer, str) or answer not in allowed:
            raise FormatFail("enum answer is off-vocabulary")
        return {"answer": answer}
    if grammar == "numeric":
        number = value.get("value")
        if not _finite_number(number):
            raise FormatFail("numeric output requires finite value")
        return {"value": number}
    if grammar == "code":
        code = value.get("code")
        if not isinstance(code, str) or not code.strip():
            raise FormatFail("code output requires code")
        return {"code": code}
    if grammar == "ranked":
        ranking = value.get("ranking")
        if not isinstance(ranking, list) or not all(isinstance(item, str) for item in ranking):
            raise FormatFail("ranked output requires ranking list")
        return {"ranking": ranking}
    if grammar == "path":
        path = value.get("path")
        if not isinstance(path, list) or not all(isinstance(item, str) for item in path):
            raise FormatFail("path output requires path list")
        cost = value.get("cost", 0)
        if not _finite_number(cost):
            raise FormatFail("path output requires finite numeric cost")
        return {"path": path, "cost": cost}
    raise FormatFail(f"unknown grammar {grammar}")


def _reject_json_constant(value: str) -> Any:
    raise FormatFail(f"non-finite JSON constant: {value}")


def _json_prefix(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 2 and lines[-1].strip() == "```":
            stripped = "\n".join(lines[1:-1]).strip()
    start = stripped.find("{")
    if start < 0:
        return stripped
    decoder = json.JSONDecoder()
    try:
        _, end = decoder.raw_decode(stripped[start:])
    except json.JSONDecodeError:
        return stripped
    return stripped[start : start + end]


def _canonical_vocab(answer: str, vocab: tuple[str, ...]) -> str:
    allowed = set(vocab) | {"insufficient_evidence"}
    if answer in allowed:
        return answer
    lowered = answer.lower()
    matches = [item for item in allowed if item.lower() == lowered]
    if len(matches) == 1:
        return matches[0]
    return answer


def _constrain_decoded(
    grammar: str, value: dict[str, Any], vocab: tuple[str, ...]
) -> dict[str, Any]:
    if grammar != "enum":
        return value
    answer = value.get("answer")
    if isinstance(answer, str):
        canonical = _canonical_vocab(answer, vocab)
        if canonical != answer:
            return {**value, "answer": canonical}
    return value


def decode_output(
    task_type: TaskType, grammar: str, text: str, vocab: tuple[str, ...]
) -> dict[str, Any]:
    """Decode model text with deterministic grammar constraints, then validate."""
    if grammar == "prose":
        return validate_output(task_type, grammar, text, vocab)
    candidate = _json_prefix(text)
    try:
        value = json.loads(candidate, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise FormatFail(f"output is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FormatFail("output must be a JSON object")
    constrained = _constrain_decoded(grammar, value, vocab)
    return validate_output(
        task_type, grammar, json.dumps(constrained, sort_keys=True), vocab
    )


def _tool_request(text: str) -> tuple[str, dict[str, Any]] | None:
    candidate = _json_prefix(text)
    try:
        value = json.loads(candidate, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, FormatFail):
        return None
    if not isinstance(value, dict):
        return None
    tool = value.get("tool")
    arguments = value.get("arguments", {})
    if not isinstance(tool, str) or not tool.strip():
        return None
    if not isinstance(arguments, dict):
        return None
    return tool.strip(), {str(key): item for key, item in arguments.items()}
