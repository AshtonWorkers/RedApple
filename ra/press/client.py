"""PRESS model transports: DeepSeek egress and local offline replay."""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..errors import FormatFail, RaError
from .redact import redact_text

DEFAULT_ENDPOINT = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4.1-flash"


@dataclass(frozen=True)
class ChatResponse:
    """Normalized chat response."""

    text: str
    tokens_in: int | None = None
    tokens_out: int | None = None
    latency_ms: int | None = None
    finish_reason: str | None = None


class ModelClient(Protocol):
    """Minimal model transport protocol."""

    def chat(
        self,
        system: str,
        user: str,
        *,
        temperature: float,
        max_tokens: int,
        json_object: bool,
    ) -> ChatResponse:
        """Send one redacted chat request."""
        ...


class DeepSeekError(RaError):
    code = "MODEL_EGRESS"


class DeepSeekClient:
    """OpenAI-compatible DeepSeek client (stdlib only; key never logged)."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        timeout_s: float = 90.0,
        max_retries: int = 3,
    ) -> None:
        import os

        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        if not self.api_key:
            raise DeepSeekError("DEEPSEEK_API_KEY is not set")

    def chat(
        self,
        system: str,
        user: str,
        *,
        temperature: float,
        max_tokens: int,
        json_object: bool,
    ) -> ChatResponse:
        """Send one chat completion; redaction runs before egress (I9)."""
        started = time.perf_counter()
        safe_system = redact_text(system)
        safe_user = redact_text(user)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": safe_system},
                {"role": "user", "content": safe_user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_object:
            payload["response_format"] = {"type": "json_object"}
        data = self._post("/chat/completions", payload)
        latency_ms = int((time.perf_counter() - started) * 1000)
        try:
            choice = data["choices"][0]
            message = choice["message"]
            content = message.get("content")
            if not isinstance(content, str):
                raise DeepSeekError("model response missing content")
            usage = data.get("usage") or {}
            return ChatResponse(
                text=content,
                tokens_in=_opt_int(usage.get("prompt_tokens")),
                tokens_out=_opt_int(usage.get("completion_tokens")),
                latency_ms=latency_ms,
                finish_reason=_opt_str(choice.get("finish_reason")),
            )
        except (KeyError, IndexError, TypeError) as exc:
            raise DeepSeekError(f"unexpected response shape: {exc}") from exc

    def models(self) -> object:
        """List models (diagnostic)."""
        request = urllib.request.Request(self.endpoint + "/models", method="GET")
        request.add_header("Authorization", "Bearer " + (self.api_key or ""))
        with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(self.endpoint + path, data=body, method="POST")
            request.add_header("Content-Type", "application/json")
            request.add_header("Authorization", "Bearer " + (self.api_key or ""))
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                    parsed = json.loads(response.read().decode("utf-8"))
                    if not isinstance(parsed, dict):
                        raise DeepSeekError("model response was not an object")
                    return parsed
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:500]
                last = DeepSeekError(f"HTTP {exc.code}: {detail}")
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    time.sleep(self._backoff(attempt))
                    continue
                raise last from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                last = DeepSeekError(f"network error: {exc}")
                if attempt < self.max_retries:
                    time.sleep(self._backoff(attempt))
                    continue
                raise last from exc
        raise DeepSeekError("model request failed") from last

    @staticmethod
    def _backoff(attempt: int) -> float:
        # Egress governor: exponential backoff with full jitter, capped at 60s.
        cap = min(60.0, 2.0 ** (attempt + 1))
        return random.uniform(0.0, cap)


class ReplayQueue:
    """Append-only local queue for offline packet replay (RA-SEC-002)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: Mapping[str, Any]) -> None:
        """Append one redacted packet record."""
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        """Read queued packet records."""
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                out.append(value)
        return out

    def clear(self) -> None:
        """Clear the queue after replay."""
        if self.path.exists():
            self.path.unlink()


def _opt_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def validate_client(client: ModelClient) -> None:
    """Small helper to keep type checkers honest about the protocol."""
    if not callable(client.chat):
        raise FormatFail("model client must implement chat")
