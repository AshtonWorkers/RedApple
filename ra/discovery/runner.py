"""Process-per-case ``jsc`` runner.

Each candidate JavaScript source is written to a unique temporary file and run
in its own ``jsc`` process, so a crash can never corrupt harness state and
cases are safely parallelizable later. Classification is the pure logic in
:mod:`ra.discovery.harness`; this module is only the I/O edge.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from collections.abc import Mapping
from pathlib import Path

from ..proc import CommandRunner, SubprocessRunner
from .harness import (
    CrashResult,
    JscConfig,
    classify_run,
    exec_error_result,
    timeout_result,
)


def _candidate_bytes(content: str | bytes) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace")
    try:
        return bytes(content)
    except Exception:  # bytes-like failure must not escape the runner
        return b""


class JscRunner:
    """Runs JavaScript candidates through a ``jsc`` binary, one process each."""

    def __init__(
        self,
        config: JscConfig,
        *,
        runner: CommandRunner | None = None,
        workdir: str | Path | None = None,
        base_env: Mapping[str, str] | None = None,
    ) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()
        self._workdir = None if workdir is None else Path(workdir)
        self._base_env = dict(base_env) if base_env is not None else None

    @property
    def config(self) -> JscConfig:
        return self._config

    def _env(self) -> dict[str, str]:
        base = dict(os.environ) if self._base_env is None else dict(self._base_env)
        return self._config.build_env(base)

    async def run_source(self, content: str | bytes) -> CrashResult:
        """Write ``content`` to a candidate file, run ``jsc``, classify the run.

        Inputs are size-bounded before touching disk; oversized or undecodable
        candidates become ``exec-error`` results instead of crashing the
        campaign harness.
        """
        if not self._config.binary:
            return exec_error_result("jsc binary is empty")
        data = _candidate_bytes(content)
        if len(data) > self._config.max_input_bytes:
            return exec_error_result(
                f"candidate too large: {len(data)} bytes > {self._config.max_input_bytes}"
            )
        argv = (self._config.binary, *self._config.args)
        if self._workdir is not None:
            try:
                self._workdir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                return exec_error_result(f"workdir unavailable: {exc}")
            candidate = self._workdir / f"candidate-{uuid.uuid4().hex}.js"
            try:
                candidate.write_bytes(data)
                return await self._execute(argv, candidate)
            except OSError as exc:
                return exec_error_result(f"candidate write failed: {exc}")
            finally:
                with contextlib.suppress(OSError):
                    candidate.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="ra-jsc-") as tmp:
            candidate = Path(tmp) / "candidate.js"
            try:
                candidate.write_bytes(data)
            except OSError as exc:
                return exec_error_result(f"candidate write failed: {exc}")
            return await self._execute(argv, candidate)

    async def _execute(self, argv: tuple[str, ...], candidate: Path) -> CrashResult:
        try:
            result = await self._runner.run(
                [*argv, str(candidate)],
                timeout_s=self._config.timeout_s,
                env=self._env(),
            )
        except (OSError, ValueError) as exc:
            return exec_error_result(str(exc))
        except Exception as exc:  # runner defect must not kill the campaign
            return exec_error_result(f"runner error: {exc}")
        if result.timed_out:
            return timeout_result(self._config.timeout_s)
        return classify_run(result.returncode, result.stderr)
