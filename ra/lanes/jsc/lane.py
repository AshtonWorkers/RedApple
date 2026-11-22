"""JSC discovery lane adapter.

Runs the :mod:`ra.discovery` crash harness as an Appendix C lane: each feed is
one JavaScript candidate executed process-per-case through ``jsc``, genuine
engine crashes are deduped and persisted as ``discovery_crash`` ledger claims,
and :meth:`JscDiscoveryLane.fuzz` drives seeded mutation campaigns whose
summaries land as ``discovery_campaign`` claims.

macOS/JSC gating: provisioning requires a ``jsc`` binary. On macOS it is
resolved from the lane/profile configuration or ``PATH``; on other platforms
an explicitly configured binary is required (the CI/test escape hatch), and
anything else parks as ``needs_hand`` so Linux CI passes without a device.
"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ...discovery import (
    DEFAULT_MAX_EXECUTIONS,
    DEFAULT_MINIMIZE_ATTEMPTS,
    DEFAULT_MINIMIZE_BUDGET_S,
    DEFAULT_SEED,
    CampaignMeta,
    CampaignResult,
    CoverageProvider,
    CrashRecord,
    CrashResult,
    CrashSink,
    JscConfig,
    JscFuzzer,
    JscRunner,
    load_corpus,
)
from ...proc import CommandRunner, SubprocessRunner
from ..base import (
    BaseLane,
    CrashRef,
    DeviceProfile,
    FeedStatus,
    Handle,
    HarnessRef,
    HumanCard,
    LaneError,
    LaneErrorCode,
    ProvisionResult,
    ProvisionState,
    RingGate,
    Thermal,
    Tier,
)

JSC_DISCOVERY_CAPABILITIES = frozenset(
    {"jsc", "javascriptcore", "webkit", "fuzz", "discovery"}
)
DEFAULT_TIMEOUT_S = 10.0
JSC_BINARY_METADATA_KEY = "jsc_binary"
JSC_ARGS_METADATA_KEY = "jsc_args"


def crash_ref_for_record(record: CrashRecord, *, context: str = "app") -> CrashRef:
    """Convert a persisted discovery crash record into a lane ``CrashRef``."""
    return CrashRef(
        id=record.claim_id,
        kind="jsc_crash",
        handle_id=record.handle_id,
        path=None,
        digest=record.signature,
        payload=record.input_js,
        context=context,
        metadata={
            "claim_id": record.claim_id,
            "signature": record.signature,
            "crash_type": record.crash_type,
            "signal": record.signal,
            "returncode": record.returncode,
            "stack": list(record.stack),
            "artifact_ids": list(record.artifact_ids),
            "target": record.target,
            "ring_node": record.ring_node,
            "build": record.build,
            "campaign_id": record.campaign_id,
        },
    )


class JscDiscoveryLane(BaseLane):
    """Lane adapter for host-side WebKit/JSC crash discovery."""

    name = "jsc-discovery"

    def __init__(
        self,
        *,
        sink: CrashSink,
        jsc_binary: str | None = None,
        jsc_args: Sequence[str] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        library_path: str | None = None,
        corpus_dir: str | Path | None = None,
        seed: int = DEFAULT_SEED,
        workdir_root: str | Path | None = None,
        command_runner: CommandRunner | None = None,
        card_sink: Callable[[HumanCard], None] | None = None,
        ring: RingGate | None = None,
        which: Callable[[str], str | None] | None = None,
        platform: str | None = None,
        thermal_reader: Callable[[], Thermal | str] | None = None,
        feed_timeout_s: float = 30.0,
        id_prefix: str | None = None,
    ) -> None:
        super().__init__(
            feed_timeout_s=feed_timeout_s, card_sink=card_sink, ring=ring, id_prefix=id_prefix
        )
        self._sink = sink
        self._jsc_binary = jsc_binary
        self._jsc_args = None if jsc_args is None else tuple(str(arg) for arg in jsc_args)
        self._timeout_s = timeout_s
        self._library_path = library_path
        self._corpus_dir = corpus_dir
        self._seed = seed
        self._workdir_root = None if workdir_root is None else Path(workdir_root)
        self._command_runner = command_runner or SubprocessRunner()
        self._which = which or shutil.which
        self._platform = platform or sys.platform
        self._thermal_reader = thermal_reader
        self._binary: str | None = None
        self._args: tuple[str, ...] = ()

    def capability(self) -> tuple[Tier, frozenset[str]]:
        """Tier.B host-side engine lane (the A/B/C ladder is iOS device tiers)."""
        return Tier.B, JSC_DISCOVERY_CAPABILITIES

    async def provision(self, p: DeviceProfile) -> ProvisionResult:
        """Resolve and validate the ``jsc`` binary, parking gaps as needs_hand."""
        self._profile = p
        self._ready = False
        self._paused = False
        self._drained = False
        self._binary = None

        if self._ring is not None and not self._ring.allows(p.ring_node, p.build):
            raise LaneError(
                LaneErrorCode.OUT_OF_RING,
                f"{p.ring_node}/{p.build or '<unknown>'} is outside the ring",
            )

        explicit = self._jsc_binary or p.metadata.get(JSC_BINARY_METADATA_KEY)
        binary, source = self._resolve_binary(p)
        if binary is None:
            if source == "explicit":
                return self._provision_gap(
                    p,
                    action="fix_jsc_binary",
                    title="Fix the configured jsc binary",
                    instruction=(
                        f"The configured jsc binary {str(explicit)!r} is not an executable "
                        "file. Point jsc_binary at a built WebKit/JSC binary or remove the "
                        "override to fall back to PATH/macOS provisioning."
                    ),
                    blocker="jsc_binary_invalid",
                    details={"path": str(explicit), "platform": self._platform},
                )
            if self._platform != "darwin":
                return self._provision_gap(
                    p,
                    action="configure_jsc_binary",
                    title="Configure a jsc binary for JSC discovery",
                    instruction=(
                        "JSC discovery runs real WebKit/JSC and is macOS-gated. On this "
                        "host, set the lane's jsc_binary (or profile metadata "
                        f"'{JSC_BINARY_METADATA_KEY}') to an explicit binary path."
                    ),
                    blocker="jsc_requires_macos_or_explicit_binary",
                    details={"platform": self._platform},
                )
            return self._provision_gap(
                p,
                action="install_jsc",
                title="Install a WebKit/JSC binary",
                instruction=(
                    "Build WebKit with `Tools/Scripts/build-webkit --jsc-only` (or install "
                    "a jsc binary on PATH), then retry attach."
                ),
                blocker="jsc_binary_missing",
                details={"platform": self._platform},
            )

        self._binary = binary
        self._args = JscConfig.resolve_args(self._jsc_args)
        p.state = "ready"
        p.thermal = Thermal.NOMINAL
        self._ready = True
        return ProvisionResult(
            profile=p,
            state=ProvisionState.READY,
            tier=Tier.B,
            capabilities=JSC_DISCOVERY_CAPABILITIES,
            details={
                "jsc_binary": binary,
                "jsc_binary_source": source,
                "jsc_args": list(self._args),
                "timeout_s": self._timeout_s,
                "library_path": self._library_path,
            },
        )

    def _resolve_binary(self, p: DeviceProfile) -> tuple[str | None, str]:
        """Resolve the jsc binary; returns (path, source) with source in
        explicit|path|missing."""
        explicit = self._jsc_binary or p.metadata.get(JSC_BINARY_METADATA_KEY)
        if explicit is not None:
            resolved = self._resolve_explicit(str(explicit))
            if resolved is not None:
                return resolved, "explicit"
            return None, "explicit"
        if self._platform == "darwin":
            found = self._which("jsc")
            if found is not None:
                return found, "path"
        return None, "missing"

    def _resolve_explicit(self, value: str) -> str | None:
        """Resolve an explicit binary name/path to an executable file."""
        if os.path.sep in value or value.startswith("."):
            if os.path.isfile(value) and os.access(value, os.X_OK):
                return value
            return None
        found = self._which(value)
        return found if found is not None else None

    async def _launch(self, handle: Handle, target: str, harness: HarnessRef) -> None:
        if self._binary is None:
            raise LaneError(
                LaneErrorCode.NOT_PROVISIONED,
                "jsc binary was not resolved during provision",
            )
        metadata: Mapping[str, Any] = harness.metadata
        binary = self._metadata_str(metadata, JSC_BINARY_METADATA_KEY) or self._binary
        args_override = self._jsc_launch_args(metadata)
        if args_override is None:
            args_override = self._jsc_args
        args = JscConfig.resolve_args(args_override)
        timeout_s = self._metadata_float(metadata, "timeout_s", self._timeout_s)
        library_path = self._metadata_str(metadata, "library_path") or self._library_path
        corpus_dir = self._metadata_str(metadata, "corpus_dir") or self._corpus_dir
        seed = self._metadata_int(metadata, "seed", self._seed)
        workdir = self._workdir_for(handle.handle_id)

        config = JscConfig(
            binary=binary,
            args=args,
            timeout_s=timeout_s,
            library_path=library_path,
        )
        runner = JscRunner(config, runner=self._command_runner, workdir=workdir)
        handle.metadata["jsc"] = {
            "runner": runner,
            "config": config,
            "corpus": load_corpus(corpus_dir),
            "seed": seed,
            "corpus_dir": None if corpus_dir is None else str(corpus_dir),
            "campaign_defaults": {
                "time_budget_s": self._metadata_float(metadata, "time_budget_s", 60.0),
                "max_executions": self._metadata_int(
                    metadata, "max_executions", DEFAULT_MAX_EXECUTIONS
                ),
                "mutation_kinds": self._metadata_str_list(metadata, "mutation_kinds"),
                "mutation_stacks": self._metadata_int(metadata, "mutation_stacks", 2),
                "minimize_crashes": self._metadata_bool(metadata, "minimize_crashes", False),
                "minimize_attempts": self._metadata_int(
                    metadata, "minimize_attempts", DEFAULT_MINIMIZE_ATTEMPTS
                ),
                "minimize_budget_s": self._metadata_float(
                    metadata, "minimize_budget_s", DEFAULT_MINIMIZE_BUDGET_S
                ),
                "use_coverage_scheduler": self._metadata_bool(
                    metadata, "use_coverage_scheduler", False
                ),
            },
        }
        handle.metadata["jsc_stats"] = {
            "executions": 0,
            "crashes": 0,
            "exec_errors": 0,
            "timeouts": 0,
            "last_exec_error": "",
        }

    def _workdir_for(self, handle_id: str) -> Path | None:
        if self._workdir_root is None:
            return None
        return self._workdir_root / handle_id

    @staticmethod
    def _jsc_launch_args(metadata: Mapping[str, Any]) -> tuple[str, ...] | None:
        raw = metadata.get(JSC_ARGS_METADATA_KEY)
        if raw is None:
            return None
        if isinstance(raw, str):
            return tuple(raw.split())
        if isinstance(raw, Sequence):
            return tuple(str(arg) for arg in raw)
        return None

    @staticmethod
    def _metadata_bool(metadata: Mapping[str, Any], key: str, default: bool) -> bool:
        value = metadata.get(key)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _metadata_str_list(metadata: Mapping[str, Any], key: str) -> tuple[str, ...] | None:
        value = metadata.get(key)
        if value is None:
            return None
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        if isinstance(value, Sequence):
            return tuple(str(part).strip() for part in value if str(part).strip())
        return None

    @staticmethod
    def _metadata_str(metadata: Mapping[str, Any], key: str) -> str | None:
        value = metadata.get(key)
        return None if value is None else str(value)

    @staticmethod
    def _metadata_float(metadata: Mapping[str, Any], key: str, default: float) -> float:
        value = metadata.get(key)
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _metadata_int(metadata: Mapping[str, Any], key: str, default: int) -> int:
        value = metadata.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _jsc_state(self, handle: Handle) -> dict[str, Any]:
        state = handle.metadata.get("jsc")
        if not isinstance(state, dict) or "runner" not in state:
            raise LaneError(
                LaneErrorCode.NOT_PROVISIONED,
                "handle was not launched by the JSC discovery lane",
                details={"handle_id": handle.handle_id},
            )
        return state

    async def _feed_bytes(self, handle: Handle, data: bytes) -> FeedStatus | str:
        state = self._jsc_state(handle)
        runner: JscRunner = state["runner"]
        result = await runner.run_source(data)
        stats = handle.metadata.setdefault("jsc_stats", {})
        stats["executions"] = int(stats.get("executions", 0)) + 1
        if result.exec_error:
            stats["exec_errors"] = int(stats.get("exec_errors", 0)) + 1
            stats["last_exec_error"] = result.stderr
            return FeedStatus.REJECTED
        if result.timed_out:
            stats["timeouts"] = int(stats.get("timeouts", 0)) + 1
            return FeedStatus.ACCEPTED
        if result.is_crash:
            stats["crashes"] = int(stats.get("crashes", 0)) + 1
            await self._record_crash(handle, data, result)
        return FeedStatus.ACCEPTED

    async def _record_crash(self, handle: Handle, content: str | bytes, result: CrashResult) -> None:
        profile = self._profile
        await self._sink.record_crash(
            content,
            result,
            {
                "handle_id": handle.handle_id,
                "target": handle.target,
                "ring_node": None if profile is None else profile.ring_node,
                "build": None if profile is None else profile.build,
            },
        )

    async def _collect_crashes(self, handle: Handle) -> list[CrashRef]:
        records = await self._sink.crashes_for_handle(handle.handle_id)
        returned = set(handle.metadata.get("returned_crash_ids", ()))
        refs: list[CrashRef] = []
        for record in records:
            if record.claim_id in returned:
                continue
            returned.add(record.claim_id)
            refs.append(crash_ref_for_record(record))
        handle.metadata["returned_crash_ids"] = sorted(returned)
        return refs

    async def _reset(self, handle: Handle) -> None:
        """Process-per-case execution keeps no persistent process to kill."""
        return None

    async def _teardown(self) -> None:
        """The sink and command runner are caller-owned; nothing to release."""
        return None

    async def _read_thermal(self) -> Thermal | str:
        if self._thermal_reader is not None:
            return self._thermal_reader()
        return Thermal.NOMINAL

    async def fuzz(
        self,
        handle: Handle,
        *,
        time_budget_s: float | None = None,
        max_executions: int | None = None,
        seed: int | None = None,
        progress: Callable[[int, int, int], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
        mutation_kinds: Sequence[str] | None = None,
        mutation_stacks: int | None = None,
        minimize_crashes: bool | None = None,
        minimize_attempts: int | None = None,
        minimize_budget_s: float | None = None,
        coverage_provider: CoverageProvider | None = None,
        use_coverage_scheduler: bool | None = None,
    ) -> CampaignResult:
        """Drive a seeded mutation campaign against the handle's ``jsc``.

        Crashes persist as ``discovery_crash`` claims and the campaign summary
        as a ``discovery_campaign`` claim through the lane's sink.
        """
        await self.assert_ready()
        state = self._jsc_state(handle)
        runner: JscRunner = state["runner"]
        defaults = state.get("campaign_defaults", {})
        budget = (
            float(defaults.get("time_budget_s", 60.0))
            if time_budget_s is None
            else float(time_budget_s)
        )
        cap = (
            int(defaults.get("max_executions", DEFAULT_MAX_EXECUTIONS))
            if max_executions is None
            else int(max_executions)
        )
        kinds = (
            tuple(defaults.get("mutation_kinds") or ())
            if mutation_kinds is None
            else tuple(mutation_kinds)
        )
        stacks = (
            int(defaults.get("mutation_stacks", 2))
            if mutation_stacks is None
            else int(mutation_stacks)
        )
        minimize = (
            bool(defaults.get("minimize_crashes", False))
            if minimize_crashes is None
            else bool(minimize_crashes)
        )
        min_attempts = (
            int(defaults.get("minimize_attempts", DEFAULT_MINIMIZE_ATTEMPTS))
            if minimize_attempts is None
            else int(minimize_attempts)
        )
        min_budget = (
            float(defaults.get("minimize_budget_s", DEFAULT_MINIMIZE_BUDGET_S))
            if minimize_budget_s is None
            else float(minimize_budget_s)
        )
        coverage_on = (
            bool(defaults.get("use_coverage_scheduler", False))
            if use_coverage_scheduler is None
            else bool(use_coverage_scheduler)
        ) or coverage_provider is not None
        profile = self._profile
        config: JscConfig = state["config"]
        meta = CampaignMeta(
            handle_id=handle.handle_id,
            target=handle.target,
            ring_node=None if profile is None else profile.ring_node,
            build=None if profile is None else profile.build,
            jsc_binary=config.binary,
            jsc_args=config.args,
        )
        fuzzer = JscFuzzer(
            runner,
            state["corpus"],
            self._sink,
            meta,
            seed=self._seed if seed is None else seed,
            mutation_kinds=kinds or None,
            mutation_stacks=stacks,
            coverage_provider=coverage_provider,
            use_coverage_scheduler=coverage_on,
            minimize_crashes=minimize,
            minimize_attempts=min_attempts,
            minimize_budget_s=min_budget,
        )

        def thermal_stop() -> bool:
            return self._paused or self._drained

        def combined_stop() -> bool:
            return thermal_stop() or (should_stop() if should_stop is not None else False)

        return await fuzzer.run(
            budget,
            max_executions=cap,
            progress=progress,
            should_stop=combined_stop,
        )

    def _provision_gap(
        self,
        profile: DeviceProfile,
        *,
        action: str,
        title: str,
        instruction: str,
        blocker: str,
        details: Mapping[str, Any],
    ) -> ProvisionResult:
        card = HumanCard(
            card_id=f"card_{uuid.uuid4().hex[:12]}",
            action=action,
            title=title,
            instruction=instruction,
            device_udid=profile.udid,
            blocker=blocker,
            metadata=dict(details),
        )
        self._emit_card(card)
        profile.state = "needs_hand"
        self._ready = False
        return ProvisionResult(
            profile=profile,
            state=ProvisionState.NEEDS_HAND,
            human_card=card,
            error_code=LaneErrorCode.NOT_PROVISIONED,
            details=dict(details),
        )
