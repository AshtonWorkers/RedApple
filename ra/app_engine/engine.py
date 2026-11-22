"""Native-app engine bridge backed by the hardened ``ra`` core."""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ra.campaign import (
    CampaignBudget,
    CampaignCrash,
    CampaignOrchestrator,
    CampaignSurface,
    LaneTickResult,
)
from ra.chain.surface import (
    SurfaceCategory,
    SurfaceChainConfig,
    SurfaceChainEmitter,
    SurfaceEdge,
    SurfaceGraph,
    SurfaceHopKind,
    SurfaceNode,
    enumerate_surface_chains,
    rank_surface_chains,
)
from ra.corpus import CorpusSeedSpec
from ra.discovery import JscConfig, JscRunner, load_corpus
from ra.discovery.jsc_store import CLAIM_TYPE_CRASH, LedgerCrashStore, records_from_rows
from ra.discovery.mutators import mutate_program
from ra.escalate.emit import EscalationLedgerEmitter
from ra.escalate.graph import EscalationGraph, analyze_escalations
from ra.escalate.models import EscalationEdge, EscalationNode, EscalationStage
from ra.ledger import Ledger
from ra.triage.exploit import classify_signature
from ra.triage.exploit_ledger import CrashExploitabilityTriage

from . import workspace as ws

LANE = "jsc"
SURFACE_ID = "webkit-jsc"
DEFAULT_TIME_BUDGET_S = 300.0
MAX_LEADS = 50


class EngineStopped(asyncio.CancelledError):
    pass


class EngineError(RuntimeError):
    pass


@dataclass(frozen=True)
class EngineConfig:
    home: Path
    db_path: Path
    time_budget_s: float
    jsc_binary: str | None = None
    jsc_library_path: str | None = None
    jsc_args: tuple[str, ...] = ()
    timeout_s: float = 10.0
    corpus_dir: str | Path | None = None
    model: str = "redapple-core"


def default_model() -> str:
    if os.environ.get("DEEPSEEK_API_KEY"):
        return os.environ.get("DEEPSEEK_MODEL", "deepseek-v4.1-flash")
    return "redapple-core"


def load_engine_json(root: Path) -> dict[str, Any]:
    value = ws.load_json(root / "engine.json", {})
    return value if isinstance(value, dict) else {}


def config_from_env(home: Path | None = None, *, time_budget_s: float | None = None) -> EngineConfig:
    root = home or ws.home()
    ws.ensure_dirs(root)
    engine = load_engine_json(root)
    args = engine.get("jsc_args")
    if isinstance(args, str):
        jsc_args = tuple(args.split())
    elif isinstance(args, list):
        jsc_args = tuple(str(item) for item in args)
    else:
        jsc_args = ()
    budget = time_budget_s if time_budget_s is not None else float(engine.get("time_budget_s", DEFAULT_TIME_BUDGET_S))
    return EngineConfig(
        home=root,
        db_path=root / "ledger.sqlite",
        time_budget_s=max(1.0, budget),
        jsc_binary=engine.get("jsc_binary") or os.environ.get("REDAPPLE_JSC"),
        jsc_library_path=engine.get("jsc_library_path") or os.environ.get("REDAPPLE_JSC_LIBPATH"),
        jsc_args=jsc_args,
        timeout_s=float(engine.get("timeout_s", 10.0)),
        corpus_dir=engine.get("corpus_dir"),
        model=default_model(),
    )


def _candidate_jsc_paths() -> list[Path]:
    roots = [
        Path.home() / "WebKit",
        Path.home() / "webkit",
        Path("/opt/WebKit"),
        Path("/home/ubuntu/webkit"),
        Path("/home/ubuntu/WebKit"),
    ]
    found: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in ("WebKitBuild/**/bin/jsc", "**/bin/jsc"):
            try:
                found.extend(sorted(root.glob(pattern)))
            except OSError:
                continue
            if found:
                return found
    return found


def resolve_jsc(config: EngineConfig) -> dict[str, Any]:
    explicit = config.jsc_binary
    source = "engine"
    if not explicit:
        info_path = os.environ.get("REDAPPLE_JSC_BUILD_INFO")
        if info_path and Path(info_path).exists():
            try:
                data = json.loads(Path(info_path).read_text(encoding="utf-8"))
                binary = Path(str(data.get("binary", "")))
                if binary.exists():
                    explicit = str(binary)
                    source = "build-info"
            except (OSError, ValueError):
                pass
    if not explicit:
        found = shutil.which("jsc")
        if found:
            explicit = found
            source = "path"
    if not explicit:
        candidates = _candidate_jsc_paths()
        if candidates:
            explicit = str(candidates[0])
            source = "search"
    if not explicit or not Path(explicit).exists() or not os.access(explicit, os.X_OK):
        raise EngineError(
            "No executable jsc binary found. Set engine.json jsc_binary, REDAPPLE_JSC, "
            "or build WebKit with Tools/Scripts/build-webkit --jsc-only."
        )
    library_path = config.jsc_library_path
    if not library_path:
        lib = Path(explicit).parent.parent / "lib"
        library_path = str(lib) if lib.exists() else None
    return {
        "binary": explicit,
        "library_path": library_path,
        "revision": os.environ.get("REDAPPLE_JSC_REVISION", "unknown"),
        "build_type": os.environ.get("REDAPPLE_JSC_BUILD_TYPE", "unknown"),
        "sanitizers": [item for item in os.environ.get("REDAPPLE_JSC_SANITIZERS", "").split(",") if item],
        "source": source,
    }


class _StatusWriter:
    def __init__(self, root: Path, *, run_id: str, model: str, budget_s: float, started_at: str) -> None:
        self.root = root
        self.run_id = run_id
        self.model = model
        self.budget_s = budget_s
        self.started_at = started_at
        self.executions = 0
        self.crashes = 0

    def write(self, state: str, message: str = "", leads: int = 0) -> None:
        ws.write_status(
            self.root,
            state=state,
            run_id=self.run_id,
            model=self.model,
            message=message,
            executions=self.executions,
            crashes=self.crashes,
            leads=leads,
            time_budget_seconds=self.budget_s,
            started_at=self.started_at,
        )


class _JscCampaignRunner:
    def __init__(
        self,
        *,
        runner: JscRunner,
        store: LedgerCrashStore,
        status: _StatusWriter,
        stop_event: asyncio.Event,
        run_id: str,
        campaign_id: str,
        jsc: dict[str, Any],
    ) -> None:
        self._runner = runner
        self._store = store
        self._status = status
        self._stop_event = stop_event
        self._run_id = run_id
        self._campaign_id = campaign_id
        self._jsc = jsc
        self._crash_ids: set[str] = set()
        self._since_write = 0

    async def run_seed(self, lane: str, seed: Any, *, tick: int, case_index: int) -> LaneTickResult:
        if self._stop_event.is_set():
            raise EngineStopped()
        metadata = dict(getattr(seed, "metadata", {}) or {})
        base = metadata.get("js")
        if not isinstance(base, str) or not base:
            return LaneTickResult(covered_edges=tuple(getattr(seed, "edges", ())), crashes=())
        rng = random.Random(f"{seed.seed_id}:{tick}:{case_index}")
        content = mutate_program(base, rng, max_attempts=4)
        started = time.monotonic()
        result = await self._runner.run_source(content)
        elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
        self._status.executions += 1
        crashes: list[CampaignCrash] = []
        if result.is_crash:
            record = await self._store.record_crash(
                content,
                result,
                {
                    "handle_id": self._run_id,
                    "target": "WebKit/JavaScriptCore",
                    "ring_node": None,
                    "build": self._jsc.get("revision"),
                    "campaign_id": self._campaign_id,
                    "run_id": self._run_id,
                    "jsc_binary": self._jsc.get("binary"),
                    "source_kind": "campaign",
                },
            )
            if record is not None and record.claim_id not in self._crash_ids:
                self._crash_ids.add(record.claim_id)
                self._status.crashes = len(self._crash_ids)
                crashes.append(
                    CampaignCrash(
                        crash_id=record.claim_id,
                        signature=record.signature,
                        lane=lane,
                        surface_id=str(metadata.get("surface_id", SURFACE_ID)),
                        seed_id=seed.seed_id,
                        payload=record.input_js[:4096],
                        metadata={
                            "crash_type": record.crash_type,
                            "signal": record.signal,
                            "claim_id": record.claim_id,
                        },
                    )
                )
        self._since_write += 1
        if self._since_write >= 25 or crashes:
            self._since_write = 0
            self._status.write("fuzzing", "Fuzzing JavaScriptCore")
        return LaneTickResult(
            covered_edges=tuple(getattr(seed, "edges", ())),
            crashes=tuple(crashes),
            elapsed_ms=elapsed_ms,
        )


async def _campaign(config: EngineConfig, ledger: Ledger, jsc: dict[str, Any], status: _StatusWriter, stop_event: asyncio.Event) -> tuple[str, dict[str, Any]]:
    campaign_id = f"app-{uuid.uuid4().hex[:12]}"
    run_id = status.run_id
    programs = load_corpus(config.corpus_dir)
    if not programs:
        raise EngineError("JSC corpus is empty")
    seeds = tuple(
        CorpusSeedSpec(
            seed_id=f"seed-{index:04d}",
            lane=LANE,
            edges=(f"corpus:{index}",),
            target="WebKit/JavaScriptCore",
            metadata={"js": program, "surface_id": SURFACE_ID, "index": index},
        )
        for index, program in enumerate(programs)
    )
    surface = CampaignSurface(
        surface_id=SURFACE_ID,
        lane=LANE,
        score=1.0,
        seeds=seeds,
        metadata={"jsc_binary": jsc.get("binary"), "revision": jsc.get("revision")},
    )
    budget = CampaignBudget(
        max_ticks=1_000_000,
        cases_per_tick=8,
        max_wall_ms=max(1000, int(config.time_budget_s * 1000)),
    )
    jsc_config = JscConfig(
        binary=str(jsc["binary"]),
        args=JscConfig.resolve_args(config.jsc_args or None),
        timeout_s=config.timeout_s,
        library_path=jsc.get("library_path"),
    )
    runner = JscRunner(jsc_config)
    store = LedgerCrashStore(ledger)
    campaign_runner = _JscCampaignRunner(
        runner=runner,
        store=store,
        status=status,
        stop_event=stop_event,
        run_id=run_id,
        campaign_id=campaign_id,
        jsc=jsc,
    )
    orchestrator = CampaignOrchestrator(ledger, namespace="app")
    status.write("fuzzing", "Fuzzing JavaScriptCore")
    result = await orchestrator.run(campaign_id, (surface,), budget, runner=campaign_runner, run_id=run_id)
    summary = {
        "campaign_id": campaign_id,
        "status": getattr(result, "status", "complete"),
        "stop_reason": getattr(result, "stop_reason", ""),
        "ticks": getattr(result, "ticks", 0),
        "cases": getattr(result, "cases", status.executions),
        "crashes": getattr(result, "crashes", status.crashes),
        "errors": getattr(result, "errors", 0),
    }
    return campaign_id, summary


def _crash_mapping(record: Any) -> dict[str, Any]:
    return {
        "id": record.claim_id,
        "kind": "jsc_crash",
        "payload": record.input_js,
        "path": None,
        "handle_id": record.handle_id,
        "context": "app",
        "metadata": {
            "crash_type": record.crash_type,
            "signal": record.signal,
            "stderr": record.stderr[:8192],
            "stack": list(record.stack)[:16],
            "target": record.target,
        },
    }


async def _exploitability(ledger: Ledger, record: Any, *, run_id: str) -> Any | None:
    try:
        triage = CrashExploitabilityTriage(ledger)
        mapping = _crash_mapping(record)
        signature = triage.signature_for(mapping)
        assessment = classify_signature(signature)
        try:
            persisted = await triage.record(mapping, run_id=run_id)
            assessment = persisted.assessment
        except Exception:
            pass
        return assessment
    except Exception:
        return None


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value)[:80] or "crash"


async def _crash_leads(ledger: Ledger, root: Path, *, run_id: str) -> list[dict[str, Any]]:
    rows = ledger.claims_by_type(CLAIM_TYPE_CRASH, limit=200)
    records = records_from_rows(rows)
    records.sort(key=lambda item: item.created_ms, reverse=True)
    leads: list[dict[str, Any]] = []
    for record in records[:MAX_LEADS]:
        crash_id = f"crash-{_slug(record.signature)}"
        assessment = await _exploitability(ledger, record, run_id=run_id)
        grade = getattr(getattr(assessment, "grade", None), "value", "low") if assessment is not None else "low"
        reasons = list(getattr(assessment, "reasons", ()) or ()) if assessment is not None else []
        primitive = getattr(assessment, "primitive", "") if assessment is not None else ""
        top = record.stack[0] if record.stack else ""
        where = f" @ {top}" if top else ""
        title = f"WebKit · JavaScriptCore — {record.crash_type}{where} ({record.signature})"
        summary = reasons[0] if reasons else (primitive or record.stderr.splitlines()[0] if record.stderr else record.crash_type)
        triage_record = {
            "crash_id": crash_id,
            "run_id": run_id,
            "created_at": ws.utcnow(),
            "source_kind": "fuzzer",
            "signature": record.signature,
            "crash_type": record.crash_type,
            "signal": record.signal,
            "returncode": record.returncode,
            "stack": list(record.stack)[:16],
            "command": "jsc <file>",
            "repro": {
                "content": record.input_js.decode("utf-8", errors="replace")[:20000],
                "size": len(record.input_js),
            },
            "exploitability": assessment.as_dict() if assessment is not None else {},
            "lead_ref": {"kind": "component", "target": title},
        }
        artifact = ws.write_triage(root, crash_id, triage_record)
        leads.append(
            {
                "id": crash_id,
                "title": title,
                "component": "JavaScriptCore",
                "summary": str(summary)[:400],
                "assessment": str(summary)[:400],
                "rating": str(grade),
                "created_at": ws.utcnow(),
                "run_id": run_id,
                "crash_id": crash_id,
                "artifact_path": str(artifact),
                "category": "Browser",
                "category_id": "category-9",
                "max_reward": 0,
                "confidence": float(getattr(assessment, "confidence", 0.0) or 0.0) if assessment is not None else 0.0,
                "needs_review": False,
                "source_kind": "fuzzer",
                "claim_id": record.claim_id,
            }
        )
    return leads


def _surface_graph(leads: list[dict[str, Any]]) -> SurfaceGraph:
    nodes = [
        SurfaceNode(id="jsc-ingress", category=SurfaceCategory.JSC, name="JavaScriptCore ingress", impact=0.2, feasibility=1.0, zero_click=True),
        SurfaceNode(id="xpc-dispatch", category=SurfaceCategory.XPC, name="XPC dispatch", impact=0.4, feasibility=0.7),
        SurfaceNode(id="sandbox-escape", category=SurfaceCategory.SANDBOX, name="Sandbox escape", impact=0.7, feasibility=0.5),
        SurfaceNode(id="kernel-target", category=SurfaceCategory.KERNEL, name="Kernel target", impact=1.0, feasibility=0.3, terminal=True),
    ]
    edges = [
        SurfaceEdge(id="e-ingress-xpc", source="jsc-ingress", target="xpc-dispatch", kind=SurfaceHopKind.XPC_DISPATCH, privilege_delta=0.2, impact_delta=0.4, reliability=0.7),
        SurfaceEdge(id="e-xpc-sandbox", source="xpc-dispatch", target="sandbox-escape", kind=SurfaceHopKind.SANDBOX_ESCAPE, privilege_delta=0.3, impact_delta=0.5, reliability=0.5),
        SurfaceEdge(id="e-sandbox-kernel", source="sandbox-escape", target="kernel-target", kind=SurfaceHopKind.GENERIC, privilege_delta=0.5, impact_delta=0.7, reliability=0.4),
    ]
    for index, lead in enumerate(leads[:5]):
        node_id = f"crash-{index}"
        nodes.append(SurfaceNode(id=node_id, category=SurfaceCategory.JSC, name=str(lead.get("title", node_id))[:120], impact=0.6, feasibility=0.6))
        edges.append(SurfaceEdge(id=f"e-ingress-{index}", source="jsc-ingress", target=node_id, kind=SurfaceHopKind.JSC_BRIDGE, privilege_delta=0.1, impact_delta=0.5, reliability=0.8))
        edges.append(SurfaceEdge(id=f"e-{index}-xpc", source=node_id, target="xpc-dispatch", kind=SurfaceHopKind.XPC_DISPATCH, privilege_delta=0.2, impact_delta=0.4, reliability=0.6))
    return SurfaceGraph(nodes=tuple(nodes), edges=tuple(edges))


async def _chain_leads(ledger: Ledger, leads: list[dict[str, Any]], *, run_id: str) -> list[dict[str, Any]]:
    extra: list[dict[str, Any]] = []
    try:
        graph = _surface_graph(leads)
        result = enumerate_surface_chains(graph, SurfaceChainConfig(max_paths=8, deadline_s=2.0))
        ranked = rank_surface_chains(result.paths, default_novelty=0.5)
        if ranked:
            await SurfaceChainEmitter(ledger).emit(ranked[:3], run_id=run_id, limit=3)
        for quality in ranked[:3]:
            path = quality.path
            extra.append(
                {
                    "id": f"chain-{_slug(path.dedup_material())}",
                    "title": "Cross-surface chain — " + " → ".join(category.value for category in path.categories),
                    "component": "Chain search",
                    "summary": f"quality {quality.quality_score:.2f}; impact {path.impact:.2f}; feasibility {path.feasibility:.2f}",
                    "assessment": f"rank {quality.rank}; hops {path.hop_count}",
                    "rating": "chain",
                    "created_at": ws.utcnow(),
                    "run_id": run_id,
                    "artifact_path": "",
                    "category": "Chain",
                    "category_id": "category-8",
                    "max_reward": 0,
                    "confidence": quality.quality_score,
                    "needs_review": False,
                    "source_kind": "chain",
                }
            )
    except Exception:
        pass
    return leads + extra


async def _escalation_leads(ledger: Ledger, leads: list[dict[str, Any]], *, run_id: str) -> list[dict[str, Any]]:
    extra: list[dict[str, Any]] = []
    try:
        nodes = (
            EscalationNode(id="sandbox:profile", stage=EscalationStage.SANDBOX_PROFILE, privilege=0.0, impact=0.0, name="Sandbox profile"),
            EscalationNode(id="entitlement:tcc", stage=EscalationStage.ENTITLEMENT, privilege=1.0, impact=0.2, name="Entitlement"),
            EscalationNode(id="service:xpc", stage=EscalationStage.SERVICE, privilege=2.0, impact=0.4, name="XPC service"),
            EscalationNode(id="kernel:entry", stage=EscalationStage.KERNEL, privilege=4.0, impact=0.8, name="Kernel entry"),
            EscalationNode(id="root:uid0", stage=EscalationStage.ROOT, privilege=5.0, impact=1.0, name="Root"),
        )
        edges = (
            EscalationEdge(source="sandbox:profile", target="entitlement:tcc", relation="escalates", privilege_delta=1.0, impact_delta=0.2, reliability=0.7),
            EscalationEdge(source="entitlement:tcc", target="service:xpc", relation="escalates", privilege_delta=1.0, impact_delta=0.3, reliability=0.6),
            EscalationEdge(source="service:xpc", target="kernel:entry", relation="escalates", privilege_delta=2.0, impact_delta=0.5, reliability=0.5),
            EscalationEdge(source="kernel:entry", target="root:uid0", relation="escalates", privilege_delta=1.0, impact_delta=0.4, reliability=0.4),
        )
        graph = EscalationGraph(nodes=nodes, edges=edges)
        result = analyze_escalations(graph, max_paths=4)
        await EscalationLedgerEmitter(ledger).emit(result, run_id=run_id, limit=4)
        for path in result.paths[:2]:
            extra.append(
                {
                    "id": f"escalation-{_slug(path.dedup_material())}",
                    "title": "Escalation path — " + " → ".join(path.nodes),
                    "component": "Escalation reasoning",
                    "summary": f"privilege +{path.privilege_gain:.1f}; impact {path.impact_score:.2f}; reliability {path.reliability:.2f}",
                    "assessment": f"stage progress {path.stage_progress}; cost {path.cost:.2f}",
                    "rating": "escalation",
                    "created_at": ws.utcnow(),
                    "run_id": run_id,
                    "artifact_path": "",
                    "category": "Escalation",
                    "category_id": "category-8",
                    "max_reward": 0,
                    "confidence": path.reliability,
                    "needs_review": False,
                    "source_kind": "escalation",
                }
            )
    except Exception:
        pass
    return leads + extra


async def run_engine(config: EngineConfig, stop_event: asyncio.Event | None = None) -> int:
    stop = stop_event or asyncio.Event()
    root = config.home
    ws.ensure_dirs(root)
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    started_at = ws.utcnow()
    started = time.monotonic()
    status = _StatusWriter(root, run_id=run_id, model=config.model, budget_s=config.time_budget_s, started_at=started_at)
    ws.acquire_lock(root, run_id)
    try:
        status.write("building", "Resolving JavaScriptCore")
        try:
            jsc = resolve_jsc(config)
        except Exception as exc:
            status.write("failed", str(exc))
            return 2
        status.write("fuzzing", "Fuzzing JavaScriptCore")
        async with await Ledger.open(config.db_path) as ledger:
            await ledger.create_run(
                "macos",
                budget={"spend_usd_micro": 0, "max_wall_ms": int(config.time_budget_s * 1000)},
                state="running",
                run_id=run_id,
            )
            run_state = "aborted"
            try:
                campaign_id, campaign_summary = await _campaign(config, ledger, jsc, status, stop)
                status.write("triaging", "Triaging crashes and chains")
                crash_leads = await _crash_leads(ledger, root, run_id=run_id)
                leads = await _chain_leads(ledger, crash_leads, run_id=run_id)
                leads = await _escalation_leads(ledger, leads, run_id=run_id)
                ws.write_leads(root, leads)
                run_state = "drained"
            except EngineStopped:
                run_state = "aborted"
                raise
            finally:
                await ledger.end_run(run_id, run_state)
            status.write("complete", "Discovery complete", leads=len(leads))
            ws.append_run(
                root,
                {
                    "run_id": run_id,
                    "campaign_id": campaign_id,
                    "started_at": started_at,
                    "ended_at": ws.utcnow(),
                    "wall_s": round(time.monotonic() - started, 3),
                    "executions": status.executions,
                    "crashes": status.crashes,
                    "leads": len(leads),
                    "jsc": jsc,
                    "campaign": campaign_summary,
                    "model": config.model,
                },
            )
        return 0
    except EngineStopped:
        status.write("stopped", "Stopped by user", leads=0)
        return 130
    except asyncio.CancelledError:
        status.write("stopped", "Stopped", leads=0)
        return 130
    except Exception as exc:
        status.write("failed", str(exc), leads=0)
        return 1
    finally:
        ws.release_lock(root, run_id)


async def stop_engine(root: Path | None = None) -> bool:
    base = root or ws.home()
    lock = ws.read_lock(base)
    if not lock:
        return False
    pid = lock.get("pid")
    if pid is None or not ws.pid_alive(pid):
        ws.release_lock(base, str(lock.get("run_id", "")))
        return False
    try:
        os.kill(int(str(pid)), 15)
        return True
    except OSError:
        return False
