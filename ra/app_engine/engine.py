"""Native-app engine bridge backed by the hardened ``ra`` core."""

from __future__ import annotations

import asyncio
import contextlib
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
        crash_ids: set[str] | None = None,
    ) -> None:
        self._runner = runner
        self._store = store
        self._status = status
        self._stop_event = stop_event
        self._run_id = run_id
        self._campaign_id = campaign_id
        self._jsc = jsc
        self._crash_ids: set[str] = crash_ids if crash_ids is not None else set()
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


async def _campaign(
    config: EngineConfig,
    ledger: Ledger,
    jsc: dict[str, Any],
    status: _StatusWriter,
    stop_event: asyncio.Event,
    *,
    crash_ids: set[str] | None = None,
) -> tuple[str, dict[str, Any]]:
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
        crash_ids=crash_ids,
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


_STAGE_LABELS = {
    "jsc": "JavaScriptCore",
    "xpc": "XPC dispatch",
    "sandbox": "Sandbox escape",
    "kernel": "Kernel",
    "media": "Media pipeline",
    "codec": "Codec",
    "font": "Font parser",
    "render": "Renderer",
    "iokit": "IOKit",
    "network": "Network stack",
    "other": "Other surface",
}


def _hop_status(reliability: float) -> str:
    if reliability >= 0.6:
        return "supported"
    if reliability >= 0.3:
        return "exploring"
    return "unproven"


def _escalation_chain_stages(path: Any, by_id: dict[str, Any]) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = []
    node_ids = tuple(path.nodes)
    for index, node_id in enumerate(node_ids[:5]):
        node = by_id.get(str(node_id))
        label = str(getattr(node, "name", "") or node_id)
        status = "exploring" if index == len(node_ids) - 1 else "supported"
        detail = ""
        if node is not None:
            detail = f"privilege {float(node.privilege):.1f} · impact {float(node.impact):.2f}"
        stages.append({"stage": label, "status": status, "detail": detail})
    return stages


def _surface_chain_stages(path: Any) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = []
    for index, category in enumerate(tuple(path.categories)[:5]):
        label = _STAGE_LABELS.get(str(category), str(category))
        if index == 0:
            stages.append({"stage": label, "status": "confirmed", "detail": "Grounded in a reproduced crash"})
        else:
            edge = path.edges[index - 1]
            stages.append(
                {
                    "stage": label,
                    "status": _hop_status(float(edge.reliability)),
                    "detail": f"Hop reliability {float(edge.reliability):.2f}",
                }
            )
    return stages


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
                    "quality_score": float(quality.quality_score),
                    "impact": float(path.impact),
                    "feasibility": float(path.feasibility),
                    "hops": int(path.hop_count),
                    "chain_stages": _surface_chain_stages(path),
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
        by_id = {node.id: node for node in nodes}
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
                    "privilege_gain": float(path.privilege_gain),
                    "impact_score": float(path.impact_score),
                    "reliability": float(path.reliability),
                    "stage_progress": int(path.stage_progress),
                    "chain_stages": _escalation_chain_stages(path, by_id),
                }
            )
    except Exception:
        pass
    return leads + extra


PROVEN_SOURCES = frozenset({"chain", "escalation"})
PROVEN_GRADES = frozenset({"exploitable", "probably-exploitable"})
MAX_PROVEN_FINDINGS = 20
LOOP_CYCLE_PAUSE_S = 2.0


def _is_proven_lead(lead: dict[str, Any]) -> bool:
    return str(lead.get("source_kind") or "") in PROVEN_SOURCES or str(lead.get("rating") or "") in PROVEN_GRADES


def _read_lead_triage(lead: dict[str, Any], root: Path) -> dict[str, Any]:
    artifact = lead.get("artifact_path")
    if not isinstance(artifact, str) or not artifact:
        return {}
    path = Path(artifact)
    if not path.is_absolute():
        path = root / artifact
    data = ws.load_json(path, {})
    return data if isinstance(data, dict) else {}


def _default_chain_stages(source_kind: str) -> list[dict[str, Any]]:
    if source_kind != "fuzzer":
        return []
    return [
        {"stage": "JavaScriptCore", "status": "confirmed", "detail": "Crash reproduced by the fuzzer"},
        {"stage": "XPC dispatch", "status": "exploring", "detail": "Chain search treats this as the next hop"},
        {"stage": "Sandbox escape", "status": "unproven", "detail": "No escape evidence yet"},
        {"stage": "Kernel", "status": "unproven", "detail": "No kernel evidence yet"},
    ]


def _fuzzer_evidence(lead: dict[str, Any], triage: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    crash_type = str(triage.get("crash_type") or "crash")
    signal = str(triage.get("signal") or "unknown")
    returncode = triage.get("returncode")
    evidence.append(
        {"label": "Reproducible crash", "value": "Recorded", "detail": f"{crash_type} · {signal} · exit {returncode}"}
    )
    repro = triage.get("repro")
    content = str(repro.get("content") or "") if isinstance(repro, dict) else ""
    lines = content.count("\n") + 1 if content else 0
    evidence.append(
        {
            "label": "Minimized testcase",
            "value": f"{lines} lines" if lines else "Stored",
            "detail": "Repro artifact kept in the workspace",
        }
    )
    signature = str(triage.get("signature") or "")
    if signature:
        evidence.append({"label": "Unique crash fingerprint", "value": signature, "detail": "Stable dedup signature"})
    assessment = triage.get("exploitability")
    assessment = assessment if isinstance(assessment, dict) else {}
    grade = str(assessment.get("exploitability_grade") or lead.get("rating") or "unknown")
    confidence = assessment.get("confidence")
    detail = f"confidence {confidence:.2f}" if isinstance(confidence, (int, float)) else "heuristic classification"
    evidence.append({"label": "Exploitability grade", "value": grade, "detail": detail})
    stack = triage.get("stack")
    if isinstance(stack, list) and stack:
        evidence.append({"label": "Stack frames", "value": str(len(stack)), "detail": str(stack[0])[:120]})
    return evidence


def _score_evidence(lead: dict[str, Any], pairs: list[tuple[str, Any, str]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for label, value, detail in pairs:
        if isinstance(value, (int, float)):
            evidence.append({"label": label, "value": f"{float(value):.2f}", "detail": detail})
        elif value is not None:
            evidence.append({"label": label, "value": str(value), "detail": detail})
    return evidence


def _evidence_items(lead: dict[str, Any], triage: dict[str, Any], source_kind: str) -> list[dict[str, Any]]:
    if source_kind == "fuzzer":
        return _fuzzer_evidence(lead, triage)
    if source_kind == "chain":
        return _score_evidence(
            lead,
            [
                ("Chain quality score", lead.get("quality_score"), "Ranked by the chain search"),
                ("Impact", lead.get("impact"), "Path impact score"),
                ("Feasibility", lead.get("feasibility"), "Path feasibility score"),
                ("Hops", lead.get("hops"), "Cross-surface hops in the path"),
            ],
        )
    if source_kind == "escalation":
        return _score_evidence(
            lead,
            [
                ("Privilege gain", lead.get("privilege_gain"), "Privilege delta along the path"),
                ("Impact score", lead.get("impact_score"), "Path impact score"),
                ("Reliability", lead.get("reliability"), "Path reliability score"),
                ("Stage progress", lead.get("stage_progress"), "Escalation stages covered"),
            ],
        )
    return []


def _next_step(source_kind: str, grade: str) -> str:
    if source_kind == "chain":
        return "Validate each hop with a concrete proof of concept, starting at the confirmed stage."
    if source_kind == "escalation":
        return "Map the escalation path to a concrete entitlement or service target and test reachability."
    if grade == "exploitable":
        return "Reproduce the crash manually, minimize the testcase, and check whether the primitive reaches XPC services."
    if grade == "probably-exploitable":
        return "Confirm reproducibility, then look for a controlled read or write primitive."
    return "Review the diagnostic artifact and record triage notes before deeper work."


def _proven_finding(lead: dict[str, Any], root: Path) -> dict[str, Any]:
    source_kind = str(lead.get("source_kind") or "fuzzer")
    grade = str(lead.get("rating") or "unknown")
    triage = _read_lead_triage(lead, root)
    stages = lead.get("chain_stages")
    chain = [dict(stage) for stage in stages if isinstance(stage, dict)] if isinstance(stages, list) else []
    if not chain:
        chain = _default_chain_stages(source_kind)
    return {
        "id": str(lead.get("id") or ""),
        "title": str(lead.get("title") or "Untitled finding"),
        "component": str(lead.get("component") or ""),
        "summary": str(lead.get("summary") or ""),
        "grade": grade,
        "confidence": float(lead.get("confidence") or 0.0),
        "source_kind": source_kind,
        "created_at": str(lead.get("created_at") or ""),
        "run_id": str(lead.get("run_id") or ""),
        "artifact_path": str(lead.get("artifact_path") or ""),
        "signature": str(triage.get("signature") or ""),
        "chain": chain,
        "evidence": _evidence_items(lead, triage, source_kind),
        "next_step": _next_step(source_kind, grade),
    }


def write_proven_findings(root: Path, leads: list[dict[str, Any]], *, run_id: str) -> list[dict[str, Any]]:
    """Promote validated leads and exploit chains into the proven-findings feed."""
    findings = [_proven_finding(lead, root) for lead in leads if _is_proven_lead(lead)]
    findings.sort(key=lambda item: -item["confidence"])
    findings = findings[:MAX_PROVEN_FINDINGS]
    ws.save_json(
        ws.proven_path(root),
        {
            "schema_version": ws.SCHEMA_VERSION,
            "updated_at": ws.utcnow(),
            "run_id": run_id,
            "findings": findings,
        },
    )
    return findings


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
                write_proven_findings(root, leads, run_id=run_id)
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


async def loop_engine(config: EngineConfig, stop_event: asyncio.Event | None = None) -> int:
    """Run discovery campaigns back-to-back until the user stops the loop."""
    stop = stop_event or asyncio.Event()
    root = config.home
    ws.ensure_dirs(root)
    run_id = f"loop-{uuid.uuid4().hex[:12]}"
    started_at = ws.utcnow()
    status = _StatusWriter(root, run_id=run_id, model=config.model, budget_s=config.time_budget_s, started_at=started_at)
    try:
        ws.acquire_lock(root, run_id)
    except ws.RunLockError as exc:
        status.write("failed", str(exc))
        return 1
    crash_ids: set[str] = set()
    total_leads = 0
    iteration = 0
    try:
        status.write("building", "Resolving JavaScriptCore")
        try:
            jsc = resolve_jsc(config)
        except Exception as exc:
            status.write("failed", str(exc))
            return 2
        async with await Ledger.open(config.db_path) as ledger:
            await ledger.create_run(
                "macos",
                budget={"spend_usd_micro": 0, "max_wall_ms": int(config.time_budget_s * 1000)},
                state="running",
                run_id=run_id,
            )
            try:
                while not stop.is_set():
                    iteration += 1
                    cycle_started = time.monotonic()
                    cycle_started_at = ws.utcnow()
                    executions_before = status.executions
                    crashes_before = status.crashes
                    try:
                        campaign_id, campaign_summary = await _campaign(
                            config, ledger, jsc, status, stop, crash_ids=crash_ids
                        )
                    except EngineStopped:
                        break
                    status.write("triaging", f"Triaging crashes and chains (cycle {iteration})")
                    crash_leads = await _crash_leads(ledger, root, run_id=run_id)
                    leads = await _chain_leads(ledger, crash_leads, run_id=run_id)
                    leads = await _escalation_leads(ledger, leads, run_id=run_id)
                    new_leads = max(0, len(leads) - total_leads)
                    total_leads = len(leads)
                    ws.write_leads(root, leads)
                    write_proven_findings(root, leads, run_id=run_id)
                    ws.append_run(
                        root,
                        {
                            "run_id": f"{run_id}-cycle-{iteration}",
                            "iteration": iteration,
                            "campaign_id": campaign_id,
                            "started_at": cycle_started_at,
                            "ended_at": ws.utcnow(),
                            "wall_s": round(time.monotonic() - cycle_started, 3),
                            "executions": status.executions - executions_before,
                            "crashes": status.crashes - crashes_before,
                            "leads": total_leads,
                            "new_leads": new_leads,
                            "jsc": jsc,
                            "campaign": campaign_summary,
                            "model": config.model,
                        },
                    )
                    status.write("fuzzing", f"Cycle {iteration} complete · fuzzing continues", leads=total_leads)
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(stop.wait(), timeout=LOOP_CYCLE_PAUSE_S)
            finally:
                await ledger.end_run(run_id, "aborted")
        status.write("stopped", "Stopped by user", leads=total_leads)
        return 130
    except EngineStopped:
        status.write("stopped", "Stopped by user", leads=total_leads)
        return 130
    except asyncio.CancelledError:
        status.write("stopped", "Stopped", leads=total_leads)
        return 130
    except Exception as exc:
        status.write("failed", str(exc), leads=total_leads)
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
