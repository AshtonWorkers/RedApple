"""Workspace file contract shared with the native RedApple app."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def home() -> Path:
    default = Path.home() / (
        "Library/Application Support/RedApple" if os.uname().sysname == "Darwin" else ".redapple"
    )
    return Path(os.environ.get("REDAPPLE_HOME", default)).expanduser()


def discovery_dir(root: Path | None = None) -> Path:
    return (root or home()) / "discovery"


def triage_dir(root: Path | None = None) -> Path:
    return discovery_dir(root) / "triage"


def status_path(root: Path | None = None) -> Path:
    return discovery_dir(root) / "status.json"


def leads_path(root: Path | None = None) -> Path:
    return discovery_dir(root) / "leads.json"


def runs_path(root: Path | None = None) -> Path:
    return discovery_dir(root) / "runs.json"


def lock_path(root: Path | None = None) -> Path:
    return discovery_dir(root) / "run.lock"


def ensure_dirs(root: Path) -> None:
    for path in (root, discovery_dir(root), triage_dir(root)):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            path.chmod(0o700)


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_status(
    root: Path,
    *,
    state: str,
    run_id: str,
    model: str,
    message: str = "",
    executions: int = 0,
    crashes: int = 0,
    leads: int = 0,
    time_budget_seconds: float = 0.0,
    started_at: str = "",
) -> None:
    save_json(
        status_path(root),
        {
            "schema_version": SCHEMA_VERSION,
            "state": state,
            "run_id": run_id,
            "model": model,
            "updated_at": utcnow(),
            "message": message,
            "executions": executions,
            "crashes": crashes,
            "leads": leads,
            "target_revision": os.environ.get("REDAPPLE_JSC_REVISION", "unknown"),
            "time_budget_seconds": time_budget_seconds,
            "started_at": started_at or utcnow(),
        },
    )


def write_leads(root: Path, leads: list[dict[str, Any]]) -> None:
    save_json(leads_path(root), leads[:100])


def write_triage(root: Path, crash_id: str, record: dict[str, Any]) -> Path:
    path = triage_dir(root) / f"{crash_id}.json"
    save_json(path, record)
    return path


def append_run(root: Path, record: dict[str, Any]) -> None:
    path = runs_path(root)
    runs = load_json(path, [])
    if not isinstance(runs, list):
        runs = []
    run_id = str(record.get("run_id", ""))
    runs = [item for item in runs if isinstance(item, dict) and item.get("run_id") != run_id]
    runs.insert(0, record)
    save_json(path, runs[:200])


def pid_alive(pid: Any) -> bool:
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError, TypeError):
        return False
    return True


class RunLockError(RuntimeError):
    pass


def acquire_lock(root: Path, run_id: str) -> None:
    path = lock_path(root)
    existing = load_json(path, None)
    if isinstance(existing, dict) and existing.get("run_id") != run_id and pid_alive(existing.get("pid")):
        raise RunLockError(f"another run is active (pid {existing.get('pid')}, run {existing.get('run_id')})")
    save_json(path, {"pid": os.getpid(), "run_id": run_id, "started_at": utcnow()})


def release_lock(root: Path, run_id: str | None = None) -> None:
    existing = load_json(lock_path(root), None)
    if isinstance(existing, dict) and run_id is not None and existing.get("run_id") != run_id:
        return
    lock_path(root).unlink(missing_ok=True)


def read_lock(root: Path) -> dict[str, Any] | None:
    value = load_json(lock_path(root), None)
    return value if isinstance(value, dict) else None
