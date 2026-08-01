"""Track the active orchestrator scan job (start / status / cancel / logs)."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = PROJECT_ROOT / "backend" / "output" / "scan_job.json"
LOG_PATH = PROJECT_ROOT / "backend" / "output" / "scan_job.log"
COMPOSE_FILE = str(PROJECT_ROOT / "compose.yaml")


@dataclass
class ScanJob:
    pid: int
    mode: str
    platform: str
    status: str = "running"  # running | completed | cancelled | failed
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["running"] = self.status == "running" and _pid_alive(self.pid)
        return d


_job: Optional[ScanJob] = None


def _pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _save(job: Optional[ScanJob]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if job is None:
        if STATE_PATH.exists():
            try:
                STATE_PATH.unlink()
            except OSError:
                pass
        return
    STATE_PATH.write_text(json.dumps(job.to_dict(), indent=2))


def _load() -> Optional[ScanJob]:
    global _job
    if _job is not None:
        return _job
    if not STATE_PATH.exists():
        return None
    try:
        data = json.loads(STATE_PATH.read_text())
        job = ScanJob(
            pid=int(data.get("pid") or 0),
            mode=data.get("mode") or "minimal",
            platform=data.get("platform") or "auto",
            status=data.get("status") or "running",
            started_at=data.get("started_at") or "",
            finished_at=data.get("finished_at"),
            message=data.get("message") or "",
        )
        _job = job
        return job
    except Exception:
        return None


def _refresh(job: ScanJob) -> ScanJob:
    if job.status == "running" and not _pid_alive(job.pid):
        job.status = "completed"
        job.finished_at = datetime.now(timezone.utc).isoformat()
        job.message = job.message or "Scan process finished"
        _save(job)
    return job


def get_status() -> Dict[str, Any]:
    job = _load()
    if not job:
        return {"running": False, "status": "idle"}
    job = _refresh(job)
    return job.to_dict()


def _fetch_docker_logs(max_lines: int = 30) -> str:
    """Fetch recent docker compose logs for the project services."""
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "logs", "--tail", str(max_lines)],
            cwd=str(PROJECT_ROOT),
            capture_output=True, text=True, timeout=15, check=False,
        )
        out = (result.stdout or "") + (result.stderr or "")
        lines = [l for l in out.splitlines() if l.strip() and "Attaching to" not in l]
        # Keep only last N
        return "\n".join(lines[-max_lines:])
    except Exception:
        return ""


def get_logs(limit: int = 150) -> str:
    parts = []
    # 1. Orchestrator process log
    if LOG_PATH.exists():
        try:
            text = LOG_PATH.read_text(encoding="utf-8", errors="replace")
            lines = [l for l in text.splitlines() if l.strip()]
            tail = lines[-limit:] if len(lines) > limit else lines
            if tail:
                parts.append("── Orchestrator ──")
                parts.extend(tail)
        except Exception:
            pass

    # 2. Docker service logs (only when scan is running)
    job = _load()
    if job and job.status == "running" and _pid_alive(job.pid):
        docker_logs = _fetch_docker_logs(20)
        if docker_logs:
            parts.append("── Docker services ──")
            parts.append(docker_logs)

    return "\n".join(parts) if parts else ""


def _cleanup_log() -> None:
    try:
        if LOG_PATH.exists():
            LOG_PATH.unlink()
    except OSError:
        pass


def start_scan(cmd: list[str], mode: str, platform: str, cwd: str) -> Dict[str, Any]:
    global _job
    current = _load()
    if current and current.status == "running" and _pid_alive(current.pid):
        return {
            "error": "A scan is already running",
            "status": "busy",
            **current.to_dict(),
        }

    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_file = open(LOG_PATH, "w", buffering=1, encoding="utf-8")

    # start_new_session=True → new process group so cancel can kill children
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        start_new_session=True,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    job = ScanJob(
        pid=proc.pid,
        mode=mode,
        platform=platform,
        status="running",
        message=f"Scan started ({mode} mode, PID {proc.pid})",
    )
    _job = job
    _save(job)
    return {"status": "started", **job.to_dict()}


def _stop_docker_pipeline() -> None:
    """Stop compose services and remove their containers, networks, and volumes."""
    try:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "kill"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            timeout=20,
            check=False,
        )
    except Exception:
        pass

    try:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "down", "--remove-orphans", "--volumes", "--timeout", "5"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            timeout=30,
            check=False,
        )
    except Exception:
        pass

    try:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "rm", "-f", "-s", "-v"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            timeout=30,
            check=False,
        )
    except Exception:
        pass

    # Also remove any lingering `compose run` containers that were not part of a stack
    try:
        project = PROJECT_ROOT.name.lower().replace(" ", "")
        listed = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={project}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        ids = [x.strip() for x in (listed.stdout or "").splitlines() if x.strip()]
        if ids:
            subprocess.run(["docker", "rm", "-f", "-v", *ids], capture_output=True, timeout=20, check=False)
    except Exception:
        pass


def cancel_scan() -> Dict[str, Any]:
    global _job
    job = _load()
    if not job or job.status != "running":
        _stop_docker_pipeline()
        _cleanup_log()
        return {"status": "idle", "running": False, "message": "No active scan to cancel"}

    pid = job.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            break
        except PermissionError:
            try:
                os.kill(pid, sig)
            except OSError:
                break
        time.sleep(0.4 if sig == signal.SIGTERM else 0.1)

    _stop_docker_pipeline()
    _cleanup_log()

    job.status = "cancelled"
    job.finished_at = datetime.now(timezone.utc).isoformat()
    job.message = "Scan cancelled — all processes and containers stopped"
    _save(job)
    return job.to_dict()
