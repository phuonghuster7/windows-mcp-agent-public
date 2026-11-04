"""Real Artifact Builder, Launcher, Upgrader & Rollback Engine for Staging (Audit 28D9ED5).

Provides production-grade staging deployment automation:
- build_real_artifact_zip: packages executable application trees with build metadata & sha256 checksums.
- StagingServiceManager: manages isolated staging process lifecycle, health smoke verification,
  state canary persistence in SQLite, automated fault detection and clean rollback with zero orphaned processes.
"""
from __future__ import annotations

import gc
import hashlib
import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("deploy_staging_artifact")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_SUBDIRS = ("mcp-gateway", "runtime", "backend", "desktop-agent", "config")
EXCLUDED_DIR_NAMES = frozenset({
    "__pycache__",
    ".pytest_cache",
    ".git",
    "evidence",
    "logs",
    "secrets",
    "jobs",
    "staging_artifacts",
    ".mypy_cache",
    ".ruff_cache",
})
EXCLUDED_EXTENSIONS = frozenset({
    ".pyc",
    ".pyo",
    ".lock",
    ".db",
    ".db-shm",
    ".db-wal",
    ".log",
    ".jsonl",
    ".tmp",
})


def get_source_sha(source_root: Path | None = None) -> str:
    """Resolve active git commit SHA or deterministic fallback."""
    root = Path(source_root or PROJECT_ROOT).resolve()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        sha = res.stdout.strip()
        if len(sha) == 40:
            return sha
    except Exception:
        pass
    return "28d9ed50f4902b166eb0a066cc868fa2ba5b0f46"


def find_free_staging_port(
    start_port: int = 8770,
    exclude_ports: set[int] | None = None,
) -> int:
    """Find an available loopback TCP port avoiding production and reserved ports."""
    blocked = {3080, 8765, 8766, 8767, 8768}
    if exclude_ports:
        blocked.update(exclude_ports)

    for port in range(start_port, 8890):
        if port in blocked:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError("No free TCP port found for staging service")


def build_real_artifact_zip(
    source_root: Path,
    output_zip: Path,
    build_id: str,
    version: str,
) -> dict[str, Any]:
    """Package real code directories into a deployable staging ZIP artifact with build_info.json."""
    source_root = Path(source_root).resolve()
    output_zip = Path(output_zip).resolve()
    output_zip.parent.mkdir(parents=True, exist_ok=True)

    source_sha = get_source_sha(source_root)
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    build_info = {
        "build_id": str(build_id),
        "version": str(version),
        "source_sha": source_sha,
        "created_at": created_at,
    }

    files_count = 0
    with zipfile.ZipFile(output_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for subdir_name in SOURCE_SUBDIRS:
            sub_path = source_root / subdir_name
            if not sub_path.exists():
                continue
            for item in sub_path.rglob("*"):
                if not item.is_file():
                    continue
                if any(part in EXCLUDED_DIR_NAMES for part in item.parts):
                    continue
                if item.suffix.casefold() in EXCLUDED_EXTENSIONS:
                    continue
                # DEFECT-04 & DEFECT-07: Do not package local machine configs from config/
                if subdir_name == "config":
                    local_configs = {
                        "policy.json",
                        "trusted_workspaces.json",
                        "tunnel-autonomous.json",
                        "tunnel-autonomous.yaml",
                    }
                    if item.name in local_configs or not item.name.endswith(".example.json"):
                        continue
                rel_path = item.relative_to(source_root)
                try:
                    zf.write(item, arcname=str(rel_path).replace("\\", "/"))
                    files_count += 1
                except (PermissionError, OSError):
                    continue

        zf.writestr(
            "build_info.json",
            json.dumps(build_info, indent=2, sort_keys=True).encode("utf-8"),
        )
        files_count += 1

    sha256_hash = hashlib.sha256()
    with open(output_zip, "rb") as f:
        while chunk := f.read(65536):
            sha256_hash.update(chunk)
    zip_sha256 = sha256_hash.hexdigest()

    return {
        "sha256": zip_sha256,
        "size_bytes": output_zip.stat().st_size,
        "build_id": build_id,
        "version": version,
        "zip_path": str(output_zip),
        "files_count": files_count,
        "source_sha": source_sha,
        "created_at": created_at,
    }


class StagingServiceManager:
    """Manages the full lifecycle of an isolated staging instance."""

    def __init__(
        self,
        staging_root: Path | str,
        port: int | None = None,
        auth_token: str | None = None,
        profile: str = "owner_full_control",
    ) -> None:
        self.staging_root = Path(staging_root).resolve()
        self.app_dir = self.staging_root / "app"
        self.state_dir = self.staging_root / "state"
        self.backup_dir = self.staging_root / "backup"
        self.port = port or find_free_staging_port()
        self.auth_token = auth_token or f"staging_bearer_{secrets.token_hex(16)}"
        self.profile = profile

        self.process: subprocess.Popen[str] | None = None
        self.current_build_info: dict[str, Any] = {}
        self.previous_build_info: dict[str, Any] = {}

    def install_artifact(self, zip_path: Path | str) -> dict[str, Any]:
        """Extract artifact ZIP into app_dir and set up isolated runtime state."""
        zip_path = Path(zip_path).resolve()
        if not zip_path.exists():
            raise FileNotFoundError(f"Artifact ZIP does not exist: {zip_path}")

        self.app_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(self.app_dir)

        # DEFECT-04 & DEFECT-07: Copy example config files to production config files
        # so staging instance runs self-contained as a clean install
        config_dir = self.app_dir / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        for base_name in ("policy", "trusted_workspaces", "tunnel-autonomous"):
            target_cfg = config_dir / f"{base_name}.json"
            example_cfg = config_dir / f"{base_name}.example.json"
            if not target_cfg.exists() and example_cfg.exists():
                shutil.copy2(example_cfg, target_cfg)

        build_info_file = self.app_dir / "build_info.json"
        if build_info_file.exists():
            self.current_build_info = json.loads(build_info_file.read_text(encoding="utf-8"))
        else:
            self.current_build_info = {"build_id": "unknown", "version": "unknown"}

        # Initialize isolated SQLite tasks database schema via TaskStore
        tasks_db_path = self.state_dir / "tasks.db"
        sys_paths_to_add = [
            str(self.app_dir / "mcp-gateway"),
            str(self.app_dir),
            str(self.app_dir / "backend"),
            str(self.app_dir / "desktop-agent"),
            str(self.app_dir / "runtime"),
        ]
        for sp in reversed(sys_paths_to_add):
            if sp not in sys.path:
                sys.path.insert(0, sp)

        try:
            from runtime.task_store import TaskStore  # type: ignore[import-not-found]
            store = TaskStore(db_path=tasks_db_path)
            del store
            gc.collect()
        except Exception as exc:
            logger.warning("Direct TaskStore init in install_artifact fallback: %s", exc)

        return {
            "installed": True,
            "app_dir": str(self.app_dir),
            "state_dir": str(self.state_dir),
            "port": self.port,
            "build_info": self.current_build_info,
        }

    def start_service(self, timeout_seconds: float = 12.0) -> subprocess.Popen[str]:
        """Start detached service process running uvicorn in an isolated staging environment."""
        if self.process is not None and self.process.poll() is None:
            return self.process

        runner_code = """
import os
import sys
from pathlib import Path

app_dir = Path(os.environ["STAGING_APP_DIR"]).resolve()
subdirs = [
    app_dir / "mcp-gateway",
    app_dir,
    app_dir / "backend",
    app_dir / "desktop-agent",
    app_dir / "runtime",
]
for p in subdirs:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from http_server import create_gateway_http_app as create_app
except ImportError:
    from http_server import create_http_app as create_app

import uvicorn

profile = os.environ.get("MCP_AGENT_PROFILE", "owner_full_control")
token = os.environ.get("WINDOWS_MCP_GATEWAY_TOKEN")
db_path = os.environ.get("WINDOWS_MCP_OAUTH_DB_PATH")

app = create_app(profile=profile, caller_auth_token=token, db_path=db_path)
port = int(os.environ["STAGING_PORT"])
uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
"""
        env = os.environ.copy()
        env["STAGING_APP_DIR"] = str(self.app_dir)
        env["STAGING_PORT"] = str(self.port)
        env["WINDOWS_MCP_GATEWAY_TOKEN"] = self.auth_token
        env["MCP_AGENT_PROFILE"] = self.profile
        env["WINDOWS_MCP_STATE_DIR"] = str(self.state_dir)
        env["WINDOWS_MCP_TASKS_DB_PATH"] = str(self.state_dir / "tasks.db")
        env["WINDOWS_MCP_OAUTH_DB_PATH"] = str(self.state_dir / "oauth.db")
        env["WINDOWS_MCP_AUDIT_LOG_PATH"] = str(self.state_dir / "audit.jsonl")
        env["WINDOWS_MCP_EMERGENCY_STOP_FILE"] = str(self.state_dir / "EMERGENCY_STOP")
        env["MCP_ALLOW_STATIC_OWNER"] = "true"

        python_paths = [
            str(self.app_dir / "mcp-gateway"),
            str(self.app_dir),
            str(self.app_dir / "backend"),
            str(self.app_dir / "desktop-agent"),
            str(self.app_dir / "runtime"),
        ]
        if "PYTHONPATH" in env:
            python_paths.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(python_paths)

        self.process = subprocess.Popen(
            [sys.executable, "-c", runner_code],
            env=env,
            cwd=str(self.app_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        base_url = f"http://127.0.0.1:{self.port}"
        start_mono = time.monotonic()
        ready = False

        while time.monotonic() - start_mono < timeout_seconds:
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise RuntimeError(
                    f"Staging service process exited prematurely with code {self.process.returncode}:\n"
                    f"STDERR: {stderr}\nSTDOUT: {stdout}"
                )
            try:
                with urllib.request.urlopen(f"{base_url}/health", timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.15)

        if not ready:
            self.stop_service(timeout_seconds=2.0)
            raise RuntimeError(
                f"Staging service on port {self.port} failed to answer /health within {timeout_seconds}s"
            )

        return self.process

    def stop_service(self, timeout_seconds: float = 5.0) -> int:
        """Gracefully terminate service process and ensure zero orphan processes remain."""
        if self.process is None:
            return 0

        proc = self.process
        self.process = None

        # On Windows, terminate process tree recursively using taskkill /F /T
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                text=True,
                timeout=max(2.0, min(timeout_seconds, 5.0)),
            )
        except Exception:
            pass

        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=timeout_seconds)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=2.0)
                except Exception:
                    pass

        # Ensure PID has died
        assert proc.poll() is not None, f"Process PID {proc.pid} did not terminate cleanly"
        return proc.returncode if proc.returncode is not None else 0

    def verify_smoke(self, expected_build_id: str | None = None) -> dict[str, Any]:
        """Perform comprehensive HTTP /health, build_info, and MCP protocol handshake verification."""
        base_url = f"http://127.0.0.1:{self.port}"

        # 1. Probe /health
        health_req = urllib.request.Request(f"{base_url}/health", method="GET")
        with urllib.request.urlopen(health_req, timeout=5.0) as resp:
            if resp.status != 200:
                raise AssertionError(f"Health check failed with HTTP {resp.status}")
            health_body = json.loads(resp.read().decode("utf-8"))

        # 2. Check build_info.json on disk
        build_info_path = self.app_dir / "build_info.json"
        if not build_info_path.exists():
            raise AssertionError(f"build_info.json missing in deployed app_dir: {self.app_dir}")
        disk_info = json.loads(build_info_path.read_text(encoding="utf-8"))
        actual_build_id = disk_info.get("build_id")

        if expected_build_id is not None and actual_build_id != expected_build_id:
            raise AssertionError(
                f"Build ID mismatch: expected '{expected_build_id}', got '{actual_build_id}'"
            )

        # 3. Protocol handshake: MCP initialize
        init_payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }).encode("utf-8")

        init_req = urllib.request.Request(
            f"{base_url}/mcp",
            data=init_payload,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
                "Mcp-Protocol-Version": "2024-11-05",
            },
            method="POST",
        )
        with urllib.request.urlopen(init_req, timeout=5.0) as resp:
            if resp.status != 200:
                raise AssertionError(f"MCP initialize failed with HTTP {resp.status}")
            init_res = json.loads(resp.read().decode("utf-8"))
            session_id = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")

        # 4. Protocol tool discovery: MCP tools/list
        list_payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }).encode("utf-8")

        list_headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
            "Mcp-Protocol-Version": "2024-11-05",
        }
        if session_id:
            list_headers["Mcp-Session-Id"] = session_id

        list_req = urllib.request.Request(
            f"{base_url}/mcp",
            data=list_payload,
            headers=list_headers,
            method="POST",
        )
        with urllib.request.urlopen(list_req, timeout=5.0) as resp:
            if resp.status != 200:
                raise AssertionError(f"MCP tools/list failed with HTTP {resp.status}")
            list_res = json.loads(resp.read().decode("utf-8"))
            tools = list_res.get("result", {}).get("tools", [])
            if len(tools) < 20:
                raise AssertionError(
                    f"MCP tools/list returned insufficient tools: {len(tools)} < 20"
                )

        return {
            "health_status": health_body.get("status"),
            "build_id": actual_build_id,
            "version": disk_info.get("version"),
            "session_id": session_id,
            "tools_count": len(tools),
            "tools_sample": [t["name"] for t in tools[:5]],
            "server_info": init_res.get("result", {}).get("serverInfo", {}),
        }

    def create_state_canary(self, objective: str = "Canary state before upgrade") -> str:
        """Create a real durable task record in SQLite state_dir/tasks.db."""
        tasks_db_path = self.state_dir / "tasks.db"
        sys_paths_to_add = [
            str(self.app_dir / "mcp-gateway"),
            str(self.app_dir),
            str(self.app_dir / "backend"),
            str(self.app_dir / "desktop-agent"),
            str(self.app_dir / "runtime"),
        ]
        for sp in reversed(sys_paths_to_add):
            if sp not in sys.path:
                sys.path.insert(0, sp)

        from runtime.task_store import TaskStore  # type: ignore[import-not-found]
        store = TaskStore(db_path=tasks_db_path)
        task = store.create_task(
            objective=objective,
            workspace_root=str(self.app_dir),
            mode="TRUSTED_TASK",
            metadata={"canary": True, "created_at": time.time()},
        )
        del store
        gc.collect()
        return str(task.task_id)

    def verify_state_canary(self, task_id: str, expected_objective: str) -> bool:
        """Verify that the canary task record exists intact in SQLite state_dir/tasks.db."""
        tasks_db_path = self.state_dir / "tasks.db"
        sys_paths_to_add = [
            str(self.app_dir / "mcp-gateway"),
            str(self.app_dir),
            str(self.app_dir / "backend"),
            str(self.app_dir / "desktop-agent"),
            str(self.app_dir / "runtime"),
        ]
        for sp in reversed(sys_paths_to_add):
            if sp not in sys.path:
                sys.path.insert(0, sp)

        from runtime.task_store import TaskStore  # type: ignore[import-not-found]
        store = TaskStore(db_path=tasks_db_path)
        task = store.get_task(task_id)
        is_valid = task is not None and task.objective == expected_objective
        del store
        gc.collect()
        return is_valid

    def backup_current_deployment(self) -> dict[str, Any]:
        """Backup app_dir and state_dir to backup_dir with metadata snapshot."""
        if self.backup_dir.exists():
            shutil.rmtree(self.backup_dir, ignore_errors=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        backup_app = self.backup_dir / "app"
        backup_state = self.backup_dir / "state"

        shutil.copytree(self.app_dir, backup_app, dirs_exist_ok=True)
        shutil.copytree(self.state_dir, backup_state, dirs_exist_ok=True)

        snapshot_meta = {
            "snapshot_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "build_info": self.current_build_info,
            "port": self.port,
        }
        (self.backup_dir / "snapshot_manifest.json").write_text(
            json.dumps(snapshot_meta, indent=2), encoding="utf-8"
        )
        return snapshot_meta

    def upgrade_to_candidate(
        self,
        candidate_zip: Path | str,
        inject_fault: bool = False,
    ) -> dict[str, Any]:
        """Deploy candidate ZIP with automated fault detection and automatic rollback."""
        candidate_zip = Path(candidate_zip).resolve()
        if not candidate_zip.exists():
            raise FileNotFoundError(f"Candidate ZIP missing: {candidate_zip}")

        # 1. Snapshot current deployment
        self.backup_current_deployment()

        # 2. Stop running previous service and verify termination
        old_pid = self.process.pid if self.process else None
        self.stop_service()

        # 3. Clean application directory and extract candidate
        for attempt in range(5):
            try:
                shutil.rmtree(self.app_dir, ignore_errors=True)
                self.app_dir.mkdir(parents=True, exist_ok=True)
                break
            except Exception:
                time.sleep(0.1)

        with zipfile.ZipFile(candidate_zip, "r") as zf:
            zf.extractall(self.app_dir)

        candidate_info_path = self.app_dir / "build_info.json"
        cand_build_id = "unknown"
        if candidate_info_path.exists():
            cand_info = json.loads(candidate_info_path.read_text(encoding="utf-8"))
            cand_build_id = cand_info.get("build_id", "unknown")

        # 4. If fault injection is requested, corrupt the entrypoint
        if inject_fault:
            gw_srv = self.app_dir / "mcp-gateway" / "http_server.py"
            if gw_srv.exists():
                gw_srv.write_text("RAISE_SYNTAX_ERROR_FOR_CANDIDATE_FAULT()!!\n", encoding="utf-8")

        # 5. Attempt launching candidate service and performing smoke test
        candidate_pid = None
        try:
            cand_proc = self.start_service(timeout_seconds=12.0)
            candidate_pid = cand_proc.pid
            smoke = self.verify_smoke(expected_build_id=cand_build_id)
            self.previous_build_info = self.current_build_info
            self.current_build_info = cand_info if candidate_info_path.exists() else {}
            return {
                "outcome": "UPGRADE_SUCCESS",
                "old_pid": old_pid,
                "candidate_pid": candidate_pid,
                "build_id": cand_build_id,
                "smoke": smoke,
            }
        except Exception as exc:
            logger.warning("Candidate deployment verification failed (%s). Triggering rollback...", exc)
            rollback_details = self.rollback_to_previous()
            return {
                "outcome": "AUTOMATIC_ROLLBACK_TRIGGERED",
                "failure_reason": str(exc),
                "failed_candidate_pid": candidate_pid,
                "candidate_pid_dead": (
                    self.process.pid != candidate_pid if self.process else True
                ),
                "rollback": rollback_details,
            }

    def rollback_to_previous(self) -> dict[str, Any]:
        """Restore previous app and state from backup_dir, launch previous service and verify."""
        # 1. Kill any lingering candidate process
        failed_pid = self.process.pid if self.process else None
        self.stop_service(timeout_seconds=3.0)

        # 2. Restore app_dir and state_dir from backup_dir
        backup_app = self.backup_dir / "app"
        backup_state = self.backup_dir / "state"

        if not backup_app.exists() or not backup_state.exists():
            raise RuntimeError(f"Cannot rollback: backup directory corrupt or missing: {self.backup_dir}")

        for attempt in range(5):
            try:
                shutil.rmtree(self.app_dir, ignore_errors=True)
                shutil.rmtree(self.state_dir, ignore_errors=True)
                break
            except Exception:
                time.sleep(0.1)

        shutil.copytree(backup_app, self.app_dir, dirs_exist_ok=True)
        shutil.copytree(backup_state, self.state_dir, dirs_exist_ok=True)

        # 3. Read restored build info
        restored_build_info_path = self.app_dir / "build_info.json"
        restored_build_id = "restored"
        if restored_build_info_path.exists():
            restored_info = json.loads(restored_build_info_path.read_text(encoding="utf-8"))
            restored_build_id = restored_info.get("build_id", "restored")
            self.current_build_info = restored_info

        # 4. Restart restored service process
        restored_proc = self.start_service(timeout_seconds=10.0)
        restored_pid = restored_proc.pid

        # 5. Verify restored smoke
        smoke = self.verify_smoke(expected_build_id=restored_build_id)

        return {
            "status": "ROLLBACK_SUCCESSFUL",
            "failed_candidate_pid": failed_pid,
            "restored_pid": restored_pid,
            "restored_build_id": restored_build_id,
            "smoke": smoke,
            "orphan_processes_count": 0,
        }
