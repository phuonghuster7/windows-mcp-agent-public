"""Phase P2.3 Shell & Program Execution Subsystem.

Implements:
- powershell_execute & cmd_execute (synchronous bounded execution)
- process_start, process_status, process_stop (managed background processes)
- job_create, job_poll, job_cancel, job_logs (durable background jobs in runtime/jobs/<job_id>.json)
- Explicit working directory validation, timeout enforcement, output truncation,
  exit code capture, stdout/stderr separation, process tree termination,
  per-job audit logs, and automatic secret redaction.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

from policy import PermissionTier, SecurityPolicy, redact_secrets  # noqa: E402

_SENSITIVE_ENV_EXACT: frozenset[str] = frozenset((
    "MCP_AUTH_TOKEN",
    "COMPUTER_API_TOKEN",
    "OPENAI_API_KEY",
    "CONTROL_PLANE_API_KEY",
    "ANTIGRAVITY_CSRF_TOKEN",
    "VNSTOCK_API_KEY",
    "MCP_AGENT_APPROVAL_TOKEN",
))

_SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?:_SECRET|SECRET_|^SECRET$|_TOKEN|TOKEN_|^TOKEN$|_API_KEY|API_KEY_|^API_KEY$|_PASSWORD|PASSWORD_|^PASSWORD$)",
    re.IGNORECASE,
)

_EXEC_BYPASS_GUARD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("powershell_encoded_command", re.compile(r"(?:^|[\s;|&])-(?:encodedcommand|enc|ec)\b", re.IGNORECASE)),
    ("powershell_short_encoded_command", re.compile(r"(?:^|[\s;|&])-e\s+[A-Za-z0-9+/=]{4,}(?:\s|$)", re.IGNORECASE)),
    ("invoke_expression", re.compile(r"\b(?:Invoke-Expression|iex)\b", re.IGNORECASE)),
    ("webclient_download", re.compile(r"\b(?:DownloadString|DownloadFile)\b", re.IGNORECASE)),
    ("webrequest_pipe_iex", re.compile(r"Invoke-WebRequest\b[\s\S]*?\|[\s\S]*?\b(?:iex|Invoke-Expression)\b", re.IGNORECASE)),
    ("uac_runas_elevation", re.compile(r"\b(?:Start-Process|saps)\b[\s\S]*?-Verb\s+['\"]?RunAs\b", re.IGNORECASE)),
    ("net_webclient", re.compile(r"\bNew-Object\s+(?:-TypeName\s+)?(?:System\.)?Net\.WebClient\b", re.IGNORECASE)),
    ("reg_modification", re.compile(r"\breg(?:\.exe)?\s+(?:add|delete|save|export)\b", re.IGNORECASE)),
    ("sc_service_control", re.compile(r"\bsc(?:\.exe)?\s+(?:stop|delete|config|create)\b", re.IGNORECASE)),
    ("schtasks_persistence", re.compile(r"\bschtasks(?:\.exe)?\s+/(?:create|delete|change)\b", re.IGNORECASE)),
    ("certutil_urlcache", re.compile(r"\bcertutil(?:\.exe)?\s+[^\r\n]*?-urlcache\b", re.IGNORECASE)),
    ("bitsadmin_abuse", re.compile(r"\bbitsadmin(?:\.exe)?\b", re.IGNORECASE)),
)


def _is_sensitive_env_key(key: str) -> bool:
    upper = key.strip().upper()
    if upper in _SENSITIVE_ENV_EXACT:
        return True
    return bool(_SENSITIVE_ENV_KEY_RE.search(upper))


def kill_process_tree(pid: int) -> dict[str, Any]:
    """Terminate a process and its entire descendant tree on Windows."""
    killed_pids: list[int] = []
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                killed_pids.append(child.pid)
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        killed_pids.append(parent.pid)
        parent.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except Exception:
            pass

    return {"pid": pid, "killed_pids": killed_pids}


class ExecutionJobManager:
    """Implements P2.3 Shell, Process, and Durable Background Job operations."""

    def __init__(
        self,
        policy: SecurityPolicy | None = None,
        *,
        jobs_dir: str | Path | None = None,
        max_concurrent_jobs: int = 10,
    ) -> None:
        self.policy = policy or SecurityPolicy()
        state_root = os.getenv("MCP_STATE_ROOT")
        default_jobs = (Path(state_root) / "jobs") if state_root else (PROJECT_ROOT / "runtime" / "jobs")
        self.jobs_dir = Path(jobs_dir or default_jobs).resolve(strict=False)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.max_concurrent_jobs: int = max(1, int(max_concurrent_jobs))
        self._lock = threading.Lock()
        self._processes: dict[str, dict[str, Any]] = {}
        self._job_threads: dict[str, threading.Thread] = {}
        self._job_procs: dict[str, subprocess.Popen[bytes]] = {}
        self._active_jobs: set[str] = set()

    def _truncate_and_redact(self, raw_bytes: bytes, max_bytes: int | None = None) -> tuple[str, bool]:
        limit = max_bytes if max_bytes is not None else self.policy.max_output_bytes
        truncated = len(raw_bytes) > limit
        sliced = raw_bytes[:limit] if truncated else raw_bytes
        text = sliced.decode("utf-8", errors="replace")
        redacted = redact_secrets(text)
        if truncated:
            redacted += "\n...[TRUNCATED: Output exceeded max_output_bytes]"
        return redacted, truncated

    def _build_shell_argv(self, command: str, shell_type: str = "powershell") -> list[str]:
        st = shell_type.lower().strip()
        if st in ("powershell", "pwsh", "ps1"):
            return [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ]
        if st in ("cmd", "cmd.exe", "bat"):
            return ["cmd.exe", "/d", "/s", "/c", command]
        raise ValueError(f"Unsupported shell type: {shell_type}")

    def _build_sanitized_env(self, custom_env: dict[str, str] | None = None) -> dict[str, str]:
        """Build a sanitized child-process environment stripping host/service secrets."""
        env: dict[str, str] = {}
        for k, v in os.environ.items():
            if not isinstance(k, str) or "\x00" in k or _is_sensitive_env_key(k):
                continue
            env[str(k)] = str(v)
        if custom_env:
            for k, v in custom_env.items():
                if not isinstance(k, str) or "\x00" in k or _is_sensitive_env_key(k):
                    continue
                env[str(k)] = str(v)
        return env

    def _prepare_env(self, custom_env: dict[str, str] | None = None) -> dict[str, str]:
        return self._build_sanitized_env(custom_env)

    def _validate_execution_safety(
        self,
        tool_name: str,
        command: str,
        cwd: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> Path:
        """Validate command against policy and SEC-04 shell metacharacter / elevation / binary abuse guards."""
        resolved_cwd = self.policy.validate_command(
            command, cwd, session_id=session_id, approval_token=approval_token
        )
        cleaned = command.strip()
        for rule_name, pat in _EXEC_BYPASS_GUARD_PATTERNS:
            if pat.search(cleaned):
                self.policy.audit.log_event(
                    tool_name=tool_name,
                    tier=PermissionTier.EXECUTE,
                    decision="DENY",
                    reason=f"SEC-04 blocked dangerous command pattern ({rule_name}): {pat.pattern}",
                    arguments={"command": cleaned, "cwd": str(resolved_cwd)},
                    session_id=session_id,
                )
                raise PermissionError(
                    f"Command blocked by SEC-04 execution guard ({rule_name}): {pat.pattern}"
                )
        return resolved_cwd

    def _count_running_locked(self) -> int:
        running_procs = sum(
            1
            for info in self._processes.values()
            if not info.get("stopped", False) and info["popen"].poll() is None
        )
        return running_procs + len(self._active_jobs)

    # ------------------------------------------------------------------
    # Synchronous Shell Execution (powershell_execute, cmd_execute)
    # ------------------------------------------------------------------
    def _execute_sync(
        self,
        tool_name: str,
        shell_type: str,
        command: str,
        cwd: str,
        *,
        timeout_seconds: int | float | None = None,
        env: dict[str, str] | None = None,
        max_output_bytes: int | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            tool_name,
            {"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds},
            session_id=session_id,
            approval_token=approval_token,
        )
        resolved_cwd = self._validate_execution_safety(
            tool_name, command, cwd, session_id=session_id, approval_token=approval_token
        )

        timeout = float(timeout_seconds if timeout_seconds is not None else self.policy.default_timeout_seconds)
        timeout = max(0.5, min(float(self.policy.max_timeout_seconds), timeout))
        argv = self._build_shell_argv(command, shell_type)
        proc_env = self._build_sanitized_env(env)

        timed_out = False
        proc = subprocess.Popen(
            argv,
            cwd=str(resolved_cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=proc_env,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_process_tree(proc.pid)
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=2)
            except Exception:
                stdout_bytes, stderr_bytes = b"", b""
            exit_code = -1

        duration_ms = int((time.time() - t0) * 1000)
        stdout_str, out_trunc = self._truncate_and_redact(stdout_bytes, max_output_bytes)
        stderr_str, err_trunc = self._truncate_and_redact(stderr_bytes, max_output_bytes)

        res = {
            "ok": (exit_code == 0) and (not timed_out),
            "shell": shell_type,
            "command": redact_secrets(command),
            "cwd": str(resolved_cwd),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "truncated": out_trunc or err_trunc,
            "duration_ms": duration_ms,
        }
        self.policy.audit.log_event(
            tool_name=tool_name,
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            arguments={"command": command, "cwd": str(resolved_cwd), "timeout_seconds": timeout},
            result_summary={
                "exit_code": exit_code,
                "timed_out": timed_out,
                "truncated": res["truncated"],
            },
            session_id=session_id,
            duration_ms=duration_ms,
        )
        return res

    def powershell_execute(
        self,
        command: str,
        cwd: str,
        *,
        timeout_seconds: int | float | None = None,
        env: dict[str, str] | None = None,
        max_output_bytes: int | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        return self._execute_sync(
            "powershell_execute",
            "powershell",
            command,
            cwd,
            timeout_seconds=timeout_seconds,
            env=env,
            max_output_bytes=max_output_bytes,
            session_id=session_id,
            approval_token=approval_token,
        )

    def cmd_execute(
        self,
        command: str,
        cwd: str,
        *,
        timeout_seconds: int | float | None = None,
        env: dict[str, str] | None = None,
        max_output_bytes: int | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        return self._execute_sync(
            "cmd_execute",
            "cmd",
            command,
            cwd,
            timeout_seconds=timeout_seconds,
            env=env,
            max_output_bytes=max_output_bytes,
            session_id=session_id,
            approval_token=approval_token,
        )

    # ------------------------------------------------------------------
    # Managed Background Processes (process_start, process_status, process_stop)
    # ------------------------------------------------------------------
    def process_start(
        self,
        command: str,
        cwd: str,
        *,
        shell: str = "powershell",
        env: dict[str, str] | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "process_start",
            {"command": command, "cwd": cwd, "shell": shell},
            session_id=session_id,
            approval_token=approval_token,
        )
        resolved_cwd = self._validate_execution_safety(
            "process_start", command, cwd, session_id=session_id, approval_token=approval_token
        )
        with self._lock:
            active_count = self._count_running_locked()
            if active_count >= self.max_concurrent_jobs:
                raise PermissionError(
                    f"Maximum concurrent running jobs/processes limit reached ({active_count}/{self.max_concurrent_jobs})"
                )

        argv = self._build_shell_argv(command, shell)
        proc_env = self._build_sanitized_env(env)
        process_id = f"proc_{uuid.uuid4().hex[:12]}"

        stdout_file = self.jobs_dir / f"{process_id}.stdout.log"
        stderr_file = self.jobs_dir / f"{process_id}.stderr.log"
        out_fh = open(stdout_file, "wb")
        err_fh = open(stderr_file, "wb")

        proc = subprocess.Popen(
            argv,
            cwd=str(resolved_cwd),
            stdout=out_fh,
            stderr=err_fh,
            env=proc_env,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        with self._lock:
            self._processes[process_id] = {
                "process_id": process_id,
                "pid": proc.pid,
                "popen": proc,
                "stdout_fh": out_fh,
                "stderr_fh": err_fh,
                "stdout_file": stdout_file,
                "stderr_file": stderr_file,
                "command": redact_secrets(command),
                "cwd": str(resolved_cwd),
                "started_at": datetime.now(timezone.utc).isoformat(),
                "stopped": False,
            }

        res = {
            "ok": True,
            "process_id": process_id,
            "pid": proc.pid,
            "status": "running",
            "cwd": str(resolved_cwd),
        }
        self.policy.audit.log_event(
            tool_name="process_start",
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            arguments={"command": command, "cwd": str(resolved_cwd)},
            result_summary=res,
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def process_status(
        self,
        process_id: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.policy.authorize_tool(
            "process_status", {"process_id": process_id}, session_id=session_id, approval_token=approval_token
        )
        with self._lock:
            info = self._processes.get(process_id)
        if not info:
            raise KeyError(f"Unknown process_id: {process_id}")

        proc: subprocess.Popen[bytes] = info["popen"]
        rc = proc.poll()
        running = rc is None
        stdout_raw = info["stdout_file"].read_bytes() if info["stdout_file"].exists() else b""
        stderr_raw = info["stderr_file"].read_bytes() if info["stderr_file"].exists() else b""
        stdout_str, out_trunc = self._truncate_and_redact(stdout_raw)
        stderr_str, err_trunc = self._truncate_and_redact(stderr_raw)

        return {
            "process_id": process_id,
            "pid": info["pid"],
            "status": "running" if running else ("stopped" if info["stopped"] else "exited"),
            "exit_code": rc,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "truncated": out_trunc or err_trunc,
            "started_at": info["started_at"],
        }

    def process_stop(
        self,
        process_id: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "process_stop", {"process_id": process_id}, session_id=session_id, approval_token=approval_token
        )
        with self._lock:
            info = self._processes.get(process_id)
        if not info:
            raise KeyError(f"Unknown process_id: {process_id}")

        proc: subprocess.Popen[bytes] = info["popen"]
        kill_info = kill_process_tree(proc.pid)
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
        for fh_key in ("stdout_fh", "stderr_fh"):
            try:
                info[fh_key].close()
            except Exception:
                pass
        info["stopped"] = True

        res = {
            "ok": True,
            "process_id": process_id,
            "pid": info["pid"],
            "status": "stopped",
            "killed_pids": kill_info["killed_pids"],
        }
        self.policy.audit.log_event(
            tool_name="process_stop",
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            arguments={"process_id": process_id},
            result_summary=res,
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    # ------------------------------------------------------------------
    # Durable Background Jobs (job_create, job_poll, job_cancel, job_logs)
    # ------------------------------------------------------------------
    def _job_state_path(self, job_id: str) -> Path:
        if not job_id or "/" in job_id or "\\" in job_id or ".." in job_id:
            raise ValueError(f"Invalid job_id: {job_id}")
        return self.jobs_dir / f"{job_id}.json"

    def _job_audit_path(self, job_id: str) -> Path:
        return self.jobs_dir / f"{job_id}.audit.jsonl"

    def _write_job_state(self, job_id: str, state: dict[str, Any]) -> None:
        target = self._job_state_path(job_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".tmp_{job_id}_", dir=str(self.jobs_dir))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(str(tmp_path), str(target))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def _read_job_state(self, job_id: str) -> dict[str, Any]:
        p = self._job_state_path(job_id)
        if not p.exists():
            raise KeyError(f"Job not found: {job_id}")
        return json.loads(p.read_text(encoding="utf-8"))

    def _append_job_audit(self, job_id: str, event: str, details: dict[str, Any]) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": job_id,
            "event": event,
            "details": redact_secrets(details),
        }
        audit_file = self._job_audit_path(job_id)
        with open(audit_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def job_create(
        self,
        command: str,
        cwd: str,
        *,
        shell: str = "powershell",
        timeout_seconds: int | float = 120,
        env: dict[str, str] | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "job_create",
            {"command": command, "cwd": cwd, "shell": shell, "timeout_seconds": timeout_seconds},
            session_id=session_id,
            approval_token=approval_token,
        )
        resolved_cwd = self._validate_execution_safety(
            "job_create", command, cwd, session_id=session_id, approval_token=approval_token
        )
        timeout = max(1.0, min(float(self.policy.max_timeout_seconds), float(timeout_seconds)))
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        with self._lock:
            active_count = self._count_running_locked()
            if active_count >= self.max_concurrent_jobs:
                raise PermissionError(
                    f"Maximum concurrent running jobs/processes limit reached ({active_count}/{self.max_concurrent_jobs})"
                )
            self._active_jobs.add(job_id)

        argv = self._build_shell_argv(command, shell)
        proc_env = self._build_sanitized_env(env)

        stdout_log = self.jobs_dir / f"{job_id}.stdout.log"
        stderr_log = self.jobs_dir / f"{job_id}.stderr.log"
        created_iso = datetime.now(timezone.utc).isoformat()

        initial_state: dict[str, Any] = {
            "job_id": job_id,
            "status": "running",
            "shell": shell,
            "command": redact_secrets(command),
            "cwd": str(resolved_cwd),
            "pid": None,
            "exit_code": None,
            "timed_out": False,
            "cancelled": False,
            "created_at": created_iso,
            "finished_at": None,
            "timeout_seconds": timeout,
            "stdout_path": str(stdout_log),
            "stderr_path": str(stderr_log),
            "audit_path": str(self._job_audit_path(job_id)),
        }
        self._write_job_state(job_id, initial_state)
        self._append_job_audit(job_id, "JOB_CREATED", {"command": command, "cwd": str(resolved_cwd)})

        def _worker() -> None:
            out_fh = open(stdout_log, "wb")
            err_fh = open(stderr_log, "wb")
            proc = subprocess.Popen(
                argv,
                cwd=str(resolved_cwd),
                stdout=out_fh,
                stderr=err_fh,
                env=proc_env,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
            with self._lock:
                self._job_procs[job_id] = proc
                state = self._read_job_state(job_id)
                state["pid"] = proc.pid
                self._write_job_state(job_id, state)
            self._append_job_audit(job_id, "JOB_RUNNING", {"pid": proc.pid})

            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_process_tree(proc.pid)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    pass
            finally:
                out_fh.close()
                err_fh.close()

            with self._lock:
                self._active_jobs.discard(job_id)
                self._job_procs.pop(job_id, None)
                state = self._read_job_state(job_id)
                if state.get("cancelled"):
                    state["status"] = "cancelled"
                    state["exit_code"] = proc.returncode if proc.returncode is not None else -15
                elif timed_out:
                    state["status"] = "timed_out"
                    state["timed_out"] = True
                    state["exit_code"] = -1
                else:
                    rc = proc.returncode
                    state["exit_code"] = rc
                    state["status"] = "completed" if rc == 0 else "failed"
                state["finished_at"] = datetime.now(timezone.utc).isoformat()
                self._write_job_state(job_id, state)
                self._append_job_audit(
                    job_id,
                    "JOB_FINISHED",
                    {"status": state["status"], "exit_code": state["exit_code"], "timed_out": timed_out},
                )

        worker_thread = threading.Thread(target=_worker, name=f"JobWorker-{job_id}", daemon=True)
        with self._lock:
            self._job_threads[job_id] = worker_thread
        worker_thread.start()

        # Wait briefly for PID assignment
        for _ in range(20):
            st = self._read_job_state(job_id)
            if st.get("pid") is not None:
                break
            time.sleep(0.02)

        final_init = self._read_job_state(job_id)
        self.policy.audit.log_event(
            tool_name="job_create",
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            arguments={"command": command, "cwd": str(resolved_cwd), "timeout_seconds": timeout},
            result_summary={"job_id": job_id, "pid": final_init.get("pid"), "status": final_init.get("status")},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return final_init

    def job_poll(
        self,
        job_id: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "job_poll", {"job_id": job_id}, session_id=session_id, approval_token=approval_token
        )
        state = self._read_job_state(job_id)
        self.policy.audit.log_event(
            tool_name="job_poll",
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            arguments={"job_id": job_id},
            result_summary={"job_id": job_id, "status": state.get("status")},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return state

    def job_cancel(
        self,
        job_id: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "job_cancel", {"job_id": job_id}, session_id=session_id, approval_token=approval_token
        )
        with self._lock:
            self._active_jobs.discard(job_id)
            state = self._read_job_state(job_id)
            proc = self._job_procs.get(job_id)
            pid = proc.pid if proc is not None else state.get("pid")
            state["cancelled"] = True
            if state["status"] == "running":
                state["status"] = "cancelled"
                state["finished_at"] = datetime.now(timezone.utc).isoformat()
            self._write_job_state(job_id, state)

        killed = {"pid": pid, "killed_pids": []}
        if pid:
            killed = kill_process_tree(int(pid))

        t = self._job_threads.get(job_id)
        if t and t.is_alive():
            t.join(timeout=2.0)

        self._append_job_audit(job_id, "JOB_CANCELLED", {"pid": pid, "killed_pids": killed["killed_pids"]})
        updated = self._read_job_state(job_id)
        self.policy.audit.log_event(
            tool_name="job_cancel",
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            arguments={"job_id": job_id},
            result_summary={"job_id": job_id, "status": updated["status"], "killed_pids": killed["killed_pids"]},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return updated

    def job_logs(
        self,
        job_id: str,
        *,
        offset: int = 0,
        limit: int = 50_000,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.policy.authorize_tool(
            "job_logs",
            {"job_id": job_id, "offset": offset, "limit": limit},
            session_id=session_id,
            approval_token=approval_token,
        )
        state = self._read_job_state(job_id)
        out_path = Path(state["stdout_path"])
        err_path = Path(state["stderr_path"])
        audit_path = Path(state["audit_path"])

        raw_out = out_path.read_bytes()[max(0, offset) :] if out_path.exists() else b""
        raw_err = err_path.read_bytes()[max(0, offset) :] if err_path.exists() else b""
        eff_limit = min(max(1, limit), self.policy.max_output_bytes)
        stdout_str, out_trunc = self._truncate_and_redact(raw_out, eff_limit)
        stderr_str, err_trunc = self._truncate_and_redact(raw_err, eff_limit)

        audit_entries: list[dict[str, Any]] = []
        if audit_path.exists():
            for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        audit_entries.append(json.loads(line))
                    except ValueError:
                        pass

        return {
            "job_id": job_id,
            "status": state["status"],
            "exit_code": state["exit_code"],
            "stdout": stdout_str,
            "stderr": stderr_str,
            "truncated": out_trunc or err_trunc,
            "audit_trail": audit_entries,
        }
