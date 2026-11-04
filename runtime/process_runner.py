"""Process Tree Lifecycle Execution & AuthPrincipal Security Engine.

Remediates Audit Findings C1 & C2:
  - C1: Deterministic Parent-Child-Grandchild tracking with PID + create_time matching.
        Eliminates false passes and count inflation. Cleans orphan descendants even
        if parent exits early. Strict memory-bounded dual-stream stdout/stderr.
  - C2: Replaces legacy hardcoded caller name fallbacks with verified AuthPrincipal
        authorization checks (mcp:owner / is_owner).
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil


@dataclass
class ProcessTreeResult:
    """Dataclass contract for process tree execution and verified cleanup evidence."""
    exit_code: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    interrupted_by_emergency_stop: bool = False
    cancelled: bool = False
    parent_pid: Optional[int] = None
    parent_terminated: bool = True
    children_discovered: List[Dict[str, Any]] = field(default_factory=list)
    descendants_expected: int = 0
    descendants_terminated: int = 0
    descendants_killed: int = 0  # Backward-compatible alias for descendants_terminated
    survivors: List[int] = field(default_factory=list)
    cleanup_status: str = "NOT_NEEDED"  # "CLEAN", "PARTIAL", "FAILED", "NOT_NEEDED"
    cleanup_error: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def interrupted(self) -> bool:
        return self.interrupted_by_emergency_stop or self.cancelled

    @property
    def truncated(self) -> bool:
        return self.stdout_truncated or self.stderr_truncated

    @property
    def cleanup_verified(self) -> bool:
        return self.cleanup_status in ("CLEAN", "NOT_NEEDED") and len(self.survivors) == 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary matching gateway response expectations."""
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "timed_out": self.timed_out,
            "interrupted": self.interrupted,
            "interrupted_by_emergency_stop": self.interrupted_by_emergency_stop,
            "cancelled": self.cancelled,
            "parent_pid": self.parent_pid,
            "parent_terminated": self.parent_terminated,
            "children_discovered": self.children_discovered,
            "descendants_expected": self.descendants_expected,
            "descendants_terminated": self.descendants_terminated,
            "descendants_killed": self.descendants_killed,
            "survivors": self.survivors,
            "cleanup_status": self.cleanup_status,
            "cleanup_verified": self.cleanup_verified,
            "cleanup_error": self.cleanup_error,
            "truncated": self.truncated,
            "duration_seconds": self.duration_seconds,
        }


def safe_process_info(proc: psutil.Process) -> Dict[str, Any]:
    """Safely extract PID, create_time, and executable path from a psutil.Process."""
    pid = proc.pid
    try:
        create_time = proc.create_time()
    except Exception:
        create_time = 0.0
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    return {"pid": pid, "create_time": create_time, "exe": exe}


def is_process_alive_with_create_time(pid: int, expected_create_time: float, tolerance: float = 1.0) -> bool:
    """Verify whether a process with the exact PID and create_time is currently alive.
    
    Guards against PID recycling by operating systems.
    """
    try:
        if not psutil.pid_exists(pid):
            return False
        p = psutil.Process(pid)
        if not p.is_running() or p.status() == psutil.STATUS_ZOMBIE:
            return False
        if expected_create_time > 0.0:
            actual_ct = p.create_time()
            if abs(actual_ct - expected_create_time) > tolerance:
                # PID has been recycled by a new process
                return False
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False
    except Exception:
        return False


def terminate_process_tree(
    parent_pid: Optional[int],
    target_descendants: List[Dict[str, Any]],
    timeout_seconds: float = 5.0,
) -> Tuple[bool, int, List[int], Optional[str]]:
    """Recursively and forcefully terminate a process tree (parent + descendants).
    
    Returns:
        (parent_terminated, descendants_terminated, survivors, cleanup_error)
    """
    cleanup_error: Optional[str] = None
    parent_terminated = True
    survivors: List[int] = []

    # 1. On Windows, execute taskkill /F /T /PID on parent if alive
    if parent_pid is not None and psutil.pid_exists(parent_pid):
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(parent_pid)],
                capture_output=True,
                text=True,
                timeout=max(2.0, min(timeout_seconds, 5.0)),
            )
        except Exception as tk_err:
            cleanup_error = f"taskkill parent error: {tk_err}"

    # 2. Iterate psutil handles for descendants
    procs_to_wait: List[psutil.Process] = []
    
    # Also attempt taskkill on any descendant process whose parent might already be gone
    for d in target_descendants:
        d_pid = d["pid"]
        d_ct = d.get("create_time", 0.0)
        if is_process_alive_with_create_time(d_pid, d_ct):
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(d_pid)],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                )
            except Exception:
                pass
            try:
                p_obj = psutil.Process(d_pid)
                p_obj.kill()
                procs_to_wait.append(p_obj)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    if parent_pid is not None:
        try:
            p_parent = psutil.Process(parent_pid)
            p_parent.kill()
            procs_to_wait.append(p_parent)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Wait for processes to disappear
    if procs_to_wait:
        try:
            gone, alive = psutil.wait_procs(procs_to_wait, timeout=timeout_seconds)
            for p in alive:
                try:
                    p.kill()
                except Exception:
                    pass
        except Exception as wait_err:
            cleanup_error = f"wait_procs error: {wait_err}"

    # 3. Final verification against exact PID + create_time
    if parent_pid is not None:
        parent_terminated = not psutil.pid_exists(parent_pid)

    descendants_terminated = 0
    for d in target_descendants:
        d_pid = d["pid"]
        d_ct = d.get("create_time", 0.0)
        if is_process_alive_with_create_time(d_pid, d_ct):
            survivors.append(d_pid)
        else:
            descendants_terminated += 1

    return parent_terminated, descendants_terminated, survivors, cleanup_error


def execute_powershell_tree(
    command: str,
    *,
    cwd: Optional[str | Path] = None,
    timeout_seconds: float = 60.0,
    max_output_bytes: int = 65536,
    stop_check_fn: Optional[Callable[[], bool]] = None,
    cancel_check_fn: Optional[Callable[[], bool]] = None,
    poll_interval_seconds: float = 0.04,
    cleanup_timeout_seconds: float = 5.0,
    powershell_executable: str = "powershell.exe",
    extra_ps_args: Optional[List[str]] = None,
) -> ProcessTreeResult:
    """Execute a PowerShell command with process-tree discovery, dual-stream bounded readers,
    and verified cleanup.
    """
    start_mono = time.monotonic()
    ps_args = [
        powershell_executable,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ]
    if extra_ps_args:
        ps_args.extend(extra_ps_args)
    ps_args.extend(["-Command", command])

    str_cwd = str(cwd) if cwd is not None else None

    # Bounded byte buffers
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    out_flag = [False]
    err_flag = [False]

    def _drain_stream(stream, buf: bytearray, flag: List[bool]) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                if len(buf) < max_output_bytes:
                    avail = max_output_bytes - len(buf)
                    buf.extend(chunk[:avail])
                    if len(chunk) > avail:
                        flag[0] = True
                else:
                    flag[0] = True
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    discovered_descendants: Dict[int, Dict[str, Any]] = {}
    proc: Optional[subprocess.Popen] = None
    parent_pid: Optional[int] = None
    parent_create_time: float = 0.0

    timed_out = False
    interrupted_stop = False
    cancelled = False
    exit_code = 0

    try:
        proc = subprocess.Popen(
            ps_args,
            cwd=str_cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        parent_pid = proc.pid
        try:
            parent_create_time = psutil.Process(parent_pid).create_time()
        except Exception:
            parent_create_time = 0.0

        t_out = threading.Thread(target=_drain_stream, args=(proc.stdout, stdout_buf, out_flag), daemon=True)
        t_err = threading.Thread(target=_drain_stream, args=(proc.stderr, stderr_buf, err_flag), daemon=True)
        t_out.start()
        t_err.start()

        while True:
            # 1. Discover descendants continuously
            try:
                if psutil.pid_exists(parent_pid):
                    p_obj = psutil.Process(parent_pid)
                    for child in p_obj.children(recursive=True):
                        try:
                            c_pid = child.pid
                            if c_pid != parent_pid and c_pid not in discovered_descendants:
                                discovered_descendants[c_pid] = safe_process_info(child)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # 2. Check if parent process exited
            ret = proc.poll()
            if ret is not None:
                exit_code = ret
                # Even if parent has exited, check if orphan descendants survived
                orphan_alive = False
                for d in list(discovered_descendants.values()):
                    if is_process_alive_with_create_time(d["pid"], d.get("create_time", 0.0)):
                        orphan_alive = True
                        break
                if not orphan_alive:
                    # Clean completion: parent dead and all descendants dead
                    break
                else:
                    # Parent exited early leaving orphans; must trigger cleanup!
                    break

            # 3. Check emergency stop
            if stop_check_fn is not None and stop_check_fn():
                interrupted_stop = True
                exit_code = -1
                break

            # 4. Check cancellation
            if cancel_check_fn is not None and cancel_check_fn():
                cancelled = True
                exit_code = -1
                break

            # 5. Check timeout
            elapsed = time.monotonic() - start_mono
            if elapsed > timeout_seconds:
                timed_out = True
                exit_code = -1
                break

            time.sleep(poll_interval_seconds)

        # Determine if cleanup is required
        needs_cleanup = timed_out or interrupted_stop or cancelled
        
        # Check for orphan descendants even if parent terminated normally
        surviving_before_cleanup: List[Dict[str, Any]] = []
        for d in discovered_descendants.values():
            if is_process_alive_with_create_time(d["pid"], d.get("create_time", 0.0)):
                surviving_before_cleanup.append(d)

        if surviving_before_cleanup:
            needs_cleanup = True

        cleanup_error: Optional[str] = None
        descendants_terminated = 0
        descendants_expected = len(surviving_before_cleanup)
        survivors: List[int] = []
        parent_terminated = True

        if needs_cleanup:
            p_term, d_term, surs, cl_err = terminate_process_tree(
                parent_pid=parent_pid,
                target_descendants=surviving_before_cleanup,
                timeout_seconds=cleanup_timeout_seconds,
            )
            parent_terminated = p_term
            descendants_terminated = d_term
            survivors = surs
            cleanup_error = cl_err

            if len(survivors) == 0:
                cleanup_status = "CLEAN"
            elif descendants_terminated > 0:
                cleanup_status = "PARTIAL"
            else:
                cleanup_status = "FAILED"
        else:
            cleanup_status = "NOT_NEEDED"
            parent_terminated = True
            descendants_expected = len(discovered_descendants)
            descendants_terminated = 0
            survivors = []

        # Join streams
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

        stdout_truncated = out_flag[0]
        stderr_truncated = err_flag[0]

        stdout_text = stdout_buf.decode("utf-8", errors="replace")
        stderr_text = stderr_buf.decode("utf-8", errors="replace")

        # Format diagnostic messages in stderr if terminated abnormally
        if timed_out:
            diag = "process tree terminated" if cleanup_status == "CLEAN" else f"cleanup {cleanup_status.lower()}"
            stderr_text = f"Command timed out after {timeout_seconds}s ({diag})\n{stderr_text}"
        elif interrupted_stop:
            diag = "process tree terminated" if cleanup_status == "CLEAN" else f"cleanup {cleanup_status.lower()}"
            stderr_text = f"Command interrupted: Emergency Stop triggered ({diag})\n{stderr_text}"
        elif cancelled:
            diag = "process tree terminated" if cleanup_status == "CLEAN" else f"cleanup {cleanup_status.lower()}"
            stderr_text = f"Command interrupted: Task Cancelled ({diag})\n{stderr_text}"

        dur = time.monotonic() - start_mono

        return ProcessTreeResult(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            timed_out=timed_out,
            interrupted_by_emergency_stop=interrupted_stop,
            cancelled=cancelled,
            parent_pid=parent_pid,
            parent_terminated=parent_terminated,
            children_discovered=list(discovered_descendants.values()),
            descendants_expected=descendants_expected,
            descendants_terminated=descendants_terminated,
            descendants_killed=descendants_terminated,
            survivors=survivors,
            cleanup_status=cleanup_status,
            cleanup_error=cleanup_error,
            duration_seconds=dur,
        )

    except Exception as ex:
        # Handle unexpected process launch errors
        dur = time.monotonic() - start_mono
        return ProcessTreeResult(
            exit_code=-1,
            stdout="",
            stderr=str(ex),
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
            interrupted_by_emergency_stop=False,
            cancelled=False,
            parent_pid=parent_pid,
            parent_terminated=True,
            children_discovered=list(discovered_descendants.values()),
            descendants_expected=0,
            descendants_terminated=0,
            descendants_killed=0,
            survivors=[],
            cleanup_status="FAILED",
            cleanup_error=str(ex),
            duration_seconds=dur,
        )


def verify_cloud_principal(
    auth_principal: Any,
    *,
    internal_local_trusted: bool = False,
) -> Tuple[bool, bool, str]:
    """Strictly verify caller principal for cloud surfaces (Audit Remediation C2).
    
    Returns:
        (is_authenticated: bool, is_owner: bool, caller_identity: str)
    
    Security Contract:
      1. Under NO circumstance does a caller name like "local_owner" or "chatgpt_cloud_client"
         grant owner privileges when auth_principal is None or unauthenticated.
      2. If auth_principal is present:
         - is_owner is True ONLY if auth_principal.is_owner is True (derived from verified
           mcp:owner / mcp:all OAuth scope).
         - caller_identity is derived strictly from verified client_id or subject.
      3. If auth_principal is None:
         - Allowed only if internal_local_trusted is True (in-process local CLI / test).
         - Otherwise (cloud surface), authentication and owner privileges are rejected.
    """
    if auth_principal is not None:
        is_authenticated = bool(getattr(auth_principal, "is_authenticated", True))
        is_owner = bool(getattr(auth_principal, "is_owner", False))
        identity = str(
            getattr(auth_principal, "client_id", "")
            or getattr(auth_principal, "subject", "")
            or "authenticated_client"
        )
        return is_authenticated, is_owner, identity

    if internal_local_trusted:
        # Explicit local in-process invocation
        return True, True, "local_owner"

    # Cloud surface with missing AuthPrincipal
    return False, False, ""
