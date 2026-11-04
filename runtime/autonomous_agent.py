"""Antigravity 2.0 Turbo — Autonomous Agent Execution Engine.

Implements the Plan-Act-Observe-Verify-Repair continuous control loop:
- Task-scoped authorization via TaskGrant
- Transactional state persistence & durable SQLite checkpoints
- Idempotent action execution surviving browser disconnects & process restarts
- Dynamic test verification and heuristic/LLM-guided code repair
- Real-time pause/resume, revocation checks, and Emergency Stop circuit-breakers
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_GW_DIR = str(PROJECT_ROOT / "mcp-gateway")
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

from policy import GatewayPolicy, PermissionTier
from runtime.llm_adapter import (
    LLMProviderAdapter,
    UnsupportedObjectiveError,
    extract_objective_requirements,
    get_llm_adapter,
)
from runtime.task_grant import TaskGrant, TaskGrantBroker
from runtime.task_store import CheckpointRecord, ExecutionMode, TaskRecord, TaskState, TaskStore

if not hasattr(TaskStore, "update_task"):
    def _update_task(self: TaskStore, task_id: str, metadata: dict[str, Any] | None = None, **kwargs: Any) -> bool:
        with self._get_connection() as conn:
            updates: list[str] = []
            params: list[Any] = []
            if metadata is not None:
                updates.append("metadata = ?")
                params.append(json.dumps(metadata))
            for k, v in kwargs.items():
                if k in ("error_message", "result_summary", "state", "proposal_digest"):
                    updates.append(f"{k} = ?")
                    params.append(v)
            if not updates:
                return True
            updates.append("updated_at = ?")
            params.append(time.time())
            params.append(task_id)
            with conn:
                conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = ?", tuple(params))
            return True
    TaskStore.update_task = _update_task


def _get_process_memory_mb() -> float:
    """Measure resident set size memory of current process in MB."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            c = PMC()
            c.cb = ctypes.sizeof(PMC)
            h = ctypes.windll.kernel32.GetCurrentProcess()
            ctypes.windll.kernel32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
            ctypes.windll.kernel32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
            if ctypes.windll.kernel32.K32GetProcessMemoryInfo(h, ctypes.byref(c), c.cb):
                return c.WorkingSetSize / (1024 * 1024)
        except Exception:
            pass
    return 0.0


def _kill_process_tree(pid: int, tracked_pids: set[int] | None = None) -> tuple[bool, int, str]:
    """Terminate process with given PID and its entire child process tree, verifying complete termination."""
    if pid <= 0:
        return True, 0, "No process"
    killed_count = 0
    all_pids: set[int] = set(tracked_pids or ())
    try:
        import psutil
        if psutil.pid_exists(pid):
            all_pids.add(pid)
            try:
                p_obj = psutil.Process(pid)
                for c in p_obj.children(recursive=True):
                    all_pids.add(c.pid)
            except Exception:
                pass
    except Exception:
        pass

    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                shell=False,
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass
    else:
        try:
            import signal
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            try:
                os.kill(pid, 9)
            except Exception:
                pass

    try:
        import psutil
        for p in all_pids:
            try:
                if psutil.pid_exists(p):
                    psutil.Process(p).kill()
                    killed_count += 1
            except Exception:
                pass
    except Exception:
        pass

    alive_pids: list[int] = []
    try:
        import psutil
        for p in all_pids:
            if psutil.pid_exists(p):
                alive_pids.append(p)
    except Exception:
        pass

    if not alive_pids:
        return True, max(killed_count, len(all_pids)), "Process tree terminated cleanly"
    return False, killed_count, f"Descendants still alive: {alive_pids}"


class FailureClassification:
    TOOL_FAILURE = "TOOL_FAILURE"
    PERMISSION_DENIAL = "PERMISSION_DENIAL"
    TEST_FAILURE = "TEST_FAILURE"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    RATE_LIMIT = "RATE_LIMIT"
    UNRECOVERABLE = "UNRECOVERABLE"


class AutonomousAgentController:
    """Core autonomous controller executing a single TaskGrant lifecycle."""

    def __init__(
        self,
        task_id: str,
        store: TaskStore,
        broker: TaskGrantBroker,
        policy: GatewayPolicy | None = None,
        llm_adapter: LLMProviderAdapter | None = None,
        runtime_paths: Any = None,
    ):
        self.task_id = task_id
        self.store = store
        self.broker = broker
        self.policy = policy
        self.llm = llm_adapter or get_llm_adapter()
        self.runtime_paths = runtime_paths
        self._paused = False
        self._cancelled = False
        self._file_write_count = 0
        self._verification_passed = False
        self._last_verified_source_hash: str | None = None
        self._last_test_evidence: dict[str, Any] = {}
        self._last_exit_code: int | None = None
        self._start_time = 0.0
        self._files_modified: list[str] = []

        # Coordinate broker db_path if broker supports it
        if hasattr(self.broker, "db_path") and getattr(self.broker, "db_path", None) is None:
            self.broker.db_path = self.store.db_path

    def _check_emergency_stop(self) -> bool:
        """Check if Emergency Stop latch file is present."""
        if self.policy and self.policy.is_emergency_stop_active():
            return True
        if getattr(self, "runtime_paths", None) is not None:
            return self.runtime_paths.is_emergency_stop_active()
        emergency_file = Path(__file__).resolve().parent / "EMERGENCY_STOP"
        return emergency_file.exists()

    def _build_sanitized_env(self) -> dict[str, str]:
        """Strip confidential API keys and credentials from subprocess execution environment."""
        exact_keys = {
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "MCP_AUTH_TOKEN",
            "GITHUB_TOKEN",
        }
        match_tokens = ("SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY", "API_KEY", "AWS_", "AZURE_")
        env = {}
        for k, v in os.environ.items():
            k_upper = k.upper()
            if k_upper in exact_keys or any(token in k_upper for token in match_tokens):
                continue
            env[k] = v
        return env

    def _check_interrupts(self, grant: TaskGrant) -> tuple[bool, str | None]:
        """Check Emergency Stop, SQLite heartbeat / control signals, and grant revocation."""
        if self._check_emergency_stop():
            return True, "Emergency Stop is active"
        if self._cancelled:
            return True, "Task cancelled"
        if self._paused:
            return True, "Task paused"

        # SQLite heartbeat & cross-process control signals
        hb = self.store.heartbeat(self.task_id, worker_pid=os.getpid())
        if hb:
            sig = hb.get("control_signal")
            if sig == "PAUSE":
                self._paused = True
                return True, "Operator PAUSE signal received"
            if sig == "CANCEL":
                self._cancelled = True
                return True, "Operator CANCEL signal received"
            st = hb.get("state")
            if st == TaskState.PAUSED.value:
                self._paused = True
                return True, "Task paused by operator"
            if st in (TaskState.CANCELLED.value, TaskState.FAILED.value):
                self._cancelled = True
                return True, f"Task transitioned to {st}"

        # Grant validity & revocation check
        try:
            valid, msg = self.broker.validate_grant(grant, expected_task_id=self.task_id)
        except TypeError:
            valid, msg = self.broker.validate_grant(grant)
            if valid and getattr(grant, "task_id", None) != self.task_id:
                valid = False
                msg = f"Cross-task grant reuse denied (G02): Grant {grant.grant_id} issued for {grant.task_id}, not {self.task_id}"

        if not valid:
            return True, f"TaskGrant invalid: {msg}"
        if grant.revoked:
            return True, f"TaskGrant revoked: {grant.revoked_reason}"

        # Wall-time & expiration check
        if time.time() >= grant.expires_at:
            return True, "TaskGrant expired"
        if self._start_time > 0 and (time.time() - self._start_time >= grant.max_wall_time):
            return True, "BUDGET_EXHAUSTED: max_wall_time exceeded"

        return False, None

    def _compute_task_unified_diff(
        self,
        workspace_root: str,
        files_modified: list[str],
        baseline_files: dict[str, str],
    ) -> str:
        """Compute git-style unified diff for all files modified by this task."""
        ws = Path(workspace_root).resolve()
        diff_chunks: list[str] = []
        unique_files = list(dict.fromkeys(files_modified))
        for fpath_str in unique_files:
            p = Path(fpath_str).resolve()
            try:
                rel_posix = p.relative_to(ws).as_posix()
            except ValueError:
                rel_posix = p.name

            before_text = baseline_files.get(rel_posix)
            after_text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else None
            if before_text is not None and before_text == after_text:
                # Re-created identical target deliverable from scratch
                before_text = None

            from_lines = before_text.splitlines(keepends=True) if before_text is not None else []
            to_lines = after_text.splitlines(keepends=True) if after_text is not None else []

            fromfile = "/dev/null" if before_text is None else f"a/{rel_posix}"
            tofile = f"b/{rel_posix}" if after_text is not None else "/dev/null"

            chunk = list(difflib.unified_diff(
                from_lines,
                to_lines,
                fromfile=fromfile,
                tofile=tofile,
                lineterm="\n",
            ))
            if chunk:
                diff_chunks.append("".join(chunk))

        return "\n".join(diff_chunks)

    def _sync_task_diff(
        self,
        workspace_root: str,
        baseline_files: dict[str, str],
        task: TaskRecord,
    ) -> str:
        """Compute and persist current task_diff in task metadata."""
        task_diff = self._compute_task_unified_diff(workspace_root, self._files_modified, baseline_files)
        task_meta = dict(task.metadata or {})
        task_meta["task_diff"] = task_diff
        task.metadata = task_meta
        self.store.update_task(self.task_id, metadata=task_meta)
        return task_diff

    def _verify_objective_deliverables(
        self,
        task: TaskRecord,
        workspace_root: str,
        baseline_files: dict[str, str],
        last_pytest_output: str,
    ) -> tuple[bool, str]:
        """Verify contract deliverables against objective requirements before completion."""
        reqs = extract_objective_requirements(task.objective, workspace_root)
        ws = Path(workspace_root).resolve()

        # Check 1: Every required file exists and is non-empty
        all_req_files = list(dict.fromkeys(reqs.get("required_files_to_create", []) + reqs.get("required_files_to_exist", [])))
        for req_f in all_req_files:
            target = (ws / req_f).resolve()
            if not target.exists() or not target.is_file():
                return False, f"Required file '{req_f}' does not exist on disk"
            if target.stat().st_size == 0:
                return False, f"Required file '{req_f}' is empty on disk"

        # Check 2: Every file in required_files_to_create was actually created/modified in task
        mod_resolved = {Path(f).resolve() for f in (self._files_modified or task.files_modified or [])}
        for req_f in reqs.get("required_files_to_create", []):
            target = (ws / req_f).resolve()
            if target not in mod_resolved:
                return False, f"Required file to create '{req_f}' was not modified or created during task"

        # Check 3: If forbid_modifying_existing_py is True, verify no pre-existing .py was changed
        req_create_set = {Path(f).name for f in reqs.get("required_files_to_create", [])} | set(reqs.get("required_files_to_create", []))
        if reqs.get("forbid_modifying_existing_py", False):
            for rel_path, orig_text in baseline_files.items():
                if rel_path in req_create_set or Path(rel_path).name in req_create_set:
                    continue
                if rel_path.endswith(".py"):
                    curr_file = ws / rel_path
                    if not curr_file.exists():
                        return False, f"Pre-existing python file '{rel_path}' was deleted despite prohibition"
                    try:
                        curr_text = curr_file.read_text(encoding="utf-8", errors="replace")
                    except Exception as e:
                        return False, f"Failed reading pre-existing file '{rel_path}': {e}"
                    if curr_text != orig_text:
                        return False, f"Pre-existing python file '{rel_path}' was modified despite prohibition"

        # Check 4: Every required function exists in AST in workspace
        req_funcs = reqs.get("required_functions", [])
        if req_funcs:
            all_funcs: set[str] = set()
            for py_path in ws.rglob("*.py"):
                if any(part in py_path.parts for part in (".git", "__pycache__", ".venv", ".pytest_cache")):
                    continue
                try:
                    tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"), filename=str(py_path))
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            all_funcs.add(node.name)
                except Exception:
                    pass
            for req_fn in req_funcs:
                if req_fn not in all_funcs:
                    return False, f"Required function '{req_fn}' not found in any workspace python file"

        # Check 5: min_new_tests count
        min_new_tests = reqs.get("min_new_tests", 0)
        if min_new_tests > 0:
            new_test_count = 0
            for py_path in ws.rglob("*.py"):
                if any(part in py_path.parts for part in (".git", "__pycache__", ".venv", ".pytest_cache")):
                    continue
                try:
                    rel_p = py_path.relative_to(ws).as_posix()
                except ValueError:
                    rel_p = py_path.name

                is_test_file = py_path.name.startswith("test_") or py_path.name.endswith("_test.py") or "test" in py_path.name.lower()
                if not is_test_file:
                    continue

                if rel_p not in baseline_files or rel_p in req_create_set or py_path.name in req_create_set:
                    try:
                        tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"), filename=str(py_path))
                        for node in ast.walk(tree):
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                                new_test_count += 1
                    except Exception:
                        pass
                else:
                    try:
                        orig_tree = ast.parse(baseline_files[rel_p])
                        orig_names = {
                            n.name for n in ast.walk(orig_tree)
                            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
                        }
                        curr_tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"), filename=str(py_path))
                        curr_names = {
                            n.name for n in ast.walk(curr_tree)
                            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
                        }
                        added = len(curr_names - orig_names)
                        if added > 0:
                            new_test_count += added
                    except Exception:
                        pass

            if new_test_count < min_new_tests:
                return False, f"Expected at least {min_new_tests} new tests, found {new_test_count}"

        # Check 6: min_total_tests passed
        min_total_tests = reqs.get("min_total_tests", 0)
        if min_total_tests > 0:
            fail_m = re.search(r'(\d+)\s+failed', last_pytest_output)
            if fail_m and int(fail_m.group(1)) > 0:
                return False, f"Test suite has {fail_m.group(1)} failing tests"
            err_m = re.search(r'(\d+)\s+errors?', last_pytest_output)
            if err_m and int(err_m.group(1)) > 0:
                return False, f"Test suite has {err_m.group(1)} collection errors"

            passed_m = re.search(r'(\d+)\s+passed', last_pytest_output)
            passed_count = int(passed_m.group(1)) if passed_m else None
            if passed_count is None:
                return False, "Test suite execution output missing or unverified; no passing tests recorded in task execution loop"

            if passed_count < min_total_tests:
                return False, f"Expected at least {min_total_tests} passing tests, but only {passed_count} passed"

        # Check 7: Ensure source code was not modified after verification pass
        curr_source_fp = self._compute_workspace_source_fingerprint(ws)
        if getattr(self, "_last_verified_source_hash", None) and self._last_verified_source_hash != curr_source_fp:
            return False, "Source code was modified after the last passing verification run without re-running tests"

        return True, "OK"

    _SOURCE_EXTENSIONS = frozenset({
        ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
        ".toml", ".ini", ".cfg", ".ps1", ".cmd", ".bat", ".sh", ".c", ".cpp",
        ".h", ".hpp", ".rs", ".go", ".sql", ".html", ".css", ".md"
    })
    _IGNORE_PARTS = frozenset({
        ".git", "__pycache__", ".venv", "venv", ".pytest_cache", "node_modules",
        "dist", "build", ".ruff_cache", ".mypy_cache"
    })

    def _compute_workspace_source_fingerprint(self, ws_path: Path) -> str:
        """Compute aggregate SHA-256 fingerprint of all source and configuration files in workspace."""
        h = hashlib.sha256()
        try:
            for p in sorted(ws_path.rglob("*")):
                if not p.is_file():
                    continue
                if any(part in self._IGNORE_PARTS for part in p.parts):
                    continue
                if p.suffix.lower() not in self._SOURCE_EXTENSIONS:
                    continue
                try:
                    rel_p = str(p.relative_to(ws_path)).replace("\\", "/")
                    h.update(rel_p.encode("utf-8"))
                    h.update(p.read_bytes())
                except (OSError, ValueError):
                    pass
        except Exception:
            pass
        return h.hexdigest()

    def _compute_step_hash(self, step: dict[str, Any], attempt: int = 0) -> str:
        """Compute composite idempotency key for an action step including step_id to avoid colliding different steps with same tool/args."""
        step_id = str(step.get("step_id") or "")
        action = str(step.get("action") or "")
        tool = str(step.get("tool") or "")
        args_str = json.dumps(step.get("args", {}), sort_keys=True)
        raw = f"{step_id}:{action}:{tool}:{args_str}:attempt_{attempt}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _run_structured_process(
        self,
        argv: list[str],
        cwd: str,
        timeout: float,
        grant: TaskGrant,
        is_test: bool = False,
    ) -> tuple[bool, Any, str]:
        """Execute structured subprocess with sanitized env and 0.1s tick interrupt handling."""
        if not argv:
            return False, None, "Empty command"

        exe_name = argv[0].lower()
        if exe_name in ("pytest", "pytest.exe"):
            exec_argv = [sys.executable, "-m", "pytest"] + argv[1:]
        elif exe_name in ("python", "python.exe"):
            exec_argv = [sys.executable] + argv[1:]
        else:
            resolved_exe = shutil.which(argv[0])
            if not resolved_exe:
                return False, None, f"Executable '{argv[0]}' not found"
            exec_argv = [resolved_exe] + argv[1:]

        sanitized_env = self._build_sanitized_env()
        start_cmd_time = time.time()

        ws_root_path = Path(cwd) if cwd else Path(grant.workspace_root)
        pre_exec_source_fp = self._compute_workspace_source_fingerprint(ws_root_path) if is_test else ""

        report_file: Path | None = None
        if is_test:
            is_pytest = (
                (bool(exec_argv) and Path(exec_argv[0]).stem.lower() == "pytest")
                or (len(exec_argv) >= 3 and Path(exec_argv[0]).stem.lower() in ("python", "python3") and exec_argv[1] == "-m" and exec_argv[2] == "pytest")
            )
            if is_pytest:
                run_id = f"testrun_{uuid.uuid4().hex[:12]}"
                evidence_root = self.runtime_paths.evidence_dir if getattr(self, "runtime_paths", None) else (PROJECT_ROOT / "runtime" / "evidence")
                evidence_dir = evidence_root / "tasks" / self.task_id
                evidence_dir.mkdir(parents=True, exist_ok=True)
                report_file = evidence_dir / f"{run_id}_report.xml"
                exec_argv = list(exec_argv) + [f"--junitxml={str(report_file)}"]

        try:
            proc = subprocess.Popen(
                exec_argv,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=sanitized_env,
                shell=False,
            )
        except Exception as ex:
            return False, None, f"Failed to spawn process {exec_argv[0]}: {ex}"

        tracked_pids: set[int] = set()
        while True:
            try:
                import psutil
                if psutil.pid_exists(proc.pid):
                    p_obj = psutil.Process(proc.pid)
                    for c in p_obj.children(recursive=True):
                        tracked_pids.add(c.pid)
            except Exception:
                pass

            try:
                stdout, stderr = proc.communicate(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                # Check command timeout
                if time.time() - start_cmd_time > timeout:
                    _kill_process_tree(proc.pid, tracked_pids)
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass
                    return False, None, f"Command timed out after {timeout}s"

                # Check interrupts (<500ms fail-safe)
                is_int, reason = self._check_interrupts(grant)
                if is_int:
                    _kill_process_tree(proc.pid, tracked_pids)
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass
                    return False, None, f"Interrupted: {reason}"

        output = (stdout or "") + (stderr or "")
        res = {
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output": output,
        }
        success = (proc.returncode == 0)
        self._last_exit_code = proc.returncode

        if is_test:
            structured_verified = False
            passed_cnt = 0
            failed_cnt = 0
            error_cnt = 0
            skipped_cnt = 0

            # 1. Parse JUnit XML report generated by genuine verifier for this exact run_id (R1 / V03)
            # The report file must exist, be fresh (mtime >= start_cmd_time - 1.0), and non-empty.
            if is_pytest and report_file and report_file.exists():
                file_mtime = report_file.stat().st_mtime
                if file_mtime >= (start_cmd_time - 1.0) and report_file.stat().st_size > 0:
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(report_file)
                        root = tree.getroot()
                        suites = list(root.findall("testsuite")) if root.tag == "testsuites" else [root]
                        total_tests = sum(int(s.attrib.get("tests", 0)) for s in suites)
                        total_fails = sum(int(s.attrib.get("failures", 0)) for s in suites)
                        total_errs = sum(int(s.attrib.get("errors", 0)) for s in suites)
                        total_skips = sum(int(s.attrib.get("skipped", 0)) for s in suites)
                        passed_cnt = total_tests - total_fails - total_errs - total_skips
                        failed_cnt = total_fails
                        error_cnt = total_errs
                        skipped_cnt = total_skips
                        if total_tests > 0 and passed_cnt > 0 and failed_cnt == 0 and error_cnt == 0:
                            structured_verified = True
                    except Exception:
                        structured_verified = False
                # Do NOT delete report_file — keep it in task evidence directory for auditability

            # 2. Summary line cross-check (DIAGNOSTIC ONLY — CANNOT GRANT PASS ON ITS OWN)
            # Used exclusively to disqualify if stdout reveals errors or failures missed by parser.
            summary_lines = re.findall(r'=+\s*([^\n=]+?in\s+[\d\.]+s[^\n=]*)\s*=+', output)
            if summary_lines:
                last_summary = summary_lines[-1]
                fail_m = re.search(r'\b(\d+)\s+failed\b', last_summary)
                err_m = re.search(r'\b(\d+)\s+errors?\b', last_summary)
                if fail_m and int(fail_m.group(1)) > 0:
                    failed_cnt = max(failed_cnt, int(fail_m.group(1)))
                    structured_verified = False
                if err_m and int(err_m.group(1)) > 0:
                    error_cnt = max(error_cnt, int(err_m.group(1)))
                    structured_verified = False

            # Anti-cheat check: MUST have structured_verified == True, exit_code == 0, passed_cnt > 0,
            # no collection errors, no 'collected 0 items', and no 'no tests ran'
            has_zero_collected = bool(re.search(r'collected\s+0\s+items', output, re.IGNORECASE))
            has_no_tests_ran = bool(re.search(r'no\s+tests\s+ran', output, re.IGNORECASE))
            has_errors = bool(error_cnt > 0 or re.search(r'\b(INTERNALERROR|CollectionError)\b', output))

            post_exec_source_fp = self._compute_workspace_source_fingerprint(ws_root_path)
            source_mutated_during_test = bool(pre_exec_source_fp and pre_exec_source_fp != post_exec_source_fp)
            if source_mutated_during_test:
                structured_verified = False

            is_valid_test_pass = (
                structured_verified
                and not source_mutated_during_test
                and (proc.returncode == 0)
                and (passed_cnt > 0)
                and (failed_cnt == 0)
                and (error_cnt == 0)
                and not has_zero_collected
                and not has_no_tests_ran
                and not has_errors
            )

            curr_fp = post_exec_source_fp

            if is_valid_test_pass:
                self._verification_passed = True
                self._last_verified_source_hash = curr_fp
                self._last_test_evidence = {
                    "run_id": run_id if is_pytest else None,
                    "report_path": str(report_file) if (is_pytest and report_file and report_file.exists()) else None,
                    "passed_count": passed_cnt,
                    "failed_count": failed_cnt,
                    "error_count": error_cnt,
                    "skipped_count": skipped_cnt,
                    "exit_code": proc.returncode,
                    "source_fingerprint": curr_fp,
                    "timestamp": time.time(),
                }
                self.store.update_task_progress(self.task_id, verification_passed=True)
            else:
                self._verification_passed = False
                self._last_test_evidence = {
                    "run_id": run_id if is_pytest else None,
                    "report_path": str(report_file) if (is_pytest and report_file and report_file.exists()) else None,
                    "passed_count": passed_cnt,
                    "failed_count": failed_cnt,
                    "error_count": error_cnt,
                    "skipped_count": skipped_cnt,
                    "exit_code": proc.returncode,
                    "source_fingerprint": curr_fp,
                    "timestamp": time.time(),
                }
                self.store.update_task_progress(self.task_id, verification_passed=False)
                self.store.update_task_progress(self.task_id, verification_passed=False)

        return success, res, "OK" if success else f"Command exited with code {proc.returncode}"

    def _execute_tool_action(self, grant: TaskGrant, tool_name: str, args: dict[str, Any]) -> tuple[bool, Any, str]:
        """Execute a tool action with fail-closed grant enforcement, scope containment, and safeguards."""
        # 1. Emergency stop check
        if self._check_emergency_stop():
            return False, None, "Execution blocked: Emergency Stop is active"

        # 2. Grant validity & revocation check
        try:
            valid, msg = self.broker.validate_grant(grant, expected_task_id=self.task_id)
        except TypeError:
            valid, msg = self.broker.validate_grant(grant)
            if valid and getattr(grant, "task_id", None) != self.task_id:
                valid = False
                msg = f"Cross-task grant reuse denied (G02): Grant {grant.grant_id} issued for {grant.task_id}, not {self.task_id}"

        if not valid:
            return False, None, f"Permission Denied: {msg}"

        # 3. Tool allowlist check
        if not grant.allows_tool(tool_name):
            return False, None, f"Permission Denied: Tool '{tool_name}' not permitted by TaskGrant"

        # 4. Scope containment & execution based on tool type (F03, F04)
        budget = grant.resource_budget or {}

        # Filesystem write / edit tools
        if tool_name in ("write_file", "append_file", "edit_file", "put_file"):
            target_path = args.get("path") or args.get("file_path") or ""
            if not target_path or not grant.allows_path(target_path, is_write=True):
                return False, None, f"Permission Denied: Target path '{target_path}' is outside approved workspace"

            p = Path(target_path).resolve(strict=False)

            # Check max_file_writes budget
            max_file_writes = budget.get("max_file_writes", 200)
            if self._file_write_count >= max_file_writes:
                return False, None, f"Budget exhausted: max_file_writes limit reached ({self._file_write_count})"

            # Determine content
            if tool_name in ("write_file", "put_file"):
                content = args.get("content", "")
            elif tool_name == "append_file":
                existing = p.read_text(encoding="utf-8") if p.exists() else ""
                content = existing + args.get("content", "")
            elif tool_name == "edit_file":
                if not p.exists():
                    return False, None, f"File not found: {p}"
                existing = p.read_text(encoding="utf-8")
                old_text = args.get("old_text") or args.get("target") or ""
                new_text = args.get("new_text") or args.get("replacement") or ""
                if not old_text:
                    return False, None, "edit_file requires 'old_text' or 'target' argument"
                if old_text not in existing:
                    return False, None, f"Target text not found in {p.name}"
                count = args.get("count", 1)
                content = existing.replace(old_text, new_text, count)
            else:
                content = args.get("content", "")

            # Check max_write_bytes
            max_write_bytes = budget.get("max_write_bytes", 10 * 1024 * 1024)
            content_bytes = content.encode("utf-8")
            if len(content_bytes) > max_write_bytes:
                return False, None, f"Write rejected: content size {len(content_bytes)} exceeds limit {max_write_bytes}"

            # Create backup if file already exists
            if p.exists():
                backup_dir = Path(__file__).resolve().parent.parent / "backups" / "file_versions"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_file = backup_dir / f"{self.task_id}_{int(time.time() * 1000)}_{p.name}.bak"
                try:
                    shutil.copy2(p, backup_file)
                except Exception:
                    pass

            # Atomic write (.tmp.<pid> flush & fsync -> os.replace)
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                tmp_path = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, p)
            except Exception as ex:
                return False, None, f"Failed to write file {p}: {ex}"

            # Update metrics & mark verification needed
            self._file_write_count += 1
            self.store.update_task_progress(self.task_id, file_write_delta=1)
            self._verification_passed = False
            self.store.update_task_progress(self.task_id, verification_passed=False)
            if str(p) not in self._files_modified:
                self._files_modified.append(str(p))

            return True, {"path": str(p), "bytes_written": len(content_bytes)}, "OK"

        if tool_name == "create_directory":
            target_path = args.get("path") or ""
            if not target_path or not grant.allows_path(target_path, is_write=True):
                return False, None, f"Permission Denied: Target path '{target_path}' is outside approved workspace"
            p = Path(target_path).resolve(strict=False)
            p.mkdir(parents=True, exist_ok=True)
            return True, {"path": str(p)}, "OK"

        # Filesystem read tools
        if tool_name in ("read_file", "read_file_range", "get_file"):
            target_path = args.get("path") or args.get("file_path") or ""
            if not target_path or not grant.allows_path(target_path, is_write=False):
                return False, None, f"Permission Denied: Read path '{target_path}' is outside approved workspace or is sensitive"

            p = Path(target_path).resolve(strict=False)
            if not p.exists():
                return False, None, f"File not found: {p}"

            if tool_name == "read_file_range":
                lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
                start = max(0, args.get("start_line", 1) - 1)
                end = args.get("end_line", len(lines))
                return True, {"content": "".join(lines[start:end]), "total_lines": len(lines)}, "OK"

            return True, {"content": p.read_text(encoding="utf-8")}, "OK"

        # Directory listing & searching tools
        if tool_name in ("list_directory", "search_code", "find_files", "search_files", "grep", "list_tree"):
            target_path = args.get("path") or args.get("directory") or grant.workspace_root
            if not grant.allows_path(target_path, is_write=False):
                return False, None, f"Permission Denied: Target path '{target_path}' is outside approved workspace"

            p = Path(target_path).resolve(strict=False)
            if not p.exists():
                return False, None, f"Directory not found: {p}"

            if tool_name in ("list_directory", "list_tree"):
                entries = [{"name": e.name, "is_dir": e.is_dir()} for e in p.iterdir()]
                return True, {"entries": entries}, "OK"

            query = args.get("query", "")
            matches = []
            for f in p.rglob("*"):
                if f.is_file() and grant.allows_path(f, is_write=False):
                    if query.lower() in f.name.lower():
                        matches.append(str(f))
                    elif query:
                        try:
                            if query in f.read_text(encoding="utf-8", errors="ignore"):
                                matches.append(str(f))
                        except Exception:
                            pass
            return True, {"matches": matches[:50]}, "OK"

        # Git tools
        if tool_name in ("git_status", "git_diff", "git_log"):
            cwd = args.get("cwd") or args.get("repo_path") or grant.workspace_root
            if not grant.allows_path(cwd, is_write=False):
                return False, None, "Permission Denied: Git cwd is outside approved workspace"

            if tool_name == "git_status":
                argv = ["git", "status", "--porcelain"]
            elif tool_name == "git_diff":
                argv = ["git", "diff"]
                if args.get("staged"):
                    argv.append("--staged")
            else:
                argv = ["git", "log", "-n", str(args.get("limit", 10))]

            return self._run_structured_process(argv, cwd=str(cwd), timeout=args.get("timeout", 15), grant=grant, is_test=False)

        # Command execution tools
        if tool_name in ("powershell_execute", "cmd_execute"):
            cwd = args.get("cwd", grant.workspace_root)
            if not grant.allows_path(cwd, is_write=False):
                return False, None, f"Permission Denied: Execution cwd '{cwd}' is outside approved workspace"

            cmd = args.get("command", "")
            if hasattr(grant, "parse_and_validate_command"):
                ok, argv, reason = grant.parse_and_validate_command(cmd, cwd=cwd)
                if not ok:
                    return False, None, f"Permission Denied: {reason}"
            else:
                if not grant.allows_command(cmd):
                    return False, None, f"Permission Denied: Command '{cmd}' is outside allowed command templates"
                import shlex
                try:
                    argv = shlex.split(cmd)
                except Exception as e:
                    return False, None, f"Permission Denied: Failed to parse command: {e}"

            is_test = (
                args.get("action") == "run_tests"
                or (bool(argv) and Path(argv[0]).stem.lower() == "pytest")
                or (bool(argv) and len(argv) >= 3 and Path(argv[0]).stem.lower() in ("python", "python3") and argv[1] == "-m" and argv[2] == "pytest")
                or ("pytest" in " ".join(argv).lower())
            )
            return self._run_structured_process(argv, cwd=str(cwd), timeout=args.get("timeout", 60), grant=grant, is_test=is_test)

        return False, None, f"Unsupported tool in autonomous worker: {tool_name}"

    def run(self) -> TaskRecord:
        """Execute the complete autonomous task loop with checkpoint recovery."""
        task = self.store.get_task(self.task_id)
        if not task:
            raise ValueError(f"Task {self.task_id} not found in store")

        if not task.grant_id:
            grant_by_task = self.broker.get_grant_for_task(self.task_id)
            if grant_by_task:
                task.grant_id = grant_by_task.grant_id
                self.store.bind_grant(self.task_id, grant_by_task.grant_id)
            else:
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message="No TaskGrant bound")
                return self.store.get_task(self.task_id)  # type: ignore

        grant = self.broker.get_grant(task.grant_id)
        if not grant:
            grant = self.broker.get_grant_for_task(self.task_id)
        if not grant:
            self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message="TaskGrant not found in broker")
            return self.store.get_task(self.task_id)  # type: ignore

        # Validate grant initially (G02 Cross-task check)
        try:
            is_valid, msg = self.broker.validate_grant(grant, expected_task_id=self.task_id)
        except TypeError:
            is_valid, msg = self.broker.validate_grant(grant)
            if is_valid and getattr(grant, "task_id", None) != self.task_id:
                is_valid = False
                msg = f"Cross-task grant reuse denied (G02): Grant {grant.grant_id} issued for {grant.task_id}, not {self.task_id}"

        if not is_valid:
            terminal_state = TaskState.CANCELLED.value if "revoked" in msg.lower() else TaskState.FAILED.value
            self.store.update_task_state(self.task_id, terminal_state, error_message=msg)
            return self.store.get_task(self.task_id)  # type: ignore

        self.store.update_task_state(self.task_id, TaskState.RUNNING.value)
        self.store.log_event(self.task_id, "START", f"Starting autonomous execution under grant {grant.grant_id}")

        self._start_time = time.time()
        self._file_write_count = task.file_write_count
        self._verification_passed = task.verification_passed

        # Baseline files snapshot before task modifications
        baseline_files: dict[str, str] = {}
        ws_path = Path(grant.workspace_root).resolve()
        if ws_path.exists():
            for p in ws_path.rglob("*"):
                if p.is_file():
                    if any(part in p.parts for part in (".git", "__pycache__", ".venv", ".pytest_cache")):
                        continue
                    try:
                        rel = p.relative_to(ws_path).as_posix()
                        baseline_files[rel] = p.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        pass

        # Checkpoint restoration: recover completed state if previously interrupted
        latest_chk = self.store.get_latest_checkpoint(self.task_id)
        plan: list[dict[str, Any]] = latest_chk.plan_snapshot if latest_chk else list(task.current_plan)
        completed_steps: list[dict[str, Any]] = latest_chk.completed_steps if latest_chk else list(task.completed_steps)
        self._files_modified = latest_chk.files_modified if latest_chk else list(task.files_modified)
        completed_step_hashes = {self._compute_step_hash(s) for s in completed_steps}

        tool_call_count = task.tool_call_count
        retry_count = task.retry_count

        # Step 1: Planning (if no existing plan)
        if not plan:
            self.store.update_task_state(self.task_id, TaskState.PLANNING.value)
            ws_summary = {
                "workspace_root": grant.workspace_root,
                "files": [p.name for p in Path(grant.workspace_root).glob("*") if p.is_file()],
            }
            try:
                plan = self.llm.generate_plan(task.objective, ws_summary, grant.allowed_tools)
            except Exception as exc:
                if (
                    "UNSUPPORTED_OBJECTIVE" in str(exc)
                    or "MODEL_PROVIDER_NOT_CONFIGURED" in str(exc)
                    or exc.__class__.__name__ in ("UnsupportedObjectiveError", "ModelProviderNotConfiguredError", "LiveAINotConfiguredError")
                ):
                    err_msg = str(exc)
                    task_meta = task.metadata if isinstance(task.metadata, dict) else {}
                    should_block = bool(
                        task_meta.get("block_on_missing_llm")
                        or task_meta.get("surface") == "cloud_autonomous"
                        or str(task_meta.get("task_type") or "").upper() in ("LLM_DEPENDENT", "AI_REASONING")
                    )
                    target_state = TaskState.BLOCKED.value if should_block else TaskState.FAILED.value
                    self.store.update_task_state(self.task_id, target_state, error_message=err_msg)
                    self.store.log_event(
                        self.task_id,
                        target_state,
                        err_msg,
                        level="WARN" if should_block else "ERROR",
                        data={
                            "tool_name": "planner_gate",
                            "status": "MODEL_PROVIDER_NOT_CONFIGURED" if "MODEL_PROVIDER_NOT_CONFIGURED" in err_msg else "UNSUPPORTED_OBJECTIVE",
                            "task_category": task_meta.get("task_category", "LLM_DEPENDENT"),
                        },
                    )
                    return self.store.get_task(self.task_id)  # type: ignore
                raise

            if not plan:
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message="Planning produced empty plan")
                return self.store.get_task(self.task_id)  # type: ignore
            self.store.update_task_progress(self.task_id, current_plan=plan)
            self.store.log_event(self.task_id, "PLANNING", f"Generated execution plan with {len(plan)} steps", data={"plan": plan})

        self.store.update_task_state(self.task_id, TaskState.RUNNING.value)

        has_test_steps = any(
            s.get("action") == "run_tests" or "pytest" in s.get("args", {}).get("command", "")
            for s in plan
        )

        # Main Loop: Plan-Act-Observe-Verify-Repair
        step_idx = len(completed_steps)
        max_loop_iterations = grant.max_tool_calls
        last_pytest_output: str = ""

        while step_idx < len(plan) and tool_call_count < max_loop_iterations:
            # Check pause / cancel / emergency stop / interrupts
            is_int, reason = self._check_interrupts(grant)
            if is_int:
                if self._paused or "pause" in str(reason).lower():
                    self.store.update_task_state(self.task_id, TaskState.PAUSED.value)
                    self.store.log_event(self.task_id, "PAUSED", f"Task execution paused: {reason}")
                    return self.store.get_task(self.task_id)  # type: ignore

                if self._cancelled or "cancel" in str(reason).lower() or "stop" in str(reason).lower():
                    self.store.update_task_state(self.task_id, TaskState.CANCELLED.value, error_message=f"Cancelled or halted: {reason}")
                    self.store.log_event(self.task_id, "STOP", f"Task cancelled or halted: {reason}")
                    return self.store.get_task(self.task_id)  # type: ignore

                if "expired" in str(reason).lower():
                    self.store.update_task_state(self.task_id, TaskState.EXPIRED.value, error_message=reason)
                    return self.store.get_task(self.task_id)  # type: ignore

                if "revoked" in str(reason).lower():
                    self.store.update_task_state(self.task_id, TaskState.CANCELLED.value, error_message=reason)
                    return self.store.get_task(self.task_id)  # type: ignore

                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=reason)
                return self.store.get_task(self.task_id)  # type: ignore

            # Active budget checks (F05)
            # 1. Wall time
            if time.time() - self._start_time >= grant.max_wall_time:
                err = "BUDGET_EXHAUSTED: max_wall_time exceeded"
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                return self.store.get_task(self.task_id)  # type: ignore

            # 2. Tool calls
            if tool_call_count >= grant.max_tool_calls:
                err = f"BUDGET_EXHAUSTED: max_tool_calls reached before completion ({tool_call_count}/{grant.max_tool_calls})"
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                return self.store.get_task(self.task_id)  # type: ignore

            # 3. File writes
            max_writes = (grant.resource_budget or {}).get("max_file_writes", 200)
            if self._file_write_count > max_writes:
                err = f"BUDGET_EXHAUSTED: max_file_writes exceeded ({self._file_write_count} > {max_writes})"
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                return self.store.get_task(self.task_id)  # type: ignore

            # 4. Memory budget
            mem_mb = _get_process_memory_mb()
            max_mem = (grant.resource_budget or {}).get("max_memory_mb", 2048)
            if mem_mb > max_mem:
                err = f"BUDGET_EXHAUSTED: memory budget exceeded ({mem_mb:.1f} MB > {max_mem} MB)"
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                return self.store.get_task(self.task_id)  # type: ignore

            # 5. API cost budget
            cost = getattr(self.llm, "estimated_cost", 0.0)
            if cost > grant.api_cost_budget:
                err = f"BUDGET_EXHAUSTED: api_cost_budget exceeded ({cost:.2f} > {grant.api_cost_budget:.2f})"
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                return self.store.get_task(self.task_id)  # type: ignore

            step = plan[step_idx]
            step_hash = self._compute_step_hash(step, attempt=retry_count)

            # Idempotency check: skip already committed steps
            if step_hash in completed_step_hashes:
                step_idx += 1
                continue

            # ACT
            tool = step.get("tool", "")
            args = step.get("args", {})
            self.store.log_event(self.task_id, "ACT", f"Executing {tool} for step: {step.get('step_id')}", data={"args": args})

            success, output, err_msg = self._execute_tool_action(grant, tool, args)
            tool_call_count += 1
            self.store.update_task_progress(self.task_id, tool_call_delta=1, api_cost_usd=getattr(self.llm, "estimated_cost", 0.0))

            if step.get("action") == "run_tests" or "pytest" in args.get("command", ""):
                if isinstance(output, dict):
                    last_pytest_output = (output.get("stdout") or "") + "\n" + (output.get("stderr") or "") + "\n" + (output.get("output") or "")
                else:
                    last_pytest_output = str(output)

            # OBSERVE & VERIFY
            if not success:
                self.store.log_event(self.task_id, "OBSERVE", f"Step {step.get('step_id')} failed: {err_msg}", level="WARN", data={"output": output})

                # Check if failure is an expected test failure that needs REPAIR
                is_test_step = (step.get("action") == "run_tests" or "pytest" in args.get("command", ""))
                if is_test_step and retry_count < grant.max_retries:
                    self.store.update_task_state(self.task_id, TaskState.REPAIRING.value)
                    retry_count += 1
                    self.store.update_task_progress(self.task_id, retry_delta=1)

                    test_output = output.get("output", "") if isinstance(output, dict) else str(output)
                    self.store.log_event(self.task_id, "REPAIRING", f"Diagnosing test failure (attempt {retry_count}/{grant.max_retries})")

                    repair_action = self.llm.diagnose_and_repair(task.objective, step, test_output, grant.workspace_root)
                    if repair_action:
                        rep_tool = repair_action["tool"]
                        rep_args = repair_action["args"]
                        rep_ok, rep_res, rep_err = self._execute_tool_action(grant, rep_tool, rep_args)
                        tool_call_count += 1
                        self.store.update_task_progress(self.task_id, tool_call_delta=1, api_cost_usd=getattr(self.llm, "estimated_cost", 0.0))

                        if rep_ok:
                            if "path" in rep_args and rep_args["path"] not in self._files_modified:
                                self._files_modified.append(rep_args["path"])
                            self._sync_task_diff(grant.workspace_root, baseline_files, task)
                            self.store.log_event(self.task_id, "REPAIRING", f"Applied repair: {repair_action.get('reason')}", data={"file": rep_args.get("path")})
                            # Retry the failed test step
                            self.store.update_task_state(self.task_id, TaskState.VERIFYING.value)
                            continue
                        else:
                            self.store.log_event(self.task_id, "REPAIRING", f"Repair execution failed: {rep_err}", level="ERROR")
                    else:
                        self.store.log_event(self.task_id, "REPAIRING", "Diagnosis produced no targeted repair", level="WARN")

                # If unrecoverable or out of retries
                self.store.update_task_state(
                    self.task_id,
                    TaskState.FAILED.value,
                    error_message=f"Step {step.get('step_id')} failed: {err_msg}",
                )
                return self.store.get_task(self.task_id)  # type: ignore

            # Step succeeded
            completed_steps.append(step)
            completed_step_hashes.add(step_hash)
            if tool in ("write_file", "append_file", "edit_file", "put_file") and "path" in args:
                if args["path"] not in self._files_modified:
                    self._files_modified.append(args["path"])
                self._sync_task_diff(grant.workspace_root, baseline_files, task)

            is_test_cmd = (tool in ("powershell_execute", "cmd_execute") and "pytest" in args.get("command", ""))
            # Note: self._verification_passed is set strictly by _run_structured_process based on actual test results

            # Checkpoint
            self.store.save_checkpoint(
                task_id=self.task_id,
                step_index=step_idx,
                state=TaskState.RUNNING.value,
                plan_snapshot=plan,
                completed_steps=completed_steps,
                files_modified=self._files_modified,
                test_results=output if is_test_cmd else {},
            )
            self.store.update_task_progress(
                self.task_id,
                completed_steps=completed_steps,
                files_modified=self._files_modified,
            )

            step_idx += 1

        # Strict completion validation (F05)
        if step_idx < len(plan):
            err = f"BUDGET_EXHAUSTED: max_tool_calls ({grant.max_tool_calls}) exhausted at step {step_idx}/{len(plan)}"
            self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
            self.store.log_event(self.task_id, "FAILED", err, level="ERROR")
            return self.store.get_task(self.task_id)  # type: ignore

        if not plan:
            err = "Planning produced empty plan"
            self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
            return self.store.get_task(self.task_id)  # type: ignore

        # If files were modified or plan included test steps, require verification_passed is True
        if (self._files_modified or has_test_steps) and not self._verification_passed:
            can_exec = grant.allows_tool("powershell_execute") or grant.allows_tool("cmd_execute")
            if can_exec and grant.allows_command("pytest"):
                if tool_call_count >= max_loop_iterations:
                    err = f"BUDGET_EXHAUSTED: max_tool_calls ({grant.max_tool_calls}) reached before final verification"
                    self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                    self.store.log_event(self.task_id, "FAILED", err, level="ERROR")
                    return self.store.get_task(self.task_id)  # type: ignore

                tool = "powershell_execute" if grant.allows_tool("powershell_execute") else "cmd_execute"
                v_ok, v_out, v_err = self._execute_tool_action(
                    grant, tool, {"command": "pytest", "cwd": grant.workspace_root, "action": "run_tests"}
                )
                tool_call_count += 1
                self.store.update_task_progress(self.task_id, tool_call_delta=1)

                if isinstance(v_out, dict):
                    last_pytest_output = (v_out.get("stdout") or "") + "\n" + (v_out.get("stderr") or "") + "\n" + (v_out.get("output") or "")
                else:
                    last_pytest_output = str(v_out)

            if not self._verification_passed:
                err = "Verification failed or did not run after code modifications"
                self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
                self.store.log_event(self.task_id, "FAILED", err, level="ERROR")
                return self.store.get_task(self.task_id)  # type: ignore

        # Compute final task diff
        self._sync_task_diff(grant.workspace_root, baseline_files, task)

        # Strict objective deliverable verification gate
        v_ok, v_reason = self._verify_objective_deliverables(
            task=task,
            workspace_root=grant.workspace_root,
            baseline_files=baseline_files,
            last_pytest_output=last_pytest_output,
        )
        task_meta = dict(task.metadata or {})
        task_meta["acceptance_passed"] = bool(v_ok)
        task_meta["acceptance_reason"] = v_reason
        task_meta["test_evidence"] = getattr(self, "_last_test_evidence", {})
        task_meta["source_fingerprint"] = self._compute_workspace_source_fingerprint(Path(grant.workspace_root))
        task_meta["last_exit_code"] = getattr(self, "_last_exit_code", 0 if v_ok else 1)
        task.metadata = task_meta
        self.store.update_task_metadata(self.task_id, task_meta)

        if not v_ok:
            err = f"OBJECTIVE_DELIVERABLE_MISSING: {v_reason}"
            self.store.update_task_state(self.task_id, TaskState.FAILED.value, error_message=err)
            self.store.log_event(
                self.task_id,
                "FAILED",
                err,
                level="ERROR",
                data={"tool_name": "deliverable_gate", "status": "OBJECTIVE_DELIVERABLE_MISSING"},
            )
            return self.store.get_task(self.task_id)  # type: ignore

        summary = f"Autonomous task completed successfully. {len(completed_steps)} steps executed, {len(self._files_modified)} files modified."
        self.store.update_task_state(self.task_id, TaskState.COMPLETED.value, result_summary=summary)
        self.store.log_event(self.task_id, "COMPLETED", summary)
        return self.store.get_task(self.task_id)  # type: ignore

    def pause(self) -> None:
        self._paused = True
        self.store.set_control_signal(self.task_id, "PAUSE")

    def resume(self) -> None:
        self._paused = False
        self.store.set_control_signal(self.task_id, "RESUME")

    def cancel(self) -> None:
        self._cancelled = True
        self.store.set_control_signal(self.task_id, "CANCEL")

    _run_structured_command = _run_structured_process


class UnattendedWorkerDaemon:
    """Persistent background worker daemon polling and executing approved tasks."""

    def __init__(
        self,
        store: TaskStore,
        broker: TaskGrantBroker,
        policy: GatewayPolicy | None = None,
        poll_interval_seconds: float = 2.0,
    ):
        self.store = store
        self.broker = broker
        self.policy = policy
        self.poll_interval = poll_interval_seconds
        self.running = False

        if hasattr(self.broker, "db_path") and getattr(self.broker, "db_path", None) is None:
            self.broker.db_path = self.store.db_path

    def start(self, max_tasks: int | None = None, target_task_id: str | None = None) -> int:
        """Run daemon loop, claiming and executing QUEUED tasks."""
        self.running = True
        processed = 0
        while self.running:
            # Check for Emergency Stop
            emergency_file = Path(__file__).resolve().parent / "EMERGENCY_STOP"
            if emergency_file.exists():
                time.sleep(self.poll_interval)
                continue

            task = self.store.claim_next_queued_task(
                worker_pid=os.getpid(),
                target_task_id=target_task_id if processed == 0 else None,
            )
            if task:
                ctrl = AutonomousAgentController(task.task_id, self.store, self.broker, self.policy)
                ctrl.run()
                processed += 1
                if max_tasks is not None and processed >= max_tasks:
                    break
            else:
                if max_tasks == 1 and target_task_id:
                    break
                time.sleep(self.poll_interval)
        return processed

    def stop(self) -> None:
        self.running = False


def spawn_independent_worker_once(
    db_path: Path | str,
    key_path: Path | str | None = None,
    max_tasks: int = 1,
    target_task_id: str | None = None,
) -> int:
    """Spawns an independent OS Python process running UnattendedWorkerDaemon once without blocking."""
    cwd = str(Path(__file__).resolve().parent.parent)
    cmd = [
        sys.executable,
        "-m",
        "runtime.autonomous_agent",
        "--db-path",
        str(db_path),
        *(["--key-path", str(key_path)] if key_path else []),
        "--max-tasks",
        str(max_tasks),
        "--once",
        *(["--task-id", str(target_task_id)] if target_task_id else []),
    ]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    return proc.pid


def ensure_independent_worker_running(
    db_path: Path | str,
    key_path: Path | str | None = None,
    max_tasks: int = 1,
    target_task_id: str | None = None,
) -> int:
    """Ensure at least one independent OS worker process is spawned."""
    return spawn_independent_worker_once(
        db_path, key_path=key_path, max_tasks=max_tasks, target_task_id=target_task_id
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Windows MCP Agent — Autonomous Worker Daemon")
    parser.add_argument("--db-path", type=str, default=None, help="Path to SQLite database")
    parser.add_argument("--key-path", type=str, default=None, help="Path to HMAC key file")
    parser.add_argument("--max-tasks", type=int, default=None, help="Max tasks to execute before exiting")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Process at most one task then exit")
    parser.add_argument("--task-id", type=str, default=None, help="Specific task_id to claim first")

    args = parser.parse_args()

    store = TaskStore(db_path=args.db_path)
    broker = TaskGrantBroker(
        key_path=Path(args.key_path) if args.key_path else None,
        db_path=Path(args.db_path) if args.db_path else None,
    )
    daemon = UnattendedWorkerDaemon(
        store=store,
        broker=broker,
        poll_interval_seconds=args.poll_interval,
    )

    max_t = 1 if args.once else args.max_tasks
    print(f"Autonomous Worker Daemon PID {os.getpid()} starting...")
    processed_count = daemon.start(max_tasks=max_t, target_task_id=args.task_id)
    print(f"Autonomous Worker Daemon PID {os.getpid()} finished. Processed {processed_count} tasks.")
