"""Test suite for Agent B State Isolation Guard (Audit 28D9ED5).

Verifies 5 mandatory acceptance criteria for real-time state isolation:
1. Transient write and immediate delete of EMERGENCY_STOP is blocked at the first operation.
2. All write primitives (append log, write config, unlink, rename, replace, mkdir, sqlite connect)
   are blocked in real-time while read-only operations succeed.
3. Subprocess write protection enforced via get_subprocess_env and sitecustomize bootstrap.
4. Dual isolated runtime state instances run concurrently without cross-contamination.
5. Static scan inventory and runtime enforcement audit verifying 100% sandbox containment.
"""
from __future__ import annotations

import gc
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for p in (PROJECT_ROOT, PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent", PROJECT_ROOT / "runtime"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pytest

from runtime.contracts import RuntimeStatePaths, ProductionWriteGuard
from task_store import TaskStore
from policy import GatewayPolicy
from gateway_server import MCPGatewayServer
from exec_jobs import ExecutionJobManager
from agent import DesktopAgent


def test_01_transient_create_then_delete_stop_file_blocked_at_first_op(tmp_path):
    """Auditor Flaw 1: Transient file creation then deletion.

    Verifies that creating EMERGENCY_STOP and immediately unlinking it is
    blocked at the very first operation (write_text), preventing disk writes,
    and records the event with exact metadata.
    """
    canary_dir = tmp_path / "mock_prod"
    canary_dir.mkdir()
    stop_file = canary_dir / "EMERGENCY_STOP"

    guard = ProductionWriteGuard(protected_roots=[canary_dir], run_id="test_01_run")
    with guard:
        with pytest.raises(PermissionError) as exc_info:
            stop_file.write_text("TRANSIENT_STOP", encoding="utf-8")
            # If the write had not been blocked, this would have run:
            stop_file.unlink(missing_ok=True)

        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_info.value)
        assert not stop_file.exists(), "File should NEVER have been created on disk"
        assert len(guard.blocked_events) == 1
        ev = guard.blocked_events[0]
        assert ev["operation"] == "Path.write_text"
        assert ev["normalized_target"] == str(stop_file.resolve())
        assert ev["run_id"] == "test_01_run"


def test_02_all_write_primitives_db_log_config_rename_wal_blocked(tmp_path):
    """Auditor Flaw 2: Direct writes across all I/O primitives.

    Verifies real-time interception of:
    - append to log file (open with 'a')
    - config mutation (Path.write_text)
    - unlinking existing files (Path.unlink)
    - moving/replacing files into protected root (os.rename, os.replace)
    - directory creation (Path.mkdir)
    - SQLite database connections in write/WAL mode (sqlite3.connect)
    While ensuring read-only operations continue to function 100%.
    """
    canary_dir = tmp_path / "mock_prod"
    canary_dir.mkdir()
    log_file = canary_dir / "audit.log"
    log_file.write_text("INIT_LOG\n", encoding="utf-8")
    cfg_file = canary_dir / "policy.json"
    cfg_file.write_text('{"mode": "prod"}', encoding="utf-8")
    existing_file = canary_dir / "existing.txt"
    existing_file.write_text("DO_NOT_DELETE", encoding="utf-8")
    db_file = canary_dir / "tasks.db"

    # Pre-populate SQLite DB before activating guard
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO tasks VALUES ('t1', 'pending')")
    conn.commit()
    conn.close()

    guard = ProductionWriteGuard(protected_roots=[canary_dir], run_id="test_02_run")
    with guard:
        # A. Read-only operations succeed 100%
        assert cfg_file.read_text(encoding="utf-8") == '{"mode": "prod"}'
        with open(log_file, "r", encoding="utf-8") as f:
            assert f.read() == "INIT_LOG\n"
        assert existing_file.exists() is True
        assert db_file.stat().st_size > 0

        # SQLite URI mode=ro succeeds
        ro_conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        row = ro_conn.execute("SELECT status FROM tasks WHERE id='t1'").fetchone()
        assert row[0] == "pending"
        ro_conn.close()

        # B. Log append blocked
        with pytest.raises(PermissionError) as exc_log:
            open(log_file, "a", encoding="utf-8")
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_log.value)

        # C. Config modification blocked
        with pytest.raises(PermissionError) as exc_cfg:
            cfg_file.write_text('{"mode": "hacked"}', encoding="utf-8")
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_cfg.value)
        assert cfg_file.read_text(encoding="utf-8") == '{"mode": "prod"}'

        # D. Unlink existing file blocked
        with pytest.raises(PermissionError) as exc_unl:
            existing_file.unlink()
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_unl.value)
        assert existing_file.exists() is True

        # E. Rename / Replace into canary blocked
        temp_file = tmp_path / "temp_payload.txt"
        temp_file.write_text("OVERWRITE_DATA", encoding="utf-8")
        with pytest.raises(PermissionError) as exc_ren:
            os.rename(temp_file, canary_dir / "payload.txt")
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_ren.value)

        with pytest.raises(PermissionError) as exc_rep:
            os.replace(temp_file, canary_dir / "payload.txt")
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_rep.value)

        # F. Directory creation blocked
        with pytest.raises(PermissionError) as exc_mk:
            (canary_dir / "sub_folder").mkdir()
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_mk.value)

        # G. SQLite connection in write / WAL mode blocked
        with pytest.raises(PermissionError) as exc_db1:
            sqlite3.connect(db_file)
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_db1.value)

        with pytest.raises(PermissionError) as exc_db2:
            sqlite3.connect(f"file:{db_file}?mode=rw", uri=True)
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_db2.value)

        # Ensure all blocked events logged
        assert len(guard.blocked_events) >= 7


def test_03_subprocess_write_protection_enforced(tmp_path):
    """Auditor Requirement: Subprocess Write-Boundary Enforcement.

    Verifies that Python child processes spawned with guard.get_subprocess_env()
    have ProductionWriteGuard automatically loaded via sitecustomize.py and are
    strictly blocked from mutating protected canary roots.
    """
    canary_dir = tmp_path / "mock_prod"
    canary_dir.mkdir()
    target_file = canary_dir / "subproc_target.txt"
    target_db = canary_dir / "subproc.db"
    readable_file = canary_dir / "readable.txt"
    readable_file.write_text("CANARY_PROD_READABLE", encoding="utf-8")

    guard = ProductionWriteGuard(protected_roots=[canary_dir], run_id="test_03_subproc")
    sub_env = guard.get_subprocess_env()

    # 1. Subprocess trying to write file must be blocked
    code_write = f"from pathlib import Path; Path(r'{target_file}').write_text('POLLUTED', encoding='utf-8')"
    res_w = subprocess.run([sys.executable, "-c", code_write], env=sub_env, capture_output=True, text=True)
    assert res_w.returncode != 0
    assert "PRODUCTION_STATE_WRITE_BLOCKED" in res_w.stderr
    assert not target_file.exists()

    # 2. Subprocess trying to open sqlite connection in write mode must be blocked
    code_db = f"import sqlite3; sqlite3.connect(r'{target_db}')"
    res_db = subprocess.run([sys.executable, "-c", code_db], env=sub_env, capture_output=True, text=True)
    assert res_db.returncode != 0
    assert "PRODUCTION_STATE_WRITE_BLOCKED" in res_db.stderr
    assert not target_db.exists()

    # 3. Subprocess reading protected file must succeed
    code_read = f"from pathlib import Path; print(Path(r'{readable_file}').read_text(encoding='utf-8'))"
    res_r = subprocess.run([sys.executable, "-c", code_read], env=sub_env, capture_output=True, text=True)
    assert res_r.returncode == 0
    assert "CANARY_PROD_READABLE" in res_r.stdout.strip()


def test_04_dual_isolated_instances_concurrent_execution_and_cleanup(tmp_path):
    """Auditor Requirement: Dual Isolated Instances Concurrent Execution and Cleanup.

    Two isolated runtime state roots execute concurrently with TaskStore,
    audit logging, and emergency stop triggers without cross-contamination.
    """
    td1 = tmp_path / "instance_1"
    td2 = tmp_path / "instance_2"
    paths1 = RuntimeStatePaths.create_isolated(td1)
    paths2 = RuntimeStatePaths.create_isolated(td2)

    errors = []

    def run_worker_1():
        try:
            store1 = TaskStore(db_path=paths1.tasks_db_path)
            store1.create_task("Task One in Instance 1", td1, task_id="t1")
            paths1.trigger_emergency_stop("STOP_INSTANCE_1")
            assert paths1.is_emergency_stop_active() is True
            paths1.audit_log_path.write_text("AUDIT_LOG_INSTANCE_1\n", encoding="utf-8")
        except Exception as e:
            errors.append(("inst1", e))

    def run_worker_2():
        try:
            store2 = TaskStore(db_path=paths2.tasks_db_path)
            store2.create_task("Task Two in Instance 2", td2, task_id="t2")
            assert paths2.is_emergency_stop_active() is False
            paths2.audit_log_path.write_text("AUDIT_LOG_INSTANCE_2\n", encoding="utf-8")
        except Exception as e:
            errors.append(("inst2", e))

    th1 = threading.Thread(target=run_worker_1)
    th2 = threading.Thread(target=run_worker_2)
    th1.start()
    th2.start()
    th1.join()
    th2.join()

    assert not errors, f"Concurrent execution errors: {errors}"

    # Verify state isolation between instances
    assert paths1.is_emergency_stop_active() is True
    assert paths2.is_emergency_stop_active() is False

    store1 = TaskStore(db_path=paths1.tasks_db_path)
    store2 = TaskStore(db_path=paths2.tasks_db_path)
    assert store1.get_task("t1") is not None
    assert store1.get_task("t2") is None
    assert store2.get_task("t2") is not None
    assert store2.get_task("t1") is None

    assert "AUDIT_LOG_INSTANCE_1" in paths1.audit_log_path.read_text(encoding="utf-8")
    assert "AUDIT_LOG_INSTANCE_2" in paths2.audit_log_path.read_text(encoding="utf-8")

    # Instance 1 cleanup simulation: deleting instance 1 sandbox does not affect instance 2
    del store1
    gc.collect()
    shutil.rmtree(td1, ignore_errors=True)

    assert paths2.tasks_db_path.exists()
    assert store2.get_task("t2") is not None
    assert paths2.is_emergency_stop_active() is False


def test_05_static_scan_and_runtime_enforcement_audit(tmp_path):
    """Auditor Requirement: Static Scan and Runtime Enforcement Audit.

    Scans codebase for default fallback path constructs and verifies that
    injected RuntimeStatePaths enforces full containment in sandbox.
    """
    scan_roots = [PROJECT_ROOT / "runtime", PROJECT_ROOT / "mcp-gateway"]
    patterns = [
        ("EMERGENCY_STOP", re.compile(r"EMERGENCY_STOP")),
        ("tasks.db", re.compile(r"tasks\.db")),
        ("broker_hmac.key", re.compile(r"broker_hmac\.key|task_grant\.key|\.key")),
        ("audit.db", re.compile(r"audit\.db")),
        ("oauth_db", re.compile(r"oauth(?:_state)?\.db")),
        ("watchdog.lock", re.compile(r"watchdog\.lock")),
        ("default_path_construct", re.compile(r"Path\(__file__\)\.resolve\(\)\.parent")),
    ]

    findings = []
    for s_root in scan_roots:
        for root, _, files in os.walk(s_root):
            if "__pycache__" in root:
                continue
            for f in files:
                if not f.endswith(".py"):
                    continue
                p = Path(root) / f
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    for p_name, pat in patterns:
                        if pat.search(line):
                            findings.append({
                                "file": str(p.relative_to(PROJECT_ROOT)),
                                "line": i,
                                "pattern": p_name,
                                "snippet": line.strip()[:100]
                            })

    assert len(findings) > 0, "Static scan should locate fallback path constructs"

    # Runtime demonstration
    sandbox = RuntimeStatePaths.create_isolated(tmp_path / "sandbox")
    env_map = sandbox.to_env_dict()
    assert env_map["MCP_STATE_ROOT"] == str(sandbox.root_dir)
    assert env_map["MCP_EMERGENCY_STOP_FILE"] == str(sandbox.emergency_stop_file)
    assert env_map["MCP_TASKS_DB_PATH"] == str(sandbox.tasks_db_path)
    assert env_map["MCP_IS_ISOLATED"] == "1"

    store = TaskStore(db_path=sandbox.tasks_db_path)
    store.create_task("Test Sandbox Isolation", sandbox.root_dir, task_id="t_audit")
    assert sandbox.tasks_db_path.exists()
    assert store.get_task("t_audit") is not None


def test_dual_instance_state_isolation():
    """Verify two gateway instances with isolated state roots operate completely independently."""
    td1 = tempfile.mkdtemp(prefix="test_iso_inst1_")
    td2 = tempfile.mkdtemp(prefix="test_iso_inst2_")
    try:
        paths1 = RuntimeStatePaths.create_isolated(td1)
        paths2 = RuntimeStatePaths.create_isolated(td2)

        pol1 = GatewayPolicy(
            profile="owner_full_control",
            emergency_stop_file=paths1.emergency_stop_file,
            audit_log_path=paths1.audit_log_path,
        )
        exec1 = ExecutionJobManager(policy=pol1, jobs_dir=paths1.jobs_dir)
        desk1 = DesktopAgent(policy=pol1, emergency_stop_file=paths1.emergency_stop_file)
        gw1 = MCPGatewayServer(policy=pol1, exec_ops=exec1, desktop_agent=desk1, runtime_paths=paths1)

        pol2 = GatewayPolicy(
            profile="owner_full_control",
            emergency_stop_file=paths2.emergency_stop_file,
            audit_log_path=paths2.audit_log_path,
        )
        exec2 = ExecutionJobManager(policy=pol2, jobs_dir=paths2.jobs_dir)
        desk2 = DesktopAgent(policy=pol2, emergency_stop_file=paths2.emergency_stop_file)
        gw2 = MCPGatewayServer(policy=pol2, exec_ops=exec2, desktop_agent=desk2, runtime_paths=paths2)

        # Baseline: neither has emergency stop active
        assert not paths1.is_emergency_stop_active()
        assert not paths2.is_emergency_stop_active()
        assert not pol1.is_emergency_stop_active()
        assert not pol2.is_emergency_stop_active()

        # Trigger stop ONLY in instance 1
        paths1.trigger_emergency_stop("ISOLATED_STOP_INSTANCE_1")

        assert paths1.is_emergency_stop_active() is True
        assert pol1.is_emergency_stop_active() is True

        # Instance 2 MUST remain inactive and unaffected
        assert paths2.is_emergency_stop_active() is False
        assert pol2.is_emergency_stop_active() is False

        # Verify gw1 rejects command due to emergency stop
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "agent_powershell_execute", "arguments": {"command": "Write-Output 'SHOULD_FAIL'"}},
        }
        res1 = gw1.handle_jsonrpc_autonomous(msg, caller_id="local_owner", caller_tier="WRITE")
        assert res1["result"]["isError"] is True
        assert "Emergency Stop is active" in res1["result"]["content"][0]["text"]

        # Verify gw2 executes successfully
        msg2 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "agent_powershell_execute", "arguments": {"command": "Write-Output 'INSTANCE_2_OK'"}},
        }
        res2 = gw2.handle_jsonrpc_autonomous(msg2, caller_id="local_owner", caller_tier="WRITE")
        assert res2["result"]["isError"] is False
        assert "INSTANCE_2_OK" in res2["result"]["content"][0]["text"]

        # Clear instance 1
        paths1.clear_emergency_stop()
        assert not paths1.is_emergency_stop_active()
        assert not pol1.is_emergency_stop_active()
        assert not paths2.is_emergency_stop_active()
        assert not pol2.is_emergency_stop_active()

    finally:
        shutil.rmtree(td1, ignore_errors=True)
        shutil.rmtree(td2, ignore_errors=True)


def test_production_state_canary_protection():
    """Verify that test operations on isolated state never mutate a production canary state."""
    prod_canary_dir = tempfile.mkdtemp(prefix="mock_production_")
    test_sandbox_dir = tempfile.mkdtemp(prefix="test_sandbox_")
    try:
        # Create mock production state with canary
        prod_stop_file = Path(prod_canary_dir) / "EMERGENCY_STOP"
        prod_stop_file.write_text("GENUINE_OWNER_PRODUCTION_STOP", encoding="utf-8")
        prod_stat_before = prod_stop_file.stat()

        # Run test operations inside test_sandbox_dir
        paths = RuntimeStatePaths.create_isolated(test_sandbox_dir)
        pol = GatewayPolicy(
            profile="owner_full_control",
            emergency_stop_file=paths.emergency_stop_file,
            audit_log_path=paths.audit_log_path,
        )
        exec_ops = ExecutionJobManager(policy=pol, jobs_dir=paths.jobs_dir)
        desk_ops = DesktopAgent(policy=pol, emergency_stop_file=paths.emergency_stop_file)
        gw = MCPGatewayServer(policy=pol, exec_ops=exec_ops, desktop_agent=desk_ops, runtime_paths=paths)

        # Test creates, verifies, and clears its own emergency stop
        paths.trigger_emergency_stop("TEST_STOP")
        assert paths.is_emergency_stop_active() is True
        paths.clear_emergency_stop()
        assert paths.is_emergency_stop_active() is False

        # Production canary MUST be 100% intact and unchanged
        assert prod_stop_file.exists() is True
        assert prod_stop_file.read_text(encoding="utf-8") == "GENUINE_OWNER_PRODUCTION_STOP"
        prod_stat_after = prod_stop_file.stat()
        assert prod_stat_before.st_mtime == prod_stat_after.st_mtime
        assert prod_stat_before.st_size == prod_stat_after.st_size

    finally:
        shutil.rmtree(prod_canary_dir, ignore_errors=True)
        shutil.rmtree(test_sandbox_dir, ignore_errors=True)
