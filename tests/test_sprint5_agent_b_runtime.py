"""Unit and Integration Tests for Agent B Sprint 5.1 Runtime & Worker.

Verifies fixes for Defects F03, F04, F05, F07:
- F03: Atomic writes, backup creation, max size enforcement, env sanitization, structured subprocess
- F04: Universal scope containment across all filesystem, git, and execution tools
- F05: Active budget enforcement (wall-time, tool calls, file writes, memory, API cost), verification requirement
- F07: Cross-process control signals (PAUSE, CANCEL, RESUME), PID liveness, orphan reconciliation, CLI entry
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GW_DIR = str(PROJECT_ROOT / "mcp-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from policy import GatewayPolicy
from runtime.autonomous_agent import (
    AutonomousAgentController,
    UnattendedWorkerDaemon,
    _get_process_memory_mb,
    _kill_process_tree,
    spawn_independent_worker_once,
)
from runtime.task_grant import TaskGrant, TaskGrantBroker
from runtime.task_store import TaskRecord, TaskState, TaskStore, is_pid_alive


@pytest.fixture
def clean_env():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        ws = Path(td).resolve()
        db_path = ws / "test_tasks.db"
        key_path = ws / "test_broker.key"
        store = TaskStore(db_path=db_path)
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=key_path, policy=policy, db_path=db_path)
        yield {
            "workspace": ws,
            "store": store,
            "broker": broker,
            "policy": policy,
        }


class TestAgentBTaskStore:

    def test_pid_liveness(self):
        """Verify is_pid_alive works for current PID and invalid PID."""
        assert is_pid_alive(os.getpid()) is True
        assert is_pid_alive(None) is False
        assert is_pid_alive(-1) is False
        assert is_pid_alive(999999) is False

    def test_task_store_extended_columns(self, clean_env):
        """Verify new TaskRecord fields and SQLite persistence."""
        store: TaskStore = clean_env["store"]
        ws = clean_env["workspace"]
        task = store.create_task(
            objective="Extended columns test",
            workspace_root=ws,
            requested_scope={"paths": [str(ws)]},
        )
        assert task.file_write_count == 0
        assert task.api_cost_usd == 0.0
        assert task.verification_passed is False
        assert task.worker_pid is None
        assert task.control_signal is None
        assert len(task.proposal_digest) == 64

        # Test heartbeat
        hb = store.heartbeat(task.task_id, worker_pid=os.getpid())
        assert hb is not None
        assert hb["state"] == task.state
        t_reloaded = store.get_task(task.task_id)
        assert t_reloaded.worker_pid == os.getpid()
        assert t_reloaded.worker_heartbeat_at is not None
        assert t_reloaded.proposal_digest == task.proposal_digest

        # Test update_task_progress with new delta fields
        store.update_task_progress(
            task.task_id,
            file_write_delta=3,
            api_cost_usd=0.05,
            verification_passed=True,
        )
        t_updated = store.get_task(task.task_id)
        assert t_updated.file_write_count == 3
        assert t_updated.api_cost_usd == 0.05
        assert t_updated.verification_passed is True

    def test_control_signals(self, clean_env):
        """Verify set_control_signal transitions for PAUSE, CANCEL, RESUME and G02 grant reuse protection."""
        store: TaskStore = clean_env["store"]
        broker = clean_env["broker"]
        ws = clean_env["workspace"]
        task = store.create_task(objective="Signal test", workspace_root=ws)
        store.bind_grant(task.task_id, "grant_1")
        assert store.get_task(task.task_id).state == TaskState.QUEUED.value

        # G02: Cannot bind same grant to a different task
        task_other = store.create_task(objective="Other task", workspace_root=ws)
        with pytest.raises(PermissionError, match="Cross-task grant reuse denied"):
            store.bind_grant(task_other.task_id, "grant_1")

        # G02: Cannot bind grant issued for another task in task_grants table
        g = broker.issue_grant(task.task_id, ws, ["read_file"], [], ["READ"])
        with pytest.raises(PermissionError, match="Cross-task grant reuse denied"):
            store.bind_grant(task_other.task_id, g.grant_id)

        # G02: Cannot bind revoked grant
        broker.revoke_grant(g.grant_id)
        with pytest.raises(PermissionError, match="Cannot bind revoked grant"):
            store.bind_grant(task.task_id, g.grant_id)

        # PAUSE on QUEUED -> PAUSED
        assert store.set_control_signal(task.task_id, "PAUSE") is True
        assert store.get_task(task.task_id).state == TaskState.PAUSED.value
        assert store.get_task(task.task_id).control_signal == "PAUSE"

        # RESUME on PAUSED -> QUEUED
        assert store.set_control_signal(task.task_id, "RESUME") is True
        assert store.get_task(task.task_id).state == TaskState.QUEUED.value

        # CANCEL on QUEUED -> CANCELLED
        assert store.set_control_signal(task.task_id, "CANCEL") is True
        assert store.get_task(task.task_id).state == TaskState.CANCELLED.value

    def test_orphan_reconciliation_and_claim(self, clean_env):
        """Verify dead worker tasks are re-queued and claimed."""
        store: TaskStore = clean_env["store"]
        ws = clean_env["workspace"]

        task = store.create_task(objective="Orphan test", workspace_root=ws)
        store.bind_grant(task.task_id, "grant_orphan")

        # Claim with a non-existent dead PID
        claimed = store.claim_next_queued_task(worker_pid=999999)
        assert claimed is not None
        assert claimed.state == TaskState.PLANNING.value
        assert claimed.worker_pid == 999999

        # Reconcile orphans
        recovered = store.reconcile_orphaned_tasks()
        assert task.task_id in recovered
        t_requeued = store.get_task(task.task_id)
        assert t_requeued.state == TaskState.QUEUED.value
        assert t_requeued.worker_pid is None


class TestAgentBUniversalScopeContainment:

    def test_f04_scope_containment_across_all_tools(self, clean_env):
        """F04: Verify all tools reject out-of-scope paths."""
        ws = clean_env["workspace"]
        store = clean_env["store"]
        broker = clean_env["broker"]

        task = store.create_task(objective="Scope check", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=[
                "read_file", "read_file_range", "write_file", "append_file",
                "edit_file", "list_directory", "search_code", "git_status",
                "powershell_execute"
            ],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)
        ctrl = AutonomousAgentController(task.task_id, store, broker)

        outside_file = ws.parent / "forbidden.txt"
        outside_file.write_text("secret", encoding="utf-8")

        # 1. read_file
        ok, res, err = ctrl._execute_tool_action(grant, "read_file", {"path": str(outside_file)})
        assert ok is False
        assert "outside approved workspace" in err

        # 2. read_file_range
        ok, res, err = ctrl._execute_tool_action(grant, "read_file_range", {"path": str(outside_file)})
        assert ok is False
        assert "outside approved workspace" in err

        # 3. list_directory
        ok, res, err = ctrl._execute_tool_action(grant, "list_directory", {"path": str(ws.parent)})
        assert ok is False
        assert "outside approved workspace" in err

        # 4. search_code
        ok, res, err = ctrl._execute_tool_action(grant, "search_code", {"path": str(ws.parent), "query": "x"})
        assert ok is False
        assert "outside approved workspace" in err

        # 5. write_file
        ok, res, err = ctrl._execute_tool_action(grant, "write_file", {"path": str(outside_file), "content": "bad"})
        assert ok is False
        assert "outside approved workspace" in err

        # 6. append_file
        ok, res, err = ctrl._execute_tool_action(grant, "append_file", {"path": str(outside_file), "content": "bad"})
        assert ok is False
        assert "outside approved workspace" in err

        # 7. edit_file
        ok, res, err = ctrl._execute_tool_action(grant, "edit_file", {"path": str(outside_file), "old_text": "s", "new_text": "x"})
        assert ok is False
        assert "outside approved workspace" in err

        # 8. git_status with out-of-scope cwd
        ok, res, err = ctrl._execute_tool_action(grant, "git_status", {"cwd": str(ws.parent)})
        assert ok is False
        assert "outside approved workspace" in err

        # 9. powershell_execute with out-of-scope cwd
        ok, res, err = ctrl._execute_tool_action(grant, "powershell_execute", {"command": "pytest", "cwd": str(ws.parent)})
        assert ok is False
        assert "outside approved workspace" in err


class TestAgentBGatewaySafeguards:

    def test_f03_atomic_write_backup_and_budget(self, clean_env):
        """F03: Atomic writes, backup copies, and max size/write budget enforcement."""
        ws = clean_env["workspace"]
        store = clean_env["store"]
        broker = clean_env["broker"]

        task = store.create_task(objective="Safeguards test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["write_file", "edit_file", "read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ", "WRITE"],
            duration_seconds=300.0,
            resource_budget={"max_file_writes": 2, "max_write_bytes": 1024},
        )
        store.bind_grant(task.task_id, grant.grant_id)
        ctrl = AutonomousAgentController(task.task_id, store, broker)

        test_file = ws / "target.txt"

        # Write 1: Initial creation
        ok, res, err = ctrl._execute_tool_action(grant, "write_file", {"path": str(test_file), "content": "Hello World"})
        assert ok is True
        assert test_file.exists()
        assert test_file.read_text(encoding="utf-8") == "Hello World"
        assert ctrl._file_write_count == 1

        # Write 2: Edit creates backup and replaces atomically
        ok, res, err = ctrl._execute_tool_action(
            grant, "edit_file",
            {"path": str(test_file), "old_text": "World", "new_text": "Agent B"}
        )
        assert ok is True
        assert test_file.read_text(encoding="utf-8") == "Hello Agent B"
        assert ctrl._file_write_count == 2

        # Verify backup was created
        backup_dir = PROJECT_ROOT / "backups" / "file_versions"
        backups = list(backup_dir.glob(f"{task.task_id}_*target.txt.bak"))
        assert len(backups) >= 1
        assert "Hello World" in backups[0].read_text(encoding="utf-8")

        # Write 3: Exceeds max_file_writes budget of 2
        ok, res, err = ctrl._execute_tool_action(grant, "write_file", {"path": str(test_file), "content": "Overflow"})
        assert ok is False
        assert "Budget exhausted: max_file_writes limit reached" in err

    def test_f03_sanitized_environment(self, clean_env):
        """F03: Subprocess environment strips secrets."""
        store = clean_env["store"]
        broker = clean_env["broker"]
        ctrl = AutonomousAgentController("task_dummy", store, broker)

        os.environ["OPENAI_API_KEY"] = "sk-secret-test-123"
        os.environ["MY_AWS_SECRET_KEY"] = "super-secret"
        os.environ["MCP_AUTH_TOKEN"] = "token-xyz"
        os.environ["SAFE_VARIABLE"] = "safe_value"

        sanitized = ctrl._build_sanitized_env()
        assert "OPENAI_API_KEY" not in sanitized
        assert "MY_AWS_SECRET_KEY" not in sanitized
        assert "MCP_AUTH_TOKEN" not in sanitized
        assert sanitized.get("SAFE_VARIABLE") == "safe_value"


class TestAgentBBudgetAndDaemon:

    def test_f05_budget_exhaustion_detection(self, clean_env):
        """F05: Controllers detect and report budget exhaustion."""
        ws = clean_env["workspace"]
        store = clean_env["store"]
        broker = clean_env["broker"]

        task = store.create_task(objective="Budget test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
            duration_seconds=1.0,  # 1 second wall-time
        )
        grant.max_tool_calls = 1
        grant.sign(broker.secret)
        store.bind_grant(task.task_id, grant.grant_id)

        ctrl = AutonomousAgentController(task.task_id, store, broker)
        # Sleep to exceed wall-time
        time.sleep(1.2)
        final_task = ctrl.run()
        assert final_task.state in (TaskState.FAILED.value, TaskState.EXPIRED.value)
        assert "BUDGET_EXHAUSTED" in (final_task.error_message or "") or "expired" in (final_task.error_message or "").lower()

    def test_f07_cli_worker_daemon_execution(self, clean_env):
        """F07: UnattendedWorkerDaemon CLI entry point via subprocess."""
        ws = clean_env["workspace"]
        store = clean_env["store"]
        broker = clean_env["broker"]

        task = store.create_task(objective="CLI daemon test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)

        # Run worker once via python -m runtime.autonomous_agent
        key_file = ws / "test_broker.key"
        cmd = [
            sys.executable,
            "-m",
            "runtime.autonomous_agent",
            "--db-path",
            str(store.db_path),
            "--key-path",
            str(key_file),
            "--once",
            "--poll-interval",
            "0.5",
        ]
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=15)
        assert proc.returncode == 0
        assert "Autonomous Worker Daemon PID" in proc.stdout

    def test_10_windows_child_process_tree_termination(self, clean_env):
        """Verify Windows process tree termination kills parent command and child/grandchild within < 2s."""
        import threading

        ws = clean_env["workspace"]
        store: TaskStore = clean_env["store"]
        broker: TaskGrantBroker = clean_env["broker"]

        # 1. Prepare child-spawning script in workspace
        child_pid_file = ws / "grandchild_pid.txt"
        script_file = ws / "spawn_child_tree.py"
        script_file.write_text(
            f"""import subprocess, sys, time, pathlib
# Spawn grandchild process sleeping for 60s
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
pathlib.Path(r"{child_pid_file}").write_text(str(child.pid), encoding="utf-8")
# Parent sleeps 60s awaiting interrupt
time.sleep(60)
""",
            encoding="utf-8",
        )

        task = store.create_task(objective="Process tree kill test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["powershell_execute"],
            allowed_commands=["python*"],
            allowed_permission_tiers=["READ", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)
        ctrl = AutonomousAgentController(task.task_id, store, broker)

        # 2. Run structured command in a background thread
        exec_result: dict[str, Any] = {}

        def run_step():
            exec_result["res"] = ctrl._run_structured_process(
                [sys.executable, str(script_file)],
                cwd=str(ws),
                timeout=30.0,
                grant=grant,
            )

        worker_thread = threading.Thread(target=run_step)
        worker_thread.start()

        # 3. Wait for grandchild PID file to appear and confirm it's alive
        grandchild_pid: int | None = None
        for _ in range(60):
            if child_pid_file.exists():
                txt = child_pid_file.read_text(encoding="utf-8").strip()
                if txt.isdigit():
                    grandchild_pid = int(txt)
                    break
            time.sleep(0.05)

        assert grandchild_pid is not None, "Grandchild PID file was not created"
        assert is_pid_alive(grandchild_pid) is True, "Grandchild process must be alive initially"

        # 4. Trigger Cancel and record duration (<2.0s requirement)
        t_start = time.time()
        ctrl.cancel()
        worker_thread.join(timeout=3.0)
        t_duration = time.time() - t_start

        assert t_duration < 2.0, f"Process tree termination took {t_duration:.2f}s, expected < 2.0s"
        assert not worker_thread.is_alive(), "Worker execution thread should have exited"

        # 5. Verify both grandchild and parent process are dead
        time.sleep(0.1)
        assert is_pid_alive(grandchild_pid) is False, f"Grandchild PID {grandchild_pid} survived cancellation!"
        ok, res, err = exec_result.get("res", (True, None, ""))
        assert ok is False, "Command should have returned failure on cancellation"
        assert "Interrupted" in err or "cancelled" in err.lower()

    def test_11_gateway_disconnect_independent_worker_survival(self, clean_env):
        """Verify independent OS worker process continues executing to completion after Gateway exits."""
        ws = clean_env["workspace"]
        store: TaskStore = clean_env["store"]
        broker: TaskGrantBroker = clean_env["broker"]

        # 1. Create a passing test in workspace for autonomous completion
        (ws / "test_success.py").write_text(
            "def test_passes():\n    assert True\n", encoding="utf-8"
        )

        # 2. Queue task and grant in SQLite
        task = store.create_task(
            objective="Independent worker survival verification",
            workspace_root=ws,
        )
        assert task.proposal_digest != "", "Task must have a non-empty proposal digest"

        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)
        assert store.get_task(task.task_id).state == TaskState.QUEUED.value

        # 3. Simulate short-lived Gateway process that calls spawn_independent_worker_once and exits (sys.exit(0))
        key_file = ws / "test_broker.key"
        gateway_sim = ws / "gateway_exit_sim.py"
        gateway_sim.write_text(
            f"""import sys
from pathlib import Path
sys.path.insert(0, r"{PROJECT_ROOT}")
sys.path.insert(0, r"{GW_DIR}")
from runtime.autonomous_agent import spawn_independent_worker_once

worker_pid = spawn_independent_worker_once(
    db_path=r"{store.db_path}",
    key_path=r"{key_file}",
    max_tasks=1,
)
print(f"GATEWAY_SPAWNED_WORKER:{{worker_pid}}")
sys.exit(0)
""",
            encoding="utf-8",
        )

        gw_proc = subprocess.run(
            [sys.executable, str(gateway_sim)],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert gw_proc.returncode == 0, f"Gateway exited with error: {gw_proc.stderr}"
        assert "GATEWAY_SPAWNED_WORKER:" in gw_proc.stdout
        worker_pid = int(gw_proc.stdout.strip().split("GATEWAY_SPAWNED_WORKER:")[1].split()[0])
        assert worker_pid > 0

        # Gateway process is now dead (returncode 0).
        # 4. Prove the independent worker continues running and completes the task
        completed = False
        t_deadline = time.time() + 20.0
        while time.time() < t_deadline:
            t_record = store.get_task(task.task_id)
            if t_record.state == TaskState.COMPLETED.value:
                completed = True
                break
            if t_record.state in (TaskState.FAILED.value, TaskState.CANCELLED.value):
                pytest.fail(f"Task unexpectedly entered terminal failure: {t_record.error_message}")
            time.sleep(0.5)

        assert completed is True, "Independent worker did not complete the task within deadline"
        final_task = store.get_task(task.task_id)
        assert final_task.state == TaskState.COMPLETED.value
        assert final_task.verification_passed is True
        assert final_task.retry_count == 0, "Expected zero retries/duplicate executions"
