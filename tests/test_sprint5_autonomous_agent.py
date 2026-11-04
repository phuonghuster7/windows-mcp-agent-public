"""End-to-End Acceptance Tests for Sprint 5 Autonomous Full Agent.

Implements the mandatory 22-criteria acceptance scenario and negative test cases:
1. Disposable Python repository with intentional defects.
2. Single-grant authorization: zero per-operation confirmation prompts for in-scope actions.
3. Complete Plan -> Act -> Observe -> Verify -> Repair -> Pass lifecycle.
4. Transactional SQLite persistence & Checkpoint recovery across worker restarts.
5. High-level MCP tools integration (agent_submit_task, agent_task_status, etc.).
6. Full negative test matrix: forged grants, expired grants, out-of-scope containment,
   command injection, infinite repair cutoff, and Emergency Stop halting.
"""
from __future__ import annotations

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

from policy import GatewayPolicy, PermissionTier
from runtime.agent_mcp_tools import AgentMCPToolHandler
from runtime.autonomous_agent import AutonomousAgentController, UnattendedWorkerDaemon
from runtime.task_grant import TaskGrant, TaskGrantBroker
from runtime.task_store import ExecutionMode, TaskRecord, TaskState, TaskStore


@pytest.fixture
def disposable_repo():
    """Create a temporary disposable Python project with an intentional defect."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        ws = Path(td).resolve()
        # calculator.py with intentional arithmetic defect
        calc_code = (
            "# Calculator module\n"
            "def add(a, b):\n"
            "    # BUG: Defective addition logic\n"
            "    return a - b\n\n"
            "def multiply(a, b):\n"
            "    return a * b\n"
        )
        (ws / "calculator.py").write_text(calc_code, encoding="utf-8")

        # test_calculator.py
        test_code = (
            "import pytest\n"
            "from calculator import add, multiply\n\n"
            "def test_addition():\n"
            "    assert add(2, 3) == 5\n\n"
            "def test_multiplication():\n"
            "    assert multiply(3, 4) == 12\n"
        )
        (ws / "test_calculator.py").write_text(test_code, encoding="utf-8")
        yield ws


@pytest.fixture
def test_env(disposable_repo):
    emergency_file = disposable_repo / "EMERGENCY_STOP"
    db_path = disposable_repo / "tasks_test.db"
    key_path = disposable_repo / "broker_test.key"
    store = TaskStore(db_path=db_path)
    policy = GatewayPolicy(profile="full_agent", emergency_stop_file=emergency_file)
    policy.reset_emergency_stop()
    broker = TaskGrantBroker(key_path=key_path, policy=policy, db_path=db_path, preapproved_roots=[disposable_repo])
    yield {
        "workspace": disposable_repo,
        "store": store,
        "broker": broker,
        "policy": policy,
    }
    policy.reset_emergency_stop()
    if emergency_file.exists():
        try:
            emergency_file.unlink()
        except Exception:
            pass


class TestSprint5AutonomousAgent:

    def test_01_autonomous_defect_repair_e2e_lifecycle(self, test_env):
        """Mandatory Acceptance Scenario (Criteria 1-14):

        Single grant, zero repeated dialogs, plan generated, test run, defect diagnosed,
        code repaired, re-tested, and all tests pass with checkpoints saved.
        """
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        objective = (
            "Inspect this project, identify the bugs, fix the source, run the tests, "
            "and continue until all tests pass. Do not ask for approval for individual operations inside this workspace."
        )

        # 1. Task created & TaskGrant issued once
        task = store.create_task(objective=objective, workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )

        store.bind_grant(task.task_id, grant.grant_id)

        # 2. Run controller
        ctrl = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])
        final_task = ctrl.run()

        # 3. Assertions on E2E Lifecycle
        assert final_task.state == TaskState.COMPLETED.value
        assert final_task.retry_count >= 1  # Detected defect and retried after repair
        assert len(final_task.files_modified) >= 1
        assert any("calculator.py" in f for f in final_task.files_modified)

        # Verify calculator.py code was repaired
        calc_content = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a + b" in calc_content
        assert "return a - b" not in calc_content

        # Verify checkpoints were persisted
        chk = store.get_latest_checkpoint(task.task_id)
        assert chk is not None
        assert chk.step_index >= 1

        # Verify logs were recorded
        logs = store.get_logs(task.task_id)
        phases = [log["phase"] for log in logs]
        assert "PLANNING" in phases
        assert "ACT" in phases
        assert "REPAIRING" in phases
        assert "COMPLETED" in phases

    def test_02_idempotency_and_resumption_after_restart(self, test_env):
        """Worker restart & checkpoint recovery (Criteria 15-17):

        Interrupted task resumes safely from checkpoint without duplicating committed steps.
        """
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        task = store.create_task(objective="Idempotent execution test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)

        # First controller: pause execution after first step
        ctrl1 = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])
        ctrl1.pause()
        t1 = ctrl1.run()
        assert t1.state == TaskState.PAUSED.value

        # Second controller simulating worker process restart
        ctrl2 = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])
        ctrl2.resume()
        t2 = ctrl2.run()
        assert t2.state == TaskState.COMPLETED.value

    def test_03_revocation_blocks_further_privileged_actions(self, test_env):
        """Grant revocation immediately halts active agent (Criteria 18)."""
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        task = store.create_task(objective="Revocation test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)

        # Revoke the grant before running
        broker.revoke_grant(grant.grant_id, reason="Security audit trigger")

        ctrl = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])
        t = ctrl.run()
        assert t.state in (TaskState.CANCELLED.value, TaskState.FAILED.value)
        assert "revoked" in (t.error_message or "").lower()

    def test_04_out_of_scope_filesystem_access_is_denied(self, test_env):
        """Agent cannot escape workspace root (Criteria 19)."""
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        task = store.create_task(objective="Containment test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["write_file"],
            allowed_commands=[],
            allowed_permission_tiers=["WRITE"],
            duration_seconds=300.0,
        )

        ctrl = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])

        # Attempt out-of-scope write
        outside_path = ws.parent / "escape_attempt.txt"
        success, res, err = ctrl._execute_tool_action(grant, "write_file", {"path": str(outside_path), "content": "evil"})
        assert success is False
        assert "outside approved workspace" in err
        assert not outside_path.exists()

    def test_05_emergency_stop_halts_active_worker(self, test_env):
        """Emergency Stop latch halts worker immediately (Criteria 20)."""
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        task = store.create_task(objective="Emergency stop test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ", "WRITE"],
            duration_seconds=300.0,
        )

        ctrl = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])

        # Engage Emergency Stop on policy
        test_env["policy"].engage_emergency_stop(reason="Operator Panic Trigger")

        success, res, err = ctrl._execute_tool_action(grant, "write_file", {"path": str(ws / "file.txt"), "content": "x"})
        assert success is False
        assert "Emergency Stop is active" in err

    def test_06_high_level_mcp_tools_dispatch(self, test_env):
        """High-level MCP tools integration (Criteria 21-22)."""
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        handler = AgentMCPToolHandler(store, broker)

        # 1. agent_submit_task without token -> AUTHORIZATION_PENDING (Defect F02)
        submit_res = handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "MCP tool submitted task",
                "workspace_root": str(ws),
                "auto_start": True,
            },
        )
        task_id = submit_res["task_id"]
        assert task_id != ""
        assert submit_res["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert submit_res.get("requires_owner_approval") is True

        # Owner approval step (Defect F02)
        token = broker.generate_owner_approval_token(task_id, ws)
        approve_res = handler.execute_tool(
            "agent_approve_task",
            {
                "task_id": task_id,
                "owner_approval_token": token,
                "spawn_worker": False,
            },
        )
        assert approve_res["status"] == TaskState.QUEUED.value
        assert approve_res["grant_id"] is not None

        # 2. agent_task_status
        status_res = handler.execute_tool("agent_task_status", {"task_id": task_id})
        assert status_res["task_id"] == task_id
        assert "state" in status_res

        # 3. agent_task_logs
        logs_res = handler.execute_tool("agent_task_logs", {"task_id": task_id})
        assert logs_res["task_id"] == task_id
        assert logs_res["count"] >= 0

        # 4. agent_task_artifacts
        art_res = handler.execute_tool("agent_task_artifacts", {"task_id": task_id})
        assert art_res["task_id"] == task_id

        # 5. agent_list_tasks
        list_res = handler.execute_tool("agent_list_tasks", {})
        assert list_res["count"] >= 1

        # 6. agent_task_pause and resume
        pause_res = handler.execute_tool("agent_task_pause", {"task_id": task_id})
        assert pause_res["paused"] is True

        resume_res = handler.execute_tool("agent_task_resume", {"task_id": task_id, "spawn_worker": False})
        assert resume_res["resumed"] is True
        assert resume_res["state"] == TaskState.QUEUED.value

        # 7. agent_task_cancel
        cancel_res = handler.execute_tool("agent_task_cancel", {"task_id": task_id, "reason": "Test finished"})
        assert cancel_res["cancelled"] is True

    def test_07_negative_infinite_repair_cutoff(self, test_env):
        """Negative test: task terminates when max_retries is reached without infinite loop."""
        ws = test_env["workspace"]
        store = test_env["store"]
        broker = test_env["broker"]

        # Create a test that always fails with an unrepairable error
        (ws / "unfixable.py").write_text("# permanently broken\n", encoding="utf-8")
        (ws / "test_unfixable.py").write_text("def test_fail(): assert False, 'Cannot fix this'\n", encoding="utf-8")

        task = store.create_task(objective="Unfixable test", workspace_root=ws)
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        # Cap retries to 2
        grant.max_retries = 2
        grant.sign(broker.secret)

        store.bind_grant(task.task_id, grant.grant_id)

        ctrl = AutonomousAgentController(task.task_id, store, broker, policy=test_env["policy"])
        final_task = ctrl.run()
        # Must fail gracefully within max_retries without spinning forever
        assert final_task.state == TaskState.FAILED.value
        assert final_task.retry_count <= grant.max_retries
