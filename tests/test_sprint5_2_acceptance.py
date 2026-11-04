"""Comprehensive Acceptance & Security Closure Test Suite for Sprint 5.2.

Covers:
- Step 1: ChatGPT Cloud /mcp/autonomous Task Submission & Tool Discovery (G05)
- Step 2: Owner One-Time Approval in Local Web Console — Authorize & Start (G01, G03)
- Step 3 & 4: Autonomous Execution & Browser/Gateway Disconnect Survival (G04)
- Step 5: All 9 Mandatory Security Closure Checks (Checks 1-9 across G01-G05)
- Section 6: OFFLINE_TEST_MODE vs LIVE_AI_MODE Operating Status & Guardrails
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GW_DIR = str(PROJECT_ROOT / "mcp-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway_server import MCPGatewayServer
from http_server import create_gateway_http_app
from policy import SecurityPolicy
from runtime.agent_mcp_tools import (
    CLOUD_AUTONOMOUS_TOOL_DEFINITIONS,
    CLOUD_SAFE_AUTONOMOUS_TOOLS,
    OWNER_CONTROL_AUTONOMOUS_TOOLS,
    AgentMCPToolHandler,
)
from runtime.autonomous_agent import _kill_process_tree
from runtime.llm_adapter import (
    LiveAINotConfiguredError,
    OperatingProfile,
    get_llm_adapter,
    get_llm_operating_status,
)
from runtime.task_grant import (
    TaskGrant,
    TaskGrantBroker,
    compute_proposal_scope_digest,
)
from runtime.task_store import TaskRecord, TaskState, TaskStore, is_pid_alive
from web_console import create_web_console_app

TEST_OWNER_SECRET = "Sprint5_2_Acceptance_Secret_Passphrase_12345"


@pytest.fixture(scope="module")
def shared_acceptance_fixture():
    """Create a temporary workspace, database, broker key, and integrated test clients."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        base_dir = Path(td).resolve()
        workspace = base_dir / "test_repo"
        workspace.mkdir(parents=True, exist_ok=True)
        db_path = base_dir / "sprint5_2_tasks.db"
        audit_log = base_dir / "audit.jsonl"
        estop_file = base_dir / "EMERGENCY_STOP"

        # Create defect in calculator.py
        calc_code = (
            "def add(a, b):\n"
            "    # BUG: addition returns subtraction\n"
            "    return a - b\n\n"
            "def multiply(a, b):\n"
            "    return a * b\n"
        )
        (workspace / "calculator.py").write_text(calc_code, encoding="utf-8")

        test_code = (
            "from calculator import add, multiply\n\n"
            "def test_addition():\n"
            "    assert add(2, 3) == 5\n\n"
            "def test_multiplication():\n"
            "    assert multiply(3, 4) == 12\n"
        )
        (workspace / "test_calculator.py").write_text(test_code, encoding="utf-8")

        store = TaskStore(db_path=db_path)
        policy = SecurityPolicy(
            profile="full_agent",
            allowed_read_roots=[str(base_dir)],
            allowed_write_roots=[str(workspace)],
            allowed_exec_roots=[str(workspace)],
            allowed_git_repos=[str(workspace)],
            audit_log_path=audit_log,
            emergency_stop_file=estop_file,
            require_session_for_privileged=False,
        )
        broker = TaskGrantBroker(
            policy=policy,
            db_path=db_path,
            preapproved_roots=[],
            require_preapproved_roots=True,
        )
        gateway = MCPGatewayServer(policy=policy)
        gateway.store = store
        handler = AgentMCPToolHandler(store, broker)
        gateway._agent_tool_handler = handler

        gw_app = create_gateway_http_app(gateway=gateway, caller_auth_token="dummy_token")
        gw_client = TestClient(
            gw_app,
            headers={
                "Authorization": "Bearer dummy_token",
                "X-MCP-Caller-Id": "chatgpt_cloud_client",
            },
        )

        console_app = create_web_console_app(
            gateway=gateway,
            owner_password=TEST_OWNER_SECRET,
            task_store=store,
            grant_broker=broker,
        )
        console_client = TestClient(console_app)

        yield {
            "base_dir": base_dir,
            "workspace": workspace,
            "db_path": db_path,
            "store": store,
            "broker": broker,
            "gateway": gateway,
            "handler": handler,
            "gw_client": gw_client,
            "console_client": console_client,
        }

        # Teardown: ensure emergency stop is cleaned up if created
        if estop_file.exists():
            try:
                estop_file.unlink()
            except Exception:
                pass


# ==============================================================================
# STEP 1: CHATGPT CLOUD /mcp/autonomous TASK SUBMISSION & TOOL DISCOVERY
# ==============================================================================
class TestStep1_CloudAutonomous:
    """Step 1: ChatGPT Cloud /mcp/autonomous Task Submission & Tool Discovery."""

    def test_01_cloud_autonomous_tool_discovery_and_schema_sanitization(
        self, shared_acceptance_fixture
    ):
        gw_client: TestClient = shared_acceptance_fixture["gw_client"]

        # Call tools/list on /mcp/autonomous
        list_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        resp = gw_client.post("/mcp/autonomous", json=list_payload)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "result" in data
        tools = data["result"]["tools"]
        tool_names = [t["name"] for t in tools]

        # 1. Strictly the 6 safe tools are exposed
        assert sorted(tool_names) == sorted(CLOUD_SAFE_AUTONOMOUS_TOOLS)
        assert len(tools) == 6

        # 2. Schema check on agent_submit_task: owner_approval_token and grant_id omitted
        submit_tool = next(t for t in tools if t["name"] == "agent_submit_task")
        submit_schema = submit_tool.get("inputSchema") or submit_tool.get("input_schema")
        properties = submit_schema.get("properties", {})
        assert "owner_approval_token" not in properties
        assert "grant_id" not in properties
        assert "objective" in properties
        assert "workspace_root" in properties

        # 3. Verify zero privileged tools in tools/list
        for forbidden in (
            "write_file",
            "powershell_execute",
            "mouse_click",
            "agent_approve_task",
            "agent_emergency_stop",
            "agent_task_cancel",
            "agent_task_resume",
            "agent_task_pause",
        ):
            assert forbidden not in tool_names

    def test_02_cloud_task_submission_in_authorization_pending(
        self, shared_acceptance_fixture
    ):
        gw_client: TestClient = shared_acceptance_fixture["gw_client"]
        ws: Path = shared_acceptance_fixture["workspace"]
        store: TaskStore = shared_acceptance_fixture["store"]

        initial_calc_text = (ws / "calculator.py").read_text(encoding="utf-8")

        # Submit task via /mcp/autonomous tools/call
        submit_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "agent_submit_task",
                "arguments": {
                    "objective": "Inspect this test project, find and fix defects, run tests until they pass, and report the results.",
                    "workspace_root": str(ws),
                    "allowed_tools": [
                        "read_file",
                        "write_file",
                        "edit_file",
                        "list_directory",
                        "powershell_execute",
                        "git_status",
                        "git_diff",
                    ],
                    "allowed_commands": ["pytest*", "python*", "git*"],
                },
            },
        }
        resp = gw_client.post("/mcp/autonomous", json=submit_payload)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "result" in data
        assert not data["result"].get("isError", False)
        tool_res = json.loads(data["result"]["content"][0]["text"])

        # Returns real task_id immediately in AUTHORIZATION_PENDING state
        task_id = tool_res["task_id"]
        assert task_id.startswith("task_")
        assert tool_res["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert tool_res["grant_id"] is None
        assert tool_res["requires_owner_approval"] is True
        assert tool_res.get("proposal_digest")

        # Prove no unapproved file modifications occurred
        current_calc_text = (ws / "calculator.py").read_text(encoding="utf-8")
        assert current_calc_text == initial_calc_text

        # Verify task is tracked in store
        task_rec = store.get_task(task_id)
        assert task_rec is not None
        assert task_rec.state == TaskState.AUTHORIZATION_PENDING.value
        assert task_rec.grant_id is None

        shared_acceptance_fixture["e2e_task_id"] = task_id
        shared_acceptance_fixture["e2e_proposal_digest"] = tool_res["proposal_digest"]

    def test_03_cloud_negative_g05_controls_strictly_denied(
        self, shared_acceptance_fixture
    ):
        gw_client: TestClient = shared_acceptance_fixture["gw_client"]

        # 1. agent_approve_task from /mcp/autonomous -> DENIED
        approve_call = {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "agent_approve_task",
                "arguments": {"task_id": "task_dummy", "owner_approval_token": "token"},
            },
        }
        r1 = gw_client.post("/mcp/autonomous", json=approve_call)
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["result"]["isError"] is True
        assert "Permission Denied (G05)" in d1["result"]["content"][0]["text"]

        # 2. agent_emergency_stop from /mcp/autonomous -> DENIED
        estop_call = {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "agent_emergency_stop",
                "arguments": {"reason": "cloud caller stop"},
            },
        }
        r2 = gw_client.post("/mcp/autonomous", json=estop_call)
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["result"]["isError"] is True
        assert "Permission Denied (G05)" in d2["result"]["content"][0]["text"]

        # 3. raw write_file from /mcp/autonomous -> DENIED
        write_call = {
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "should_not_exist.txt", "content": "bad"},
            },
        }
        r3 = gw_client.post("/mcp/autonomous", json=write_call)
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["result"]["isError"] is True
        assert "Permission Denied (G05)" in d3["result"]["content"][0]["text"]


# ==============================================================================
# STEP 2: OWNER ONE-TIME APPROVAL IN LOCAL WEB CONSOLE (AUTHORIZE & START)
# ==============================================================================
class TestStep2_OwnerWebConsoleApproval:
    """Step 2: Owner One-Time Approval in Local Web Console — Authorize & Start."""

    def test_04_owner_login_and_workspace_onboarding(self, shared_acceptance_fixture):
        console_client: TestClient = shared_acceptance_fixture["console_client"]
        ws: Path = shared_acceptance_fixture["workspace"]

        # 1. Login to Owner Web Console
        login_resp = console_client.post(
            "/console/api/login",
            json={"password": TEST_OWNER_SECRET},
        )
        assert login_resp.status_code == 200, login_resp.text
        login_data = login_resp.json()
        assert login_data["authenticated"] is True
        csrf_token = login_data["csrf_token"]
        assert csrf_token
        shared_acceptance_fixture["csrf_token"] = csrf_token

        # 2. Onboard workspace root via POST /console/api/autonomous/roots (G03)
        onboard_resp = console_client.post(
            "/console/api/autonomous/roots",
            headers={"x-csrf-token": csrf_token},
            json={"root_path": str(ws)},
        )
        assert onboard_resp.status_code in (200, 201), onboard_resp.text
        onboard_data = onboard_resp.json()
        assert Path(onboard_data["onboarded_root"]).resolve() == ws.resolve()

        # Verify root listed
        list_roots = console_client.get("/console/api/autonomous/roots")
        assert list_roots.status_code == 200
        roots = list_roots.json().get("preapproved_roots", [])
        assert any(Path(r).resolve() == ws.resolve() for r in roots)

    def test_05_reject_scope_modification_during_approval(
        self, shared_acceptance_fixture
    ):
        console_client: TestClient = shared_acceptance_fixture["console_client"]
        csrf_token = shared_acceptance_fixture["csrf_token"]
        task_id = shared_acceptance_fixture["e2e_task_id"]

        # 1. Attempt to alter workspace_root during approval -> HTTP 400 (G01)
        r_mod_ws = console_client.post(
            f"/console/api/autonomous/tasks/{task_id}/approve",
            headers={"x-csrf-token": csrf_token},
            json={"workspace_root": "C:\\Windows\\System32"},
        )
        assert r_mod_ws.status_code == 400
        assert "Scope modification rejected (G01)" in r_mod_ws.json()["error"]

        # 2. Attempt to broaden allowed_tools during approval -> HTTP 400 (G01)
        r_mod_tools = console_client.post(
            f"/console/api/autonomous/tasks/{task_id}/approve",
            headers={"x-csrf-token": csrf_token},
            json={"allowed_tools": ["read_file", "powershell_execute", "mouse_click"]},
        )
        assert r_mod_tools.status_code == 400
        assert "Scope modification rejected (G01)" in r_mod_tools.json()["error"]

        # 3. Attempt to broaden allowed_commands during approval -> HTTP 400 (G01)
        r_mod_cmds = console_client.post(
            f"/console/api/autonomous/tasks/{task_id}/approve",
            headers={"x-csrf-token": csrf_token},
            json={"allowed_commands": ["rmdir*", "pytest*"]},
        )
        assert r_mod_cmds.status_code == 400
        assert "Scope modification rejected (G01)" in r_mod_cmds.json()["error"]

    def test_06_owner_approve_and_start_once(self, shared_acceptance_fixture):
        console_client: TestClient = shared_acceptance_fixture["console_client"]
        csrf_token = shared_acceptance_fixture["csrf_token"]
        task_id = shared_acceptance_fixture["e2e_task_id"]
        expected_digest = shared_acceptance_fixture["e2e_proposal_digest"]

        # Approve exact proposal once with auto_start: True
        approve_resp = console_client.post(
            f"/console/api/autonomous/tasks/{task_id}/approve",
            headers={"x-csrf-token": csrf_token},
            json={"auto_start": True},
        )
        assert approve_resp.status_code == 200, approve_resp.text
        data = approve_resp.json()

        # Verify response structure and secrets exclusion (G01)
        assert data["task_id"] == task_id
        assert data["grant_id"] and data["grant_id"].startswith("grant_")
        assert data["proposal_digest"] == expected_digest
        assert data["state"] == "QUEUED"
        assert data["worker_pid"] is not None and isinstance(data["worker_pid"], int)
        assert data["worker_pid"] > 0

        # CRITICAL (G01): Response must never leak tokens or signatures
        assert "owner_approval_token" not in data
        assert "token" not in data
        assert "signature" not in data

        shared_acceptance_fixture["grant_id"] = data["grant_id"]
        shared_acceptance_fixture["worker_pid"] = data["worker_pid"]


# ==============================================================================
# STEPS 3 & 4: AUTONOMOUS EXECUTION & BROWSER/GATEWAY DISCONNECT SURVIVAL
# ==============================================================================
class TestStep3And4_AutonomousExecutionAndSurvival:
    """Steps 3 & 4: Independent OS Worker Execution and Gateway Reconnect Query."""

    def test_07_independent_worker_defect_repair_and_completion(
        self, shared_acceptance_fixture
    ):
        store: TaskStore = shared_acceptance_fixture["store"]
        ws: Path = shared_acceptance_fixture["workspace"]
        task_id = shared_acceptance_fixture["e2e_task_id"]

        # Verify independent OS worker executes to completion without active gateway/console thread
        t_deadline = time.time() + 35.0
        completed = False
        last_state = ""
        while time.time() < t_deadline:
            t_rec = store.get_task(task_id)
            if t_rec is not None:
                last_state = t_rec.state
                if t_rec.state == TaskState.COMPLETED.value:
                    completed = True
                    break
                if t_rec.state in (TaskState.FAILED.value, TaskState.CANCELLED.value):
                    pytest.fail(
                        f"Task failed unexpectedly: {t_rec.error_message} (logs: {store.get_task_logs(task_id)})"
                    )
            time.sleep(0.5)

        assert completed is True, f"Worker did not complete within timeout. Last state: {last_state}"

        # Verify defect in calculator.py was atomically repaired
        repaired_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a + b" in repaired_calc
        assert "return a - b" not in repaired_calc

        # Verify atomic write backup was created in backups/file_versions/
        backup_dir = PROJECT_ROOT / "backups" / "file_versions"
        if backup_dir.exists():
            backups = list(backup_dir.glob(f"{task_id}_*calculator.py.bak"))
            assert len(backups) >= 1
            # Clean up test backups
            for b in backups:
                try:
                    b.unlink()
                except Exception:
                    pass

        # Verify task progress record
        final_task = store.get_task(task_id)
        assert final_task is not None
        assert final_task.verification_passed is True
        assert "calculator.py" in str(final_task.files_modified)

    def test_08_chatgpt_reconnect_query_completion_status_and_diff(
        self, shared_acceptance_fixture
    ):
        gw_client: TestClient = shared_acceptance_fixture["gw_client"]
        task_id = shared_acceptance_fixture["e2e_task_id"]

        # 1. agent_task_status
        status_resp = gw_client.post(
            "/mcp/autonomous",
            json={
                "jsonrpc": "2.0",
                "id": 81,
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task_id}},
            },
        )
        assert status_resp.status_code == 200
        s_data = json.loads(status_resp.json()["result"]["content"][0]["text"])
        assert s_data["status"] == TaskState.COMPLETED.value
        assert s_data["task_id"] == task_id

        # 2. agent_task_logs
        logs_resp = gw_client.post(
            "/mcp/autonomous",
            json={
                "jsonrpc": "2.0",
                "id": 82,
                "method": "tools/call",
                "params": {"name": "agent_task_logs", "arguments": {"task_id": task_id}},
            },
        )
        assert logs_resp.status_code == 200
        l_data = json.loads(logs_resp.json()["result"]["content"][0]["text"])
        assert "logs" in l_data
        log_phases = [item.get("phase") for item in l_data["logs"]]
        assert "PLANNING" in log_phases or "ACT" in log_phases
        assert "COMPLETED" in log_phases

        # 3. agent_task_diff
        diff_resp = gw_client.post(
            "/mcp/autonomous",
            json={
                "jsonrpc": "2.0",
                "id": 83,
                "method": "tools/call",
                "params": {"name": "agent_task_diff", "arguments": {"task_id": task_id}},
            },
        )
        assert diff_resp.status_code == 200
        d_data = json.loads(diff_resp.json()["result"]["content"][0]["text"])
        assert "git_diff" in d_data
        assert any("calculator.py" in str(f) for f in d_data.get("files_modified", []))

        # 4. agent_task_artifacts
        artifacts_resp = gw_client.post(
            "/mcp/autonomous",
            json={
                "jsonrpc": "2.0",
                "id": 84,
                "method": "tools/call",
                "params": {"name": "agent_task_artifacts", "arguments": {"task_id": task_id}},
            },
        )
        assert artifacts_resp.status_code == 200
        a_data = json.loads(artifacts_resp.json()["result"]["content"][0]["text"])
        assert "files_modified" in a_data
        assert any("calculator.py" in str(a) for a in a_data["files_modified"])


# ==============================================================================
# STEP 5: ALL 9 MANDATORY SECURITY CLOSURE CHECKS
# ==============================================================================
class TestStep5_NineMandatorySecurityChecks:
    """Step 5: All 9 Mandatory Security Closure Checks."""

    def test_check1_no_owner_approval_no_privileged_execution(
        self, shared_acceptance_fixture
    ):
        """Check 1: Unapproved task stays in AUTHORIZATION_PENDING; cannot execute privileged actions."""
        store: TaskStore = shared_acceptance_fixture["store"]
        ws: Path = shared_acceptance_fixture["workspace"]
        handler: AgentMCPToolHandler = shared_acceptance_fixture["handler"]

        res = handler.execute_tool(
            "agent_submit_task",
            {"objective": "Unapproved task", "workspace_root": str(ws)},
            surface="cloud_autonomous",
            caller_id="chatgpt_cloud_client",
        )
        t_id = res["task_id"]
        task = store.get_task(t_id)
        assert task.state == TaskState.AUTHORIZATION_PENDING.value
        assert task.grant_id is None

    def test_check2_forged_approval_token_denied(self, shared_acceptance_fixture):
        """Check 2: Forged HMAC token fails validation and is rejected."""
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        ws: Path = shared_acceptance_fixture["workspace"]

        is_valid = broker.verify_owner_approval_token(
            task_id="task_test_forged",
            workspace_root=ws,
            token="v2.eyJleHAiOjE5OTk5OTk5OTl9.invalid_signature_hex_0123456789abcdef",  # gitleaks:allow  (synthetic regression fixture; reviewed)
        )
        assert is_valid is False

    def test_check3_replayed_approval_token_denied_g01(
        self, shared_acceptance_fixture
    ):
        """Check 3: Replayed single-use approval token is strictly rejected (G01)."""
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        ws: Path = shared_acceptance_fixture["workspace"]

        token = broker.generate_owner_approval_token("task_g01_replay", ws)
        # First verification succeeds and consumes nonce
        first_valid = broker.verify_owner_approval_token(
            "task_g01_replay", ws, token, consume=True
        )
        assert first_valid is True

        # Second verification with same token fails closed (replayed nonce in SQLite)
        second_valid = broker.verify_owner_approval_token(
            "task_g01_replay", ws, token, consume=True
        )
        assert second_valid is False

    def test_check4_wildcard_task_approval_denied_g01(
        self, shared_acceptance_fixture
    ):
        """Check 4: Wildcard task approval (task_id='*') is strictly forbidden (G01)."""
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        ws: Path = shared_acceptance_fixture["workspace"]

        with pytest.raises(PermissionError) as exc_info:
            broker.generate_owner_approval_token("*", ws)
        assert "Wildcard task_id approval ('*') is strictly forbidden (G01)" in str(
            exc_info.value
        )

    def test_check5_modified_task_scope_denied_g01(self, shared_acceptance_fixture):
        """Check 5: Modified task scope between review and approval causes digest mismatch (G01)."""
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        ws: Path = shared_acceptance_fixture["workspace"]

        token = broker.generate_owner_approval_token(
            "task_g01_tamper", ws, scope_digest="digest_original_aaa"
        )
        # Verify with modified digest fails
        tampered_valid = broker.verify_owner_approval_token(
            "task_g01_tamper",
            ws,
            token,
            expected_scope_digest="digest_modified_bbb",
        )
        assert tampered_valid is False

    def test_check6_cross_task_grant_reuse_denied_g02(
        self, shared_acceptance_fixture
    ):
        """Check 6: Binding Task 1's grant to Task 2 is rejected (G02)."""
        store: TaskStore = shared_acceptance_fixture["store"]
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        ws: Path = shared_acceptance_fixture["workspace"]

        t1 = store.create_task("Task 1", workspace_root=ws)
        t2 = store.create_task("Task 2", workspace_root=ws)

        g1 = broker.issue_grant(
            task_id=t1.task_id,
            workspace_root=ws,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
        )
        # Bind g1 to t1 works
        store.bind_grant(t1.task_id, g1.grant_id)

        # Attempt to bind g1 to t2 fails closed with G02
        with pytest.raises(PermissionError) as exc_info:
            store.bind_grant(t2.task_id, g1.grant_id)
        assert "(G02)" in str(exc_info.value)

    def test_check7_unauthorized_workspace_root_denied_g03(
        self, shared_acceptance_fixture
    ):
        """Check 7: Workspace path outside preapproved roots fails closed (G03)."""
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        base_dir: Path = shared_acceptance_fixture["base_dir"]
        unauthorized_dir = base_dir / "unauthorized_external_repo"
        unauthorized_dir.mkdir(parents=True, exist_ok=True)

        with pytest.raises(PermissionError) as exc_info:
            broker.issue_grant(
                task_id="task_g03_unauth",
                workspace_root=unauthorized_dir,
                allowed_tools=["read_file"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ"],
            )
        assert "outside owner preapproved roots" in str(exc_info.value).lower()

    def test_check8_expired_revoked_grant_and_unapproved_commands_denied(
        self, shared_acceptance_fixture
    ):
        """Check 8: Expired/revoked grant cannot execute tools; unapproved commands blocked."""
        broker: TaskGrantBroker = shared_acceptance_fixture["broker"]
        ws: Path = shared_acceptance_fixture["workspace"]

        # 1. Expired grant verification
        expired_grant = broker.issue_grant(
            task_id="task_expired",
            workspace_root=ws,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=0.01,
        )
        time.sleep(0.05)
        v_exp, msg_exp = expired_grant.is_valid(broker.secret)
        assert v_exp is False
        assert "expired" in msg_exp.lower()

        # 2. Revoked grant verification
        rev_grant = broker.issue_grant(
            task_id="task_revoked",
            workspace_root=ws,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=300.0,
        )
        broker.revoke_grant(rev_grant.grant_id, reason="Owner revoked")
        v_rev, msg_rev = rev_grant.is_valid(broker.secret)
        assert v_rev is False
        assert "revoked" in msg_rev.lower()

        # 3. Unapproved command validation
        valid_grant = broker.issue_grant(
            task_id="task_cmd_check",
            workspace_root=ws,
            allowed_tools=["powershell_execute"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["READ", "EXECUTE"],
            duration_seconds=300.0,
        )
        assert valid_grant.allows_command("pytest -v") is True
        assert valid_grant.allows_command("python -m unittest") is True
        assert valid_grant.allows_command("cmd.exe /c format C:") is False
        assert valid_grant.allows_command("powershell.exe -enc AAAA") is False

    def test_check9_emergency_stop_windows_process_tree_termination(
        self, shared_acceptance_fixture
    ):
        """Check 9: _kill_process_tree terminates parent and grandchild processes cleanly."""
        ws: Path = shared_acceptance_fixture["workspace"]
        child_pid_file = ws / "test_child_pid.txt"

        spawn_script = (
            "import subprocess, sys, time, pathlib\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            f"pathlib.Path(r'{child_pid_file}').write_text(str(child.pid), encoding='utf-8')\n"
            "time.sleep(60)\n"
        )
        script_file = ws / "spawn_child_tree.py"
        script_file.write_text(spawn_script, encoding="utf-8")

        parent_proc = subprocess.Popen(
            [sys.executable, str(script_file)],
            cwd=str(ws),
        )
        parent_pid = parent_proc.pid

        # Wait for child PID to be recorded
        t_deadline = time.time() + 10.0
        child_pid = None
        while time.time() < t_deadline:
            if child_pid_file.exists():
                txt = child_pid_file.read_text(encoding="utf-8").strip()
                if txt.isdigit():
                    child_pid = int(txt)
                    break
            time.sleep(0.2)

        assert child_pid is not None, "Child PID file was not written"
        assert is_pid_alive(parent_pid) is True
        assert is_pid_alive(child_pid) is True

        # Execute process tree kill
        _kill_process_tree(parent_pid)
        time.sleep(1.0)

        assert is_pid_alive(parent_pid) is False
        assert is_pid_alive(child_pid) is False

        # Cleanup
        try:
            child_pid_file.unlink()
            script_file.unlink()
        except Exception:
            pass


# ==============================================================================
# SECTION 6: OFFLINE_TEST_MODE VS LIVE_AI_MODE
# ==============================================================================
class TestSection6_LLMOperatingProfiles:
    """Section 6: OFFLINE_TEST_MODE vs LIVE_AI_MODE Operating Status."""

    def test_operating_status_offline_mode_and_guardrails(
        self, shared_acceptance_fixture
    ):
        console_client: TestClient = shared_acceptance_fixture["console_client"]

        # Ensure OPENAI_API_KEY is not configured
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            # 1. GET /console/api/autonomous/status
            status_resp = console_client.get("/console/api/autonomous/status")
            assert status_resp.status_code == 200, status_resp.text
            data = status_resp.json()
            llm_info = data.get("llm_status", {})
            assert llm_info.get("status") == "LIVE_AI_NOT_CONFIGURED"
            assert llm_info.get("operating_profile") == OperatingProfile.OFFLINE_TEST_MODE
            assert llm_info.get("is_live_ai") is False

            # 2. get_llm_operating_status()
            op_status = get_llm_operating_status()
            assert op_status["status"] == "LIVE_AI_NOT_CONFIGURED"
            assert op_status["operating_profile"] == OperatingProfile.OFFLINE_TEST_MODE
            assert op_status["is_live_ai"] is False

            # 3. get_llm_adapter(profile="LIVE_AI_MODE") raises LiveAINotConfiguredError
            with pytest.raises(LiveAINotConfiguredError) as exc_info:
                get_llm_adapter(profile=OperatingProfile.LIVE_AI_MODE)
            assert "LIVE_AI_NOT_CONFIGURED" in str(exc_info.value)
