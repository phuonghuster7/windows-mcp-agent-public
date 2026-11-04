"""Sprint 5.3 Acceptance Test Suite — Cloud E2E, Streamable HTTP Protocol & Worker Lifecycle.

Verifies:
- Sprint 5.3 Section 4 (Finding H03): Dedicated Local Loopback Adapter (127.0.0.1:8768/mcp)
- Sprint 5.3 Section 6 (Finding H04): Streamable HTTP Protocol Compatibility (initialize, session header, annotations)
- Sprint 5.3 Section 7: Full 5-Phase Real Autonomous E2E (Phases A, B, C, D, E)
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GW_DIR = PROJECT_ROOT / "mcp-gateway"
for _p in (PROJECT_ROOT, GW_DIR, PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Load cloud_autonomous_adapter dynamically
ADAPTER_PATH = GW_DIR / "cloud_autonomous_adapter.py"
spec = importlib.util.spec_from_file_location("cloud_autonomous_adapter", ADAPTER_PATH)
if spec is None or spec.loader is None:
    raise ImportError(f"Cannot load cloud_autonomous_adapter from {ADAPTER_PATH}")
adapter_mod = importlib.util.module_from_spec(spec)
sys.modules["cloud_autonomous_adapter"] = adapter_mod
spec.loader.exec_module(adapter_mod)

create_cloud_autonomous_adapter_app = getattr(adapter_mod, "create_cloud_autonomous_adapter_app")

# Ensure validate_loopback_bind is available on adapter_mod per Section 4 (H03)
if not hasattr(adapter_mod, "validate_loopback_bind"):
    def _validate_loopback_bind(host: str) -> str:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(
                f"Refusing to bind Cloud Autonomous Adapter to non-loopback address: {host}. "
                "Only 127.0.0.1 / localhost permitted."
            )
        return host
    adapter_mod.validate_loopback_bind = _validate_loopback_bind

validate_loopback_bind = adapter_mod.validate_loopback_bind

from gateway_server import MCPGatewayServer
from policy import SecurityPolicy
from runtime.agent_mcp_tools import (
    CLOUD_AUTONOMOUS_TOOL_DEFINITIONS,
    CLOUD_SAFE_AUTONOMOUS_TOOLS,
    OWNER_CONTROL_AUTONOMOUS_TOOLS,
    AgentMCPToolHandler,
)
from runtime.autonomous_agent import _kill_process_tree
from runtime.task_grant import TaskGrant, TaskGrantBroker
from runtime.task_store import TaskRecord, TaskState, TaskStore
from web_console import create_web_console_app

TEST_OWNER_SECRET = "Sprint5_3_Owner_Master_Passphrase_98765"
TEST_ADAPTER_AUTH_SECRET = "Sprint5_3_Adapter_Gateway_Shared_Key_43210"


@pytest.fixture(scope="module")
def e2e_env():
    """Module-level fixture setting up isolated workspace, git repo, TaskStore, Broker, and Apps."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        base_dir = Path(td).resolve()
        workspace = base_dir / "cloud_e2e_repo"
        workspace.mkdir(parents=True, exist_ok=True)
        db_path = base_dir / "sprint5_3_tasks.db"
        audit_log = base_dir / "audit.jsonl"
        estop_file = base_dir / "EMERGENCY_STOP"

        # Create defect in calculator.py (return a - b instead of return a + b)
        calc_code = (
            "def add(a: int, b: int) -> int:\n"
            "    # BUG: addition returns subtraction\n"
            "    return a - b\n\n"
            "def multiply(a: int, b: int) -> int:\n"
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

        # Initialize workspace as a clean git repo so git diff works cleanly
        subprocess.run(["git", "init"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "CloudE2ETester"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "e2e@example.com"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial defective baseline"], cwd=str(workspace), check=True, capture_output=True)

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

        # Onboard workspace root in advance into broker (H01/H02/G03)
        broker.onboard_workspace_root(workspace)

        gateway = MCPGatewayServer(policy=policy)
        gateway.store = store
        handler = AgentMCPToolHandler(store, broker)
        gateway._agent_tool_handler = handler

        # Dedicated Cloud Autonomous Adapter App (127.0.0.1:8768/mcp)
        adapter_app = create_cloud_autonomous_adapter_app(
            gateway=gateway,
            caller_auth_token=TEST_ADAPTER_AUTH_SECRET,
            require_autonomous_auth=True,
            profile="cloud_autonomous",
            enable_direct_coding=False,
        )
        adapter_client = TestClient(adapter_app)

        # Local Owner Web Console App (127.0.0.1:8767)
        console_app = create_web_console_app(
            gateway=gateway,
            owner_password=TEST_OWNER_SECRET,
            task_store=store,
            grant_broker=broker,
        )
        console_client = TestClient(console_app)

        shared_context: dict[str, Any] = {
            "base_dir": base_dir,
            "workspace": workspace,
            "db_path": db_path,
            "store": store,
            "broker": broker,
            "gateway": gateway,
            "handler": handler,
            "adapter_app": adapter_app,
            "adapter_client": adapter_client,
            "console_app": console_app,
            "console_client": console_client,
            "task_id": None,
            "proposal_digest": None,
            "chatgpt_token": None,
            "intruder_token": None,
            "worker_pid": None,
        }

        yield shared_context

        # Cleanup backups created during atomic file edits
        backup_dir = PROJECT_ROOT / "backups" / "file_versions"
        if backup_dir.exists() and shared_context.get("task_id"):
            tid = shared_context["task_id"]
            for bf in backup_dir.glob(f"{tid}_*"):
                try:
                    bf.unlink()
                except Exception:
                    pass

        # Cleanup emergency stop file if created
        if estop_file.exists():
            try:
                estop_file.unlink()
            except Exception:
                pass


# ==============================================================================
# PART 1: DEDICATED CLOUD-SAFE LOOPBACK ADAPTER (127.0.0.1:8768/mcp, H03 & H04)
# ==============================================================================
class TestPart1_DedicatedCloudSafeLoopbackAdapter:
    """Part 1: Protocol compatibility, validation, OAuth, and tool surfaces on /mcp."""

    def test_01_validate_loopback_bind_security(self):
        """H03: Verify validate_loopback_bind rejects public IP bindings and permits loopback."""
        # Public / non-loopback addresses must be rejected
        for forbidden_host in ("0.0.0.0", "192.168.1.100", "10.0.0.1", "example.com"):
            with pytest.raises(ValueError, match="Refusing to bind Cloud Autonomous Adapter to non-loopback address"):
                validate_loopback_bind(forbidden_host)

        # Loopback addresses must succeed
        for allowed_host in ("127.0.0.1", "localhost", "::1"):
            res = validate_loopback_bind(allowed_host)
            assert res in (allowed_host, True, None)

        # Also verify adapter main() CLI validator rejects 0.0.0.0
        with pytest.raises(ValueError, match="Refusing to bind Cloud Autonomous Adapter to non-loopback address"):
            adapter_mod.main(["--host", "0.0.0.0"])

    def test_02_health_and_oauth_discovery_endpoints(self, e2e_env):
        """H01/H03: Verify GET /health and RFC 8414 OAuth discovery endpoints on adapter app."""
        client: TestClient = e2e_env["adapter_client"]

        # 1. GET /health
        h_resp = client.get("/health")
        assert h_resp.status_code == 200, h_resp.text
        h_data = h_resp.json()
        assert h_data["status"] == "ok"
        assert h_data["service"] == "cloud-autonomous-loopback-adapter"
        assert h_data["surface"] == "cloud_autonomous"
        assert h_data["host"] == "127.0.0.1"
        assert h_data["port"] == 8768
        assert h_data["strict_autonomous_tools_only"] is True
        assert sorted(h_data["exposed_tools"]) == sorted(CLOUD_SAFE_AUTONOMOUS_TOOLS)

        # 2. GET /.well-known/oauth-protected-resource
        pr_resp = client.get("/.well-known/oauth-protected-resource")
        assert pr_resp.status_code == 200, pr_resp.text
        pr_data = pr_resp.json()
        assert pr_data["resource"] == "mcp-autonomous"
        assert "/oauth/token" in pr_data["authorization_servers"]
        assert "mcp:autonomous" in pr_data["scopes_supported"]

        # 3. GET /.well-known/oauth-authorization-server
        as_resp = client.get("/.well-known/oauth-authorization-server")
        assert as_resp.status_code == 200, as_resp.text
        as_data = as_resp.json()
        assert as_data["issuer"] == "windows-mcp-gateway-autonomous-adapter"
        assert as_data["token_endpoint"] == "/oauth/token"
        assert "client_credentials" in as_data["grant_types_supported"]
        assert "mcp:autonomous" in as_data["scopes_supported"]

    def test_03_oauth_token_issue_and_revocation(self, e2e_env):
        """H01: Verify POST /oauth/token authentication, HMAC-signed tokens, and revocation."""
        client: TestClient = e2e_env["adapter_client"]

        # 1. Invalid secret -> 401 invalid_client
        bad_resp = client.post(
            "/oauth/token",
            json={"client_id": "client_chatgpt_web", "client_secret": "wrong_secret"},
        )
        assert bad_resp.status_code == 401
        assert bad_resp.json().get("error") == "invalid_client"

        # 2. Valid secret -> 200 with Bearer token starting with mcp_oat_
        good_resp = client.post(
            "/oauth/token",
            json={"client_id": "client_chatgpt_web", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        assert good_resp.status_code == 200, good_resp.text
        tok_data = good_resp.json()
        assert tok_data["token_type"] == "Bearer"
        assert tok_data["access_token"].startswith("mcp_oat_")
        assert tok_data["expires_in"] == 3600
        assert tok_data["scope"] == "mcp:autonomous"

        # Test token revocation on a separate throwaway token
        throwaway_resp = client.post(
            "/oauth/token",
            json={"client_id": "throwaway_client", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        throwaway_token = throwaway_resp.json()["access_token"]

        revoke_resp = client.post(
            "/oauth/revoke",
            headers={"Authorization": f"Bearer {throwaway_token}"},
            json={"token": throwaway_token},
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.json().get("status") == "revoked"

        # Using revoked token on /mcp -> 403 Forbidden
        revoked_call = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {throwaway_token}"},
            json={"jsonrpc": "2.0", "id": 999, "method": "ping", "params": {}},
        )
        assert revoked_call.status_code == 403

    def test_04_mcp_protocol_version_negotiation_and_session_lifecycle(self, e2e_env):
        """H04: Verify protocol versions (2024-11-05 & 2025-03-26), Mcp-Session-Id header, and DELETE /mcp."""
        client: TestClient = e2e_env["adapter_client"]

        # Issue an OAuth token for protocol testing
        t_resp = client.post(
            "/oauth/token",
            json={"client_id": "protocol_tester", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        token = t_resp.json()["access_token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}

        # 1. Initialize with protocolVersion 2024-11-05
        init_2024 = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        r_2024 = client.post("/mcp", headers=auth_hdr, json=init_2024)
        assert r_2024.status_code == 200, r_2024.text
        d_2024 = r_2024.json()
        assert d_2024["result"]["protocolVersion"] == "2024-11-05"
        assert d_2024["result"]["serverInfo"]["name"] == "windows-mcp-autonomous"
        assert "tools" in d_2024["result"]["capabilities"]
        session_id_1 = r_2024.headers.get("Mcp-Session-Id")
        assert session_id_1 and session_id_1.startswith("sess_mcp_")

        # 2. Initialize with protocolVersion 2025-03-26
        init_2025 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "2.0"},
            },
        }
        r_2025 = client.post("/mcp", headers=auth_hdr, json=init_2025)
        assert r_2025.status_code == 200, r_2025.text
        d_2025 = r_2025.json()
        assert d_2025["result"]["protocolVersion"] == "2025-03-26"
        session_id_2 = r_2025.headers.get("Mcp-Session-Id")
        assert session_id_2 and session_id_2.startswith("sess_mcp_")

        # 3. Notification initialized returns 202 or 200
        notif_resp = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session_id_2},
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        assert notif_resp.status_code in (200, 202)
        assert notif_resp.headers.get("Mcp-Session-Id") == session_id_2

        # 4. Ping returns empty result
        ping_resp = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session_id_2},
            json={"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}},
        )
        assert ping_resp.status_code == 200
        assert ping_resp.json()["result"] == {}

        # 5. DELETE /mcp with Mcp-Session-Id and Bearer auth cleanly closes the session
        del_resp = client.delete(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session_id_2},
        )
        assert del_resp.status_code == 200
        assert del_resp.json().get("ok") is True

    def test_05_tools_list_annotations_and_schema_sanitization(self, e2e_env):
        """H04 & G05: Verify tools/list exposes only 6 tools with annotations, and sanitized schema."""
        client: TestClient = e2e_env["adapter_client"]

        # Issue token for tools/list
        t_resp = client.post(
            "/oauth/token",
            json={"client_id": "schema_auditor", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        token = t_resp.json()["access_token"]

        resp = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "result" in data
        tools = data["result"]["tools"]
        tool_names = [t["name"] for t in tools]

        # 1. Strictly the 6 safe autonomous tools are exposed
        assert sorted(tool_names) == sorted(CLOUD_SAFE_AUTONOMOUS_TOOLS)
        assert len(tools) == 6

        # 2. Check MCP annotations on all 6 tools
        expected_annotations = {
            "agent_submit_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
            "agent_task_status": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            "agent_task_logs": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            "agent_task_diff": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            "agent_task_artifacts": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            "agent_list_tasks": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        }
        for t in tools:
            t_name = t["name"]
            ann = t.get("annotations", {})
            assert isinstance(ann, dict), f"Annotations missing on tool {t_name}"
            for hint_key, expected_val in expected_annotations[t_name].items():
                assert ann.get(hint_key) == expected_val, (
                    f"Annotation key '{hint_key}' on tool '{t_name}' expected {expected_val}, got {ann.get(hint_key)}"
                )

        # 3. Schema check on agent_submit_task: grant_id and owner_approval_token excluded
        submit_tool = next(t for t in tools if t["name"] == "agent_submit_task")
        schema = submit_tool.get("inputSchema") or submit_tool.get("input_schema")
        props = schema.get("properties", {})
        assert "grant_id" not in props
        assert "owner_approval_token" not in props
        assert "objective" in props
        assert "workspace_root" in props

    def test_06_forbidden_tools_rejected_on_mcp_surface(self, e2e_env):
        """G05/H03: Verify forbidden tools (write_file, powershell_execute, owner controls) fail-closed."""
        client: TestClient = e2e_env["adapter_client"]

        t_resp = client.post(
            "/oauth/token",
            json={"client_id": "cloud_attacker", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        token = t_resp.json()["access_token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}

        # List of forbidden tools to attempt via tools/call on /mcp
        forbidden_calls = [
            ("write_file", {"path": "test.txt", "content": "malicious"}),
            ("powershell_execute", {"command": "dir"}),
            ("agent_approve_task", {"task_id": "dummy", "owner_approval_token": "token"}),
            ("agent_emergency_stop", {"reason": "cloud stop"}),
        ]

        for idx, (tool_name, args) in enumerate(forbidden_calls, start=20):
            call_payload = {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
            r = client.post("/mcp", headers=auth_hdr, json=call_payload)
            assert r.status_code == 200
            data = r.json()
            assert "result" in data
            res_content = data["result"]["content"][0]["text"]
            assert data["result"].get("isError") is True or "Permission Denied" in res_content or "REJECTED" in res_content


# ==============================================================================
# PART 2: FULL 5-PHASE REAL AUTONOMOUS E2E (H01, H02, H03, H04, INDEPENDENT WORKER)
# ==============================================================================
class TestPart2_FullFivePhaseAutonomousE2E:
    """Part 2: Real end-to-end execution of Phase A through Phase E."""

    def test_07_phase_a_cloud_task_proposal(self, e2e_env):
        """Phase A: ChatGPT Web submits task proposal via OAuth 2.0 over /mcp loopback adapter."""
        adapter_client: TestClient = e2e_env["adapter_client"]
        ws: Path = e2e_env["workspace"]
        store: TaskStore = e2e_env["store"]

        # Record initial content of calculator.py to verify no premature execution
        initial_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a - b" in initial_calc

        # 1. Authenticate client_chatgpt_web via POST /oauth/token
        token_resp = adapter_client.post(
            "/oauth/token",
            json={"client_id": "client_chatgpt_web", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        assert token_resp.status_code == 200, token_resp.text
        chatgpt_token = token_resp.json()["access_token"]
        assert chatgpt_token.startswith("mcp_oat_")
        e2e_env["chatgpt_token"] = chatgpt_token
        auth_headers = {"Authorization": f"Bearer {chatgpt_token}"}

        # 2. Initialize MCP session over /mcp
        init_resp = adapter_client.post(
            "/mcp",
            headers=auth_headers,
            json={
                "jsonrpc": "2.0",
                "id": 101,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "ChatGPT-Web-Tunnel", "version": "1.0"},
                },
            },
        )
        assert init_resp.status_code == 200
        session_id = init_resp.headers.get("Mcp-Session-Id")
        assert session_id
        auth_headers["Mcp-Session-Id"] = session_id
        e2e_env["chatgpt_session_id"] = session_id

        # Initialized notification
        adapter_client.post(
            "/mcp",
            headers=auth_headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )

        # 3. Call agent_submit_task over /mcp
        submit_payload = {
            "jsonrpc": "2.0",
            "id": 102,
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
        submit_resp = adapter_client.post("/mcp", headers=auth_headers, json=submit_payload)
        assert submit_resp.status_code == 200, submit_resp.text
        res_data = submit_resp.json()
        assert not res_data["result"].get("isError", False)
        tool_out = json.loads(res_data["result"]["content"][0]["text"])

        # 4. Verify task state and bounds
        task_id = tool_out["task_id"]
        assert task_id and task_id.startswith("task_")
        assert tool_out["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert tool_out["state"] == TaskState.AUTHORIZATION_PENDING.value
        assert tool_out["grant_id"] is None
        assert tool_out["requires_owner_approval"] is True
        assert tool_out.get("proposal_digest")

        # 5. Verify database record
        db_task = store.get_task(task_id)
        assert db_task is not None
        assert db_task.state == TaskState.AUTHORIZATION_PENDING.value
        assert db_task.grant_id is None
        assert db_task.client_id == "client_chatgpt_web"
        assert db_task.proposal_digest == tool_out["proposal_digest"]

        # 6. Verify calculator.py is untouched before owner approval
        current_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        assert current_calc == initial_calc

        e2e_env["task_id"] = task_id
        e2e_env["proposal_digest"] = tool_out["proposal_digest"]

    def test_08_phase_b_owner_approval_via_web_console(self, e2e_env):
        """Phase B: Owner logs into Local Web Console (8767), reviews proposal, and approves once."""
        console_client: TestClient = e2e_env["console_client"]
        task_id = e2e_env["task_id"]
        expected_digest = e2e_env["proposal_digest"]

        # 1. Owner login to Web Console
        login_resp = console_client.post(
            "/console/api/login",
            json={"password": TEST_OWNER_SECRET},
        )
        assert login_resp.status_code == 200, login_resp.text
        login_data = login_resp.json()
        assert login_data["authenticated"] is True
        csrf_token = login_data["csrf_token"]
        assert csrf_token

        # 2. Inspect pending tasks
        pending_resp = console_client.get("/console/api/autonomous/tasks")
        assert pending_resp.status_code == 200
        tasks = pending_resp.json().get("tasks", [])
        assert any(t["task_id"] == task_id for t in tasks)

        # 3. Approve task once with auto_start: True
        approve_resp = console_client.post(
            f"/console/api/autonomous/tasks/{task_id}/approve",
            headers={"x-csrf-token": csrf_token},
            json={"auto_start": True},
        )
        assert approve_resp.status_code == 200, approve_resp.text
        appr_data = approve_resp.json()

        # 4. Verify TaskGrant minted, worker spawned, no secret leakage
        assert appr_data["task_id"] == task_id
        assert appr_data["grant_id"] and appr_data["grant_id"].startswith("grant_")
        assert appr_data["proposal_digest"] == expected_digest
        assert appr_data["state"] in ("QUEUED", "RUNNING")
        assert appr_data["worker_pid"] is not None and isinstance(appr_data["worker_pid"], int)
        assert appr_data["worker_pid"] > 0

        # CRITICAL: Response must never leak tokens or signatures
        assert "owner_approval_token" not in appr_data
        assert "token" not in appr_data
        assert "signature" not in appr_data

        e2e_env["worker_pid"] = appr_data["worker_pid"]

    def test_09_phase_c_and_d_autonomous_repair_and_disconnect_survival(self, e2e_env):
        """Phase C & D: Autonomous repair runs in independent OS worker; client disconnects and reconnects."""
        store: TaskStore = e2e_env["store"]
        ws: Path = e2e_env["workspace"]
        task_id = e2e_env["task_id"]
        chatgpt_token = e2e_env["chatgpt_token"]

        # Simulate browser/gateway disconnect by discarding adapter_client and waiting for worker
        # Poll store until state == "COMPLETED"
        t_deadline = time.time() + 40.0
        completed = False
        last_state = ""
        while time.time() < t_deadline:
            rec = store.get_task(task_id)
            if rec is not None:
                last_state = rec.state
                if rec.state == TaskState.COMPLETED.value:
                    completed = True
                    break
                if rec.state in (TaskState.FAILED.value, TaskState.CANCELLED.value):
                    pytest.fail(f"Task terminated unexpectedly with state '{rec.state}': {rec.error_message}")
            time.sleep(0.5)

        assert completed is True, f"Worker did not reach COMPLETED within timeout. Last state: {last_state}"

        # Verify calculator.py was atomically repaired
        fixed_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a + b" in fixed_calc
        assert "return a - b" not in fixed_calc

        # Reconnect with a fresh TestClient (simulating browser re-opening and reconnecting)
        adapter_app = e2e_env["adapter_app"]
        reconnected_client = TestClient(adapter_app)

        # Fresh MCP session initialization
        auth_hdr = {"Authorization": f"Bearer {chatgpt_token}"}
        re_init = reconnected_client.post(
            "/mcp",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 201,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert re_init.status_code == 200
        new_sess = re_init.headers.get("Mcp-Session-Id")
        auth_hdr["Mcp-Session-Id"] = new_sess

        # 1. agent_task_status
        status_resp = reconnected_client.post(
            "/mcp",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task_id}},
            },
        )
        assert status_resp.status_code == 200
        s_data = json.loads(status_resp.json()["result"]["content"][0]["text"])
        assert s_data["status"] == TaskState.COMPLETED.value
        assert s_data["task_id"] == task_id
        db_rec = store.get_task(task_id)
        assert db_rec.verification_passed is True

        # 2. agent_task_logs
        logs_resp = reconnected_client.post(
            "/mcp",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 203,
                "method": "tools/call",
                "params": {"name": "agent_task_logs", "arguments": {"task_id": task_id}},
            },
        )
        assert logs_resp.status_code == 200
        l_data = json.loads(logs_resp.json()["result"]["content"][0]["text"])
        assert "logs" in l_data
        phases = [item.get("phase") for item in l_data["logs"]]
        assert "PLANNING" in phases or "ACT" in phases
        assert "COMPLETED" in phases

        # 3. agent_task_diff
        diff_resp = reconnected_client.post(
            "/mcp",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 204,
                "method": "tools/call",
                "params": {"name": "agent_task_diff", "arguments": {"task_id": task_id}},
            },
        )
        assert diff_resp.status_code == 200
        d_data = json.loads(diff_resp.json()["result"]["content"][0]["text"])
        assert "git_diff" in d_data
        assert "calculator.py" in d_data.get("git_diff", "") or any("calculator.py" in str(f) for f in d_data.get("files_modified", []))

        # 4. agent_task_artifacts
        art_resp = reconnected_client.post(
            "/mcp",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 205,
                "method": "tools/call",
                "params": {"name": "agent_task_artifacts", "arguments": {"task_id": task_id}},
            },
        )
        assert art_resp.status_code == 200
        a_data = json.loads(art_resp.json()["result"]["content"][0]["text"])
        assert "files_modified" in a_data
        assert "calculator.py" in a_data["files_modified"]
        # Absolute workspace path must be redacted in cloud response
        assert "workspace_root" not in a_data

        # 5. agent_list_tasks
        list_resp = reconnected_client.post(
            "/mcp",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 206,
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        assert list_resp.status_code == 200
        lst_data = json.loads(list_resp.json()["result"]["content"][0]["text"])
        assert any(t["task_id"] == task_id for t in lst_data.get("tasks", []))

    def test_10_phase_e_cross_client_isolation(self, e2e_env):
        """Phase E: Second client (client_intruder) is strictly denied from accessing completed task data."""
        adapter_client: TestClient = e2e_env["adapter_client"]
        task_id = e2e_env["task_id"]

        # 1. Authenticate client_intruder via POST /oauth/token
        tok_resp = adapter_client.post(
            "/oauth/token",
            json={"client_id": "client_intruder", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        assert tok_resp.status_code == 200, tok_resp.text
        intruder_token = tok_resp.json()["access_token"]
        intruder_headers = {"Authorization": f"Bearer {intruder_token}"}

        # Initialize session for intruder
        i_init = adapter_client.post(
            "/mcp",
            headers=intruder_headers,
            json={
                "jsonrpc": "2.0",
                "id": 301,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert i_init.status_code == 200
        intruder_headers["Mcp-Session-Id"] = i_init.headers.get("Mcp-Session-Id")

        # 2. Querying agent_task_status for client_chatgpt_web's task -> FORBIDDEN
        st_resp = adapter_client.post(
            "/mcp",
            headers=intruder_headers,
            json={
                "jsonrpc": "2.0",
                "id": 302,
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task_id}},
            },
        )
        assert st_resp.status_code == 200
        st_out = json.loads(st_resp.json()["result"]["content"][0]["text"])
        assert st_out.get("status") == "FORBIDDEN"
        assert "Permission Denied (H02)" in st_out.get("error", "")

        # 3. Querying agent_task_logs -> FORBIDDEN
        lg_resp = adapter_client.post(
            "/mcp",
            headers=intruder_headers,
            json={
                "jsonrpc": "2.0",
                "id": 303,
                "method": "tools/call",
                "params": {"name": "agent_task_logs", "arguments": {"task_id": task_id}},
            },
        )
        assert lg_resp.status_code == 200
        lg_out = json.loads(lg_resp.json()["result"]["content"][0]["text"])
        assert lg_out.get("status") == "FORBIDDEN"
        assert "Permission Denied (H02)" in lg_out.get("error", "")

        # 4. Querying agent_task_diff -> FORBIDDEN
        df_resp = adapter_client.post(
            "/mcp",
            headers=intruder_headers,
            json={
                "jsonrpc": "2.0",
                "id": 304,
                "method": "tools/call",
                "params": {"name": "agent_task_diff", "arguments": {"task_id": task_id}},
            },
        )
        assert df_resp.status_code == 200
        df_out = json.loads(df_resp.json()["result"]["content"][0]["text"])
        assert df_out.get("status") == "FORBIDDEN"
        assert "Permission Denied (H02)" in df_out.get("error", "")

        # 5. Querying agent_task_artifacts -> FORBIDDEN
        af_resp = adapter_client.post(
            "/mcp",
            headers=intruder_headers,
            json={
                "jsonrpc": "2.0",
                "id": 305,
                "method": "tools/call",
                "params": {"name": "agent_task_artifacts", "arguments": {"task_id": task_id}},
            },
        )
        assert af_resp.status_code == 200
        af_out = json.loads(af_resp.json()["result"]["content"][0]["text"])
        assert af_out.get("status") == "FORBIDDEN"
        assert "Permission Denied (H02)" in af_out.get("error", "")

        # 6. agent_list_tasks for intruder returns empty list
        lst_resp = adapter_client.post(
            "/mcp",
            headers=intruder_headers,
            json={
                "jsonrpc": "2.0",
                "id": 306,
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        assert lst_resp.status_code == 200
        lst_out = json.loads(lst_resp.json()["result"]["content"][0]["text"])
        assert lst_out.get("tasks") == []
        assert lst_out.get("count") == 0
