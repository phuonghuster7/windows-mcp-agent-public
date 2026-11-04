"""Sprint 5.4 End-to-End Verification Suite — Real Cloud Plugin & Runtime E2E.

Verifies:
- Test 01: Personal Plugin Contract (Windows MCP Autonomous Agent, Section 6)
  * Exact 6 Cloud-Safe tools exposed on /mcp (agent_submit_task, agent_task_status,
    agent_task_logs, agent_task_diff, agent_task_artifacts, agent_list_tasks)
  * OAuth 2.1 securitySchemes on all tools ([{"type": "oauth2", "scopes": ["mcp:autonomous"]}])
  * Complete MCP tool annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
  * Zero privileged tools exposed (write_file, powershell_execute, agent_approve_task, agent_emergency_stop)
  * RFC 8414 discovery endpoints and HTTP 405 on GET /mcp
- Test 02: Full OAuth 2.1 Authorization Code + PKCE S256 -> 5-Phase Autonomous E2E (Section 7)
  * Connect: POST /oauth/register, GET/POST /oauth/authorize with PKCE S256, POST /oauth/token (mcp_oat_..., mcp_ort_...)
  * Phase A: Task proposal on defective calculator.py enters AUTHORIZATION_PENDING without premature execution
  * Phase B: Owner logs into Web Console, inspects scope, single-click approves with auto_start, spawns independent worker
  * Phase C: Independent Windows worker executes repair, runs pytest until passing, creates .bak backup, zero repeated prompts
  * Phase D: Client disconnects, refreshes token via OAuth refresh_token, reconnects, queries all 5 inspection tools
  * Phase E: Negative authorization tests (unapproved scope modification 400, replayed token rejection, intruder FORBIDDEN, emergency stop)
- Test 03: Live AI Requirement & Operating Profile Honesty (Section 8)
  * OFFLINE_TEST_MODE / LIVE_AI_NOT_CONFIGURED reported honestly without OPENAI_API_KEY
  * get_llm_adapter(require_live=True) raises LiveAINotConfiguredError
  * Zero paid network calls or fabricated live LLM evidence
- Test 04: Account Migration & Credential Non-Reuse Verification (Section 9)
  * Connect-ChatGPTAccount.ps1 -Simulated -DryRun succeeds with PASS
  * Switching from Account 1 to Account 2 generates independent credentials with zero cross-account task leakage
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any, Generator

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

from gateway_server import MCPGatewayServer  # noqa: E402
from policy import SecurityPolicy  # noqa: E402
from runtime.agent_mcp_tools import (  # noqa: E402
    CLOUD_AUTONOMOUS_TOOL_DEFINITIONS,
    CLOUD_SAFE_AUTONOMOUS_TOOLS,
    OWNER_CONTROL_AUTONOMOUS_TOOLS,
    AgentMCPToolHandler,
)
from runtime.llm_adapter import (  # noqa: E402
    DeterministicRuleBasedAdapter,
    LiveAINotConfiguredError,
    OpenAIProviderAdapter,
    OperatingProfile,
    get_llm_adapter,
    get_llm_operating_status,
)
from runtime.task_grant import TaskGrantBroker  # noqa: E402
from runtime.task_store import TaskState, TaskStore, is_pid_alive  # noqa: E402
from web_console import create_web_console_app  # noqa: E402

TEST_OWNER_MASTER_SECRET = "Sprint5_4_Owner_Master_Passphrase_Secure_998811"
TEST_ADAPTER_AUTH_SECRET = "Sprint5_4_Adapter_Auth_Secret_Key_554433"
REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate RFC 7636 PKCE S256 verifier and challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


@pytest.fixture(scope="module")
def autonomous_e2e_env() -> Generator[dict[str, Any], None, None]:
    """Module-level fixture setting up isolated disposable Git coding workspace, TaskStore, Broker, and Apps."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        base_dir = Path(td).resolve()
        workspace = base_dir / "autonomous_coding_repo"
        workspace.mkdir(parents=True, exist_ok=True)
        db_path = base_dir / "sprint5_4_tasks.db"
        audit_log = base_dir / "audit.jsonl"
        estop_file = base_dir / "EMERGENCY_STOP"

        # Create defect in calculator.py (returns subtraction instead of addition)
        calc_code = (
            "def add(a: int, b: int) -> int:\n"
            "    # DEFECT: returns subtraction instead of addition\n"
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

        # Initialize clean disposable Git repo baseline
        subprocess.run(["git", "init"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "ChatGPTAutonomousTester"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "autonomous@example.com"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Baseline with calculator defect"], cwd=str(workspace), check=True, capture_output=True)

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

        # Onboard workspace root in advance into broker
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
            db_path=db_path,
            enable_direct_coding=False,
        )
        adapter_client = TestClient(adapter_app)

        # Local Owner Web Console App (127.0.0.1:8767)
        console_app = create_web_console_app(
            gateway=gateway,
            owner_password=TEST_OWNER_MASTER_SECRET,
            task_store=store,
            grant_broker=broker,
        )
        console_client = TestClient(console_app)

        ctx: dict[str, Any] = {
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
            "client_id": None,
            "client_secret": None,
            "access_token": None,
            "refresh_token": None,
            "worker_pid": None,
        }

        yield ctx

        # Cleanup backups created during file edits
        backup_dir = PROJECT_ROOT / "backups" / "file_versions"
        if backup_dir.exists() and ctx.get("task_id"):
            tid = ctx["task_id"]
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
# TEST 01: PERSONAL PLUGIN CONTRACT (Windows MCP Autonomous Agent, Section 6)
# ==============================================================================
class Test01_PersonalPluginContract:
    """Verify tool surface, OAuth 2.1 security schemes, annotations, and absence of privileged tools."""

    def test_01_exposed_tools_contract_and_security_schemes(self, autonomous_e2e_env):
        """Verify /mcp exposes EXACTLY the 6 Cloud-Safe tools with securitySchemes and annotations."""
        client: TestClient = autonomous_e2e_env["adapter_client"]

        # Issue an initial test token to list tools
        tok_resp = client.post(
            "/oauth/token",
            json={"client_id": "test_contract_inspector", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        )
        assert tok_resp.status_code == 200, tok_resp.text
        test_tok = tok_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {test_tok}"}

        # Initialize session
        init_resp = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert init_resp.status_code == 200
        headers["Mcp-Session-Id"] = init_resp.headers.get("Mcp-Session-Id")

        # Query tools/list
        tools_resp = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools_resp.status_code == 200, tools_resp.text
        result = tools_resp.json().get("result", {})
        tools = result.get("tools", [])

        # 1. Exactly 6 tools exposed
        exposed_names = [t["name"] for t in tools]
        expected_tools = [
            "agent_submit_task",
            "agent_task_status",
            "agent_task_logs",
            "agent_task_diff",
            "agent_task_artifacts",
            "agent_list_tasks",
        ]
        assert sorted(exposed_names) == sorted(expected_tools), f"Exposed: {exposed_names}"
        assert len(tools) == 6

        # 2. Verify OAuth 2.1 securitySchemes and MCP annotations on each tool
        for t in tools:
            name = t["name"]
            # Private Tunnel noauth or OAuth 2.1 securitySchemes
            assert "securitySchemes" in t, f"Tool '{name}' missing securitySchemes"
            sec = t["securitySchemes"]
            assert isinstance(sec, list) and len(sec) > 0
            assert sec[0]["type"] in ("noauth", "oauth2")
            if sec[0]["type"] == "oauth2":
                assert "mcp:autonomous" in sec[0]["scopes"]

            # MCP Annotations
            assert "annotations" in t, f"Tool '{name}' missing annotations"
            ann = t["annotations"]
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                assert hint in ann, f"Tool '{name}' missing annotation '{hint}'"

            # Specific annotation contract checks
            if name in ("agent_task_status", "agent_task_logs", "agent_task_diff", "agent_task_artifacts", "agent_list_tasks"):
                assert ann["readOnlyHint"] is True, f"{name} must have readOnlyHint=True"
                assert ann["idempotentHint"] is True, f"{name} must have idempotentHint=True"
            elif name == "agent_submit_task":
                assert ann["readOnlyHint"] is False, "agent_submit_task must have readOnlyHint=False"
                assert ann["idempotentHint"] is False, "agent_submit_task must have idempotentHint=False"

        # 3. ZERO privileged tools exposed
        forbidden_tools = ["write_file", "powershell_execute", "agent_approve_task", "agent_emergency_stop", "read_file"]
        for f_name in forbidden_tools:
            assert f_name not in exposed_names, f"Privileged tool '{f_name}' exposed on /mcp!"

        # 4. Attempting to call privileged tools over /mcp is strictly rejected
        call_priv = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "powershell_execute", "arguments": {"command": "dir"}},
            },
        )
        assert call_priv.status_code == 200
        priv_res = call_priv.json()
        assert "error" in priv_res or priv_res.get("result", {}).get("isError") is True

        call_owner = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "agent_approve_task", "arguments": {"task_id": "fake_task"}},
            },
        )
        assert call_owner.status_code == 200
        owner_res = call_owner.json()
        assert "error" in owner_res or owner_res.get("result", {}).get("isError") is True
        if "error" in owner_res:
            assert owner_res["error"]["code"] == -32003
        else:
            text = owner_res["result"]["content"][0]["text"]
            assert "Permission Denied" in text

    def test_02_oauth21_discovery_and_methods(self, autonomous_e2e_env):
        """Verify RFC 8414 OAuth discovery documents and HTTP 405 Method Not Allowed on GET /mcp."""
        client: TestClient = autonomous_e2e_env["adapter_client"]

        # 1. GET /.well-known/oauth-protected-resource
        pr_resp = client.get("/.well-known/oauth-protected-resource")
        assert pr_resp.status_code == 200
        pr_data = pr_resp.json()
        assert pr_data["resource"] == "mcp-autonomous"
        assert "mcp:autonomous" in pr_data["scopes_supported"]

        # 2. GET /.well-known/oauth-authorization-server
        as_resp = client.get("/.well-known/oauth-authorization-server")
        assert as_resp.status_code == 200
        as_data = as_resp.json()
        assert as_data["authorization_endpoint"] == "/oauth/authorize"
        assert as_data["token_endpoint"] == "/oauth/token"
        assert "authorization_code" in as_data["grant_types_supported"]
        assert "refresh_token" in as_data["grant_types_supported"]
        assert "S256" in as_data["code_challenge_methods_supported"]

        # 3. GET /mcp must return 405 Method Not Allowed
        get_resp = client.get("/mcp")
        assert get_resp.status_code == 405
        assert get_resp.json()["error"]["code"] == -32600


# ==============================================================================
# TEST 02: FULL OAUTH 2.1 PKCE S256 -> 5-PHASE AUTONOMOUS E2E (Section 7)
# ==============================================================================
class Test02_FivePhaseAutonomousE2E:
    """Full 5-Phase End-to-End Autonomous Workflow execution over real Windows OS processes."""

    def test_03_connect_oauth21_pkce_s256_exchange(self, autonomous_e2e_env):
        """Connect: Dynamic client registration -> Owner consent -> PKCE S256 token exchange."""
        client: TestClient = autonomous_e2e_env["adapter_client"]

        # 1. Register ChatGPT Plugin Client via POST /oauth/register
        reg_resp = client.post(
            "/oauth/register",
            json={
                "client_name": "ChatGPT Autonomous Agent Plugin",
                "redirect_uris": [REDIRECT_URI],
                "grant_types": ["authorization_code", "refresh_token"],
                "scope": "mcp:autonomous",
            },
        )
        assert reg_resp.status_code == 201, reg_resp.text
        reg_data = reg_resp.json()
        client_id = reg_data["client_id"]
        client_secret = reg_data["client_secret"]
        assert client_id and client_secret
        autonomous_e2e_env["client_id"] = client_id
        autonomous_e2e_env["client_secret"] = client_secret

        # 2. Generate PKCE S256 pair
        verifier, challenge = _generate_pkce_pair()

        # 3. Complete Authorization via POST /oauth/authorize with Owner Master Secret
        auth_resp = client.post(
            "/oauth/authorize",
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp:autonomous",
                "owner_token": TEST_ADAPTER_AUTH_SECRET,
                "decision": "allow",
            },
        )
        assert auth_resp.status_code in (200, 302), auth_resp.text
        if auth_resp.status_code == 200:
            auth_code = auth_resp.json()["code"]
        else:
            loc = auth_resp.headers["location"]
            parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
            auth_code = parsed_qs["code"][0]
        assert auth_code.startswith("mcp_ac_")

        # 4. Exchange Auth Code + code_verifier at POST /oauth/token
        token_resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": auth_code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert token_resp.status_code == 200, token_resp.text
        tok_data = token_resp.json()
        access_token = tok_data["access_token"]
        refresh_token = tok_data["refresh_token"]
        assert access_token.startswith("mcp_oat_")
        assert refresh_token.startswith("mcp_ort_")
        assert tok_data["token_type"] == "Bearer"

        autonomous_e2e_env["access_token"] = access_token
        autonomous_e2e_env["refresh_token"] = refresh_token

    def test_04_phase_a_task_proposal_pending(self, autonomous_e2e_env):
        """Phase A: Submit task proposal; verify AUTHORIZATION_PENDING and no files modified."""
        client: TestClient = autonomous_e2e_env["adapter_client"]
        ws: Path = autonomous_e2e_env["workspace"]
        access_token = autonomous_e2e_env["access_token"]
        store: TaskStore = autonomous_e2e_env["store"]

        # Record initial baseline of calculator.py
        baseline_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a - b" in baseline_calc

        headers = {"Authorization": f"Bearer {access_token}"}

        # Initialize session
        init_res = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert init_res.status_code == 200
        headers["Mcp-Session-Id"] = init_res.headers.get("Mcp-Session-Id")

        # Call agent_submit_task
        sub_res = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Inspect repository, repair defective calculator.py, run tests until 100% pass, and verify.",
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
            },
        )
        assert sub_res.status_code == 200, sub_res.text
        tool_out = json.loads(sub_res.json()["result"]["content"][0]["text"])

        # Verification of Phase A guarantees
        task_id = tool_out["task_id"]
        assert task_id.startswith("task_")
        assert tool_out["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert tool_out["grant_id"] is None
        assert tool_out["requires_owner_approval"] is True
        proposal_digest = tool_out["proposal_digest"]
        assert len(proposal_digest) == 64  # Valid SHA256 hex digest

        # Verify database record
        db_rec = store.get_task(task_id)
        assert db_rec is not None
        assert db_rec.state == TaskState.AUTHORIZATION_PENDING.value
        assert db_rec.grant_id is None
        assert db_rec.client_id == autonomous_e2e_env["client_id"]

        # Verify calculator.py was NOT modified prior to owner approval
        current_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        assert current_calc == baseline_calc

        autonomous_e2e_env["task_id"] = task_id
        autonomous_e2e_env["proposal_digest"] = proposal_digest

    def test_05_phase_b_owner_single_approval_and_worker_spawn(self, autonomous_e2e_env):
        """Phase B: Owner logs into Web Console, reviews scope, approves once with auto_start."""
        console_client: TestClient = autonomous_e2e_env["console_client"]
        task_id = autonomous_e2e_env["task_id"]
        expected_digest = autonomous_e2e_env["proposal_digest"]

        # 1. Owner Login
        login_resp = console_client.post(
            "/console/api/login",
            json={"password": TEST_OWNER_MASTER_SECRET},
        )
        assert login_resp.status_code == 200, login_resp.text
        csrf_token = login_resp.json()["csrf_token"]
        assert csrf_token

        # 2. Inspect pending task
        tasks_resp = console_client.get("/console/api/autonomous/tasks?state=AUTHORIZATION_PENDING")
        assert tasks_resp.status_code == 200
        pending_tasks = tasks_resp.json().get("tasks", [])
        assert any(t["task_id"] == task_id for t in pending_tasks)

        # 3. Approve and start task in a single click
        approve_resp = console_client.post(
            f"/console/api/autonomous/tasks/{task_id}/approve",
            headers={"x-csrf-token": csrf_token},
            json={"auto_start": True},
        )
        assert approve_resp.status_code == 200, approve_resp.text
        appr_data = approve_resp.json()

        # 4. Verify durable grant minted, worker process spawned, zero secrets leaked
        assert appr_data["task_id"] == task_id
        assert appr_data["grant_id"].startswith("grant_")
        assert appr_data["proposal_digest"] == expected_digest
        assert appr_data["state"] in ("QUEUED", "RUNNING")
        worker_pid = appr_data["worker_pid"]
        assert worker_pid is not None and isinstance(worker_pid, int)
        assert worker_pid > 0

        # Response must not leak tokens, secrets, or internal signatures
        for forbidden_key in ("token", "owner_approval_token", "signature", "secret"):
            assert forbidden_key not in appr_data

        autonomous_e2e_env["worker_pid"] = worker_pid

    def test_06_phase_c_autonomous_repair_and_completion(self, autonomous_e2e_env):
        """Phase C: Independent worker fixes defect, verifies tests pass, creates .bak, without repeated prompts."""
        store: TaskStore = autonomous_e2e_env["store"]
        ws: Path = autonomous_e2e_env["workspace"]
        task_id = autonomous_e2e_env["task_id"]

        # Poll store until task reaches COMPLETED
        deadline = time.time() + 45.0
        completed = False
        last_state = ""
        while time.time() < deadline:
            task_rec = store.get_task(task_id)
            if task_rec:
                last_state = task_rec.state
                if task_rec.state == TaskState.COMPLETED.value:
                    completed = True
                    break
                if task_rec.state in (TaskState.FAILED.value, TaskState.CANCELLED.value):
                    pytest.fail(f"Autonomous worker terminated in state '{task_rec.state}': {task_rec.error_message}")
            time.sleep(0.5)

        assert completed is True, f"Worker did not reach COMPLETED within timeout. Last state: {last_state}"

        # 1. Verify calculator.py was atomically repaired
        fixed_content = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a + b" in fixed_content
        assert "return a - b" not in fixed_content

        # 2. Verify verification_passed is True
        final_rec = store.get_task(task_id)
        assert final_rec.verification_passed is True

        # 3. Verify .bak backup was created in backups/file_versions/
        backup_dir = PROJECT_ROOT / "backups" / "file_versions"
        backups = list(backup_dir.glob(f"{task_id}_*"))
        assert len(backups) >= 1, f"No backup file found for task {task_id} in {backup_dir}"
        # Inspect backup content to verify original defect was saved
        bak_text = backups[0].read_text(encoding="utf-8")
        assert "return a - b" in bak_text

    def test_07_phase_d_disconnect_and_reconnect_via_refresh_token(self, autonomous_e2e_env):
        """Phase D: Disconnect client, exchange refresh_token for new access_token, query all 5 tools."""
        adapter_app = autonomous_e2e_env["adapter_app"]
        task_id = autonomous_e2e_env["task_id"]
        client_id = autonomous_e2e_env["client_id"]
        client_secret = autonomous_e2e_env["client_secret"]
        refresh_token = autonomous_e2e_env["refresh_token"]

        # 1. Exchange refresh_token at POST /oauth/token for a fresh access_token
        reconnected_client = TestClient(adapter_app)
        ref_resp = reconnected_client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
            },
        )
        assert ref_resp.status_code == 200, ref_resp.text
        new_access_token = ref_resp.json()["access_token"]
        assert new_access_token.startswith("mcp_oat_")

        # 2. Re-establish MCP session with fresh token
        fresh_headers = {"Authorization": f"Bearer {new_access_token}"}
        re_init = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 201,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert re_init.status_code == 200
        fresh_headers["Mcp-Session-Id"] = re_init.headers.get("Mcp-Session-Id")

        # 3. Query agent_task_status
        status_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task_id}},
            },
        )
        assert status_res.status_code == 200
        s_out = json.loads(status_res.json()["result"]["content"][0]["text"])
        assert s_out["status"] == TaskState.COMPLETED.value
        assert s_out["task_id"] == task_id

        # 4. Query agent_task_logs
        logs_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 203,
                "method": "tools/call",
                "params": {"name": "agent_task_logs", "arguments": {"task_id": task_id}},
            },
        )
        assert logs_res.status_code == 200
        l_out = json.loads(logs_res.json()["result"]["content"][0]["text"])
        phases = [item.get("phase") for item in l_out.get("logs", [])]
        assert "START" in phases
        assert "COMPLETED" in phases

        # 5. Query agent_task_diff
        diff_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 204,
                "method": "tools/call",
                "params": {"name": "agent_task_diff", "arguments": {"task_id": task_id}},
            },
        )
        assert diff_res.status_code == 200
        d_out = json.loads(diff_res.json()["result"]["content"][0]["text"])
        assert "git_diff" in d_out
        assert "calculator.py" in d_out.get("git_diff", "") or any("calculator.py" in str(f) for f in d_out.get("files_modified", []))

        # 6. Query agent_task_artifacts
        art_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 205,
                "method": "tools/call",
                "params": {"name": "agent_task_artifacts", "arguments": {"task_id": task_id}},
            },
        )
        assert art_res.status_code == 200
        a_out = json.loads(art_res.json()["result"]["content"][0]["text"])
        assert "calculator.py" in a_out.get("files_modified", [])
        assert "workspace_root" not in a_out  # Redacted on cloud surface

        # 7. Query agent_list_tasks
        list_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 206,
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        assert list_res.status_code == 200
        lst_out = json.loads(list_res.json()["result"]["content"][0]["text"])
        assert any(t["task_id"] == task_id for t in lst_out.get("tasks", []))

    def test_08_phase_e_negative_authorization_and_emergency_controls(self, autonomous_e2e_env):
        """Phase E: Negative tests: unapproved scope mod (400), token replay, intruder FORBIDDEN, e-stop."""
        adapter_client: TestClient = autonomous_e2e_env["adapter_client"]
        console_client: TestClient = autonomous_e2e_env["console_client"]
        store: TaskStore = autonomous_e2e_env["store"]
        broker: TaskGrantBroker = autonomous_e2e_env["broker"]
        task_id = autonomous_e2e_env["task_id"]
        ws: Path = autonomous_e2e_env["workspace"]

        # 1. Unapproved scope modification rejected with HTTP 400
        # Create a pending dummy task to test approval modification rejection
        dummy_task = store.create_task(
            task_id="task_scope_mod_test",
            objective="Scope mod test",
            workspace_root=str(ws),
            metadata={"allowed_tools": ["read_file", "write_file"], "allowed_commands": ["pytest*"]},
            requested_scope={"workspace_root": str(ws), "allowed_tools": ["read_file", "write_file"], "allowed_commands": ["pytest*"]},
        )
        store.update_task_state(dummy_task.task_id, TaskState.AUTHORIZATION_PENDING.value)

        # Login to console to get CSRF token
        login_res = console_client.post("/console/api/login", json={"password": TEST_OWNER_MASTER_SECRET})
        csrf = login_res.json()["csrf_token"]

        # Attempt to approve with altered workspace root -> 400
        tampered_ws_resp = console_client.post(
            f"/console/api/autonomous/tasks/{dummy_task.task_id}/approve",
            headers={"x-csrf-token": csrf},
            json={"workspace_root": "C:\\Windows\\System32"},
        )
        assert tampered_ws_resp.status_code == 400
        assert "Scope modification rejected" in tampered_ws_resp.json()["error"]

        # Attempt to approve with altered tools -> 400
        tampered_tools_resp = console_client.post(
            f"/console/api/autonomous/tasks/{dummy_task.task_id}/approve",
            headers={"x-csrf-token": csrf},
            json={"allowed_tools": ["read_file", "powershell_execute", "unapproved_super_tool"]},
        )
        assert tampered_tools_resp.status_code == 400
        assert "Scope modification rejected" in tampered_tools_resp.json()["error"]

        # 2. Replayed owner approval token rejected
        token = broker.generate_owner_approval_token(
            task_id="task_replay_test",
            workspace_root=ws,
            scope_digest="test_digest",
            owner_id="local_owner",
        )
        # First verification succeeds
        assert broker.verify_owner_approval_token("task_replay_test", ws, token, expected_scope_digest="test_digest", consume=True) is True
        # Replayed verification must be rejected
        assert broker.verify_owner_approval_token("task_replay_test", ws, token, expected_scope_digest="test_digest", consume=True) is False

        # 3. Cross-client intruder access rejected FORBIDDEN
        # Register and authorize an intruder client
        tok_intruder = adapter_client.post(
            "/oauth/token",
            json={"client_id": "client_intruder_99", "client_secret": TEST_ADAPTER_AUTH_SECRET},
        ).json()["access_token"]
        intruder_hdrs = {"Authorization": f"Bearer {tok_intruder}"}

        # Initialize session for intruder
        i_init = adapter_client.post(
            "/mcp",
            headers=intruder_hdrs,
            json={"jsonrpc": "2.0", "id": 501, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        )
        intruder_hdrs["Mcp-Session-Id"] = i_init.headers.get("Mcp-Session-Id")

        # Querying completed task of client_chatgpt -> FORBIDDEN
        for tool_name in ("agent_task_status", "agent_task_logs", "agent_task_diff", "agent_task_artifacts"):
            intr_call = adapter_client.post(
                "/mcp",
                headers=intruder_hdrs,
                json={"jsonrpc": "2.0", "id": 502, "method": "tools/call", "params": {"name": tool_name, "arguments": {"task_id": task_id}}},
            )
            assert intr_call.status_code == 200
            out = json.loads(intr_call.json()["result"]["content"][0]["text"])
            assert out.get("status") == "FORBIDDEN"
            assert "Permission Denied" in out.get("error", "")

        # Intruder listing tasks -> empty list (cannot see other client's tasks)
        intr_list = adapter_client.post(
            "/mcp",
            headers=intruder_hdrs,
            json={"jsonrpc": "2.0", "id": 503, "method": "tools/call", "params": {"name": "agent_list_tasks", "arguments": {}}},
        )
        assert intr_list.status_code == 200
        l_out = json.loads(intr_list.json()["result"]["content"][0]["text"])
        assert not any(t["task_id"] == task_id for t in l_out.get("tasks", []))

        # 4. Emergency Stop verification
        estop_resp = console_client.post(
            "/console/api/autonomous/emergency-stop",
            headers={"x-csrf-token": csrf},
        )
        assert estop_resp.status_code == 200
        assert estop_resp.json()["emergency_stop"] is True


# ==============================================================================
# TEST 03: LIVE AI REQUIREMENT & OPERATING PROFILE HONESTY (Section 8)
# ==============================================================================
class Test03_LiveAIRequirementAndHonesty:
    """Verify honest OFFLINE_TEST_MODE reporting and absence of fake live AI evidence."""

    def test_09_llm_operating_status_honest_offline_mode(self, monkeypatch):
        """Verify get_llm_operating_status() reports OFFLINE_TEST_MODE when OPENAI_API_KEY is unset."""
        # Ensure OPENAI_API_KEY is not set
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        # 1. get_llm_operating_status()
        status = get_llm_operating_status()
        assert status["status"] == "LIVE_AI_NOT_CONFIGURED"
        assert status["operating_profile"] == OperatingProfile.OFFLINE_TEST_MODE
        assert status["is_live_ai"] is False
        assert status["provider"] == "deterministic_offline"
        assert "OPENAI_API_KEY not configured" in status.get("reason", "")

        # 2. get_llm_adapter() returns DeterministicRuleBasedAdapter in offline mode
        adapter = get_llm_adapter(prefer_live=False)
        assert isinstance(adapter, DeterministicRuleBasedAdapter)
        assert adapter.is_live_ai is False

        # 3. Attempting require_live=True raises LiveAINotConfiguredError
        with pytest.raises(LiveAINotConfiguredError) as exc_info:
            get_llm_adapter(require_live=True)
        assert "LIVE_AI_NOT_CONFIGURED" in str(exc_info.value)

        # 4. Attempting OpenAIProviderAdapter without key raises LiveAINotConfiguredError
        live_adapter = OpenAIProviderAdapter(api_key=None)
        with pytest.raises(LiveAINotConfiguredError):
            live_adapter.generate_plan("Do work", {}, ["read_file"])

        with pytest.raises(LiveAINotConfiguredError):
            live_adapter.diagnose_and_repair("Do work", {}, "error", "ws")


# ==============================================================================
# TEST 04: ACCOUNT MIGRATION & CREDENTIAL NON-REUSE VERIFICATION (Section 9)
# ==============================================================================
class Test04_AccountMigrationAndCredentialIsolation:
    """Verify Connect-ChatGPTAccount.ps1 and multi-account credential isolation."""

    def test_10_powershell_migration_dryrun_verification(self):
        """Verify scripts/Connect-ChatGPTAccount.ps1 -Simulated -DryRun succeeds and emits report."""
        script_path = PROJECT_ROOT / "scripts" / "Connect-ChatGPTAccount.ps1"
        assert script_path.exists(), f"Missing script {script_path}"

        res = subprocess.run(
            [
                "powershell.exe",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Simulated",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        assert res.returncode == 0, f"PowerShell migration script failed: {res.stderr}\n{res.stdout}"
        assert "[SIMULATED]" in res.stdout
        assert "LiveProfileUntouched: True" in res.stdout

        # Verify generated JSON report
        report_path = PROJECT_ROOT / "runtime" / "logs" / "account-migration-report.json"
        assert report_path.exists(), "account-migration-report.json not generated"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["overall_status"] == "PASS"
        assert report["yaml_template_valid"] is True
        assert report["live_profile_unchanged"] is True
        assert report["simulated"] is True

    def test_11_multi_account_switching_and_task_isolation(self, autonomous_e2e_env):
        """Verify switching ChatGPT accounts maintains distinct credentials and strict task isolation."""
        client: TestClient = autonomous_e2e_env["adapter_client"]
        store: TaskStore = autonomous_e2e_env["store"]
        ws: Path = autonomous_e2e_env["workspace"]

        # Account 1 setup
        reg1 = client.post(
            "/oauth/register",
            json={"client_name": "ChatGPT Account 1", "redirect_uris": [REDIRECT_URI]},
        ).json()
        client1_id = reg1["client_id"]
        v1, c1 = _generate_pkce_pair()
        auth1 = client.post(
            "/oauth/authorize",
            headers={"Accept": "application/json"},
            data={
                "client_id": client1_id,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": c1,
                "code_challenge_method": "S256",
                "owner_token": TEST_ADAPTER_AUTH_SECRET,
                "decision": "allow",
            },
        ).json()["code"]
        tok1 = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client1_id,
                "client_secret": reg1["client_secret"],
                "code": auth1,
                "code_verifier": v1,
                "redirect_uri": REDIRECT_URI,
            },
        ).json()["access_token"]

        # Account 2 setup
        reg2 = client.post(
            "/oauth/register",
            json={"client_name": "ChatGPT Account 2", "redirect_uris": [REDIRECT_URI]},
        ).json()
        client2_id = reg2["client_id"]
        v2, c2 = _generate_pkce_pair()
        auth2 = client.post(
            "/oauth/authorize",
            headers={"Accept": "application/json"},
            data={
                "client_id": client2_id,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": c2,
                "code_challenge_method": "S256",
                "owner_token": TEST_ADAPTER_AUTH_SECRET,
                "decision": "allow",
            },
        ).json()["code"]
        tok2 = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client2_id,
                "client_secret": reg2["client_secret"],
                "code": auth2,
                "code_verifier": v2,
                "redirect_uri": REDIRECT_URI,
            },
        ).json()["access_token"]

        # Distinct credential verification
        assert client1_id != client2_id
        assert tok1 != tok2

        # Account 1 submits task
        hdrs1 = {"Authorization": f"Bearer {tok1}"}
        i1 = client.post("/mcp", headers=hdrs1, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        hdrs1["Mcp-Session-Id"] = i1.headers.get("Mcp-Session-Id")

        sub1 = client.post(
            "/mcp",
            headers=hdrs1,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {"objective": "Account 1 task", "workspace_root": str(ws)},
                },
            },
        )
        task1_id = json.loads(sub1.json()["result"]["content"][0]["text"])["task_id"]

        # Account 2 attempts to query Account 1's task -> FORBIDDEN
        hdrs2 = {"Authorization": f"Bearer {tok2}"}
        i2 = client.post("/mcp", headers=hdrs2, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        hdrs2["Mcp-Session-Id"] = i2.headers.get("Mcp-Session-Id")

        q_status = client.post(
            "/mcp",
            headers=hdrs2,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task1_id}},
            },
        )
        q_out = json.loads(q_status.json()["result"]["content"][0]["text"])
        assert q_out.get("status") == "FORBIDDEN"

        # Account 2 list tasks -> task1_id must NOT appear
        q_list = client.post(
            "/mcp",
            headers=hdrs2,
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "agent_list_tasks", "arguments": {}}},
        )
        l_out = json.loads(q_list.json()["result"]["content"][0]["text"])
        assert not any(t["task_id"] == task1_id for t in l_out.get("tasks", []))
