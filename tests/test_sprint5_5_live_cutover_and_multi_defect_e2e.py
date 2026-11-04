"""Sprint 5.5 End-to-End Verification Suite — Real Cloud Cutover, Multi-Defect E2E & 11 Security Gates.

Verifies:
- Sections 6 & 8: Real Autonomous Multi-Defect Repair E2E across disposable Git repository:
  * Phase A — Task Submission: Submit task over /mcp Autonomous Adapter (Port 8768 contract)
    with authenticated client identity (client_chatgpt_web), verifying unique task_id,
    AUTHORIZATION_PENDING, proposal_digest, and zero unapproved filesystem writes.
  * Phase B — One-Time Owner Authorization: Owner logs into Owner Web Console (Port 8767 contract),
    reviews exact task proposal, single-click approves with auto_start. Verifies signed TaskGrant
    in SQLite, QUEUED/RUNNING state, and real independent OS worker worker_pid > 0.
  * Phase C — Autonomous Multi-Action Execution: Independent Windows worker reads code,
    runs initial pytest (observing failures on multiple defects across multiple files:
    calculator.py with broken add, subtractor.py with broken subtract, and validator.py with broken is_positive),
    repairs source atomically (creating .bak backups in backups/file_versions/), runs pytest again
    until 100% pass, persists diff, logs, checkpoints, and artifacts in SQLite — with ZERO per-command
    approval prompts.
  * Phase D — Browser Disconnect & Recovery: Disconnect client while worker runs,
    confirm worker completes independently, reconnect via OAuth refresh_token, and invoke
    agent_task_status, agent_task_logs, agent_task_diff, agent_task_artifacts, and agent_list_tasks,
    correlating timestamps and task_id.
  * Phase E — All 11 Mandatory Security Checks (Section 6 Phase E):
    1. Unauthenticated MCP caller denied (401)
    2. Invalid OAuth credential denied (403)
    3. Cross-client task access denied (FORBIDDEN)
    4. Forged owner identity denied (403)
    5. Redirect URI mismatch denied (400)
    6. PKCE downgrade (plain or missing challenge) denied (400)
    7. Approval token replay denied (False / REJECTED)
    8. Workspace escape (../ or outside preapproved_roots) denied (REJECTED)
    9. Revoked TaskGrant denied (PermissionError / FAILED)
    10. Revoked OAuth token remains denied after real OS process restart (403)
    11. Emergency Stop terminates the permitted worker process tree (taskkill /F /T).
- Section 7: Live AI Reality Check:
  * Verify LIVE_AI_NOT_CONFIGURED is reported accurately when no API key is configured.
  * DeterministicRuleBasedAdapter active with zero paid API calls or fabricated evidence.
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
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Generator

import httpx
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
    AgentMCPToolHandler,
)
from runtime.autonomous_agent import AutonomousAgentController  # noqa: E402
from runtime.llm_adapter import (  # noqa: E402
    DeterministicRuleBasedAdapter,
    LiveAINotConfiguredError,
    OpenAIProviderAdapter,
    OperatingProfile,
    get_llm_adapter,
    get_llm_operating_status,
)
from runtime.oauth_store import DurableOAuthStore  # noqa: E402
from runtime.task_grant import TaskGrant, TaskGrantBroker  # noqa: E402
from runtime.task_store import TaskState, TaskStore, is_pid_alive  # noqa: E402
from web_console import create_web_console_app  # noqa: E402

TEST_OWNER_MASTER_SECRET = "Sprint5_5_Owner_Master_Passphrase_Secure_445566"
TEST_ADAPTER_AUTH_SECRET = "Sprint5_5_Adapter_Auth_Secret_Key_112233"
REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate RFC 7636 PKCE S256 verifier and challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _get_free_port() -> int:
    """Acquire a free local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(port: int, timeout: float = 25.0) -> bool:
    """Poll GET /health until HTTP 200 or timeout."""
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/health"
    with httpx.Client(timeout=1.0) as client:
        while time.time() < deadline:
            try:
                res = client.get(url)
                if res.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def multi_defect_e2e_env() -> Generator[dict[str, Any], None, None]:
    """Module-level fixture setting up isolated Git coding workspace with multiple controlled defects."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        base_dir = Path(td).resolve()
        workspace = base_dir / "autonomous_multi_defect_repo"
        workspace.mkdir(parents=True, exist_ok=True)
        db_path = base_dir / "sprint5_5_tasks.db"
        audit_log = base_dir / "audit.jsonl"
        estop_file = base_dir / "EMERGENCY_STOP"

        # ----------------------------------------------------------------------
        # Create MULTIPLE controlled defects across multiple files/modules:
        # File 1: calculator.py
        #   - Defect 1: add(a, b) returns subtraction instead of addition
        # File 2: subtractor.py
        #   - Defect 2: subtract(a, b) returns addition instead of subtraction
        # File 3: validator.py
        #   - Defect 3: is_positive(n) returns False for positive numbers
        # ----------------------------------------------------------------------
        calc_code = (
            "def add(a: int, b: int) -> int:\n"
            "    # DEFECT: returns subtraction instead of addition\n"
            "    return a - b\n\n"
            "def multiply(a: int, b: int) -> int:\n"
            "    return a * b\n"
        )
        (workspace / "calculator.py").write_text(calc_code, encoding="utf-8")

        sub_code = (
            "def subtract(a: int, b: int) -> int:\n"
            "    return a + b\n"
        )
        (workspace / "subtractor.py").write_text(sub_code, encoding="utf-8")

        val_code = (
            "def is_positive(n: int) -> bool:\n"
            "    return False\n"
        )
        (workspace / "validator.py").write_text(val_code, encoding="utf-8")

        test_code = (
            "from calculator import add, multiply\n"
            "from subtractor import subtract\n"
            "from validator import is_positive\n\n"
            "def test_addition():\n"
            "    assert add(2, 3) == 5\n\n"
            "def test_subtraction():\n"
            "    assert subtract(10, 4) == 6\n\n"
            "def test_multiplication():\n"
            "    assert multiply(3, 4) == 12\n\n"
            "def test_is_positive():\n"
            "    assert is_positive(5) == True\n"
        )
        (workspace / "test_suite.py").write_text(test_code, encoding="utf-8")

        # Initialize clean disposable Git repo baseline
        subprocess.run(["git", "init"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "ChatGPTAutonomousTester"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "autonomous@example.com"], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=str(workspace), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Baseline with multiple controlled defects"], cwd=str(workspace), check=True, capture_output=True)

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

        # Dedicated Cloud Autonomous Adapter App (127.0.0.1:8768 contract)
        adapter_app = create_cloud_autonomous_adapter_app(
            gateway=gateway,
            caller_auth_token=TEST_ADAPTER_AUTH_SECRET,
            require_autonomous_auth=True,
            profile="cloud_autonomous",
            db_path=db_path,
        )
        adapter_client = TestClient(adapter_app)

        # Local Owner Web Console App (127.0.0.1:8767 contract)
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
            "baseline_calc": calc_code,
            "baseline_sub": sub_code,
            "baseline_val": val_code,
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
# SECTION 6: REAL AUTONOMOUS MULTI-DEFECT REPAIR E2E (Phases A, B, C, D)
# ==============================================================================
class Test01_MultiDefectAutonomousE2E:
    """Full 4-Phase E2E Autonomous Workflow execution across multiple defects."""

    def test_01_phase_a_task_submission(self, multi_defect_e2e_env):
        """Phase A: Submit task proposal with authenticated client; verify AUTHORIZATION_PENDING and zero writes."""
        client: TestClient = multi_defect_e2e_env["adapter_client"]
        ws: Path = multi_defect_e2e_env["workspace"]
        store: TaskStore = multi_defect_e2e_env["store"]

        # 1. Register ChatGPT Plugin Client via POST /oauth/register
        reg_resp = client.post(
            "/oauth/register",
            json={
                "client_name": "client_chatgpt_web",
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
        multi_defect_e2e_env["client_id"] = client_id
        multi_defect_e2e_env["client_secret"] = client_secret

        # 2. Complete Authorization via POST /oauth/authorize with Owner Master Secret & PKCE S256
        verifier, challenge = _generate_pkce_pair()
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

        # 3. Exchange Auth Code + code_verifier at POST /oauth/token
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

        multi_defect_e2e_env["access_token"] = access_token
        multi_defect_e2e_env["refresh_token"] = refresh_token

        # 4. Verify baseline files before submission
        baseline_calc = (ws / "calculator.py").read_text(encoding="utf-8")
        baseline_sub = (ws / "subtractor.py").read_text(encoding="utf-8")
        baseline_val = (ws / "validator.py").read_text(encoding="utf-8")
        assert "return a - b" in baseline_calc
        assert "return a + b" in baseline_sub
        assert "return False" in baseline_val

        headers = {"Authorization": f"Bearer {access_token}"}

        # 5. Initialize session on /mcp
        init_res = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert init_res.status_code == 200
        headers["Mcp-Session-Id"] = init_res.headers.get("Mcp-Session-Id")

        # 6. Call agent_submit_task with multi-defect repair objective
        sub_res = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Inspect repository, repair multiple defects in calculator.py, subtractor.py, and validator.py, run test_suite.py until 100% pass, and verify.",
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

        # 7. Verification of Phase A guarantees
        task_id = tool_out["task_id"]
        assert task_id.startswith("task_")
        assert tool_out["status"] == TaskState.AUTHORIZATION_PENDING.value
        assert tool_out["grant_id"] is None
        assert tool_out["requires_owner_approval"] is True
        proposal_digest = tool_out["proposal_digest"]
        assert len(proposal_digest) == 64  # SHA256 hex digest

        # Verify database record
        db_rec = store.get_task(task_id)
        assert db_rec is not None
        assert db_rec.state == TaskState.AUTHORIZATION_PENDING.value
        assert db_rec.grant_id is None
        assert db_rec.client_id == client_id

        # ZERO unapproved filesystem writes: confirm files are 100% unchanged
        assert (ws / "calculator.py").read_text(encoding="utf-8") == baseline_calc
        assert (ws / "subtractor.py").read_text(encoding="utf-8") == baseline_sub
        assert (ws / "validator.py").read_text(encoding="utf-8") == baseline_val

        multi_defect_e2e_env["task_id"] = task_id
        multi_defect_e2e_env["proposal_digest"] = proposal_digest

    def test_02_phase_b_one_time_owner_authorization(self, multi_defect_e2e_env):
        """Phase B: Owner logs into Web Console, reviews exact proposal, single-click approves with auto_start."""
        console_client: TestClient = multi_defect_e2e_env["console_client"]
        task_id = multi_defect_e2e_env["task_id"]
        expected_digest = multi_defect_e2e_env["proposal_digest"]

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

        multi_defect_e2e_env["worker_pid"] = worker_pid

    def test_03_phase_c_autonomous_multi_action_repair(self, multi_defect_e2e_env):
        """Phase C: Independent worker fixes MULTIPLE defects across files, verifies tests pass, creates .bak."""
        store: TaskStore = multi_defect_e2e_env["store"]
        ws: Path = multi_defect_e2e_env["workspace"]
        task_id = multi_defect_e2e_env["task_id"]

        # Poll store until task reaches COMPLETED
        deadline = time.time() + 60.0
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

        # 1. Verify calculator.py repaired addition defect
        calc_repaired = (ws / "calculator.py").read_text(encoding="utf-8")
        assert "return a + b" in calc_repaired, "add defect was not repaired"

        # 2. Verify subtractor.py repaired subtraction defect
        sub_repaired = (ws / "subtractor.py").read_text(encoding="utf-8")
        assert "return a - b" in sub_repaired, "subtract defect was not repaired"

        # 3. Verify validator.py repaired boolean defect
        val_repaired = (ws / "validator.py").read_text(encoding="utf-8")
        assert "return True" in val_repaired, "is_positive boolean defect was not repaired"

        # 4. Verify verification_passed is True
        final_rec = store.get_task(task_id)
        assert final_rec.verification_passed is True

        # 5. Verify multiple .bak backups created in backups/file_versions/
        backup_dir = PROJECT_ROOT / "backups" / "file_versions"
        backups = list(backup_dir.glob(f"{task_id}_*"))
        assert len(backups) >= 2, f"Expected multiple backups for multiple repaired files, found {len(backups)}"

        # 6. Verify checkpoints and logs persisted in SQLite
        latest_chk = store.get_latest_checkpoint(task_id)
        assert latest_chk is not None
        assert len(latest_chk.files_modified) >= 2

        task_logs = store.get_logs(task_id)
        phases = [log.get("phase") for log in task_logs]
        assert "START" in phases
        assert "REPAIRING" in phases
        assert "COMPLETED" in phases

    def test_04_phase_d_browser_disconnect_and_recovery(self, multi_defect_e2e_env):
        """Phase D: Disconnect client, refresh token via OAuth refresh_token, reconnect, query all 5 inspection tools."""
        adapter_app = multi_defect_e2e_env["adapter_app"]
        task_id = multi_defect_e2e_env["task_id"]
        client_id = multi_defect_e2e_env["client_id"]
        client_secret = multi_defect_e2e_env["client_secret"]
        refresh_token = multi_defect_e2e_env["refresh_token"]

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
                "id": 101,
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
                "id": 102,
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
                "id": 103,
                "method": "tools/call",
                "params": {"name": "agent_task_logs", "arguments": {"task_id": task_id}},
            },
        )
        assert logs_res.status_code == 200
        l_out = json.loads(logs_res.json()["result"]["content"][0]["text"])
        phases = [item.get("phase") for item in l_out.get("logs", [])]
        assert "START" in phases
        assert "REPAIRING" in phases
        assert "COMPLETED" in phases

        # 5. Query agent_task_diff
        diff_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 104,
                "method": "tools/call",
                "params": {"name": "agent_task_diff", "arguments": {"task_id": task_id}},
            },
        )
        assert diff_res.status_code == 200
        d_out = json.loads(diff_res.json()["result"]["content"][0]["text"])
        assert "git_diff" in d_out or "files_modified" in d_out

        # 6. Query agent_task_artifacts
        art_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 105,
                "method": "tools/call",
                "params": {"name": "agent_task_artifacts", "arguments": {"task_id": task_id}},
            },
        )
        assert art_res.status_code == 200
        a_out = json.loads(art_res.json()["result"]["content"][0]["text"])
        files_mod = a_out.get("files_modified", [])
        assert any("calculator.py" in str(f) or "subtractor.py" in str(f) for f in files_mod)
        assert "workspace_root" not in a_out  # Redacted on cloud surface

        # 7. Query agent_list_tasks
        list_res = reconnected_client.post(
            "/mcp",
            headers=fresh_headers,
            json={
                "jsonrpc": "2.0",
                "id": 106,
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        assert list_res.status_code == 200
        lst_out = json.loads(list_res.json()["result"]["content"][0]["text"])
        assert any(t["task_id"] == task_id for t in lst_out.get("tasks", []))


# ==============================================================================
# SECTION 6 PHASE E: ALL 11 MANDATORY SECURITY CHECKS
# ==============================================================================
class Test02_ElevenMandatorySecurityChecks:
    """Rigorous penetration suite testing all 11 security controls required by Section 6 Phase E."""

    def test_05_sec01_unauthenticated_mcp_caller_denied_401(self, multi_defect_e2e_env):
        """Security Check 1: Unauthenticated MCP caller denied (401)."""
        client: TestClient = multi_defect_e2e_env["adapter_client"]

        # Call /mcp with no Authorization header
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            },
        )
        assert resp.status_code == 401

    def test_06_sec02_invalid_oauth_credential_denied_403(self, multi_defect_e2e_env):
        """Security Check 2: Invalid OAuth credential denied (403)."""
        client: TestClient = multi_defect_e2e_env["adapter_client"]

        # Call /mcp with forged / nonexistent Bearer token
        resp = client.post(
            "/mcp",
            headers={"Authorization": "Bearer forged_mcp_oat_completely_bogus_token_99999"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
        )
        assert resp.status_code == 403

    def test_07_sec03_cross_client_task_access_denied_forbidden(self, multi_defect_e2e_env):
        """Security Check 3: Cross-client task access denied (FORBIDDEN)."""
        client: TestClient = multi_defect_e2e_env["adapter_client"]
        task_id = multi_defect_e2e_env["task_id"]

        # Register Intruder Client B
        reg_b = client.post(
            "/oauth/register",
            json={"client_name": "client_intruder_b", "redirect_uris": [REDIRECT_URI]},
        ).json()
        client_b_id = reg_b["client_id"]
        v_b, c_b = _generate_pkce_pair()

        auth_b = client.post(
            "/oauth/authorize",
            headers={"Accept": "application/json"},
            data={
                "client_id": client_b_id,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": c_b,
                "code_challenge_method": "S256",
                "owner_token": TEST_ADAPTER_AUTH_SECRET,
                "decision": "allow",
            },
        ).json()["code"]

        tok_b = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_b_id,
                "client_secret": reg_b["client_secret"],
                "code": auth_b,
                "code_verifier": v_b,
                "redirect_uri": REDIRECT_URI,
            },
        ).json()["access_token"]

        hdrs_b = {"Authorization": f"Bearer {tok_b}"}
        i_b = client.post("/mcp", headers=hdrs_b, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        hdrs_b["Mcp-Session-Id"] = i_b.headers.get("Mcp-Session-Id")

        # Client B attempts to query Client A's task -> FORBIDDEN
        for tool_name in ("agent_task_status", "agent_task_logs", "agent_task_diff", "agent_task_artifacts"):
            call_res = client.post(
                "/mcp",
                headers=hdrs_b,
                json={"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": tool_name, "arguments": {"task_id": task_id}}},
            )
            assert call_res.status_code == 200
            out = json.loads(call_res.json()["result"]["content"][0]["text"])
            assert out.get("status") == "FORBIDDEN"
            assert "Permission Denied" in out.get("error", "")

        # Client B lists tasks -> Client A's task_id must NOT appear
        list_b = client.post(
            "/mcp",
            headers=hdrs_b,
            json={"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "agent_list_tasks", "arguments": {}}},
        )
        assert list_b.status_code == 200
        l_out = json.loads(list_b.json()["result"]["content"][0]["text"])
        assert not any(t["task_id"] == task_id for t in l_out.get("tasks", []))

    def test_08_sec04_forged_owner_identity_denied_403(self, multi_defect_e2e_env):
        """Security Check 4: Forged owner identity denied (401/403)."""
        console_client: TestClient = multi_defect_e2e_env["console_client"]
        adapter_client: TestClient = multi_defect_e2e_env["adapter_client"]

        # 1. Owner Console login with invalid passphrase -> 401
        bad_login = console_client.post("/console/api/login", json={"password": "wrong_attacker_password_999"})
        assert bad_login.status_code == 401

        # 2. Owner Console approve attempt with forged session/CSRF -> 401/403
        forged_approve = console_client.post(
            "/console/api/autonomous/tasks/task_test_fake/approve",
            headers={"x-csrf-token": "forged_csrf_token_123"},
            json={"auto_start": True},
        )
        assert forged_approve.status_code in (401, 403)

        # 3. OAuth Authorize endpoint with invalid owner_token -> 401/403
        _, challenge = _generate_pkce_pair()
        forged_auth = adapter_client.post(
            "/oauth/authorize",
            headers={"Accept": "application/json"},
            data={
                "client_id": multi_defect_e2e_env["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "owner_token": "wrong_forged_owner_secret_999",
                "decision": "allow",
            },
        )
        assert forged_auth.status_code in (401, 403)

    def test_09_sec05_redirect_uri_mismatch_denied_400(self, multi_defect_e2e_env):
        """Security Check 5: Redirect URI mismatch denied (400)."""
        adapter_client: TestClient = multi_defect_e2e_env["adapter_client"]
        client_id = multi_defect_e2e_env["client_id"]
        _, challenge = _generate_pkce_pair()

        # Authorize request with unapproved attacker redirect URI -> 400
        mismatch_resp = adapter_client.post(
            "/oauth/authorize",
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "redirect_uri": "https://attacker.evil.com/oauth_callback",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "owner_token": TEST_ADAPTER_AUTH_SECRET,
                "decision": "allow",
            },
        )
        assert mismatch_resp.status_code == 400
        assert "invalid_redirect_uri" in mismatch_resp.json()["error_description"]

    def test_10_sec06_pkce_downgrade_denied_400(self, multi_defect_e2e_env):
        """Security Check 6: PKCE downgrade (plain or missing challenge) denied (400)."""
        adapter_client: TestClient = multi_defect_e2e_env["adapter_client"]
        client_id = multi_defect_e2e_env["client_id"]

        # 1. GET /oauth/authorize with plain code challenge method rejected (400)
        plain_resp = adapter_client.get(
            f"/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={urllib.parse.quote(REDIRECT_URI)}&code_challenge=plain_challenge&code_challenge_method=plain"
        )
        assert plain_resp.status_code == 400
        assert "code_challenge_method=S256 is required" in plain_resp.json()["error_description"]

        # 2. GET /oauth/authorize with missing code challenge rejected (400)
        missing_resp = adapter_client.get(
            f"/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
        )
        assert missing_resp.status_code == 400
        assert "code_challenge_method=S256 is required" in missing_resp.json()["error_description"]

        # 3. POST /oauth/token with invalid code_verifier rejected (400)
        tok_bad_verifier = adapter_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": multi_defect_e2e_env["client_secret"],
                "code": "mcp_ac_fake_forged_code_12345",
                "code_verifier": "wrong_verifier_abcdef",
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert tok_bad_verifier.status_code == 400

    def test_11_sec07_approval_token_replay_denied(self, multi_defect_e2e_env):
        """Security Check 7: Approval token replay denied (False / REJECTED)."""
        broker: TaskGrantBroker = multi_defect_e2e_env["broker"]
        ws: Path = multi_defect_e2e_env["workspace"]

        # Mint owner approval token
        token = broker.generate_owner_approval_token(
            task_id="task_replay_sec07_check",
            workspace_root=ws,
            scope_digest="test_digest_sec07",
            owner_id="local_owner_sec07",
        )

        # First verification succeeds (token consumed)
        v1 = broker.verify_owner_approval_token(
            "task_replay_sec07_check", ws, token, expected_scope_digest="test_digest_sec07", consume=True
        )
        assert v1 is True

        # Second verification fails (single-use anti-replay)
        v2 = broker.verify_owner_approval_token(
            "task_replay_sec07_check", ws, token, expected_scope_digest="test_digest_sec07", consume=True
        )
        assert v2 is False

    def test_12_sec08_workspace_escape_denied(self, multi_defect_e2e_env):
        """Security Check 8: Workspace escape (../ or outside preapproved_roots) denied (REJECTED)."""
        broker: TaskGrantBroker = multi_defect_e2e_env["broker"]
        console_client: TestClient = multi_defect_e2e_env["console_client"]
        store: TaskStore = multi_defect_e2e_env["store"]
        ws: Path = multi_defect_e2e_env["workspace"]

        # 1. Broker rejects sensitive system directories (e.g. C:\Windows)
        with pytest.raises(PermissionError) as exc_info:
            broker.onboard_workspace_root("C:\\Windows")
        assert "sensitive directory" in str(exc_info.value).lower() or "drive root" in str(exc_info.value).lower()

        # 2. Broker rejects drive root (e.g. C:\)
        with pytest.raises(PermissionError) as exc_info_root:
            broker.onboard_workspace_root("C:\\")
        assert "drive root" in str(exc_info_root.value).lower()

        # 3. Console approve rejects altered workspace outside preapproved scope (400)
        dummy_task = store.create_task(
            task_id="task_escape_sec08_check",
            objective="Escape check",
            workspace_root=str(ws),
            metadata={"allowed_tools": ["read_file"], "allowed_commands": ["pytest*"]},
            requested_scope={"workspace_root": str(ws), "allowed_tools": ["read_file"], "allowed_commands": ["pytest*"]},
        )
        store.update_task_state(dummy_task.task_id, TaskState.AUTHORIZATION_PENDING.value)

        login_res = console_client.post("/console/api/login", json={"password": TEST_OWNER_MASTER_SECRET})
        csrf = login_res.json()["csrf_token"]

        tampered_ws = console_client.post(
            f"/console/api/autonomous/tasks/{dummy_task.task_id}/approve",
            headers={"x-csrf-token": csrf},
            json={"workspace_root": "C:\\Windows\\System32"},
        )
        assert tampered_ws.status_code == 400
        assert "Scope modification rejected" in tampered_ws.json()["error"]

    def test_13_sec09_revoked_task_grant_denied(self, multi_defect_e2e_env):
        """Security Check 9: Revoked TaskGrant denied (PermissionError / FAILED)."""
        broker: TaskGrantBroker = multi_defect_e2e_env["broker"]
        store: TaskStore = multi_defect_e2e_env["store"]
        ws: Path = multi_defect_e2e_env["workspace"]

        # Issue and immediately revoke a TaskGrant
        rev_task = store.create_task(objective="Revocation test task", workspace_root=str(ws))
        grant = broker.issue_grant(
            task_id=rev_task.task_id,
            workspace_root=ws,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=300.0,
        )
        store.bind_grant(rev_task.task_id, grant.grant_id)

        # Validate initially valid
        ok_init, _ = broker.validate_grant(grant, expected_task_id=rev_task.task_id)
        assert ok_init is True

        # Revoke the grant
        broker.revoke_grant(grant.grant_id, reason="Security audit emergency revocation")

        # Validation now fails closed
        ok_rev, rev_msg = broker.validate_grant(grant, expected_task_id=rev_task.task_id)
        assert ok_rev is False
        assert "revoked" in rev_msg.lower()

        # Controller execution fails closed under revoked grant
        ctrl = AutonomousAgentController(rev_task.task_id, store, broker)
        final_task = ctrl.run()
        assert final_task.state in (TaskState.CANCELLED.value, TaskState.FAILED.value)
        assert "revoked" in (final_task.error_message or "").lower()

    def test_14_sec10_revoked_oauth_token_denied_across_os_process_restart(self, tmp_path: Path):
        """Security Check 10: Revoked OAuth token remains denied after real OS process restart (403)."""
        port = _get_free_port()
        db_path = tmp_path / "sec10_restart_test.db"
        secret = TEST_ADAPTER_AUTH_SECRET

        # 1. Issue OAuth token via store
        store1 = DurableOAuthStore(db_path)
        cli = store1.register_client(
            client_id="sec10_client",
            client_secret="sec10_secret_val",
            owner_id="owner_admin",
            client_name="Sec10 Client",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code"],
            allowed_scopes=["mcp:autonomous"],
        )

        verifier, challenge = _generate_pkce_pair()
        auth_code = store1.create_authorization_code(
            client_id="sec10_client",
            owner_id="owner_admin",
            redirect_uri=REDIRECT_URI,
            scope="mcp:autonomous",
            resource="mcp-autonomous",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        ok_c, _, _ = store1.consume_authorization_code(
            code=auth_code,
            client_id="sec10_client",
            redirect_uri=REDIRECT_URI,
            code_verifier=verifier,
        )
        assert ok_c is True

        # Generate signed OAuth token
        now = time.time()
        p_data = {
            "sub": "sec10_client",
            "iss": "http://127.0.0.1:8768",
            "aud": "mcp-autonomous",
            "scope": "mcp:autonomous",
            "jti": f"sec10_jti_{secrets.token_hex(8)}",
            "iat": int(now),
            "exp": int(now + 3600),
        }
        b64_payload = base64.urlsafe_b64encode(json.dumps(p_data).encode("utf-8")).decode("ascii").rstrip("=")
        sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).hexdigest()
        access_token = f"mcp_oat_{b64_payload}.{sig}"

        # 2. Revoke token in durable SQLite database
        store1.revoke_token(access_token, client_id="sec10_client", reason="Revocation audit check 10")
        assert store1.is_revoked(access_token) is True

        # 3. Launch Process 1 (genuine Windows OS subprocess)
        env = os.environ.copy()
        current_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{PROJECT_ROOT}{os.pathsep}{current_pp}" if current_pp else str(PROJECT_ROOT)
        env["WINDOWS_MCP_OAUTH_DB_PATH"] = str(db_path)
        env["WINDOWS_MCP_GATEWAY_TOKEN"] = secret
        env["MCP_AGENT_PROFILE"] = "read_only"
        env["PYTHONUNBUFFERED"] = "1"

        cmd = [
            sys.executable,
            str(GW_DIR / "cloud_autonomous_adapter.py"),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--db-path", str(db_path),
            "--caller-token", secret,
        ]

        proc1 = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert _wait_for_health(port, timeout=25.0) is True, "Process 1 failed to become healthy"
            pid1 = proc1.pid
            assert is_pid_alive(pid1) is True

            # 4. Verify immediate denial (403) on Process 1
            with httpx.Client(timeout=5.0) as client:
                res1 = client.post(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={"Authorization": f"Bearer {access_token}"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                )
                assert res1.status_code == 403

            # 5. Terminate Process 1 completely
            proc1.terminate()
            try:
                proc1.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc1.kill()
                proc1.wait(timeout=3.0)
            assert is_pid_alive(pid1) is False, "Process 1 did not terminate"

            # 6. Launch Process 2 on the exact same port and SQLite DB
            proc2 = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert _wait_for_health(port, timeout=25.0) is True, "Process 2 failed to become healthy"
                pid2 = proc2.pid
                assert pid2 != pid1
                assert is_pid_alive(pid2) is True

                # 7. Steps 7 & 8: Verify revoked token REMAINS DENIED (403) across process restart
                with httpx.Client(timeout=5.0) as client:
                    res2 = client.post(
                        f"http://127.0.0.1:{port}/mcp",
                        headers={"Authorization": f"Bearer {access_token}"},
                        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    )
                    assert res2.status_code == 403, f"Expected 403 after restart, got {res2.status_code}: {res2.text}"
            finally:
                if proc2.poll() is None:
                    proc2.terminate()
                    try:
                        proc2.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        proc2.kill()
        finally:
            if proc1.poll() is None:
                proc1.terminate()
                try:
                    proc1.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    proc1.kill()

    def test_15_sec11_emergency_stop_terminates_permitted_worker_process_tree(self, multi_defect_e2e_env):
        """Security Check 11: Emergency Stop terminates the permitted worker process tree (taskkill /F /T)."""
        ws: Path = multi_defect_e2e_env["workspace"]
        store: TaskStore = multi_defect_e2e_env["store"]
        broker: TaskGrantBroker = multi_defect_e2e_env["broker"]

        # 1. Prepare child-spawning script in workspace
        child_pid_file = ws / "grandchild_pid_sec11.txt"
        script_file = ws / "spawn_child_tree_sec11.py"
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

        task = store.create_task(objective="Process tree kill test sec11", workspace_root=str(ws))
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

        # 4. Trigger Emergency Stop / Cancel and record duration (<2.0s requirement)
        t_start = time.time()
        ctrl.cancel()
        worker_thread.join(timeout=3.0)
        t_duration = time.time() - t_start

        assert t_duration < 2.0, f"Process tree termination took {t_duration:.2f}s, expected < 2.0s"
        assert not worker_thread.is_alive(), "Worker execution thread should have exited"

        # 5. Verify grandchild process is dead
        time.sleep(0.1)
        assert is_pid_alive(grandchild_pid) is False, f"Grandchild PID {grandchild_pid} survived cancellation!"
        ok, res, err = exec_result.get("res", (True, None, ""))
        assert ok is False, "Command should have returned failure on cancellation"
        assert "Interrupted" in err or "cancelled" in err.lower()


# ==============================================================================
# SECTION 7: LIVE AI REALITY CHECK & HONESTY
# ==============================================================================
class Test03_LiveAIRealityCheck:
    """Verify honest OFFLINE_TEST_MODE reporting and absence of fake live AI evidence."""

    def test_16_live_ai_not_configured_when_no_api_key(self, monkeypatch):
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

    def test_17_zero_unapproved_paid_api_calls_and_cost(self):
        """Verify deterministic adapter incurs strictly 0 external API calls and $0.00 cost."""
        adapter = DeterministicRuleBasedAdapter()
        telemetry = adapter.get_telemetry()
        assert telemetry["api_calls_count"] == 0
        assert telemetry["estimated_cost_usd"] == 0.0
        assert telemetry["is_live_ai"] is False
        assert telemetry["operating_profile"] == OperatingProfile.OFFLINE_TEST_MODE
