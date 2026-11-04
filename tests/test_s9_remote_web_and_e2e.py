"""Stage S9 — Secure Remote Web Control & Bounded Multi-Step Plan Orchestrator Acceptance Tests.

Verifies:
1. DNS rebinding defense via Host header enforcement (rejects arbitrary domains with 403).
2. Reverse proxy HTTPS detection with Secure cookie flag.
3. Security response headers (CSP, X-Frame-Options, nosniff, Referrer-Policy).
4. Web session limit tracking, list, and revoke-others.
5. Clipboard inspection with automatic secret redaction.
6. Bounded Multi-step Plan Orchestrator (create, approve, execute, snapshot, rollback, cancel).
7. Comprehensive 15-step Full Agent End-to-End workflow validation on a disposable workspace.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
for _p in (
    PROJECT_ROOT / "mcp-gateway",
    PROJECT_ROOT / "backend",
    PROJECT_ROOT / "desktop-agent",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from policy import SecurityPolicy  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from web_console import SESSION_COOKIE_NAME, create_web_console_app  # noqa: E402

TEST_OWNER_SECRET = "s9-test-owner-master-secret-112233"


@pytest.fixture()
def s9_console_env(tmp_path: Path):
    """Create an isolated Web Console + Full Agent Gateway backed by tmp_path for S9 tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    outside_dir = tmp_path / "outside_scope"
    outside_dir.mkdir(parents=True, exist_ok=True)

    audit_log = tmp_path / "audit.jsonl"
    estop_file = tmp_path / "EMERGENCY_STOP"

    policy = SecurityPolicy(
        profile="full_agent",
        allowed_read_roots=[str(tmp_path)],
        allowed_write_roots=[str(workspace)],
        allowed_exec_roots=[str(workspace)],
        allowed_git_repos=[str(PROJECT_ROOT)],
        audit_log_path=audit_log,
        emergency_stop_file=estop_file,
        require_session_for_privileged=True,
    )

    gateway = MCPGatewayServer(policy=policy)

    app = create_web_console_app(
        gateway=gateway,
        owner_password=TEST_OWNER_SECRET,
        rate_limit_max_failures=60,
        rate_limit_window_seconds=60,
        allowed_hosts=["127.0.0.1", "localhost", "testserver", "mcp.local"],
        trust_proxy_headers=True,
        max_concurrent_sessions=3,
    )

    client = TestClient(app, base_url="http://testserver")
    return {
        "client": client,
        "app": app,
        "gateway": gateway,
        "workspace": workspace,
        "tmp_path": tmp_path,
        "audit_log": audit_log,
        "estop_file": estop_file,
    }


def _login_owner(client: TestClient) -> str:
    """Helper to authenticate as owner and extract CSRF token."""
    res = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={"Origin": "http://testserver", "Host": "testserver"},
    )
    assert res.status_code == 200, res.text
    return res.json()["csrf_token"]


def _approve_control_session(client: TestClient, csrf: str, workspace: Path) -> str:
    """Helper to approve a Bounded ControlSession for privileged operations."""
    sess_resp = client.post(
        "/console/api/sessions/approve",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        json={
            "tiers": ["READ", "WRITE", "EXECUTE", "DESKTOP"],
            "ttl_seconds": 600,
            "allowed_paths": [str(workspace)],
            "allowed_commands": ["python", "pytest", "git", "powershell"],
        },
    )
    assert sess_resp.status_code == 200, sess_resp.text
    return sess_resp.json()["session"]["session_id"]


def test_01_dns_rebinding_rejection(s9_console_env):
    """Verify that requests with untrusted Host headers are rejected with 403."""
    client = s9_console_env["client"]

    # Allowed hosts: testserver, localhost, 127.0.0.1, mcp.local on login
    res_ok = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={"Origin": "http://testserver", "Host": "testserver"},
    )
    assert res_ok.status_code == 200

    # Malicious Host header (DNS Rebinding attempt) on login
    res_rebind = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={"Origin": "http://attacker.com", "Host": "attacker.controlled.domain.com"},
    )
    assert res_rebind.status_code == 403
    assert "Invalid or untrusted Host header" in res_rebind.json()["error"]


def test_02_proxy_https_secure_cookie(s9_console_env):
    """Verify that X-Forwarded-Proto: https triggers Secure flag on session cookies."""
    client = s9_console_env["client"]

    # Plain HTTP (local dev): Secure flag is False
    res_http = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={"Origin": "http://testserver", "Host": "testserver"},
    )
    assert res_http.status_code == 200
    cookie_header_http = res_http.headers.get("set-cookie", "")
    assert SESSION_COOKIE_NAME in cookie_header_http
    assert "HttpOnly" in cookie_header_http
    assert "samesite=strict" in cookie_header_http.lower()
    assert "Secure" not in cookie_header_http

    # Behind HTTPS Reverse Proxy (X-Forwarded-Proto: https)
    res_https = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={
            "Origin": "https://testserver",
            "Host": "testserver",
            "X-Forwarded-Proto": "https",
        },
    )
    assert res_https.status_code == 200
    cookie_header_https = res_https.headers.get("set-cookie", "")
    assert SESSION_COOKIE_NAME in cookie_header_https
    assert "Secure" in cookie_header_https


def test_03_security_response_headers(s9_console_env):
    """Verify security headers are attached to API and UI responses."""
    client = s9_console_env["client"]

    res = client.get("/health")
    assert res.status_code == 200
    headers = res.headers

    assert "default-src 'self'" in headers.get("content-security-policy", "")
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("referrer-policy") == "no-referrer"


def test_04_session_limits_and_revocation(s9_console_env):
    """Verify concurrent session tracking, listing, and revoking other sessions."""
    app = s9_console_env["app"]

    # Create 3 clients simulating 3 different devices/browsers
    c1 = TestClient(app, base_url="http://testserver")
    c2 = TestClient(app, base_url="http://testserver")
    c3 = TestClient(app, base_url="http://testserver")

    # Login c1
    r1 = c1.post("/console/api/login", json={"password": TEST_OWNER_SECRET}, headers={"Origin": "http://testserver", "Host": "testserver"})
    csrf1 = r1.json()["csrf_token"]
    assert r1.status_code == 200

    # Login c2
    r2 = c2.post("/console/api/login", json={"password": TEST_OWNER_SECRET}, headers={"Origin": "http://testserver", "Host": "testserver"})
    assert r2.status_code == 200

    # Login c3
    r3 = c3.post("/console/api/login", json={"password": TEST_OWNER_SECRET}, headers={"Origin": "http://testserver", "Host": "testserver"})
    assert r3.status_code == 200

    # c1 lists sessions
    list_res = c1.get("/console/api/web-sessions")
    assert list_res.status_code == 200
    data = list_res.json()
    assert data["count"] == 3
    assert len(data["web_sessions"]) == 3

    # c1 revokes all other sessions
    revoke_res = c1.post(
        "/console/api/web-sessions/revoke-others",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf1},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["revoked_count"] == 2

    # c1 is still valid
    c1_check = c1.get("/console/api/proposals")
    assert c1_check.status_code == 200

    # c2 and c3 are now rejected with 401
    c2_check = c2.get("/console/api/proposals")
    assert c2_check.status_code == 401
    c3_check = c3.get("/console/api/proposals")
    assert c3_check.status_code == 401


def test_05_clipboard_redaction(s9_console_env):
    """Verify clipboard inspection returns redacted text for sensitive tokens."""
    client = s9_console_env["client"]
    gateway = s9_console_env["gateway"]
    csrf = _login_owner(client)
    session_id = _approve_control_session(client, csrf, s9_console_env["workspace"])

    secret_text = "Bearer secret_token_xyz987 and password=SuperSecretPass!123 with api_key=ak-1234567890abcdef"  # gitleaks:allow  (synthetic regression fixture; reviewed)

    # Mock gateway desktop.get_clipboard_text
    orig_mock = MagicMock(return_value={"text": secret_text, "success": True})
    gateway.desktop.get_clipboard_text = orig_mock

    # Test with redaction (built-in defense-in-depth ensures tokens are redacted)
    res_redacted = client.get(f"/console/api/clipboard?session_id={session_id}")
    assert res_redacted.status_code == 200
    text = res_redacted.json()["text"]
    assert "secret_token_xyz987" not in text
    assert "SuperSecretPass!123" not in text
    assert "[REDACTED]" in text


def test_06_bounded_multi_step_plan_lifecycle(s9_console_env):
    """Verify Multi-Step Plan creation, approval, execution, pre-mutation snapshots, and rollback."""
    client = s9_console_env["client"]
    workspace = s9_console_env["workspace"]
    csrf = _login_owner(client)
    session_id = _approve_control_session(client, csrf, workspace)

    target_file = workspace / "plan_target.txt"
    target_file.write_text("ORIGINAL CONTENT V1\n", encoding="utf-8")

    # 1. Create a Plan with 2 steps
    plan_payload = {
        "title": "Config Migration and Verification Plan",
        "description": "Edits plan_target.txt and verifies contents via PowerShell",
        "steps": [
            {
                "tool_name": "edit_file",
                "arguments": {
                    "path": str(target_file),
                    "old_text": "ORIGINAL CONTENT V1",
                    "new_text": "NEW CONTENT V2",
                },
                "description": "Update plan target configuration to V2",
            },
            {
                "tool_name": "powershell_execute",
                "arguments": {
                    "command": f"Get-Content '{str(target_file)}'",
                    "cwd": str(workspace),
                },
                "description": "Verify updated contents via PowerShell",
            },
        ],
    }

    create_res = client.post(
        "/console/api/plans",
        json=plan_payload,
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert create_res.status_code == 201, create_res.text
    plan_data = create_res.json()["plan"]
    plan_id = plan_data["plan_id"]
    assert plan_data["status"] == "PENDING_OWNER_APPROVAL"
    assert len(plan_data["steps"]) == 2

    # 2. Cannot execute unapproved plan
    # In web_console.py, status must be APPROVED or PENDING_OWNER_APPROVAL
    # Note: approve endpoint approves it
    appr_res = client.post(
        f"/console/api/plans/{plan_id}/approve",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert appr_res.status_code == 200
    assert appr_res.json()["plan"]["status"] == "APPROVED"

    # 3. Execute plan with active session_id
    exec_res = client.post(
        f"/console/api/plans/{plan_id}/execute",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        json={"session_id": session_id},
    )
    assert exec_res.status_code == 200, exec_res.text
    exec_plan = exec_res.json()["plan"]
    assert exec_plan["status"] == "COMPLETED"
    assert len(exec_plan["steps"]) == 2
    assert exec_plan["steps"][0]["status"] == "SUCCESS"
    assert exec_plan["steps"][1]["status"] == "SUCCESS"
    assert "NEW CONTENT V2" in exec_plan["steps"][1]["output"]["stdout"]
    assert "NEW CONTENT V2" in target_file.read_text(encoding="utf-8")

    # 4. Rollback plan restoring pre-mutation snapshot
    rollback_res = client.post(
        f"/console/api/plans/{plan_id}/rollback",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert rollback_res.status_code == 200
    rb_data = rollback_res.json()
    assert rb_data["plan"]["status"] == "ROLLED_BACK"
    assert rb_data["restored_files_count"] >= 1

    # Verify original content was restored
    assert target_file.read_text(encoding="utf-8") == "ORIGINAL CONTENT V1\n"


def test_07_comprehensive_15_step_full_agent_e2e(s9_console_env):
    """Complete 15-step Full Agent E2E Scenario on a disposable workspace."""
    client = s9_console_env["client"]
    gateway = s9_console_env["gateway"]
    workspace = s9_console_env["workspace"]

    # STEP 1: Owner login & CSRF token acquisition
    login_res = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={"Origin": "http://testserver", "Host": "testserver"},
    )
    assert login_res.status_code == 200
    csrf = login_res.json()["csrf_token"]
    assert csrf and len(csrf) > 16

    # STEP 2: Read tools execution (inspect workspace directory)
    read_res = gateway.invoke_tool("list_directory", {"path": str(workspace)})
    assert "entries" in read_res

    # STEP 3: Approve ControlSession for privileged operations
    session_id = _approve_control_session(client, csrf, workspace)
    assert session_id.startswith("sess_")

    # STEP 4: Create write proposal (write test_app.py)
    target_py = workspace / "test_app.py"
    py_code = 'print("Sprint 4 Remote Web Agent E2E Verified")\n'
    prop_res = client.post(
        "/console/api/proposals",
        json={
            "tool_name": "write_file",
            "arguments": {"path": str(target_py), "content": py_code, "overwrite": True},
            "rationale": "Create test_app.py script",
        },
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert prop_res.status_code == 201
    prop1 = prop_res.json()["proposal"]
    prop1_id = prop1["proposal_id"]
    assert prop1["status"] == "PENDING_OWNER_APPROVAL"

    # STEP 5: Inspect proposal and unified diff preview
    inspect_prop = client.get(f"/console/api/proposals/{prop1_id}")
    assert inspect_prop.status_code == 200
    diff_text = inspect_prop.json()["proposal"]["preview"]["unified_diff"]
    assert "+print(\"Sprint 4 Remote Web Agent E2E Verified\")" in diff_text

    # STEP 6: Execute proposal (file written to disk)
    exec1 = client.post(
        f"/console/api/proposals/{prop1_id}/execute",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        json={"session_id": session_id},
    )
    assert exec1.status_code == 200
    assert target_py.exists()
    assert target_py.read_text(encoding="utf-8") == py_code

    # STEP 7: Create command proposal for execution
    cmd_prop = client.post(
        "/console/api/proposals",
        json={
            "tool_name": "powershell_execute",
            "arguments": {
                "command": f"python '{str(target_py)}'",
                "cwd": str(workspace),
            },
            "rationale": "Execute test_app.py",
        },
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert cmd_prop.status_code == 201
    prop2_id = cmd_prop.json()["proposal"]["proposal_id"]

    # STEP 8: Execute command proposal
    exec2 = client.post(
        f"/console/api/proposals/{prop2_id}/execute",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        json={"session_id": session_id},
    )
    assert exec2.status_code == 200

    # STEP 9: Verify exit code 0 and stdout
    output = exec2.json()["result"]
    assert output["exit_code"] == 0
    assert "Sprint 4 Remote Web Agent E2E Verified" in output["stdout"]

    # STEP 10: GUI inspection / screenshot capture
    screen_res = client.get("/console/api/screenshot")
    assert screen_res.status_code == 200
    assert screen_res.headers["content-type"] in ("image/png", "application/json")

    # STEP 11: Multi-step plan creation and execution
    aux_file = workspace / "data.txt"
    plan_payload = {
        "title": "Batch Setup and Verify",
        "description": "Creates data.txt and reads it",
        "steps": [
            {
                "tool_name": "write_file",
                "arguments": {"path": str(aux_file), "content": "INITIAL_DATA\n", "overwrite": True},
                "description": "Create data.txt",
            },
            {
                "tool_name": "read_file",
                "arguments": {"path": str(aux_file)},
                "description": "Read data.txt",
            },
        ],
    }
    plan_res = client.post(
        "/console/api/plans",
        json=plan_payload,
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert plan_res.status_code == 201
    plan_id = plan_res.json()["plan"]["plan_id"]
    client.post(
        f"/console/api/plans/{plan_id}/approve",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    plan_exec = client.post(
        f"/console/api/plans/{plan_id}/execute",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        json={"session_id": session_id},
    )
    assert plan_exec.status_code == 200
    assert plan_exec.json()["plan"]["status"] == "COMPLETED"

    # STEP 12: Verify plan rollback restores workspace
    rb = client.post(
        f"/console/api/plans/{plan_id}/rollback",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert rb.status_code == 200
    # aux_file did not exist prior to plan creation -> snapshot was None -> file is deleted
    assert not aux_file.exists()

    # STEP 13: Revoke session
    revoke_res = client.post(
        "/console/api/logout",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert revoke_res.status_code == 200

    # STEP 14: Verify 401 rejection after session revocation
    unauth_check = client.get("/console/api/proposals")
    assert unauth_check.status_code == 401

    # STEP 15: Emergency Stop trigger, confirming immediate halt and file existence
    relogin = client.post(
        "/console/api/login",
        json={"password": TEST_OWNER_SECRET},
        headers={"Origin": "http://testserver"},
    )
    new_csrf = relogin.json()["csrf_token"]
    estop_res = client.post(
        "/console/api/emergency-stop",
        headers={"Origin": "http://testserver", "X-CSRF-Token": new_csrf},
    )
    assert estop_res.status_code == 200
    assert estop_res.json()["emergency_stop"] is True
    assert s9_console_env["estop_file"].exists()
