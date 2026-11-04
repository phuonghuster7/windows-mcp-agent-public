"""Test suite for Agent A/C: Dynamic OAuth Client Identification, Owner Authorization & Task Isolation (Audit 28D9ED5).

Verifies:
1. Dynamically registered OAuth client with generated ID (mcp_client_<hex>) is authorized via claims/pairing.
2. Verified owner client can execute owner tools (agent_powershell_execute, system status, tasks).
3. Non-owner authenticated OAuth client is denied owner-level tools under principle of least privilege.
4. Token revocation immediately cuts off access (401/403).
5. Task ownership isolation: Client A submits a task, Client B is denied reading diffs/logs or cancelling it.
6. Header spoofing (X-Caller-ID, X-Owner, X-MCP-Owner) and JSON-RPC param spoofing (_caller_id) are rejected.
7. Cloud surface without verified AuthPrincipal strictly rejects owner permissions.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for p in (PROJECT_ROOT, PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pytest
from fastapi.testclient import TestClient

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app
from gateway_server import MCPGatewayServer
from policy import GatewayPolicy
from exec_jobs import ExecutionJobManager
from agent import DesktopAgent
from runtime.contracts import AuthPrincipal, RuntimeStatePaths
from runtime.process_runner import verify_cloud_principal
from runtime.task_store import TaskStore
from runtime.task_grant import TaskGrantBroker
from runtime.agent_mcp_tools import AgentMCPToolHandler


def _create_isolated_gateway(paths: RuntimeStatePaths) -> MCPGatewayServer:
    policy = GatewayPolicy(
        profile="owner_full_control",
        emergency_stop_file=paths.emergency_stop_file,
        audit_log_path=paths.audit_log_path,
    )
    exec_ops = ExecutionJobManager(policy=policy, jobs_dir=paths.jobs_dir)
    desk_agent = DesktopAgent(policy=policy, emergency_stop_file=paths.emergency_stop_file)
    gw = MCPGatewayServer(
        policy=policy,
        exec_ops=exec_ops,
        desktop_agent=desk_agent,
        runtime_paths=paths,
    )
    store = TaskStore(db_path=paths.tasks_db_path)
    broker = TaskGrantBroker(
        key_path=paths.grant_key_path,
        policy=policy,
        db_path=paths.tasks_db_path,
    )
    gw.store = store
    gw._agent_tool_handler = AgentMCPToolHandler(store, broker)
    return gw


def _generate_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _register_and_authorize_client(
    client: TestClient,
    owner_secret: str,
    *,
    client_name: str,
    scope: str,
) -> tuple[str, str, str]:
    """Helper to register and perform PKCE OAuth authorization code flow.
    Returns: (client_id, client_secret, access_token)
    """
    reg_res = client.post(
        "/oauth/register",
        json={
            "client_name": client_name,
            "redirect_uris": ["https://chatgpt.com/api/mcp/callback"],
            "scope": scope,
        },
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    client_id = reg_data["client_id"]
    client_secret = reg_data["client_secret"]
    assert client_id.startswith("mcp_client_")

    code_verifier, code_challenge = _generate_pkce_pair()
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://chatgpt.com/api/mcp/callback",
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": f"state_{secrets.token_hex(4)}",
    }
    auth_page = client.get("/oauth/authorize", params=auth_params)
    assert auth_page.status_code == 200
    csrf_token = auth_page.headers.get("X-OAuth-CSRF-Token")
    assert csrf_token is not None

    consent_payload = {
        **auth_params,
        "decision": "allow",
        "owner_token": owner_secret,
        "csrf_token": csrf_token,
    }
    consent_res = client.post(
        "/oauth/authorize",
        data=consent_payload,
        cookies={"mcp_oauth_csrf": csrf_token},
        follow_redirects=False,
    )
    assert consent_res.status_code == 302
    loc = consent_res.headers["Location"]
    auth_code = loc.split("code=")[1].split("&")[0]

    token_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": auth_code,
            "code_verifier": code_verifier,
            "redirect_uri": "https://chatgpt.com/api/mcp/callback",
        },
    )
    assert token_res.status_code == 200
    access_token = token_res.json()["access_token"]
    assert access_token.startswith("mcp_oat_")

    return client_id, client_secret, access_token


def test_dynamic_oauth_client_owner_full_control():
    """Verify dynamically registered OAuth client with mcp:owner scope can execute owner tools."""
    td = tempfile.mkdtemp(prefix="test_oauth_owner_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        gw = _create_isolated_gateway(paths)

        owner_secret = "master_owner_secret_passphrase_12345"
        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token=owner_secret,
            db_path=paths.oauth_db_path,
            enable_direct_coding=True,
        )
        client = TestClient(app)

        client_id, client_secret, access_token = _register_and_authorize_client(
            client,
            owner_secret,
            client_name="ChatGPT-Dynamic-Owner",
            scope="mcp:autonomous mcp:coding:write mcp:owner",
        )

        mcp_hdr = {
            "Authorization": f"Bearer {access_token}",
            "Mcp-Protocol-Version": "2024-11-05",
        }
        init_res = client.post(
            "/mcp",
            headers=mcp_hdr,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        )
        assert init_res.status_code == 200
        session_id = init_res.headers.get("Mcp-Session-Id")
        mcp_hdr["Mcp-Session-Id"] = session_id

        # 1. Execute PowerShell with request-bound capability grant (P0-02)
        from http_server import _verify_oauth_token
        _, tok_payload, _ = _verify_oauth_token(access_token, app.state.oauth_signing_key, set())
        grant_info = app.state.oauth_persistence.issue_owner_capability_grant(
            secret=app.state.oauth_signing_key,
            allowed_tools=["agent_powershell_execute", "agent_system_status"],
            allowed_paths=[td, str(Path(".").resolve())],
            owner_id="local_owner",
            client_id=client_id,
            oauth_token_jti=tok_payload["jti"],
            ttl_seconds=300.0,
            max_uses=5,
        )
        ps_res = client.post(
            "/mcp",
            headers=mcp_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {
                        "command": "Write-Output 'DYNAMIC_CLIENT_OWNER_SUCCESS'",
                        "cwd": td,
                        "capability_grant_id": grant_info["grant_id"],
                    },
                },
            },
        )
        assert ps_res.status_code == 200
        ps_data = ps_res.json()["result"]
        assert ps_data.get("isError") is False
        exec_out = json.loads(ps_data["content"][0]["text"])
        assert exec_out["exit_code"] == 0
        assert "DYNAMIC_CLIENT_OWNER_SUCCESS" in exec_out["stdout"]

        # 2. Execute System Status
        status_res = client.post(
            "/mcp",
            headers=mcp_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "agent_system_status", "arguments": {"capability_grant_id": grant_info["grant_id"]}},
            },
        )
        assert status_res.status_code == 200
        assert status_res.json()["result"].get("isError") is False

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_dynamic_oauth_client_least_privilege_denial():
    """Verify unprivileged OAuth client (without mcp:owner) is denied owner tools."""
    td = tempfile.mkdtemp(prefix="test_oauth_least_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        gw = _create_isolated_gateway(paths)

        owner_secret = "master_owner_secret_passphrase_12345"
        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token=owner_secret,
            db_path=paths.oauth_db_path,
            enable_direct_coding=True,
        )
        client = TestClient(app)

        unprivileged_client_id, client_secret, access_token = _register_and_authorize_client(
            client,
            owner_secret,
            client_name="Unprivileged-Client",
            scope="mcp:autonomous",
        )

        mcp_hdr = {
            "Authorization": f"Bearer {access_token}",
            "Mcp-Protocol-Version": "2024-11-05",
        }
        init_res = client.post(
            "/mcp",
            headers=mcp_hdr,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        )
        mcp_hdr["Mcp-Session-Id"] = init_res.headers.get("Mcp-Session-Id")

        # 1. Attempt owner powershell execution -> DENIED
        ps_res = client.post(
            "/mcp",
            headers=mcp_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "agent_powershell_execute", "arguments": {"command": "Write-Output 'FAIL'"}},
            },
        )
        assert ps_res.status_code == 200
        res_json = ps_res.json()
        assert res_json["result"]["isError"] is True
        assert "not authorized for owner-level powershell execution" in res_json["result"]["content"][0]["text"]

        # 2. Header spoofing attempt (X-MCP-Caller-Id: local_owner) -> DENIED 403
        spoof_hdr = {**mcp_hdr, "X-MCP-Caller-Id": "local_owner"}
        spoof_res = client.post(
            "/mcp",
            headers=spoof_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "agent_system_status", "arguments": {}},
            },
        )
        assert spoof_res.status_code == 403

        # 3. Revoke token and verify immediate denial
        revoke_res = client.post(
            "/oauth/revoke",
            data={"token": access_token},
            auth=(unprivileged_client_id, client_secret),
        )
        assert revoke_res.status_code == 200

        after_revoke = client.post(
            "/mcp",
            headers=mcp_hdr,
            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
        )
        assert after_revoke.status_code == 403

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_oauth_task_ownership_isolation():
    """Verify task isolation between two distinct dynamic OAuth clients.
    Client A creates a task; Client B is denied access to view diffs or cancel Client A's task.
    """
    td = tempfile.mkdtemp(prefix="test_oauth_isolation_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        gw = _create_isolated_gateway(paths)

        owner_secret = "master_owner_secret_passphrase_12345"
        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token=owner_secret,
            db_path=paths.oauth_db_path,
            enable_direct_coding=True,
        )
        client = TestClient(app)

        # Preapprove the temp workspace root for cloud task submission
        agent_handler = gw.get_agent_tool_handler()
        agent_handler.broker.onboard_workspace_root(td, owner_id="local_owner")

        # Register Client A
        client_a_id, _, token_a = _register_and_authorize_client(
            client, owner_secret, client_name="Client-A", scope="mcp:autonomous"
        )
        # Register Client B
        client_b_id, _, token_b = _register_and_authorize_client(
            client, owner_secret, client_name="Client-B", scope="mcp:autonomous"
        )

        hdr_a = {"Authorization": f"Bearer {token_a}", "Mcp-Protocol-Version": "2024-11-05"}
        init_a = client.post("/mcp", headers=hdr_a, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        hdr_a["Mcp-Session-Id"] = init_a.headers.get("Mcp-Session-Id")

        hdr_b = {"Authorization": f"Bearer {token_b}", "Mcp-Protocol-Version": "2024-11-05"}
        init_b = client.post("/mcp", headers=hdr_b, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        hdr_b["Mcp-Session-Id"] = init_b.headers.get("Mcp-Session-Id")

        # Client A submits a task proposal
        submit_res = client.post(
            "/mcp",
            headers=hdr_a,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Confidential Task for Client A",
                        "workspace_root": td,
                    },
                },
            },
        )
        assert submit_res.status_code == 200
        submit_data = json.loads(submit_res.json()["result"]["content"][0]["text"])
        task_id = submit_data["task_id"]
        assert task_id.startswith("task_")

        # Client B attempts to read diff of Client A's task -> FORBIDDEN
        diff_res = client.post(
            "/mcp",
            headers=hdr_b,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "agent_task_diff",
                    "arguments": {"task_id": task_id},
                },
            },
        )
        assert diff_res.status_code == 200
        diff_data = json.loads(diff_res.json()["result"]["content"][0]["text"])
        assert "Permission Denied" in diff_data.get("error", "") or diff_data.get("status") == "FORBIDDEN"

        # Client B attempts to cancel Client A's task -> DENIED
        cancel_res = client.post(
            "/mcp",
            headers=hdr_b,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "agent_task_cancel",
                    "arguments": {"task_id": task_id, "reason": "Malicious cancellation attempt"},
                },
            },
        )
        assert cancel_res.status_code == 200
        cancel_content = cancel_res.json()["result"]["content"][0]["text"]
        assert "Permission Denied" in cancel_content or cancel_res.json()["result"].get("isError") is True

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_anti_spoofing_headers_and_legacy_fallback_denial():
    """Verify spoofed headers (X-Caller-ID, X-Owner, X-MCP-Owner), JSON-RPC _caller_id parameter,
    and missing AuthPrincipal fallback are strictly denied owner privileges (Audit Finding C2).
    """
    td = tempfile.mkdtemp(prefix="test_anti_spoof_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        gw = _create_isolated_gateway(paths)

        owner_secret = "master_owner_secret_passphrase_12345"
        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token=owner_secret,
            db_path=paths.oauth_db_path,
            enable_direct_coding=True,
        )
        client = TestClient(app)

        # 1. Spoofed headers rejection
        spoof_headers = [
            {"X-Caller-ID": "local_owner"},
            {"X-Owner": "true"},
            {"X-MCP-Owner": "local_owner"},
            {"X-Caller-ID": "chatgpt_cloud_client"},
        ]
        for shdr in spoof_headers:
            resp = client.post(
                "/mcp",
                headers={**shdr, "Mcp-Protocol-Version": "2024-11-05"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            assert resp.status_code in (401, 403), f"Header {shdr} was not rejected"

        # 2. Verification of verify_cloud_principal logic
        # When auth_principal is None on cloud surface:
        is_auth, is_own, ident = verify_cloud_principal(None, internal_local_trusted=False)
        assert is_auth is False
        assert is_own is False

        # When auth_principal is not an owner:
        unprivileged_principal = AuthPrincipal(
            client_id="chatgpt_cloud_client",
            is_owner=False,
            scopes=frozenset(["mcp:tools"]),
        )
        is_auth2, is_own2, ident2 = verify_cloud_principal(unprivileged_principal, internal_local_trusted=False)
        assert is_auth2 is True
        assert is_own2 is False
        assert ident2 == "chatgpt_cloud_client"

        # Direct gateway invocation with non-owner AuthPrincipal must be rejected for powershell
        msg = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "agent_powershell_execute",
                "arguments": {"command": "Write-Output 'SPOOF_TEST'"},
            },
        }
        direct_res = gw.handle_jsonrpc_autonomous(
            msg,
            caller_id="local_owner",  # Trying to claim local_owner while principal is non-owner
            auth_principal=unprivileged_principal,
        )
        assert direct_res["result"]["isError"] is True
        assert "not authorized for owner-level powershell execution" in direct_res["result"]["content"][0]["text"]

    finally:
        shutil.rmtree(td, ignore_errors=True)
