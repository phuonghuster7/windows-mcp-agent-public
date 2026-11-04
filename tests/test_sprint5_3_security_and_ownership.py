"""Independent Penetration Tests & Authentication Regression Test Suite (Sprint 5.3).

Covers all mandatory negative and positive security checks in Sprint 5.3:
  - Finding H01: Edge Authentication, Token Integrity, Identity Header Validation, Rate Limiting
  - Finding H02: Multi-Tenant Task Data Ownership, Cross-Client Isolation, Path & Secret Redaction
  - Finding H04: MCP Protocol Negotiation, Mcp-Session-Id Binding, and Payload Size Guardrails
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
for _p in (str(PROJECT_ROOT), str(GATEWAY_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from http_server import (  # noqa: E402
    _issue_oauth_token,
    create_gateway_http_app,
)
from policy import SecurityPolicy  # noqa: E402
from runtime.agent_mcp_tools import (  # noqa: E402
    AgentMCPToolHandler,
    redact_task_output,
)
from runtime.task_grant import TaskGrantBroker  # noqa: E402
from runtime.task_store import TaskState, TaskStore  # noqa: E402

# Allowed synthetic test fixture from scripts/Build-ReleasePackage.ps1
SYNTHETIC_API_KEY = "sk-mock-key-for-unit-test-12345"


@pytest.fixture
def sec_fixture() -> Generator[dict[str, Any], None, None]:
    """Provide isolated environment for security penetration and regression tests."""
    base_dir = Path(tempfile.mkdtemp(prefix="sprint53_sec_"))
    db_path = base_dir / "tasks.db"
    approved_ws = base_dir / "approved_ws"
    approved_ws.mkdir(parents=True, exist_ok=True)
    unapproved_ws = base_dir / "unapproved_ws"
    unapproved_ws.mkdir(parents=True, exist_ok=True)

    # Initialize minimal git repository for git diff testing
    subprocess.run(["git", "init"], cwd=str(approved_ws), capture_output=True, check=False)
    subprocess.run(
        ["git", "config", "user.name", "SecurityTestBot"],
        cwd=str(approved_ws),
        capture_output=True,
        check=False,
    )
    subprocess.run(
        ["git", "config", "user.email", "sectest@example.com"],
        cwd=str(approved_ws),
        capture_output=True,
        check=False,
    )

    store = TaskStore(db_path)
    policy = SecurityPolicy(profile="read_only")
    broker = TaskGrantBroker(
        policy=policy,
        db_path=db_path,
        preapproved_roots=[approved_ws],
        require_preapproved_roots=True,
    )
    gateway = MCPGatewayServer(policy=policy)
    gateway.store = store
    handler = AgentMCPToolHandler(store, broker)
    gateway._agent_tool_handler = handler

    shared_caller_secret = "test_shared_gateway_caller_token_sprint53"
    shared_oauth_signing_key = "test_dedicated_oauth_signing_key_sprint53_abc123"
    gw_app = create_gateway_http_app(
        gateway=gateway,
        caller_auth_token=shared_caller_secret,
        oauth_signing_key=shared_oauth_signing_key,
        require_autonomous_auth=True,
    )
    adapter_app = create_cloud_autonomous_adapter_app(
        gateway=gateway,
        caller_auth_token=shared_caller_secret,
        oauth_signing_key=shared_oauth_signing_key,
        require_autonomous_auth=True,
        allow_loopback_tunnel_identity=False,
    )

    gw_client = TestClient(gw_app)
    adapter_client = TestClient(adapter_app)

    yield {
        "base_dir": base_dir,
        "db_path": db_path,
        "approved_ws": approved_ws,
        "unapproved_ws": unapproved_ws,
        "store": store,
        "policy": policy,
        "broker": broker,
        "gateway": gateway,
        "handler": handler,
        "caller_token": shared_caller_secret,
        "oauth_signing_key": shared_oauth_signing_key,
        "gw_app": gw_app,
        "adapter_app": adapter_app,
        "gw_client": gw_client,
        "adapter_client": adapter_client,
    }

    try:
        shutil.rmtree(str(base_dir), ignore_errors=True)
    except Exception:
        pass


class TestSprint53_SecurityAndOwnership:
    """Sprint 5.3 Comprehensive Security & Ownership Penetration Suite."""

    # -------------------------------------------------------------------------
    # Test 01 — Missing Authentication (H01)
    # -------------------------------------------------------------------------
    def test_01_missing_authentication_h01(self, sec_fixture: dict[str, Any]) -> None:
        """Verify unauthenticated requests fail-closed with HTTP 401 and WWW-Authenticate."""
        gw_client: TestClient = sec_fixture["gw_client"]
        adapter_client: TestClient = sec_fixture["adapter_client"]
        handler: AgentMCPToolHandler = sec_fixture["handler"]
        approved_ws: Path = sec_fixture["approved_ws"]

        list_rpc = {"jsonrpc": "2.0", "id": "test-no-auth", "method": "tools/list", "params": {}}

        # 1. Main gateway /mcp/autonomous without Authorization header -> HTTP 401
        r_gw = gw_client.post("/mcp/autonomous", json=list_rpc)
        assert r_gw.status_code == 401, r_gw.text
        www_auth = r_gw.headers.get("www-authenticate", "")
        assert "Bearer" in www_auth
        data_gw = r_gw.json()
        assert data_gw["error"]["code"] == -32001
        assert "Unauthorized (H01)" in data_gw["error"]["message"]

        # 2. Dedicated Adapter /mcp without Authorization header -> HTTP 401
        r_ad = adapter_client.post("/mcp", json=list_rpc)
        assert r_ad.status_code == 401, r_ad.text
        assert "Bearer" in r_ad.headers.get("www-authenticate", "")
        assert r_ad.json()["error"]["code"] == -32001

        # 3. Direct handler execution with anonymous/missing caller on cloud_autonomous -> REJECTED
        res_none = handler.execute_tool(
            "agent_submit_task",
            {"objective": "anonymous task", "workspace_root": str(approved_ws)},
            surface="cloud_autonomous",
            caller_id=None,
        )
        assert res_none.get("status") == "REJECTED"
        assert "Permission Denied (H01/H02)" in res_none.get("error", "")

        res_anon = handler.execute_tool(
            "agent_submit_task",
            {"objective": "anonymous task", "workspace_root": str(approved_ws)},
            surface="cloud_autonomous",
            caller_id="anonymous",
        )
        assert res_anon.get("status") == "REJECTED"
        assert "Permission Denied (H01/H02)" in res_anon.get("error", "")

        res_unauth = handler.execute_tool(
            "agent_submit_task",
            {"objective": "anonymous task", "workspace_root": str(approved_ws)},
            surface="cloud_autonomous",
            caller_id="unauthenticated",
        )
        assert res_unauth.get("status") == "REJECTED"

    # -------------------------------------------------------------------------
    # Test 02 — Invalid Caller Credential (H01)
    # -------------------------------------------------------------------------
    def test_02_invalid_caller_credential_h01(self, sec_fixture: dict[str, Any]) -> None:
        """Verify bogus/invalid credentials fail closed with HTTP 403 and error -32003."""
        gw_client: TestClient = sec_fixture["gw_client"]
        adapter_client: TestClient = sec_fixture["adapter_client"]

        list_rpc = {"jsonrpc": "2.0", "id": "test-bad-cred", "method": "tools/list", "params": {}}
        bad_headers = {"Authorization": "Bearer wrong_secret_token_12345"}

        # 1. Main gateway /mcp/autonomous with wrong Bearer token
        r_gw = gw_client.post("/mcp/autonomous", headers=bad_headers, json=list_rpc)
        assert r_gw.status_code == 403, r_gw.text
        data_gw = r_gw.json()
        assert data_gw["error"]["code"] == -32003
        assert "Forbidden (H01)" in data_gw["error"]["message"]

        # 2. Adapter /mcp with invalid Bearer token
        r_ad = adapter_client.post("/mcp", headers=bad_headers, json=list_rpc)
        assert r_ad.status_code == 403, r_ad.text
        assert r_ad.json()["error"]["code"] == -32003

    # -------------------------------------------------------------------------
    # Test 03 — Forged Caller Identity & Injection (H01)
    # -------------------------------------------------------------------------
    def test_03_forged_caller_identity_and_injection_h01(self, sec_fixture: dict[str, Any]) -> None:
        """Verify tampered OAuth signatures and injection headers return HTTP 403."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]

        list_rpc = {"jsonrpc": "2.0", "id": "test-forge", "method": "tools/list", "params": {}}

        # 1. Forged OAuth token with tampered signature
        valid_tok_info = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"])
        valid_tok = valid_tok_info["access_token"]
        raw_prefix, _ = valid_tok.split(".", 1)
        tampered_tok = f"{raw_prefix}.0000000000000000000000000000000000000000000000000000000000000000"

        r_tampered = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tampered_tok}"},
            json=list_rpc,
        )
        assert r_tampered.status_code == 403, r_tampered.text
        assert r_tampered.json()["error"]["code"] == -32003
        assert "Invalid OAuth token signature" in r_tampered.json()["error"]["message"]

        # 2. X-MCP-Caller-Id with SQL/command injection characters
        r_injection = gw_client.post(
            "/mcp/autonomous",
            headers={
                "Authorization": f"Bearer {valid_tok}",
                "X-MCP-Caller-Id": "client_a; DROP TABLE tasks;",
            },
            json=list_rpc,
        )
        assert r_injection.status_code == 403, r_injection.text
        assert r_injection.json()["error"]["code"] == -32003
        assert "Caller identity header mismatch" in r_injection.json()["error"]["message"]

        # 3. X-MCP-Caller-Id attempting to spoof reserved local roles from Cloud
        for forbidden_role in ("local_admin", "local_owner"):
            r_spoof = gw_client.post(
                "/mcp/autonomous",
                headers={
                    "Authorization": f"Bearer {valid_tok}",
                    "X-MCP-Caller-Id": forbidden_role,
                },
                json=list_rpc,
            )
            assert r_spoof.status_code == 403, f"Failed for {forbidden_role}: {r_spoof.text}"
            assert r_spoof.json()["error"]["code"] == -32003
            assert "Caller identity header mismatch" in r_spoof.json()["error"]["message"]

    # -------------------------------------------------------------------------
    # Test 04 — Expired or Revoked OAuth / Session Identity (H01)
    # -------------------------------------------------------------------------
    def test_04_expired_or_revoked_oauth_session_identity_h01(self, sec_fixture: dict[str, Any]) -> None:
        """Verify tokens revoked via /oauth/revoke and expired tokens fail closed."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]

        list_rpc = {"jsonrpc": "2.0", "id": "test-lifecycle", "method": "tools/list", "params": {}}

        # 1. Mint token via POST /oauth/token
        r_mint = gw_client.post("/oauth/token", auth=("client_alpha", secret))
        assert r_mint.status_code == 200, r_mint.text
        tok = r_mint.json()["access_token"]

        # 2. Verify token works before revocation
        r_ok = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok}"},
            json=list_rpc,
        )
        assert r_ok.status_code == 200, r_ok.text

        # 3. Revoke token via POST /oauth/revoke
        r_rev = gw_client.post("/oauth/revoke", data={"token": tok})
        assert r_rev.status_code == 200, r_rev.text
        assert r_rev.json().get("status") == "revoked"

        # 4. Subsequent use of revoked token returns HTTP 403
        r_revoked = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok}"},
            json=list_rpc,
        )
        assert r_revoked.status_code == 403, r_revoked.text
        assert r_revoked.json()["error"]["code"] == -32003
        assert "revoked" in r_revoked.json()["error"]["message"].lower()

        # 5. Expired token (exp in the past) returns HTTP 403
        exp_info = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"], ttl_seconds=-30)
        exp_tok = exp_info["access_token"]
        r_exp = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {exp_tok}"},
            json=list_rpc,
        )
        assert r_exp.status_code == 403, r_exp.text
        assert r_exp.json()["error"]["code"] == -32003
        assert "expired" in r_exp.json()["error"]["message"].lower()

    # -------------------------------------------------------------------------
    # Test 05 — Identity Mismatch (H01)
    # -------------------------------------------------------------------------
    def test_05_identity_mismatch_h01(self, sec_fixture: dict[str, Any]) -> None:
        """Verify identity mismatch between header and bearer subject, and session hijacking."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]

        # 1. Mint tokens for client_alpha and client_beta
        r_alpha = gw_client.post("/oauth/token", auth=("client_alpha", secret))
        tok_alpha = r_alpha.json()["access_token"]
        r_beta = gw_client.post("/oauth/token", auth=("client_beta", secret))
        tok_beta = r_beta.json()["access_token"]

        list_rpc = {"jsonrpc": "2.0", "id": "test-mismatch", "method": "tools/list", "params": {}}

        # 2. Bearer is client_alpha, but X-MCP-Caller-Id is client_beta -> HTTP 403
        r_mismatch = gw_client.post(
            "/mcp/autonomous",
            headers={
                "Authorization": f"Bearer {tok_alpha}",
                "X-MCP-Caller-Id": "client_beta",
            },
            json=list_rpc,
        )
        assert r_mismatch.status_code == 403, r_mismatch.text
        assert r_mismatch.json()["error"]["code"] == -32003
        assert "Caller identity header mismatch" in r_mismatch.json()["error"]["message"]

        # 3. Mcp-Session-Id bound to client_alpha cannot be reused by client_beta
        init_rpc = {"jsonrpc": "2.0", "id": "init-alpha", "method": "initialize", "params": {}}
        r_init = gw_client.post(
            "/mcp/autonomous",
            headers={
                "Authorization": f"Bearer {tok_alpha}",
                "Mcp-Session-Id": "sess_stream_alpha_100",
            },
            json=init_rpc,
        )
        assert r_init.status_code == 200, r_init.text
        assert r_init.headers.get("Mcp-Session-Id") == "sess_stream_alpha_100"

        # client_beta attempts to send requests with client_alpha's stream session
        r_hijack = gw_client.post(
            "/mcp/autonomous",
            headers={
                "Authorization": f"Bearer {tok_beta}",
                "Mcp-Session-Id": "sess_stream_alpha_100",
            },
            json=list_rpc,
        )
        assert r_hijack.status_code == 403, r_hijack.text
        assert r_hijack.json()["error"]["code"] == -32003
        assert "Mcp-Session-Id header mismatch" in r_hijack.json()["error"]["message"]

    # -------------------------------------------------------------------------
    # Test 06 — Malformed JSON-RPC Request (H01 / H04)
    # -------------------------------------------------------------------------
    def test_06_malformed_jsonrpc_request_h01_h04(self, sec_fixture: dict[str, Any]) -> None:
        """Verify invalid JSON or malformed RPC returns HTTP 400 with safe error code."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]
        tok = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"])["access_token"]
        auth_hdr = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

        # 1. Non-JSON raw body -> HTTP 400, code -32700
        r_parse = gw_client.post("/mcp/autonomous", headers=auth_hdr, content=b"INVALID_JSON_BODY{{{")
        assert r_parse.status_code == 400, r_parse.text
        assert r_parse.json()["error"]["code"] == -32700
        assert "Parse error" in r_parse.json()["error"]["message"]

        # 2. Missing jsonrpc: "2.0" field -> HTTP 400, code -32600
        r_no_rpc = gw_client.post("/mcp/autonomous", headers=auth_hdr, json={"id": 1, "method": "tools/list"})
        assert r_no_rpc.status_code == 400, r_no_rpc.text
        assert r_no_rpc.json()["error"]["code"] == -32600
        assert "jsonrpc" in r_no_rpc.json()["error"]["message"]

        # 3. Missing method field -> HTTP 400, code -32600
        r_no_method = gw_client.post("/mcp/autonomous", headers=auth_hdr, json={"jsonrpc": "2.0", "id": 2})
        assert r_no_method.status_code == 400, r_no_method.text
        assert r_no_method.json()["error"]["code"] == -32600
        assert "method" in r_no_method.json()["error"]["message"]

        # 4. Non-dict non-list primitive payload -> HTTP 400, code -32600
        r_prim = gw_client.post("/mcp/autonomous", headers=auth_hdr, json=12345)
        assert r_prim.status_code == 400, r_prim.text
        assert r_prim.json()["error"]["code"] == -32600

    # -------------------------------------------------------------------------
    # Test 07 — Oversized Request Payload (H01 / H04)
    # -------------------------------------------------------------------------
    def test_07_oversized_request_payload_h01_h04(self, sec_fixture: dict[str, Any]) -> None:
        """Verify requests exceeding 256 KB (270,000 bytes) are rejected with HTTP 413."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]
        tok = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"])["access_token"]
        auth_hdr = {"Authorization": f"Bearer {tok}"}

        # Construct payload > 256 KB (270,000 bytes)
        large_payload = {
            "jsonrpc": "2.0",
            "id": "oversized-1",
            "method": "tools/list",
            "padding": "x" * 270_000,
        }
        r_big = gw_client.post("/mcp/autonomous", headers=auth_hdr, json=large_payload)
        assert r_big.status_code == 413, r_big.text
        data = r_big.json()
        assert data["error"]["code"] == -32600
        assert "Payload Too Large" in data["error"]["message"]

    # -------------------------------------------------------------------------
    # Test 08 — Excessive Task Submissions Rate Limit (H01 / H04)
    # -------------------------------------------------------------------------
    def test_08_excessive_task_submissions_rate_limit_h01_h04(self, sec_fixture: dict[str, Any]) -> None:
        """Verify task submission rate limit triggers HTTP 429 after 10 requests per minute."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]
        approved_ws: Path = sec_fixture["approved_ws"]

        tok_alpha = _issue_oauth_token("rate_limited_client", sec_fixture["oauth_signing_key"])["access_token"]
        tok_gamma = _issue_oauth_token("separate_client_gamma", sec_fixture["oauth_signing_key"])["access_token"]
        submit_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "agent_submit_task",
                "arguments": {
                    "objective": "Rate limit probe task",
                    "workspace_root": str(approved_ws),
                },
            },
        }

        # Submissions 1 through 10 succeed
        for i in range(10):
            r = gw_client.post(
                "/mcp/autonomous",
                headers={"Authorization": f"Bearer {tok_alpha}"},
                json=submit_payload,
            )
            assert r.status_code == 200, f"Request {i+1} failed: {r.text}"

        # 11th submission from same caller is rejected with HTTP 429
        r_11 = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json=submit_payload,
        )
        assert r_11.status_code == 429, r_11.text
        data_11 = r_11.json()
        assert data_11["error"]["code"] == -32005
        assert "Rate limit exceeded" in data_11["error"]["message"]

        # Different client is not blocked by rate_limited_client's quota
        r_gamma = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_gamma}"},
            json=submit_payload,
        )
        assert r_gamma.status_code == 200, r_gamma.text

    # -------------------------------------------------------------------------
    # Test 09 — Cross-Client Task Status & List Isolation (H02)
    # -------------------------------------------------------------------------
    def test_09_cross_client_task_status_and_list_isolation_h02(self, sec_fixture: dict[str, Any]) -> None:
        """Verify client_beta cannot query or list tasks submitted by client_alpha."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]
        approved_ws: Path = sec_fixture["approved_ws"]
        handler: AgentMCPToolHandler = sec_fixture["handler"]

        tok_alpha = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"])["access_token"]
        tok_beta = _issue_oauth_token("client_beta", sec_fixture["oauth_signing_key"])["access_token"]

        # 1. client_alpha submits task_alpha
        r_sub = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json={
                "jsonrpc": "2.0",
                "id": "sub-1",
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Confidential Alpha Research Project",
                        "workspace_root": str(approved_ws),
                    },
                },
            },
        )
        assert r_sub.status_code == 200, r_sub.text
        sub_content = json.loads(r_sub.json()["result"]["content"][0]["text"])
        task_alpha_id = sub_content["task_id"]
        assert task_alpha_id.startswith("task_")

        # 2. client_beta attempts to query agent_task_status for task_alpha -> FORBIDDEN
        r_status = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_beta}"},
            json={
                "jsonrpc": "2.0",
                "id": "st-1",
                "method": "tools/call",
                "params": {
                    "name": "agent_task_status",
                    "arguments": {"task_id": task_alpha_id},
                },
            },
        )
        assert r_status.status_code == 200, r_status.text
        res_rpc = r_status.json()["result"]
        assert res_rpc["isError"] is True
        status_data = json.loads(res_rpc["content"][0]["text"])
        assert status_data.get("status") == "FORBIDDEN"
        assert "Permission Denied (H02)" in status_data.get("error", "")

        # Direct handler check also denies client_beta
        direct_res = handler.execute_tool(
            "agent_task_status",
            {"task_id": task_alpha_id},
            surface="cloud_autonomous",
            caller_id="client_beta",
        )
        assert direct_res.get("status") == "FORBIDDEN"

        # 3. client_beta lists tasks -> task_alpha must NOT appear in beta's view
        r_list_b = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_beta}"},
            json={
                "jsonrpc": "2.0",
                "id": "list-b",
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        list_b_data = json.loads(r_list_b.json()["result"]["content"][0]["text"])
        b_task_ids = [t["task_id"] for t in list_b_data.get("tasks", [])]
        assert task_alpha_id not in b_task_ids

        # 4. client_alpha lists tasks -> task_alpha MUST be present
        r_list_a = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json={
                "jsonrpc": "2.0",
                "id": "list-a",
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        list_a_data = json.loads(r_list_a.json()["result"]["content"][0]["text"])
        a_task_ids = [t["task_id"] for t in list_a_data.get("tasks", [])]
        assert task_alpha_id in a_task_ids

    # -------------------------------------------------------------------------
    # Test 10 — Cross-Client Task Logs, Diff, and Artifacts Isolation (H02)
    # -------------------------------------------------------------------------
    def test_10_cross_client_task_logs_diff_artifacts_isolation_h02(self, sec_fixture: dict[str, Any]) -> None:
        """Verify client_beta cannot access logs, diff, or artifacts of task_alpha."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]
        approved_ws: Path = sec_fixture["approved_ws"]
        handler: AgentMCPToolHandler = sec_fixture["handler"]

        tok_alpha = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"])["access_token"]
        tok_beta = _issue_oauth_token("client_beta", sec_fixture["oauth_signing_key"])["access_token"]

        # Submit task by client_alpha
        r_sub = gw_client.post(
            "/mcp/autonomous",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json={
                "jsonrpc": "2.0",
                "id": "sub-10",
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Confidential Source Code Modification",
                        "workspace_root": str(approved_ws),
                    },
                },
            },
        )
        task_alpha_id = json.loads(r_sub.json()["result"]["content"][0]["text"])["task_id"]

        # Cross-client calls from client_beta across inspection tools
        for tool_name in ("agent_task_logs", "agent_task_diff", "agent_task_artifacts"):
            # A. Over HTTP JSON-RPC
            r = gw_client.post(
                "/mcp/autonomous",
                headers={"Authorization": f"Bearer {tok_beta}"},
                json={
                    "jsonrpc": "2.0",
                    "id": f"call-{tool_name}",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {"task_id": task_alpha_id}},
                },
            )
            res_rpc = r.json()["result"]
            assert res_rpc["isError"] is True, f"{tool_name} was not marked as isError"
            content = json.loads(res_rpc["content"][0]["text"])
            assert content.get("status") == "FORBIDDEN"
            assert "Permission Denied (H02)" in content.get("error", "")

            # B. Direct tool handler invocation
            direct = handler.execute_tool(
                tool_name,
                {"task_id": task_alpha_id},
                surface="cloud_autonomous",
                caller_id="client_beta",
            )
            assert direct.get("status") == "FORBIDDEN"

        # Also verify lifecycle management tools are denied across clients
        for ctrl_tool in ("agent_task_pause", "agent_task_resume", "agent_task_cancel"):
            ctrl_res = handler.execute_tool(
                ctrl_tool,
                {"task_id": task_alpha_id},
                surface="cloud_autonomous",
                caller_id="client_beta",
            )
            assert ctrl_res.get("status") in ("FORBIDDEN", "REJECTED")

            # On local surface with non-owner caller, returns FORBIDDEN (H02)
            ctrl_res_local = handler.execute_tool(
                ctrl_tool,
                {"task_id": task_alpha_id},
                surface="local",
                caller_id="client_beta",
            )
            assert ctrl_res_local.get("status") == "FORBIDDEN"

    # -------------------------------------------------------------------------
    # Test 11 — Confidential Workspace Boundary & Secret/Path Redaction (H02)
    # -------------------------------------------------------------------------
    def test_11_confidential_workspace_boundary_and_secret_path_redaction_h02(
        self, sec_fixture: dict[str, Any]
    ) -> None:
        """Verify workspace boundary checks, path sanitization, and secret redaction."""
        gw_client: TestClient = sec_fixture["gw_client"]
        secret: str = sec_fixture["caller_token"]
        approved_ws: Path = sec_fixture["approved_ws"]
        unapproved_ws: Path = sec_fixture["unapproved_ws"]
        store: TaskStore = sec_fixture["store"]
        handler: AgentMCPToolHandler = sec_fixture["handler"]

        tok_alpha = _issue_oauth_token("client_alpha", sec_fixture["oauth_signing_key"])["access_token"]
        auth_hdr = {"Authorization": f"Bearer {tok_alpha}"}

        # ---------------------------------------------------------------------
        # 1. Unapproved Workspace Boundary Enforcement
        # ---------------------------------------------------------------------
        # Sibling directory outside preapproved roots
        r_sib = gw_client.post(
            "/mcp/autonomous",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": "unauth-sib",
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Access outside approved root",
                        "workspace_root": str(unapproved_ws),
                    },
                },
            },
        )
        assert r_sib.json()["result"]["isError"] is True
        sib_res = json.loads(r_sib.json()["result"]["content"][0]["text"])
        assert sib_res.get("status") == "REJECTED"
        assert "preapproved workspace allowlist" in sib_res.get("error", "")

        # System directory (e.g. C:\Windows\System32)
        r_sys = gw_client.post(
            "/mcp/autonomous",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": "unauth-sys",
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Target Windows system directory",
                        "workspace_root": "C:\\Windows\\System32",
                    },
                },
            },
        )
        assert r_sys.json()["result"]["isError"] is True
        sys_res = json.loads(r_sys.json()["result"]["content"][0]["text"])
        assert sys_res.get("status") == "REJECTED"
        assert "Workspace path or requested scope is invalid or forbidden" in sys_res.get("error", "")

        # ---------------------------------------------------------------------
        # 2. Secret and Path Redaction in Logs, Diffs, and Artifacts
        # ---------------------------------------------------------------------
        # Create approved task
        (approved_ws / "src").mkdir(exist_ok=True)
        mod_file_1 = approved_ws / "src" / "app.py"
        mod_file_2 = approved_ws / "src" / "worker.py"
        mod_file_1.write_text("print('app')", encoding="utf-8")
        mod_file_2.write_text("print('worker')", encoding="utf-8")

        task = store.create_task(
            "Security Redaction Test",
            workspace_root=approved_ws,
            client_id="client_alpha",
            owner_id="client_alpha",
        )
        tid = task.task_id

        # Update progress with modified files (stored as absolute host paths in tasks.db)
        store.update_task_progress(tid, files_modified=[str(mod_file_1), str(mod_file_2)])

        # Insert execution logs containing synthetic secrets
        # Note: bearer tokens and keys use synthetic test patterns passing release security scans
        dummy_bearer = "test_mcp_oat_1234567890abcdef1234567890"
        dummy_v2_tok = f"v2.synthetic_approval_nonce.{'a'*64}"
        dummy_dpapi = "dpapi: AQAAANCMnd8BFdERjHoAwE_synthetic_blob"  # gitleaks:allow  (synthetic regression fixture; reviewed)
        dummy_env = "config.env: SECRET_PRODUCTION_PASSWORD"
        dummy_key = SYNTHETIC_API_KEY

        store.log_event(tid, "RUN", f"Connecting with Bearer {dummy_bearer}", level="INFO")
        store.log_event(tid, "RUN", f"Verified approval token {dummy_v2_tok}", level="INFO")
        store.log_event(tid, "RUN", f"Loaded DPAPI secret: {dummy_dpapi}", level="INFO")
        store.log_event(tid, "RUN", f"Loaded environment: {dummy_env}", level="INFO")
        store.log_event(tid, "RUN", f"Call OpenAI with {dummy_key} succeeded", level="INFO")

        # A. Query agent_task_logs over /mcp/autonomous
        r_logs = gw_client.post(
            "/mcp/autonomous",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": "logs-redact",
                "method": "tools/call",
                "params": {"name": "agent_task_logs", "arguments": {"task_id": tid}},
            },
        )
        logs_text = r_logs.json()["result"]["content"][0]["text"]
        logs_data = json.loads(logs_text)
        log_messages = [l["message"] for l in logs_data["logs"]]
        all_logs_blob = " \n ".join(log_messages)

        # Raw secrets must NOT be present
        assert dummy_bearer not in all_logs_blob
        assert dummy_v2_tok not in all_logs_blob
        assert dummy_dpapi not in all_logs_blob
        assert dummy_key not in all_logs_blob

        # Replaced with standard redaction markers
        assert "Bearer [REDACTED_TOKEN]" in all_logs_blob
        assert "[REDACTED_APPROVAL_TOKEN]" in all_logs_blob
        assert "[REDACTED_DPAPI]" in all_logs_blob
        assert "[REDACTED_SECRET]" in all_logs_blob
        assert "[REDACTED_API_KEY]" in all_logs_blob

        # B. Query agent_task_artifacts over /mcp/autonomous
        r_art = gw_client.post(
            "/mcp/autonomous",
            headers=auth_hdr,
            json={
                "jsonrpc": "2.0",
                "id": "art-redact",
                "method": "tools/call",
                "params": {"name": "agent_task_artifacts", "arguments": {"task_id": tid}},
            },
        )
        art_data = json.loads(r_art.json()["result"]["content"][0]["text"])

        # workspace_root must NOT be leaked on cloud_autonomous surface
        assert "workspace_root" not in art_data

        # files_modified must be strictly relative paths, not raw absolute host paths
        files_mod = art_data.get("files_modified", [])
        assert files_mod == ["src/app.py", "src/worker.py"]
        for f in files_mod:
            assert not f.startswith("C:")
            assert not f.startswith("D:")
            assert "\\" not in f

        # C. Query agent_task_diff and verify redaction
        diff_res = handler.execute_tool(
            "agent_task_diff",
            {"task_id": tid},
            surface="cloud_autonomous",
            caller_id="client_alpha",
        )
        assert "files_modified" in diff_res
        assert diff_res["files_modified"] == ["src/app.py", "src/worker.py"]

        # Synthetic git diff with embedded API key is redacted
        raw_diff_sample = f"+ Found key: {SYNTHETIC_API_KEY}\n+ Bearer {dummy_bearer}"
        redacted_diff = redact_task_output(raw_diff_sample)
        assert SYNTHETIC_API_KEY not in redacted_diff
        assert "[REDACTED_API_KEY]" in redacted_diff
        assert "Bearer [REDACTED_TOKEN]" in redacted_diff
