"""Sprint 5.5 Section 2 — OAuth Metadata, PKCE, Consent, Redirect Validation & Security Audit Tests.

Verifies all 6 security and reachability audit controls:
  1. Reject owner credentials / secrets in URL query parameters (GET/POST /oauth/authorize, POST /oauth/token) -> 400.
  2. Reject unverified caller-supplied owner_id on POST /oauth/register (DCR security) -> 403.
  3. Enforce strict per-client redirect_uri matching (registered client cannot use unregistered URI) -> 400.
  4. Enforce CSRF token & Origin/Referer cross-origin validation on POST /oauth/authorize -> 403.
  5. Verify RFC 8414 OAuth Discovery Metadata (client_id_metadata_document_supported is False, response_types_supported == ["code"]).
  6. Complete PKCE S256 lifecycle: GET /oauth/authorize (CSRF) -> POST /oauth/authorize -> POST /oauth/token -> POST /mcp -> POST /oauth/revoke -> durable rejection.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Generator

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
for _p in (str(PROJECT_ROOT), str(GATEWAY_DIR), str(PROJECT_ROOT / "backend"), str(PROJECT_ROOT / "desktop-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from policy import SecurityPolicy  # noqa: E402
from runtime.agent_mcp_tools import AgentMCPToolHandler  # noqa: E402
from runtime.oauth_store import DurableOAuthStore  # noqa: E402
from runtime.task_grant import TaskGrantBroker  # noqa: E402
from runtime.task_store import TaskStore  # noqa: E402

TEST_CALLER_SECRET = "sec_test_sprint55_owner_token_abc123"
CHATGPT_REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"


@pytest.fixture
def audit_env() -> Generator[dict[str, Any], None, None]:
    """Isolated test environment for Sprint 5.5 OAuth security audit."""
    base_dir = Path(tempfile.mkdtemp(prefix="sprint55_audit_"))
    db_path = base_dir / "audit_oauth.db"
    ws = base_dir / "workspace"
    ws.mkdir(parents=True, exist_ok=True)

    subprocess.run(["git", "init"], cwd=str(ws), capture_output=True, check=False)
    subprocess.run(["git", "config", "user.name", "AuditTester"], cwd=str(ws), capture_output=True, check=False)
    subprocess.run(["git", "config", "user.email", "audit@example.com"], cwd=str(ws), capture_output=True, check=False)

    store = TaskStore(db_path)
    policy = SecurityPolicy(profile="read_only")
    broker = TaskGrantBroker(policy=policy, db_path=db_path, preapproved_roots=[ws], require_preapproved_roots=True)
    gateway = MCPGatewayServer(policy=policy)
    gateway.store = store
    handler = AgentMCPToolHandler(store, broker)
    gateway._agent_tool_handler = handler

    adapter_app = create_cloud_autonomous_adapter_app(
        gateway=gateway,
        caller_auth_token=TEST_CALLER_SECRET,
        require_autonomous_auth=True,
        allow_loopback_tunnel_identity=False,
        db_path=db_path,
        enable_direct_coding=False,
    )
    client = TestClient(adapter_app)

    yield {
        "base_dir": base_dir,
        "db_path": db_path,
        "ws": ws,
        "store": store,
        "broker": broker,
        "gateway": gateway,
        "caller_token": TEST_CALLER_SECRET,
        "adapter_app": adapter_app,
        "client": client,
    }

    try:
        shutil.rmtree(str(base_dir), ignore_errors=True)
    except Exception:
        pass


def _generate_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


class TestSprint55_OAuthSecurityAudit:
    """Security audit tests implementing Sprint 5.5 Section 2 requirements."""

    # =========================================================================
    # 1. Reject Owner Credentials / Secrets in Query Parameters -> 400
    # =========================================================================
    def test_01_reject_credentials_in_url_query_parameters(self, audit_env: dict[str, Any]) -> None:
        client: TestClient = audit_env["client"]
        token = audit_env["caller_token"]
        _, challenge = _generate_pkce()

        # A: GET /oauth/authorize with owner_token in query -> 400
        res_get_owner = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "test_client_query",
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "owner_token": token,
            },
        )
        assert res_get_owner.status_code == 400
        assert res_get_owner.json()["error"] == "invalid_request"
        assert "Security Policy Violation (Sprint 5.5)" in res_get_owner.json()["error_description"]

        # B: GET /oauth/authorize with owner_password in query -> 400
        res_get_pw = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "test_client_query",
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "owner_password": "super_secret_pw",
            },
        )
        assert res_get_pw.status_code == 400
        assert res_get_pw.json()["error"] == "invalid_request"

        # C: GET /oauth/authorize with client_secret in query -> 400
        res_get_sec = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "test_client_query",
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "client_secret": "secret_abc",
            },
        )
        assert res_get_sec.status_code == 400
        assert res_get_sec.json()["error"] == "invalid_request"

        # D: GET /oauth/authorize with access_token in query -> 400
        res_get_acc = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "test_client_query",
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "access_token": "token_xyz",
            },
        )
        assert res_get_acc.status_code == 400
        assert res_get_acc.json()["error"] == "invalid_request"

        # E: POST /oauth/authorize with owner_token in query -> 400
        res_post_auth = client.post(
            "/oauth/authorize?owner_token=secret_in_url",
            data={
                "client_id": "test_client_query",
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert res_post_auth.status_code == 400
        assert res_post_auth.json()["error"] == "invalid_request"

        # F: POST /oauth/token with client_secret in query -> 400
        res_post_tok = client.post(
            "/oauth/token?client_secret=secret_in_url",
            json={"grant_type": "client_credentials", "client_id": "test_client_query"},
        )
        assert res_post_tok.status_code == 400
        assert res_post_tok.json()["error"] == "invalid_request"

    # =========================================================================
    # 2. Reject Unverified Caller-Supplied owner_id in POST /oauth/register -> 403
    # =========================================================================
    def test_02_dcr_owner_id_security(self, audit_env: dict[str, Any]) -> None:
        client: TestClient = audit_env["client"]
        owner_tok = audit_env["caller_token"]

        # A: Foreign owner_id without auth -> 403
        res_foreign_unauth = client.post(
            "/oauth/register",
            json={
                "client_name": "Foreign Client",
                "redirect_uris": [CHATGPT_REDIRECT_URI],
                "owner_id": "attacker_or_foreign_owner",
            },
        )
        assert res_foreign_unauth.status_code == 403
        assert res_foreign_unauth.json()["error"] == "access_denied"
        assert "unverified or foreign owner_id" in res_foreign_unauth.json()["error_description"]

        # B: Foreign owner_id EVEN WITH valid owner auth header -> 403
        res_foreign_auth = client.post(
            "/oauth/register",
            headers={"Authorization": f"Bearer {owner_tok}"},
            json={
                "client_name": "Foreign Client",
                "redirect_uris": [CHATGPT_REDIRECT_URI],
                "owner_id": "foreign_owner_999",
            },
        )
        assert res_foreign_auth.status_code == 403
        assert res_foreign_auth.json()["error"] == "access_denied"

        # C: Supplying owner_id == "local_owner" WITHOUT authentication -> 403
        res_expected_unauth = client.post(
            "/oauth/register",
            json={
                "client_name": "Local Client",
                "redirect_uris": [CHATGPT_REDIRECT_URI],
                "owner_id": "local_owner",
            },
        )
        assert res_expected_unauth.status_code == 403
        assert res_expected_unauth.json()["error"] == "access_denied"
        assert "requires valid owner authentication" in res_expected_unauth.json()["error_description"]

        # D: Supplying owner_id == "local_owner" WITH valid authentication -> 201 Created
        res_expected_auth = client.post(
            "/oauth/register",
            headers={"Authorization": f"Bearer {owner_tok}"},
            json={
                "client_name": "Local Client Auth",
                "redirect_uris": [CHATGPT_REDIRECT_URI],
                "owner_id": "local_owner",
            },
        )
        assert res_expected_auth.status_code == 201
        assert res_expected_auth.json()["owner_id"] == "local_owner"

        # E: Normal DCR without owner_id (ChatGPT platform) -> 201 Created bound to local_owner
        res_normal_dcr = client.post(
            "/oauth/register",
            json={
                "client_name": "ChatGPT Standard Connector",
                "redirect_uris": [CHATGPT_REDIRECT_URI],
            },
        )
        assert res_normal_dcr.status_code == 201
        assert res_normal_dcr.json()["owner_id"] == "local_owner"

    # =========================================================================
    # 3. Strict Per-Client redirect_uri Matching -> 400
    # =========================================================================
    def test_03_strict_per_client_redirect_uri_matching(self, audit_env: dict[str, Any]) -> None:
        client: TestClient = audit_env["client"]
        _, challenge = _generate_pkce()

        # Register Client A with exact redirect_uri = CHATGPT_REDIRECT_URI
        reg_a = client.post(
            "/oauth/register",
            json={"client_name": "Client A", "redirect_uris": [CHATGPT_REDIRECT_URI]},
        )
        assert reg_a.status_code == 201
        client_a = reg_a.json()["client_id"]

        # A: Client A tries to use another chatgpt.com URI not in its registered list -> 400
        res_other_chatgpt = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_a,
                "redirect_uri": "https://chatgpt.com/other_unregistered_callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert res_other_chatgpt.status_code == 400
        assert res_other_chatgpt.json()["error"] == "invalid_request"
        assert "invalid_redirect_uri" in res_other_chatgpt.json()["error_description"]

        # B: Client A tries to use a loopback URI not in its registered list -> 400
        res_loopback_unreg = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_a,
                "redirect_uri": "http://127.0.0.1:9999/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert res_loopback_unreg.status_code == 400
        assert res_loopback_unreg.json()["error"] == "invalid_request"

        # C: Client A uses its EXACT registered URI -> 200 (renders consent form)
        res_exact = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_a,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert res_exact.status_code == 200

        # D: Unregistered client tries arbitrary evil URI -> 400
        res_unreg_evil = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "unregistered_client_xyz",
                "redirect_uri": "https://attacker.evil.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert res_unreg_evil.status_code == 400

    # =========================================================================
    # 4. CSRF Token & Origin / Referer Validation on POST /oauth/authorize -> 403
    # =========================================================================
    def test_04_csrf_token_and_origin_validation(self, audit_env: dict[str, Any]) -> None:
        client: TestClient = audit_env["client"]
        owner_tok = audit_env["caller_token"]
        _, challenge = _generate_pkce()

        reg = client.post(
            "/oauth/register",
            json={"client_name": "CSRF Test Client", "redirect_uris": [CHATGPT_REDIRECT_URI]},
        )
        client_id = reg.json()["client_id"]

        # 1. Obtain legitimate CSRF token via GET /oauth/authorize
        get_res = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "csrf_state_123",
            },
        )
        assert get_res.status_code == 200
        legit_csrf = get_res.headers["X-OAuth-CSRF-Token"]
        assert legit_csrf and legit_csrf.startswith("mcp_csrf_")

        # A: Cross-origin Origin header rejection -> 403
        res_evil_origin = client.post(
            "/oauth/authorize",
            headers={"Origin": "https://evil.attacker.com"},
            data={
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "csrf_state_123",
                "decision": "allow",
                "owner_token": owner_tok,
                "csrf_token": legit_csrf,
            },
        )
        assert res_evil_origin.status_code == 403
        assert res_evil_origin.json()["error"] == "access_denied"
        assert "Cross-origin consent submission denied" in res_evil_origin.json()["error_description"]

        # B: Cross-origin Referer header rejection -> 403
        res_evil_ref = client.post(
            "/oauth/authorize",
            headers={"Referer": "https://evil.attacker.com/malicious_form.html"},
            data={
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "csrf_state_123",
                "decision": "allow",
                "owner_token": owner_tok,
                "csrf_token": legit_csrf,
            },
        )
        assert res_evil_ref.status_code == 403

        # C: Tampered / forged CSRF token -> 403
        res_tampered_csrf = client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "csrf_state_123",
                "decision": "allow",
                "owner_token": owner_tok,
                "csrf_token": "mcp_csrf_fake_payload.fake_sig_12345678",
            },
        )
        assert res_tampered_csrf.status_code == 403
        assert "Invalid, expired, or tampered CSRF token" in res_tampered_csrf.json()["error_description"]

        # D: CSRF token generated for Client A used for Client B -> 403
        res_client_mismatch = client.post(
            "/oauth/authorize",
            data={
                "client_id": "other_client_id_forged",
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "csrf_state_123",
                "decision": "allow",
                "owner_token": owner_tok,
                "csrf_token": legit_csrf,
            },
        )
        assert res_client_mismatch.status_code in (400, 403)

        # E: Legitimate submission with valid CSRF token -> 302 Success
        res_ok = client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "csrf_state_123",
                "decision": "allow",
                "owner_token": owner_tok,
                "csrf_token": legit_csrf,
            },
            follow_redirects=False,
        )
        assert res_ok.status_code == 302
        assert "code=" in res_ok.headers["Location"]

    # =========================================================================
    # 5. Fix OAuth Discovery Metadata (CIMD False, response_types == ["code"])
    # =========================================================================
    def test_05_oauth_discovery_metadata_security(self, audit_env: dict[str, Any]) -> None:
        client: TestClient = audit_env["client"]

        res = client.get("/.well-known/oauth-authorization-server")
        assert res.status_code == 200
        meta = res.json()

        # CIMD must NOT be advertised as True because DCR is the implemented mechanism
        assert meta["client_id_metadata_document_supported"] is False

        # Only "code" supported (no implicit "token" grant)
        assert meta["response_types_supported"] == ["code"]

        # Endpoints must have both canonical and absolute URL fields
        assert meta["authorization_endpoint"] == "/oauth/authorize"
        assert meta["authorization_endpoint_url"].endswith("/oauth/authorize")
        assert meta["token_endpoint"] == "/oauth/token"
        assert meta["token_endpoint_url"].endswith("/oauth/token")
        assert meta["revocation_endpoint"] == "/oauth/revoke"
        assert meta["revocation_endpoint_url"].endswith("/oauth/revoke")
        assert meta["registration_endpoint"] == "/oauth/register"
        assert meta["registration_endpoint_url"].endswith("/oauth/register")

        # Reachability flag reflects lack of external HTTPS issuer by default
        assert meta["browser_oauth_reachable_via_private_tunnel"] is False
        assert meta["private_tunnel_auth_mode"] == "bearer_header_injection_or_external_https_idp"

        # Protected resource metadata
        pr_res = client.get("/.well-known/oauth-protected-resource")
        assert pr_res.status_code == 200
        pr_meta = pr_res.json()
        assert pr_meta["resource"] == "mcp-autonomous"
        assert "mcp:autonomous" in pr_meta["scopes_supported"]

    # =========================================================================
    # 6. Complete PKCE S256 Flow & Durable Revocation Pipeline
    # =========================================================================
    def test_06_complete_pkce_s256_flow_and_durable_revocation(self, audit_env: dict[str, Any]) -> None:
        client: TestClient = audit_env["client"]
        owner_tok = audit_env["caller_token"]
        db_path = audit_env["db_path"]

        # 1. Register Client
        reg = client.post(
            "/oauth/register",
            json={"client_name": "Full Flow Client", "redirect_uris": [CHATGPT_REDIRECT_URI]},
        )
        assert reg.status_code == 201
        c_id = reg.json()["client_id"]
        c_sec = reg.json()["client_secret"]

        # 2. Generate PKCE S256 parameters
        verifier, challenge = _generate_pkce()

        # 3. GET /oauth/authorize -> consent HTML & CSRF token
        get_auth = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": c_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "audit_full_flow_state",
            },
        )
        assert get_auth.status_code == 200
        assert "Authorize Autonomous Agent Access" in get_auth.text
        csrf = get_auth.headers.get("X-OAuth-CSRF-Token")
        assert csrf and csrf.startswith("mcp_csrf_")

        # 4. POST /oauth/authorize -> Authorization Code
        post_auth = client.post(
            "/oauth/authorize",
            data={
                "client_id": c_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "audit_full_flow_state",
                "decision": "allow",
                "owner_token": owner_tok,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert post_auth.status_code == 302
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(post_auth.headers["Location"]).query)
        auth_code = qs["code"][0]
        assert auth_code.startswith("mcp_ac_")

        # 5. POST /oauth/token -> Token Exchange
        tok_resp = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": c_id,
                "client_secret": c_sec,
                "code": auth_code,
                "code_verifier": verifier,
                "redirect_uri": CHATGPT_REDIRECT_URI,
            },
        )
        assert tok_resp.status_code == 200
        tokens = tok_resp.json()
        access_tok = tokens["access_token"]
        refresh_tok = tokens["refresh_token"]
        assert access_tok.startswith("mcp_oat_")
        assert refresh_tok.startswith("mcp_ort_")

        # 6. Authenticated MCP Handshake via POST /mcp
        mcp_resp = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {access_tok}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert mcp_resp.status_code == 200
        assert len(mcp_resp.json()["result"]["tools"]) == 6

        # 7. POST /oauth/revoke -> Revoke access_token
        rev_resp = client.post("/oauth/revoke", json={"token": access_tok})
        assert rev_resp.status_code == 200

        # 8. Subsequent call with revoked token -> 401/403 Unauthorized/Forbidden
        mcp_revoked = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {access_tok}"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert mcp_revoked.status_code in (401, 403)
        assert "revoked" in mcp_revoked.json()["error"]["message"].lower()

        # 9. Verify durable persistence across database re-read (H07)
        durable_store = DurableOAuthStore(db_path)
        assert durable_store.is_revoked(access_tok) is True
        durable_store.close()

    # =========================================================================
    # 7. Pending Task Diff Isolation & Noauth + Bearer Enforcement
    # =========================================================================
    def test_07_pending_task_diff_isolation_and_noauth_bearer_enforcement(
        self, audit_env: dict[str, Any]
    ) -> None:
        client: TestClient = audit_env["client"]
        caller_tok = audit_env["caller_token"]
        ws_path: Path = audit_env["ws"]
        ws_root = str(ws_path)

        # Create a tracked file and make the workspace git working tree dirty BEFORE task execution
        tracked_file = ws_path / "unrelated.py"
        tracked_file.write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "unrelated.py"], cwd=ws_root, capture_output=True, check=False)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=ws_root, capture_output=True, check=False)
        tracked_file.write_text("x = 999  # unrelated dirty edit\n", encoding="utf-8")

        # 1. Verify unauthenticated call to /mcp is still rejected with 401 even when tools advertise noauth
        unauth_res = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert unauth_res.status_code == 401

        # 2. Verify authenticated tools/list advertises [{"type": "noauth"}] by default
        list_res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {caller_tok}"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert list_res.status_code == 200
        tools = list_res.json()["result"]["tools"]
        assert len(tools) == 6
        for t in tools:
            assert t["securitySchemes"] == [{"type": "noauth"}]

        # 3. Submit a task (stays in AUTHORIZATION_PENDING, 0 executions, 0 modified files)
        sub_res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {caller_tok}"},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Verify pending task diff isolation",
                        "workspace_root": ws_root,
                    },
                },
            },
        )
        assert sub_res.status_code == 200
        sub_payload = json.loads(sub_res.json()["result"]["content"][0]["text"])
        task_id = sub_payload["task_id"]
        assert sub_payload["state"] == "AUTHORIZATION_PENDING"

        # 4. Call agent_task_diff on the AUTHORIZATION_PENDING task -> must NOT leak dirty workspace git diff
        diff_res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {caller_tok}"},
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "agent_task_diff",
                    "arguments": {"task_id": task_id},
                },
            },
        )
        assert diff_res.status_code == 200
        diff_payload = json.loads(diff_res.json()["result"]["content"][0]["text"])
        assert diff_payload["task_id"] == task_id
        assert diff_payload["files_modified"] == []
        assert diff_payload["git_diff"] == ""
