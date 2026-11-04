"""Comprehensive Penetration & Regression Tests for Findings H05, H06, H07 (Sprint 5.4).

Verifies the complete HTTP authentication-to-task-handler pipeline:
  - Test 01: H05 Protected Resource & Authorization Server Metadata + Tool securitySchemes
  - Test 02: H05 Complete OAuth 2.1 Authorization Code + PKCE S256 Flow & Negative PKCE Controls
  - Test 03: H06 Mandatory Check 1: Shared Token + Forged Client B Header -> DENY (403 / -32003)
  - Test 04: H06 Mandatory Check 2: Client A Requesting a Token for Client B -> DENY (401/403)
  - Test 05: H06 Mandatory Check 3 & 7: Forged OAuth Identity & Unexpected Owner Identity -> DENY (403)
  - Test 06: H06 Mandatory Checks 4, 5, 6: HTTP Auth-to-Task-Handler Multi-Client Isolation (A vs B)
  - Test 07: H07 Durable Revocation Persistence Across Adapter App Recreations (SQLite WAL)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
for _p in (str(PROJECT_ROOT), str(GATEWAY_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from http_server import _issue_oauth_token  # noqa: E402
from policy import SecurityPolicy  # noqa: E402
from runtime.agent_mcp_tools import (  # noqa: E402
    AgentMCPToolHandler,
    CLOUD_SAFE_AUTONOMOUS_TOOLS,
)
from runtime.task_grant import TaskGrantBroker  # noqa: E402
from runtime.task_store import TaskStore  # noqa: E402

TEST_CALLER_SECRET = "test_caller_secret_sprint54_h0567"
CHATGPT_REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"


@pytest.fixture
def sec_env() -> Generator[dict[str, Any], None, None]:
    """Provide an isolated, fully configured test environment for Sprint 5.4 penetration tests."""
    base_dir = Path(tempfile.mkdtemp(prefix="sprint54_sec_"))
    db_path = base_dir / "tasks_and_oauth.db"
    approved_ws = base_dir / "approved_ws"
    approved_ws.mkdir(parents=True, exist_ok=True)

    # Initialize a clean git repository for git diff support
    subprocess.run(["git", "init"], cwd=str(approved_ws), capture_output=True, check=False)
    subprocess.run(
        ["git", "config", "user.name", "SecurityTester"],
        cwd=str(approved_ws),
        capture_output=True,
        check=False,
    )
    subprocess.run(
        ["git", "config", "user.email", "sec@example.com"],
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
        "approved_ws": approved_ws,
        "store": store,
        "policy": policy,
        "broker": broker,
        "gateway": gateway,
        "handler": handler,
        "caller_token": TEST_CALLER_SECRET,
        "adapter_app": adapter_app,
        "client": client,
    }

    try:
        shutil.rmtree(str(base_dir), ignore_errors=True)
    except Exception:
        pass


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate RFC 7636 code_verifier and S256 code_challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _perform_full_pkce_oauth_flow(
    client: TestClient,
    owner_token: str,
    client_name: str = "ChatGPT Autonomous Connector",
    redirect_uri: str = CHATGPT_REDIRECT_URI,
    state: str = "test_pkce_state",
) -> dict[str, Any]:
    """Helper to execute full OAuth 2.1 registration + PKCE S256 authorization code exchange."""
    # 1. Register Client
    reg_resp = client.post(
        "/oauth/register",
        json={"client_name": client_name, "redirect_uris": [redirect_uri]},
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    client_id = reg_data["client_id"]
    client_secret = reg_data["client_secret"]

    # 2. Generate PKCE S256 parameters
    code_verifier, code_challenge = _generate_pkce_pair()

    # 3. Owner Consent & Authorization Code (Sprint 5.5: GET /oauth/authorize -> CSRF token -> POST /oauth/authorize)
    get_resp = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
    )
    assert get_resp.status_code == 200
    csrf_token = get_resp.headers.get("x-oauth-csrf-token")
    assert csrf_token and csrf_token.startswith("mcp_csrf_")

    auth_resp = client.post(
        "/oauth/authorize",
        data={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "decision": "allow",
            "owner_token": owner_token,
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    loc = auth_resp.headers["Location"]
    parsed = urllib.parse.urlparse(loc)
    qs = urllib.parse.parse_qs(parsed.query)
    code = qs["code"][0]
    assert code.startswith("mcp_ac_")
    if state:
        assert qs.get("state", [""])[0] == state

    # 4. Token Exchange
    token_resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()
    assert token_data["access_token"].startswith("mcp_oat_")
    assert token_data["refresh_token"].startswith("mcp_ort_")

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "authorization_code": code,
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"],
    }


class TestSprint54_SecurityPenetration:
    """Sprint 5.4 Comprehensive Penetration & Regression Suite for Findings H05, H06, H07."""

    # =========================================================================
    # Test 01: H05 Protected Resource & Authorization Server Metadata + Tools
    # =========================================================================
    def test_01_metadata_discovery_and_security_schemes(self, sec_env: dict[str, Any]) -> None:
        """Verify discovery endpoints RFC 8414/RFC 9207, WWW-Authenticate headers, and tool securitySchemes."""
        client = sec_env["client"]
        caller_secret = sec_env["caller_token"]

        # 1. Protected Resource Metadata Endpoints
        pr_paths = [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource/mcp/autonomous",
        ]
        for path in pr_paths:
            res = client.get(path)
            assert res.status_code == 200, f"Failed GET {path}"
            data = res.json()
            assert "resource" in data
            assert "authorization_servers" in data
            assert isinstance(data["authorization_servers"], list)
            assert "scopes_supported" in data
            assert "mcp:autonomous" in data["scopes_supported"]
            assert data.get("bearer_methods_supported") == ["header"]

        # 2. Authorization Server Metadata Endpoints
        as_paths = [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        ]
        for path in as_paths:
            res = client.get(path)
            assert res.status_code == 200, f"Failed GET {path}"
            data = res.json()
            assert data["authorization_endpoint"] == "/oauth/authorize"
            assert data["token_endpoint"] == "/oauth/token"
            assert data["revocation_endpoint"] == "/oauth/revoke"
            assert data["registration_endpoint"] == "/oauth/register"
            assert data["code_challenge_methods_supported"] == ["S256"]
            assert "authorization_code" in data["grant_types_supported"]
            assert "refresh_token" in data["grant_types_supported"]
            assert "client_credentials" in data["grant_types_supported"]

        # 3. WWW-Authenticate on 401 includes resource_metadata and scope="mcp:autonomous"
        for endpoint in ("/mcp", "/mcp/autonomous"):
            unauth_res = client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            assert unauth_res.status_code == 401
            www_auth = unauth_res.headers.get("www-authenticate", "")
            assert 'resource_metadata="/.well-known/oauth-protected-resource"' in www_auth
            assert 'scope="mcp:autonomous"' in www_auth

        # 4. tools/list on /mcp and /mcp/autonomous includes securitySchemes on all 6 Cloud-Safe tools
        for endpoint in ("/mcp", "/mcp/autonomous"):
            auth_res = client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                headers={"Authorization": f"Bearer {caller_secret}"},
            )
            assert auth_res.status_code == 200
            res_data = auth_res.json()
            assert "result" in res_data
            tools = res_data["result"]["tools"]
            assert len(tools) == len(CLOUD_SAFE_AUTONOMOUS_TOOLS)

            tool_names = {t["name"] for t in tools}
            assert tool_names == set(CLOUD_SAFE_AUTONOMOUS_TOOLS)

            expected_schemes = (
                [{"type": "noauth"}],
                [{"type": "oauth2", "scopes": ["mcp:autonomous"]}],
            )
            for t in tools:
                assert "securitySchemes" in t, f"Tool {t['name']} is missing securitySchemes"
                assert t["securitySchemes"] in expected_schemes, f"Tool {t['name']} invalid securitySchemes"

    # =========================================================================
    # Test 02: H05 Complete OAuth 2.1 Authorization Code + PKCE S256 Flow
    # =========================================================================
    def test_02_oauth21_pkce_s256_full_lifecycle_and_negative_controls(
        self, sec_env: dict[str, Any]
    ) -> None:
        """Verify RFC 7636 / RFC 9207 PKCE S256 authorization code exchange, replay protection, and refresh lifecycle."""
        client = sec_env["client"]
        caller_secret = sec_env["caller_token"]

        # 1. Register Client via POST /oauth/register
        reg_payload = {
            "client_name": "ChatGPT Autonomous Connector",
            "redirect_uris": [CHATGPT_REDIRECT_URI],
        }
        reg_res = client.post("/oauth/register", json=reg_payload)
        assert reg_res.status_code == 201
        reg_data = reg_res.json()
        client_id = reg_data["client_id"]
        client_secret = reg_data["client_secret"]
        assert client_id.startswith("mcp_client_")
        assert client_secret.startswith("mcp_sec_")

        # 2. RFC 7636 S256 Verifier & Challenge
        code_verifier, code_challenge = _generate_pkce_pair()

        # Negative Check A: Calling /oauth/authorize without code_challenge or with plain
        no_challenge_res = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
            },
        )
        assert no_challenge_res.status_code == 400
        assert no_challenge_res.json()["error"] == "invalid_request"

        plain_challenge_res = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": "plain_test_challenge",
                "code_challenge_method": "plain",
            },
        )
        assert plain_challenge_res.status_code == 400
        assert plain_challenge_res.json()["error"] == "invalid_request"

        # Negative Check B: Calling /oauth/authorize with untrusted redirect_uri
        evil_redirect_res = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://evil.example.com/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        assert evil_redirect_res.status_code == 400
        assert evil_redirect_res.json()["error"] == "invalid_request"

        # Sprint 5.5: Explicit assertion that passing owner credentials in URL query parameters returns HTTP 400
        leak_res = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "owner_token": caller_secret,
            },
        )
        assert leak_res.status_code == 400
        assert leak_res.json()["error"] == "invalid_request"
        assert "URL query parameters" in leak_res.json()["error_description"]

        # 3. Positive Consent & Redirect via GET /oauth/authorize -> POST /oauth/authorize
        get_res = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": "sprint54_pkce_test_state",
            },
        )
        assert get_res.status_code == 200
        csrf_tok = get_res.headers.get("x-oauth-csrf-token")
        assert csrf_tok and csrf_tok.startswith("mcp_csrf_")

        auth_res = client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": "sprint54_pkce_test_state",
                "decision": "allow",
                "owner_token": caller_secret,
                "csrf_token": csrf_tok,
            },
            follow_redirects=False,
        )
        assert auth_res.status_code == 302
        loc = auth_res.headers["Location"]
        assert loc.startswith(CHATGPT_REDIRECT_URI)
        parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        auth_code = parsed_qs["code"][0]
        assert auth_code.startswith("mcp_ac_")
        assert parsed_qs["state"][0] == "sprint54_pkce_test_state"

        # Negative Check C: Wrong code_verifier on token exchange
        # Create a separate authorization code specifically for wrong verifier test
        get_res_neg_c = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        assert get_res_neg_c.status_code == 200
        csrf_tok_neg_c = get_res_neg_c.headers.get("x-oauth-csrf-token")
        auth_res_for_neg_c = client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": CHATGPT_REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "decision": "allow",
                "owner_token": caller_secret,
                "csrf_token": csrf_tok_neg_c,
            },
            follow_redirects=False,
        )
        neg_c_code = urllib.parse.parse_qs(
            urllib.parse.urlparse(auth_res_for_neg_c.headers["Location"]).query
        )["code"][0]

        wrong_verifier = "wrong_code_verifier_1234567890_abcdefghijklmnopqrstuvwxyz"
        bad_token_res = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": neg_c_code,
                "code_verifier": wrong_verifier,
                "redirect_uri": CHATGPT_REDIRECT_URI,
            },
        )
        assert bad_token_res.status_code == 400
        assert bad_token_res.json()["error"] == "invalid_grant"
        assert "PKCE S256" in bad_token_res.json()["error_description"]

        # 4. Positive Token Exchange with valid code and valid code_verifier
        token_res = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code,
                "code_verifier": code_verifier,
                "redirect_uri": CHATGPT_REDIRECT_URI,
            },
        )
        assert token_res.status_code == 200
        tok_body = token_res.json()
        access_tok = tok_body["access_token"]
        refresh_tok = tok_body["refresh_token"]
        assert access_tok.startswith("mcp_oat_")
        assert refresh_tok.startswith("mcp_ort_")
        assert tok_body["token_type"] == "Bearer"

        # Negative Check D: Replaying the same authorization code a second time
        replay_res = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code,
                "code_verifier": code_verifier,
                "redirect_uri": CHATGPT_REDIRECT_URI,
            },
        )
        assert replay_res.status_code == 400
        assert replay_res.json()["error"] == "invalid_grant"

        # 5. Refresh Token Lifecycle: Exchange refresh_token for fresh access token
        refresh_res = client.post(
            "/oauth/token",
            json={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_tok,
            },
        )
        assert refresh_res.status_code == 200
        fresh_body = refresh_res.json()
        fresh_access_tok = fresh_body["access_token"]
        assert fresh_access_tok.startswith("mcp_oat_")

        # Revoke the refresh_token via POST /oauth/revoke
        revoke_res = client.post("/oauth/revoke", json={"token": refresh_tok})
        assert revoke_res.status_code == 200

        # Subsequent refresh attempt with revoked token must fail (400 / invalid_grant)
        failed_refresh = client.post(
            "/oauth/token",
            json={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_tok,
            },
        )
        assert failed_refresh.status_code in (400, 401, 403)
        assert failed_refresh.json()["error"] == "invalid_grant"

    # =========================================================================
    # Test 03: H06 Mandatory Check 1: Shared Token + Forged Client B Header -> DENY
    # =========================================================================
    def test_03_shared_token_forged_caller_id_deny(self, sec_env: dict[str, Any]) -> None:
        """Verify that shared bearer token cannot spoof client identity via X-MCP-Caller-Id (403 / -32003)."""
        client = sec_env["client"]
        shared_secret = sec_env["caller_token"]

        forged_identities = ["client_b", "client_alpha", "intruder_client"]
        rpc_payload = {"jsonrpc": "2.0", "id": 101, "method": "tools/list"}

        for forged_id in forged_identities:
            for endpoint in ("/mcp", "/mcp/autonomous"):
                res = client.post(
                    endpoint,
                    json=rpc_payload,
                    headers={
                        "Authorization": f"Bearer {shared_secret}",
                        "X-MCP-Caller-Id": forged_id,
                    },
                )
                assert res.status_code == 403, f"Expected 403 for forged {forged_id} on {endpoint}"
                data = res.json()
                assert data["error"]["code"] == -32003
                assert "cannot spoof or assume caller identity via x-mcp-caller-id" in data["error"]["message"].lower()

        # Valid control: Shared token without header or with allowed static principal succeeds
        valid_res = client.post(
            "/mcp",
            json=rpc_payload,
            headers={"Authorization": f"Bearer {shared_secret}"},
        )
        assert valid_res.status_code == 200

        valid_client_res = client.post(
            "/mcp",
            json=rpc_payload,
            headers={
                "Authorization": f"Bearer {shared_secret}",
                "X-MCP-Caller-Id": "chatgpt_cloud_client",
            },
        )
        assert valid_client_res.status_code == 200

    # =========================================================================
    # Test 04: H06 Mandatory Check 2: Client A Requesting a Token for Client B -> DENY
    # =========================================================================
    def test_04_client_a_requesting_token_for_client_b_deny(self, sec_env: dict[str, Any]) -> None:
        """Verify that Client A cannot request or mint credentials for registered Client B."""
        client = sec_env["client"]
        shared_secret = sec_env["caller_token"]

        # Register client_a and client_b
        res_a = client.post("/oauth/register", json={"client_name": "Client A"})
        assert res_a.status_code == 201
        client_a = res_a.json()["client_id"]
        secret_a = res_a.json()["client_secret"]

        res_b = client.post("/oauth/register", json={"client_name": "Client B"})
        assert res_b.status_code == 201
        client_b = res_b.json()["client_id"]
        secret_b = res_b.json()["client_secret"]

        # Attempt 1: Basic Auth (client_a, secret_a) with body {"client_id": client_b} or {"target_client_id": client_b}
        basic_a = base64.b64encode(f"{client_a}:{secret_a}".encode("utf-8")).decode("ascii")
        att1_a = client.post(
            "/oauth/token",
            headers={"Authorization": f"Basic {basic_a}"},
            json={"grant_type": "client_credentials", "client_id": client_b},
        )
        assert att1_a.status_code in (401, 403)
        assert att1_a.json()["error"] in ("invalid_client", "access_denied")

        att1_b = client.post(
            "/oauth/token",
            headers={"Authorization": f"Basic {basic_a}"},
            json={"grant_type": "client_credentials", "target_client_id": client_b},
        )
        assert att1_b.status_code in (401, 403)

        # Attempt 2: Body {"client_id": client_b, "client_secret": secret_a}
        att2 = client.post(
            "/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": client_b,
                "client_secret": secret_a,
            },
        )
        assert att2.status_code in (401, 403)
        assert att2.json()["error"] == "invalid_client"

        # Attempt 3: Body {"client_id": client_b, "client_secret": shared_secret}
        # Trying to use shared token to mint client_credentials for registered client_b
        att3 = client.post(
            "/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": client_b,
                "client_secret": shared_secret,
            },
        )
        assert att3.status_code in (401, 403)
        assert att3.json()["error"] == "invalid_client"

        # Attempt 4: Basic Auth (client_a, shared_secret) with header X-MCP-Caller-Id: client_b
        basic_shared = base64.b64encode(f"{client_a}:{shared_secret}".encode("utf-8")).decode("ascii")
        att4 = client.post(
            "/oauth/token",
            headers={
                "Authorization": f"Basic {basic_shared}",
                "X-MCP-Caller-Id": client_b,
            },
            json={"grant_type": "client_credentials"},
        )
        assert att4.status_code in (401, 403)
        assert att4.json()["error"] == "invalid_client"

    # =========================================================================
    # Test 05: H06 Mandatory Checks 3 & 7: Forged OAuth Identity & Owner Identity -> DENY
    # =========================================================================
    def test_05_forged_oauth_identity_and_unexpected_owner_deny(
        self, sec_env: dict[str, Any]
    ) -> None:
        """Verify token signature validation, unexpected owner_id rejection, and wrong audience/scope denial."""
        client = sec_env["client"]
        caller_secret = sec_env["adapter_app"].state.oauth_signing_key

        # Issue a legitimate token for client_alpha
        valid_tok_info = _issue_oauth_token(
            client_id="client_alpha",
            secret=caller_secret,
            scope="mcp:autonomous",
            owner_id="local_owner",
            resource="mcp-autonomous",
        )
        valid_token = valid_tok_info["access_token"]
        assert valid_token.startswith("mcp_oat_")

        # 1. Tamper with client_id / sub inside token payload (HMAC mismatch)
        raw_body = valid_token[len("mcp_oat_") :]
        payload_b64, sig = raw_body.split(".", 1)
        pad = len(payload_b64) % 4
        padded = payload_b64 + ("=" * (4 - pad) if pad else "")
        p_dict = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        p_dict["client_id"] = "attacker_client"
        p_dict["sub"] = "attacker_client"
        tampered_b64 = (
            base64.urlsafe_b64encode(json.dumps(p_dict, separators=(",", ":")).encode("utf-8"))
            .decode("ascii")
            .rstrip("=")
        )
        tampered_token = f"mcp_oat_{tampered_b64}.{sig}"

        for endpoint in ("/mcp", "/mcp/autonomous"):
            t_res = client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"Authorization": f"Bearer {tampered_token}"},
            )
            assert t_res.status_code == 403
            assert "Invalid OAuth token signature" in t_res.json()["error"]["message"]

        # 2. Token signed with secret but carrying owner_id="unexpected_foreign_owner"
        foreign_owner_tok = _issue_oauth_token(
            client_id="client_alpha",
            secret=caller_secret,
            scope="mcp:autonomous",
            owner_id="unexpected_foreign_owner",
            resource="mcp-autonomous",
        )["access_token"]

        for endpoint in ("/mcp", "/mcp/autonomous"):
            fo_res = client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                headers={"Authorization": f"Bearer {foreign_owner_tok}"},
            )
            assert fo_res.status_code == 403
            assert "Unexpected owner identity" in fo_res.json()["error"]["message"]

        # 3. Token signed with secret but carrying wrong audience / resource
        wrong_aud_tok = _issue_oauth_token(
            client_id="client_alpha",
            secret=caller_secret,
            scope="mcp:autonomous",
            owner_id="local_owner",
            resource="https://evil.example.com/api",
        )["access_token"]

        for endpoint in ("/mcp", "/mcp/autonomous"):
            wa_res = client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
                headers={"Authorization": f"Bearer {wrong_aud_tok}"},
            )
            assert wa_res.status_code == 403
            assert "Token audience/resource mismatch" in wa_res.json()["error"]["message"]

        # 4. Token signed with secret but carrying insufficient scope
        wrong_scope_tok = _issue_oauth_token(
            client_id="client_alpha",
            secret=caller_secret,
            scope="read_only",
            owner_id="local_owner",
            resource="mcp-autonomous",
        )["access_token"]

        for endpoint in ("/mcp", "/mcp/autonomous"):
            ws_res = client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                headers={"Authorization": f"Bearer {wrong_scope_tok}"},
            )
            assert ws_res.status_code == 403
            assert "Insufficient token scope" in ws_res.json()["error"]["message"]

        # 5. Header spoofing of owner: X-MCP-Owner-Id header mismatch
        spoof_owner_res = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
            headers={
                "Authorization": f"Bearer {valid_token}",
                "X-MCP-Owner-Id": "unexpected_foreign_owner",
            },
        )
        assert spoof_owner_res.status_code == 403
        assert "Unexpected owner identity" in spoof_owner_res.json()["error"]["message"]

    # =========================================================================
    # Test 06: H06 Mandatory Checks 4, 5, 6: Multi-Client Task Isolation
    # =========================================================================
    def test_06_http_auth_to_task_handler_multi_client_isolation(
        self, sec_env: dict[str, Any]
    ) -> None:
        """Verify strict multi-client isolation across the full HTTP auth -> task handler path."""
        client = sec_env["client"]
        caller_secret = sec_env["caller_token"]
        approved_ws = sec_env["approved_ws"]

        # 1. Authenticate Client A and Client B via full OAuth 2.1 PKCE flows
        session_a = _perform_full_pkce_oauth_flow(
            client,
            owner_token=caller_secret,
            client_name="ChatGPT Connector Client A",
            state="state_client_a",
        )
        session_b = _perform_full_pkce_oauth_flow(
            client,
            owner_token=caller_secret,
            client_name="ChatGPT Connector Client B",
            state="state_client_b",
        )
        token_a = session_a["access_token"]
        token_b = session_b["access_token"]
        client_a = session_a["client_id"]
        client_b = session_b["client_id"]
        assert client_a != client_b

        # 2. Client A submits Task A via HTTP POST /mcp
        submit_a_res = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "submit_a",
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Build secure component for Client A",
                        "workspace_root": str(approved_ws),
                    },
                },
            },
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert submit_a_res.status_code == 200
        data_a = json.loads(submit_a_res.json()["result"]["content"][0]["text"])
        task_a_id = data_a["task_id"]
        assert task_a_id

        # 3. Client B submits Task B via HTTP POST /mcp
        submit_b_res = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "submit_b",
                "method": "tools/call",
                "params": {
                    "name": "agent_submit_task",
                    "arguments": {
                        "objective": "Build independent component for Client B",
                        "workspace_root": str(approved_ws),
                    },
                },
            },
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert submit_b_res.status_code == 200
        data_b = json.loads(submit_b_res.json()["result"]["content"][0]["text"])
        task_b_id = data_b["task_id"]
        assert task_b_id != task_a_id

        # 4. Client A querying Client B's task -> Strictly FORBIDDEN
        read_tools_to_test = [
            ("agent_task_status", {"task_id": task_b_id}),
            ("agent_task_logs", {"task_id": task_b_id}),
            ("agent_task_diff", {"task_id": task_b_id}),
            ("agent_task_artifacts", {"task_id": task_b_id}),
        ]
        for tool_name, args in read_tools_to_test:
            leak_res = client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": f"leak_{tool_name}",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": args},
                },
                headers={"Authorization": f"Bearer {token_a}"},
            )
            assert leak_res.status_code == 200
            rpc_res = leak_res.json()["result"]
            assert rpc_res["isError"] is True
            parsed_text = json.loads(rpc_res["content"][0]["text"])
            assert parsed_text.get("status") == "FORBIDDEN"
            assert "Permission Denied (H02)" in parsed_text.get("error", "")

        # 5. Client B querying Client A's task -> Strictly FORBIDDEN
        reverse_leak = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "reverse_leak",
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task_a_id}},
            },
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert reverse_leak.status_code == 200
        rev_rpc = reverse_leak.json()["result"]
        assert rev_rpc["isError"] is True
        assert json.loads(rev_rpc["content"][0]["text"]).get("status") == "FORBIDDEN"

        # 6. Client A querying own Task A -> SUCCESS
        own_res = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "own_stat",
                "method": "tools/call",
                "params": {"name": "agent_task_status", "arguments": {"task_id": task_a_id}},
            },
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert own_res.status_code == 200
        own_rpc = own_res.json()["result"]
        assert own_rpc.get("isError", False) is False
        assert json.loads(own_rpc["content"][0]["text"])["task_id"] == task_a_id

        # 7. List Tasks Isolation: Client A only sees Task A; Client B only sees Task B
        list_a = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "list_a",
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert list_a.status_code == 200
        tasks_seen_by_a = [
            t["task_id"]
            for t in json.loads(list_a.json()["result"]["content"][0]["text"])["tasks"]
        ]
        assert task_a_id in tasks_seen_by_a
        assert task_b_id not in tasks_seen_by_a

        list_b = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "list_b",
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert list_b.status_code == 200
        tasks_seen_by_b = [
            t["task_id"]
            for t in json.loads(list_b.json()["result"]["content"][0]["text"])["tasks"]
        ]
        assert task_b_id in tasks_seen_by_b
        assert task_a_id not in tasks_seen_by_b

        # 8. Missing authenticated identity -> 401 DENY
        unauth_submit = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": "unauth_sub",
                "method": "tools/call",
                "params": {"name": "agent_list_tasks", "arguments": {}},
            },
        )
        assert unauth_submit.status_code == 401

    # =========================================================================
    # Test 07: H07 Durable Revocation Persistence Across Adapter App Recreations
    # =========================================================================
    def test_07_durable_revocation_persistence_across_recreation(
        self, sec_env: dict[str, Any]
    ) -> None:
        """Verify that token revocation survives adapter application recreation / process restart."""
        client = sec_env["client"]
        caller_secret = sec_env["caller_token"]
        db_path = sec_env["db_path"]
        gateway = sec_env["gateway"]

        # 1. Obtain two valid tokens for Client 1 and Client 2
        signing_key = sec_env["adapter_app"].state.oauth_signing_key
        tok1 = _issue_oauth_token(
            client_id="durable_client_1",
            secret=signing_key,
            scope="mcp:autonomous",
            owner_id="local_owner",
        )["access_token"]
        tok2 = _issue_oauth_token(
            client_id="durable_client_2",
            secret=signing_key,
            scope="mcp:autonomous",
            owner_id="local_owner",
        )["access_token"]

        rpc_list = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

        # 2. Both tokens initially succeed on current app instance
        res1_init = client.post(
            "/mcp", json=rpc_list, headers={"Authorization": f"Bearer {tok1}"}
        )
        assert res1_init.status_code == 200

        res2_init = client.post(
            "/mcp", json=rpc_list, headers={"Authorization": f"Bearer {tok2}"}
        )
        assert res2_init.status_code == 200

        # 3. Revoke tok1 via POST /oauth/revoke
        rev_res = client.post("/oauth/revoke", json={"token": tok1})
        assert rev_res.status_code == 200

        # 4. Immediate denial of tok1 on current app instance (403)
        res1_rev = client.post(
            "/mcp", json=rpc_list, headers={"Authorization": f"Bearer {tok1}"}
        )
        assert res1_rev.status_code == 403
        assert "revoked" in res1_rev.json()["error"]["message"].lower()

        # tok2 remains functional
        res2_ok = client.post(
            "/mcp", json=rpc_list, headers={"Authorization": f"Bearer {tok2}"}
        )
        assert res2_ok.status_code == 200

        # 5. Recreate a brand new adapter app instance pointing to the same db_path (restart simulation)
        recreated_app = create_cloud_autonomous_adapter_app(
            gateway=gateway,
            caller_auth_token=caller_secret,
            require_autonomous_auth=True,
            allow_loopback_tunnel_identity=False,
            db_path=db_path,
            enable_direct_coding=False,
        )
        recreated_client = TestClient(recreated_app)

        # 6. Verify tok1 REMAINS DENIED (403) on the recreated app
        recreated_res1 = recreated_client.post(
            "/mcp", json=rpc_list, headers={"Authorization": f"Bearer {tok1}"}
        )
        assert recreated_res1.status_code == 403, "Revoked token must remain denied after restart"
        assert "revoked" in recreated_res1.json()["error"]["message"].lower()

        # 7. Verify tok2 REMAINS FUNCTIONAL (200) on the recreated app
        recreated_res2 = recreated_client.post(
            "/mcp", json=rpc_list, headers={"Authorization": f"Bearer {tok2}"}
        )
        assert recreated_res2.status_code == 200, "Unrevoked token must remain functional after restart"
