"""Phase 1-4 Acceptance Tests: Workstream A1 Grant Boundary, OWNER_AUTHORIZED_SECURITY_EDIT, Online Backup & Rollback."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
_GW_DIR = str(Path(__file__).resolve().parent.parent / "mcp-gateway")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app
from gateway_server import MCPGatewayServer
from http_server import (
    _issue_oauth_token,
    _verify_oauth_token,
    expand_owner_delegation_capabilities,
)
from policy import GatewayPolicy
from runtime.contracts import RuntimeStatePaths


def _setup_delegation_env():
    td = tempfile.mkdtemp(prefix="test_sec_delegation_")
    ws = Path(td) / "disposable_repo"
    (ws / "mcp-gateway").mkdir(parents=True, exist_ok=True)
    (ws / "config").mkdir(parents=True, exist_ok=True)
    (ws / "runtime" / "secrets").mkdir(parents=True, exist_ok=True)

    # Disposable security-control files
    http_srv = ws / "mcp-gateway" / "http_server.py"
    http_srv.write_text(
        "# Disposable security-control module\nAUTH_BOUNDARY_VERSION = 1\n",
        encoding="utf-8",
    )
    gw_srv = ws / "mcp-gateway" / "gateway_server.py"
    gw_srv.write_text(
        "# Disposable gateway server module\nGATEWAY_VERSION = 1\n",
        encoding="utf-8",
    )
    pol_cfg = ws / "config" / "policy.json"
    pol_cfg.write_text('{"profile": "read_only"}\n', encoding="utf-8")

    # Raw secret file that must remain blocked even with owner grant
    raw_secret = ws / "runtime" / "secrets" / "oauth_signing.key"
    raw_secret.write_text("mcp_osk_synthetic_do_not_touch_1234567890", encoding="utf-8")

    paths = RuntimeStatePaths.create_isolated(Path(td) / "state")
    policy = GatewayPolicy(
        profile="owner_full_control",
        audit_log_path=paths.audit_log_path,
        emergency_stop_file=paths.emergency_stop_file,
    )
    policy.allowed_roots = [str(ws)]
    gw = MCPGatewayServer(policy=policy, runtime_paths=paths)

    connector_secret = "mcp_test_static_connector_secret_998877665544"
    signing_key = "mcp_osk_test_dedicated_signing_key_11223344556677889900"  # gitleaks:allow  (synthetic regression fixture; reviewed)
    owner_admin_token = "mcp_oadm_test_dedicated_owner_admin_token_77665544332211"

    app = create_cloud_autonomous_adapter_app(
        gateway=gw,
        caller_auth_token=connector_secret,
        oauth_signing_key=signing_key,
        owner_admin_token=owner_admin_token,
        require_autonomous_auth=True,
        allow_loopback_tunnel_identity=False,
        db_path=paths.oauth_db_path,
        enable_direct_coding=True,
    )
    return td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token


def _mcp_init(client: TestClient, bearer: str) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {bearer}", "Mcp-Protocol-Version": "2025-03-26"}
    r = client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
    )
    assert r.status_code == 200, f"initialize failed: {r.text}"
    sid = r.headers.get("Mcp-Session-Id") or r.headers.get("mcp-session-id")
    if sid:
        headers["Mcp-Session-Id"] = sid
    return headers


def _call_coding_tool(client: TestClient, headers: dict[str, str], name: str, arguments: dict) -> dict:
    r = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    res = r.json()["result"]
    text = res["content"][0]["text"]
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = {"raw_text": text}
    return {"isError": res.get("isError", False), "payload": parsed, "raw": text}


def test_workstream_a1_grant_endpoint_blocks_static_bearer_and_claim_forgery():
    """Verify Workstream A1: Shared static connector Bearer and body claim overrides are strictly DENIED on /oauth/grants."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)
        http_srv = ws / "mcp-gateway" / "http_server.py"

        tok_owner = _issue_oauth_token(
            client_id="chatgpt_owner_client_a",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        tok_foreign = _issue_oauth_token(
            client_id="foreign_client_b",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        tok_non_owner = _issue_oauth_token(
            client_id="ordinary_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]

        # 1. CRITICAL NEGATIVE TEST (A1): Shared static connector Bearer in body owner_token -> 403 DENY
        r_static_body = client.post(
            "/oauth/grants",
            json={
                "owner_token": connector_secret,
                "access_token": tok_owner,
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
            },
        )
        assert r_static_body.status_code == 403, r_static_body.text
        assert "Shared static connector Bearer cannot issue" in r_static_body.text

        # 2. Shared static connector Bearer in Authorization header -> 403 DENY
        r_static_hdr = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {connector_secret}"},
            json={
                "access_token": tok_owner,
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
            },
        )
        assert r_static_hdr.status_code == 403, r_static_hdr.text

        # 3. Non-owner OAuth token (missing mcp:owner scope) -> 403 DENY
        r_non_owner = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_non_owner}"},
            json={
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
            },
        )
        assert r_non_owner.status_code == 403, r_non_owner.text

        # 4. Owner OAuth Bearer attempting to override client_id in body -> 403 DENY
        r_override_cid = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "client_id": "forged_other_client",
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
            },
        )
        assert r_override_cid.status_code == 403, r_override_cid.text

        # 5. Owner OAuth Bearer attempting to override oauth_token_jti in body -> 403 DENY
        r_override_jti = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "oauth_token_jti": "forged_jti_999999",
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
            },
        )
        assert r_override_jti.status_code == 403, r_override_jti.text

        # 6. Owner OAuth Bearer attempting to pass a foreign access_token in body -> 403 DENY
        r_foreign_tok = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "access_token": tok_foreign,
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
            },
        )
        assert r_foreign_tok.status_code == 403, r_foreign_tok.text

        # Confirm zero grants were created in SQLite after all negative attempts
        conn = sqlite3.connect(str(paths.oauth_db_path))
        cnt = conn.execute("SELECT COUNT(*) FROM owner_capability_grants").fetchone()[0]
        conn.close()
        assert cnt == 0, f"Expected 0 grants after denied attempts, found {cnt}"

        # 7. Positive: Legitimate Owner OAuth Bearer issues self-bound grant -> 201 Created
        r_ok_oauth = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
                "ttl_seconds": 300,
                "max_uses": 5,
            },
        )
        assert r_ok_oauth.status_code == 201, r_ok_oauth.text
        gid_1 = r_ok_oauth.json()["grant_id"]

        # 8. Negative revoke: Shared static connector Bearer cannot revoke grant -> 403 DENY
        r_rev_static = client.post(
            "/oauth/grants/revoke",
            json={"owner_token": connector_secret, "grant_id": gid_1},
        )
        assert r_rev_static.status_code == 403, r_rev_static.text

        # 9. Negative revoke: Foreign Owner OAuth client B cannot revoke Client A's grant -> 403 DENY
        r_rev_foreign = client.post(
            "/oauth/grants/revoke",
            headers={"Authorization": f"Bearer {tok_foreign}"},
            json={"grant_id": gid_1},
        )
        assert r_rev_foreign.status_code == 403, r_rev_foreign.text

        # 10. Positive: Independent local owner_admin_token can issue & revoke grants
        r_ok_admin = client.post(
            "/oauth/grants",
            headers={"X-MCP-Owner-Admin-Token": owner_admin_token},
            json={
                "access_token": tok_owner,
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
                "ttl_seconds": 300,
                "max_uses": 5,
            },
        )
        assert r_ok_admin.status_code == 201, r_ok_admin.text
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_owner_authorized_security_edit_all_8_acceptance_criteria():
    """Verify all 8 acceptance criteria in Section 1.3 & 1.4 for OWNER_AUTHORIZED_SECURITY_EDIT."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)
        http_srv = ws / "mcp-gateway" / "http_server.py"
        gw_srv = ws / "mcp-gateway" / "gateway_server.py"
        orig_content = http_srv.read_text(encoding="utf-8")
        orig_sha = hashlib.sha256(http_srv.read_bytes()).hexdigest()
        gw_orig_sha = hashlib.sha256(gw_srv.read_bytes()).hexdigest()

        # Issue OAuth tokens for Client A (owner), Client A token 2 (different JTI), and Client B (owner)
        tok_a1 = _issue_oauth_token(
            client_id="chatgpt_owner_client_a",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        jti_a1 = _verify_oauth_token(tok_a1, signing_key, set())[1]["jti"]

        tok_a2 = _issue_oauth_token(
            client_id="chatgpt_owner_client_a",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        jti_a2 = _verify_oauth_token(tok_a2, signing_key, set())[1]["jti"]
        assert jti_a1 != jti_a2

        tok_b = _issue_oauth_token(
            client_id="chatgpt_owner_client_b",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]

        # Issue capability grant for Client A via POST /oauth/grants using Owner OAuth Bearer
        grant_res = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_a1}"},
            json={
                "capabilities": ["FILE_READ", "FILE_WRITE", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
                "ttl_seconds": 600,
                "max_uses": 10,
            },
        )
        assert grant_res.status_code == 201, grant_res.text
        grant_a1_id = grant_res.json()["grant_id"]

        hdr_static = _mcp_init(client, connector_secret)
        hdr_a1 = _mcp_init(client, tok_a1)
        hdr_a2 = _mcp_init(client, tok_a2)
        hdr_b = _mcp_init(client, tok_b)

        # ------------------------------------------------------------------
        # Criterion 2: Non-owner static Bearer -> DENY (even with valid grant_id)
        # ------------------------------------------------------------------
        res_static = _call_coding_tool(
            client,
            hdr_static,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 999",
                "expected_sha256": orig_sha,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert res_static["isError"] is True
        assert "Sensitive or security-control path is denied" in res_static["raw"]
        assert http_srv.read_text(encoding="utf-8") == orig_content

        # Also verify owner_oauth_token in tool arguments is rejected
        res_arg_tok = _call_coding_tool(
            client,
            hdr_static,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 999",
                "expected_sha256": orig_sha,
                "owner_oauth_token": tok_a1,
            },
        )
        assert res_arg_tok["isError"] is True
        assert "owner_oauth_token" in res_arg_tok["raw"]

        # ------------------------------------------------------------------
        # Criterion 3: Client B uses Client A's grant -> DENY
        # ------------------------------------------------------------------
        res_client_b = _call_coding_tool(
            client,
            hdr_b,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 888",
                "expected_sha256": orig_sha,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert res_client_b["isError"] is True
        assert http_srv.read_text(encoding="utf-8") == orig_content

        # ------------------------------------------------------------------
        # Criterion 4: Wrong JTI (Client A token 2 using grant bound to token 1) -> DENY
        # ------------------------------------------------------------------
        res_wrong_jti = _call_coding_tool(
            client,
            hdr_a2,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 777",
                "expected_sha256": orig_sha,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert res_wrong_jti["isError"] is True
        assert http_srv.read_text(encoding="utf-8") == orig_content

        # ------------------------------------------------------------------
        # Criterion 7: File outside allowlist (gateway_server.py not in allowed_paths) -> DENY
        # ------------------------------------------------------------------
        res_out_allowlist = _call_coding_tool(
            client,
            hdr_a1,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/gateway_server.py",
                "old_text": "GATEWAY_VERSION = 1",
                "new_text": "GATEWAY_VERSION = 2",
                "expected_sha256": gw_orig_sha,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert res_out_allowlist["isError"] is True
        assert (ws / "mcp-gateway" / "gateway_server.py").read_text(encoding="utf-8") == "# Disposable gateway server module\nGATEWAY_VERSION = 1\n"

        # Raw secret file remains blocked even for Owner OAuth + grant
        res_raw_secret = _call_coding_tool(
            client,
            hdr_a1,
            "agent_read_file",
            {
                "workspace_root": str(ws),
                "path": "runtime/secrets/oauth_signing.key",
                "capability_grant_id": grant_a1_id,
            },
        )
        assert res_raw_secret["isError"] is True

        # ------------------------------------------------------------------
        # Criterion 6: Emergency Stop -> DENY
        # ------------------------------------------------------------------
        policy.engage_emergency_stop("TEST_DELEGATION_ESTOP")
        try:
            res_estop = _call_coding_tool(
                client,
                hdr_a1,
                "agent_apply_patch",
                {
                    "workspace_root": str(ws),
                    "path": "mcp-gateway/http_server.py",
                    "old_text": "AUTH_BOUNDARY_VERSION = 1",
                    "new_text": "AUTH_BOUNDARY_VERSION = 2",
                    "expected_sha256": orig_sha,
                    "capability_grant_id": grant_a1_id,
                },
            )
            assert res_estop["isError"] is True
            assert "Emergency Stop" in res_estop["raw"]
            assert http_srv.read_text(encoding="utf-8") == orig_content
        finally:
            policy.reset_emergency_stop()

        # ------------------------------------------------------------------
        # Criterion 1 & 8: Owner OAuth + valid grant -> READ & EDIT security file,
        # producing durable backup, unified diff, audit record, and atomic ROLLBACK
        # ------------------------------------------------------------------
        read_ok = _call_coding_tool(
            client,
            hdr_a1,
            "agent_read_file",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "capability_grant_id": grant_a1_id,
            },
        )
        assert read_ok["isError"] is False, read_ok["raw"]
        assert read_ok["payload"]["sha256"] == orig_sha
        assert "AUTH_BOUNDARY_VERSION = 1" in read_ok["payload"]["file_text"]

        patch_ok = _call_coding_tool(
            client,
            hdr_a1,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 2",
                "expected_sha256": orig_sha,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert patch_ok["isError"] is False, patch_ok["raw"]
        patch_data = patch_ok["payload"]
        assert patch_data["ok"] is True
        assert patch_data["security_control_edit"] is True
        assert patch_data["authorization_mode"] == "OWNER_AUTHORIZED_SECURITY_EDIT"
        assert patch_data["grant_id"] == grant_a1_id
        assert patch_data["previous_sha256"] == orig_sha
        new_sha = patch_data["sha256"]
        assert new_sha != orig_sha
        backup_id = patch_data["backup_id"]
        assert backup_id and len(backup_id) == 32
        assert "-AUTH_BOUNDARY_VERSION = 1" in patch_data["diff"]
        assert "+AUTH_BOUNDARY_VERSION = 2" in patch_data["diff"]
        assert "AUTH_BOUNDARY_VERSION = 2" in http_srv.read_text(encoding="utf-8")

        # Verify durable coding_audit.db record
        audit_db = Path(paths.root_dir) / "logs" / "coding_audit.db"
        conn = sqlite3.connect(str(audit_db))
        records = [json.loads(r[0]) for r in conn.execute("SELECT record FROM coding_audit").fetchall()]
        conn.close()
        assert any(
            r.get("decision") == "WRITE_COMMITTED"
            and r.get("authorization_mode") == "OWNER_AUTHORIZED_SECURITY_EDIT"
            and r.get("grant_id") == grant_a1_id
            and r.get("client_id") == "chatgpt_owner_client_a"
            for r in records
        )

        # Rollback using backup_id via agent_write_file
        rollback_ok = _call_coding_tool(
            client,
            hdr_a1,
            "agent_write_file",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "content": "",
                "expected_sha256": new_sha,
                "rollback_backup_id": backup_id,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert rollback_ok["isError"] is False, rollback_ok["raw"]
        assert rollback_ok["payload"]["sha256"] == orig_sha
        assert rollback_ok["payload"]["rolled_back_from_backup_id"] == backup_id
        assert http_srv.read_text(encoding="utf-8") == orig_content

        # ------------------------------------------------------------------
        # Criterion 5: Expired / Revoked grant -> DENY
        # ------------------------------------------------------------------
        rev_res = client.post(
            "/oauth/grants/revoke",
            headers={"Authorization": f"Bearer {tok_a1}"},
            json={"grant_id": grant_a1_id, "reason": "test_revocation"},
        )
        assert rev_res.status_code == 200
        assert rev_res.json()["revoked"] is True

        res_revoked = _call_coding_tool(
            client,
            hdr_a1,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 3",
                "expected_sha256": orig_sha,
                "capability_grant_id": grant_a1_id,
            },
        )
        assert res_revoked["isError"] is True
        assert http_srv.read_text(encoding="utf-8") == orig_content

        # Also test expired grant (ttl=0.05s)
        exp_grant = app.state.oauth_persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["SECURITY_CONTROL_EDIT", "agent_apply_patch"],
            allowed_paths=[str(http_srv)],
            owner_id="local_owner",
            client_id="chatgpt_owner_client_a",
            oauth_token_jti=jti_a1,
            ttl_seconds=0.05,
            max_uses=5,
        )
        time.sleep(0.08)
        res_expired = _call_coding_tool(
            client,
            hdr_a1,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/http_server.py",
                "old_text": "AUTH_BOUNDARY_VERSION = 1",
                "new_text": "AUTH_BOUNDARY_VERSION = 4",
                "expected_sha256": orig_sha,
                "capability_grant_id": exp_grant["grant_id"],
            },
        )
        assert res_expired["isError"] is True
        assert http_srv.read_text(encoding="utf-8") == orig_content

        # Verify RELEASE_DEPLOY requires separate explicit approval flag
        try:
            expand_owner_delegation_capabilities(["RELEASE_DEPLOY"], include_release_deploy=False)
            raise AssertionError("RELEASE_DEPLOY should require include_release_deploy=True")
        except ValueError as exc:
            assert "RELEASE_DEPLOY" in str(exc)
        assert "RELEASE_DEPLOY" in expand_owner_delegation_capabilities(["RELEASE_DEPLOY"], include_release_deploy=True)
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_workstream_a3_and_c1_c2_refresh_and_rollback_rehearsal():
    """Verify OAuth token refresh grant JTI rotation (A3) and SQLite Online Backup + DPAPI + Rollback rehearsal (C1/C2)."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)
        http_srv = ws / "mcp-gateway" / "http_server.py"
        orig_sha = hashlib.sha256(http_srv.read_bytes()).hexdigest()

        tok_initial = _issue_oauth_token(
            client_id="chatgpt_owner_refresh_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        refresh_tok = _issue_oauth_token(
            client_id="chatgpt_owner_refresh_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=3600,
            owner_id="local_owner",
            typ="refresh",
        )["access_token"]

        g_res = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_initial}"},
            json={
                "capabilities": ["FILE_READ", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(http_srv)],
                "ttl_seconds": 600,
                "max_uses": 10,
            },
        )
        assert g_res.status_code == 201
        gid = g_res.json()["grant_id"]

        # Refresh OAuth token via /oauth/token -> grant JTI should automatically rotate to the new access token
        ref_res = client.post(
            "/oauth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": refresh_tok,
                "client_id": "chatgpt_owner_refresh_client",
            },
        )
        assert ref_res.status_code == 200, ref_res.text
        ref_data = ref_res.json()
        new_access_tok = ref_data["access_token"]
        assert ref_data.get("capability_grant_id") == gid

        # Old token JTI must no longer match the rotated grant
        hdr_old = _mcp_init(client, tok_initial)
        old_try = _call_coding_tool(
            client,
            hdr_old,
            "agent_read_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/http_server.py", "capability_grant_id": gid},
        )
        assert old_try["isError"] is True

        # New refreshed token JTI works seamlessly with the rotated grant
        hdr_new = _mcp_init(client, new_access_tok)
        new_try = _call_coding_tool(
            client,
            hdr_new,
            "agent_read_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/http_server.py", "capability_grant_id": gid},
        )
        assert new_try["isError"] is False
        assert new_try["payload"]["sha256"] == orig_sha

        # Verify C1/C2 Rollback Rehearsal script function
        from scripts.manage_owner_delegation import cmd_rehearse_rollback
        rc = cmd_rehearse_rollback(argparse.Namespace())
        assert rc == 0
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_p1_durable_delegation_auto_renew_and_cascade():
    """Verify P1: Durable delegation allows transparent rolling grant renewal, cascades revocation, and respects operation budget."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)
        http_srv = ws / "mcp-gateway" / "http_server.py"

        tok_owner = _issue_oauth_token(
            client_id="chatgpt_web_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=3600,
            owner_id="local_owner",
        )["access_token"]

        # 1. Issue durable delegation with budget 5 operations
        del_resp = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ", "FILE_WRITE", "SECURITY_CONTROL_EDIT", "SHELL", "DESKTOP"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 5,
                "allow_destructive": True,
            },
        )
        assert del_resp.status_code == 201, del_resp.text
        del_id = del_resp.json()["delegation_id"]
        assert del_id.startswith("odd_")

        hdr_owner = _mcp_init(client, tok_owner)

        # 2. Transparent grant renewal: call without specifying capability_grant_id
        res1 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_read_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/http_server.py"},
        )
        assert res1["isError"] is False, res1["raw"]
        assert "AUTH_BOUNDARY_VERSION = 1" in (res1["payload"].get("file_text") or res1["payload"].get("text") or "")

        # Call powershell execute via durable delegation
        res2 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'HELLO_OWNER'"},
        )
        assert res2["isError"] is False, res2["raw"]
        assert "HELLO_OWNER" in res2["payload"]["stdout"]

        # Call powershell execute second time to increment usage count
        res3 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'HELLO_OWNER_2'"},
        )
        assert res3["isError"] is False, res3["raw"]

        # Check durable delegation usage count in SQLite
        db = app.state.oauth_persistence
        d_row = db.get_owner_durable_delegation(del_id)
        assert d_row is not None
        assert d_row["total_used_count"] >= 2
        assert d_row["total_operation_budget"] == 5

        # 3. Test cascading revocation: revoke durable delegation
        rev_del = client.post(
            "/oauth/delegations/revoke",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={"delegation_id": del_id, "reason": "test_cascade_revocation"},
        )
        assert rev_del.status_code == 200
        assert rev_del.json()["revoked"] is True

        # Now calling owner tools must be rejected
        res_after_rev = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'SHOULD_FAIL'"},
        )
        assert res_after_rev["isError"] is True

        # 4. Test operation budget exhaustion
        del_resp2 = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ", "SHELL", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 2,
                "allow_destructive": False,
            },
        )
        assert del_resp2.status_code == 201
        del_id2 = del_resp2.json()["delegation_id"]

        # Op 1
        op1 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'OP1'"},
        )
        assert op1["isError"] is False

        # Op 2
        op2 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'OP2'"},
        )
        assert op2["isError"] is False

        # Op 3 - should fail due to budget exhaustion
        op3 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'OP3'"},
        )
        assert op3["isError"] is True
        assert "budget exceeded" in op3["raw"].lower() or "denied" in op3["raw"].lower()
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_p2_owner_filesystem_operations_suite():
    """Verify P2: Full set of owner filesystem tools: create, write, patch, delete with anti-TOCTOU/restore, directory ops, move, copy."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)

        tok_owner = _issue_oauth_token(
            client_id="chatgpt_web_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=3600,
            owner_id="local_owner",
        )["access_token"]

        del_resp = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ", "FILE_WRITE", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 100,
                "allow_destructive": True,
            },
        )
        assert del_resp.status_code == 201
        hdr_owner = _mcp_init(client, tok_owner)

        # 1. agent_create_file
        c_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_create_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/test_create.py", "content": "NEW_VAL = 100\n"},
        )
        assert c_res["isError"] is False, c_res["raw"]
        assert c_res["payload"]["sha256"] == hashlib.sha256(b"NEW_VAL = 100\n").hexdigest()
        assert (ws / "mcp-gateway" / "test_create.py").exists()

        # Fails without overwrite flag if already exists
        c_dup = _call_coding_tool(
            client,
            hdr_owner,
            "agent_create_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/test_create.py", "content": "NEW_VAL = 200\n"},
        )
        assert c_dup["isError"] is True

        # 2. agent_write_file with expected_sha256
        sha_100 = c_res["payload"]["sha256"]
        w_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_write_file",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/test_create.py",
                "content": "NEW_VAL = 200\n",
                "expected_sha256": sha_100,
            },
        )
        assert w_res["isError"] is False, w_res["raw"]
        sha_200 = w_res["payload"]["sha256"]
        assert sha_200 == hashlib.sha256(b"NEW_VAL = 200\n").hexdigest()

        # 3. agent_apply_patch
        p_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_apply_patch",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/test_create.py",
                "old_text": "NEW_VAL = 200",
                "new_text": "NEW_VAL = 300",
                "expected_sha256": sha_200,
            },
        )
        assert p_res["isError"] is False, p_res["raw"]
        sha_300 = p_res["payload"]["sha256"]
        assert sha_300 == hashlib.sha256(b"NEW_VAL = 300\n").hexdigest()

        # 4. agent_delete_file (requires expected_sha256 for anti-TOCTOU, supports rollback via backup_id)
        # Mismatch sha256 fails
        d_bad_sha = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_file",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/test_create.py",
                "expected_sha256": "0" * 64,
            },
        )
        assert d_bad_sha["isError"] is True

        # Correct sha256 succeeds and creates backup
        d_ok = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_file",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/test_create.py",
                "expected_sha256": sha_300,
            },
        )
        assert d_ok["isError"] is False, d_ok["raw"]
        assert not (ws / "mcp-gateway" / "test_create.py").exists()
        del_backup_id = d_ok["payload"]["backup_id"]
        assert del_backup_id

        # Restore deleted file using backup_id via agent_write_file
        restore_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_write_file",
            {
                "workspace_root": str(ws),
                "path": "mcp-gateway/test_create.py",
                "content": "",
                "expected_sha256": "missing",
                "rollback_backup_id": del_backup_id,
            },
        )
        assert restore_res["isError"] is False, restore_res["raw"]
        assert (ws / "mcp-gateway" / "test_create.py").exists()
        assert restore_res["payload"]["sha256"] == sha_300

        # 5. agent_create_directory
        dir_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_create_directory",
            {"workspace_root": str(ws), "path": "test_folder/nested_sub"},
        )
        assert dir_res["isError"] is False, dir_res["raw"]
        assert (ws / "test_folder" / "nested_sub").is_dir()

        # 6. agent_delete_directory
        # Create an inner file
        (ws / "test_folder" / "nested_sub" / "leaf.txt").write_text("leaf", encoding="utf-8")

        # preview_only=True returns preview without deleting
        preview_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_directory",
            {
                "workspace_root": str(ws),
                "path": "test_folder",
                "recursive": True,
                "preview_only": True,
            },
        )
        assert preview_res["isError"] is False
        assert preview_res["payload"]["preview_only"] is True
        assert (ws / "test_folder").exists()

        # recursive without destructive approval fails
        del_no_appr = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_directory",
            {
                "workspace_root": str(ws),
                "path": "test_folder",
                "recursive": True,
                "destructive_operations_approved": False,
            },
        )
        assert del_no_appr["isError"] is True

        # recursive with destructive approval succeeds
        del_dir_ok = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_directory",
            {
                "workspace_root": str(ws),
                "path": "test_folder",
                "recursive": True,
                "destructive_operations_approved": True,
            },
        )
        assert del_dir_ok["isError"] is False, del_dir_ok["raw"]
        assert not (ws / "test_folder").exists()
        assert del_dir_ok["payload"]["backup_id"]

        # 7. agent_move_path
        (ws / "source_item.txt").write_text("move_content", encoding="utf-8")
        mv_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_move_path",
            {"workspace_root": str(ws), "src_path": "source_item.txt", "dst_path": "target_item.txt"},
        )
        assert mv_res["isError"] is False
        assert not (ws / "source_item.txt").exists()
        assert (ws / "target_item.txt").exists()

        # 8. agent_copy_path
        cp_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_copy_path",
            {"workspace_root": str(ws), "src_path": "target_item.txt", "dst_path": "copied_item.txt"},
        )
        assert cp_res["isError"] is False
        assert (ws / "target_item.txt").exists()
        assert (ws / "copied_item.txt").exists()
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_l4_c_owner_delegation_negative_boundary():
    """Verify L4-C: 10 comprehensive security negative cases ensuring fail-closed boundary."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)

        # 1. Unauthenticated / forged token
        forged_hdr = {"Authorization": "Bearer invalid_forged_token_xyz", "Mcp-Protocol-Version": "2025-03-26"}
        f_res = client.post(
            "/mcp",
            headers=forged_hdr,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert f_res.status_code in (401, 403) or (f_res.status_code == 200 and f_res.json().get("error"))

        # 2. Static connector Bearer cannot call owner-only tools (powershell execute, desktop, etc.)
        stat_hdr = _mcp_init(client, connector_secret)
        stat_ps = _call_coding_tool(
            client,
            stat_hdr,
            "agent_powershell_execute",
            {"command": "whoami"},
        )
        assert stat_ps["isError"] is True
        assert "permission denied" in stat_ps["raw"].lower() or "access denied" in stat_ps["raw"].lower() or "denied" in stat_ps["raw"].lower()

        # 3. Path traversal outside approved roots
        tok_owner = _issue_oauth_token(
            client_id="chatgpt_web_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=3600,
            owner_id="local_owner",
        )["access_token"]
        client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ", "FILE_WRITE", "SECURITY_CONTROL_EDIT"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 50,
                "allow_destructive": True,
            },
        )
        hdr_owner = _mcp_init(client, tok_owner)

        trav_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_read_file",
            {"workspace_root": str(ws), "path": "../../Windows/win.ini"},
        )
        assert trav_res["isError"] is True

        # 4. Raw secrets strictly denied even with owner authority
        sec_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_read_file",
            {"workspace_root": str(ws), "path": "runtime/secrets/oauth_signing.key"},
        )
        assert sec_res["isError"] is True
        assert "secret" in sec_res["raw"].lower() or "denied" in sec_res["raw"].lower()

        # 5. Expired durable delegation rejected
        del_exp = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 0.05,
                "total_budget": 10,
                "allow_destructive": False,
            },
        ).json()["delegation_id"]
        time.sleep(0.08)
        exp_res = _call_coding_tool(
            client,
            hdr_owner,
            "agent_read_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/http_server.py", "delegation_id": del_exp},
        )
        # Even with rolling renewal, this expired delegation cannot satisfy the request
        assert app.state.oauth_persistence.get_owner_durable_delegation(del_exp)["expires_at"] < time.time()

        # 6. Revoked durable delegation rejected
        del_to_rev = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 10,
                "allow_destructive": False,
            },
        ).json()["delegation_id"]
        client.post(
            "/oauth/delegations/revoke",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={"delegation_id": del_to_rev, "reason": "negative_test"},
        )
        assert app.state.oauth_persistence.get_owner_durable_delegation(del_to_rev)["revoked"] == 1

        # 7. Exceeded operation budget rejected
        del_b1 = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["SHELL"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 1,
                "allow_destructive": False,
            },
        ).json()["delegation_id"]
        # Op 1 uses the 1 budget allowance
        b1_res1 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'b1_ok'"},
        )
        assert b1_res1["isError"] is False
        # Op 2 exceeds the budget -> DENY
        b1_res2 = _call_coding_tool(
            client,
            hdr_owner,
            "agent_powershell_execute",
            {"command": "Write-Output 'b1_exceeded'"},
        )
        assert b1_res2["isError"] is True

        # 8. Delete file without expected_sha256 rejected
        d_no_sha = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/http_server.py"},
        )
        assert d_no_sha["isError"] is True

        # 9. Delete non-empty directory without destructive approval rejected
        (ws / "non_empty_dir").mkdir(parents=True, exist_ok=True)
        (ws / "non_empty_dir" / "f.txt").write_text("x", encoding="utf-8")
        del_dir_no_app = _call_coding_tool(
            client,
            hdr_owner,
            "agent_delete_directory",
            {"workspace_root": str(ws), "path": "non_empty_dir", "recursive": True, "destructive_operations_approved": False},
        )
        assert del_dir_no_app["isError"] is True

        # 10. Non-owner / default caller cannot call owner filesystem tools
        stat_del = _call_coding_tool(
            client,
            stat_hdr,
            "agent_delete_file",
            {"workspace_root": str(ws), "path": "mcp-gateway/http_server.py", "expected_sha256": "abc"},
        )
        assert stat_del["isError"] is True
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_tool_catalog_synchronization_contract_and_dispatch():
    """Verify tool catalog synchronization contract: 14 baseline tools vs 34 owner tools."""
    from gateway_server import MCPGatewayServer, assemble_autonomous_tool_catalog, OWNER_EXEC_AND_DESKTOP_TOOLS
    from runtime.coding_tools import OWNER_FILESYSTEM_TOOL_NAMES
    from runtime.contracts import AuthPrincipal

    # 1. Non-owner assembly: exactly 14 baseline tools
    tools_14 = assemble_autonomous_tool_catalog(is_owner_full_control=False)
    assert len(tools_14) == 14
    names_14 = {t["name"] for t in tools_14}
    for fs_tool in OWNER_FILESYSTEM_TOOL_NAMES:
        assert fs_tool not in names_14, f"Filesystem tool {fs_tool} must not be in 14 baseline tools"
    for exec_tool in OWNER_EXEC_AND_DESKTOP_TOOLS:
        assert exec_tool not in names_14, f"Exec/desktop tool {exec_tool} must not be in 14 baseline tools"

    # 2. Owner assembly: exactly 34 tools
    tools_34 = assemble_autonomous_tool_catalog(is_owner_full_control=True)
    assert len(tools_34) == 34
    names_34 = {t["name"] for t in tools_34}
    for fs_tool in OWNER_FILESYSTEM_TOOL_NAMES:
        assert fs_tool in names_34, f"Filesystem tool {fs_tool} must be in 34 owner tools"
    for exec_tool in OWNER_EXEC_AND_DESKTOP_TOOLS:
        assert exec_tool in names_34, f"Exec/desktop tool {exec_tool} must be in 34 owner tools"
    for task_tool in ("agent_task_pause", "agent_task_resume", "agent_task_cancel", "agent_emergency_stop"):
        assert task_tool in names_34

    # 3. Gateway server tools/list integration
    gw = MCPGatewayServer()
    # Call tools/list as non-owner
    res_non_owner = gw.handle_jsonrpc_autonomous(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        include_coding_tools=True,
        auth_principal=None,
    )
    assert len(res_non_owner["result"]["tools"]) == 14

    # Call tools/list as verified owner
    owner_principal = AuthPrincipal(
        client_id="test_owner",
        tier="SYSTEM_ADMIN",
        is_owner=True,
        auth_method="oauth",
        scopes=frozenset(["MCP_ACCESS_FULL_CONTROL"]),
    )
    res_owner = gw.handle_jsonrpc_autonomous(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        caller_tier="SYSTEM_ADMIN",
        include_coding_tools=True,
        auth_principal=owner_principal,
    )
    assert len(res_owner["result"]["tools"]) == 34


def test_release_identity_consistency_contract():
    """Verify single source of truth for release identity across all endpoints."""
    from runtime.release_identity import get_release_identity
    from gateway_server import MCPGatewayServer
    from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app
    from starlette.testclient import TestClient

    rel_id = get_release_identity()
    assert "release_version" in rel_id
    assert "source_commit" in rel_id
    assert "build_id" in rel_id
    assert "zip_sha256" in rel_id
    assert rel_id["release_version"].startswith("v1.0.0-rc")
    assert rel_id["source_commit"] not in ("", "HEAD")

    # 1. initialize RPC response
    gw = MCPGatewayServer()
    init_res = gw.handle_jsonrpc_autonomous(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        auth_principal=None,
    )
    server_info = init_res["result"]["serverInfo"]
    assert server_info["release_version"] == rel_id["release_version"]
    assert server_info["git_sha"] == rel_id["source_commit"]
    assert server_info["build_id"] == rel_id["build_id"]

    # 2. cloud_autonomous_adapter /health endpoint
    app = create_cloud_autonomous_adapter_app(gateway=gw)
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["release_version"] == rel_id["release_version"]
    assert data["git_sha"] == rel_id["source_commit"]
    assert data["build_id"] == rel_id["build_id"]
    assert data["zip_sha256"] == rel_id["zip_sha256"]


def test_owner_global_filesystem_access_and_non_owner_isolation():
    """Verify OWNER_GLOBAL_FILESYSTEM access across arbitrary directories, with strict non-owner isolation and secret shielding."""
    td, ws, paths, policy, gw, app, connector_secret, signing_key, owner_admin_token = _setup_delegation_env()
    try:
        client = TestClient(app)
        outside_ws = Path(td) / "SimulatedDesktop_ViXua"
        outside_ws.mkdir(parents=True, exist_ok=True)
        outside_sub = outside_ws / "sub_project"

        # --- Kiểm tra 1 (Non-owner bị chặn ngoài workspace) ---
        hdr_static = _mcp_init(client, connector_secret)
        res_non_owner_read = _call_coding_tool(
            client,
            hdr_static,
            "agent_read_file",
            {"workspace_root": str(outside_ws), "path": "any_file.txt"},
        )
        assert res_non_owner_read["isError"] is True
        err_msg_read = res_non_owner_read.get("raw", "") + str(res_non_owner_read.get("payload", ""))
        assert "Workspace/tool has no owner-approved trusted workspace policy" in err_msg_read or "denied" in err_msg_read.lower()

        res_non_owner_create = _call_coding_tool(
            client,
            hdr_static,
            "agent_create_file",
            {"workspace_root": str(outside_ws), "path": "sub_project/test.txt", "content": "hello"},
        )
        assert res_non_owner_create["isError"] is True
        err_msg_create = res_non_owner_create.get("raw", "") + str(res_non_owner_create.get("payload", ""))
        assert "Workspace/tool has no owner-approved trusted workspace policy" in err_msg_create or "denied" in err_msg_create.lower()

        # Non-owner OAuth token cũng bị chặn
        tok_non_owner = _issue_oauth_token(
            client_id="ordinary_worker",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        hdr_non_owner = _mcp_init(client, tok_non_owner)
        res_oauth_non_owner = _call_coding_tool(
            client,
            hdr_non_owner,
            "agent_read_file",
            {"workspace_root": str(outside_ws), "path": "any_file.txt"},
        )
        assert res_oauth_non_owner["isError"] is True

        # --- Kiểm tra 2 (Owner chưa cấp OWNER_GLOBAL_FILESYSTEM và outside_ws nằm ngoài allowed_paths bị chặn) ---
        tok_owner_scoped = _issue_oauth_token(
            client_id="scoped_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=3600,
            owner_id="local_owner",
        )["access_token"]
        grant_scoped = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner_scoped}"},
            json={
                "capabilities": ["FILE_READ", "FILE_WRITE"],
                "allowed_paths": [str(ws)],
                "ttl_seconds": 3600,
                "total_budget": 50,
                "allow_destructive": True,
            },
        )
        assert grant_scoped.status_code == 201, grant_scoped.text
        hdr_owner_scoped = _mcp_init(client, tok_owner_scoped)
        res_outside_scoped = _call_coding_tool(
            client,
            hdr_owner_scoped,
            "agent_read_file",
            {"workspace_root": str(outside_ws), "path": "any_file.txt"},
        )
        assert res_outside_scoped["isError"] is True

        # --- Kiểm tra 3 (Owner có OWNER_GLOBAL_FILESYSTEM với allowed_paths=["*"] hoặc drive roots) ---
        tok_owner_global = _issue_oauth_token(
            client_id="chatgpt_web_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=3600,
            owner_id="local_owner",
        )["access_token"]
        del_global = client.post(
            "/oauth/delegations",
            headers={"Authorization": f"Bearer {tok_owner_global}"},
            json={
                "capabilities": ["OWNER_GLOBAL_FILESYSTEM", "SECURITY_CONTROL_EDIT", "SHELL"],
                "allowed_paths": ["*"],
                "allow_destructive": True,
                "ttl_seconds": 3600,
                "total_budget": 500,
            },
        )
        assert del_global.status_code == 201, del_global.text
        hdr_owner_global = _mcp_init(client, tok_owner_global)

        # agent_workspace_list không truyền workspace_root -> trả về danh sách chứa các ổ đĩa cố định Windows (C:\, D:\, ...)
        res_ws_list = _call_coding_tool(client, hdr_owner_global, "agent_workspace_list", {})
        assert res_ws_list["isError"] is False, f"agent_workspace_list error: {res_ws_list}"
        workspaces = res_ws_list["payload"].get("workspaces", [])
        ws_roots = [str(w.get("workspace_root", "")).upper() for w in workspaces]
        assert any(r.startswith("C:") for r in ws_roots) or any("C:\\" in r for r in ws_roots)

        # 1. agent_create_directory tạo "sub_project"
        res_mkdir = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_create_directory",
            {"workspace_root": str(outside_ws), "path": "sub_project"},
        )
        assert res_mkdir["isError"] is False, f"mkdir failed: {res_mkdir}"
        assert res_mkdir["payload"].get("authorization_mode") == "OWNER_GLOBAL_FILESYSTEM"
        assert outside_sub.is_dir()

        # 2. agent_create_file tạo "sub_project/vixua_notes.txt" với nội dung "Line 1\nLine 2\n"
        res_create_file = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_create_file",
            {
                "workspace_root": str(outside_ws),
                "path": "sub_project/vixua_notes.txt",
                "content": "Line 1\nLine 2\n",
            },
        )
        assert res_create_file["isError"] is False, f"create_file failed: {res_create_file}"
        created_sha = res_create_file["payload"].get("sha256")
        created_audit_id = res_create_file["payload"].get("audit_id")
        assert created_sha, "Missing sha256 in agent_create_file response"
        assert created_audit_id, "Missing audit_id in agent_create_file response"

        # 3. agent_read_file đọc "sub_project/vixua_notes.txt"
        res_read_file = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_read_file",
            {"workspace_root": str(outside_ws), "path": "sub_project/vixua_notes.txt"},
        )
        assert res_read_file["isError"] is False, f"read_file failed: {res_read_file}"
        assert res_read_file["payload"].get("sha256") == created_sha
        assert res_read_file["payload"].get("authorization_mode") == "OWNER_GLOBAL_FILESYSTEM"

        # 4. agent_apply_patch sửa "Line 2" thành "Line 2 Patched"
        res_patch = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_apply_patch",
            {
                "workspace_root": str(outside_ws),
                "path": "sub_project/vixua_notes.txt",
                "old_text": "Line 2",
                "new_text": "Line 2 Patched",
                "expected_sha256": created_sha,
            },
        )
        assert res_patch["isError"] is False, f"apply_patch failed: {res_patch}"
        patch_backup_id = res_patch["payload"].get("backup_id")
        patched_sha = res_patch["payload"].get("sha256")
        assert patch_backup_id, "Missing backup_id in agent_apply_patch response"
        assert patched_sha, "Missing sha256 in agent_apply_patch response"

        # 5. agent_copy_path sang "sub_project/vixua_copy.txt" và agent_move_path sang "sub_project/vixua_moved.txt"
        res_copy = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_copy_path",
            {
                "workspace_root": str(outside_ws),
                "source_path": "sub_project/vixua_notes.txt",
                "destination_path": "sub_project/vixua_copy.txt",
            },
        )
        assert res_copy["isError"] is False, f"copy_path failed: {res_copy}"

        res_move = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_move_path",
            {
                "workspace_root": str(outside_ws),
                "source_path": "sub_project/vixua_copy.txt",
                "destination_path": "sub_project/vixua_moved.txt",
            },
        )
        assert res_move["isError"] is False, f"move_path failed: {res_move}"

        # 6. agent_delete_file xóa "sub_project/vixua_moved.txt"
        res_del_moved = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_delete_file",
            {
                "workspace_root": str(outside_ws),
                "path": "sub_project/vixua_moved.txt",
                "expected_sha256": patched_sha,
            },
        )
        assert res_del_moved["isError"] is False, f"delete_file moved failed: {res_del_moved}"
        assert res_del_moved["payload"].get("backup_id"), "Missing backup_id on agent_delete_file"

        # 7. agent_delete_file xóa "sub_project/vixua_notes.txt"
        res_del_notes = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_delete_file",
            {
                "workspace_root": str(outside_ws),
                "path": "sub_project/vixua_notes.txt",
                "expected_sha256": patched_sha,
            },
        )
        assert res_del_notes["isError"] is False, f"delete_file notes failed: {res_del_notes}"

        # 8. agent_delete_directory xóa "sub_project"
        res_del_dir = _call_coding_tool(
            client,
            hdr_owner_global,
            "agent_delete_directory",
            {
                "workspace_root": str(outside_ws),
                "path": "sub_project",
                "recursive": True,
                "destructive_operations_approved": True,
            },
        )
        assert res_del_dir["isError"] is False, f"delete_directory failed: {res_del_dir}"
        assert not outside_sub.exists()

        # --- Kiểm tra 4 (Owner có OWNER_GLOBAL_FILESYSTEM vẫn bị chặn raw secrets / protected state) ---
        (outside_ws / ".env").write_text("API_SECRET=super_secret\n", encoding="utf-8")
        (outside_ws / "id_rsa").write_text("FAKE_SSH_KEY\n", encoding="utf-8")
        (outside_ws / "secret.key").write_text("CRYPTO_KEY\n", encoding="utf-8")

        for sec_file in (".env", "id_rsa", "secret.key"):
            res_sec = _call_coding_tool(
                client,
                hdr_owner_global,
                "agent_read_file",
                {"workspace_root": str(outside_ws), "path": sec_file},
            )
            assert res_sec["isError"] is True, f"Raw secret {sec_file} was not blocked!"
            raw_err = res_sec.get("raw", "") + str(res_sec.get("payload", ""))
            assert "denied" in raw_err.lower() or "sensitive" in raw_err.lower() or "secret" in raw_err.lower()

    finally:
        shutil.rmtree(td, ignore_errors=True)


