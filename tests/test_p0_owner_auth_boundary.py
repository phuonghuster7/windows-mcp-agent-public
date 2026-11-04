"""P0 Security Hotfix tests: Owner Authorization Boundary (P0-01 through P0-04)."""
from __future__ import annotations

import concurrent.futures
import json
import shutil
import sys
import tempfile
import threading
from pathlib import Path

import pytest
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
)
from policy import GatewayPolicy
from runtime.contracts import RuntimeStatePaths


def _setup_isolated_env(profile: str = "owner_full_control"):
    td = tempfile.mkdtemp(prefix="test_p0_sec_")
    paths = RuntimeStatePaths.create_isolated(td)
    policy = GatewayPolicy(
        profile=profile,
        audit_log_path=paths.audit_log_path,
        emergency_stop_file=paths.emergency_stop_file,
    )
    gw = MCPGatewayServer(policy=policy, runtime_paths=paths)
    connector_secret = "connector_static_bearer_secret_p0_12345"
    app = create_cloud_autonomous_adapter_app(
        gateway=gw,
        caller_auth_token=connector_secret,
        db_path=paths.oauth_db_path,
        enable_direct_coding=True,
    )
    client = TestClient(app)
    return td, paths, gw, app, client, connector_secret


def _get_oauth_signing_key(app) -> str:
    return getattr(app.state, "oauth_signing_key", None) or app.state.caller_auth_token


def _mcp_init_and_headers(client: TestClient, token: str, extra_headers: dict | None = None) -> dict[str, str]:
    hdrs = {"Authorization": f"Bearer {token}", "Mcp-Protocol-Version": "2025-03-26"}
    if extra_headers:
        hdrs.update(extra_headers)
    resp = client.post(
        "/mcp",
        headers=hdrs,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
    )
    assert resp.status_code == 200, f"initialize failed: {resp.status_code} {resp.text}"
    sid = resp.headers["Mcp-Session-Id"]
    return {**hdrs, "Mcp-Session-Id": sid}


def test_p0_01_remove_global_owner_lease_privilege_escalation():
    """Verify NEG-01, NEG-02, NEG-03, NEG-04, and POS-01 for P0-01."""
    td, paths, gw, app, client, connector_secret = _setup_isolated_env(profile="owner_full_control")
    try:
        signing_key = _get_oauth_signing_key(app)
        persistence = app.state.oauth_persistence

        # Client A: Valid owner OAuth token + capability grant + active cloud lease
        tok_a_info = _issue_oauth_token(
            client_id="client_a_owner",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )
        tok_a = tok_a_info["access_token"]
        _, payload_a, _ = _verify_oauth_token(tok_a, signing_key, set())
        jti_a = payload_a["jti"]

        grant_a = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute", "agent_desktop_screenshot"],
            allowed_paths=[td],
            owner_id="local_owner",
            client_id="client_a_owner",
            oauth_token_jti=jti_a,
            ttl_seconds=600.0,
            max_uses=5,
        )
        gid_a = grant_a["grant_id"]

        # Record an active owner cloud lease for Client A in the database
        persistence.activate_owner_cloud_lease(
            grant_id=gid_a,
            oauth_token=tok_a,
            owner_id="local_owner",
            ttl_seconds=600.0,
        )

        # NEG-01: Client B connects using only the shared static Bearer while Client A's lease is active.
        # Client B calls tools/list -> MUST receive non-owner tools only (no PowerShell or desktop tools).
        hdr_b = _mcp_init_and_headers(client, connector_secret)
        list_b = client.post(
            "/mcp",
            headers=hdr_b,
            json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
        )
        assert list_b.status_code == 200
        tools_b = [t["name"] for t in list_b.json()["result"]["tools"]]
        assert "agent_powershell_execute" not in tools_b, "NEG-01 FAILED: Static Bearer inherited owner tools/list!"
        assert "agent_desktop_screenshot" not in tools_b
        assert "agent_keyboard_type" not in tools_b
        assert "agent_mouse_click" not in tools_b
        # Ordinary coding tools remain preserved for static Bearer connector
        assert "agent_read_file" in tools_b
        assert "agent_write_file" in tools_b

        # NEG-02: Under the same active owner lease state, Client B calls agent_powershell_execute -> DENY, zero execution
        sentinel_b = Path(td) / "neg02_pwned.txt"
        ps_b = client.post(
            "/mcp",
            headers=hdr_b,
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {
                        "command": f"Set-Content -Path '{sentinel_b}' -Value 'PWNED'",
                        "cwd": td,
                    },
                },
            },
        )
        assert ps_b.status_code == 200
        assert ps_b.json()["result"]["isError"] is True, "NEG-02 FAILED: Static Bearer executed owner PowerShell!"
        assert not sentinel_b.exists(), "NEG-02 FAILED: Side effect created on disk!"

        # NEG-03: Client B includes Client A's known active capability_grant_id -> DENY
        ps_b_grant = client.post(
            "/mcp",
            headers=hdr_b,
            json={
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {
                        "command": f"Set-Content -Path '{sentinel_b}' -Value 'PWNED_GRANT'",
                        "cwd": td,
                        "capability_grant_id": gid_a,
                    },
                },
            },
        )
        assert ps_b_grant.status_code == 200
        assert ps_b_grant.json()["result"]["isError"] is True, "NEG-03 FAILED: Static Bearer used Client A's grant!"
        assert not sentinel_b.exists()

        # NEG-04: Client B supplies forged owner headers or caller identity -> DENY
        for forged_hdr in (
            {"X-MCP-Caller-Id": "local_owner"},
            {"X-MCP-Owner-Id": "local_owner", "X-MCP-Caller-Id": "local_owner"},
            {"X-Owner": "true"},
            {"X-Caller-ID": "local_owner"},
        ):
            forged_resp = client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {connector_secret}", **forged_hdr},
                json={
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "tools/call",
                    "params": {
                        "name": "agent_powershell_execute",
                        "arguments": {"command": "Write-Output 'FORGED'", "cwd": td, "capability_grant_id": gid_a},
                    },
                },
            )
            if forged_resp.status_code == 200:
                assert forged_resp.json()["result"]["isError"] is True, f"NEG-04 FAILED for header {forged_hdr}"
            else:
                assert forged_resp.status_code in (400, 401, 403)

        # POS-01: Client A uses valid owner OAuth credentials + authorized capability grant -> PASS
        hdr_a = _mcp_init_and_headers(client, tok_a)
        list_a = client.post(
            "/mcp",
            headers=hdr_a,
            json={"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}},
        )
        tools_a = [t["name"] for t in list_a.json()["result"]["tools"]]
        assert "agent_powershell_execute" in tools_a

        ps_a = client.post(
            "/mcp",
            headers=hdr_a,
            json={
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {
                        "command": "Write-Output 'POS_01_OWNER_OK'",
                        "cwd": td,
                        "capability_grant_id": gid_a,
                    },
                },
            },
        )
        assert ps_a.status_code == 200
        assert ps_a.json()["result"]["isError"] is False, f"POS-01 failed: {ps_a.text}"
        ps_a_data = json.loads(ps_a.json()["result"]["content"][0]["text"])
        assert ps_a_data["exit_code"] == 0
        assert "POS_01_OWNER_OK" in ps_a_data["stdout"]
        assert ps_a_data["grant_used_count"] == 1
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_p0_02_request_bound_capability_authorization_12_cases():
    """Verify all 12 required negative/positive authorization cases for P0-02."""
    td, paths, gw, app, client, connector_secret = _setup_isolated_env(profile="owner_full_control")
    try:
        signing_key = _get_oauth_signing_key(app)
        persistence = app.state.oauth_persistence

        # Mint Client A owner token #1
        tok_a1 = _issue_oauth_token(
            client_id="client_a",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, pay_a1, _ = _verify_oauth_token(tok_a1, signing_key, set())
        jti_a1 = pay_a1["jti"]

        # Mint Client A owner token #2 (different JTI)
        tok_a2 = _issue_oauth_token(
            client_id="client_a",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, pay_a2, _ = _verify_oauth_token(tok_a2, signing_key, set())
        jti_a2 = pay_a2["jti"]

        # Mint Client B owner token (different client_id)
        tok_b = _issue_oauth_token(
            client_id="client_b",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, pay_b, _ = _verify_oauth_token(tok_b, signing_key, set())
        jti_b = pay_b["jti"]

        allowed_subdir = Path(td) / "allowed_work"
        allowed_subdir.mkdir(parents=True, exist_ok=True)
        forbidden_subdir = Path(td) / "forbidden_work"
        forbidden_subdir.mkdir(parents=True, exist_ok=True)

        # Grant for Client A (bound to client_a + jti_a1)
        grant_a = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[str(allowed_subdir)],
            owner_id="local_owner",
            client_id="client_a",
            oauth_token_jti=jti_a1,
            ttl_seconds=600.0,
            max_uses=5,
        )["grant_id"]

        # Grant for Client B (bound to client_b + jti_b)
        grant_b = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[str(allowed_subdir)],
            owner_id="local_owner",
            client_id="client_b",
            oauth_token_jti=jti_b,
            ttl_seconds=600.0,
            max_uses=5,
        )["grant_id"]

        hdr_a1 = _mcp_init_and_headers(client, tok_a1)
        hdr_a2 = _mcp_init_and_headers(client, tok_a2)
        hdr_b = _mcp_init_and_headers(client, tok_b)
        hdr_static = _mcp_init_and_headers(client, connector_secret)

        def _call_tool(headers: dict, tool_name: str, args: dict):
            r = client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": tool_name, "arguments": args}},
            )
            assert r.status_code == 200
            return r.json()["result"]

        # Case 1: Client A token + Client B grant -> DENY
        res_1 = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '1'", "cwd": str(allowed_subdir), "capability_grant_id": grant_b})
        assert res_1["isError"] is True, "Case 1 failed: Client A token used Client B grant!"

        # Case 2: Client B token + Client A grant -> DENY
        res_2 = _call_tool(hdr_b, "agent_powershell_execute", {"command": "Write-Output '2'", "cwd": str(allowed_subdir), "capability_grant_id": grant_a})
        assert res_2["isError"] is True, "Case 2 failed: Client B token used Client A grant!"

        # Case 3: Correct client ID + wrong JTI -> DENY
        res_3 = _call_tool(hdr_a2, "agent_powershell_execute", {"command": "Write-Output '3'", "cwd": str(allowed_subdir), "capability_grant_id": grant_a})
        assert res_3["isError"] is True, "Case 3 failed: Wrong JTI accepted for JTI-bound grant!"

        # Case 4: Missing JTI for JTI-bound grant -> DENY
        # Direct validation call without JTI must fail closed
        ok_no_jti, msg_no_jti, _ = persistence.validate_and_consume_owner_grant(
            grant_a,
            secret=signing_key,
            tool_name="agent_powershell_execute",
            target_path=str(allowed_subdir),
            expected_owner_id="local_owner",
            expected_client_id="client_a",
            oauth_token_jti=None,
        )
        assert ok_no_jti is False, f"Case 4 failed: Missing JTI allowed JTI-bound grant! ({msg_no_jti})"

        # Case 5: Revoked grant -> DENY
        grant_rev = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[str(allowed_subdir)],
            owner_id="local_owner",
            client_id="client_a",
            oauth_token_jti=jti_a1,
            ttl_seconds=600.0,
            max_uses=5,
        )["grant_id"]
        persistence.revoke_owner_capability_grant(grant_rev, reason="test_revoke")
        res_5 = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '5'", "cwd": str(allowed_subdir), "capability_grant_id": grant_rev})
        assert res_5["isError"] is True

        # Case 6: Expired grant -> DENY
        import time
        grant_exp = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[str(allowed_subdir)],
            owner_id="local_owner",
            client_id="client_a",
            oauth_token_jti=jti_a1,
            ttl_seconds=0.05,
            max_uses=5,
        )["grant_id"]
        time.sleep(0.08)
        res_6 = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '6'", "cwd": str(allowed_subdir), "capability_grant_id": grant_exp})
        assert res_6["isError"] is True

        # Case 7: Exhausted grant -> DENY
        grant_1use = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[str(allowed_subdir)],
            owner_id="local_owner",
            client_id="client_a",
            oauth_token_jti=jti_a1,
            ttl_seconds=600.0,
            max_uses=1,
        )["grant_id"]
        res_7_ok = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '7_FIRST'", "cwd": str(allowed_subdir), "capability_grant_id": grant_1use})
        assert res_7_ok["isError"] is False
        res_7_deny = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '7_SECOND'", "cwd": str(allowed_subdir), "capability_grant_id": grant_1use})
        assert res_7_deny["isError"] is True

        # Case 8: Unauthorized tool -> DENY (grant_a only allows agent_powershell_execute, not agent_get_active_window)
        res_8 = _call_tool(hdr_a1, "agent_get_active_window", {"capability_grant_id": grant_a})
        assert res_8["isError"] is True

        # Case 9: Invalid target path -> DENY (forbidden_subdir is outside allowed_subdir)
        res_9 = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '9'", "cwd": str(forbidden_subdir), "capability_grant_id": grant_a})
        assert res_9["isError"] is True

        # Case 10: Emergency Stop active -> DENY
        gw.policy.engage_emergency_stop("P0_TEST_EMERGENCY_STOP")
        try:
            res_10 = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output '10'", "cwd": str(allowed_subdir), "capability_grant_id": grant_a})
            assert res_10["isError"] is True
        finally:
            if hasattr(gw.policy, "reset_emergency_stop"):
                gw.policy.reset_emergency_stop()
            paths.clear_emergency_stop()

        # Case 11: Owner token placed only in tool arguments -> DENY
        res_11_static = _call_tool(
            hdr_static,
            "agent_powershell_execute",
            {
                "command": "Write-Output '11_STATIC'",
                "cwd": str(allowed_subdir),
                "capability_grant_id": grant_a,
                "owner_oauth_token": tok_a1,
            },
        )
        assert res_11_static["isError"] is True, "Case 11 failed: owner_oauth_token in tool args bypassed static bearer!"

        res_11_cross = _call_tool(
            hdr_b,
            "agent_powershell_execute",
            {
                "command": "Write-Output '11_CROSS'",
                "cwd": str(allowed_subdir),
                "capability_grant_id": grant_a,
                "owner_oauth_token": tok_a1,
            },
        )
        assert res_11_cross["isError"] is True, "Case 11 failed: owner_oauth_token in tool args hijacked Client A from Client B!"

        # Also verify that even with server profile="owner_full_control", omitting capability_grant_id on HTTP is DENIED
        res_no_grant = _call_tool(
            hdr_a1,
            "agent_powershell_execute",
            {"command": "Write-Output 'NO_GRANT'", "cwd": str(allowed_subdir)},
        )
        assert res_no_grant["isError"] is True, "Cloud HTTP request without capability_grant_id must be denied even on owner_full_control profile!"

        # Case 12: Correct owner OAuth + bound grant -> PASS
        res_12 = _call_tool(hdr_a1, "agent_powershell_execute", {"command": "Write-Output 'CASE_12_OK'", "cwd": str(allowed_subdir), "capability_grant_id": grant_a})
        assert res_12["isError"] is False
        assert "CASE_12_OK" in res_12["content"][0]["text"]
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_p0_03_concurrent_single_use_grant_and_lease_revocation():
    """Verify P0-03 atomic grant consumption under concurrency and lease expiration/revocation enforcement."""
    td, paths, gw, app, client, connector_secret = _setup_isolated_env(profile="owner_full_control")
    try:
        signing_key = _get_oauth_signing_key(app)
        persistence = app.state.oauth_persistence

        tok_owner = _issue_oauth_token(
            client_id="concurrent_owner",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, pay_owner, _ = _verify_oauth_token(tok_owner, signing_key, set())
        jti_owner = pay_owner["jti"]

        # 1. Incomplete auth context fails closed
        grant_single = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[td],
            owner_id="local_owner",
            client_id="concurrent_owner",
            oauth_token_jti=jti_owner,
            ttl_seconds=600.0,
            max_uses=1,
        )["grant_id"]

        ok_empty_client, _, _ = persistence.validate_and_consume_owner_grant(
            grant_single,
            secret=signing_key,
            tool_name="agent_powershell_execute",
            target_path=td,
            expected_owner_id="local_owner",
            expected_client_id="",
            oauth_token_jti=jti_owner,
        )
        assert ok_empty_client is False, "Empty expected_client_id must fail closed!"

        # 2. Two simultaneous requests against max_uses=1 grant -> at most one succeeds
        barrier = threading.Barrier(2)

        def _worker_consume():
            barrier.wait(timeout=5.0)
            ok, msg, info = persistence.validate_and_consume_owner_grant(
                grant_single,
                secret=signing_key,
                tool_name="agent_powershell_execute",
                target_path=td,
                expected_owner_id="local_owner",
                expected_client_id="concurrent_owner",
                oauth_token_jti=jti_owner,
            )
            return ok, msg, info

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_worker_consume)
            f2 = pool.submit(_worker_consume)
            r1 = f1.result(timeout=10.0)
            r2 = f2.result(timeout=10.0)

        successes = [r for r in (r1, r2) if r[0] is True]
        failures = [r for r in (r1, r2) if r[0] is False]
        assert len(successes) == 1, f"Expected exactly 1 concurrent consumption to succeed, got {len(successes)}"
        assert len(failures) == 1

        # 3. Associated lease revocation blocks grant consumption
        grant_with_lease = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[td],
            owner_id="local_owner",
            client_id="concurrent_owner",
            oauth_token_jti=jti_owner,
            ttl_seconds=600.0,
            max_uses=5,
        )["grant_id"]
        lease_info = persistence.activate_owner_cloud_lease(
            grant_id=grant_with_lease,
            oauth_token=tok_owner,
            owner_id="local_owner",
            ttl_seconds=600.0,
        )
        persistence.revoke_owner_cloud_lease(lease_info["lease_id"])

        ok_lease_rev, msg_lease_rev, _ = persistence.validate_and_consume_owner_grant(
            grant_with_lease,
            secret=signing_key,
            tool_name="agent_powershell_execute",
            target_path=td,
            expected_owner_id="local_owner",
            expected_client_id="concurrent_owner",
            oauth_token_jti=jti_owner,
        )
        assert ok_lease_rev is False, f"Revoked associated lease must block grant consumption! ({msg_lease_rev})"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_p0_04_separate_oauth_signing_key_from_connector_shared_secret():
    """Verify P0-04: A client knowing only the shared connector Bearer cannot mint a valid owner OAuth token or grant."""
    td, paths, gw, app, client, connector_secret = _setup_isolated_env(profile="owner_full_control")
    try:
        # 1. Dedicated oauth_signing_key must exist and must NOT equal connector_secret
        signing_key = getattr(app.state, "oauth_signing_key", None)
        assert signing_key is not None and len(signing_key) >= 32, "Dedicated oauth_signing_key is missing!"
        assert signing_key != connector_secret, "oauth_signing_key must never equal caller_auth_token!"

        # 2. Attacker knowing only connector_secret tries to mint an owner OAuth token
        forged_owner_tok = _issue_oauth_token(
            client_id="forged_owner_client",
            secret=connector_secret,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]

        res_forged = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {forged_owner_tok}", "Mcp-Protocol-Version": "2025-03-26"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        )
        assert res_forged.status_code == 403, f"P0-04 FAILED: Token signed with connector_secret was accepted! ({res_forged.status_code})"

        # 3. Attacker knowing only connector_secret tries to forge a capability grant signature
        persistence = app.state.oauth_persistence
        real_owner_tok = _issue_oauth_token(
            client_id="real_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, real_pay, _ = _verify_oauth_token(real_owner_tok, signing_key, set())
        real_jti = real_pay["jti"]

        forged_grant = persistence.issue_owner_capability_grant(
            secret=connector_secret,  # Forged with connector secret instead of oauth_signing_key
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[td],
            owner_id="local_owner",
            client_id="real_owner_client",
            oauth_token_jti=real_jti,
            ttl_seconds=600.0,
            max_uses=5,
        )["grant_id"]

        hdr_real = _mcp_init_and_headers(client, real_owner_tok)
        res_forged_grant = client.post(
            "/mcp",
            headers=hdr_real,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {"command": "Write-Output 'FORGED_GRANT'", "cwd": td, "capability_grant_id": forged_grant},
                },
            },
        )
        assert res_forged_grant.json()["result"]["isError"] is True, "P0-04 FAILED: Grant signed with connector_secret was accepted!"

        # 4. Configuration with oauth_signing_key == caller_auth_token must be rejected (fail closed)
        with pytest.raises((PermissionError, ValueError)):
            create_cloud_autonomous_adapter_app(
                gateway=gw,
                caller_auth_token=connector_secret,
                oauth_signing_key=connector_secret,
                db_path=paths.oauth_db_path,
            )
    finally:
        shutil.rmtree(td, ignore_errors=True)
