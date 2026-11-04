"""Dedicated adapter lifecycle and coding authorization regressions (no live ports)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
for folder in (ROOT, ROOT / "mcp-gateway", ROOT / "backend", ROOT / "desktop-agent"):
    sys.path.insert(0, str(folder))

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app
from gateway_server import MCPGatewayServer
from http_server import _issue_oauth_token
from policy import SecurityPolicy
from runtime.agent_mcp_tools import CLOUD_SAFE_AUTONOMOUS_TOOLS
from runtime.coding_tools import CODING_TOOL_NAMES

TOKEN = "dedicated-test-owner-bearer"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDOWS_MCP_REQUIRE_AUTONOMOUS_AUTH", "false")
    monkeypatch.delenv("MCP_OAUTH_EXTERNAL_ISSUER", raising=False)
    monkeypatch.delenv("MCP_AUTONOMOUS_AUTH_SCHEME", raising=False)
    policy = SecurityPolicy(
        profile="full_agent", allowed_read_roots=[str(tmp_path)],
        allowed_write_roots=[str(tmp_path)], allowed_exec_roots=[str(tmp_path)],
        allowed_git_repos=[str(tmp_path)], audit_log_path=tmp_path / "audit.jsonl",
        emergency_stop_file=tmp_path / "EMERGENCY_STOP", require_session_for_privileged=False,
    )
    gw = MCPGatewayServer(policy=policy)
    app = create_cloud_autonomous_adapter_app(
        gateway=gw, caller_auth_token=TOKEN, require_autonomous_auth=False,
        allow_loopback_tunnel_identity=True, db_path=tmp_path / "oauth.db",
    )
    with TestClient(app) as client:
        yield client, app, gw


def rpc(client, method="ping", *, headers=None, params=None, req_id=1):
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    return client.post("/mcp", json=payload, headers=AUTH if headers is None else headers)


def initialize(client, version="2025-11-25", headers=None):
    return rpc(client, "initialize", params={"protocolVersion": version}, headers=headers)


def test_exact_fourteen_tools_on_dedicated_surface_only(env):
    client, app, gateway = env
    tools = rpc(client, "tools/list").json()["result"]["tools"]
    assert len(tools) == 14
    assert {t["name"] for t in tools} == set(CLOUD_SAFE_AUTONOMOUS_TOOLS) | CODING_TOOL_NAMES
    assert set(client.get("/health").json()["exposed_tools"]) == {t["name"] for t in tools}
    assert all(t["inputSchema"]["additionalProperties"] is False for t in tools if t["name"] in CODING_TOOL_NAMES)
    assert all(t["securitySchemes"] == [{"type": "noauth"}] for t in tools)
    for t in tools:
        if t["name"] in {"agent_run_tests", "agent_run_command"}:
            assert t["annotations"]["openWorldHint"] is True
    old = gateway.handle_jsonrpc_autonomous({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert {t["name"] for t in old["result"]["tools"]} == set(CLOUD_SAFE_AUTONOMOUS_TOOLS)


def test_bearer_required_despite_environment_and_legacy_switches(env):
    client, app, _ = env
    for headers in ({}, {"X-MCP-Caller-Id": "local_owner"}, {"X-MCP-Session-Id": "fake"}, {"X-MCP-Caller-Token": TOKEN}):
        assert rpc(client, headers=headers).status_code == 401
    assert rpc(client, headers={"Authorization": "Bearer invalid"}).status_code == 403
    assert app.state.require_autonomous_auth is True
    assert app.state.allow_loopback_tunnel_identity is False
    assert rpc(client).status_code == 200  # authenticated stateless compatibility


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
def test_protocol_negotiation_and_notification(env, version):
    client, _, _ = env
    response = initialize(client, version)
    assert response.json()["result"]["protocolVersion"] == version
    sid = response.headers["Mcp-Session-Id"]
    headers = {**AUTH, "Mcp-Session-Id": sid, "MCP-Protocol-Version": version}
    notice = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert notice.status_code == 202 and not notice.content
    assert rpc(client, headers=headers).json()["result"] == {}
    assert client.get("/mcp", headers=headers).status_code == 405


def test_stale_session_returns_404_and_fresh_initialize_recovers(env):
    client, app, _ = env
    sid = initialize(client).headers["Mcp-Session-Id"]
    headers = {**AUTH, "Mcp-Session-Id": sid}
    assert client.delete("/mcp", headers={"Mcp-Session-Id": sid}).status_code == 401
    assert client.delete("/mcp", headers=headers).status_code == 200
    assert rpc(client, headers=headers).status_code == 404
    assert initialize(client, headers=headers).status_code == 404
    assert sid not in app.state.mcp_stream_sessions
    fresh = initialize(client)
    assert fresh.status_code == 200 and fresh.headers["Mcp-Session-Id"] != sid
    assert rpc(client, headers={**AUTH, "Mcp-Session-Id": fresh.headers["Mcp-Session-Id"]}).status_code == 200


def test_session_ownership_expiry_capacity_and_version(env):
    client, app, _ = env
    sid = initialize(client).headers["Mcp-Session-Id"]
    other = _issue_oauth_token("other-client", app.state.oauth_signing_key)["access_token"]
    stolen = {"Authorization": f"Bearer {other}", "Mcp-Session-Id": sid}
    assert rpc(client, headers=stolen).status_code == 403
    assert client.delete("/mcp", headers=stolen).status_code == 403
    assert initialize(client, headers=stolen).status_code == 403
    assert rpc(client, headers={**AUTH, "Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-03-26"}).status_code == 400
    bad_protocol = {**AUTH, "Mcp-Session-Id": sid, "MCP-Protocol-Version": "unsupported"}
    assert client.get("/mcp", headers=bad_protocol).status_code == 400
    assert client.delete("/mcp", headers=bad_protocol).status_code == 400
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}]
    assert client.post("/mcp", headers={**AUTH, "Mcp-Session-Id": sid}, json=batch).status_code == 400
    app.state.mcp_session_last_seen[sid] = time.monotonic() - 4000
    assert rpc(client, headers={**AUTH, "Mcp-Session-Id": sid}).status_code == 404
    app.state.max_mcp_sessions = 2
    ids = [initialize(client).headers["Mcp-Session-Id"] for _ in range(3)]
    assert len(app.state.mcp_stream_sessions) == 2
    assert rpc(client, headers={**AUTH, "Mcp-Session-Id": ids[0]}).status_code == 404


def test_malformed_protocol_origin_and_coding_args_fail_cleanly(env):
    client, _, _ = env
    assert rpc(client, headers={**AUTH, "MCP-Protocol-Version": "bad"}).status_code == 400
    assert rpc(client, params=[]).status_code == 400
    assert rpc(client, headers={**AUTH, "Origin": "https://attacker.invalid"}).status_code == 403
    assert initialize(client, "unsupported-future-version").json()["result"]["protocolVersion"] == "2025-11-25"
    bad = rpc(client, "tools/call", params={"name": "agent_workspace_list", "arguments": {"caller_id": "local_owner"}})
    assert bad.status_code == 200 and bad.json()["result"]["isError"] is True


def test_direct_coding_tier_is_derived_from_verified_auth(env):
    client, app, gw = env

    class Recorder:
        def execute_tool(self, name, args, **kwargs):
            return kwargs

    gw._coding_tool_handler = Recorder()
    call = {"name": "agent_workspace_list", "arguments": {}}
    response = rpc(client, "tools/call", params=call)
    import json
    result = json.loads(response.json()["result"]["content"][0]["text"])
    assert result["caller_tier"] == "WRITE" and result["caller_id"] == "cloud_client_default"
    for scope, expected in (("mcp:autonomous", "READ"), ("mcp:autonomous mcp:coding:write", "WRITE")):
        token = _issue_oauth_token("oauth-client", app.state.oauth_signing_key, scope=scope)["access_token"]
        result = rpc(client, "tools/call", params=call, headers={"Authorization": f"Bearer {token}"})
        data = json.loads(result.json()["result"]["content"][0]["text"])
        assert data["caller_tier"] == expected and data["caller_id"] == "oauth-client"
    direct = gw.handle_jsonrpc_autonomous({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": call}, include_coding_tools=True)
    assert direct["result"]["isError"] is True


def test_session_survives_adapter_restart_and_auto_recovers_server_issued_session(tmp_path):
    db_file = tmp_path / "restart_test.db"
    policy = SecurityPolicy(
        profile="full_agent", allowed_read_roots=[str(tmp_path)],
        allowed_write_roots=[str(tmp_path)], allowed_exec_roots=[str(tmp_path)],
        allowed_git_repos=[str(tmp_path)], audit_log_path=tmp_path / "audit.jsonl",
        emergency_stop_file=tmp_path / "EMERGENCY_STOP", require_session_for_privileged=False,
    )
    gw1 = MCPGatewayServer(policy=policy)
    app1 = create_cloud_autonomous_adapter_app(
        gateway=gw1, caller_auth_token=TOKEN, require_autonomous_auth=False,
        allow_loopback_tunnel_identity=True, db_path=db_file,
    )
    with TestClient(app1) as client1:
        # 1. Issue session 1 (survives restart via SQLite)
        resp1 = initialize(client1, version="2025-11-25")
        assert resp1.status_code == 200
        sid1 = resp1.headers["Mcp-Session-Id"]
        assert sid1.startswith("sess_mcp_")

        # 2. Issue session 2 and explicitly DELETE it
        resp2 = initialize(client1, version="2025-11-25")
        sid2 = resp2.headers["Mcp-Session-Id"]
        del_resp = client1.delete("/mcp", headers={**AUTH, "Mcp-Session-Id": sid2})
        assert del_resp.status_code == 200

        # 3. Issue session 3 and expire it
        resp3 = initialize(client1, version="2025-11-25")
        sid3 = resp3.headers["Mcp-Session-Id"]
        app1.state.mcp_session_last_seen[sid3] = time.monotonic() - 5000
        # Trigger prune
        assert rpc(client1, headers={**AUTH, "Mcp-Session-Id": sid3}).status_code == 404

        # 4. Issue sessions to test eviction (capacity)
        # Touch sid1 to keep it newer than sid_evict_1
        app1.state.mcp_session_last_seen[sid1] = time.monotonic() + 500
        resp_evict_1 = initialize(client1, version="2025-11-25")
        sid_evict_1 = resp_evict_1.headers["Mcp-Session-Id"]
        app1.state.mcp_session_last_seen[sid_evict_1] = time.monotonic() - 500
        app1.state.max_mcp_sessions = len(app1.state.mcp_stream_sessions)
        # Trigger eviction of oldest (sid_evict_1) by adding a new one
        resp_evict_2 = initialize(client1, version="2025-11-25")
        assert rpc(client1, headers={**AUTH, "Mcp-Session-Id": sid_evict_1}).status_code == 404

    # Restart adapter with fresh instance pointing to the same SQLite db_file
    gw2 = MCPGatewayServer(policy=policy)
    app2 = create_cloud_autonomous_adapter_app(
        gateway=gw2, caller_auth_token=TOKEN, require_autonomous_auth=False,
        allow_loopback_tunnel_identity=True, db_path=db_file,
    )
    with TestClient(app2) as client2:
        # A) Session 1 issued before restart continues working with HTTP 200
        h1 = {**AUTH, "Mcp-Session-Id": sid1}
        res_list = rpc(client2, "tools/list", headers=h1)
        assert res_list.status_code == 200
        assert "result" in res_list.json()

        # B) A well-formed sess_mcp_<48_hex> that was never terminated auto-recovers
        unseen_sid = "sess_mcp_" + "f" * 48
        h_unseen = {**AUTH, "Mcp-Session-Id": unseen_sid}
        res_unseen_list = rpc(client2, "tools/list", headers=h_unseen)
        assert res_unseen_list.status_code == 200
        assert "result" in res_unseen_list.json()
        assert unseen_sid in app2.state.mcp_stream_sessions

        # Verify tools/call also works on auto-recovered session
        res_unseen_call = rpc(client2, "tools/call", params={"name": "agent_workspace_list", "arguments": {}}, headers=h_unseen)
        assert res_unseen_call.status_code == 200
        assert "result" in res_unseen_call.json()

        # C) Explicitly DELETE'd session still returns HTTP 404
        assert rpc(client2, headers={**AUTH, "Mcp-Session-Id": sid2}).status_code == 404

        # D) Expired session still returns HTTP 404
        assert rpc(client2, headers={**AUTH, "Mcp-Session-Id": sid3}).status_code == 404

        # E) Evicted session still returns HTTP 404
        assert rpc(client2, headers={**AUTH, "Mcp-Session-Id": sid_evict_1}).status_code == 404

        # F) Invalid session ID like "stale-acceptance-session" returns HTTP 404
        assert rpc(client2, headers={**AUTH, "Mcp-Session-Id": "stale-acceptance-session"}).status_code == 404

