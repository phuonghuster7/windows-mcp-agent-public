"""Unit tests verifying owner_full_control security boundaries, end-to-end execution, and authorization."""
from __future__ import annotations

import gc
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
_GW_DIR = str(Path(__file__).resolve().parent.parent / "mcp-gateway")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

import pytest

from gateway_server import MCPGatewayServer
from policy import GatewayPolicy, PermissionTier
from runtime.coding_tools import CodingToolHandler
from runtime.task_grant import TaskGrantBroker
from runtime.task_store import TaskStore


def test_owner_full_control_allows_any_drive_workspace():
    policy = GatewayPolicy(profile="owner_full_control")

    # In owner_full_control, unrestricted workspace access is enabled
    assert policy.unrestricted_workspace_access is True

    # Root access covers fixed drives
    roots = policy.get_roots_for_tier(PermissionTier.WRITE)
    assert len(roots) >= 1
    # Check that current project drive is covered
    current_drive = Path(".").resolve().anchor
    assert any(str(r).startswith(current_drive) for r in roots)


def test_owner_full_control_authorizes_privileged_without_repeated_approval_token():
    td = tempfile.mkdtemp()
    try:
        policy = GatewayPolicy(profile="owner_full_control")
        test_file = Path(td) / "test.txt"

        # In owner_full_control, authorize_tool succeeds directly without approval token
        tool_args = {"path": str(test_file), "content": "authorized_content"}
        auth_tier = policy.authorize_tool("write_file", tool_args)
        assert auth_tier == PermissionTier.WRITE

        # In restricted_read, the exact same call is blocked
        restricted_policy = GatewayPolicy(profile="restricted_read")
        with pytest.raises(PermissionError) as exc_blocked:
            restricted_policy.authorize_tool("write_file", tool_args)
        assert "not enabled in profile" in str(exc_blocked.value)
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_owner_full_control_coding_handler_executes_outside_repo():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        policy = GatewayPolicy(profile="owner_full_control")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy, db_path=ws / "tasks.db", preapproved_roots=[ws])
        store = TaskStore(db_path=ws / "tasks.db")
        handler = CodingToolHandler(store, broker, audit_path=ws / "audit.db")

        # 1. Write file to folder outside repository
        write_res = handler.execute_tool(
            "agent_write_file",
            {"workspace_root": str(ws), "path": "notes.txt", "content": "hello owner full control", "expected_sha256": "missing"},
            caller_tier="WRITE",
            caller_id="local_owner",
        )
        assert write_res["ok"] is True
        assert (ws / "notes.txt").read_text(encoding="utf-8") == "hello owner full control"

        # 2. Read file back
        read_res = handler.execute_tool(
            "agent_read_file",
            {"workspace_root": str(ws), "path": "notes.txt"},
            caller_tier="READ",
            caller_id="local_owner",
        )
        assert read_res["ok"] is True
        assert read_res["content"] == "hello owner full control"

        # 3. Run structured command
        cmd_res = handler.execute_tool(
            "agent_run_command",
            {"workspace_root": str(ws), "argv": [sys.executable, "-c", "print('EXEC_SUCCESS')"]},
            caller_tier="EXECUTE",
            caller_id="local_owner",
        )
        assert cmd_res["ok"] is True
        assert "EXEC_SUCCESS" in cmd_res["stdout"]

        # 4. Reject unauthenticated caller
        unauth_res = handler.execute_tool(
            "agent_read_file",
            {"workspace_root": str(ws), "path": "notes.txt"},
            caller_tier="READ",
            caller_id="anonymous",
        )
        assert unauth_res["ok"] is False
        assert "Authenticated caller identity is required" in unauth_res["error"]
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_owner_full_control_preserves_ads_and_unc_protection():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        policy = GatewayPolicy(profile="owner_full_control")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy, db_path=ws / "tasks.db", preapproved_roots=[ws])
        store = TaskStore(db_path=ws / "tasks.db")
        handler = CodingToolHandler(store, broker, audit_path=ws / "audit.db")

        # ADS streams are rejected
        ads_res = handler.execute_tool(
            "agent_write_file",
            {"workspace_root": str(ws), "path": "notes.txt:hidden", "content": "x", "expected_sha256": "missing"},
            caller_tier="WRITE",
            caller_id="local_owner",
        )
        assert ads_res["ok"] is False
        assert "Traversal, ADS, reserved, and ambiguous paths are denied" in ads_res["error"]

        # UNC paths are rejected
        unc_res = handler.execute_tool(
            "agent_read_file",
            {"workspace_root": r"\\evil-server\share\folder", "path": "file.txt"},
            caller_tier="READ",
            caller_id="local_owner",
        )
        assert unc_res["ok"] is False
        assert "UNC, device, or control-character paths are denied" in unc_res["error"]
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_owner_full_control_respects_emergency_stop():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        stop_file = ws / "EMERGENCY_STOP"
        policy = GatewayPolicy(profile="owner_full_control", emergency_stop_file=stop_file)
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy, db_path=ws / "tasks.db", preapproved_roots=[ws])
        store = TaskStore(db_path=ws / "tasks.db")
        handler = CodingToolHandler(store, broker, audit_path=ws / "audit.db")

        # Engage emergency stop
        policy.engage_emergency_stop(reason="Security audit test")
        assert policy.is_emergency_stop_active() is True
        assert stop_file.exists()

        # Any operation must be blocked immediately
        res = handler.execute_tool(
            "agent_write_file",
            {"workspace_root": str(ws), "path": "blocked.txt", "content": "x", "expected_sha256": "missing"},
            caller_tier="WRITE",
            caller_id="local_owner",
        )
        assert res["ok"] is False
        assert "Emergency Stop is active" in res["error"]
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_owner_full_control_gateway_jsonrpc_tools_list_and_call():
    policy = GatewayPolicy(profile="owner_full_control")
    gw = MCPGatewayServer(policy=policy)

    # 1. tools/list returns owner remote control tools
    list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    list_resp = gw.handle_jsonrpc_autonomous(list_req, caller_id="local_owner", include_coding_tools=True, caller_tier="WRITE")
    assert list_resp is not None
    assert "result" in list_resp
    tool_names = [t["name"] for t in list_resp["result"]["tools"]]

    assert "agent_powershell_execute" in tool_names
    assert "agent_desktop_screenshot" in tool_names
    assert "agent_system_status" in tool_names
    assert "agent_task_pause" in tool_names
    assert "agent_emergency_stop" in tool_names

    # 2. tools/call agent_system_status
    call_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "agent_system_status", "arguments": {}}}
    call_resp = gw.handle_jsonrpc_autonomous(call_req, caller_id="local_owner", include_coding_tools=True, caller_tier="WRITE")
    assert call_resp is not None
    assert call_resp["result"]["isError"] is False
    content_text = call_resp["result"]["content"][0]["text"]
    assert "os" in content_text or "drives" in content_text


def test_owner_full_control_http_transport_e2e():
    """Verify full HTTP ASGI stack over /mcp with Bearer auth and Mcp-Session-Id lifecycle (V01, V05)."""
    from fastapi.testclient import TestClient
    from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app

    td = tempfile.mkdtemp()
    try:
        policy = GatewayPolicy(profile="owner_full_control")
        gw = MCPGatewayServer(policy=policy)
        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token="owner_secret_token_12345",
            db_path=Path(td) / "oauth.db",
            enable_direct_coding=True,
        )
        client = TestClient(app)

        # 1. Health check returns all owner remote tools
        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        exposed = health_resp.json()["exposed_tools"]
        assert "agent_powershell_execute" in exposed
        assert "agent_system_status" in exposed
        assert "agent_workspace_list" in exposed

        # 2. Reject unauthenticated /mcp call
        unauth_resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert unauth_resp.status_code == 401

        # 3. Initialize session with owner OAuth Bearer auth + request-bound grant (P0-01/P0-02/P0-04)
        from http_server import _issue_oauth_token, _verify_oauth_token
        signing_key = app.state.oauth_signing_key
        owner_tok = _issue_oauth_token(
            client_id="owner_e2e_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, owner_pay, _ = _verify_oauth_token(owner_tok, signing_key, set())
        grant_info = app.state.oauth_persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute", "agent_system_status"],
            allowed_paths=[td, str(Path(".").resolve())],
            owner_id="local_owner",
            client_id="owner_e2e_client",
            oauth_token_jti=owner_pay["jti"],
            ttl_seconds=300.0,
            max_uses=5,
        )
        auth_hdr = {"Authorization": f"Bearer {owner_tok}", "Mcp-Protocol-Version": "2024-11-05"}
        init_resp = client.post(
            "/mcp",
            headers=auth_hdr,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        )
        assert init_resp.status_code == 200
        sess_id = init_resp.headers.get("Mcp-Session-Id")
        assert sess_id is not None and sess_id.startswith("sess_mcp_")

        sess_hdr = {**auth_hdr, "Mcp-Session-Id": sess_id}

        # 4. tools/list via HTTP
        list_resp = client.post(
            "/mcp",
            headers=sess_hdr,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert list_resp.status_code == 200
        tools = [t["name"] for t in list_resp.json()["result"]["tools"]]
        assert "agent_workspace_list" in tools
        assert "agent_powershell_execute" in tools
        assert "agent_system_status" in tools

        # 5. tools/call agent_workspace_list for C:\ (V01 verification)
        ws_call_resp = client.post(
            "/mcp",
            headers=sess_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "agent_workspace_list", "arguments": {"workspace_root": "C:\\", "max_entries": 2}},
            },
        )
        assert ws_call_resp.status_code == 200
        ws_result = ws_call_resp.json()["result"]
        assert ws_result.get("isError") is False
        assert "entries" in ws_result["content"][0]["text"]

        # 6. tools/call agent_powershell_execute with timeout and process control (V02 verification)
        ps_call_resp = client.post(
            "/mcp",
            headers=sess_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {
                        "command": "Write-Output 'LIVE_HTTP_OK'",
                        "cwd": td,
                        "capability_grant_id": grant_info["grant_id"],
                    },
                },
            },
        )
        assert ps_call_resp.status_code == 200
        ps_result = ps_call_resp.json()["result"]
        assert ps_result.get("isError") is False
        assert "LIVE_HTTP_OK" in ps_result["content"][0]["text"]

        # 7. tools/call agent_system_status
        sys_call_resp = client.post(
            "/mcp",
            headers=sess_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "agent_system_status", "arguments": {"capability_grant_id": grant_info["grant_id"]}},
            },
        )
        assert sys_call_resp.status_code == 200
        assert sys_call_resp.json()["result"]["isError"] is False
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_owner_full_control_r2_task_ownership_and_caller_identity():
    """Verify R2: Non-owner callers cannot hijack other tasks or run owner-only tools."""
    td = tempfile.mkdtemp()
    try:
        policy = GatewayPolicy(profile="owner_full_control")
        gw = MCPGatewayServer(policy=policy)
        agent_handler = gw.get_agent_tool_handler()

        # Alice creates a task
        alice_task = agent_handler.store.create_task(
            objective="Alice confidential task",
            workspace_root=td,
            owner_id="alice",
        )
        t_alice = alice_task.task_id

        # Bob (non-owner) attempts to cancel Alice's task -> MUST BE DENIED
        cancel_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "agent_task_cancel", "arguments": {"task_id": t_alice}},
        }
        res_bob = gw.handle_jsonrpc_autonomous(cancel_msg, caller_id="bob", caller_tier="READ")
        assert res_bob["result"]["isError"] is True
        assert "Caller does not own this task" in res_bob["result"]["content"][0]["text"]
        assert agent_handler.store.get_task(t_alice).state != "CANCELLED"

        # Bob (non-owner) attempts to execute powershell -> MUST BE DENIED
        ps_msg = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "agent_powershell_execute", "arguments": {"command": "Write-Output 'HACK'"}},
        }
        res_bob_ps = gw.handle_jsonrpc_autonomous(ps_msg, caller_id="bob", caller_tier="READ")
        assert res_bob_ps["result"]["isError"] is True
        assert "Caller is not authorized for owner-level powershell execution" in res_bob_ps["result"]["content"][0]["text"]

        # Alice (task owner) cancels her own task -> PERMITTED
        res_alice = gw.handle_jsonrpc_autonomous(cancel_msg, caller_id="alice", caller_tier="WRITE")
        assert res_alice["result"]["isError"] is False
        assert agent_handler.store.get_task(t_alice).state == "CANCELLED"

        # Owner ('local_owner') creates Bob task and cancels it -> PERMITTED
        bob_task = agent_handler.store.create_task(objective="Bob task", workspace_root=td, owner_id="bob")
        cancel_bob_by_owner = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "agent_task_cancel", "arguments": {"task_id": bob_task.task_id}},
        }
        res_owner = gw.handle_jsonrpc_autonomous(cancel_bob_by_owner, caller_id="local_owner", caller_tier="WRITE")
        assert res_owner["result"]["isError"] is False
        assert agent_handler.store.get_task(bob_task.task_id).state == "CANCELLED"
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_owner_full_control_r3_runner_bounded_streaming_and_interrupt():
    """Verify R3: Bounded streaming memory cap (64KB) and emergency stop interrupt polling."""
    import time
    import threading
    import tempfile
    import shutil
    from runtime.contracts import RuntimeStatePaths

    td = tempfile.mkdtemp(prefix="test_r3_isolated_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        policy = GatewayPolicy(profile="owner_full_control", emergency_stop_file=paths.emergency_stop_file)
        gw = MCPGatewayServer(policy=policy, runtime_paths=paths)

        # 1. Output >100KB is bounded to 64KB and truncated=True without deadlock
        large_cmd = "1..2000 | ForEach-Object { 'Line ' + $_ + ' with extensive padding data for buffer test 1234567890' }"
        msg_large = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "agent_powershell_execute", "arguments": {"command": large_cmd, "timeout_seconds": 15}},
        }
        res_large = gw.handle_jsonrpc_autonomous(msg_large, caller_id="local_owner", caller_tier="WRITE")
        assert res_large["result"]["isError"] is False
        import json
        data = json.loads(res_large["result"]["content"][0]["text"])
        assert data["exit_code"] == 0
        assert len(data["stdout"]) <= 65536
        assert data["truncated"] is True

        # 2. Emergency stop during execution terminates process tree early
        stop_file = paths.emergency_stop_file
        paths.clear_emergency_stop()

        def trigger_stop():
            time.sleep(0.4)
            paths.trigger_emergency_stop("STOP_TEST_ACTIVE")

        t = threading.Thread(target=trigger_stop, daemon=True)
        t.start()

        start_t = time.monotonic()
        sleep_cmd = "Start-Sleep -Seconds 4; Write-Output 'SHOULD_NOT_REACH'"
        msg_sleep = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "agent_powershell_execute", "arguments": {"command": sleep_cmd, "timeout_seconds": 15}},
        }
        res_sleep = gw.handle_jsonrpc_autonomous(msg_sleep, caller_id="local_owner", caller_tier="WRITE")
        dur = time.monotonic() - start_t
        paths.clear_emergency_stop()

        assert dur < 2.5, f"Expected emergency stop within ~1s, took {dur}s"
        data_sleep = json.loads(res_sleep["result"]["content"][0]["text"])
        assert data_sleep["interrupted"] is True
        assert data_sleep["cleanup_verified"] is True
        assert "Emergency Stop" in data_sleep["stderr"]
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_b2_b3_b4_owner_capability_grants_desktop_and_deterministic_tasks():
    """Verify B2, B3, and B4 remediation requirements and adversarial cases."""
    import json
    from fastapi.testclient import TestClient
    from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app
    from http_server import _issue_oauth_token, _verify_oauth_token
    from runtime.contracts import RuntimeStatePaths
    from runtime.autonomous_agent import AutonomousAgentController
    from runtime.task_store import TaskState

    td = tempfile.mkdtemp(prefix="test_b2_b3_b4_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        # Keep default policy="read_only" (do NOT disable policy globally!)
        policy = GatewayPolicy(profile="read_only", emergency_stop_file=paths.emergency_stop_file)
        gw = MCPGatewayServer(policy=policy, runtime_paths=paths)
        secret = "test_b2_b3_secret_token_999"
        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token=secret,
            db_path=paths.oauth_db_path,
        )
        client = TestClient(app)

        # 1. Default trusted-dev caller (static token, no active owner lease) sees exact 14 tools (B3 non-exposure)
        init_default = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {secret}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        )
        assert init_default.status_code == 200
        sess_default = init_default.headers["Mcp-Session-Id"]
        list_default = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {secret}", "Mcp-Session-Id": sess_default},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        default_tools = [t["name"] for t in list_default.json()["result"]["tools"]]
        assert len(default_tools) == 14
        assert "agent_powershell_execute" not in default_tools
        assert "agent_desktop_screenshot" not in default_tools
        assert "agent_keyboard_type" not in default_tools
        assert "agent_mouse_click" not in default_tools

        # Default caller attempting B2/B3 directly is strictly denied
        deny_default = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {secret}", "Mcp-Session-Id": sess_default},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "agent_powershell_execute", "arguments": {"command": "Write-Output 'NOPE'"}},
            },
        )
        assert deny_default.json()["result"]["isError"] is True
        assert "Permission Denied" in deny_default.json()["result"]["content"][0]["text"]

        # 2. Mint owner OAuth token (mcp:owner) and non-owner OAuth token (mcp:autonomous only) using dedicated oauth_signing_key
        signing_key = app.state.oauth_signing_key
        owner_tok = _issue_oauth_token(
            client_id="owner_chatgpt_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:owner mcp:coding:write",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        _, owner_payload, _ = _verify_oauth_token(owner_tok, signing_key, set())
        owner_jti = owner_payload["jti"]

        non_owner_tok = _issue_oauth_token(
            client_id="guest_client",
            secret=signing_key,
            scope="mcp:autonomous",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]

        # Issue short-lived bounded capability grant (max_uses=3)
        persistence = app.state.oauth_persistence
        grant_info = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=[
                "agent_powershell_execute",
                "agent_desktop_screenshot",
                "agent_get_active_window",
                "agent_focus_window",
                "agent_keyboard_type",
                "agent_mouse_click",
                "agent_visual_verify",
            ],
            allowed_paths=[td],
            owner_id="local_owner",
            client_id="owner_chatgpt_client",
            oauth_token_jti=owner_jti,
            ttl_seconds=300.0,
            max_uses=3,
        )
        gid = grant_info["grant_id"]

        # 3. B2: Non-owner OAuth token is denied even if presenting valid grant_id
        init_non_owner = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {non_owner_tok}"},
            json={"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        )
        sess_non_owner = init_non_owner.headers["Mcp-Session-Id"]
        res_non_owner = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {non_owner_tok}", "Mcp-Session-Id": sess_non_owner},
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {"command": "Write-Output 'NON_OWNER'", "cwd": td, "capability_grant_id": gid},
                },
            },
        )
        assert res_non_owner.json()["result"]["isError"] is True
        assert "not local_owner or lacks mcp:owner scope" in res_non_owner.json()["result"]["content"][0]["text"]

        # 4. B2: Owner OAuth token + valid capability grant executes PowerShell and returns stdout, stderr, exit_code
        init_owner = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}"},
            json={"jsonrpc": "2.0", "id": 20, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        )
        sess_owner = init_owner.headers["Mcp-Session-Id"]
        list_owner = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}", "Mcp-Session-Id": sess_owner},
            json={"jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {}},
        )
        owner_tools = [t["name"] for t in list_owner.json()["result"]["tools"]]
        for expected_t in (
            "agent_powershell_execute",
            "agent_desktop_screenshot",
            "agent_get_active_window",
            "agent_focus_window",
            "agent_keyboard_type",
            "agent_mouse_click",
            "agent_visual_verify",
        ):
            assert expected_t in owner_tools

        res_ps_ok = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}", "Mcp-Session-Id": sess_owner},
            json={
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {
                        "command": "Write-Output 'B2_STDOUT_OK'; [Console]::Error.WriteLine('B2_STDERR_MSG'); exit 0",
                        "cwd": td,
                        "capability_grant_id": gid,
                    },
                },
            },
        )
        ps_data = json.loads(res_ps_ok.json()["result"]["content"][0]["text"])
        assert ps_data["exit_code"] == 0
        assert "B2_STDOUT_OK" in ps_data["stdout"]
        assert "B2_STDERR_MSG" in ps_data["stderr"]
        assert ps_data["grant_used_count"] == 1

        # 5. B3: Owner desktop tool execution & bounded session exhaustion (uses 2 and 3, then 4th is rejected)
        res_win = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}", "Mcp-Session-Id": sess_owner},
            json={
                "jsonrpc": "2.0",
                "id": 23,
                "method": "tools/call",
                "params": {
                    "name": "agent_get_active_window",
                    "arguments": {"capability_grant_id": gid},
                },
            },
        )
        assert res_win.json()["result"]["isError"] is False
        win_data = json.loads(res_win.json()["result"]["content"][0]["text"])
        assert win_data["ok"] is True

        shot_file = Path(td) / "b3_test_shot.png"
        res_shot = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}", "Mcp-Session-Id": sess_owner},
            json={
                "jsonrpc": "2.0",
                "id": 24,
                "method": "tools/call",
                "params": {
                    "name": "agent_desktop_screenshot",
                    "arguments": {"max_width": 640, "save_path": str(shot_file), "capability_grant_id": gid},
                },
            },
        )
        assert res_shot.json()["result"]["isError"] is False
        shot_data = json.loads(res_shot.json()["result"]["content"][0]["text"])
        assert shot_data["ok"] is True
        assert shot_data["grant_used_count"] == 3
        assert shot_file.exists() and shot_file.stat().st_size > 0

        # 4th use exceeds max_uses=3 -> DENIED
        res_exhausted = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}", "Mcp-Session-Id": sess_owner},
            json={
                "jsonrpc": "2.0",
                "id": 25,
                "method": "tools/call",
                "params": {
                    "name": "agent_get_active_window",
                    "arguments": {"capability_grant_id": gid},
                },
            },
        )
        assert res_exhausted.json()["result"]["isError"] is True
        assert "exhausted its bounded session limit" in res_exhausted.json()["result"]["content"][0]["text"]

        # 6. Revoked capability grant is immediately denied
        grant2 = persistence.issue_owner_capability_grant(
            secret=signing_key,
            allowed_tools=["agent_powershell_execute"],
            allowed_paths=[td],
            owner_id="local_owner",
            client_id="owner_chatgpt_client",
            oauth_token_jti=owner_jti,
            ttl_seconds=300.0,
            max_uses=10,
        )
        gid2 = grant2["grant_id"]
        persistence.revoke_owner_capability_grant(gid2, reason="adversarial_revoke_test")
        res_revoked = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {owner_tok}", "Mcp-Session-Id": sess_owner},
            json={
                "jsonrpc": "2.0",
                "id": 26,
                "method": "tools/call",
                "params": {
                    "name": "agent_powershell_execute",
                    "arguments": {"command": "Write-Output 'REVOKED'", "cwd": td, "capability_grant_id": gid2},
                },
            },
        )
        assert res_revoked.json()["result"]["isError"] is True
        assert "has been revoked" in res_revoked.json()["result"]["content"][0]["text"]

        # 7. B4: Separate deterministic vs LLM-dependent background tasks
        agent_handler = gw.get_agent_tool_handler()
        ws_b4 = Path(td) / "b4_ws"
        ws_b4.mkdir(parents=True, exist_ok=True)
        (ws_b4 / "test_det.py").write_text("def test_pass():\n    assert 2 + 2 == 4\n", encoding="utf-8")
        agent_handler.broker.preapproved_roots.append(ws_b4.resolve())

        # 7a. LLM-dependent task on cloud surface transitions to BLOCKED when no live provider is configured
        llm_task_sub = agent_handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "CREATE quantum_router.py from scratch with full neural routing engine",
                "workspace_root": str(ws_b4),
            },
            caller_tier="READ",
            surface="cloud_autonomous",
            caller_id="owner_chatgpt_client",
        )
        llm_tid = llm_task_sub["task_id"]
        llm_grant = agent_handler.broker.issue_grant(
            task_id=llm_tid,
            workspace_root=str(ws_b4),
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        agent_handler.store.bind_grant(llm_tid, llm_grant.grant_id)
        ctrl_llm = AutonomousAgentController(llm_tid, agent_handler.store, agent_handler.broker, policy=GatewayPolicy(profile="full_agent"))
        final_llm = ctrl_llm.run()
        assert final_llm.state == TaskState.BLOCKED.value
        assert "MODEL_PROVIDER_NOT_CONFIGURED" in (final_llm.error_message or "")

        # 7b. Deterministic task reaches COMPLETED
        det_task_sub = agent_handler.execute_tool(
            "agent_submit_task",
            {
                "objective": "Inspect workspace and run pytest verification suite",
                "workspace_root": str(ws_b4),
            },
            caller_tier="READ",
            surface="cloud_autonomous",
            caller_id="owner_chatgpt_client",
        )
        det_tid = det_task_sub["task_id"]
        det_grant = agent_handler.broker.issue_grant(
            task_id=det_tid,
            workspace_root=str(ws_b4),
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        agent_handler.store.bind_grant(det_tid, det_grant.grant_id)
        ctrl_det = AutonomousAgentController(det_tid, agent_handler.store, agent_handler.broker, policy=GatewayPolicy(profile="full_agent"))
        final_det = ctrl_det.run()
        assert final_det.state == TaskState.COMPLETED.value

        # 8. Real _get_owner_desktop_agent() policy must authorize mouse_click and keyboard_type without secondary approval token failure
        from policy import PermissionTier
        gw.desktop_agent = None
        real_owner_desk = gw._get_owner_desktop_agent()
        assert real_owner_desk.policy.authorize_tool("mouse_click", {"x": 100, "y": 100, "button": "left"}) == PermissionTier.DESKTOP
        assert real_owner_desk.policy.authorize_tool("keyboard_type", {"text": "test"}) == PermissionTier.DESKTOP
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


