"""Stage S1 Verification: Fail-Closed Privileged Authorization, Independent Caller Authentication,
Scoped Owner Control Sessions, Single-Use Approval Tokens, and Emergency-Stop Job Termination.

Covers all 14 mandatory Sprint 3 Stage S1 security regression tests (Remediation of F01 & F02).
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _d in (PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from gateway_server import MCPGatewayServer, MCPGatewayServer as UnifiedMCPGateway  # noqa: E402
from http_server import create_gateway_http_app, load_gateway_auth_token  # noqa: E402
from policy import PolicyViolationError, SecurityPolicy  # noqa: E402


class TestS1PrivilegedAuth(unittest.TestCase):
    """Sprint 3 Stage S1 Privileged Security & Authentication Test Suite (14 Mandatory Tests)."""

    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory(dir=str(PROJECT_ROOT))
        self.tmp_path = Path(self._tmp_dir.name)
        self.auth_token = load_gateway_auth_token()
        self.auth_headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "X-MCP-Caller-Id": "owner-test-client",
        }

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def test_01_full_agent_no_session_write_file_denied(self) -> None:
        """1. full_agent profile without session -> write_file is DENIED (PolicyViolationError)."""
        gw = UnifiedMCPGateway(profile="full_agent")
        target_file = self.tmp_path / "unauth_write.txt"
        with self.assertRaises(PolicyViolationError) as ctx:
            gw.invoke_tool("write_file", {"path": str(target_file), "content": "denied"})
        self.assertIn("session", str(ctx.exception).lower())
        self.assertFalse(target_file.exists())

        # Also verify via JSON-RPC that isError=True is returned when no session_id is supplied
        rpc_resp = gw.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": str(target_file), "content": "denied"}},
        })
        self.assertTrue(rpc_resp["result"]["isError"])

    def test_02_full_agent_no_session_powershell_execute_denied(self) -> None:
        """2. full_agent profile without session -> powershell_execute is DENIED (PolicyViolationError)."""
        gw = UnifiedMCPGateway(profile="full_agent")
        with self.assertRaises(PolicyViolationError) as ctx:
            gw.invoke_tool("powershell_execute", {"command": "Write-Output 'hello'", "cwd": str(self.tmp_path)})
        self.assertIn("session", str(ctx.exception).lower())

    def test_03_full_agent_no_session_mouse_click_denied(self) -> None:
        """3. full_agent profile without session -> mouse_click is DENIED (PolicyViolationError)."""
        gw = UnifiedMCPGateway(profile="full_agent")
        with self.assertRaises(PolicyViolationError) as ctx:
            gw.invoke_tool("mouse_click", {"x": 50, "y": 50})
        self.assertIn("session", str(ctx.exception).lower())

    def test_04_read_only_profile_with_privileged_session_write_file_denied(self) -> None:
        """4. read_only profile WITH a valid WRITE/EXECUTE/DESKTOP ControlSession -> write_file is STILL DENIED."""
        gw = UnifiedMCPGateway(profile="read_only")
        sess = gw.policy.session_manager.create_session(
            owner="s1-admin",
            allowed_tiers=["READ", "WRITE", "EXECUTE", "DESKTOP"],
            ttl_seconds=300,
        )
        tok = gw.policy.session_manager.issue_approval_token(
            tier="WRITE",
            tool_name="write_file",
            session_id=sess.session_id,
        )
        target_file = self.tmp_path / "readonly_ceiling.txt"
        with self.assertRaises(PolicyViolationError) as ctx:
            gw.invoke_tool(
                "write_file",
                {"path": str(target_file), "content": "must fail"},
                session_id=sess.session_id,
                approval_token=tok.token_id,
            )
        self.assertIn("read_only", str(ctx.exception))
        self.assertFalse(target_file.exists())

    def test_05_forged_session_id_and_approval_token_denied(self) -> None:
        """5. Forged X-MCP-Session-Id or X-MCP-Approval-Token on /mcp -> DENIED."""
        pol = SecurityPolicy(profile="full_agent", emergency_stop_file=self.tmp_path / "EMERGENCY_STOP")
        gw = MCPGatewayServer(policy=pol)
        app = create_gateway_http_app(gateway=gw)
        client = TestClient(app)

        # Forged session ID with valid caller auth token -> 403
        resp_forged_sess = client.post(
            "/mcp",
            headers={
                **self.auth_headers,
                "X-MCP-Session-Id": "sess_forged_nonexistent_12345",
            },
            json={
                "jsonrpc": "2.0",
                "id": 501,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": str(self.tmp_path / "forged.txt"), "content": "x"},
                },
            },
        )
        self.assertEqual(resp_forged_sess.status_code, 403)
        self.assertTrue(resp_forged_sess.json()["result"]["isError"])

        # Valid session ID but forged approval token -> tool execution denied
        sess_res = client.post(
            "/api/sessions",
            headers=self.auth_headers,
            json={
                "owner": "s1-owner",
                "allowed_tiers": ["READ", "WRITE"],
                "ttl_seconds": 300,
                "issue_approval_tokens": False,
            },
        )
        self.assertEqual(sess_res.status_code, 200)
        valid_session_id = sess_res.json()["session"]["session_id"]

        resp_forged_tok = client.post(
            "/mcp",
            headers={
                **self.auth_headers,
                "X-MCP-Session-Id": valid_session_id,
                "X-MCP-Approval-Token": "appr_forged_token_99999",
            },
            json={
                "jsonrpc": "2.0",
                "id": 502,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": str(self.tmp_path / "forged_tok.txt"), "content": "x"},
                },
            },
        )
        self.assertEqual(resp_forged_tok.status_code, 200)
        self.assertTrue(resp_forged_tok.json()["result"]["isError"])
        self.assertIn("approval_token", resp_forged_tok.json()["result"]["content"][0]["text"])

    def test_06_smuggled_session_id_and_approval_token_in_arguments_denied(self) -> None:
        """6. _session_id, session_id, _approval_token, approval_token smuggled inside tool arguments -> DENIED."""
        gw = UnifiedMCPGateway(profile="full_agent")
        sess = gw.policy.session_manager.create_session(
            owner="s1-admin",
            allowed_tiers=["READ", "WRITE"],
            ttl_seconds=300,
        )
        for smuggled_key in ("_session_id", "session_id", "_approval_token", "approval_token"):
            # Even on a READ tool or WRITE tool with valid transport session, smuggled keys in arguments are rejected
            with self.assertRaises(PolicyViolationError) as ctx:
                gw.invoke_tool(
                    "path_exists",
                    {"path": str(self.tmp_path), smuggled_key: sess.session_id},
                    session_id=sess.session_id,
                )
            self.assertIn("smuggling", str(ctx.exception).lower())

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 601,
                    "method": "tools/call",
                    "params": {
                        "name": "write_file",
                        "arguments": {
                            "path": str(self.tmp_path / "smuggled.txt"),
                            "content": "bad",
                            smuggled_key: sess.session_id,
                        },
                    },
                },
                session_id=sess.session_id,
            )
            self.assertTrue(rpc_resp["result"]["isError"])
            self.assertIn("smuggling", rpc_resp["result"]["content"][0]["text"].lower())

    def test_07_expired_session_id_denied(self) -> None:
        """7. Expired session_id (TTL elapsed) -> DENIED."""
        gw = UnifiedMCPGateway(profile="full_agent")
        sess = gw.policy.session_manager.create_session(
            owner="s1-short-ttl",
            allowed_tiers=["READ", "WRITE"],
            ttl_seconds=1,
        )
        # Force expiration deterministically
        sess.expires_at = time.time() - 5.0
        with self.assertRaises(PolicyViolationError) as ctx:
            gw.invoke_tool(
                "write_file",
                {"path": str(self.tmp_path / "expired.txt"), "content": "denied"},
                session_id=sess.session_id,
            )
        self.assertIn("expired", str(ctx.exception).lower())

    def test_08_revoked_session_id_denied(self) -> None:
        """8. Revoked session_id (via POST /api/sessions/{session_id}/revoke) -> DENIED."""
        pol = SecurityPolicy(profile="full_agent", emergency_stop_file=self.tmp_path / "EMERGENCY_STOP")
        gw = MCPGatewayServer(policy=pol)
        app = create_gateway_http_app(gateway=gw)
        client = TestClient(app)

        create_resp = client.post(
            "/api/sessions",
            headers=self.auth_headers,
            json={
                "owner": "s1-revoke-test",
                "allowed_tiers": ["READ", "WRITE"],
                "ttl_seconds": 300,
                "issue_approval_tokens": True,
                "approval_tools": ["write_file"],
            },
        )
        self.assertEqual(create_resp.status_code, 200)
        data = create_resp.json()
        session_id = data["session"]["session_id"]
        approval_token = data["approval_tokens"]["write_file"]["token_id"]

        # Revoke via owner endpoint
        revoke_resp = client.post(
            f"/api/sessions/{session_id}/revoke",
            headers=self.auth_headers,
        )
        self.assertEqual(revoke_resp.status_code, 200)
        self.assertTrue(revoke_resp.json()["revoked"])

        # Subsequent /mcp call with revoked session_id must be rejected with 403
        mcp_resp = client.post(
            "/mcp",
            headers={
                **self.auth_headers,
                "X-MCP-Session-Id": session_id,
                "X-MCP-Approval-Token": approval_token,
            },
            json={
                "jsonrpc": "2.0",
                "id": 801,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": str(self.tmp_path / "revoked.txt"), "content": "denied"},
                },
            },
        )
        self.assertEqual(mcp_resp.status_code, 403)
        self.assertTrue(mcp_resp.json()["result"]["isError"])

    def test_09_single_use_approval_token_replay_denied(self) -> None:
        """9. Single-use approval_token used once -> succeeds; replayed a second time -> DENIED."""
        gw = UnifiedMCPGateway(profile="full_agent")
        sess = gw.policy.session_manager.create_session(
            owner="s1-replay-test",
            allowed_tiers=["READ", "WRITE"],
            ttl_seconds=300,
        )
        tok = gw.policy.session_manager.issue_approval_token(
            tier="WRITE",
            tool_name="write_file",
            session_id=sess.session_id,
            ttl_seconds=120,
        )
        target_file = self.tmp_path / "single_use.txt"

        # First call with approval token -> succeeds
        res1 = gw.invoke_tool(
            "write_file",
            {"path": str(target_file), "content": "first write ok"},
            session_id=sess.session_id,
            approval_token=tok.token_id,
        )
        self.assertTrue(res1["ok"])
        self.assertTrue(target_file.exists())

        # Second call replaying the same single-use approval token -> DENIED
        with self.assertRaises(PolicyViolationError) as ctx:
            gw.invoke_tool(
                "write_file",
                {"path": str(target_file), "content": "replay write must fail"},
                session_id=sess.session_id,
                approval_token=tok.token_id,
            )
        self.assertIn("approval_token", str(ctx.exception).lower())
        self.assertEqual(target_file.read_text(encoding="utf-8"), "first write ok")

    def test_10_valid_owner_session_allows_scoped_operations(self) -> None:
        """10. Valid owner-created session with matching tier/path/command scope -> WRITE/EXECUTE/DESKTOP succeed, out-of-scope DENIED."""
        scoped_dir = self.tmp_path / "scoped_workspace"
        scoped_dir.mkdir(parents=True, exist_ok=True)
        outside_dir = self.tmp_path / "outside_workspace"
        outside_dir.mkdir(parents=True, exist_ok=True)

        gw = UnifiedMCPGateway(profile="full_agent")
        sess = gw.policy.session_manager.create_session(
            owner="s1-scoped-owner",
            client_id="owner-test-client",
            allowed_tiers=["READ", "WRITE", "EXECUTE", "DESKTOP"],
            allowed_paths=[str(scoped_dir)],
            allowed_commands=[r"^Write-Output\s+'scoped-ok'$"],
            allowed_tools=["write_file", "powershell_execute", "mouse_click"],
            ttl_seconds=300,
        )

        # 1) Scoped WRITE succeeds
        tok_write = gw.policy.session_manager.issue_approval_token(
            tier="WRITE", tool_name="write_file", session_id=sess.session_id
        )
        in_scope_file = scoped_dir / "allowed.txt"
        w_res = gw.invoke_tool(
            "write_file",
            {"path": str(in_scope_file), "content": "scoped content"},
            session_id=sess.session_id,
            approval_token=tok_write.token_id,
            caller_id="owner-test-client",
        )
        self.assertTrue(w_res["ok"])

        # Out-of-scope path is DENIED even though inside global allowed_roots
        tok_write_2 = gw.policy.session_manager.issue_approval_token(
            tier="WRITE", tool_name="write_file", session_id=sess.session_id
        )
        with self.assertRaises(PolicyViolationError) as path_ctx:
            gw.invoke_tool(
                "write_file",
                {"path": str(outside_dir / "forbidden.txt"), "content": "nope"},
                session_id=sess.session_id,
                approval_token=tok_write_2.token_id,
                caller_id="owner-test-client",
            )
        self.assertIn("allowed_paths", str(path_ctx.exception))

        # 2) Scoped EXECUTE succeeds
        tok_exec = gw.policy.session_manager.issue_approval_token(
            tier="EXECUTE", tool_name="powershell_execute", session_id=sess.session_id
        )
        e_res = gw.invoke_tool(
            "powershell_execute",
            {"command": "Write-Output 'scoped-ok'", "cwd": str(scoped_dir)},
            session_id=sess.session_id,
            approval_token=tok_exec.token_id,
            caller_id="owner-test-client",
        )
        self.assertEqual(e_res["exit_code"], 0)
        self.assertIn("scoped-ok", e_res["stdout"])

        # Out-of-scope command is DENIED
        tok_exec_2 = gw.policy.session_manager.issue_approval_token(
            tier="EXECUTE", tool_name="powershell_execute", session_id=sess.session_id
        )
        with self.assertRaises(PolicyViolationError) as cmd_ctx:
            gw.invoke_tool(
                "powershell_execute",
                {"command": "Write-Output 'other-command'", "cwd": str(scoped_dir)},
                session_id=sess.session_id,
                approval_token=tok_exec_2.token_id,
                caller_id="owner-test-client",
            )
        self.assertIn("allowed_commands", str(cmd_ctx.exception))

        # 3) Scoped DESKTOP succeeds (with interactive session unlocked check mocked)
        tok_desk = gw.policy.session_manager.issue_approval_token(
            tier="DESKTOP", tool_name="mouse_click", session_id=sess.session_id
        )
        with patch.object(gw.desktop, "_require_interactive_unlocked_desktop"), \
             patch("ctypes.windll.user32.SetCursorPos"), \
             patch("ctypes.windll.user32.mouse_event"):
            d_res = gw.invoke_tool(
                "mouse_click",
                {"x": 120, "y": 140},
                session_id=sess.session_id,
                approval_token=tok_desk.token_id,
                caller_id="owner-test-client",
            )
        self.assertTrue(d_res["ok"])

    def test_11_emergency_stop_blocks_new_calls_and_cancels_running_jobs(self) -> None:
        """11. POST /api/emergency-stop blocks new WRITE/EXECUTE/DESKTOP calls AND terminates/cancels in-flight background jobs."""
        pol = SecurityPolicy(profile="full_agent", emergency_stop_file=self.tmp_path / "EMERGENCY_STOP")
        gw = MCPGatewayServer(policy=pol)
        app = create_gateway_http_app(gateway=gw)
        client = TestClient(app)

        # Create session + approval token to launch a long-running background job
        sess_resp = client.post(
            "/api/sessions",
            headers=self.auth_headers,
            json={
                "owner": "s1-estop-owner",
                "allowed_tiers": ["READ", "WRITE", "EXECUTE", "DESKTOP"],
                "ttl_seconds": 300,
                "issue_approval_tokens": True,
                "approval_tools": ["job_create", "write_file"],
            },
        )
        self.assertEqual(sess_resp.status_code, 200)
        s_data = sess_resp.json()
        session_id = s_data["session"]["session_id"]
        bg_tok = s_data["approval_tokens"]["job_create"]["token_id"]

        # Start a background job that sleeps for 30 seconds
        bg_mcp = client.post(
            "/mcp",
            headers={
                **self.auth_headers,
                "X-MCP-Session-Id": session_id,
                "X-MCP-Approval-Token": bg_tok,
            },
            json={
                "jsonrpc": "2.0",
                "id": 1101,
                "method": "tools/call",
                "params": {
                    "name": "job_create",
                    "arguments": {
                        "command": "Start-Sleep -Seconds 30",
                        "cwd": str(self.tmp_path),
                        "timeout_seconds": 60,
                    },
                },
            },
        )
        self.assertEqual(bg_mcp.status_code, 200)
        self.assertFalse(bg_mcp.json()["result"]["isError"])
        job_info = json.loads(bg_mcp.json()["result"]["content"][0]["text"])
        job_id = job_info["job_id"]

        # Trigger Emergency Stop via authenticated HTTP endpoint
        estop_resp = client.post(
            "/api/emergency-stop",
            headers=self.auth_headers,
            json={"reason": "S1 Test 11 Emergency Stop Verification"},
        )
        self.assertEqual(estop_resp.status_code, 200)
        estop_data = estop_resp.json()
        self.assertTrue(estop_data["emergency_stop"])
        self.assertIn(job_id, estop_data["cancelled_jobs"])
        self.assertGreaterEqual(estop_data["revoked_sessions"], 1)

        # Verify background job is cancelled/terminated
        status_res = app.state.gateway.exec_ops._read_job_state(job_id)
        self.assertEqual(status_res["status"], "cancelled")

        # Verify new privileged calls are blocked while Emergency Stop is active
        with self.assertRaises(PolicyViolationError) as estop_ctx:
            app.state.gateway.invoke_tool(
                "write_file",
                {"path": str(self.tmp_path / "blocked_by_estop.txt"), "content": "no"},
            )
        self.assertIn("emergency stop", str(estop_ctx.exception).lower())

        # Reset Emergency Stop and verify it clears cleanly
        reset_resp = client.post("/api/emergency-stop/reset", headers=self.auth_headers)
        self.assertEqual(reset_resp.status_code, 200)
        self.assertFalse(reset_resp.json()["emergency_stop"])

    def test_12_unauthenticated_api_session_and_emergency_stop_rejected(self) -> None:
        """12. Unauthenticated calls to /api/sessions or /api/emergency-stop -> HTTP 401/403 DENIED."""
        pol = SecurityPolicy(profile="full_agent", emergency_stop_file=self.tmp_path / "EMERGENCY_STOP")
        gw = MCPGatewayServer(policy=pol)
        app = create_gateway_http_app(gateway=gw)
        client = TestClient(app)

        # Missing token -> 401
        r1 = client.post("/api/sessions", json={"owner": "attacker", "allowed_tiers": ["WRITE"]})
        self.assertIn(r1.status_code, (401, 403))

        r2 = client.post("/api/emergency-stop", json={"reason": "unauth"})
        self.assertIn(r2.status_code, (401, 403))

        r3 = client.post("/api/sessions/revoke-all")
        self.assertIn(r3.status_code, (401, 403))

        # Wrong Bearer token -> 401
        bad_headers = {"Authorization": "Bearer wrong_token_value_000"}
        r4 = client.post("/api/sessions", headers=bad_headers, json={"owner": "attacker"})
        self.assertIn(r4.status_code, (401, 403))

        r5 = client.post("/api/emergency-stop/reset", headers=bad_headers)
        self.assertIn(r5.status_code, (401, 403))

    def test_13_unauthorized_task_scheduler_and_service_persistence_denied(self) -> None:
        """13. Unauthorized Task Scheduler / Windows Service creation via powershell_execute -> DENIED even with EXECUTE session."""
        gw = UnifiedMCPGateway(profile="full_agent")
        sess = gw.policy.session_manager.create_session(
            owner="s1-admin",
            allowed_tiers=["READ", "EXECUTE"],
            ttl_seconds=300,
        )
        persistence_commands = [
            "schtasks /create /tn BackdoorTask /tr calc.exe /sc onlogon",
            "New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'cmd.exe')",
            "Register-ScheduledTask -TaskName 'Persist' -InputObject $task",
            "sc.exe create EvilService binPath= 'C:\\evil.exe'",
            "New-Service -Name 'EvilSvc' -BinaryPathName 'C:\\evil.exe'",
        ]
        for cmd in persistence_commands:
            tok = gw.policy.session_manager.issue_approval_token(
                tier="EXECUTE", tool_name="powershell_execute", session_id=sess.session_id
            )
            with self.assertRaises(PolicyViolationError, msg=f"Command was not blocked: {cmd}"):
                gw.invoke_tool(
                    "powershell_execute",
                    {"command": cmd, "cwd": str(self.tmp_path)},
                    session_id=sess.session_id,
                    approval_token=tok.token_id,
                )

    def test_14_unauthorized_firewall_uac_defender_changes_denied(self) -> None:
        """14. Unauthorized Firewall / UAC / Defender disabling -> DENIED by command blocklist even with EXECUTE session."""
        gw = UnifiedMCPGateway(profile="full_agent")
        sess = gw.policy.session_manager.create_session(
            owner="s1-admin",
            allowed_tiers=["READ", "EXECUTE"],
            ttl_seconds=300,
        )
        security_tamper_commands = [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Add-MpPreference -ExclusionPath 'C:\\Temp'",
            "netsh advfirewall set allprofiles state off",
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
            "Disable-NetFirewallRule -DisplayName 'Core Networking'",
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f",
        ]
        for cmd in security_tamper_commands:
            tok = gw.policy.session_manager.issue_approval_token(
                tier="EXECUTE", tool_name="powershell_execute", session_id=sess.session_id
            )
            with self.assertRaises(PolicyViolationError, msg=f"Security tamper command was not blocked: {cmd}"):
                gw.invoke_tool(
                    "powershell_execute",
                    {"command": cmd, "cwd": str(self.tmp_path)},
                    session_id=sess.session_id,
                    approval_token=tok.token_id,
                )


if __name__ == "__main__":
    unittest.main()
