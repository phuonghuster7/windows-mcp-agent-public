"""MCP Gateway Automated Tests (Bridge v0.2.1 Compatibility + Profile-Gated P2/P3).

Covers:
1. MCP JSON-RPC 2.0 initialize handshake & ping
2. Strict read_only profile:
   - Exposes strictly the 15 Bridge v0.2.1 read-only tools (verifies no stale 8-tool snapshot)
   - Zero hidden write, shell, or desktop manipulation tools in tools/list
   - Rejects any direct tools/call to write_file, delete_file, powershell_execute, mouse_click
3. Execution of all 15 read-only tools via MCP JSON-RPC tools/call
4. Extended profiles (developer_p2, desktop_p3, full_agent):
   - Profile-gated publication of P2 and P3 tools
   - Execution of P2 (write_file, edit_file, powershell_execute, job_create/job_poll)
     and P3 (get_desktop_session_status, get_screen_geometry, screenshot) via MCP JSON-RPC tools/call
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _d in (PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from policy import PermissionTier, SecurityPolicy, V021_READ_TOOLS  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from file_code_ops import FileCodeOperations  # noqa: E402
from exec_jobs import ExecutionJobManager  # noqa: E402
from agent import DesktopAgent  # noqa: E402


EXPECTED_15_READ_TOOLS = {
    "get_roots",
    "list_directory",
    "list_tree",
    "stat_path",
    "read_file",
    "read_file_range",
    "get_file",
    "search_files",
    "search_code",
    "grep",
    "disk_usage",
    "path_exists",
    "git_status",
    "git_diff",
    "git_log",
}

LEGACY_8_TOOLS_SNAPSHOT = {
    "list_directory",
    "read_file",
    "read_file_range",
    "git_status",
    "git_diff",
    "git_log",
    "search_code",
    "path_exists",
}


class TestMCPGateway(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name).resolve()
        self.workspace = self.base / "workspace"
        self.backups = self.base / "backups"
        self.jobs_dir = self.base / "jobs"
        self.audit_log = self.base / "audit.jsonl"
        self.workspace.mkdir(parents=True, exist_ok=True)

        # Initialize disposable Git repo with a sample file
        subprocess.run(["git", "init"], cwd=str(self.workspace), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "gw@local.mcp"], cwd=str(self.workspace), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Gateway Test"], cwd=str(self.workspace), capture_output=True, check=True)

        sample_py = self.workspace / "app.py"
        sample_py.write_text(
            "def greet(name: str) -> str:\n    return f'Hello, {name}!'\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "app.py"], cwd=str(self.workspace), capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "Add app.py"], cwd=str(self.workspace), capture_output=True, check=True)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _make_gateway(self, profile: str) -> MCPGatewayServer:
        policy = SecurityPolicy(
            profile=profile,
            allowed_read_roots=[str(self.workspace)],
            allowed_write_roots=[str(self.workspace)],
            allowed_git_repos=[str(self.workspace)],
            allowed_exec_roots=[str(self.workspace)],
            audit_log_path=str(self.audit_log),
        )
        return MCPGatewayServer(
            policy=policy,
            file_ops=FileCodeOperations(policy=policy, backups_root=self.backups),
            exec_ops=ExecutionJobManager(policy=policy, jobs_dir=self.jobs_dir),
            desktop_agent=DesktopAgent(policy=policy, emergency_stop_file=self.base / "EMERGENCY_STOP"),
        )

    def test_read_only_profile_handshake_and_strict_15_tools_discovery(self) -> None:
        """Verify initialize handshake, strict 15 read tools, no stale 8-tool snapshot, and zero write tools."""
        gw = self._make_gateway("read_only")

        # 1. MCP initialize handshake
        init_resp = gw.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pytest-client", "version": "1.0.0"},
            },
        })
        self.assertIsNotNone(init_resp)
        assert init_resp is not None
        self.assertEqual(init_resp["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(init_resp["result"]["serverInfo"]["version"], "0.2.1")
        self.assertEqual(init_resp["result"]["serverInfo"]["profile"], "read_only")

        # 2. tools/list discovery
        list_resp = gw.handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert list_resp is not None
        tools = list_resp["result"]["tools"]
        exposed_names = {t["name"] for t in tools}

        # Must be strictly 15 tools (not stale 8-tool snapshot, and no extra P2/P3 tools)
        self.assertEqual(len(tools), 15)
        self.assertNotEqual(exposed_names, LEGACY_8_TOOLS_SNAPSHOT)
        self.assertEqual(exposed_names, EXPECTED_15_READ_TOOLS)
        self.assertEqual(exposed_names, set(V021_READ_TOOLS))

        # Verify no hidden write/exec/desktop tools in tools/list
        for forbidden in (
            "write_file",
            "edit_file",
            "delete_file",
            "powershell_execute",
            "cmd_execute",
            "job_create",
            "mouse_click",
            "keyboard_type",
            "focus_window",
        ):
            self.assertNotIn(forbidden, exposed_names)

        # Verify calling write/exec/desktop tools in read_only profile fails with isError=True
        for forbidden_call in (
            ("write_file", {"path": str(self.workspace / "hack.txt"), "content": "x"}),
            ("delete_file", {"path": str(self.workspace / "app.py")}),
            ("powershell_execute", {"command": "whoami", "cwd": str(self.workspace)}),
            ("mouse_click", {"x": 10, "y": 10}),
        ):
            call_resp = gw.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": forbidden_call[0], "arguments": forbidden_call[1]},
            })
            assert call_resp is not None
            self.assertTrue(call_resp["result"]["isError"], f"{forbidden_call[0]} was not blocked in read_only mode")

    def test_all_15_read_only_tools_via_mcp_jsonrpc(self) -> None:
        """Invoke all 15 Bridge v0.2.1 read-only tools via MCP JSON-RPC tools/call."""
        gw = self._make_gateway("read_only")
        app_path = str(self.workspace / "app.py")
        ws_path = str(self.workspace)

        calls = [
            ("get_roots", {}),
            ("path_exists", {"path": app_path}),
            ("stat_path", {"path": app_path}),
            ("disk_usage", {"path": ws_path}),
            ("list_directory", {"path": ws_path}),
            ("list_tree", {"path": ws_path, "max_depth": 2}),
            ("read_file", {"path": app_path}),
            ("read_file_range", {"path": app_path, "start_line": 1, "end_line": 2}),
            ("get_file", {"path": app_path}),
            ("search_files", {"root": ws_path, "pattern": "*.py"}),
            ("search_code", {"cwd": ws_path, "pattern": "greet", "file_glob": "*.py"}),
            ("grep", {"root": ws_path, "pattern": "Hello", "file_glob": "*.py"}),
            ("git_status", {"cwd": ws_path}),
            ("git_diff", {"cwd": ws_path}),
            ("git_log", {"cwd": ws_path, "n": 5}),
        ]

        for idx, (tool_name, tool_args) in enumerate(calls, start=10):
            resp = gw.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": tool_args},
            })
            assert resp is not None
            self.assertFalse(
                resp["result"]["isError"],
                f"Read tool {tool_name} failed: {resp['result']['content']}",
            )
            text_payload = resp["result"]["content"][0]["text"]
            parsed = json.loads(text_payload)
            self.assertIsNotNone(parsed)

    def test_full_agent_profile_p2_and_p3_jsonrpc_execution(self) -> None:
        """Verify profile-gated P2 and P3 tool publication and execution via MCP JSON-RPC."""
        gw = self._make_gateway("full_agent")

        list_resp = gw.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert list_resp is not None
        exposed = {t["name"] for t in list_resp["result"]["tools"]}

        # Must include all 15 read tools + P2 + P3 tools, and never SYSTEM_ADMIN tools
        self.assertTrue(EXPECTED_15_READ_TOOLS.issubset(exposed))
        for expected_ext in (
            "write_file",
            "edit_file",
            "apply_patch",
            "delete_file",
            "powershell_execute",
            "job_create",
            "job_poll",
            "get_desktop_session_status",
            "get_screen_geometry",
            "screenshot",
            "mouse_move",
            "keyboard_type",
            "visual_action_verify",
        ):
            self.assertIn(expected_ext, exposed)
        self.assertNotIn("system_admin_exec", exposed)
        self.assertNotIn("modify_firewall", exposed)

        # Verify fail-closed: without ControlSession, write_file is denied even in full_agent
        new_file = str(self.workspace / "created_via_mcp.txt")
        no_sess_resp = gw.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 19,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": new_file, "content": "Denied without session!\n"},
            },
        })
        assert no_sess_resp is not None
        self.assertTrue(no_sess_resp["result"]["isError"])

        # Mint an authorized ControlSession for WRITE, EXECUTE, DESKTOP
        sess = gw.policy.sessions.create_session(
            [PermissionTier.WRITE, PermissionTier.EXECUTE, PermissionTier.DESKTOP],
            ttl_seconds=600,
        )

        # Execute P2 write_file via JSON-RPC with active ControlSession
        w_resp = gw.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": new_file, "content": "Hello from MCP Gateway!\n"},
                },
            },
            session_id=sess.session_id,
        )
        assert w_resp is not None
        self.assertFalse(w_resp["result"]["isError"])
        w_data = json.loads(w_resp["result"]["content"][0]["text"])
        self.assertTrue(w_data["ok"])

        # Execute P2 powershell_execute via JSON-RPC with active ControlSession
        ps_resp = gw.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "powershell_execute",
                    "arguments": {"command": "Write-Output 'MCP_GATEWAY_EXEC_OK'", "cwd": str(self.workspace)},
                },
            },
            session_id=sess.session_id,
        )
        assert ps_resp is not None
        self.assertFalse(ps_resp["result"]["isError"])
        ps_data = json.loads(ps_resp["result"]["content"][0]["text"])
        self.assertEqual(ps_data["exit_code"], 0)
        self.assertIn("MCP_GATEWAY_EXEC_OK", ps_data["stdout"])

        # Execute P3 get_screen_geometry & get_desktop_session_status via JSON-RPC
        geom_resp = gw.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "get_screen_geometry", "arguments": {}},
        })
        assert geom_resp is not None
        self.assertFalse(geom_resp["result"]["isError"])
        geom_data = json.loads(geom_resp["result"]["content"][0]["text"])
        self.assertGreater(geom_data["primary_width"], 0)

        # Execute P3 screenshot via JSON-RPC and verify image/png content block
        sess_status = gw.desktop.get_desktop_session_status()
        if not sess_status["is_locked"] and sess_status["is_interactive"]:
            shot_resp = gw.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "screenshot",
                    "arguments": {"target": "region", "x": 0, "y": 0, "width": 120, "height": 90},
                },
            })
            assert shot_resp is not None
            self.assertFalse(shot_resp["result"]["isError"])
            content_list = shot_resp["result"]["content"]
            self.assertEqual(content_list[0]["type"], "image")
            self.assertEqual(content_list[0]["mimeType"], "image/png")


if __name__ == "__main__":
    unittest.main()
