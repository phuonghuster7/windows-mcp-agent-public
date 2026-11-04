"""Section 11: Mandatory 20 Security Red-Team Tests & Independent QA Audit Suite.

Owner: AGENT E — Independent QA / Red Team Engineer
Target: Windows Local-Computer Full-Control Agent Stack (Antigravity 2.0)

This suite implements 20 distinct adversarial Red-Team security tests mapping 1-to-1
to the 20 mandatory requirements in Section 11:
  01. test_01_readonly_caller_cannot_invoke_write_file
  02. test_02_readonly_caller_cannot_invoke_powershell_execute
  03. test_03_expired_sessions_are_rejected
  04. test_04_revoked_sessions_are_rejected
  05. test_05_forged_session_ids_are_rejected
  06. test_06_forged_approval_tokens_are_rejected
  07. test_07_write_cannot_escape_approved_write_roots
  08. test_08_execute_cannot_bypass_execution_policy
  09. test_09_symlink_and_junction_traversal_blocked
  10. test_10_recursive_search_does_not_expose_secrets
  11. test_11_git_cannot_escape_approved_repository_scope
  12. test_12_locked_workstation_rejects_gui_interaction
  13. test_13_emergency_stop_prevents_all_desktop_actions
  14. test_14_sensitive_screenshot_targets_are_blocked
  15. test_15_secrets_redacted_from_logs_and_tool_results
  16. test_16_legacy_ngrok_edge_cannot_bypass_authorization
  17. test_17_backend_direct_calls_without_credentials_are_denied
  18. test_18_unapproved_cloud_connector_cannot_access_advanced_capabilities
  19. test_19_tool_discovery_changes_do_not_bypass_per_action_policy
  20. test_20_rollback_restores_last_known_good_state
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _d in (PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from policy import (  # noqa: E402
    AuditLogger,
    PermissionTier,
    SecurityPolicy,
    V021_READ_TOOLS,
    redact_secrets,
)
from gateway_server import ALL_TOOL_DEFINITIONS, MCPGatewayServer  # noqa: E402
from file_code_ops import FileCodeOperations  # noqa: E402
from exec_jobs import ExecutionJobManager  # noqa: E402
from agent import (  # noqa: E402
    DesktopAgent,
    DesktopSessionLockedError,
    EmergencyStopActiveError,
)

MCP_BRIDGE_URL = "http://127.0.0.1:8765/mcp"
BACKEND_BASE_URL = "http://127.0.0.1:3080"
NGROK_API_URL = "http://127.0.0.1:4040/api/tunnels"
ROLLBACK_SCRIPT_PATH = PROJECT_ROOT / "scripts" / "Rollback-WindowsMcp.ps1"
EVIDENCE_PATH = PROJECT_ROOT / "runtime" / "evidence" / "stage8_red_team_qa.json"

_TK_SENSITIVE_WINDOW_SCRIPT = """
import sys
import tkinter as tk

title = sys.argv[1]
root = tk.Tk()
root.title(title)
root.geometry("380x240+140+140")
root.attributes("-topmost", True)
lbl = tk.Label(root, text="Sensitive Credential Vault Window", bg="#551111", fg="white", height=6)
lbl.pack(fill="both", expand=True, padx=15, pady=15)
root.after(15000, root.destroy)
root.mainloop()
"""

# Global evidence collector populated during test execution
_RED_TEAM_EVIDENCE: dict[str, dict[str, Any]] = {}


def _record_evidence(
    test_id: str,
    *,
    requirement: str,
    execution_origin: str,
    passed: bool,
    latency_ms: float,
    details: dict[str, Any],
) -> None:
    _RED_TEAM_EVIDENCE[test_id] = {
        "test_id": test_id,
        "requirement": requirement,
        "execution_origin": execution_origin,
        "status": "PASS" if passed else "FAIL",
        "passed": passed,
        "latency_ms": round(latency_ms, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }


def _call_mcp_http(
    method: str,
    params: dict[str, Any] | None = None,
    req_id: int = 1,
    url: str = MCP_BRIDGE_URL,
    timeout: float = 10.0,
) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params if params is not None else {},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw_text = resp.read().decode("utf-8", errors="replace").strip()

    for line in raw_text.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("data:"):
            json_str = trimmed[5:].strip()
            if json_str:
                return json.loads(json_str)
    if raw_text.startswith("{"):
        return json.loads(raw_text)
    raise ValueError(f"Unrecognized MCP HTTP response: {raw_text[:200]}")


class TestRedTeamSecurity(unittest.TestCase):
    """20 Mandatory Adversarial Red-Team Security Tests (Section 11)."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name).resolve()
        self.workspace = self.base / "workspace"
        self.outside = self.base / "outside_root"
        self.outside_git = self.base / "outside_git_repo"
        self.backups = self.base / "backups"
        self.jobs_dir = self.base / "jobs"
        self.audit_log = self.base / "logs" / "audit.jsonl"
        self.emergency_file = self.base / "EMERGENCY_STOP"

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.outside.mkdir(parents=True, exist_ok=True)
        self.outside_git.mkdir(parents=True, exist_ok=True)
        (self.outside / "escaped.txt").write_text("TOP_SECRET_OUTSIDE_DATA\n", encoding="utf-8")

        # Initialize approved Git repository inside workspace
        for repo_dir in (self.workspace, self.outside_git):
            subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, check=True)
            subprocess.run(
                ["git", "config", "user.email", "redteam@local.mcp"],
                cwd=str(repo_dir),
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Red Team Verifier"],
                cwd=str(repo_dir),
                capture_output=True,
                check=True,
            )
            sample = repo_dir / "main.py"
            sample.write_text("print('ok')\n", encoding="utf-8")
            subprocess.run(["git", "add", "main.py"], cwd=str(repo_dir), capture_output=True, check=True)
            subprocess.run(
                ["git", "commit", "-m", "init"],
                cwd=str(repo_dir),
                capture_output=True,
                check=True,
            )

    def tearDown(self) -> None:
        if self.emergency_file.exists():
            try:
                self.emergency_file.unlink()
            except OSError:
                pass
        self.tmp_dir.cleanup()

    def _make_stack(
        self,
        profile: str = "read_only",
        *,
        enabled_tiers: list[str | PermissionTier] | None = None,
        approval_token: str = "valid_master_approval_token_777",
    ) -> tuple[SecurityPolicy, MCPGatewayServer, FileCodeOperations, ExecutionJobManager, DesktopAgent]:
        policy = SecurityPolicy(
            profile=profile,
            allowed_read_roots=[str(self.workspace)],
            allowed_write_roots=[str(self.workspace)],
            allowed_git_repos=[str(self.workspace)],
            allowed_exec_roots=[str(self.workspace)],
            enabled_tiers=enabled_tiers,
            audit_log_path=str(self.audit_log),
            approval_token=approval_token,
        )
        file_ops = FileCodeOperations(policy=policy, backups_root=self.backups)
        exec_ops = ExecutionJobManager(policy=policy, jobs_dir=self.jobs_dir)
        desktop = DesktopAgent(policy=policy, emergency_stop_file=self.emergency_file)
        gw = MCPGatewayServer(
            policy=policy,
            file_ops=file_ops,
            exec_ops=exec_ops,
            desktop_agent=desktop,
        )
        return policy, gw, file_ops, exec_ops, desktop

    # ------------------------------------------------------------------
    # Test 01: Read-only caller cannot invoke write_file
    # ------------------------------------------------------------------
    def test_01_readonly_caller_cannot_invoke_write_file(self) -> None:
        t0 = time.perf_counter()
        policy, gw, file_ops, _, _ = self._make_stack("read_only")
        target_path = self.workspace / "unauthorized_write.txt"

        # 1. Verify write_file is not exposed in tools/list
        exposed = set(gw.exposed_tool_names())
        self.assertNotIn("write_file", exposed)

        # 2. Direct Python API via FileCodeOperations
        with self.assertRaises(PermissionError):
            file_ops.write_file(str(target_path), "pwned")

        # 3. Gateway invoke_tool API
        with self.assertRaises(PermissionError):
            gw.invoke_tool("write_file", {"path": str(target_path), "content": "pwned"})

        # 4. MCP JSON-RPC tools/call
        rpc_resp = gw.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": str(target_path), "content": "pwned"},
            },
        })
        assert rpc_resp is not None
        self.assertTrue(rpc_resp["result"]["isError"])
        self.assertFalse(target_path.exists())

        _record_evidence(
            "test_01_readonly_caller_cannot_invoke_write_file",
            requirement="Read-only caller cannot invoke write_file via Python API or MCP JSON-RPC",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "profile": "read_only",
                "exposed_in_tools_list": "write_file" in exposed,
                "python_api_rejected": True,
                "jsonrpc_is_error": rpc_resp["result"]["isError"],
                "file_created": target_path.exists(),
            },
        )

    # ------------------------------------------------------------------
    # Test 02: Read-only caller cannot invoke powershell_execute
    # ------------------------------------------------------------------
    def test_02_readonly_caller_cannot_invoke_powershell_execute(self) -> None:
        t0 = time.perf_counter()
        _, gw, _, exec_ops, _ = self._make_stack("read_only")

        exposed = set(gw.exposed_tool_names())
        self.assertNotIn("powershell_execute", exposed)

        # 1. Direct Python API via ExecutionJobManager
        with self.assertRaises(PermissionError):
            exec_ops.powershell_execute("Write-Output 'UNAUTHORIZED'", cwd=str(self.workspace))

        # 2. Gateway invoke_tool API
        with self.assertRaises(PermissionError):
            gw.invoke_tool(
                "powershell_execute",
                {"command": "Write-Output 'UNAUTHORIZED'", "cwd": str(self.workspace)},
            )

        # 3. MCP JSON-RPC tools/call
        rpc_resp = gw.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "powershell_execute",
                "arguments": {"command": "Write-Output 'UNAUTHORIZED'", "cwd": str(self.workspace)},
            },
        })
        assert rpc_resp is not None
        self.assertTrue(rpc_resp["result"]["isError"])

        _record_evidence(
            "test_02_readonly_caller_cannot_invoke_powershell_execute",
            requirement="Read-only caller cannot invoke powershell_execute via Python API or MCP JSON-RPC",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "profile": "read_only",
                "exposed_in_tools_list": "powershell_execute" in exposed,
                "python_api_rejected": True,
                "jsonrpc_is_error": rpc_resp["result"]["isError"],
            },
        )

    # ------------------------------------------------------------------
    # Test 03: Expired sessions are rejected
    # ------------------------------------------------------------------
    def test_03_expired_sessions_are_rejected(self) -> None:
        t0 = time.perf_counter()
        for prof in ("read_only", "full_agent"):
            policy, gw, _, _, _ = self._make_stack(prof)
            sess = policy.sessions.create_session(
                [PermissionTier.WRITE, PermissionTier.EXECUTE], ttl_seconds=1
            )
            # Backdate expiration so test is deterministic and immediate
            sess.expires_at = time.time() - 10.0
            self.assertFalse(sess.is_active())

            with self.assertRaises(
                PermissionError,
                msg=f"Expired session was not rejected for write_file in profile={prof}",
            ):
                gw.invoke_tool(
                    "write_file",
                    {"path": str(self.workspace / f"expired_{prof}.txt"), "content": "x"},
                    session_id=sess.session_id,
                )

            with self.assertRaises(
                PermissionError,
                msg=f"Expired session was not rejected for powershell_execute in profile={prof}",
            ):
                gw.invoke_tool(
                    "powershell_execute",
                    {"command": "Write-Output 'expired'", "cwd": str(self.workspace)},
                    session_id=sess.session_id,
                )

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 103,
                    "method": "tools/call",
                    "params": {
                        "name": "write_file",
                        "arguments": {"path": str(self.workspace / f"expired_rpc_{prof}.txt"), "content": "x"},
                    },
                },
                session_id=sess.session_id,
            )
            assert rpc_resp is not None
            self.assertTrue(rpc_resp["result"]["isError"])

        _record_evidence(
            "test_03_expired_sessions_are_rejected",
            requirement="Expired ControlSessions are rejected across both read_only and full_agent profiles",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "profiles_tested": ["read_only", "full_agent"],
                "tools_tested": ["write_file", "powershell_execute"],
                "rejected_on_all_profiles": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 04: Revoked sessions are rejected
    # ------------------------------------------------------------------
    def test_04_revoked_sessions_are_rejected(self) -> None:
        t0 = time.perf_counter()
        for prof in ("developer_p2", "full_agent"):
            policy, gw, _, _, _ = self._make_stack(prof)
            sess = policy.sessions.create_session(
                [PermissionTier.WRITE, PermissionTier.EXECUTE], ttl_seconds=300
            )
            # Verify active session works first in privileged profile
            ok_res = gw.invoke_tool(
                "write_file",
                {"path": str(self.workspace / f"pre_revoke_{prof}.txt"), "content": "valid"},
                session_id=sess.session_id,
            )
            self.assertTrue(ok_res["ok"])

            # Revoke session
            revoked = policy.sessions.revoke_session(sess.session_id, reason="red_team_revocation")
            self.assertTrue(revoked)
            self.assertFalse(sess.is_active())

            # Verify subsequent calls with revoked session_id are rejected
            with self.assertRaises(
                PermissionError,
                msg=f"Revoked session was not rejected in profile={prof}",
            ):
                gw.invoke_tool(
                    "write_file",
                    {"path": str(self.workspace / f"post_revoke_{prof}.txt"), "content": "denied"},
                    session_id=sess.session_id,
                )

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 104,
                    "method": "tools/call",
                    "params": {
                        "name": "powershell_execute",
                        "arguments": {"command": "Write-Output 'revoked'", "cwd": str(self.workspace)},
                    },
                },
                session_id=sess.session_id,
            )
            assert rpc_resp is not None
            self.assertTrue(rpc_resp["result"]["isError"])

        _record_evidence(
            "test_04_revoked_sessions_are_rejected",
            requirement="Revoked ControlSessions are immediately rejected on subsequent calls",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "profiles_tested": ["developer_p2", "full_agent"],
                "revocation_reason": "red_team_revocation",
                "rejected_after_revoke": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 05: Forged session IDs are rejected
    # ------------------------------------------------------------------
    def test_05_forged_session_ids_are_rejected(self) -> None:
        t0 = time.perf_counter()
        forged_id = "sess_forged_1234567890"
        for prof in ("read_only", "full_agent"):
            _, gw, _, _, _ = self._make_stack(prof)

            with self.assertRaises(
                PermissionError,
                msg=f"Forged session_id was not rejected by invoke_tool in profile={prof}",
            ):
                gw.invoke_tool(
                    "write_file",
                    {"path": str(self.workspace / f"forged_sess_{prof}.txt"), "content": "evil"},
                    session_id=forged_id,
                )

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 105,
                    "method": "tools/call",
                    "params": {
                        "name": "write_file",
                        "arguments": {"path": str(self.workspace / f"forged_rpc_{prof}.txt"), "content": "evil"},
                    },
                },
                session_id=forged_id,
            )
            assert rpc_resp is not None
            self.assertTrue(rpc_resp["result"]["isError"])

            # Also verify payload injection of session_id inside arguments dict is rejected
            injected_resp = gw.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": 1051,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": str(self.workspace / f"injected_sess_{prof}.txt"),
                        "content": "evil",
                        "session_id": forged_id,
                    },
                },
            })
            assert injected_resp is not None
            self.assertTrue(injected_resp["result"]["isError"])

        _record_evidence(
            "test_05_forged_session_ids_are_rejected",
            requirement="Caller-forged session_id is rejected via invoke_tool, handle_jsonrpc, and argument injection",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "forged_session_id": forged_id,
                "profiles_tested": ["read_only", "full_agent"],
                "argument_injection_blocked": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 06: Forged approval tokens are rejected
    # ------------------------------------------------------------------
    def test_06_forged_approval_tokens_are_rejected(self) -> None:
        t0 = time.perf_counter()
        forged_token = "tok_forged_evil_token"
        for prof in ("read_only", "full_agent"):
            _, gw, _, _, _ = self._make_stack(prof, approval_token="real_secret_token_abc123")

            with self.assertRaises(
                PermissionError,
                msg=f"Forged approval_token was not rejected by invoke_tool in profile={prof}",
            ):
                gw.invoke_tool(
                    "write_file",
                    {"path": str(self.workspace / f"forged_tok_{prof}.txt"), "content": "evil"},
                    approval_token=forged_token,
                )

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 106,
                    "method": "tools/call",
                    "params": {
                        "name": "write_file",
                        "arguments": {"path": str(self.workspace / f"forged_tok_rpc_{prof}.txt"), "content": "evil"},
                    },
                },
                approval_token=forged_token,
            )
            assert rpc_resp is not None
            self.assertTrue(rpc_resp["result"]["isError"])

            # Also verify payload injection of approval_token inside arguments dict is rejected
            injected_resp = gw.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": 1061,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": str(self.workspace / f"injected_tok_{prof}.txt"),
                        "content": "evil",
                        "approval_token": forged_token,
                    },
                },
            })
            assert injected_resp is not None
            self.assertTrue(injected_resp["result"]["isError"])

        _record_evidence(
            "test_06_forged_approval_tokens_are_rejected",
            requirement="Caller-forged approval_token is rejected via invoke_tool, handle_jsonrpc, and argument injection",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "forged_approval_token": forged_token,
                "profiles_tested": ["read_only", "full_agent"],
                "argument_injection_blocked": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 07: Write cannot escape approved write roots
    # ------------------------------------------------------------------
    def test_07_write_cannot_escape_approved_write_roots(self) -> None:
        t0 = time.perf_counter()
        policy, gw, file_ops, _, _ = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.WRITE], ttl_seconds=300)

        escape_targets = [
            r"C:\Windows\Temp\evil.txt",
            r"..\outside.txt",
            str(self.workspace / ".." / "outside_root" / "evil.txt"),
            r"\\127.0.0.1\c$\Windows\Temp\evil.txt",
            r"\\.\C:\Windows\Temp\evil.txt",
            str(self.workspace / "normal.txt:hidden_ads_stream"),
        ]
        for bad_target in escape_targets:
            with self.assertRaises(
                PermissionError,
                msg=f"write_file did not block escape path: {bad_target}",
            ):
                file_ops.write_file(bad_target, "escaped", session_id=sess.session_id)

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 107,
                    "method": "tools/call",
                    "params": {"name": "write_file", "arguments": {"path": bad_target, "content": "escaped"}},
                },
                session_id=sess.session_id,
            )
            assert rpc_resp is not None
            self.assertTrue(rpc_resp["result"]["isError"])

        _record_evidence(
            "test_07_write_cannot_escape_approved_write_roots",
            requirement="write_file cannot escape approved write roots via absolute, .., UNC, device, or ADS paths",
            execution_origin="direct_python_api_and_mcp_jsonrpc",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={"blocked_targets": escape_targets},
        )

    # ------------------------------------------------------------------
    # Test 08: Execute cannot bypass execution policy or leak env secrets
    # ------------------------------------------------------------------
    def test_08_execute_cannot_bypass_execution_policy(self) -> None:
        t0 = time.perf_counter()
        policy, gw, _, exec_ops, _ = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.EXECUTE], ttl_seconds=300)

        forbidden_commands = [
            "Format-Volume -DriveLetter C -FileSystem NTFS",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "powershell -EncodedCommand V3JpdGUtT3V0cHV0ICdldmlsJw==",
            "Invoke-Expression 'Write-Output bypassed'",
            "Start-Process powershell -Verb RunAs",
        ]
        for cmd in forbidden_commands:
            with self.assertRaises(
                PermissionError,
                msg=f"powershell_execute did not block forbidden command: {cmd}",
            ):
                exec_ops.powershell_execute(cmd, cwd=str(self.workspace), session_id=sess.session_id)

            rpc_resp = gw.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 108,
                    "method": "tools/call",
                    "params": {"name": "powershell_execute", "arguments": {"command": cmd, "cwd": str(self.workspace)}},
                },
                session_id=sess.session_id,
            )
            assert rpc_resp is not None
            self.assertTrue(rpc_resp["result"]["isError"])

        # Verify child process environment does not leak MCP_AUTH_TOKEN or OPENAI_API_KEY
        saved_mcp = os.environ.get("MCP_AUTH_TOKEN")
        saved_openai = os.environ.get("OPENAI_API_KEY")
        os.environ["MCP_AUTH_TOKEN"] = "leaked_mcp_auth_secret_value_999"
        os.environ["OPENAI_API_KEY"] = "sk-proj-leakedOpenAiSecretValue1234567890"
        try:
            env_res = exec_ops.powershell_execute(
                "Write-Output \"MCP=$($env:MCP_AUTH_TOKEN)|OAI=$($env:OPENAI_API_KEY)\"",
                cwd=str(self.workspace),
                session_id=sess.session_id,
            )
            self.assertEqual(env_res["exit_code"], 0)
            self.assertNotIn("leaked_mcp_auth_secret_value_999", env_res["stdout"])
            self.assertNotIn("sk-proj-leakedOpenAiSecretValue1234567890", env_res["stdout"])
        finally:
            if saved_mcp is None:
                os.environ.pop("MCP_AUTH_TOKEN", None)
            else:
                os.environ["MCP_AUTH_TOKEN"] = saved_mcp
            if saved_openai is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = saved_openai

        _record_evidence(
            "test_08_execute_cannot_bypass_execution_policy",
            requirement="powershell_execute blocks destructive/encoded/IEX/RunAs commands and sanitizes child env secrets",
            execution_origin="direct_python_api_and_subprocess_env_check",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "blocked_commands": forbidden_commands,
                "env_leaks_prevented": ["MCP_AUTH_TOKEN", "OPENAI_API_KEY"],
            },
        )

    # ------------------------------------------------------------------
    # Test 09: Symlink and junction traversal blocked
    # ------------------------------------------------------------------
    def test_09_symlink_and_junction_traversal_blocked(self) -> None:
        t0 = time.perf_counter()
        policy, _, file_ops, _, _ = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.WRITE], ttl_seconds=300)
        junction_dir = self.workspace / "junction_to_outside"

        proc = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction_dir), str(self.outside)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertTrue(
            junction_dir.exists(),
            f"Failed to create NTFS directory junction for test_09: {proc.stderr or proc.stdout}",
        )
        try:
            with self.assertRaises(PermissionError):
                file_ops.read_file(str(junction_dir / "escaped.txt"))
            with self.assertRaises(PermissionError):
                file_ops.write_file(str(junction_dir / "planted.txt"), "blocked", session_id=sess.session_id)
        finally:
            subprocess.run(["cmd.exe", "/c", "rmdir", str(junction_dir)], capture_output=True, check=False)

        _record_evidence(
            "test_09_symlink_and_junction_traversal_blocked",
            requirement="NTFS directory junction (mklink /J) pointing outside approved roots is blocked for read and write",
            execution_origin="ntfs_junction_mklink_and_file_ops",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "junction_path": str(junction_dir),
                "target_outside_root": str(self.outside),
                "read_blocked": True,
                "write_blocked": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 10: Recursive search does not expose secrets
    # ------------------------------------------------------------------
    def test_10_recursive_search_does_not_expose_secrets(self) -> None:
        t0 = time.perf_counter()
        _, gw, file_ops, _, _ = self._make_stack("read_only")

        # Populate disposable directory with sensitive files and an inline secret in a .py file
        (self.workspace / ".env").write_text("DATABASE_PASSWORD=super_secret_env_pass\n", encoding="utf-8")
        (self.workspace / "id_rsa").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0123456789\n-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        (self.workspace / "secrets.json").write_text(
            '{"api_secret": "top_secret_json_val"}\n', encoding="utf-8"
        )
        raw_token = "sk-1234567890abcdef12345678"  # gitleaks:allow  (synthetic regression fixture; reviewed)
        (self.workspace / "client_code.py").write_text(
            f'AUTH_HEADER = "Bearer {raw_token}"\n',
            encoding="utf-8",
        )

        # 1. search_files must exclude .env, id_rsa, secrets.json
        sf_res = file_ops.search_files(str(self.workspace), "*", recursive=True)
        found_names = {item["name"] for item in sf_res["results"]}
        self.assertNotIn(".env", found_names)
        self.assertNotIn("id_rsa", found_names)
        self.assertNotIn("secrets.json", found_names)
        self.assertIn("client_code.py", found_names)

        # 2. search_code must redact inline Bearer sk-... token
        sc_res = gw.invoke_tool(
            "search_code",
            {"cwd": str(self.workspace), "pattern": "AUTH_HEADER", "file_glob": "*.py"},
        )
        self.assertGreaterEqual(sc_res["count"], 1)
        sc_dump = json.dumps(sc_res)
        self.assertNotIn(raw_token, sc_dump)
        self.assertIn("[REDACTED]", sc_dump)

        # 3. grep across workspace must skip secrets.json/.env/id_rsa and redact inline secrets
        grep_res = gw.invoke_tool(
            "grep",
            {"root": str(self.workspace), "pattern": "Bearer|top_secret_json_val|super_secret_env_pass"},
        )
        grep_results_dump = json.dumps(grep_res["results"])
        self.assertNotIn("top_secret_json_val", grep_results_dump)
        self.assertNotIn("super_secret_env_pass", grep_results_dump)
        self.assertNotIn(raw_token, grep_results_dump)
        self.assertIn("[REDACTED]", grep_results_dump)

        _record_evidence(
            "test_10_recursive_search_does_not_expose_secrets",
            requirement="search_files, search_code, and grep skip .env/id_rsa/secrets.json and redact inline Bearer tokens",
            execution_origin="direct_python_api_and_mcp_gateway",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "sensitive_files_excluded": [".env", "id_rsa", "secrets.json"],
                "inline_token_redacted": True,
                "discovered_safe_files": sorted(found_names),
            },
        )

    # ------------------------------------------------------------------
    # Test 11: Git cannot escape approved repository scope
    # ------------------------------------------------------------------
    def test_11_git_cannot_escape_approved_repository_scope(self) -> None:
        t0 = time.perf_counter()
        # Allow reading self.outside_git, but ONLY allow git operations in self.workspace
        policy = SecurityPolicy(
            profile="full_agent",
            allowed_read_roots=[str(self.workspace), str(self.outside_git)],
            allowed_write_roots=[str(self.workspace), str(self.outside_git)],
            allowed_git_repos=[str(self.workspace)],
            allowed_exec_roots=[str(self.workspace)],
            audit_log_path=str(self.audit_log),
        )
        file_ops = FileCodeOperations(policy=policy, backups_root=self.backups)

        with self.assertRaises(PermissionError):
            file_ops.git_status(str(self.outside_git))
        with self.assertRaises(PermissionError):
            file_ops.git_diff(str(self.outside_git))
        with self.assertRaises(PermissionError):
            file_ops.git_log(str(self.outside_git))

        # Verify approved repo works
        ok_status = file_ops.git_status(str(self.workspace))
        self.assertIn("cwd", ok_status)

        _record_evidence(
            "test_11_git_cannot_escape_approved_repository_scope",
            requirement="git_status, git_diff, and git_log reject repositories outside allowed_git_repos",
            execution_origin="direct_python_api_git_scope_check",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "approved_repo": str(self.workspace),
                "unapproved_repo": str(self.outside_git),
                "git_status_rejected": True,
                "git_diff_rejected": True,
                "git_log_rejected": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 12: Locked workstation rejects GUI interaction
    # ------------------------------------------------------------------
    def test_12_locked_workstation_rejects_gui_interaction(self) -> None:
        t0 = time.perf_counter()
        policy, _, _, _, desktop = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.DESKTOP], ttl_seconds=600)
        desktop.set_simulated_locked_session(True)
        try:
            status = desktop.get_desktop_session_status()
            self.assertTrue(status["is_locked"])
            self.assertFalse(status["gui_manipulation_allowed"])

            with self.assertRaises(DesktopSessionLockedError):
                desktop.mouse_click(100, 100, session_id=sess.session_id)
            with self.assertRaises(DesktopSessionLockedError):
                desktop.keyboard_type("secret_input", session_id=sess.session_id)
            with self.assertRaises(DesktopSessionLockedError):
                desktop.focus_window(12345, session_id=sess.session_id)
            with self.assertRaises(DesktopSessionLockedError):
                desktop.screenshot(target="desktop")
            with self.assertRaises(DesktopSessionLockedError):
                desktop.get_clipboard_text(session_id=sess.session_id)
        finally:
            desktop.set_simulated_locked_session(False)

        _record_evidence(
            "test_12_locked_workstation_rejects_gui_interaction",
            requirement="Locked workstation / Secure Desktop refuses mouse_click, keyboard_type, focus_window, screenshot, get_clipboard_text",
            execution_origin="desktop_agent_locked_session_guard",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "blocked_tools": [
                    "mouse_click",
                    "keyboard_type",
                    "focus_window",
                    "screenshot",
                    "get_clipboard_text",
                ],
                "exception_raised": "DesktopSessionLockedError",
            },
        )

    # ------------------------------------------------------------------
    # Test 13: Emergency stop prevents all desktop actions & revokes sessions
    # ------------------------------------------------------------------
    def test_13_emergency_stop_prevents_all_desktop_actions(self) -> None:
        t0 = time.perf_counter()
        policy, _, _, _, desktop = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.DESKTOP], ttl_seconds=600)
        self.assertTrue(sess.is_active())

        stop_res = desktop.engage_emergency_stop(reason="red_team_test_13_panic")
        try:
            self.assertTrue(stop_res["emergency_stop"])
            self.assertTrue(self.emergency_file.exists())
            self.assertGreaterEqual(stop_res["revoked_sessions"], 1)
            self.assertFalse(sess.is_active())
            self.assertTrue(sess.revoked)

            with self.assertRaises(EmergencyStopActiveError):
                desktop.mouse_move(50, 50)
            with self.assertRaises(EmergencyStopActiveError):
                desktop.mouse_click(50, 50)
            with self.assertRaises(EmergencyStopActiveError):
                desktop.keyboard_type("halt")
            with self.assertRaises(EmergencyStopActiveError):
                desktop.focus_window(12345)
            with self.assertRaises(EmergencyStopActiveError):
                desktop.screenshot(target="desktop")
            with self.assertRaises(EmergencyStopActiveError):
                desktop.get_clipboard_text()
        finally:
            reset_res = desktop.reset_emergency_stop()
            self.assertFalse(reset_res["emergency_stop"])
            self.assertFalse(self.emergency_file.exists())

        _record_evidence(
            "test_13_emergency_stop_prevents_all_desktop_actions",
            requirement="EMERGENCY_STOP halts all desktop actions with EmergencyStopActiveError, revokes sessions, and resets cleanly",
            execution_origin="desktop_agent_emergency_stop_latch_and_file",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "revoked_sessions": stop_res["revoked_sessions"],
                "emergency_file_created": True,
                "clean_reset_verified": not self.emergency_file.exists(),
            },
        )

    # ------------------------------------------------------------------
    # Test 14: Sensitive screenshot targets are blocked & blacked out
    # ------------------------------------------------------------------
    def test_14_sensitive_screenshot_targets_are_blocked(self) -> None:
        t0 = time.perf_counter()
        policy, _, _, _, desktop = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.DESKTOP], ttl_seconds=600)
        status = desktop.get_desktop_session_status()
        if status["is_locked"] or not status["is_interactive"]:
            self.skipTest("Interactive unlocked desktop session required for live window blackout test")

        sens_title = "KeePass - Master Password"
        proc = subprocess.Popen(
            [sys.executable, "-c", _TK_SENSITIVE_WINDOW_SCRIPT, sens_title],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            hwnd = None
            for _ in range(40):
                wins = desktop.list_windows(title_contains="KeePass")["windows"]
                if wins:
                    hwnd = wins[0]["hwnd"]
                    self.assertTrue(wins[0]["sensitive"])
                    break
                time.sleep(0.1)

            self.assertIsNotNone(hwnd, "Disposable 'KeePass - Master Password' window did not appear")
            assert hwnd is not None

            # 1. Direct window screenshot must raise PermissionError
            with self.assertRaises(PermissionError):
                desktop.screenshot(target="window", hwnd=hwnd)

            # 2. Focusing sensitive window must raise PermissionError
            with self.assertRaises(PermissionError):
                desktop.focus_window(hwnd, session_id=sess.session_id)

            # 3. Desktop screenshot must redact the sensitive window region
            desk_shot = desktop.screenshot(target="desktop", monitor=0)
            self.assertIn(sens_title, desk_shot["redacted_windows"])
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

        _record_evidence(
            "test_14_sensitive_screenshot_targets_are_blocked",
            requirement="Window titled 'KeePass - Master Password' is blocked on focus_window & window screenshot, and redacted in desktop screenshot",
            execution_origin="live_win32_gui_and_tkinter_window",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "window_title": sens_title,
                "hwnd": hwnd,
                "window_screenshot_blocked": True,
                "focus_window_blocked": True,
                "redacted_in_desktop_screenshot": sens_title in desk_shot["redacted_windows"],
            },
        )

    # ------------------------------------------------------------------
    # Test 15: Secrets redacted from logs and tool results
    # ------------------------------------------------------------------
    def test_15_secrets_redacted_from_logs_and_tool_results(self) -> None:
        t0 = time.perf_counter()
        raw_bearer = "Bearer sk-live-999999999999999999"
        raw_api_key = "secret123"
        payload = {
            "authorization_header": raw_bearer,
            "api_key": raw_api_key,
            "nested": {
                "message": f"Connecting with {raw_bearer} and api_key={raw_api_key}",
            },
        }
        redacted_payload = redact_secrets(payload)
        redacted_str = json.dumps(redacted_payload)
        self.assertNotIn("sk-live-999999999999999999", redacted_str)
        self.assertNotIn("secret123", redacted_str)
        self.assertIn("[REDACTED]", redacted_str)

        audit_file = self.base / "redaction_audit.jsonl"
        logger = AuditLogger(log_path=audit_file, redact=True)
        logger.log_event(
            tool_name="red_team_secret_test",
            tier=PermissionTier.EXECUTE,
            decision="ALLOW",
            reason=f"Header {raw_bearer}",
            arguments={"api_key": raw_api_key, "header": raw_bearer},
            result_summary={"leaked": f"api_key={raw_api_key}"},
        )
        raw_disk_log = audit_file.read_text(encoding="utf-8")
        self.assertNotIn("sk-live-999999999999999999", raw_disk_log)
        self.assertNotIn("secret123", raw_disk_log)
        self.assertIn("[REDACTED]", raw_disk_log)

        _record_evidence(
            "test_15_secrets_redacted_from_logs_and_tool_results",
            requirement="Bearer sk-live-... and api_key='secret123' are scrubbed by redact_secrets and never written to audit.jsonl",
            execution_origin="direct_python_api_and_disk_audit_log_inspection",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "audit_log_file": str(audit_file),
                "raw_bearer_present_on_disk": "sk-live-999999999999999999" in raw_disk_log,
                "raw_api_key_present_on_disk": "secret123" in raw_disk_log,
            },
        )

    # ------------------------------------------------------------------
    # Test 16: Legacy Ngrok edge cannot bypass authorization
    # ------------------------------------------------------------------
    def test_16_legacy_ngrok_edge_cannot_bypass_authorization(self) -> None:
        t0 = time.perf_counter()
        ngrok_procs: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (proc.info.get("name") or "").lower()
                if "ngrok" in pname:
                    ngrok_procs.append({
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "cmdline": proc.info.get("cmdline"),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.assertEqual(
            len(ngrok_procs),
            0,
            f"Unauthenticated public Ngrok process still running: {ngrok_procs}",
        )

        # Also check http://127.0.0.1:4040/api/tunnels
        active_3080_tunnels: list[str] = []
        ngrok_api_reachable = False
        try:
            req = urllib.request.Request(NGROK_API_URL, method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                ngrok_api_reachable = True
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                for t in data.get("tunnels", []):
                    addr = str(t.get("config", {}).get("addr", ""))
                    if "3080" in addr:
                        active_3080_tunnels.append(t.get("public_url", addr))
        except Exception:
            ngrok_api_reachable = False

        self.assertEqual(
            len(active_3080_tunnels),
            0,
            f"Public Ngrok tunnel to port 3080 is still active: {active_3080_tunnels}",
        )

        _record_evidence(
            "test_16_legacy_ngrok_edge_cannot_bypass_authorization",
            requirement="Public unauthenticated Ngrok tunnel to port 3080 is terminated and absent from process table & 127.0.0.1:4040",
            execution_origin="live_os_process_and_ngrok_api_inspection",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "running_ngrok_processes": len(ngrok_procs),
                "ngrok_api_4040_reachable": ngrok_api_reachable,
                "active_3080_tunnels": active_3080_tunnels,
            },
        )

    # ------------------------------------------------------------------
    # Test 17: Backend direct calls without credentials are denied
    # ------------------------------------------------------------------
    def test_17_backend_direct_calls_without_credentials_are_denied(self) -> None:
        t0 = time.perf_counter()
        # 1. Verify GET /health returns 200
        health_req = urllib.request.Request(f"{BACKEND_BASE_URL}/health", method="GET")
        with urllib.request.urlopen(health_req, timeout=5.0) as h_resp:
            health_status = h_resp.status
        self.assertEqual(health_status, 200)

        # 2. Verify POST /api/tools/path_exists with NO Authorization header returns 401 or 403
        body = json.dumps({"path": str(PROJECT_ROOT)}).encode("utf-8")
        no_auth_req = urllib.request.Request(
            f"{BACKEND_BASE_URL}/api/tools/path_exists",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        no_auth_status = 200
        try:
            with urllib.request.urlopen(no_auth_req, timeout=5.0) as resp:
                no_auth_status = resp.status
        except urllib.error.HTTPError as err:
            no_auth_status = err.code

        self.assertIn(
            no_auth_status,
            (401, 403),
            f"Expected HTTP 401/403 for unauthenticated POST to port 3080, got {no_auth_status}",
        )

        # 3. Verify POST /api/tools/path_exists with forged Bearer token returns 401 or 403
        bad_auth_req = urllib.request.Request(
            f"{BACKEND_BASE_URL}/api/tools/path_exists",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer forged_token",
            },
            method="POST",
        )
        bad_auth_status = 200
        try:
            with urllib.request.urlopen(bad_auth_req, timeout=5.0) as resp:
                bad_auth_status = resp.status
        except urllib.error.HTTPError as err:
            bad_auth_status = err.code

        self.assertIn(
            bad_auth_status,
            (401, 403),
            f"Expected HTTP 401/403 for forged Bearer token on port 3080, got {bad_auth_status}",
        )

        _record_evidence(
            "test_17_backend_direct_calls_without_credentials_are_denied",
            requirement="Direct calls to http://127.0.0.1:3080/api/tools/* without credentials or with forged token return 401/403 while /health returns 200",
            execution_origin="live_http_127.0.0.1:3080",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "health_http_status": health_status,
                "unauthenticated_post_http_status": no_auth_status,
                "forged_bearer_post_http_status": bad_auth_status,
            },
        )

    # ------------------------------------------------------------------
    # Test 18: Unapproved cloud connector cannot access advanced capabilities
    # ------------------------------------------------------------------
    def test_18_unapproved_cloud_connector_cannot_access_advanced_capabilities(self) -> None:
        t0 = time.perf_counter()
        # 1. Check live MCP Bridge tools/list exposes strictly the 15 read-only tools
        list_resp = _call_mcp_http("tools/list", {}, req_id=180)
        tools = list_resp.get("result", {}).get("tools", [])
        tool_names = {t["name"] for t in tools}
        self.assertEqual(len(tools), 15)
        self.assertEqual(tool_names, set(V021_READ_TOOLS))

        # 2. Attempt write_file, powershell_execute, and mouse_click on live Bridge (port 8765)
        blocked_results: dict[str, bool] = {}
        for idx, (tool_name, args) in enumerate(
            (
                ("write_file", {"path": str(PROJECT_ROOT / "cloud_hack.txt"), "content": "x"}),
                ("powershell_execute", {"command": "whoami", "cwd": str(PROJECT_ROOT)}),
                ("mouse_click", {"x": 100, "y": 100}),
            ),
            start=181,
        ):
            resp = _call_mcp_http("tools/call", {"name": tool_name, "arguments": args}, req_id=idx)
            res_obj = resp.get("result", {})
            is_err = bool(res_obj.get("isError") is True or "error" in resp)
            self.assertTrue(
                is_err,
                f"Live MCP Bridge (8765) did not reject advanced capability tool: {tool_name}",
            )
            blocked_results[tool_name] = is_err

        _record_evidence(
            "test_18_unapproved_cloud_connector_cannot_access_advanced_capabilities",
            requirement="Live MCP Bridge (127.0.0.1:8765/mcp) exposes strictly 15 read tools and rejects write_file, powershell_execute, mouse_click",
            execution_origin="live_mcp_bridge_http_127.0.0.1:8765/mcp",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "bridge_endpoint": MCP_BRIDGE_URL,
                "exposed_tool_count": len(tools),
                "blocked_calls": blocked_results,
            },
        )

    # ------------------------------------------------------------------
    # Test 19: Tool discovery changes do not bypass per-action policy
    # ------------------------------------------------------------------
    def test_19_tool_discovery_changes_do_not_bypass_per_action_policy(self) -> None:
        t0 = time.perf_counter()
        # Create policy with strict_v021_read_tools_only=False but only READ tier enabled
        policy, gw, _, _, _ = self._make_stack(
            "read_only",
            enabled_tiers=[PermissionTier.READ],
        )
        policy.strict_v021_read_tools_only = False

        # Caller knows tool schemas from ALL_TOOL_DEFINITIONS and calls authorize_tool / invoke_tool directly
        tier_samples = [
            ("write_file", PermissionTier.WRITE, {"path": str(self.workspace / "x.txt"), "content": "x"}),
            ("powershell_execute", PermissionTier.EXECUTE, {"command": "whoami", "cwd": str(self.workspace)}),
            ("mouse_click", PermissionTier.DESKTOP, {"x": 10, "y": 10}),
            ("system_admin_exec", PermissionTier.SYSTEM_ADMIN, {}),
            ("modify_firewall", PermissionTier.SYSTEM_ADMIN, {}),
            ("modify_defender", PermissionTier.SYSTEM_ADMIN, {}),
            ("edit_registry", PermissionTier.SYSTEM_ADMIN, {}),
        ]
        for tool_name, expected_tier, sample_args in tier_samples:
            self.assertIn(tool_name, ALL_TOOL_DEFINITIONS if expected_tier != PermissionTier.SYSTEM_ADMIN else {tool_name})
            with self.assertRaises(
                PermissionError,
                msg=f"authorize_tool did not block disabled tier {expected_tier} for {tool_name}",
            ):
                policy.authorize_tool(tool_name, sample_args)

            with self.assertRaises(
                PermissionError,
                msg=f"invoke_tool did not block disabled tier {expected_tier} for {tool_name}",
            ):
                gw.invoke_tool(tool_name, sample_args)

        # Even in full_agent profile, SYSTEM_ADMIN tools must be denied by default
        full_policy, full_gw, _, _, _ = self._make_stack("full_agent")
        for sys_tool in ("system_admin_exec", "modify_firewall", "modify_defender", "edit_registry"):
            with self.assertRaises(PermissionError):
                full_policy.authorize_tool(sys_tool, {})
            with self.assertRaises(PermissionError):
                full_gw.invoke_tool(sys_tool, {})

        _record_evidence(
            "test_19_tool_discovery_changes_do_not_bypass_per_action_policy",
            requirement="Per-action authorize_tool() enforces enabled_tiers for WRITE, EXECUTE, DESKTOP, and SYSTEM_ADMIN regardless of discovery",
            execution_origin="direct_python_api_per_action_policy_gate",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "tested_tiers": ["WRITE", "EXECUTE", "DESKTOP", "SYSTEM_ADMIN"],
                "system_admin_blocked_in_full_agent": True,
            },
        )

    # ------------------------------------------------------------------
    # Test 20: Rollback restores last-known-good state
    # ------------------------------------------------------------------
    def test_20_rollback_restores_last_known_good_state(self) -> None:
        t0 = time.perf_counter()
        # Part A: Verify rollback dry-run against a disposable synthetic baseline.
        # Public-source tests must not require the developer's private backups.
        self.assertTrue(ROLLBACK_SCRIPT_PATH.exists(), f"Missing rollback script: {ROLLBACK_SCRIPT_PATH}")
        import hashlib
        baseline_dir = self.workspace / "synthetic_rollback_baseline"
        baseline_dir.mkdir(parents=True, exist_ok=True)
        fixture_bytes = b"SYNTHETIC_ROLLBACK_FIXTURE\n"
        (baseline_dir / "fixture.txt").write_bytes(fixture_bytes)
        live_fixture = self.workspace / "synthetic_rollback_live.txt"
        live_fixture.write_bytes(fixture_bytes)
        (baseline_dir / "baseline_hashes.json").write_text(
            json.dumps({"files": [{
                "relative_path": "fixture.txt",
                "original_path": str(live_fixture),
                "sha256": hashlib.sha256(fixture_bytes).hexdigest(),
            }]}),
            encoding="utf-8",
        )
        ps_proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ROLLBACK_SCRIPT_PATH),
                "-DryRun",
                "-BackupDir",
                str(baseline_dir),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(
            ps_proc.returncode,
            0,
            f"Rollback-WindowsMcp.ps1 -DryRun failed (rc={ps_proc.returncode}): {ps_proc.stderr or ps_proc.stdout}",
        )
        self.assertIn("Failures=0", ps_proc.stdout)

        # Part B: Verify deterministic file-level rollback on modified and deleted file
        policy, _, file_ops, _, _ = self._make_stack("full_agent")
        sess = policy.sessions.create_session([PermissionTier.WRITE], ttl_seconds=600)
        disp_file = self.workspace / "rollback_target.txt"
        known_good_text = "KNOWN_GOOD_STATE_V1\nLine 2 intact.\n"

        w1 = file_ops.write_file(str(disp_file), known_good_text, session_id=sess.session_id)
        sha_v1 = w1["sha256"]

        # Modify/corrupt the file
        w2 = file_ops.write_file(str(disp_file), "CORRUPTED_STATE_V2\n", session_id=sess.session_id)
        self.assertNotEqual(w2["sha256"], sha_v1)

        # Restore from version backup
        r1 = file_ops.restore_file(str(disp_file), session_id=sess.session_id)
        self.assertTrue(r1["ok"])
        self.assertEqual(r1["sha256"], sha_v1)
        self.assertEqual(disp_file.read_text(encoding="utf-8"), known_good_text)

        # Delete the file (moves to backups/trash) and restore from trash
        del_res = file_ops.delete_file(str(disp_file), session_id=sess.session_id)
        self.assertTrue(del_res["ok"])
        self.assertFalse(disp_file.exists())

        r2 = file_ops.restore_file(str(disp_file), session_id=sess.session_id)
        self.assertTrue(r2["ok"])
        self.assertTrue(disp_file.exists())
        self.assertEqual(r2["sha256"], sha_v1)
        self.assertEqual(disp_file.read_text(encoding="utf-8"), known_good_text)

        _record_evidence(
            "test_20_rollback_restores_last_known_good_state",
            requirement="Rollback-WindowsMcp.ps1 -DryRun passes with Failures=0 and FileCodeOperations.restore_file() restores modified & deleted files",
            execution_origin="powershell_rollback_script_and_file_ops",
            passed=True,
            latency_ms=(time.perf_counter() - t0) * 1000,
            details={
                "rollback_script_exit_code": ps_proc.returncode,
                "rollback_script_failures_zero": "Failures=0" in ps_proc.stdout,
                "version_backup_restored_sha256": r1["sha256"] == sha_v1,
                "trash_delete_restored_sha256": r2["sha256"] == sha_v1,
            },
        )


def write_evidence_report() -> dict[str, Any]:
    """Persist machine-readable Red-Team QA evidence to runtime/evidence/stage8_red_team_qa.json."""
    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ordered_keys = sorted(_RED_TEAM_EVIDENCE.keys())
    tests_list = [_RED_TEAM_EVIDENCE[k] for k in ordered_keys]
    passed_count = sum(1 for item in tests_list if item.get("passed"))
    report = {
        "schema_version": "2.0.0",
        "stage": "Stage 8 / Section 11 — Mandatory 20 Security Red-Team Tests",
        "agent": "AGENT E — Independent QA / Red Team Engineer",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(tests_list),
        "passed_tests": passed_count,
        "failed_tests": len(tests_list) - passed_count,
        "overall_status": "PASS" if (len(tests_list) >= 20 and passed_count == len(tests_list)) else "FAIL",
        "tests": tests_list,
    }
    EVIDENCE_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def teardown_module(_module: Any = None) -> None:
    """pytest module teardown hook: write evidence report if all 20 tests ran."""
    if _RED_TEAM_EVIDENCE:
        write_evidence_report()


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestRedTeamSecurity)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    rep = write_evidence_report()
    print(f"\nSaved Red-Team QA Evidence ({rep['passed_tests']}/{rep['total_tests']} PASS) -> {EVIDENCE_PATH}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
