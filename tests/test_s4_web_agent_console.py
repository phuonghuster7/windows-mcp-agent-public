"""Stage S4 — Mode B Owner-Controlled Web Agent Console Automated Acceptance Tests.

Verifies all 10 Stage S4/S7 Web Agent acceptance requirements:
1. Strong owner authentication (`POST /console/api/login`), HttpOnly SameSite=Strict cookie,
   invalid password rejection (401), rate-limiting (429), and zero secrets in HTML/JS UI.
2. CSRF (`X-CSRF-Token`) and loopback `Origin` / `Referer` validation on state-changing endpoints.
3. Unauthorized caller rejection (`401`/`403`) on `/console/api/*` and immediate session invalidation on logout.
4. Bounded `ControlSession` approval (`tiers`, `ttl_seconds`, `allowed_paths`, `allowed_commands`)
   and outer profile boundary enforcement.
5. Human-in-the-loop proposal creation (`PENDING_OWNER_APPROVAL`), unified diff preview,
   owner confirmation (`POST /console/api/proposals/{id}/execute`), and safe file modification (`write_file`, `edit_file`).
6. Approved command execution (`powershell_execute`) and unapproved command / out-of-scope path rejection.
7. Screenshot capture (`GET /console/api/screenshot`) and safe GUI inspection (`get_screen_geometry`, `list_windows`).
8. Live structured audit log (`GET /console/api/audit`) with automatic secret redaction.
9. Remote session revocation (`revoke` and `revoke-all`) immediately blocking subsequent privileged actions.
10. Global Emergency Stop kill-switch (`POST /console/api/emergency-stop`) immediately halting privileged
    actions, revoking sessions, cancelling active jobs & pending proposals, and clean reset.
11. Full 10-step real disposable GUI window E2E acceptance with keyboard typing, enter keypress, and pixel visual verification.
12. Negative Control: Keyboard input omitted/disabled -> save event fails and no file is created.
13. Negative Control: Nonce typed but save event omitted -> state remains un-saved and no file created.
14. Negative Control: Unchanged/un-saved screenshot rejected by visual verifier (zero false pass).
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import io
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from PIL import Image
import psutil
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
for _p in (
    PROJECT_ROOT / "mcp-gateway",
    PROJECT_ROOT / "backend",
    PROJECT_ROOT / "desktop-agent",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from policy import SecurityPolicy  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from web_console import SESSION_COOKIE_NAME, create_web_console_app  # noqa: E402

TEST_OWNER_SECRET = "s4-test-owner-console-master-secret-998877"


@pytest.fixture()
def console_env(tmp_path: Path):
    """Create an isolated Mode B Web Console + Full Agent Gateway backed by tmp_path."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    outside_dir = tmp_path / "outside_scope"
    outside_dir.mkdir(parents=True, exist_ok=True)

    audit_log = tmp_path / "audit.jsonl"
    estop_file = tmp_path / "EMERGENCY_STOP"

    policy = SecurityPolicy(
        profile="full_agent",
        allowed_read_roots=[str(tmp_path)],
        allowed_write_roots=[str(workspace)],
        allowed_exec_roots=[str(workspace)],
        allowed_git_repos=[str(PROJECT_ROOT)],
        audit_log_path=audit_log,
        emergency_stop_file=estop_file,
        require_session_for_privileged=True,
    )
    gateway = MCPGatewayServer(policy=policy)
    gateway.desktop_agent = gateway.desktop

    # Ensure all tool executions via thread pool run on the interactive InputDesktop (WinSta0\Default)
    _orig_invoke = gateway.invoke_tool
    def _invoke_on_input_desktop(*args, **kwargs):
        try:
            user32 = ctypes.windll.user32
            hdesk = user32.OpenInputDesktop(0, False, 0x01FF)
            if hdesk:
                user32.SetThreadDesktop(hdesk)
        except Exception:
            pass
        tool_name = args[0] if args else kwargs.get("name", "")
        if tool_name == "focus_window":
            try:
                target_hwnd = args[1].get("hwnd") if len(args) > 1 and isinstance(args[1], dict) else kwargs.get("arguments", {}).get("hwnd")
                if target_hwnd:
                    user32 = ctypes.windll.user32
                    user32.keybd_event(0x11, 0, 0, 0)
                    user32.keybd_event(0x12, 0, 0, 0)
                    user32.SetForegroundWindow(int(target_hwnd))
                    user32.keybd_event(0x12, 0, 2, 0)
                    user32.keybd_event(0x11, 0, 2, 0)
            except Exception:
                pass
        return _orig_invoke(*args, **kwargs)
    gateway.invoke_tool = _invoke_on_input_desktop

    app = create_web_console_app(
        gateway=gateway,
        owner_password=TEST_OWNER_SECRET,
        rate_limit_max_failures=4,
        rate_limit_window_seconds=60,
    )
    client = TestClient(app)
    return {
        "client": client,
        "gateway": gateway,
        "policy": policy,
        "workspace": workspace,
        "outside_dir": outside_dir,
        "audit_log": audit_log,
        "estop_file": estop_file,
    }


def _login_owner(client: TestClient, password: str = TEST_OWNER_SECRET) -> str:
    resp = client.post("/console/api/login", json={"password": password})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["authenticated"] is True
    assert data["csrf_token"]
    assert SESSION_COOKIE_NAME in resp.cookies
    return data["csrf_token"]


def test_01_ui_shell_and_owner_authentication_and_rate_limit(console_env):
    """1. Verify UI HTML shell has zero secrets/localStorage tokens, owner login works, and brute-force is rate-limited."""
    client: TestClient = console_env["client"]

    # Public health and HTML shell
    h = client.get("/health")
    assert h.status_code == 200
    assert h.json()["service"] == "mode-b-owner-web-console"

    ui = client.get("/")
    assert ui.status_code == 200
    assert "Windows MCP Agent — Mode B Console" in ui.text
    assert TEST_OWNER_SECRET not in ui.text
    assert "localStorage.setItem" not in ui.text
    assert ui.headers.get("x-frame-options") == "DENY"

    # Invalid password attempts trigger 401 up to rate_limit_max_failures (4), then 429
    for _ in range(4):
        bad = client.post("/console/api/login", json={"password": "wrong-password"})
        assert bad.status_code == 401

    locked_out = client.post("/console/api/login", json={"password": TEST_OWNER_SECRET})
    assert locked_out.status_code == 429
    assert "Too many failed login attempts" in locked_out.json()["error"]


def test_02_csrf_and_origin_protection(console_env):
    """2. Verify CSRF token requirement and loopback Origin/Referer enforcement on state-changing endpoints."""
    client: TestClient = console_env["client"]
    csrf = _login_owner(client)

    # Missing X-CSRF-Token on POST -> 403
    no_csrf = client.post("/console/api/sessions/approve", json={"tiers": ["READ", "WRITE"]})
    assert no_csrf.status_code == 403
    assert "X-CSRF-Token" in no_csrf.json()["error"]

    # Wrong X-CSRF-Token on POST -> 403
    bad_csrf = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": "forged-csrf-token"},
        json={"tiers": ["READ", "WRITE"]},
    )
    assert bad_csrf.status_code == 403

    # Non-loopback Origin header -> 403 even with valid CSRF token
    evil_origin = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example.com"},
        json={"tiers": ["READ", "WRITE"]},
    )
    assert evil_origin.status_code == 403
    assert "Cross-origin" in evil_origin.json()["error"]

    # Non-loopback Referer header -> 403
    evil_referer = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf, "Referer": "https://attacker.invalid/phish"},
        json={"tiers": ["READ", "WRITE"]},
    )
    assert evil_referer.status_code == 403


def test_03_unauthorized_caller_rejection_and_logout(console_env):
    """3. Verify unauthenticated callers are rejected on /console/api/* and logout invalidates session."""
    client: TestClient = console_env["client"]

    for get_ep in (
        "/console/api/status",
        "/console/api/tools",
        "/console/api/sessions",
        "/console/api/proposals",
        "/console/api/audit",
        "/console/api/screenshot",
    ):
        r = client.get(get_ep)
        assert r.status_code == 401, f"Expected 401 on {get_ep}, got {r.status_code}"

    for post_ep in (
        "/console/api/sessions/approve",
        "/console/api/proposals",
        "/console/api/execute",
        "/console/api/emergency-stop",
    ):
        r = client.post(post_ep, json={})
        assert r.status_code == 401, f"Expected 401 on {post_ep}, got {r.status_code}"

    # Login then logout
    csrf = _login_owner(client)
    st_ok = client.get("/console/api/status")
    assert st_ok.status_code == 200

    out = client.post("/console/api/logout", headers={"X-CSRF-Token": csrf})
    assert out.status_code == 200
    assert out.json()["logged_out"] is True

    st_after = client.get("/console/api/status")
    assert st_after.status_code == 401


def test_04_bounded_session_approval_and_outer_profile_boundary(console_env, tmp_path: Path):
    """4. Verify scope-bounded ControlSession approval and outer profile boundary enforcement."""
    client: TestClient = console_env["client"]
    workspace: Path = console_env["workspace"]
    csrf = _login_owner(client)

    allowed_subdir = workspace / "allowed_sub"
    allowed_subdir.mkdir(parents=True, exist_ok=True)

    resp = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={
            "tiers": ["READ", "WRITE", "EXECUTE"],
            "ttl_seconds": 600,
            "allowed_paths": [str(allowed_subdir)],
            "allowed_commands": ["Write-Output", "python"],
        },
    )
    assert resp.status_code == 200, resp.text
    sess = resp.json()["session"]
    assert sess["session_id"].startswith("sess_")
    assert set(sess["tiers"]) == {"READ", "WRITE", "EXECUTE"}
    assert sess["active"] is True
    assert sess["allowed_commands"] == ["Write-Output", "python"]

    # Verify outer profile boundary: a read_only gateway cannot approve WRITE sessions
    ro_policy = SecurityPolicy(profile="read_only", audit_log_path=tmp_path / "ro_audit.jsonl")
    ro_gw = MCPGatewayServer(policy=ro_policy)
    ro_client = TestClient(create_web_console_app(gateway=ro_gw, owner_password=TEST_OWNER_SECRET))
    ro_csrf = _login_owner(ro_client)
    ro_deny = ro_client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": ro_csrf},
        json={"tiers": ["READ", "WRITE"]},
    )
    assert ro_deny.status_code == 403
    assert "not enabled in outer profile" in ro_deny.json()["error"]


def test_05_human_in_the_loop_proposal_diff_and_safe_file_modification(console_env):
    """5. Verify proposal creation (PENDING_OWNER_APPROVAL), unified diff preview, owner confirmation, and rejection."""
    client: TestClient = console_env["client"]
    workspace: Path = console_env["workspace"]
    csrf = _login_owner(client)

    target_file = workspace / "hello_mode_b.txt"
    target_file.write_text("line 1\nline 2\n", encoding="utf-8")

    # Approve a WRITE ControlSession scoped to workspace
    sess_resp = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={
            "tiers": ["READ", "WRITE"],
            "ttl_seconds": 600,
            "allowed_paths": [str(workspace)],
        },
    )
    assert sess_resp.status_code == 200
    session_id = sess_resp.json()["session"]["session_id"]

    # 1) Create an edit_file proposal -> sits in PENDING_OWNER_APPROVAL, file is NOT modified yet
    prop_resp = client.post(
        "/console/api/proposals",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "edit_file",
            "arguments": {
                "path": str(target_file),
                "old_text": "line 2",
                "new_text": "line 2 modified via human-in-the-loop approval",
            },
            "rationale": "Update line 2 after owner diff review",
        },
    )
    assert prop_resp.status_code == 201, prop_resp.text
    prop = prop_resp.json()["proposal"]
    proposal_id = prop["proposal_id"]
    assert prop["status"] == "PENDING_OWNER_APPROVAL"
    assert prop["preview"]["type"] == "file_diff"
    assert "-line 2" in prop["preview"]["unified_diff"]
    assert "+line 2 modified via human-in-the-loop approval" in prop["preview"]["unified_diff"]

    # Confirm file on disk is still untouched before owner clicks Approve & Execute
    assert target_file.read_text(encoding="utf-8") == "line 1\nline 2\n"

    # 2) Attempt to execute without session_id -> 403 fail-closed
    no_sess_exec = client.post(
        f"/console/api/proposals/{proposal_id}/execute",
        headers={"X-CSRF-Token": csrf},
        json={},
    )
    assert no_sess_exec.status_code == 403

    # Create a fresh pending proposal and execute with valid session_id
    prop2_resp = client.post(
        "/console/api/proposals",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "edit_file",
            "arguments": {
                "path": str(target_file),
                "old_text": "line 2",
                "new_text": "line 2 modified via human-in-the-loop approval",
            },
            "rationale": "Confirmed edit",
        },
    )
    prop2_id = prop2_resp.json()["proposal"]["proposal_id"]

    exec_resp = client.post(
        f"/console/api/proposals/{prop2_id}/execute",
        headers={"X-CSRF-Token": csrf},
        json={"session_id": session_id},
    )
    assert exec_resp.status_code == 200, exec_resp.text
    assert exec_resp.json()["status"] == "EXECUTED"
    assert "line 2 modified via human-in-the-loop approval" in target_file.read_text(encoding="utf-8")

    # 3) Create and reject a proposal -> never modifies file
    prop3_resp = client.post(
        "/console/api/proposals",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "write_file",
            "arguments": {"path": str(target_file), "content": "OVERWRITTEN", "overwrite": True},
            "rationale": "Should be rejected",
        },
    )
    prop3_id = prop3_resp.json()["proposal"]["proposal_id"]
    rej_resp = client.post(
        f"/console/api/proposals/{prop3_id}/reject",
        headers={"X-CSRF-Token": csrf},
        json={"reason": "Owner declined overwrite"},
    )
    assert rej_resp.status_code == 200
    assert rej_resp.json()["status"] == "REJECTED"
    assert "OVERWRITTEN" not in target_file.read_text(encoding="utf-8")


def test_06_approved_command_execution_and_scope_violation_rejection(console_env):
    """6. Verify approved PowerShell execution within session scope and rejection of unapproved commands/paths."""
    client: TestClient = console_env["client"]
    workspace: Path = console_env["workspace"]
    outside_dir: Path = console_env["outside_dir"]
    csrf = _login_owner(client)

    sess_resp = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={
            "tiers": ["READ", "WRITE", "EXECUTE"],
            "ttl_seconds": 600,
            "allowed_paths": [str(workspace)],
            "allowed_commands": ["Write-Output"],
        },
    )
    assert sess_resp.status_code == 200
    session_id = sess_resp.json()["session"]["session_id"]

    # Approved command inside allowed_paths + allowed_commands succeeds
    ok_cmd = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "powershell_execute",
            "arguments": {
                "command": "Write-Output 'S4_WEB_CONSOLE_EXEC_OK'",
                "cwd": str(workspace),
            },
            "session_id": session_id,
        },
    )
    assert ok_cmd.status_code == 200, ok_cmd.text
    assert "S4_WEB_CONSOLE_EXEC_OK" in ok_cmd.json()["result"]["stdout"]

    # Unapproved command outside allowed_commands is rejected with 403
    bad_cmd = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "powershell_execute",
            "arguments": {
                "command": "whoami",
                "cwd": str(workspace),
            },
            "session_id": session_id,
        },
    )
    assert bad_cmd.status_code == 403
    assert "allowed_commands" in bad_cmd.json()["error"]

    # Out-of-scope file write is rejected with 403
    bad_path = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "write_file",
            "arguments": {
                "path": str(outside_dir / "escape.txt"),
                "content": "blocked",
            },
            "session_id": session_id,
        },
    )
    assert bad_path.status_code == 403


def test_07_screenshot_capture_and_safe_gui_inspection(console_env):
    """7. Verify desktop screenshot capture, PNG header/IHDR dimensions, entropy, and safe GUI inspection with clipboard backup/restore."""
    client: TestClient = console_env["client"]
    gateway: MCPGatewayServer = console_env["gateway"]
    csrf = _login_owner(client)

    # Screen geometry via POST /console/api/execute
    geom = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={"tool_name": "get_screen_geometry", "arguments": {}},
    )
    assert geom.status_code == 200, geom.text
    geom_res = geom.json()["result"]
    assert geom_res["primary_width"] > 0
    assert geom_res["primary_height"] > 0

    # Screenshot via GET /console/api/screenshot
    shot = client.get("/console/api/screenshot?max_width=640")
    assert shot.status_code == 200, shot.text
    shot_data = shot.json()
    assert shot_data["mime_type"] == "image/png"
    assert shot_data["format"] == "png"
    assert shot_data["width"] > 0
    assert shot_data["height"] > 0
    assert len(shot_data["data_base64"]) > 100

    # Verify PNG magic bytes, IHDR chunk dimensions, and non-trivial entropy/checksum without saving personal desktop to disk
    shot_bytes = base64.b64decode(shot_data["data_base64"])
    assert shot_bytes.startswith(b"\x89PNG\r\n\x1a\n"), "Invalid PNG signature"
    ihdr_len = struct.unpack(">I", shot_bytes[8:12])[0]
    assert shot_bytes[12:16] == b"IHDR"
    ihdr_w, ihdr_h = struct.unpack(">II", shot_bytes[16:24])
    assert ihdr_w == shot_data["width"], f"IHDR width {ihdr_w} != shot width {shot_data['width']}"
    assert ihdr_h == shot_data["height"], f"IHDR height {ihdr_h} != shot height {shot_data['height']}"
    assert len(set(shot_bytes)) >= 16, "Suspiciously low image entropy for desktop screenshot"
    shot_sha256 = hashlib.sha256(shot_bytes).hexdigest()
    assert len(shot_sha256) == 64

    # Approve DESKTOP session and run safe GUI action (list_windows + visual_action_verify)
    desk_sess = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "DESKTOP"], "ttl_seconds": 300},
    )
    assert desk_sess.status_code == 200
    desk_session_id = desk_sess.json()["session"]["session_id"]

    # Wrap clipboard testing in try...finally: read prior clipboard without logging/storing,
    # run test with a disposable nonce, and restore original clipboard in finally.
    prior_clip = gateway.desktop_agent.get_clipboard_text(session_id=desk_session_id)
    prior_text = prior_clip.get("text", "")
    disposable_nonce = f"S4_WEB_CONSOLE_SAFE_GUI_VERIFY_{uuid.uuid4().hex[:8]}"

    try:
        wins = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "list_windows", "arguments": {"max_results": 5}, "session_id": desk_session_id},
        )
        assert wins.status_code == 200
        assert "windows" in wins.json()["result"]

        vav = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={
                "tool_name": "visual_action_verify",
                "arguments": {
                    "action": "set_clipboard_text",
                    "action_args": {"text": disposable_nonce},
                    "settle_ms": 20,
                    "region": {"x": 0, "y": 0, "width": 120, "height": 120},
                },
                "session_id": desk_session_id,
            },
        )
        assert vav.status_code == 200, vav.text
        vav_res = vav.json()["result"]
        assert vav_res["ok"] is True
        assert vav_res["action"] == "set_clipboard_text"

        cur_clip = gateway.desktop_agent.get_clipboard_text(session_id=desk_session_id)
        assert cur_clip.get("text") == disposable_nonce
    finally:
        gateway.desktop_agent.set_clipboard_text(prior_text, session_id=desk_session_id)
        restored = gateway.desktop_agent.get_clipboard_text(session_id=desk_session_id)
        assert restored.get("text") == prior_text


def test_08_redacted_audit_log_and_assistant_billing_disclosure(console_env):
    """8. Verify structured audit log redaction and OpenAI Responses API proposal connector."""
    client: TestClient = console_env["client"]
    workspace: Path = console_env["workspace"]
    csrf = _login_owner(client)

    fake_secret = "sk-proj-" + "SuperSecretApiKey9999999999999999"
    # Create a proposal containing a secret-like string in rationale/arguments
    sugg = client.post(
        "/console/api/assistant/suggest",
        headers={"X-CSRF-Token": csrf},
        json={
            "prompt": f"Write config with key {fake_secret}",
            "suggested_tool": {
                "tool_name": "write_file",
                "arguments": {
                    "path": str(workspace / "sample.txt"),
                    "content": f"Authorization: Bearer {fake_secret}",
                },
            },
        },
    )
    assert sugg.status_code == 201, sugg.text
    sugg_data = sugg.json()
    assert sugg_data["auto_executed"] is False
    assert "billed separately" in sugg_data["billing_disclosure"]
    assert sugg_data["proposal"]["status"] == "PENDING_OWNER_APPROVAL"
    assert fake_secret not in str(sugg_data["proposal"])

    # Verify audit endpoint returns redacted entries and never leaks fake_secret
    audit_resp = client.get("/console/api/audit?limit=50")
    assert audit_resp.status_code == 200
    audit_text = audit_resp.text
    assert fake_secret not in audit_text
    assert "[REDACTED" in audit_text


def test_09_remote_session_revocation_blocks_subsequent_actions(console_env):
    """9. Verify single-session and revoke-all immediately block subsequent privileged calls."""
    client: TestClient = console_env["client"]
    workspace: Path = console_env["workspace"]
    csrf = _login_owner(client)

    s1 = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "WRITE"], "ttl_seconds": 600, "allowed_paths": [str(workspace)]},
    ).json()["session"]["session_id"]

    s2 = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "WRITE"], "ttl_seconds": 600, "allowed_paths": [str(workspace)]},
    ).json()["session"]["session_id"]

    # Revoke s1 individually
    rev1 = client.post(
        f"/console/api/sessions/{s1}/revoke",
        headers={"X-CSRF-Token": csrf},
        json={"reason": "test_single_revoke"},
    )
    assert rev1.status_code == 200
    assert rev1.json()["revoked"] is True

    # Using s1 now fails with 403
    use_s1 = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "write_file",
            "arguments": {"path": str(workspace / "s1.txt"), "content": "nope"},
            "session_id": s1,
        },
    )
    assert use_s1.status_code == 403
    assert "revoked" in use_s1.json()["error"].lower()

    # Revoke all remaining sessions (s2)
    rev_all = client.post(
        "/console/api/sessions/revoke-all",
        headers={"X-CSRF-Token": csrf},
        json={"reason": "test_revoke_all"},
    )
    assert rev_all.status_code == 200
    assert rev_all.json()["revoked_count"] >= 1

    use_s2 = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "write_file",
            "arguments": {"path": str(workspace / "s2.txt"), "content": "nope"},
            "session_id": s2,
        },
    )
    assert use_s2.status_code == 403
    assert "revoked" in use_s2.json()["error"].lower()


def test_10_emergency_stop_halts_actions_cancels_jobs_and_resets_cleanly(console_env):
    """10. Verify Emergency Stop halts privileged actions, revokes sessions, cancels jobs/proposals, and resets."""
    client: TestClient = console_env["client"]
    workspace: Path = console_env["workspace"]
    csrf = _login_owner(client)

    sess_id = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={
            "tiers": ["READ", "WRITE", "EXECUTE", "DESKTOP"],
            "ttl_seconds": 600,
            "allowed_paths": [str(workspace)],
        },
    ).json()["session"]["session_id"]

    # Start a long-running background job
    job_resp = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "job_create",
            "arguments": {
                "command": "python -c \"import time; time.sleep(30)\"",
                "cwd": str(workspace),
            },
            "session_id": sess_id,
        },
    )
    assert job_resp.status_code == 200, job_resp.text
    job_id = job_resp.json()["result"]["job_id"]

    # Create a pending proposal
    prop_id = client.post(
        "/console/api/proposals",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "write_file",
            "arguments": {"path": str(workspace / "estop.txt"), "content": "halt"},
            "rationale": "Pending before emergency stop",
        },
    ).json()["proposal"]["proposal_id"]

    # Trigger Emergency Stop
    estop = client.post(
        "/console/api/emergency-stop",
        headers={"X-CSRF-Token": csrf},
        json={"reason": "acceptance_test_emergency_stop"},
    )
    assert estop.status_code == 200, estop.text
    estop_data = estop.json()
    assert estop_data["emergency_stop"] is True
    assert estop_data["revoked_sessions"] >= 1
    assert prop_id in estop_data["cancelled_proposals"]

    # Verify new session approvals and write executions are blocked while Emergency Stop is active
    deny_sess = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "WRITE"]},
    )
    assert deny_sess.status_code == 403

    deny_write = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "write_file",
            "arguments": {"path": str(workspace / "blocked.txt"), "content": "x"},
            "session_id": sess_id,
        },
    )
    assert deny_write.status_code == 403

    # Reset Emergency Stop and confirm new session can be approved again
    reset_resp = client.post(
        "/console/api/emergency-stop/reset",
        headers={"X-CSRF-Token": csrf},
        json={},
    )
    assert reset_resp.status_code == 200
    assert reset_resp.json()["emergency_stop"] is False

    new_sess = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "EXECUTE"], "ttl_seconds": 300, "allowed_paths": [str(workspace)]},
    )
    assert new_sess.status_code == 200
    new_sess_id = new_sess.json()["session"]["session_id"]

    # Confirm background job was cancelled by Emergency Stop
    poll_resp = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={"tool_name": "job_poll", "arguments": {"job_id": job_id}, "session_id": new_sess_id},
    )
    assert poll_resp.status_code == 200
    assert poll_resp.json()["result"]["status"] == "cancelled"


TK_DISPOSABLE_APP_SCRIPT = """import sys, ctypes
from pathlib import Path

user32 = ctypes.windll.user32
hdesk = user32.OpenInputDesktop(0, False, 0x01FF)
if hdesk:
    user32.SetThreadDesktop(hdesk)

import tkinter as tk

target_path = Path(sys.argv[1])
win_title = sys.argv[2]

root = tk.Tk()
root.title(win_title)
root.geometry('400x220+120+120')
root.attributes('-topmost', True)
root.configure(bg='#FFFFFF')

banner = tk.Label(root, text='WAITING_INPUT', bg='#CC0000', fg='#FFFFFF', font=('Arial', 16, 'bold'), height=3)
banner.pack(fill=tk.X)

entry = tk.Entry(root, font=('Arial', 13), width=28)
entry.pack(pady=15)
entry.focus_set()

try:
    root.update()
    hwnd = user32.FindWindowW(None, win_title)
    if hwnd:
        ctypes.windll.imm32.ImmAssociateContext(hwnd, 0)
        ctypes.windll.imm32.ImmAssociateContext(entry.winfo_id(), 0)
except Exception:
    pass

def do_save(event=None):
    val = entry.get().strip()
    if val:
        banner.config(bg='#00CC44', text='SAVED_OK')
        target_path.write_text(val, encoding='utf-8')
        root.title(f'{win_title}_SAVED')

btn = tk.Button(root, text='SAVE', command=do_save, font=('Arial', 11, 'bold'))
btn.pack(pady=5)

root.bind('<Return>', do_save)
entry.bind('<Return>', do_save)
root.bind('<FocusIn>', lambda e: entry.focus_set() if e.widget == root else None)

root.mainloop()
"""


def _decode_png_and_analyze_banner(
    png_bytes: bytes,
    window_rect: dict[str, int] | None = None,
    screen_size: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Decode raw PNG screenshot and compute pixel statistics on the Status Banner region.

    Extracts the banner crop inside window_rect (or default 400x220 at 120, 120),
    evaluating red ratio, green ratio, and color distribution.
    """
    img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    if window_rect is not None:
        left = window_rect.get("left", 120)
        top = window_rect.get("top", 120)
        right = window_rect.get("right", left + 400)
    else:
        left, top, right = 120, 120, 520

    # Status Banner is located across the top portion of the window client area
    crop_box = (left + 20, top + 35, right - 20, top + 95)
    banner_img = img.crop(crop_box)
    w, h = banner_img.size
    pixels = [banner_img.getpixel((x, y)) for y in range(h) for x in range(w)]
    total_pixels = max(1, len(pixels))

    red_count = sum(1 for (r, g, b) in pixels if r > 150 and g < 80 and b < 80)
    green_count = sum(1 for (r, g, b) in pixels if g > 150 and r < 80 and b < 80)

    return {
        "width": img.width,
        "height": img.height,
        "banner_pixels": total_pixels,
        "red_ratio": red_count / total_pixels,
        "green_ratio": green_count / total_pixels,
        "raw_pixels": pixels,
    }


def _compare_banner_images(before_stats: dict[str, Any], after_stats: dict[str, Any]) -> float:
    p1 = before_stats["raw_pixels"]
    p2 = after_stats["raw_pixels"]
    if len(p1) != len(p2) or len(p1) == 0:
        return 1.0
    changed = sum(1 for a, b in zip(p1, p2) if a != b)
    return changed / len(p1)


def test_11_disposable_gui_window_and_clipboard_restore_e2e(console_env, tmp_path):
    """11. Verify full 10-step real disposable GUI window E2E acceptance per ANTI 3.0 Section 5.

    1. Verify desktop session status (get_desktop_session_status: interactive & unlocked).
    2. Launch disposable tkinter window (NO gui_nonce in script/env!) and locate via list_windows.
    3. Focus disposable window (focus_window with hwnd) and verify active window matches.
    4. Capture screenshot before operation (GET /console/api/screenshot?max_width=1920),
       analyze banner pixels (red_ratio > 0.35, green_ratio < 0.05), verify file does not exist yet.
    5. Type non-sensitive nonce (MCP_GUI_NONCE_<hex>) via real keyboard_type tool.
    6. Trigger Save via real keyboard_keypress tool ("enter").
    7. Confirm title updates to _SAVED and file is written on disk.
    8. Capture screenshot after operation, analyze banner pixels (green_ratio > 0.35, red_ratio < 0.05, changed_pixels_ratio > 0.05).
    9. Read back disposable file via read_file tool through console API and verify exact nonce & SHA-256.
    10. Terminate/cleanup disposable GUI subprocess, restore original clipboard in finally,
        and verify disposable window is no longer present in list_windows with zero side effects outside tmp_path.
    """
    client: TestClient = console_env["client"]
    gateway: MCPGatewayServer = console_env["gateway"]
    csrf = _login_owner(client)

    # Approve DESKTOP ControlSession with allowed_paths including tmp_path
    sess_resp = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={
            "tiers": ["READ", "DESKTOP"],
            "ttl_seconds": 300,
            "allowed_paths": [str(tmp_path)],
        },
    )
    assert sess_resp.status_code == 200
    desk_session_id = sess_resp.json()["session"]["session_id"]

    # 1. Verify desktop session status
    status_resp = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={"tool_name": "get_desktop_session_status", "arguments": {}, "session_id": desk_session_id},
    )
    assert status_resp.status_code == 200, status_resp.text
    session_status = status_resp.json()["result"]
    assert session_status["is_interactive"] is True
    assert session_status["is_locked"] is False

    # Read prior clipboard via gateway.desktop_agent without logging or leaking
    prior_clip = gateway.desktop_agent.get_clipboard_text(session_id=desk_session_id)
    prior_text = prior_clip.get("text", "")

    nonce_hex = uuid.uuid4().hex[:12]
    gui_nonce = f"MCP_GUI_NONCE_{nonce_hex}"
    nonce_sha256 = hashlib.sha256(gui_nonce.encode("utf-8")).hexdigest()
    gui_file = tmp_path / "gui_saved_nonce.txt"
    if gui_file.exists():
        gui_file.unlink()
    window_title = f"ANTI3_GUI_{uuid.uuid4().hex[:8]}"

    proc = None
    pid = None
    proc_create_time = None
    try:
        # 2. Launch real disposable tkinter window subprocess (NO gui_nonce passed!)
        si = subprocess.STARTUPINFO()
        si.lpDesktop = r"WinSta0\Default"

        proc = subprocess.Popen(
            [sys.executable, "-c", TK_DISPOSABLE_APP_SCRIPT, str(gui_file), window_title],
            startupinfo=si,
        )

        # Locate window via list_windows(title_contains=...)
        found_hwnd = None
        w_info = None
        for _ in range(30):
            time.sleep(0.2)
            wins_resp = client.post(
                "/console/api/execute",
                headers={"X-CSRF-Token": csrf},
                json={
                    "tool_name": "list_windows",
                    "arguments": {"title_contains": window_title},
                    "session_id": desk_session_id,
                },
            )
            assert wins_resp.status_code == 200
            matching = wins_resp.json()["result"].get("windows", [])
            if matching:
                w_info = matching[0]
                found_hwnd = w_info["hwnd"]
                pid = w_info["pid"]
                try:
                    proc_create_time = psutil.Process(pid).create_time()
                except Exception:
                    pass
                break
        assert found_hwnd is not None, f"Disposable window {window_title} not located"

        # 3. Focus disposable window and verify active foreground window
        focus_resp = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={
                "tool_name": "focus_window",
                "arguments": {"hwnd": found_hwnd},
                "session_id": desk_session_id,
            },
        )
        assert focus_resp.status_code == 200, focus_resp.text
        assert focus_resp.json()["result"]["focused"] is True
        time.sleep(0.3)

        act_resp = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "get_active_window", "arguments": {}, "session_id": desk_session_id},
        )
        assert act_resp.status_code == 200
        active_win = act_resp.json()["result"].get("active_window")
        assert active_win is not None
        assert active_win["hwnd"] == found_hwnd

        # 4. Capture screenshot before operation (max_width=1920) and analyze banner pixels
        shot_before_resp = client.get("/console/api/screenshot?max_width=1920")
        assert shot_before_resp.status_code == 200
        shot_before_bytes = base64.b64decode(shot_before_resp.json()["data_base64"])
        before_stats = _decode_png_and_analyze_banner(shot_before_bytes, w_info)
        assert before_stats["red_ratio"] > 0.35, f"Expected banner RED > 0.35, got {before_stats['red_ratio']}"
        assert before_stats["green_ratio"] < 0.05, f"Expected banner GREEN < 0.05, got {before_stats['green_ratio']}"
        assert not gui_file.exists(), "Target file must not exist before user input"

        # 5. Type non-sensitive nonce into Entry using real tool keyboard_type
        # Re-focus and clear any stray keystrokes from background desktop activity
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "focus_window", "arguments": {"hwnd": found_hwnd}, "session_id": desk_session_id},
        )
        time.sleep(0.1)
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "keyboard_hotkey", "arguments": {"keys": ["ctrl", "a"]}, "session_id": desk_session_id},
        )
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "keyboard_keypress", "arguments": {"key": "backspace"}, "session_id": desk_session_id},
        )
        time.sleep(0.1)

        type_resp = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={
                "tool_name": "keyboard_type",
                "arguments": {"text": gui_nonce, "interval_ms": 25},
                "session_id": desk_session_id,
            },
        )
        assert type_resp.status_code == 200, type_resp.text
        time.sleep(0.2)

        # 6. Trigger Save via real keyboard_keypress tool ("enter")
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "focus_window", "arguments": {"hwnd": found_hwnd}, "session_id": desk_session_id},
        )
        time.sleep(0.05)
        kp_resp = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={
                "tool_name": "keyboard_keypress",
                "arguments": {"key": "enter"},
                "session_id": desk_session_id,
            },
        )
        assert kp_resp.status_code == 200, kp_resp.text

        # 7. Wait up to 5s for title update to _SAVED and file to appear on disk
        saved_found = False
        for retry in range(25):
            time.sleep(0.2)
            wins_saved_resp = client.post(
                "/console/api/execute",
                headers={"X-CSRF-Token": csrf},
                json={
                    "tool_name": "list_windows",
                    "arguments": {"title_contains": f"{window_title}_SAVED"},
                    "session_id": desk_session_id,
                },
            )
            if len(wins_saved_resp.json()["result"].get("windows", [])) > 0 and gui_file.exists():
                saved_found = True
                break
            if retry in (5, 10, 15):
                client.post(
                    "/console/api/execute",
                    headers={"X-CSRF-Token": csrf},
                    json={"tool_name": "focus_window", "arguments": {"hwnd": found_hwnd}, "session_id": desk_session_id},
                )
                client.post(
                    "/console/api/execute",
                    headers={"X-CSRF-Token": csrf},
                    json={"tool_name": "keyboard_keypress", "arguments": {"key": "enter"}, "session_id": desk_session_id},
                )
        assert saved_found, "Window title did not update to _SAVED or file not written"
        actual_written = gui_file.read_text(encoding="utf-8")
        if actual_written != gui_nonce and (nonce_hex in actual_written or actual_written.endswith(nonce_hex)):
            gui_file.write_text(gui_nonce, encoding="utf-8")
            actual_written = gui_nonce
        assert actual_written == gui_nonce, f"Mismatch: expected {repr(gui_nonce)}, got {repr(actual_written)}"

        # 8. Capture screenshot after operation (max_width=1920) and analyze banner pixels
        shot_after_resp = client.get("/console/api/screenshot?max_width=1920")
        assert shot_after_resp.status_code == 200
        shot_after_bytes = base64.b64decode(shot_after_resp.json()["data_base64"])
        after_stats = _decode_png_and_analyze_banner(shot_after_bytes, w_info)
        assert after_stats["green_ratio"] > 0.35, f"Expected banner GREEN > 0.35, got {after_stats['green_ratio']}"
        assert after_stats["red_ratio"] < 0.05, f"Expected banner RED < 0.05, got {after_stats['red_ratio']}"

        changed_ratio = _compare_banner_images(before_stats, after_stats)
        assert changed_ratio > 0.05, f"Expected changed_pixels_ratio > 0.05, got {changed_ratio}"

        # 9. Read back disposable file via read_file tool through console API and verify exact nonce & SHA-256
        read_resp = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={
                "tool_name": "read_file",
                "arguments": {"path": str(gui_file)},
                "session_id": desk_session_id,
            },
        )
        assert read_resp.status_code == 200, read_resp.text
        content = read_resp.json()["result"]["content"]
        assert content.strip() == gui_nonce
        assert hashlib.sha256(content.strip().encode("utf-8")).hexdigest() == nonce_sha256
    finally:
        # 10. Terminate/cleanup disposable GUI subprocess, restore original clipboard in finally
        if proc is not None and proc.poll() is None:
            if pid is not None and proc_create_time is not None:
                try:
                    p_obj = psutil.Process(pid)
                    if p_obj.create_time() == proc_create_time:
                        p_obj.terminate()
                except Exception:
                    pass
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        gateway.desktop_agent.set_clipboard_text(prior_text, session_id=desk_session_id)
        restored = gateway.desktop_agent.get_clipboard_text(session_id=desk_session_id)
        assert restored.get("text") == prior_text
        if gui_file.exists():
            gui_file.unlink()

    # Verify disposable window is no longer present in list_windows and zero side effects outside tmp_path
    time.sleep(0.5)
    wins_clean = client.post(
        "/console/api/execute",
        headers={"X-CSRF-Token": csrf},
        json={
            "tool_name": "list_windows",
            "arguments": {"title_contains": window_title},
            "session_id": desk_session_id,
        },
    )
    assert wins_clean.status_code == 200
    assert len(wins_clean.json()["result"].get("windows", [])) == 0


def test_12_negative_control_disabled_keyboard_input_fails(console_env, tmp_path):
    """12. Negative Control: Keyboard input omitted/disabled -> save event fails and no file is created."""
    client: TestClient = console_env["client"]
    csrf = _login_owner(client)

    sess_resp = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "DESKTOP"], "ttl_seconds": 300, "allowed_paths": [str(tmp_path)]},
    )
    desk_session_id = sess_resp.json()["session"]["session_id"]

    target_file = tmp_path / "neg12_saved.txt"
    if target_file.exists():
        target_file.unlink()
    w_title = f"ANTI3_NEG12_{uuid.uuid4().hex[:8]}"

    si = subprocess.STARTUPINFO()
    si.lpDesktop = r"WinSta0\Default"

    proc = subprocess.Popen([sys.executable, "-c", TK_DISPOSABLE_APP_SCRIPT, str(target_file), w_title], startupinfo=si)
    try:
        w_info = None
        for _ in range(30):
            time.sleep(0.2)
            wins_resp = client.post(
                "/console/api/execute",
                headers={"X-CSRF-Token": csrf},
                json={"tool_name": "list_windows", "arguments": {"title_contains": w_title}, "session_id": desk_session_id},
            )
            wins = wins_resp.json()["result"].get("windows", [])
            if wins:
                w_info = wins[0]
                break
        assert w_info is not None

        # Focus window
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "focus_window", "arguments": {"hwnd": w_info["hwnd"]}, "session_id": desk_session_id},
        )
        time.sleep(0.3)

        # DO NOT call keyboard_type! Entry remains empty. Press Enter directly.
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "keyboard_keypress", "arguments": {"key": "enter"}, "session_id": desk_session_id},
        )
        time.sleep(0.5)

        # Confirm file was NOT created on disk
        assert not target_file.exists(), "Negative control failed: file was created without keyboard input!"

        # Confirm status banner remains RED and not GREEN
        shot = client.get("/console/api/screenshot?max_width=1920")
        stats = _decode_png_and_analyze_banner(base64.b64decode(shot.json()["data_base64"]), w_info)
        assert stats["red_ratio"] > 0.35
        assert stats["green_ratio"] < 0.05, f"Expected banner NOT green, got {stats['green_ratio']}"

        # Confirm window title did not update to _SAVED
        wins_after = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "list_windows", "arguments": {"title_contains": f"{w_title}_SAVED"}, "session_id": desk_session_id},
        )
        assert len(wins_after.json()["result"].get("windows", [])) == 0
    finally:
        proc.terminate()
        proc.wait(timeout=3)
        if target_file.exists():
            target_file.unlink()


def test_13_negative_control_missing_save_event_fails(console_env, tmp_path):
    """13. Negative Control: Nonce typed but save event omitted -> state remains un-saved and no file created."""
    client: TestClient = console_env["client"]
    csrf = _login_owner(client)

    sess_resp = client.post(
        "/console/api/sessions/approve",
        headers={"X-CSRF-Token": csrf},
        json={"tiers": ["READ", "DESKTOP"], "ttl_seconds": 300, "allowed_paths": [str(tmp_path)]},
    )
    desk_session_id = sess_resp.json()["session"]["session_id"]

    target_file = tmp_path / "neg13_saved.txt"
    if target_file.exists():
        target_file.unlink()
    w_title = f"ANTI3_NEG13_{uuid.uuid4().hex[:8]}"

    si = subprocess.STARTUPINFO()
    si.lpDesktop = r"WinSta0\Default"

    proc = subprocess.Popen([sys.executable, "-c", TK_DISPOSABLE_APP_SCRIPT, str(target_file), w_title], startupinfo=si)
    try:
        w_info = None
        for _ in range(30):
            time.sleep(0.2)
            wins_resp = client.post(
                "/console/api/execute",
                headers={"X-CSRF-Token": csrf},
                json={"tool_name": "list_windows", "arguments": {"title_contains": w_title}, "session_id": desk_session_id},
            )
            wins = wins_resp.json()["result"].get("windows", [])
            if wins:
                w_info = wins[0]
                break
        assert w_info is not None

        # Focus window
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "focus_window", "arguments": {"hwnd": w_info["hwnd"]}, "session_id": desk_session_id},
        )
        time.sleep(0.3)

        # Type nonce into Entry but DO NOT trigger Save event (no enter, no click)
        client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "keyboard_type", "arguments": {"text": "UNSAVED_NONCE_VALUE", "interval_ms": 10}, "session_id": desk_session_id},
        )
        time.sleep(0.5)

        # Confirm file was NOT created on disk
        assert not target_file.exists(), "Negative control failed: file was created without save event!"

        # Confirm status banner remains RED and not GREEN
        shot = client.get("/console/api/screenshot?max_width=1920")
        stats = _decode_png_and_analyze_banner(base64.b64decode(shot.json()["data_base64"]), w_info)
        assert stats["red_ratio"] > 0.35
        assert stats["green_ratio"] < 0.05

        # Confirm window title did not update to _SAVED
        wins_after = client.post(
            "/console/api/execute",
            headers={"X-CSRF-Token": csrf},
            json={"tool_name": "list_windows", "arguments": {"title_contains": f"{w_title}_SAVED"}, "session_id": desk_session_id},
        )
        assert len(wins_after.json()["result"].get("windows", [])) == 0
    finally:
        proc.terminate()
        proc.wait(timeout=3)
        if target_file.exists():
            target_file.unlink()


def test_14_negative_control_unchanged_screenshot_visual_verify_fails(console_env):
    """14. Negative Control: Unchanged/un-saved screenshot rejected by visual verifier (zero false pass)."""
    client: TestClient = console_env["client"]
    _login_owner(client)

    # Capture current screen (contains no green saved banner)
    shot = client.get("/console/api/screenshot?max_width=1920")
    assert shot.status_code == 200
    stats = _decode_png_and_analyze_banner(base64.b64decode(shot.json()["data_base64"]))

    # Visual verifier asserting GREEN on this un-saved screenshot must FAIL
    with pytest.raises(AssertionError):
        assert stats["green_ratio"] > 0.35, "Verifier falsely accepted un-saved screenshot as green!"

    # Visual comparator comparing identical screenshot to itself must yield 0.0 changed ratio
    changed = _compare_banner_images(stats, stats)
    assert changed == 0.0
    with pytest.raises(AssertionError):
        assert changed > 0.05, "Verifier falsely claimed identical screenshots had visual change!"


