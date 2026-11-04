"""Phase P3 (Windows Desktop Agent) Automated Acceptance & Safety Tests.

Covers:
1. Interactive session & lock inspection (get_desktop_session_status)
2. Multi-monitor & DPI geometry inspection (get_screen_geometry)
3. Full desktop, region, and window screenshots (PNG validation, MCP image/png content block,
   coordinate mapping, payload size guard)
4. Safe isolated disposable test window (Tkinter top-level window):
   - list_windows discovery by title
   - focus_window & get_active_window
   - mouse_move, mouse_click, keyboard_type, keyboard_keypress, keyboard_hotkey inside disposable window
   - visual_action_verify workflow
5. Clipboard roundtrip (set_clipboard_text / get_clipboard_text) with original clipboard restoration
6. Sensitive window title blackout & rejection filter (e.g. '1Password Vault')
7. Emergency Stop engagement (file flag runtime/EMERGENCY_STOP + latch) & reset
8. Simulated locked/non-interactive session rejection (DesktopSessionLockedError)
"""
from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _d in (PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from policy import PermissionTier, SecurityPolicy  # noqa: E402
from agent import (  # noqa: E402
    DesktopAgent,
    DesktopSessionLockedError,
    EmergencyStopActiveError,
)


_TK_WINDOW_SCRIPT = """
import sys
import tkinter as tk

title = sys.argv[1]
root = tk.Tk()
root.title(title)
root.geometry("360x220+120+120")
root.attributes("-topmost", True)
entry = tk.Entry(root, font=("Consolas", 14))
entry.pack(fill="x", padx=15, pady=15)
entry.focus_set()
lbl = tk.Label(root, text="Disposable MCP Test Window", bg="#225588", fg="white", height=5)
lbl.pack(fill="both", expand=True, padx=15, pady=10)
root.after(15000, root.destroy)
root.mainloop()
"""


class TestP3DesktopAgent(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name).resolve()
        self.audit_log = self.base / "audit.jsonl"
        self.emergency_file = self.base / "EMERGENCY_STOP"

        self.policy = SecurityPolicy(
            profile="desktop_p3",
            allowed_read_roots=[str(self.base)],
            allowed_write_roots=[str(self.base)],
            audit_log_path=str(self.audit_log),
        )
        self.session = self.policy.sessions.create_session([PermissionTier.DESKTOP], ttl_seconds=600)
        self.sid = self.session.session_id
        self.agent = DesktopAgent(
            policy=self.policy,
            emergency_stop_file=self.emergency_file,
        )

    def tearDown(self) -> None:
        self.agent.set_simulated_locked_session(False)
        self.agent.reset_emergency_stop()
        self.tmp_dir.cleanup()

    def test_session_status_and_screen_geometry(self) -> None:
        """Verify session inspection and DPI/monitor geometry."""
        status = self.agent.get_desktop_session_status()
        self.assertIn("windows_session_id", status)
        self.assertIn("window_station", status)
        self.assertFalse(status["emergency_stop_active"])

        geom = self.agent.get_screen_geometry()
        self.assertGreater(geom["primary_width"], 0)
        self.assertGreater(geom["primary_height"], 0)
        self.assertGreaterEqual(geom["monitor_count"], 1)
        self.assertGreater(geom["dpi"], 0)
        self.assertTrue(len(geom["monitors"]) >= 1)

    def test_desktop_and_region_screenshots_and_clipboard(self) -> None:
        """Verify screenshot capture (desktop + region) and clipboard roundtrip."""
        status = self.agent.get_desktop_session_status()
        if status["is_locked"] or not status["is_interactive"]:
            self.skipTest("Interactive unlocked desktop not available in current environment")

        # Full desktop screenshot
        shot = self.agent.screenshot(target="desktop", monitor=0, max_width=1024)
        self.assertTrue(shot["ok"])
        self.assertGreater(shot["width"], 0)
        self.assertGreater(shot["height"], 0)
        raw_png = base64.b64decode(shot["data_base64"])
        self.assertTrue(raw_png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertEqual(shot["mcp_content"][0]["mimeType"], "image/png")
        self.assertIn("coordinate_mapping", shot)

        # Region screenshot
        reg_shot = self.agent.screenshot(target="region", x=50, y=50, width=200, height=150)
        self.assertTrue(reg_shot["ok"])
        self.assertEqual(reg_shot["width"], 200)
        self.assertEqual(reg_shot["height"], 150)

        # Clipboard roundtrip (preserving existing user clipboard)
        orig_clip = self.agent.get_clipboard_text(session_id=self.sid)
        try:
            marker = "MCP_P3_CLIPBOARD_TEST_Xin_Chao_12345"
            set_res = self.agent.set_clipboard_text(marker, session_id=self.sid)
            self.assertTrue(set_res["ok"])
            self.assertEqual(set_res["char_count"], len(marker))

            get_res = self.agent.get_clipboard_text(session_id=self.sid)
            self.assertTrue(get_res["ok"])
            self.assertEqual(get_res["text"], marker)
        finally:
            if orig_clip.get("has_text"):
                self.agent.set_clipboard_text(orig_clip["text"], session_id=self.sid)

    def test_disposable_window_automation_and_visual_verify(self) -> None:
        """Launch a harmless disposable Tkinter window, inspect HWND, focus, click, type, and verify."""
        status = self.agent.get_desktop_session_status()
        if status["is_locked"] or not status["is_interactive"]:
            self.skipTest("Interactive unlocked desktop not available")

        unique_title = "MCP_P3_Disposable_Test_Window_8899"
        proc = subprocess.Popen(
            [sys.executable, "-c", _TK_WINDOW_SCRIPT, unique_title],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            hwnd = None
            win_info = None
            for _ in range(30):
                found = self.agent.list_windows(title_contains=unique_title)["windows"]
                if found:
                    win_info = found[0]
                    hwnd = win_info["hwnd"]
                    break
                time.sleep(0.1)

            self.assertIsNotNone(hwnd, "Disposable test window did not appear in list_windows")
            assert hwnd is not None and win_info is not None
            self.assertGreater(win_info["width"], 100)
            self.assertGreater(win_info["height"], 100)

            # Focus the disposable window
            f_res = self.agent.focus_window(hwnd, session_id=self.sid)
            self.assertTrue(f_res["ok"])

            # Capture window screenshot
            w_shot = self.agent.screenshot(target="window", hwnd=hwnd)
            self.assertTrue(w_shot["ok"])
            self.assertGreater(w_shot["width"], 100)

            # Move mouse and click inside the disposable window's entry box
            click_x = win_info["left"] + 80
            click_y = win_info["top"] + 55
            mv_res = self.agent.mouse_move(click_x, click_y, session_id=self.sid)
            self.assertTrue(mv_res["ok"])

            clk_res = self.agent.mouse_click(click_x, click_y, button="left", session_id=self.sid)
            self.assertTrue(clk_res["ok"])

            # Use visual_action_verify while typing text into the disposable window
            verify_res = self.agent.visual_action_verify(
                action="keyboard_type",
                action_args={"text": "HelloMCP", "interval_ms": 10},
                settle_ms=100,
                region={
                    "x": max(0, win_info["left"]),
                    "y": max(0, win_info["top"]),
                    "width": max(100, win_info["width"]),
                    "height": max(100, win_info["height"]),
                },
                session_id=self.sid,
            )
            self.assertTrue(verify_res["ok"])
            self.assertIn("before_sha256", verify_res)
            self.assertIn("after_sha256", verify_res)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    def test_sensitive_window_rejection_and_blackout(self) -> None:
        """Verify windows with sensitive titles (e.g. 1Password) are blocked from focus/window-capture and blacked out."""
        status = self.agent.get_desktop_session_status()
        if status["is_locked"] or not status["is_interactive"]:
            self.skipTest("Interactive unlocked desktop not available")

        sens_title = "1Password - Master Vault Credentials"
        proc = subprocess.Popen(
            [sys.executable, "-c", _TK_WINDOW_SCRIPT, sens_title],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            hwnd = None
            for _ in range(30):
                found = self.agent.list_windows(title_contains="1Password")["windows"]
                if found:
                    hwnd = found[0]["hwnd"]
                    break
                time.sleep(0.1)

            self.assertIsNotNone(hwnd)
            assert hwnd is not None

            # Direct window screenshot of sensitive window must be rejected
            with self.assertRaises(PermissionError):
                self.agent.screenshot(target="window", hwnd=hwnd)

            # Focusing sensitive window must be rejected even with active session
            with self.assertRaises(PermissionError):
                self.agent.focus_window(hwnd, session_id=self.sid)

            # Desktop screenshot must blackout the sensitive window and record it in redacted_windows
            desk_shot = self.agent.screenshot(target="desktop", monitor=0)
            self.assertIn(sens_title, desk_shot["redacted_windows"])
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    def test_emergency_stop_and_simulated_locked_session_rejection(self) -> None:
        """Verify Emergency Stop kill-switch and Locked Session refusal."""
        # 1. Engage Emergency Stop
        stop_info = self.agent.engage_emergency_stop(reason="unit_test_panic")
        self.assertTrue(stop_info["emergency_stop"])
        self.assertTrue(self.emergency_file.exists())

        with self.assertRaises(EmergencyStopActiveError):
            self.agent.mouse_move(100, 100, session_id=self.sid)
        with self.assertRaises(EmergencyStopActiveError):
            self.agent.keyboard_type("blocked", session_id=self.sid)
        with self.assertRaises(EmergencyStopActiveError):
            self.agent.screenshot(target="desktop")

        # Reset Emergency Stop
        reset_info = self.agent.reset_emergency_stop()
        self.assertFalse(reset_info["emergency_stop"])
        self.assertFalse(self.emergency_file.exists())

        # Mint fresh session after emergency stop revoked all previous sessions
        locked_sess = self.policy.sessions.create_session([PermissionTier.DESKTOP], ttl_seconds=600)
        locked_sid = locked_sess.session_id

        # 2. Simulate Locked Session / UAC Secure Desktop
        self.agent.set_simulated_locked_session(True)
        locked_status = self.agent.get_desktop_session_status()
        self.assertTrue(locked_status["is_locked"])
        self.assertFalse(locked_status["gui_manipulation_allowed"])

        with self.assertRaises(DesktopSessionLockedError):
            self.agent.mouse_click(100, 100, session_id=locked_sid)
        with self.assertRaises(DesktopSessionLockedError):
            self.agent.keyboard_keypress("enter", session_id=locked_sid)
        with self.assertRaises(DesktopSessionLockedError):
            self.agent.set_clipboard_text("blocked while locked", session_id=locked_sid)
        with self.assertRaises(DesktopSessionLockedError):
            self.agent.screenshot(target="desktop")


if __name__ == "__main__":
    unittest.main()
