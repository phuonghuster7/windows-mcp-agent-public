"""Phase P3.1 - P3.5 Interactive Session Windows Desktop Agent.

Implements:
- get_desktop_session_status: verifies Windows Session ID, WinSta0 interactive workstation,
  and OpenInputDesktop check for locked desktop / UAC Secure Desktop.
  Refuses all GUI manipulation when session is locked or non-interactive.
- Emergency Stop: file flag (runtime/EMERGENCY_STOP) + global hotkey state check
  (GetAsyncKeyState for Ctrl+Alt+Pause or Ctrl+Alt+F12) + manual latch.
- get_screen_geometry: DPI awareness, primary & multi-monitor bounds, scaling metadata.
- screenshot: full desktop, monitor index, active window, specific HWND, or region
  returning PNG bytes (base64 + MCP image/png content block), width/height/DPI metadata,
  coordinate mapping, payload size limit, and sensitive window title blackout/rejection.
- list_windows, get_active_window, focus_window.
- mouse_move, mouse_click, mouse_double_click, mouse_right_click, mouse_scroll, mouse_drag.
- keyboard_type (Unicode SendInput), keyboard_keypress, keyboard_hotkey.
- get_clipboard_text, set_clipboard_text (pure ctypes Win32 clipboard).
- visual_action_verify: captures before-state, executes an allowed GUI action,
  captures after-screenshot, and verifies window/screen state change.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import hashlib
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
from PIL import Image, ImageChops, ImageDraw, ImageGrab

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

from policy import PermissionTier, SecurityPolicy, redact_secrets  # noqa: E402

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32
try:
    shcore = ctypes.windll.shcore
except Exception:
    shcore = None


class DesktopSessionLockedError(PermissionError):
    """Raised when the Windows session is locked, non-interactive, or on UAC Secure Desktop."""


class EmergencyStopActiveError(PermissionError):
    """Raised when the Emergency Stop kill-switch is engaged."""


# ---------------------------------------------------------------------------
# Win32 Constants & Structures
# ---------------------------------------------------------------------------
UOI_NAME = 2
DESKTOP_SWITCHDESKTOP = 0x0100

SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
SM_CMONITORS = 80

SW_RESTORE = 9
GW_OWNER = 4
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_APPWINDOW = 0x00040000

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_HWHEEL = 0x01000
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
WHEEL_DELTA = 120

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

VK_CONTROL = 0x11
VK_MENU = 0x12      # Alt
VK_PAUSE = 0x13     # Pause/Break
VK_F12 = 0x7B

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

SRCCOPY = 0x00CC0020
LOGPIXELSX = 88
BI_RGB = 0
DIB_RGB_COLORS = 0


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.wintypes.DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szDevice", ctypes.wintypes.WCHAR * 32),
    ]


ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("time", ctypes.wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.wintypes.WORD),
        ("wScan", ctypes.wintypes.WORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("time", ctypes.wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class _INPUTunion(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.wintypes.DWORD), ("union", _INPUTunion)]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", ctypes.wintypes.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", ctypes.wintypes.WORD),
        ("biBitCount", ctypes.wintypes.WORD),
        ("biCompression", ctypes.wintypes.DWORD),
        ("biSizeImage", ctypes.wintypes.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", ctypes.wintypes.DWORD),
        ("biClrImportant", ctypes.wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", ctypes.wintypes.DWORD * 3)]


# Configure Win32 function argtypes/restypes for 64-bit safety
kernel32.GlobalAlloc.argtypes = [ctypes.wintypes.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = ctypes.wintypes.HANDLE
kernel32.GlobalLock.argtypes = [ctypes.wintypes.HANDLE]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [ctypes.wintypes.HANDLE]
kernel32.GlobalUnlock.restype = ctypes.wintypes.BOOL
kernel32.GlobalFree.argtypes = [ctypes.wintypes.HANDLE]
kernel32.GlobalFree.restype = ctypes.wintypes.HANDLE

user32.OpenClipboard.argtypes = [ctypes.wintypes.HWND]
user32.OpenClipboard.restype = ctypes.wintypes.BOOL
user32.CloseClipboard.argtypes = []
user32.CloseClipboard.restype = ctypes.wintypes.BOOL
user32.EmptyClipboard.argtypes = []
user32.EmptyClipboard.restype = ctypes.wintypes.BOOL
user32.GetClipboardData.argtypes = [ctypes.wintypes.UINT]
user32.GetClipboardData.restype = ctypes.wintypes.HANDLE
user32.SetClipboardData.argtypes = [ctypes.wintypes.UINT, ctypes.wintypes.HANDLE]
user32.SetClipboardData.restype = ctypes.wintypes.HANDLE
user32.IsClipboardFormatAvailable.argtypes = [ctypes.wintypes.UINT]
user32.IsClipboardFormatAvailable.restype = ctypes.wintypes.BOOL


# Key mapping for keyboard_keypress and keyboard_hotkey
_VK_MAP: dict[str, int] = {
    "ctrl": 0x11, "control": 0x11,
    "shift": 0x10,
    "alt": 0x12, "menu": 0x12,
    "win": 0x5B, "lwin": 0x5B,
    "enter": 0x0D, "return": 0x0D,
    "esc": 0x1B, "escape": 0x1B,
    "tab": 0x09,
    "space": 0x20,
    "backspace": 0x08, "back": 0x08,
    "delete": 0x2E, "del": 0x2E,
    "insert": 0x2D, "ins": 0x2D,
    "home": 0x24,
    "end": 0x23,
    "pageup": 0x21, "pgup": 0x21,
    "pagedown": 0x22, "pgdn": 0x22,
    "up": 0x26,
    "down": 0x28,
    "left": 0x25,
    "right": 0x27,
    "pause": 0x13,
    "capslock": 0x14,
}
for _i in range(1, 13):
    _VK_MAP[f"f{_i}"] = 0x6F + _i
for _c in range(ord("a"), ord("z") + 1):
    _VK_MAP[chr(_c)] = _c - 32
for _d in range(10):
    _VK_MAP[str(_d)] = 0x30 + _d

_EXTENDED_VKS = {0x2D, 0x2E, 0x24, 0x23, 0x21, 0x22, 0x25, 0x26, 0x27, 0x28, 0x5B}


def _enable_dpi_awareness() -> str:
    """Enable Per-Monitor DPI awareness so screen coordinates and screenshots match physical pixels."""
    if shcore is not None:
        try:
            # PROCESS_PER_MONITOR_DPI_AWARE = 2
            res = shcore.SetProcessDpiAwareness(2)
            if res == 0:
                return "per_monitor_dpi_aware"
        except Exception:
            pass
    try:
        if user32.SetProcessDPIAware():
            return "system_dpi_aware"
    except Exception:
        pass
    return "dpi_awareness_unchanged"


_DPI_STATUS = _enable_dpi_awareness()


def _bitblt_capture_bbox(left: int, top: int, width: int, height: int) -> Image.Image:
    """Pure Win32 GDI BitBlt screen capture fallback."""
    hdc_screen = user32.GetDC(0)
    if not hdc_screen:
        raise RuntimeError("GetDC(0) failed")
    hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
    hbmp = gdi32.CreateCompatibleBitmap(hdc_screen, width, height)
    old_obj = gdi32.SelectObject(hdc_mem, hbmp)
    try:
        gdi32.BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, left, top, SRCCOPY)
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = width
        bmi.bmiHeader.biHeight = -height  # top-down DIB
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = BI_RGB
        buf_size = width * height * 4
        buf = ctypes.create_string_buffer(buf_size)
        gdi32.GetDIBits(hdc_mem, hbmp, 0, height, buf, ctypes.byref(bmi), DIB_RGB_COLORS)
        return Image.frombuffer("RGB", (width, height), buf, "raw", "BGRX", 0, 1).copy()
    finally:
        gdi32.SelectObject(hdc_mem, old_obj)
        gdi32.DeleteObject(hbmp)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(0, hdc_screen)


class DesktopAgent:
    """Interactive Windows Desktop Agent (Phase P3.1 - P3.5) with P5 security safeguards."""

    def __init__(
        self,
        policy: SecurityPolicy | None = None,
        *,
        emergency_stop_file: str | Path | None = None,
    ) -> None:
        self.policy = policy or SecurityPolicy()
        desk_cfg = self.policy.config.get("desktop_policy", {})
        self.emergency_stop_file = Path(
            emergency_stop_file
            or getattr(self.policy, "emergency_stop_file", None)
            or desk_cfg.get("emergency_stop_file")
            or (PROJECT_ROOT / "runtime" / "EMERGENCY_STOP")
        ).resolve(strict=False)
        self.max_screenshot_bytes: int = int(desk_cfg.get("max_screenshot_bytes", 5 * 1024 * 1024))
        self.sensitive_window_keywords: tuple[str, ...] = tuple(
            k.casefold()
            for k in desk_cfg.get(
                "sensitive_window_keywords",
                [
                    "1password",
                    "bitwarden",
                    "keepass",
                    "lastpass",
                    "dashlane",
                    "windows security",
                    "credential manager",
                    "metamask",
                    "ledger live",
                    "banking",
                    "password manager",
                ],
            )
        )
        self._emergency_latch: bool = False
        self._emergency_reason: str | None = None
        self._simulated_locked_session: bool = False

    # ------------------------------------------------------------------
    # Emergency Stop & Session Status Safeguards
    # ------------------------------------------------------------------
    def engage_emergency_stop(self, reason: str = "manual_emergency_stop") -> dict[str, Any]:
        """Engage the Emergency Stop kill-switch (in-memory latch + file flag + session revoke)."""
        self._emergency_latch = True
        self._emergency_reason = reason
        self.emergency_stop_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "engaged": True,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.emergency_stop_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        revoked_count = self.policy.sessions.revoke_all(reason=f"emergency_stop:{reason}")
        self.policy.audit.log_event(
            tool_name="emergency_stop",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            reason=f"Emergency stop engaged: {reason}",
            result_summary={"revoked_sessions": revoked_count, "file": str(self.emergency_stop_file)},
        )
        return {
            "emergency_stop": True,
            "reason": reason,
            "file": str(self.emergency_stop_file),
            "revoked_sessions": revoked_count,
        }

    def reset_emergency_stop(self) -> dict[str, Any]:
        """Clear the Emergency Stop latch and remove runtime/EMERGENCY_STOP file."""
        self._emergency_latch = False
        self._emergency_reason = None
        if self.emergency_stop_file.exists():
            try:
                self.emergency_stop_file.unlink()
            except OSError:
                pass
        self.policy.audit.log_event(
            tool_name="reset_emergency_stop",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            reason="Emergency stop reset",
        )
        return {"emergency_stop": False, "file_exists": self.emergency_stop_file.exists()}

    def _hotkey_panic_pressed(self) -> bool:
        """Check hardware async key state for Ctrl+Alt+Pause or Ctrl+Alt+F12."""
        try:
            ctrl_down = (user32.GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0
            alt_down = (user32.GetAsyncKeyState(VK_MENU) & 0x8000) != 0
            pause_down = (user32.GetAsyncKeyState(VK_PAUSE) & 0x8000) != 0
            f12_down = (user32.GetAsyncKeyState(VK_F12) & 0x8000) != 0
            return bool(ctrl_down and alt_down and (pause_down or f12_down))
        except Exception:
            return False

    def check_emergency_stop(self) -> None:
        """Verify Emergency Stop is not active; raise EmergencyStopActiveError if triggered."""
        if self._hotkey_panic_pressed():
            self.engage_emergency_stop(reason="global_hotkey_ctrl_alt_pause")
        if self._emergency_latch or self.emergency_stop_file.exists():
            reason = self._emergency_reason or "EMERGENCY_STOP file present"
            raise EmergencyStopActiveError(
                f"GUI automation halted by Emergency Stop ({reason})"
            )

    def set_simulated_locked_session(self, locked: bool) -> None:
        """Test helper to simulate a locked or non-interactive Windows session."""
        self._simulated_locked_session = bool(locked)

    def _inspect_desktop_session_status(self) -> dict[str, Any]:
        """Raw Win32 inspection of current Windows Session ID, workstation name, and input desktop lock state."""
        pid = kernel32.GetCurrentProcessId()
        win_session_id = ctypes.wintypes.DWORD(0)
        kernel32.ProcessIdToSessionId(pid, ctypes.byref(win_session_id))

        # Workstation name (e.g. WinSta0)
        hwinsta = user32.GetProcessWindowStation()
        winsta_name = ""
        if hwinsta:
            buf = ctypes.create_unicode_buffer(256)
            needed = ctypes.wintypes.DWORD(0)
            if user32.GetUserObjectInformationW(
                hwinsta, UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(needed)
            ):
                winsta_name = buf.value

        # Input desktop check (OpenInputDesktop)
        input_desktop_name = ""
        desktop_accessible = False
        hdesk = user32.OpenInputDesktop(0, False, DESKTOP_SWITCHDESKTOP)
        if hdesk:
            desktop_accessible = True
            buf = ctypes.create_unicode_buffer(256)
            needed = ctypes.wintypes.DWORD(0)
            if user32.GetUserObjectInformationW(
                hdesk, UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(needed)
            ):
                input_desktop_name = buf.value
            user32.CloseDesktop(hdesk)

        is_interactive_winsta = winsta_name.lower() == "winsta0"
        is_default_desktop = input_desktop_name.lower() == "default"
        is_locked_or_secure = (
            self._simulated_locked_session
            or (not desktop_accessible)
            or (not is_default_desktop)
            or (win_session_id.value == 0)
        )
        emergency_active = self._emergency_latch or self.emergency_stop_file.exists()

        return {
            "process_id": pid,
            "windows_session_id": int(win_session_id.value),
            "window_station": winsta_name,
            "input_desktop": input_desktop_name,
            "is_interactive": is_interactive_winsta and (win_session_id.value > 0) and (not self._simulated_locked_session),
            "is_locked": is_locked_or_secure,
            "gui_manipulation_allowed": (not is_locked_or_secure) and is_interactive_winsta and (not emergency_active),
            "emergency_stop_active": emergency_active,
            "dpi_awareness": _DPI_STATUS,
        }

    def get_desktop_session_status(
        self, *, session_id: str | None = None, approval_token: str | None = None
    ) -> dict[str, Any]:
        """Inspect current Windows Session ID, workstation name, and input desktop lock state."""
        self.policy.authorize_tool(
            "get_desktop_session_status", {}, session_id=session_id, approval_token=approval_token
        )
        return self._inspect_desktop_session_status()

    def _require_interactive_unlocked_desktop(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        require_desktop_tier: bool = True,
    ) -> dict[str, Any]:
        """Enforce Emergency Stop, capability tier authorization, and unlocked interactive desktop."""
        self.check_emergency_stop()
        if require_desktop_tier:
            self.policy.authorize_tool(
                tool_name, arguments, session_id=session_id, approval_token=approval_token
            )
        status = self._inspect_desktop_session_status()
        if status["is_locked"] or not status["is_interactive"]:
            self.policy.audit.log_event(
                tool_name=tool_name,
                tier=PermissionTier.DESKTOP,
                decision="DENY",
                reason="Refused GUI manipulation: desktop session is locked, on UAC Secure Desktop, or non-interactive",
                arguments=arguments,
                session_id=session_id,
            )
            raise DesktopSessionLockedError(
                "Desktop session is locked, on UAC Secure Desktop, or non-interactive; GUI manipulation refused"
            )
        return status

    # ------------------------------------------------------------------
    # Screen Geometry & DPI Metadata
    # ------------------------------------------------------------------
    def _inspect_screen_geometry(self) -> dict[str, Any]:

        primary_w = int(user32.GetSystemMetrics(SM_CXSCREEN))
        primary_h = int(user32.GetSystemMetrics(SM_CYSCREEN))
        vx = int(user32.GetSystemMetrics(SM_XVIRTUALSCREEN))
        vy = int(user32.GetSystemMetrics(SM_YVIRTUALSCREEN))
        vw = int(user32.GetSystemMetrics(SM_CXVIRTUALSCREEN))
        vh = int(user32.GetSystemMetrics(SM_CYVIRTUALSCREEN))
        num_monitors = int(user32.GetSystemMetrics(SM_CMONITORS))

        # System DPI
        dpi = 96
        try:
            if hasattr(user32, "GetDpiForSystem"):
                dpi = int(user32.GetDpiForSystem())
            else:
                hdc = user32.GetDC(0)
                if hdc:
                    dpi = int(gdi32.GetDeviceCaps(hdc, LOGPIXELSX))
                    user32.ReleaseDC(0, hdc)
        except Exception:
            dpi = 96
        scale_factor = round(dpi / 96.0, 2)

        monitors: list[dict[str, Any]] = []
        MonitorEnumProc = ctypes.WINFUNCTYPE(
            ctypes.wintypes.BOOL,
            ctypes.wintypes.HMONITOR,
            ctypes.wintypes.HDC,
            ctypes.POINTER(RECT),
            ctypes.wintypes.LPARAM,
        )

        def _enum_cb(hmon, _hdc, _lprect, _lparam):
            mi = MONITORINFOEXW()
            mi.cbSize = ctypes.sizeof(MONITORINFOEXW)
            if user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                w = mi.rcMonitor.right - mi.rcMonitor.left
                h = mi.rcMonitor.bottom - mi.rcMonitor.top
                monitors.append({
                    "index": len(monitors),
                    "device": mi.szDevice,
                    "primary": bool(mi.dwFlags & 1),
                    "left": int(mi.rcMonitor.left),
                    "top": int(mi.rcMonitor.top),
                    "right": int(mi.rcMonitor.right),
                    "bottom": int(mi.rcMonitor.bottom),
                    "width": int(w),
                    "height": int(h),
                    "work_left": int(mi.rcWork.left),
                    "work_top": int(mi.rcWork.top),
                    "work_width": int(mi.rcWork.right - mi.rcWork.left),
                    "work_height": int(mi.rcWork.bottom - mi.rcWork.top),
                })
            return True

        try:
            user32.EnumDisplayMonitors(0, None, MonitorEnumProc(_enum_cb), 0)
        except Exception:
            pass

        if not monitors:
            monitors.append({
                "index": 0,
                "device": "DISPLAY1",
                "primary": True,
                "left": 0,
                "top": 0,
                "right": primary_w,
                "bottom": primary_h,
                "width": primary_w,
                "height": primary_h,
                "work_left": 0,
                "work_top": 0,
                "work_width": primary_w,
                "work_height": primary_h,
            })

        return {
            "primary_width": primary_w,
            "primary_height": primary_h,
            "virtual_left": vx,
            "virtual_top": vy,
            "virtual_width": vw,
            "virtual_height": vh,
            "monitor_count": max(num_monitors, len(monitors)),
            "dpi": dpi,
            "scale_factor": scale_factor,
            "scale_percent": int(round(scale_factor * 100)),
            "dpi_awareness": _DPI_STATUS,
            "monitors": monitors,
        }

    def get_screen_geometry(
        self, *, session_id: str | None = None, approval_token: str | None = None
    ) -> dict[str, Any]:
        self.policy.authorize_tool(
            "get_screen_geometry", {}, session_id=session_id, approval_token=approval_token
        )
        return self._inspect_screen_geometry()

    # ------------------------------------------------------------------
    # Window Inspection & Focus
    # ------------------------------------------------------------------
    def _is_sensitive_title(self, title: str) -> bool:
        if not title:
            return False
        low = title.casefold()
        return any(kw in low for kw in self.sensitive_window_keywords)

    def _get_window_info(self, hwnd: int) -> dict[str, Any]:
        length = user32.GetWindowTextLengthW(hwnd)
        title = ""
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value

        cls_buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, cls_buf, 256)
        class_name = cls_buf.value

        pid = ctypes.wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_val = int(pid.value)

        proc_name = ""
        try:
            proc_name = psutil.Process(pid_val).name()
        except Exception:
            pass

        rect = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        return {
            "hwnd": int(hwnd),
            "title": title,
            "class_name": class_name,
            "pid": pid_val,
            "process_name": proc_name,
            "visible": bool(user32.IsWindowVisible(hwnd)),
            "minimized": bool(user32.IsIconic(hwnd)),
            "sensitive": self._is_sensitive_title(title),
            "left": int(rect.left),
            "top": int(rect.top),
            "right": int(rect.right),
            "bottom": int(rect.bottom),
            "width": int(rect.right - rect.left),
            "height": int(rect.bottom - rect.top),
        }

    def _enumerate_windows(
        self,
        *,
        title_contains: str | None = None,
        include_untitled: bool = False,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        max_results = max(1, min(500, int(max_results)))
        results: list[dict[str, Any]] = []

        EnumWindowsProc = ctypes.WINFUNCTYPE(
            ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM
        )

        def _cb(hwnd, _lparam):
            if len(results) >= max_results:
                return False
            if not user32.IsWindowVisible(hwnd):
                return True
            ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            owner = user32.GetWindow(hwnd, GW_OWNER)
            if (ex_style & WS_EX_TOOLWINDOW) and not owner:
                return True
            info = self._get_window_info(hwnd)
            if not info["title"] and not include_untitled:
                return True
            if title_contains and title_contains.casefold() not in info["title"].casefold():
                return True
            results.append(info)
            return True

        user32.EnumWindows(EnumWindowsProc(_cb), 0)
        return results

    def list_windows(
        self,
        *,
        title_contains: str | None = None,
        include_untitled: bool = False,
        max_results: int = 100,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.policy.authorize_tool(
            "list_windows",
            {"title_contains": title_contains},
            session_id=session_id,
            approval_token=approval_token,
        )
        results = self._enumerate_windows(
            title_contains=title_contains,
            include_untitled=include_untitled,
            max_results=max_results,
        )
        return {"windows": results, "count": len(results)}

    def get_active_window(
        self, *, session_id: str | None = None, approval_token: str | None = None
    ) -> dict[str, Any]:
        self.policy.authorize_tool(
            "get_active_window", {}, session_id=session_id, approval_token=approval_token
        )
        hwnd = int(user32.GetForegroundWindow())
        if not hwnd or not user32.IsWindow(hwnd):
            return {"active_window": None}
        return {"active_window": self._get_window_info(hwnd)}

    def focus_window(
        self,
        hwnd: int,
        *,
        restore_if_minimized: bool = True,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "focus_window",
            {"hwnd": hwnd, "restore_if_minimized": restore_if_minimized},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "focus_window",
            {"hwnd": hwnd, "restore_if_minimized": restore_if_minimized},
            session_id=session_id,
            approval_token=approval_token,
        )
        if not user32.IsWindow(hwnd):
            raise ValueError(f"HWND {hwnd} is not a valid window")

        info_before = self._get_window_info(hwnd)
        if info_before["sensitive"]:
            raise PermissionError(f"Refusing to focus sensitive window: {info_before['title']}")

        if user32.IsIconic(hwnd) and restore_if_minimized:
            user32.ShowWindow(hwnd, SW_RESTORE)
            time.sleep(0.06)

        fg_hwnd = user32.GetForegroundWindow()
        if fg_hwnd and fg_hwnd != hwnd:
            fg_tid = user32.GetWindowThreadProcessId(fg_hwnd, None)
            my_tid = kernel32.GetCurrentThreadId()
            if fg_tid and fg_tid != my_tid:
                user32.AttachThreadInput(my_tid, fg_tid, True)
                try:
                    user32.BringWindowToTop(hwnd)
                    user32.SetForegroundWindow(hwnd)
                finally:
                    user32.AttachThreadInput(my_tid, fg_tid, False)
            else:
                user32.BringWindowToTop(hwnd)
                user32.SetForegroundWindow(hwnd)
        else:
            user32.SetForegroundWindow(hwnd)

        time.sleep(0.05)
        focused = int(user32.GetForegroundWindow()) == int(hwnd)
        res = {
            "ok": True,
            "hwnd": int(hwnd),
            "focused": focused,
            "window": self._get_window_info(hwnd),
        }
        self.policy.audit.log_event(
            tool_name="focus_window",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"hwnd": hwnd},
            result_summary={"hwnd": hwnd, "focused": focused},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    # ------------------------------------------------------------------
    # Screenshot (with Sensitive Window Blackout/Rejection & Coordinate Mapping)
    # ------------------------------------------------------------------
    def screenshot(
        self,
        *,
        target: str = "desktop",
        monitor: int = 0,
        hwnd: int | None = None,
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
        max_width: int = 0,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "screenshot",
            {"target": target, "monitor": monitor, "hwnd": hwnd, "x": x, "y": y, "width": width, "height": height},
            session_id=session_id,
            approval_token=approval_token,
        )
        status = self._inspect_desktop_session_status()
        if status["is_locked"] or not status["is_interactive"]:
            raise DesktopSessionLockedError(
                "Cannot capture screenshot: desktop session is locked or non-interactive"
            )

        geom = self._inspect_screen_geometry()
        target_norm = target.lower().strip()
        if target_norm not in ("desktop", "monitor", "window", "active_window", "region"):
            raise ValueError(f"Unsupported screenshot target: {target}")

        if target_norm == "active_window":
            fg = int(user32.GetForegroundWindow())
            if not fg or not user32.IsWindow(fg):
                raise ValueError("No active foreground window found")
            hwnd = fg
            target_norm = "window"

        if target_norm == "window":
            if not hwnd or not user32.IsWindow(hwnd):
                raise ValueError(f"Valid hwnd required for target=window; got {hwnd}")
            win_info = self._get_window_info(hwnd)
            if win_info["sensitive"]:
                raise PermissionError(
                    f"Screenshot blocked: target window '{win_info['title']}' matches sensitive window filter"
                )
            if win_info["width"] <= 0 or win_info["height"] <= 0:
                raise ValueError(f"Window {hwnd} has non-positive bounds")
            cap_left, cap_top = win_info["left"], win_info["top"]
            cap_w, cap_h = win_info["width"], win_info["height"]
        elif target_norm == "region":
            if None in (x, y, width, height):
                raise ValueError("target=region requires x, y, width, height")
            if int(width) <= 0 or int(height) <= 0:
                raise ValueError("width and height must be positive integers")
            cap_left, cap_top = int(x), int(y)
            cap_w, cap_h = int(width), int(height)
        else:
            # desktop or monitor
            monitors = geom["monitors"]
            if monitor == -1:
                cap_left = geom["virtual_left"]
                cap_top = geom["virtual_top"]
                cap_w = geom["virtual_width"]
                cap_h = geom["virtual_height"]
            else:
                if monitor < 0 or monitor >= len(monitors):
                    raise ValueError(f"Monitor index {monitor} out of range (0..{len(monitors) - 1})")
                m_info = monitors[monitor]
                cap_left = m_info["left"]
                cap_top = m_info["top"]
                cap_w = m_info["width"]
                cap_h = m_info["height"]

        bbox = (cap_left, cap_top, cap_left + cap_w, cap_top + cap_h)
        try:
            img = ImageGrab.grab(bbox=bbox, all_screens=True)
        except Exception:
            img = _bitblt_capture_bbox(cap_left, cap_top, cap_w, cap_h)

        # Sensitive window blackout filter on captured region
        redacted_windows: list[str] = []
        all_wins = self._enumerate_windows(include_untitled=False, max_results=200)
        draw: ImageDraw.ImageDraw | None = None
        for w in all_wins:
            if w["sensitive"] and not w["minimized"]:
                ix1 = max(cap_left, w["left"])
                iy1 = max(cap_top, w["top"])
                ix2 = min(cap_left + cap_w, w["right"])
                iy2 = min(cap_top + cap_h, w["bottom"])
                if ix2 > ix1 and iy2 > iy1:
                    if draw is None:
                        draw = ImageDraw.Draw(img)
                    draw.rectangle(
                        [ix1 - cap_left, iy1 - cap_top, ix2 - cap_left, iy2 - cap_top],
                        fill=(0, 0, 0),
                    )
                    redacted_windows.append(w["title"])

        native_w, native_h = img.width, img.height
        if max_width and max_width > 0 and img.width > max_width:
            ratio = max_width / float(img.width)
            img = img.resize((int(max_width), max(1, int(img.height * ratio))), Image.LANCZOS)

        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        png_bytes = buf.getvalue()

        # Enforce payload size limit
        if len(png_bytes) > self.max_screenshot_bytes:
            # Downscale progressively to fit max_screenshot_bytes
            scale = (self.max_screenshot_bytes / float(len(png_bytes))) ** 0.5
            new_w = max(64, int(img.width * scale * 0.9))
            new_h = max(64, int(img.height * scale * 0.9))
            img = img.resize((new_w, new_h), Image.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            png_bytes = buf.getvalue()
            if len(png_bytes) > self.max_screenshot_bytes:
                raise ValueError(
                    f"Screenshot PNG size ({len(png_bytes)} bytes) exceeds limit ({self.max_screenshot_bytes} bytes)"
                )

        b64 = base64.b64encode(png_bytes).decode("ascii")
        sha = hashlib.sha256(png_bytes).hexdigest()

        res = {
            "ok": True,
            "target": target_norm,
            "width": img.width,
            "height": img.height,
            "native_width": native_w,
            "native_height": native_h,
            "dpi": geom["dpi"],
            "scale_factor": geom["scale_factor"],
            "byte_length": len(png_bytes),
            "sha256": sha,
            "coordinate_mapping": {
                "desktop_offset_x": cap_left,
                "desktop_offset_y": cap_top,
                "capture_width": cap_w,
                "capture_height": cap_h,
                "image_width": img.width,
                "image_height": img.height,
                "x_scale_to_desktop": round(cap_w / float(max(1, img.width)), 4),
                "y_scale_to_desktop": round(cap_h / float(max(1, img.height)), 4),
            },
            "redacted_windows": redacted_windows,
            "mime_type": "image/png",
            "data_base64": b64,
            "mcp_content": [
                {
                    "type": "image",
                    "data": b64,
                    "mimeType": "image/png",
                }
            ],
        }
        self.policy.audit.log_event(
            tool_name="screenshot",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"target": target_norm, "monitor": monitor, "hwnd": hwnd, "x": x, "y": y},
            result_summary={
                "width": img.width,
                "height": img.height,
                "byte_length": len(png_bytes),
                "redacted_windows": redacted_windows,
            },
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    # ------------------------------------------------------------------
    # Mouse Automation
    # ------------------------------------------------------------------
    def _validate_screen_coords(self, x: int, y: int) -> tuple[int, int]:
        geom = self._inspect_screen_geometry()
        vx1 = geom["virtual_left"]
        vy1 = geom["virtual_top"]
        vx2 = vx1 + geom["virtual_width"]
        vy2 = vy1 + geom["virtual_height"]
        if not (vx1 <= int(x) < vx2 and vy1 <= int(y) < vy2):
            raise ValueError(
                f"Coordinates ({x}, {y}) are outside virtual desktop bounds "
                f"({vx1}, {vy1})..({vx2 - 1}, {vy2 - 1})"
            )
        return int(x), int(y)

    def _get_cursor_pos(self) -> tuple[int, int]:
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        return int(pt.x), int(pt.y)

    def _send_mouse_flags(self, flags: int, mouse_data: int = 0) -> None:
        inp = INPUT(type=INPUT_MOUSE)
        inp.union.mi = MOUSEINPUT(
            dx=0,
            dy=0,
            mouseData=ctypes.wintypes.DWORD(mouse_data & 0xFFFFFFFF),
            dwFlags=ctypes.wintypes.DWORD(flags),
            time=0,
            dwExtraInfo=0,
        )
        user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

    def mouse_move(
        self,
        x: int,
        y: int,
        *,
        duration_ms: int = 0,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "mouse_move",
            {"x": x, "y": y, "duration_ms": duration_ms},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "mouse_move", {"x": x, "y": y, "duration_ms": duration_ms},
            session_id=session_id, approval_token=approval_token,
        )
        tx, ty = self._validate_screen_coords(x, y)
        if duration_ms > 0:
            sx, sy = self._get_cursor_pos()
            steps = max(2, min(30, duration_ms // 10))
            step_sleep = (duration_ms / 1000.0) / steps
            for i in range(1, steps + 1):
                self.check_emergency_stop()
                ix = int(sx + (tx - sx) * (i / steps))
                iy = int(sy + (ty - sy) * (i / steps))
                user32.SetCursorPos(ix, iy)
                time.sleep(step_sleep)
        else:
            user32.SetCursorPos(tx, ty)

        cx, cy = self._get_cursor_pos()
        res = {"ok": True, "x": cx, "y": cy, "requested_x": tx, "requested_y": ty}
        self.policy.audit.log_event(
            tool_name="mouse_move",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"x": tx, "y": ty},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def mouse_click(
        self,
        x: int | None = None,
        y: int | None = None,
        *,
        button: str = "left",
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "mouse_click",
            {"x": x, "y": y, "button": button},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "mouse_click", {"x": x, "y": y, "button": button},
            session_id=session_id, approval_token=approval_token,
        )
        if x is not None and y is not None:
            tx, ty = self._validate_screen_coords(x, y)
            user32.SetCursorPos(tx, ty)
            time.sleep(0.01)

        btn = button.lower().strip()
        if btn == "left":
            down, up = MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP
        elif btn == "right":
            down, up = MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP
        elif btn == "middle":
            down, up = MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP
        else:
            raise ValueError(f"Unsupported mouse button: {button}")

        self._send_mouse_flags(down)
        time.sleep(0.01)
        self._send_mouse_flags(up)
        cx, cy = self._get_cursor_pos()
        res = {"ok": True, "button": btn, "x": cx, "y": cy}
        self.policy.audit.log_event(
            tool_name="mouse_click",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"x": x, "y": y, "button": btn},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def mouse_double_click(
        self,
        x: int | None = None,
        y: int | None = None,
        *,
        button: str = "left",
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "mouse_double_click",
            {"x": x, "y": y, "button": button},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "mouse_double_click", {"x": x, "y": y, "button": button},
            session_id=session_id, approval_token=approval_token,
        )
        self.mouse_click(x=x, y=y, button=button, session_id=session_id, approval_token=approval_token)
        time.sleep(0.04)
        res = self.mouse_click(x=None, y=None, button=button, session_id=session_id, approval_token=approval_token)
        res["double_click"] = True
        self.policy.audit.log_event(
            tool_name="mouse_double_click",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"x": x, "y": y, "button": button},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def mouse_right_click(
        self,
        x: int | None = None,
        y: int | None = None,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "mouse_right_click",
            {"x": x, "y": y},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "mouse_right_click", {"x": x, "y": y},
            session_id=session_id, approval_token=approval_token,
        )
        res = self.mouse_click(
            x=x, y=y, button="right", session_id=session_id, approval_token=approval_token
        )
        self.policy.audit.log_event(
            tool_name="mouse_right_click",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"x": x, "y": y},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def mouse_scroll(
        self,
        clicks: int,
        *,
        x: int | None = None,
        y: int | None = None,
        horizontal: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "mouse_scroll",
            {"clicks": clicks, "x": x, "y": y, "horizontal": horizontal},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "mouse_scroll", {"clicks": clicks, "x": x, "y": y, "horizontal": horizontal},
            session_id=session_id, approval_token=approval_token,
        )
        if x is not None and y is not None:
            tx, ty = self._validate_screen_coords(x, y)
            user32.SetCursorPos(tx, ty)

        flag = MOUSEEVENTF_HWHEEL if horizontal else MOUSEEVENTF_WHEEL
        delta = int(clicks) * WHEEL_DELTA
        self._send_mouse_flags(flag, mouse_data=delta)
        cx, cy = self._get_cursor_pos()
        res = {"ok": True, "clicks": int(clicks), "horizontal": horizontal, "x": cx, "y": cy}
        self.policy.audit.log_event(
            tool_name="mouse_scroll",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"clicks": clicks, "horizontal": horizontal},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def mouse_drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        *,
        button: str = "left",
        steps: int = 10,
        duration_ms: int = 120,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "mouse_drag",
            {"start_x": start_x, "start_y": start_y, "end_x": end_x, "end_y": end_y, "button": button},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "mouse_drag",
            {"start_x": start_x, "start_y": start_y, "end_x": end_x, "end_y": end_y, "button": button},
            session_id=session_id,
            approval_token=approval_token,
        )
        sx, sy = self._validate_screen_coords(start_x, start_y)
        ex, ey = self._validate_screen_coords(end_x, end_y)
        btn = button.lower().strip()
        down = MOUSEEVENTF_LEFTDOWN if btn == "left" else MOUSEEVENTF_RIGHTDOWN
        up = MOUSEEVENTF_LEFTUP if btn == "left" else MOUSEEVENTF_RIGHTUP

        user32.SetCursorPos(sx, sy)
        time.sleep(0.02)
        self._send_mouse_flags(down)
        try:
            steps = max(2, min(50, int(steps)))
            sleep_s = max(0.005, (duration_ms / 1000.0) / steps)
            for i in range(1, steps + 1):
                self.check_emergency_stop()
                ix = int(sx + (ex - sx) * (i / steps))
                iy = int(sy + (ey - sy) * (i / steps))
                user32.SetCursorPos(ix, iy)
                time.sleep(sleep_s)
        finally:
            self._send_mouse_flags(up)

        cx, cy = self._get_cursor_pos()
        res = {"ok": True, "start": [sx, sy], "end": [cx, cy], "button": btn}
        self.policy.audit.log_event(
            tool_name="mouse_drag",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"start_x": sx, "start_y": sy, "end_x": ex, "end_y": ey},
            result_summary=res,
            session_id=session_id,
        )
        return res

    # ------------------------------------------------------------------
    # Keyboard Automation (Unicode SendInput, Keypress, Hotkey)
    # ------------------------------------------------------------------
    def _send_vk(self, vk: int, up: bool = False) -> None:
        flags = KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED_VKS else 0
        if up:
            flags |= KEYEVENTF_KEYUP
        inp = INPUT(type=INPUT_KEYBOARD)
        inp.union.ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=flags, time=0, dwExtraInfo=0)
        user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

    def _send_unicode_char(self, ch: str) -> None:
        code = ord(ch)
        for flags in (KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP):
            inp = INPUT(type=INPUT_KEYBOARD)
            inp.union.ki = KEYBDINPUT(wVk=0, wScan=code, dwFlags=flags, time=0, dwExtraInfo=0)
            user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

    def keyboard_type(
        self,
        text: str,
        *,
        interval_ms: int = 5,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "keyboard_type",
            {"text_length": len(text)},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "keyboard_type", {"text_length": len(text)},
            session_id=session_id, approval_token=approval_token,
        )
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        delay = max(0, min(200, int(interval_ms))) / 1000.0
        for ch in text:
            self.check_emergency_stop()
            if ch == "\n":
                self._send_vk(_VK_MAP["enter"], up=False)
                self._send_vk(_VK_MAP["enter"], up=True)
            elif ch == "\r":
                continue
            else:
                self._send_unicode_char(ch)
            if delay > 0:
                time.sleep(delay)

        res = {"ok": True, "chars_typed": len(text)}
        self.policy.audit.log_event(
            tool_name="keyboard_type",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"text": redact_secrets(text)},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def keyboard_keypress(
        self,
        key: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "keyboard_keypress",
            {"key": key},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "keyboard_keypress", {"key": key},
            session_id=session_id, approval_token=approval_token,
        )
        k = key.lower().strip()
        if k not in _VK_MAP:
            raise ValueError(f"Unsupported key '{key}'. Allowed keys: {sorted(_VK_MAP)}")
        vk = _VK_MAP[k]
        self._send_vk(vk, up=False)
        time.sleep(0.015)
        self._send_vk(vk, up=True)
        res = {"ok": True, "key": k}
        self.policy.audit.log_event(
            tool_name="keyboard_keypress",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"key": k},
            result_summary=res,
            session_id=session_id,
        )
        return res

    def keyboard_hotkey(
        self,
        keys: list[str],
        *,
        interval_ms: int = 25,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "keyboard_hotkey",
            {"keys": keys, "interval_ms": interval_ms},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "keyboard_hotkey", {"keys": keys, "interval_ms": interval_ms},
            session_id=session_id, approval_token=approval_token,
        )
        if not keys or len(keys) > 5:
            raise ValueError("keys must be a list of 1 to 5 key names")
        norm = [k.lower().strip() for k in keys]
        invalid = [k for k in norm if k not in _VK_MAP]
        if invalid:
            raise ValueError(f"Unsupported hotkey key(s): {invalid}")

        # Block Ctrl+Alt+Del
        if set(norm) == {"ctrl", "alt", "delete"} or set(norm) == {"control", "alt", "del"}:
            raise PermissionError("Ctrl+Alt+Delete Secure Attention Sequence is disallowed")

        delay = max(0, min(300, int(interval_ms))) / 1000.0
        pressed: list[int] = []
        try:
            for k in norm:
                vk = _VK_MAP[k]
                self._send_vk(vk, up=False)
                pressed.append(vk)
                if delay > 0:
                    time.sleep(delay)
        finally:
            for vk in reversed(pressed):
                self._send_vk(vk, up=True)
                if delay > 0:
                    time.sleep(delay)

        res = {"ok": True, "keys": norm}
        self.policy.audit.log_event(
            tool_name="keyboard_hotkey",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"keys": norm},
            result_summary=res,
            session_id=session_id,
        )
        return res

    # ------------------------------------------------------------------
    # Clipboard Control (Pure ctypes Win32 Clipboard)
    # ------------------------------------------------------------------
    def _open_clipboard_with_retry(self, retries: int = 8, delay: float = 0.03) -> None:
        for _ in range(retries):
            if user32.OpenClipboard(None):
                return
            time.sleep(delay)
        raise RuntimeError("Failed to open Windows clipboard (locked by another window)")

    def get_clipboard_text(
        self,
        *,
        max_chars: int = 100_000,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "get_clipboard_text",
            {"max_chars": max_chars},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "get_clipboard_text", {"max_chars": max_chars},
            session_id=session_id, approval_token=approval_token,
        )
        max_chars = max(1, min(1_000_000, int(max_chars)))
        self._open_clipboard_with_retry()
        try:
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                text = ""
                has_text = False
            else:
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if not handle:
                    text = ""
                    has_text = False
                else:
                    ptr = kernel32.GlobalLock(handle)
                    if not ptr:
                        text = ""
                        has_text = False
                    else:
                        try:
                            text = ctypes.wstring_at(ptr)
                            has_text = True
                        finally:
                            kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()

        orig_len = len(text)
        truncated = orig_len > max_chars
        if truncated:
            text = text[:max_chars]

        redacted = redact_secrets(text)
        res = {
            "ok": True,
            "text": redacted,
            "has_text": has_text,
            "char_count": orig_len,
            "truncated": truncated,
        }
        self.policy.audit.log_event(
            tool_name="get_clipboard_text",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"max_chars": max_chars},
            result_summary={"has_text": has_text, "char_count": orig_len},
            session_id=session_id,
        )
        return res

    def set_clipboard_text(
        self,
        text: str,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "set_clipboard_text",
            {"char_count": len(text)},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "set_clipboard_text", {"char_count": len(text)},
            session_id=session_id, approval_token=approval_token,
        )
        if not isinstance(text, str):
            raise ValueError("Clipboard text must be a string")

        encoded = text.encode("utf-16-le") + b"\x00\x00"
        self._open_clipboard_with_retry()
        try:
            user32.EmptyClipboard()
            h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
            if not h_mem:
                raise MemoryError("GlobalAlloc failed for clipboard data")
            ptr = kernel32.GlobalLock(h_mem)
            if not ptr:
                kernel32.GlobalFree(h_mem)
                raise MemoryError("GlobalLock failed for clipboard data")
            try:
                ctypes.memmove(ptr, encoded, len(encoded))
            finally:
                kernel32.GlobalUnlock(h_mem)
            if not user32.SetClipboardData(CF_UNICODETEXT, h_mem):
                kernel32.GlobalFree(h_mem)
                raise RuntimeError("SetClipboardData failed")
        finally:
            user32.CloseClipboard()

        res = {"ok": True, "char_count": len(text)}
        self.policy.audit.log_event(
            tool_name="set_clipboard_text",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"char_count": len(text)},
            result_summary=res,
            session_id=session_id,
        )
        return res

    # ------------------------------------------------------------------
    # Visual Action Verify Workflow (P3.5)
    # ------------------------------------------------------------------
    def visual_action_verify(
        self,
        action: str,
        action_args: dict[str, Any] | None = None,
        *,
        settle_ms: int = 120,
        region: dict[str, int] | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Capture before-state, execute an allowed GUI action, capture after-screenshot,
        and compute visual/window state change verification.
        """
        t0 = time.time()
        self.check_emergency_stop()
        self.policy.authorize_tool(
            "visual_action_verify",
            {"action": action, "action_args": action_args},
            session_id=session_id,
            approval_token=approval_token,
        )
        self._require_interactive_unlocked_desktop(
            "visual_action_verify",
            {"action": action, "action_args": action_args},
            session_id=session_id,
            approval_token=approval_token,
        )
        args = dict(action_args or {})
        allowed_actions = {
            "focus_window": self.focus_window,
            "mouse_move": self.mouse_move,
            "mouse_click": self.mouse_click,
            "mouse_double_click": self.mouse_double_click,
            "mouse_right_click": self.mouse_right_click,
            "mouse_scroll": self.mouse_scroll,
            "mouse_drag": self.mouse_drag,
            "keyboard_type": self.keyboard_type,
            "keyboard_keypress": self.keyboard_keypress,
            "keyboard_hotkey": self.keyboard_hotkey,
            "set_clipboard_text": self.set_clipboard_text,
        }
        if action not in allowed_actions:
            raise ValueError(f"Unsupported GUI action for visual_action_verify: {action}")

        # 1. Capture before state
        before_win = self.get_active_window(
            session_id=session_id, approval_token=approval_token
        ).get("active_window")
        if region:
            before_shot = self.screenshot(
                target="region",
                x=region["x"],
                y=region["y"],
                width=region["width"],
                height=region["height"],
                session_id=session_id,
                approval_token=approval_token,
            )
        else:
            before_shot = self.screenshot(
                target="desktop",
                monitor=0,
                max_width=1280,
                session_id=session_id,
                approval_token=approval_token,
            )

        # 2. Execute action
        action_result = allowed_actions[action](
            **args, session_id=session_id, approval_token=approval_token
        )

        if settle_ms > 0:
            time.sleep(min(2.0, settle_ms / 1000.0))

        # 3. Capture after state
        after_win = self.get_active_window(
            session_id=session_id, approval_token=approval_token
        ).get("active_window")
        if region:
            after_shot = self.screenshot(
                target="region",
                x=region["x"],
                y=region["y"],
                width=region["width"],
                height=region["height"],
                session_id=session_id,
                approval_token=approval_token,
            )
        else:
            after_shot = self.screenshot(
                target="desktop",
                monitor=0,
                max_width=1280,
                session_id=session_id,
                approval_token=approval_token,
            )

        # 4. Compute visual difference
        img_before = Image.open(io.BytesIO(base64.b64decode(before_shot["data_base64"]))).convert("RGB")
        img_after = Image.open(io.BytesIO(base64.b64decode(after_shot["data_base64"]))).convert("RGB")
        if img_before.size != img_after.size:
            img_after = img_after.resize(img_before.size, Image.LANCZOS)
        diff_img = ImageChops.difference(img_before, img_after)
        diff_bbox = diff_img.getbbox()
        visual_changed = before_shot["sha256"] != after_shot["sha256"] and diff_bbox is not None
        active_hwnd_changed = (before_win or {}).get("hwnd") != (after_win or {}).get("hwnd")
        active_title_changed = (before_win or {}).get("title") != (after_win or {}).get("title")

        res = {
            "ok": True,
            "action": action,
            "action_result": action_result,
            "state_changed": bool(visual_changed or active_hwnd_changed or active_title_changed),
            "visual_changed": visual_changed,
            "diff_bbox": list(diff_bbox) if diff_bbox else None,
            "active_hwnd_changed": active_hwnd_changed,
            "active_title_changed": active_title_changed,
            "before_sha256": before_shot["sha256"],
            "after_sha256": after_shot["sha256"],
            "before_active_window": before_win,
            "after_active_window": after_win,
            "after_screenshot": {
                "width": after_shot["width"],
                "height": after_shot["height"],
                "sha256": after_shot["sha256"],
                "data_base64": after_shot["data_base64"],
            },
        }
        self.policy.audit.log_event(
            tool_name="visual_action_verify",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            arguments={"action": action, "action_args": args},
            result_summary={
                "state_changed": res["state_changed"],
                "visual_changed": visual_changed,
                "active_hwnd_changed": active_hwnd_changed,
            },
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res
