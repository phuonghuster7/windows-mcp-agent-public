"""Local-First DPAPI Password Setup & Rotation for Windows MCP Owner Console (Port 8767).

Allows the owner to enter a new console password directly on Windows (masked input).
Encrypts the password using Windows DPAPI (CurrentUser scope) and stores it in:
  runtime/secrets/console_owner_secret.dpapi
Then restarts ONLY Owner Web Console (Port 8767) and verifies successful login.
Never logs, prints, or exposes the secret.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
SECRETS_DIR = PROJECT_ROOT / "runtime" / "secrets"
DPAPI_FILE = SECRETS_DIR / "console_owner_secret.dpapi"

for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "runtime"), str(PROJECT_ROOT / "mcp-gateway")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import win32crypt
except ImportError:
    print("Error: pywin32 / win32crypt is required for DPAPI encryption.", file=sys.stderr)
    sys.exit(1)


def save_dpapi_secret(plain_password: str) -> None:
    """Seal password into runtime/secrets/console_owner_secret.dpapi using CurrentUser DPAPI."""
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    cipher_bytes = win32crypt.CryptProtectData(
        plain_password.encode("utf-8"),
        "mcp_console_owner",
        None,
        None,
        None,
        0,
    )
    b64_str = base64.b64encode(cipher_bytes).decode("ascii")
    DPAPI_FILE.write_text(b64_str, encoding="utf-8")


def restart_owner_web_console() -> int | None:
    """Restart ONLY port 8767 (web_console.py), preserving all other processes and tunnels."""
    from watchdog import (
        query_windows_processes,
        safe_terminate_pids,
        start_owner_web_console_process,
        setup_logger,
    )
    logger = setup_logger()
    procs = query_windows_processes()
    console_pids = [p.pid for p in procs if "web_console.py" in p.command_line]
    if console_pids:
        safe_terminate_pids(console_pids, "owner_web_console", logger, procs)
        time.sleep(1.0)
    ok, err = start_owner_web_console_process(logger)
    if not ok:
        print(f"Warning: Failed to restart Owner Web Console: {err}", file=sys.stderr)
        return None
    # Find new PID
    procs_after = query_windows_processes()
    new_pids = [p.pid for p in procs_after if "web_console.py" in p.command_line]
    return new_pids[0] if new_pids else None


def verify_login(plain_password: str) -> bool:
    """Verify login against http://127.0.0.1:8767/console/api/login without logging credentials."""
    login_url = "http://127.0.0.1:8767/console/api/login"
    payload = json.dumps({"password": plain_password}).encode("utf-8")
    req = urllib.request.Request(
        login_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Host": "127.0.0.1:8767",
            "Origin": "http://127.0.0.1:8767",
        },
    )
    for _ in range(10):
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return bool(data.get("authenticated"))
        except (urllib.error.HTTPError, urllib.error.URLError):
            time.sleep(1.0)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Set Owner Console Password via DPAPI")
    parser.add_argument("--password", help="Password string (omit to prompt interactively)")
    parser.add_argument("--no-restart", action="store_true", help="Do not restart port 8767")
    args = parser.parse_args()

    if args.password:
        pwd = args.password
    else:
        print("=== THIET LAP MAT KHAU OWNER CONSOLE 8767 (DPAPI) ===")
        pwd = getpass.getpass("Nhap mat khau moi (khong hien tren man hinh): ")
        if not pwd or not pwd.strip():
            print("Mat khau khong duoc de trong.", file=sys.stderr)
            return 1
        confirm = getpass.getpass("Xac nhan lai mat khau: ")
        if pwd != confirm:
            print("Mat khau xac nhan khong khop.", file=sys.stderr)
            return 1

    save_dpapi_secret(pwd)
    print(f"Da ma hoa DPAPI va luu tai: {DPAPI_FILE}")

    if not args.no_restart:
        print("Dang khoi dong lai Owner Web Console (Port 8767)...")
        new_pid = restart_owner_web_console()
        if new_pid:
            print(f"Owner Web Console da khoi dong thanh cong voi PID: {new_pid}")
        else:
            print("Khong tim thay PID moi cua Owner Web Console.", file=sys.stderr)
            return 1

        print("Dang xac minh dang nhap...")
        ok = verify_login(pwd)
        if ok:
            print("XAC MINH DANG NHAP THANH CONG (HTTP 200 - authenticated: true)!")
        else:
            print("Xac minh dang nhap that bai.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
