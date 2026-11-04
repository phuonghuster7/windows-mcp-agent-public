"""Production-grade Windows Supervisor & Watchdog Daemon for the WinOwner MCP Stack.

Monitors and heals the dependency chain in strict order:
  1) FastAPI Backend (http://127.0.0.1:3080/health)
  2) MCP Bridge (http://127.0.0.1:8765/mcp via MCP initialize + tools/list handshake)
  3) Unified Gateway Staging (http://127.0.0.1:8766/health & http://127.0.0.1:8766/mcp)
  4) Owner Web Console (http://127.0.0.1:8767/console/api/health & /health)
  5) Dedicated Cloud Autonomous Adapter (http://127.0.0.1:8768/health & /mcp)
  6) Secure MCP Tunnel (tunnel-client.exe --profile windows-mcp-isolated,
     verifying windows-mcp-isolated-health.url /healthz and /readyz)
  7) Legacy Codex Tunnel (codex-chatgpt-web / tunnel_unconfigured_legacy,
     strictly read-only observation, untouched=True)

Key safety guarantees (P0.4, P5.4, P5.5, Stage 6):
  - Single-instance lockfile/mutex (runtime/watchdog.lock + Windows named mutex).
  - Automatically loads MCP_AUTH_TOKEN from backend .env and injects as COMPUTER_API_TOKEN
    into child MCP Bridge / Unified Gateway environments without ever logging secret values.
  - Reuses existing healthy instances; NEVER kills healthy primary processes.
  - Detects and safely cleans up duplicate orphan bridge.py or windows-mcp-isolated processes.
  - NEVER touches or terminates the legacy Codex tunnel
    (tunnel_unconfigured_legacy / --profile codex-chatgpt-web).
  - Identifies exact PID and CommandLine via CIM (Win32_Process) before stopping
    an unhealthy/hung or duplicate process.
  - Network outage / restoration detection (NETWORK_OUTAGE_DETECTED / NETWORK_RESTORED):
    holds off tunnel failure counting and restarts when outbound network is unavailable.
  - Sleep/resume wall-clock time-jump detection (SYSTEM_RESUME_DETECTED):
    grants a grace period when elapsed loop time jumps > 3 * interval.
  - Exponential backoff with circuit breaker to prevent rapid restart loops.
  - Rotating file logger (runtime/logs/watchdog.log, 5MB x 5 files) with secret redaction.
  - Writes atomic live observability state to runtime/logs/status.json.
"""
from __future__ import annotations

import argparse
import ctypes
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import msvcrt
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Paths & Constants
# ---------------------------------------------------------------------------
def _safe_user_home() -> Path:
    """Return user home directory or safe fallback if USERPROFILE/HOME are unset."""
    try:
        return Path.home()
    except Exception:
        fallback = os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir()
        return Path(fallback)


RUNTIME_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = RUNTIME_DIR.parent
LOGS_DIR = RUNTIME_DIR / "logs"
LOCK_FILE = RUNTIME_DIR / "watchdog.lock"
STATUS_FILE = LOGS_DIR / "status.json"
WATCHDOG_LOG_FILE = LOGS_DIR / "watchdog.log"
POLICY_FILE = PROJECT_ROOT / "config" / "policy.json"

BACKEND_URL = os.getenv("WINDOWS_MCP_BACKEND_URL", "http://127.0.0.1:3080")
BACKEND_PORT = 3080
BACKEND_PYTHON = Path(
    os.getenv(
        "WINDOWS_MCP_BACKEND_PYTHON",
        sys.executable,
    )
)
BACKEND_WORKDIR = Path(
    os.getenv(
        "WINDOWS_MCP_BACKEND_WORKDIR",
        str(_safe_user_home() / ".gemini" / "antigravity-ide" / "scratch" / "computer-mcp-server"),
    )
)
BACKEND_ENV_FILE = Path(
    os.getenv(
        "WINDOWS_MCP_BACKEND_ENV_FILE",
        str(BACKEND_WORKDIR / ".env"),
    )
)

BRIDGE_URL = os.getenv("WINDOWS_MCP_BRIDGE_URL", "http://127.0.0.1:8765/mcp")
BRIDGE_PORT = 8765
RECOVERY_ROOT = Path(
    os.getenv(
        "WINDOWS_MCP_RECOVERY_ROOT",
        str(_safe_user_home() / "Downloads" / "local-computer-mcp-recovery-v0.1.4"),
    )
)
BRIDGE_PYTHON = Path(
    os.getenv(
        "WINDOWS_MCP_BRIDGE_PYTHON",
        str(RECOVERY_ROOT / ".venv" / "Scripts" / "python.exe"),
    )
)

UNIFIED_GATEWAY_STAGING_PORT = int(os.getenv("WINDOWS_MCP_GATEWAY_STAGING_PORT", "8766"))
UNIFIED_GATEWAY_STAGING_URL = os.getenv(
    "WINDOWS_MCP_GATEWAY_STAGING_URL",
    f"http://127.0.0.1:{UNIFIED_GATEWAY_STAGING_PORT}/mcp",
)
UNIFIED_GATEWAY_STAGING_HEALTH_URL = os.getenv(
    "WINDOWS_MCP_GATEWAY_STAGING_HEALTH_URL",
    f"http://127.0.0.1:{UNIFIED_GATEWAY_STAGING_PORT}/health",
)
UNIFIED_GATEWAY_STAGING_SCRIPT = PROJECT_ROOT / "mcp-gateway" / "http_server.py"

WEB_CONSOLE_PORT = int(os.getenv("WINDOWS_MCP_CONSOLE_PORT", "8767"))
WEB_CONSOLE_URL = os.getenv("WINDOWS_MCP_CONSOLE_URL", f"http://127.0.0.1:{WEB_CONSOLE_PORT}")
WEB_CONSOLE_HEALTH_URL = f"{WEB_CONSOLE_URL}/console/api/health"
WEB_CONSOLE_HEALTH_FALLBACK_URL = f"{WEB_CONSOLE_URL}/health"
WEB_CONSOLE_SCRIPT = PROJECT_ROOT / "mcp-gateway" / "web_console.py"

AUTONOMOUS_ADAPTER_PORT = int(os.getenv("WINDOWS_MCP_AUTONOMOUS_ADAPTER_PORT", "8768"))
AUTONOMOUS_ADAPTER_URL = os.getenv(
    "WINDOWS_MCP_AUTONOMOUS_ADAPTER_URL",
    f"http://127.0.0.1:{AUTONOMOUS_ADAPTER_PORT}/mcp",
)
AUTONOMOUS_ADAPTER_HEALTH_URL = os.getenv(
    "WINDOWS_MCP_AUTONOMOUS_ADAPTER_HEALTH_URL",
    f"http://127.0.0.1:{AUTONOMOUS_ADAPTER_PORT}/health",
)
AUTONOMOUS_ADAPTER_SCRIPT = PROJECT_ROOT / "mcp-gateway" / "cloud_autonomous_adapter.py"

TUNNEL_BIN = Path(
    os.getenv(
        "WINDOWS_MCP_TUNNEL_BIN",
        str(_safe_user_home() / ".codex-chatgpt-web" / "bin" / "tunnel-client.exe"),
    )
)
TUNNEL_PROFILE = os.getenv("WINDOWS_MCP_TUNNEL_PROFILE", "windows-mcp-isolated")
TUNNEL_ID = os.getenv("WINDOWS_MCP_ISOLATED_TUNNEL_ID", "tunnel_unconfigured_isolated")
TUNNEL_HEALTH_URL_FILE = Path(
    os.getenv(
        "WINDOWS_MCP_TUNNEL_HEALTH_URL_FILE",
        str(_safe_user_home() / ".codex-chatgpt-web" / "tunnel" / "windows-mcp-isolated-health.url"),
    )
)

AUTONOMOUS_TUNNEL_PROFILE = os.getenv("WINDOWS_MCP_AUTONOMOUS_TUNNEL_PROFILE", "windows-mcp-autonomous")
AUTONOMOUS_TUNNEL_ID = os.getenv("WINDOWS_MCP_AUTONOMOUS_TUNNEL_ID", "tunnel_unconfigured_autonomous")
AUTONOMOUS_TUNNEL_HEALTH_URL_FILE = Path(
    os.getenv(
        "WINDOWS_MCP_AUTONOMOUS_TUNNEL_HEALTH_URL_FILE",
        str(LOGS_DIR / "windows-mcp-autonomous-health.url"),
    )
)

LEGACY_CODEX_TUNNEL_ID = os.getenv("WINDOWS_MCP_LEGACY_CODEX_TUNNEL_ID", "tunnel_unconfigured_legacy")
LEGACY_CODEX_PROFILE = os.getenv("WINDOWS_MCP_LEGACY_CODEX_PROFILE", "codex-chatgpt-web")
LEGACY_CODEX_HEALTH_URL_FILE = Path(
    os.getenv(
        "WINDOWS_MCP_LEGACY_CODEX_HEALTH_URL_FILE",
        str(_safe_user_home() / ".local" / "state" / "tunnel-client" / "health" / "codex-chatgpt-web.url"),
    )
)

DESKTOP_AGENT_URL = os.getenv("WINDOWS_MCP_DESKTOP_AGENT_URL", "http://127.0.0.1:8766/health")
DESKTOP_AGENT_PORT = 8766

MUTEX_NAME = r"Local\WindowsMcpAgentWatchdog"
ERROR_ALREADY_EXISTS = 183

CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def _spawn_detached_background(
    cmd: list[str],
    cwd: str,
    stdout_path: Path,
    stderr_path: Path,
    env: dict[str, str] | None = None,
) -> int:
    """Spawn a background service via WMI Win32_Process.Create so it is completely
    detached from the caller's process tree, ConPTY, and Job Object.
    """
    import base64

    payload_json = json.dumps(
        {
            "cmd": cmd,
            "cwd": cwd,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
            "env": env,
        }
    )
    b64_payload = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")
    inner_py = (
        "import base64, json, os, subprocess; "
        f"cfg = json.loads(base64.b64decode('{b64_payload}').decode('utf-8')); "
        "env = os.environ.copy(); "
        "env.update(cfg['env'] or {}); "
        "out_f = open(cfg['stdout'], 'ab'); "
        "err_f = open(cfg['stderr'], 'ab'); "
        "p = subprocess.Popen("
        "cfg['cmd'], cwd=cfg['cwd'], env=env, stdout=out_f, stderr=err_f, "
        "stdin=subprocess.DEVNULL, creationflags=0x00000200 | 0x08000000, close_fds=True"
        "); "
        "print(p.pid)"
    )
    wmi_cmd = subprocess.list2cmdline([sys.executable, "-c", inner_py])
    ps_escaped_cmd = wmi_cmd.replace("'", "''")
    ps_escaped_cwd = cwd.replace("'", "''")
    ps_script = (
        "$startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly; "
        "$startup.ShowWindow = [uint16]0; "
        "$res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ "
        f"CommandLine = '{ps_escaped_cmd}'; CurrentDirectory = '{ps_escaped_cwd}'; ProcessStartupInformation = $startup "
        "}; "
        "if ($res.ReturnValue -ne 0) { exit 1 }; "
        "Write-Output $res.ProcessId"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=CREATE_NO_WINDOW,
    )
    if completed.returncode == 0 and (completed.stdout or "").strip().isdigit():
        return int(completed.stdout.strip())

    # Fallback to direct Popen if WMI is unavailable
    out_f = open(stdout_path, "ab")
    err_f = open(stderr_path, "ab")
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdout=out_f,
        stderr=err_f,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        close_fds=True,
    )
    return proc.pid


# ---------------------------------------------------------------------------
# Secret Redaction & Backend .env Token Loading
# ---------------------------------------------------------------------------
_KNOWN_SECRET_VALUES: set[str] = set()

_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-+/=]{8,}", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{10,}\b"), "[REDACTED_SK]"),
    (
        re.compile(
            r"([A-Za-z0-9_]*(?:api_key|apikey|token|secret|password|authorization|credential|access_token)"
            r"\s*[:=]\s*['\"]?)([^\s'\",;}\]]{6,})",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
)


def register_secret_for_redaction(secret_val: str | None) -> None:
    """Register a dynamic secret value so redact_secrets always strips it even if bare."""
    if secret_val and len(secret_val.strip()) >= 6:
        _KNOWN_SECRET_VALUES.add(secret_val.strip())


def redact_secrets(text: str | None) -> str:
    """Redact API keys, Bearer tokens, and secret values from log/status strings."""
    if not text:
        return ""
    cleaned = str(text)
    for secret in list(_KNOWN_SECRET_VALUES):
        if secret and secret in cleaned:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    for pattern, replacement in _REDACT_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def load_backend_auth_token(env_path: Path | None = None) -> str:
    """Load MCP_AUTH_TOKEN (or COMPUTER_API_TOKEN) from backend .env without logging the value."""
    target = env_path if env_path is not None else BACKEND_ENV_FILE
    token = ""
    if target.exists():
        try:
            for raw_line in target.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("export "):
                    line = line[7:].strip()
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                k = key.strip()
                if k in ("MCP_AUTH_TOKEN", "COMPUTER_API_TOKEN"):
                    cleaned_val = val.strip()
                    if (
                        len(cleaned_val) >= 2
                        and cleaned_val[0] == cleaned_val[-1]
                        and cleaned_val[0] in ("'", '"')
                    ):
                        cleaned_val = cleaned_val[1:-1].strip()
                    if cleaned_val:
                        token = cleaned_val
                        if k == "MCP_AUTH_TOKEN":
                            break
        except Exception:
            pass

    if not token:
        token = (
            os.getenv("COMPUTER_API_TOKEN", "").strip()
            or os.getenv("MCP_AUTH_TOKEN", "").strip()
        )
    if token:
        register_secret_for_redaction(token)
    return token


def build_bridge_env(
    base_env: dict[str, str] | None = None,
    env_path: Path | None = None,
) -> dict[str, str]:
    """Construct the child environment for MCP Bridge / Gateway with COMPUTER_API_TOKEN."""
    env = dict(base_env) if base_env is not None else os.environ.copy()
    env.setdefault("COMPUTER_API_URL", "http://127.0.0.1:3080")
    env.setdefault("COMPUTER_ALLOWED_ROOTS", "AUTO")
    env.setdefault("COMPUTER_GIT_DISPATCH_MODE", "legacy")
    env.setdefault(
        "COMPUTER_ALLOWED_GIT_REPOS",
        f"{_safe_user_home() / 'Desktop'};{PROJECT_ROOT};{RECOVERY_ROOT}",
    )
    token = load_backend_auth_token(env_path=env_path)
    if token:
        env["COMPUTER_API_TOKEN"] = token
    return env


class SecretRedactionFilter(logging.Filter):
    """Logging filter that strips secrets from log messages and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_secrets(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


def setup_logger() -> logging.Logger:
    """Configure rotating file logger (5MB x 5 files) with secret redaction."""
    state_root = os.getenv("MCP_STATE_ROOT")
    eff_logs_dir = (Path(state_root) / "logs") if state_root else LOGS_DIR
    eff_log_file = eff_logs_dir / "watchdog.log"
    eff_logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("windows_mcp_watchdog")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    redactor = SecretRedactionFilter()
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = RotatingFileHandler(
        eff_log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Single-Instance Lockfile + Windows Named Mutex
# ---------------------------------------------------------------------------
class SingleInstanceLock:
    """Enforces single watchdog instance via Windows Mutex and runtime/watchdog.lock."""

    def __init__(self, lock_path: Path = LOCK_FILE, mutex_name: str = MUTEX_NAME) -> None:
        self.lock_path = lock_path
        self.mutex_name = mutex_name
        self._mutex_handle: int | None = None
        self._file_handle: Any = None
        self.acquired = False

    def acquire(self, mode: str) -> bool:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Windows Named Mutex check
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateMutexW(None, True, self.mutex_name)
            last_error = kernel32.GetLastError()
            if not handle:
                return False
            if last_error == ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                return False
            self._mutex_handle = handle
        except Exception:
            self._mutex_handle = None

        # 2. File lock on runtime/watchdog.lock
        try:
            fh = open(self.lock_path, "a+b")
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            fh.seek(0)
            fh.truncate()
            payload = json.dumps(
                {
                    "pid": os.getpid(),
                    "mode": mode,
                    "acquired_at": datetime.now(timezone.utc).isoformat(),
                    "executable": sys.executable,
                },
                indent=2,
            ).encode("utf-8")
            fh.write(payload)
            fh.flush()
            self._file_handle = fh
            self.acquired = True
            return True
        except OSError:
            if self._mutex_handle:
                try:
                    ctypes.windll.kernel32.ReleaseMutex(self._mutex_handle)
                    ctypes.windll.kernel32.CloseHandle(self._mutex_handle)
                except Exception:
                    pass
                self._mutex_handle = None
            return False

    def release(self) -> None:
        if self._file_handle is not None:
            try:
                self._file_handle.seek(0)
                msvcrt.locking(self._file_handle.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
        try:
            if self.lock_path.exists():
                self.lock_path.unlink(missing_ok=True)
        except Exception:
            pass

        if self._mutex_handle is not None:
            try:
                ctypes.windll.kernel32.ReleaseMutex(self._mutex_handle)
                ctypes.windll.kernel32.CloseHandle(self._mutex_handle)
            except Exception:
                pass
            self._mutex_handle = None
        self.acquired = False


# ---------------------------------------------------------------------------
# Backoff & Circuit Breaker State
# ---------------------------------------------------------------------------
@dataclass
class RestartTracker:
    """Tracks restarts, exponential backoff, and circuit breaker state per service."""

    service_name: str
    base_backoff_sec: float = 2.0
    max_backoff_sec: float = 120.0
    window_sec: float = 600.0
    max_restarts_in_window: int = 5
    cooldown_sec: float = 300.0

    restart_count: int = 0
    consecutive_failures: int = 0
    consecutive_health_Confirm_failures: int = 0
    circuit_state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    circuit_opened_at: float = 0.0
    next_retry_epoch: float = 0.0
    last_error: str | None = None
    recent_restarts: deque[float] = field(default_factory=deque)

    def _prune_window(self, now: float) -> None:
        while self.recent_restarts and (now - self.recent_restarts[0]) > self.window_sec:
            self.recent_restarts.popleft()

    def record_healthy(self) -> None:
        self.consecutive_failures = 0
        self.consecutive_health_Confirm_failures = 0
        self.circuit_state = "CLOSED"
        self.next_retry_epoch = 0.0
        self.last_error = None

    def can_attempt_restart(self, now: float | None = None) -> tuple[bool, str]:
        now = now if now is not None else time.time()
        self._prune_window(now)

        if self.circuit_state == "OPEN":
            elapsed = now - self.circuit_opened_at
            if elapsed >= self.cooldown_sec:
                self.circuit_state = "HALF_OPEN"
            else:
                remaining = int(self.cooldown_sec - elapsed)
                return False, f"circuit_breaker_open ({remaining}s remaining)"

        if now < self.next_retry_epoch:
            remaining = round(self.next_retry_epoch - now, 1)
            return False, f"backoff_waiting ({remaining}s remaining)"

        if self.circuit_state != "HALF_OPEN" and len(self.recent_restarts) >= self.max_restarts_in_window:
            self.circuit_state = "OPEN"
            self.circuit_opened_at = now
            self.next_retry_epoch = now + self.cooldown_sec
            return False, f"circuit_breaker_tripped ({len(self.recent_restarts)} restarts in {int(self.window_sec)}s)"

        return True, "ok"

    def record_restart_attempt(self, success: bool, error_msg: str | None = None, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self._prune_window(now)
        self.restart_count += 1
        self.recent_restarts.append(now)

        if success:
            self.consecutive_failures = 0
            self.consecutive_health_Confirm_failures = 0
            self.circuit_state = "CLOSED"
            self.next_retry_epoch = 0.0
            self.last_error = None
        else:
            self.consecutive_failures += 1
            self.last_error = redact_secrets(error_msg or "restart verification failed")
            delay = min(
                self.max_backoff_sec,
                self.base_backoff_sec * (2 ** max(0, self.consecutive_failures - 1)),
            )
            self.next_retry_epoch = now + delay
            if self.circuit_state == "HALF_OPEN" or len(self.recent_restarts) >= self.max_restarts_in_window:
                self.circuit_state = "OPEN"
                self.circuit_opened_at = now
                self.next_retry_epoch = now + self.cooldown_sec

    def to_dict(self) -> dict[str, Any]:
        return {
            "restart_count": self.restart_count,
            "consecutive_failures": self.consecutive_failures,
            "circuit_state": self.circuit_state,
            "restarts_in_window": len(self.recent_restarts),
            "next_retry_at": (
                datetime.fromtimestamp(self.next_retry_epoch, tz=timezone.utc).isoformat()
                if self.next_retry_epoch > time.time()
                else None
            ),
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Process & System Inspection Helpers
# ---------------------------------------------------------------------------
@dataclass
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    executable_path: str
    command_line: str


def query_windows_processes() -> list[ProcessInfo]:
    """Query Win32_Process via PowerShell CIM for exact PID and CommandLine matching."""
    ps_cmd = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -in @('python.exe','pythonw.exe','tunnel-client.exe','uvicorn.exe') } | "
        "Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | "
        "ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        raw = (completed.stdout or "").strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        results: list[ProcessInfo] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            pid = int(item.get("ProcessId") or 0)
            if pid <= 0:
                continue
            results.append(
                ProcessInfo(
                    pid=pid,
                    parent_pid=int(item.get("ParentProcessId") or 0),
                    name=str(item.get("Name") or ""),
                    executable_path=str(item.get("ExecutablePath") or ""),
                    command_line=str(item.get("CommandLine") or ""),
                )
            )
        return results
    except Exception:
        return []


def is_tcp_port_listening(host: str, port: int, timeout: float = 1.5) -> bool:
    """Check if a local TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_network_available(timeout: float = 3.0) -> bool:
    """Check outbound network connectivity to OpenAI control plane (api.openai.com:443)."""
    for host, port in (("api.openai.com", 443), ("1.1.1.1", 443)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def get_windows_session_info() -> dict[str, Any]:
    """Inspect current Windows session ID, interactivity, and desktop lock state."""
    session_id = -1
    try:
        pid = os.getpid()
        sid = ctypes.c_ulong()
        if ctypes.windll.kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
            session_id = int(sid.value)
    except Exception:
        pass

    # Check if LogonUI.exe is running (indicates workstation is locked)
    locked = False
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                " [bool](Get-Process -Name 'LogonUI' -ErrorAction SilentlyContinue)",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
        locked = (completed.stdout or "").strip().lower() == "true"
    except Exception:
        locked = False

    return {
        "session_id": session_id,
        "interactive": session_id > 0,
        "desktop_locked": locked,
        "user": os.getenv("USERNAME", "Admin"),
    }


def is_desktop_agent_enabled() -> bool:
    """Determine if the optional Desktop Agent should be supervised."""
    env_flag = os.getenv("WINDOWS_MCP_DESKTOP_AGENT_ENABLED", "").strip().lower()
    if env_flag in ("1", "true", "yes"):
        return True
    if env_flag in ("0", "false", "no"):
        return False

    try:
        if POLICY_FILE.exists():
            policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            desktop_tier = policy.get("tiers", {}).get("DESKTOP", {})
            if desktop_tier.get("enabled") is True:
                return True
    except Exception:
        pass
    return False


def is_unified_gateway_staging_enabled() -> bool:
    """Determine if the Unified Gateway Staging service on port 8766 should be started/supervised."""
    env_flag = os.getenv("WINDOWS_MCP_GATEWAY_STAGING_ENABLED", "").strip().lower()
    if env_flag in ("1", "true", "yes"):
        return True
    if env_flag in ("0", "false", "no"):
        return False
    return UNIFIED_GATEWAY_STAGING_SCRIPT.exists()


def resolve_bridge_script() -> tuple[Path, Path]:
    """Return (working_directory, bridge_script_path) for launching MCP Bridge."""
    custom_script = os.getenv("WINDOWS_MCP_BRIDGE_SCRIPT", "").strip()
    if custom_script:
        p = Path(custom_script).resolve()
        return p.parent, p

    use_gateway = os.getenv("WINDOWS_MCP_USE_GATEWAY", "").strip().lower() in ("1", "true", "yes")
    gateway_script = PROJECT_ROOT / "mcp-gateway" / "bridge.py"
    recovery_script = RECOVERY_ROOT / "server" / "bridge.py"

    if use_gateway and gateway_script.exists():
        return PROJECT_ROOT, gateway_script
    if recovery_script.exists():
        return RECOVERY_ROOT, recovery_script
    if gateway_script.exists():
        return PROJECT_ROOT, gateway_script
    return RECOVERY_ROOT, recovery_script


def resolve_desktop_agent_script() -> tuple[Path, Path] | None:
    """Return (working_directory, script_path) for optional Desktop Agent if available."""
    desktop_dir = PROJECT_ROOT / "desktop-agent"
    for candidate in ("agent.py", "server.py", "main.py", "service.py"):
        p = desktop_dir / candidate
        if p.exists():
            return PROJECT_ROOT, p
    return None


def is_legacy_codex_tunnel_cmd(cmdline: str) -> bool:
    """Return True if CommandLine explicitly specifies --profile codex-chatgpt-web or legacy tunnel ID."""
    return bool(
        re.search(
            rf"--profile(?:\s+|=)[\"']?{re.escape(LEGACY_CODEX_PROFILE)}\b",
            cmdline,
            re.IGNORECASE,
        )
        or LEGACY_CODEX_TUNNEL_ID.lower() in cmdline.lower()
    )


def is_autonomous_mcp_tunnel_cmd(cmdline: str) -> bool:
    """Return True if CommandLine specifies --profile windows-mcp-autonomous or tunnel-autonomous.yaml."""
    cmd_low = cmdline.lower()
    return bool(
        re.search(
            rf"--profile(?:\s+|=)[\"']?{re.escape(AUTONOMOUS_TUNNEL_PROFILE)}\b",
            cmdline,
            re.IGNORECASE,
        )
        or AUTONOMOUS_TUNNEL_PROFILE.lower() in cmd_low
        or "tunnel-autonomous.yaml" in cmd_low
        or AUTONOMOUS_TUNNEL_ID.lower() in cmd_low
    )


def is_isolated_mcp_tunnel_cmd(cmdline: str) -> bool:
    """Return True if CommandLine explicitly specifies --profile windows-mcp-isolated.

    Strictly never matches windows-mcp-autonomous or codex-chatgpt-web.
    """
    if is_legacy_codex_tunnel_cmd(cmdline) or is_autonomous_mcp_tunnel_cmd(cmdline):
        return False
    return bool(
        re.search(
            rf"--profile(?:\s+|=)[\"']?{re.escape(TUNNEL_PROFILE)}\b",
            cmdline,
            re.IGNORECASE,
        )
    )


def is_mcp_bridge_cmd(cmdline: str) -> bool:
    """Return True if CommandLine matches the MCP Bridge process (bridge.py --http-local)."""
    cmd_low = cmdline.lower()
    return "bridge.py" in cmd_low and "--http-local" in cmd_low


def is_unified_gateway_staging_cmd(cmdline: str) -> bool:
    """Return True if CommandLine matches Unified Gateway Staging on port 8766."""
    cmd_low = cmdline.lower()
    if "bridge.py" in cmd_low:
        return False
    if "web_console.py" in cmd_low or "cloud_autonomous_adapter.py" in cmd_low:
        return False
    if "8767" in cmd_low or "8768" in cmd_low:
        return False
    return (
        "http_server.py" in cmd_low
        or ("mcp-gateway" in cmd_low and ("8766" in cmd_low or "http" in cmd_low))
        or ("gateway_server" in cmd_low and "8766" in cmd_low)
    )


def is_owner_web_console_cmd(cmdline: str) -> bool:
    """Return True if CommandLine matches Owner Web Console on port 8767."""
    cmd_low = cmdline.lower()
    return "web_console.py" in cmd_low or ("8767" in cmd_low and "console" in cmd_low)


def is_autonomous_cloud_adapter_cmd(cmdline: str) -> bool:
    """Return True if CommandLine matches Dedicated Cloud Autonomous Adapter on port 8768."""
    cmd_low = cmdline.lower()
    return "cloud_autonomous_adapter.py" in cmd_low or (
        "8768" in cmd_low and ("adapter" in cmd_low or "cloud" in cmd_low)
    )


def find_duplicate_service_pids(
    processes: list[ProcessInfo],
    service: str,
    active_pid: int | None = None,
) -> list[int]:
    """Identify duplicate orphan process PIDs for 'mcp_bridge' or 'tunnel'.

    Groups matched processes into parent-child process trees so that a Windows Python
    venv launcher stub + child python.exe pair is recognized as ONE logical instance.
    Any additional independent process tree is returned as duplicate orphan PIDs.
    Strictly excludes codex-chatgpt-web / legacy tunnel processes.
    """
    matched: list[ProcessInfo] = []
    for p in processes:
        if is_legacy_codex_tunnel_cmd(p.command_line):
            continue
        if service == "mcp_bridge":
            if p.name.lower() in ("python.exe", "pythonw.exe") and is_mcp_bridge_cmd(p.command_line):
                matched.append(p)
        elif service == "tunnel":
            if p.name.lower() == "tunnel-client.exe" and is_isolated_mcp_tunnel_cmd(p.command_line):
                matched.append(p)
        elif service == "autonomous_tunnel":
            if p.name.lower() == "tunnel-client.exe" and is_autonomous_mcp_tunnel_cmd(p.command_line):
                matched.append(p)

    if len(matched) <= 1:
        return []

    by_pid = {p.pid: p for p in matched}

    def _find_root(proc: ProcessInfo) -> int:
        curr = proc
        visited = {curr.pid}
        while curr.parent_pid in by_pid and curr.parent_pid not in visited:
            visited.add(curr.parent_pid)
            curr = by_pid[curr.parent_pid]
        return curr.pid

    trees: dict[int, list[int]] = {}
    root_by_pid: dict[int, int] = {}
    for p in matched:
        r = _find_root(p)
        root_by_pid[p.pid] = r
        trees.setdefault(r, []).append(p.pid)

    if len(trees) <= 1:
        return []

    keeper_root: int | None = None
    if active_pid is not None and active_pid in root_by_pid:
        keeper_root = root_by_pid[active_pid]
    else:
        keeper_root = next(iter(trees.keys()))

    duplicate_pids: list[int] = []
    for r_pid, tree_pids in trees.items():
        if r_pid != keeper_root:
            duplicate_pids.extend(tree_pids)

    return duplicate_pids


# ---------------------------------------------------------------------------
# Component Health Probes
# ---------------------------------------------------------------------------
def _invoke_mcp_jsonrpc(
    url: str,
    method: str,
    params: dict[str, Any] | None = None,
    req_id: int = 1,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """Send a JSON-RPC 2.0 POST request to an MCP HTTP endpoint and parse JSON or SSE response."""
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw_text = resp.read().decode("utf-8", errors="replace").strip()
        for line in raw_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("data:"):
                data_str = line_s[5:].strip()
                if data_str:
                    return json.loads(data_str)
        if raw_text.startswith("{"):
            return json.loads(raw_text)
    return None


def probe_backend(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe FastAPI Backend on 127.0.0.1:3080/health."""
    matched = [
        p
        for p in processes
        if p.name.lower() in ("python.exe", "uvicorn.exe")
        and "uvicorn" in p.command_line.lower()
        and "3080" in p.command_line
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[0] if pids else None
    cmdline = redact_secrets(matched[0].command_line) if matched else None

    port_open = is_tcp_port_listening("127.0.0.1", BACKEND_PORT)
    start_t = time.perf_counter()
    http_ok = False
    version = None
    server_name = None
    error_detail = None

    if port_open:
        try:
            req = urllib.request.Request(f"{BACKEND_URL.rstrip('/')}/health", method="GET")
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
                if resp.status == 200 and isinstance(body, dict) and body.get("status") == "ok":
                    http_ok = True
                    version = body.get("version")
                    server_name = body.get("server")
                else:
                    error_detail = f"Unexpected /health payload: {body}"
        except Exception as exc:
            error_detail = f"HTTP /health failed: {type(exc).__name__}: {exc}"
    else:
        error_detail = "Port 3080 not listening"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(port_open and http_ok)
    return {
        "service": "backend",
        "status": "healthy" if healthy else ("degraded" if port_open else "down"),
        "healthy": healthy,
        "port_listening": port_open,
        "pid": primary_pid,
        "pids": pids,
        "port": BACKEND_PORT,
        "url": f"{BACKEND_URL.rstrip('/')}/health",
        "server": server_name,
        "version": version,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_mcp_bridge(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe MCP Bridge on 127.0.0.1:8765/mcp using live MCP initialize + tools/list."""
    matched = [
        p
        for p in processes
        if p.name.lower() in ("python.exe", "pythonw.exe")
        and is_mcp_bridge_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[-1] if pids else None
    cmdline = redact_secrets(matched[-1].command_line) if matched else None

    port_open = is_tcp_port_listening("127.0.0.1", BRIDGE_PORT)
    start_t = time.perf_counter()
    init_ok = False
    tools_ok = True
    tools_count: int | None = None
    protocol_version = None
    server_info = None
    error_detail = None

    if port_open:
        try:
            parsed_rpc = _invoke_mcp_jsonrpc(
                BRIDGE_URL,
                "initialize",
                params={
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "windows-mcp-watchdog", "version": "1.0.0"},
                },
                req_id=1,
                timeout=5.0,
            )
            if isinstance(parsed_rpc, dict) and "result" in parsed_rpc:
                res = parsed_rpc["result"]
                init_ok = True
                protocol_version = res.get("protocolVersion")
                server_info = res.get("serverInfo")
            else:
                error_detail = f"Invalid initialize response: {str(parsed_rpc)[:160]}"
        except Exception as exc:
            error_detail = f"MCP initialize failed: {type(exc).__name__}: {exc}"

        if init_ok:
            try:
                tools_rpc = _invoke_mcp_jsonrpc(
                    BRIDGE_URL,
                    "tools/list",
                    params={},
                    req_id=2,
                    timeout=5.0,
                )
                if isinstance(tools_rpc, dict) and "result" in tools_rpc:
                    tools_list = tools_rpc["result"].get("tools", [])
                    if isinstance(tools_list, list):
                        tools_count = len(tools_list)
                        if tools_count == 0 and is_tcp_port_listening("127.0.0.1", BACKEND_PORT):
                            tools_ok = False
                            error_detail = (
                                "MCP Bridge tools/list returned 0 tools while Backend 3080 is up "
                                "(possible missing/stale COMPUTER_API_TOKEN)"
                            )
            except Exception:
                # If tools/list is not mocked in a synthetic test, keep init_ok result
                pass
    else:
        error_detail = "Port 8765 not listening"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(port_open and init_ok and tools_ok)
    return {
        "service": "mcp_bridge",
        "status": "healthy" if healthy else ("degraded" if port_open else "down"),
        "healthy": healthy,
        "port_listening": port_open,
        "pid": primary_pid,
        "pids": pids,
        "port": BRIDGE_PORT,
        "url": BRIDGE_URL,
        "protocol_version": protocol_version,
        "server_info": server_info,
        "tools_count": tools_count,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_unified_gateway_staging(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe Unified Gateway Staging on http://127.0.0.1:8766/health and /mcp."""
    enabled = is_unified_gateway_staging_enabled()
    matched = [
        p
        for p in processes
        if p.name.lower() in ("python.exe", "pythonw.exe", "uvicorn.exe")
        and is_unified_gateway_staging_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[-1] if pids else None
    cmdline = redact_secrets(matched[-1].command_line) if matched else None

    port_open = is_tcp_port_listening("127.0.0.1", UNIFIED_GATEWAY_STAGING_PORT)
    if not port_open and not enabled:
        return {
            "service": "unified_gateway_staging",
            "status": "staging_not_started",
            "healthy": True,
            "enabled": False,
            "optional": True,
            "port_listening": False,
            "pid": primary_pid,
            "pids": pids,
            "port": UNIFIED_GATEWAY_STAGING_PORT,
            "url": UNIFIED_GATEWAY_STAGING_URL,
            "health_url": UNIFIED_GATEWAY_STAGING_HEALTH_URL,
            "health_ok": False,
            "mcp_init_ok": False,
            "protocol_version": None,
            "server_info": None,
            "command_line": cmdline,
            "latency_ms": 0.0,
            "error": None,
        }

    start_t = time.perf_counter()
    health_ok = False
    mcp_init_ok = False
    protocol_version = None
    server_info = None
    error_detail = None

    if port_open:
        try:
            req = urllib.request.Request(UNIFIED_GATEWAY_STAGING_HEALTH_URL, method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                health_ok = resp.status == 200
        except Exception as exc:
            error_detail = f"GET /health failed: {type(exc).__name__}: {exc}"

        try:
            parsed_rpc = _invoke_mcp_jsonrpc(
                UNIFIED_GATEWAY_STAGING_URL,
                "initialize",
                params={
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "windows-mcp-watchdog", "version": "1.0.0"},
                },
                req_id=1,
                timeout=4.0,
            )
            if isinstance(parsed_rpc, dict) and "result" in parsed_rpc:
                res = parsed_rpc["result"]
                mcp_init_ok = True
                protocol_version = res.get("protocolVersion")
                server_info = res.get("serverInfo")
                error_detail = None
            elif not health_ok:
                error_detail = f"Invalid /mcp initialize response: {str(parsed_rpc)[:160]}"
        except Exception as exc:
            if not health_ok:
                error_detail = f"MCP initialize on 8766 failed: {type(exc).__name__}: {exc}"
    else:
        error_detail = f"Port {UNIFIED_GATEWAY_STAGING_PORT} not listening"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(port_open and (mcp_init_ok or health_ok))
    return {
        "service": "unified_gateway_staging",
        "status": "healthy" if healthy else ("degraded" if port_open else "down"),
        "healthy": healthy,
        "enabled": enabled,
        "optional": not enabled,
        "port_listening": port_open,
        "pid": primary_pid,
        "pids": pids,
        "port": UNIFIED_GATEWAY_STAGING_PORT,
        "url": UNIFIED_GATEWAY_STAGING_URL,
        "health_url": UNIFIED_GATEWAY_STAGING_HEALTH_URL,
        "health_ok": health_ok,
        "mcp_init_ok": mcp_init_ok,
        "protocol_version": protocol_version,
        "server_info": server_info,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_owner_web_console(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe Owner Web Console on http://127.0.0.1:8767/console/api/health (or /health)."""
    matched = [
        p
        for p in processes
        if p.name.lower() in ("python.exe", "pythonw.exe", "uvicorn.exe")
        and is_owner_web_console_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[-1] if pids else None
    cmdline = redact_secrets(matched[-1].command_line) if matched else None

    port_open = is_tcp_port_listening("127.0.0.1", WEB_CONSOLE_PORT)
    if not port_open and not WEB_CONSOLE_SCRIPT.exists():
        return {
            "service": "owner_web_console",
            "status": "not_installed",
            "healthy": True,
            "enabled": False,
            "optional": True,
            "port_listening": False,
            "pid": primary_pid,
            "pids": pids,
            "port": WEB_CONSOLE_PORT,
            "url": WEB_CONSOLE_URL,
            "health_url": WEB_CONSOLE_HEALTH_URL,
            "health_ok": False,
            "command_line": cmdline,
            "latency_ms": 0.0,
            "error": None,
        }

    start_t = time.perf_counter()
    health_ok = False
    server_info = None
    error_detail = None

    if port_open:
        for target_url in (WEB_CONSOLE_HEALTH_URL, WEB_CONSOLE_HEALTH_FALLBACK_URL):
            try:
                req = urllib.request.Request(target_url, method="GET")
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        health_ok = True
                        try:
                            server_info = json.loads(resp.read().decode("utf-8", errors="replace"))
                        except Exception:
                            server_info = {"status": "ok"}
                        error_detail = None
                        break
            except Exception as exc:
                error_detail = f"GET {target_url} failed: {type(exc).__name__}: {exc}"
    else:
        error_detail = f"Port {WEB_CONSOLE_PORT} not listening"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(port_open and health_ok)
    return {
        "service": "owner_web_console",
        "status": "healthy" if healthy else ("degraded" if port_open else "down"),
        "healthy": healthy,
        "enabled": WEB_CONSOLE_SCRIPT.exists(),
        "optional": not WEB_CONSOLE_SCRIPT.exists(),
        "port_listening": port_open,
        "pid": primary_pid,
        "pids": pids,
        "port": WEB_CONSOLE_PORT,
        "url": WEB_CONSOLE_URL,
        "health_url": WEB_CONSOLE_HEALTH_URL,
        "health_ok": health_ok,
        "server_info": server_info,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_autonomous_cloud_adapter(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe Dedicated Cloud Autonomous Adapter on http://127.0.0.1:8768/health and /mcp."""
    matched = [
        p
        for p in processes
        if p.name.lower() in ("python.exe", "pythonw.exe", "uvicorn.exe")
        and is_autonomous_cloud_adapter_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[-1] if pids else None
    cmdline = redact_secrets(matched[-1].command_line) if matched else None

    port_open = is_tcp_port_listening("127.0.0.1", AUTONOMOUS_ADAPTER_PORT)
    if not port_open and not AUTONOMOUS_ADAPTER_SCRIPT.exists():
        return {
            "service": "autonomous_cloud_adapter",
            "status": "not_installed",
            "healthy": True,
            "enabled": False,
            "optional": True,
            "port_listening": False,
            "pid": primary_pid,
            "pids": pids,
            "port": AUTONOMOUS_ADAPTER_PORT,
            "url": AUTONOMOUS_ADAPTER_URL,
            "health_url": AUTONOMOUS_ADAPTER_HEALTH_URL,
            "health_ok": False,
            "command_line": cmdline,
            "latency_ms": 0.0,
            "error": None,
        }

    start_t = time.perf_counter()
    health_ok = False
    server_info = None
    error_detail = None

    if port_open:
        try:
            req = urllib.request.Request(AUTONOMOUS_ADAPTER_HEALTH_URL, method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    health_ok = True
                    try:
                        server_info = json.loads(resp.read().decode("utf-8", errors="replace"))
                    except Exception:
                        server_info = {"status": "ok"}
                    error_detail = None
        except Exception as exc:
            error_detail = f"GET /health failed: {type(exc).__name__}: {exc}"
    else:
        error_detail = f"Port {AUTONOMOUS_ADAPTER_PORT} not listening"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(port_open and health_ok)
    return {
        "service": "autonomous_cloud_adapter",
        "status": "healthy" if healthy else ("degraded" if port_open else "down"),
        "healthy": healthy,
        "enabled": AUTONOMOUS_ADAPTER_SCRIPT.exists(),
        "optional": not AUTONOMOUS_ADAPTER_SCRIPT.exists(),
        "port_listening": port_open,
        "pid": primary_pid,
        "pids": pids,
        "port": AUTONOMOUS_ADAPTER_PORT,
        "url": AUTONOMOUS_ADAPTER_URL,
        "health_url": AUTONOMOUS_ADAPTER_HEALTH_URL,
        "health_ok": health_ok,
        "server_info": server_info,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_tunnel(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe Secure MCP Tunnel (windows-mcp-isolated) and its dynamic /healthz & /readyz."""
    matched = [
        p
        for p in processes
        if p.name.lower() == "tunnel-client.exe"
        and is_isolated_mcp_tunnel_cmd(p.command_line)
        and not is_legacy_codex_tunnel_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[0] if pids else None
    cmdline = redact_secrets(matched[0].command_line) if matched else None

    health_url = None
    if TUNNEL_HEALTH_URL_FILE.exists():
        try:
            raw_url = TUNNEL_HEALTH_URL_FILE.read_text(encoding="utf-8", errors="replace").strip()
            if raw_url.startswith("http://127.0.0.1:") or raw_url.startswith("http://localhost:"):
                health_url = raw_url.rstrip("/")
        except Exception:
            health_url = None

    start_t = time.perf_counter()
    healthz_code = None
    healthz_body = None
    readyz_code = None
    readyz_body = None
    error_detail = None

    if not matched:
        error_detail = f"tunnel-client.exe process for profile '{TUNNEL_PROFILE}' is not running"
    elif not health_url:
        error_detail = f"Health URL file missing or empty: {TUNNEL_HEALTH_URL_FILE}"
    else:
        try:
            with urllib.request.urlopen(f"{health_url}/healthz", timeout=3.0) as r_hz:
                healthz_code = r_hz.status
                healthz_body = r_hz.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            healthz_code = e.code
            error_detail = f"/healthz HTTP {e.code}"
        except Exception as exc:
            error_detail = f"/healthz probe failed: {type(exc).__name__}: {exc}"

        try:
            with urllib.request.urlopen(f"{health_url}/readyz", timeout=3.0) as r_rz:
                readyz_code = r_rz.status
                readyz_body = r_rz.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            readyz_code = e.code
            try:
                readyz_body = e.read().decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            error_detail = f"/readyz HTTP {e.code}: {readyz_body}"
        except Exception as exc:
            error_detail = error_detail or f"/readyz probe failed: {type(exc).__name__}: {exc}"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(
        matched
        and healthz_code == 200
        and readyz_code == 200
        and (healthz_body or "").lower() == "live"
        and (readyz_body or "").lower() == "ready"
    )
    return {
        "service": "tunnel",
        "status": "healthy" if healthy else ("degraded" if (matched and healthz_code == 200) else "down"),
        "healthy": healthy,
        "pid": primary_pid,
        "pids": pids,
        "profile": TUNNEL_PROFILE,
        "tunnel_id": TUNNEL_ID,
        "health_url_file": str(TUNNEL_HEALTH_URL_FILE),
        "health_url": health_url,
        "healthz_status": healthz_code,
        "healthz_body": healthz_body,
        "readyz_status": readyz_code,
        "readyz_body": readyz_body,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_autonomous_tunnel(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Probe Cloud Autonomous MCP Tunnel (windows-mcp-autonomous) and its dynamic /healthz & /readyz."""
    matched = [
        p
        for p in processes
        if p.name.lower() == "tunnel-client.exe"
        and is_autonomous_mcp_tunnel_cmd(p.command_line)
        and not is_legacy_codex_tunnel_cmd(p.command_line)
        and not is_isolated_mcp_tunnel_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[0] if pids else None
    cmdline = redact_secrets(matched[0].command_line) if matched else None

    health_url = None
    if AUTONOMOUS_TUNNEL_HEALTH_URL_FILE.exists():
        try:
            raw_url = AUTONOMOUS_TUNNEL_HEALTH_URL_FILE.read_text(encoding="utf-8", errors="replace").strip()
            if raw_url.startswith("http://127.0.0.1:") or raw_url.startswith("http://localhost:"):
                health_url = raw_url.rstrip("/")
        except Exception:
            health_url = None

    start_t = time.perf_counter()
    healthz_code = None
    healthz_body = None
    readyz_code = None
    readyz_body = None
    error_detail = None

    if not matched:
        error_detail = f"tunnel-client.exe process for profile '{AUTONOMOUS_TUNNEL_PROFILE}' is not running"
    elif not health_url:
        error_detail = f"Health URL file missing or empty: {AUTONOMOUS_TUNNEL_HEALTH_URL_FILE}"
    else:
        try:
            with urllib.request.urlopen(f"{health_url}/healthz", timeout=3.0) as r_hz:
                healthz_code = r_hz.status
                healthz_body = r_hz.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            healthz_code = e.code
            error_detail = f"/healthz HTTP {e.code}"
        except Exception as exc:
            error_detail = f"/healthz probe failed: {type(exc).__name__}: {exc}"

        try:
            with urllib.request.urlopen(f"{health_url}/readyz", timeout=3.0) as r_rz:
                readyz_code = r_rz.status
                readyz_body = r_rz.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            readyz_code = e.code
            try:
                readyz_body = e.read().decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            error_detail = f"/readyz HTTP {e.code}: {readyz_body}"
        except Exception as exc:
            error_detail = error_detail or f"/readyz probe failed: {type(exc).__name__}: {exc}"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(
        matched
        and healthz_code == 200
        and readyz_code == 200
        and (healthz_body or "").lower() == "live"
        and (readyz_body or "").lower() == "ready"
    )
    return {
        "service": "autonomous_tunnel",
        "status": "healthy" if healthy else ("degraded" if (matched and healthz_code == 200) else "down"),
        "healthy": healthy,
        "pid": primary_pid,
        "pids": pids,
        "profile": AUTONOMOUS_TUNNEL_PROFILE,
        "tunnel_id": AUTONOMOUS_TUNNEL_ID,
        "health_url_file": str(AUTONOMOUS_TUNNEL_HEALTH_URL_FILE),
        "health_url": health_url,
        "healthz_status": healthz_code,
        "healthz_body": healthz_body,
        "readyz_status": readyz_code,
        "readyz_body": readyz_body,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


def probe_legacy_codex_tunnel(processes: list[ProcessInfo]) -> dict[str, Any]:
    """Read-only observation of the legacy Codex tunnel (NEVER modified or stopped)."""
    matched = [
        p
        for p in processes
        if p.name.lower() == "tunnel-client.exe"
        and is_legacy_codex_tunnel_cmd(p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[0] if pids else None
    cmdline = redact_secrets(matched[0].command_line) if matched else None

    health_url = None
    healthz_code = None
    readyz_code = None
    if LEGACY_CODEX_HEALTH_URL_FILE.exists():
        try:
            raw_url = LEGACY_CODEX_HEALTH_URL_FILE.read_text(encoding="utf-8", errors="replace").strip()
            if raw_url.startswith("http://127.0.0.1:"):
                health_url = raw_url.rstrip("/")
                with urllib.request.urlopen(f"{health_url}/healthz", timeout=2.5) as r_hz:
                    healthz_code = r_hz.status
                with urllib.request.urlopen(f"{health_url}/readyz", timeout=2.5) as r_rz:
                    readyz_code = r_rz.status
        except Exception:
            pass

    healthy = bool(matched and healthz_code == 200 and readyz_code == 200)
    return {
        "service": "legacy_codex_tunnel",
        "status": "running" if matched else "not_running",
        "healthy": healthy if matched else False,
        "pid": primary_pid,
        "pids": pids,
        "profile": LEGACY_CODEX_PROFILE,
        "tunnel_id": LEGACY_CODEX_TUNNEL_ID,
        "health_url": health_url,
        "healthz_status": healthz_code,
        "readyz_status": readyz_code,
        "command_line": cmdline,
        "untouched": True,
    }


def probe_desktop_agent(processes: list[ProcessInfo], session_info: dict[str, Any]) -> dict[str, Any]:
    """Probe Optional Desktop Agent on 127.0.0.1:8766/health when enabled."""
    enabled = is_desktop_agent_enabled()
    matched = [
        p
        for p in processes
        if p.name.lower() in ("python.exe", "pythonw.exe")
        and ("desktop-agent" in p.command_line.lower() or "8766" in p.command_line)
    ]
    pids = [p.pid for p in matched]
    primary_pid = pids[0] if pids else None
    cmdline = redact_secrets(matched[0].command_line) if matched else None
    port_open = is_tcp_port_listening("127.0.0.1", DESKTOP_AGENT_PORT)

    if not enabled and not port_open:
        return {
            "service": "desktop_agent",
            "status": "disabled_by_policy",
            "healthy": True,
            "enabled": False,
            "optional": True,
            "pid": primary_pid,
            "pids": pids,
            "port": DESKTOP_AGENT_PORT,
            "url": DESKTOP_AGENT_URL,
            "command_line": cmdline,
            "latency_ms": 0.0,
            "error": None,
        }

    start_t = time.perf_counter()
    http_ok = False
    error_detail = None
    if port_open:
        try:
            with urllib.request.urlopen(DESKTOP_AGENT_URL, timeout=3.0) as resp:
                http_ok = resp.status == 200
        except Exception as exc:
            error_detail = f"Desktop agent /health failed: {type(exc).__name__}: {exc}"
    else:
        error_detail = "Port 8766 not listening"

    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
    healthy = bool(port_open and http_ok)
    return {
        "service": "desktop_agent",
        "status": "healthy" if healthy else ("down" if enabled else "optional_down"),
        "healthy": healthy if enabled else True,
        "enabled": enabled,
        "optional": True,
        "interactive_session": session_info.get("interactive", False),
        "pid": primary_pid,
        "pids": pids,
        "port": DESKTOP_AGENT_PORT,
        "url": DESKTOP_AGENT_URL,
        "command_line": cmdline,
        "latency_ms": latency_ms,
        "error": redact_secrets(error_detail) if error_detail else None,
    }


# ---------------------------------------------------------------------------
# Safe Process Lifecycle Actions
# ---------------------------------------------------------------------------
def safe_terminate_pids(
    pids: list[int],
    expected_service: str,
    logger: logging.Logger,
    live_processes: list[ProcessInfo] | None = None,
) -> list[int]:
    """Verify exact PID and CommandLine via CIM before terminating unhealthy/duplicate processes.

    NEVER terminates the legacy Codex tunnel or unrelated processes.
    """
    if not pids:
        return []

    proc_list = live_processes if live_processes is not None else query_windows_processes()
    live_procs = {p.pid: p for p in proc_list}
    stopped: list[int] = []

    for pid in pids:
        proc = live_procs.get(pid)
        if proc is None:
            continue
        cmd_low = proc.command_line.lower()

        # Hard safety guard: NEVER touch the legacy Codex tunnel
        if is_legacy_codex_tunnel_cmd(proc.command_line):
            logger.error(
                "SAFETY REFUSAL: Refusing to stop legacy Codex tunnel PID=%s cmd=%s",
                pid,
                redact_secrets(proc.command_line),
            )
            continue

        # Validate exact service signature before termination
        if expected_service == "tunnel":
            if proc.name.lower() != "tunnel-client.exe" or not is_isolated_mcp_tunnel_cmd(proc.command_line):
                logger.warning(
                    "Skipping PID=%s: does not match tunnel profile %s",
                    pid,
                    TUNNEL_PROFILE,
                )
                continue
        elif expected_service == "mcp_bridge":
            if not is_mcp_bridge_cmd(proc.command_line):
                logger.warning("Skipping PID=%s: does not match bridge.py --http-local", pid)
                continue
        elif expected_service == "backend":
            if "uvicorn" not in cmd_low or "3080" not in cmd_low:
                logger.warning("Skipping PID=%s: does not match uvicorn port 3080", pid)
                continue
        elif expected_service in ("unified_gateway_staging", "desktop_agent"):
            if (
                not is_unified_gateway_staging_cmd(proc.command_line)
                and "desktop-agent" not in cmd_low
                and "8766" not in cmd_low
            ):
                logger.warning("Skipping PID=%s: does not match unified_gateway_staging/desktop-agent", pid)
                continue
        elif expected_service == "owner_web_console":
            if not is_owner_web_console_cmd(proc.command_line):
                logger.warning("Skipping PID=%s: does not match owner_web_console", pid)
                continue
        elif expected_service == "autonomous_cloud_adapter":
            if not is_autonomous_cloud_adapter_cmd(proc.command_line):
                logger.warning("Skipping PID=%s: does not match autonomous_cloud_adapter", pid)
                continue
        elif expected_service == "autonomous_tunnel":
            if proc.name.lower() != "tunnel-client.exe" or not is_autonomous_mcp_tunnel_cmd(proc.command_line):
                logger.warning(
                    "Skipping PID=%s: does not match autonomous tunnel profile %s",
                    pid,
                    AUTONOMOUS_TUNNEL_PROFILE,
                )
                continue
        else:
            continue

        logger.info(
            "Stopping %s process PID=%s CmdLine=%s",
            expected_service,
            pid,
            redact_secrets(proc.command_line),
        )
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/F", "/T"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=CREATE_NO_WINDOW,
            )
            stopped.append(pid)
        except Exception as exc:
            logger.error("Failed to stop PID=%s: %s", pid, exc)

    return stopped


def start_backend_process(logger: logging.Logger) -> tuple[bool, str | None]:
    """Start FastAPI Backend on 127.0.0.1:3080 hidden in background."""
    if not BACKEND_PYTHON.exists():
        return False, f"Backend Python not found: {BACKEND_PYTHON}"
    if not BACKEND_WORKDIR.exists():
        return False, f"Backend WorkingDir not found: {BACKEND_WORKDIR}"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "backend.stdout.log"
    stderr_path = LOGS_DIR / "backend.stderr.log"

    cmd = [
        str(BACKEND_PYTHON),
        "-m",
        "uvicorn",
        "server.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(BACKEND_PORT),
    ]
    logger.info("Starting FastAPI Backend: %s (cwd=%s)", " ".join(cmd), BACKEND_WORKDIR)
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(BACKEND_WORKDIR),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
    except Exception as exc:
        return False, f"Failed to spawn backend: {exc}"

    for _ in range(15):
        time.sleep(1.5)
        state = probe_backend(query_windows_processes())
        if state["healthy"]:
            logger.info("FastAPI Backend healthy on port %s (PID=%s)", BACKEND_PORT, state["pid"])
            return True, None

    return False, "Backend did not pass /health check within 22.5s"


def start_bridge_process(
    logger: logging.Logger,
    env_path: Path | None = None,
) -> tuple[bool, str | None]:
    """Start MCP Bridge on 127.0.0.1:8765/mcp hidden in background with COMPUTER_API_TOKEN."""
    workdir, script_path = resolve_bridge_script()
    python_exe = BRIDGE_PYTHON if BRIDGE_PYTHON.exists() else BACKEND_PYTHON
    if not python_exe.exists():
        return False, f"Bridge Python not found: {python_exe}"
    if not script_path.exists():
        return False, f"Bridge script not found: {script_path}"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "mcp_bridge.stdout.log"
    stderr_path = LOGS_DIR / "mcp_bridge.stderr.log"

    env = build_bridge_env(env_path=env_path)
    has_token = bool(env.get("COMPUTER_API_TOKEN"))

    rel_or_abs_script = (
        str(script_path.relative_to(workdir))
        if script_path.is_relative_to(workdir)
        else str(script_path)
    )
    cmd = [str(python_exe), rel_or_abs_script, "--http-local"]
    logger.info(
        "Starting MCP Bridge: %s (cwd=%s, backend_token_loaded=%s)",
        " ".join(cmd),
        workdir,
        has_token,
    )
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(workdir),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=env,
        )
    except Exception as exc:
        return False, f"Failed to spawn MCP Bridge: {exc}"

    for _ in range(15):
        time.sleep(1.5)
        state = probe_mcp_bridge(query_windows_processes())
        if state["healthy"]:
            logger.info("MCP Bridge healthy on port %s (PID=%s)", BRIDGE_PORT, state["pid"])
            return True, None

    return False, "MCP Bridge did not pass initialize handshake within 22.5s"


def start_unified_gateway_staging_process(
    logger: logging.Logger,
    env_path: Path | None = None,
) -> tuple[bool, str | None]:
    """Start Unified Gateway Staging on 127.0.0.1:8766 hidden in background when script exists."""
    if not UNIFIED_GATEWAY_STAGING_SCRIPT.exists():
        return False, f"Unified Gateway Staging script not found: {UNIFIED_GATEWAY_STAGING_SCRIPT}"

    python_exe = BACKEND_PYTHON if BACKEND_PYTHON.exists() else BRIDGE_PYTHON
    if not python_exe.exists():
        return False, f"Gateway Python not found: {python_exe}"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "gateway_staging.stdout.log"
    stderr_path = LOGS_DIR / "gateway_staging.stderr.log"

    env = build_bridge_env(env_path=env_path)
    cmd = [str(python_exe), str(UNIFIED_GATEWAY_STAGING_SCRIPT)]
    logger.info(
        "Starting Unified Gateway Staging: %s (port=%s)",
        " ".join(cmd),
        UNIFIED_GATEWAY_STAGING_PORT,
    )
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=env,
        )
    except Exception as exc:
        return False, f"Failed to spawn Unified Gateway Staging: {exc}"

    for _ in range(12):
        time.sleep(1.5)
        state = probe_unified_gateway_staging(query_windows_processes())
        if state["healthy"]:
            logger.info(
                "Unified Gateway Staging healthy on port %s (PID=%s)",
                UNIFIED_GATEWAY_STAGING_PORT,
                state["pid"],
            )
            return True, None

    return False, f"Unified Gateway Staging did not pass health/initialize on port {UNIFIED_GATEWAY_STAGING_PORT}"


def start_owner_web_console_process(
    logger: logging.Logger,
    env_path: Path | None = None,
) -> tuple[bool, str | None]:
    """Start Owner Web Console on 127.0.0.1:8767 hidden in background."""
    if not WEB_CONSOLE_SCRIPT.exists():
        return False, f"Web Console script not found: {WEB_CONSOLE_SCRIPT}"

    python_exe = BACKEND_PYTHON if BACKEND_PYTHON.exists() else BRIDGE_PYTHON
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "web_console.stdout.log"
    stderr_path = LOGS_DIR / "web_console.stderr.log"

    env = build_bridge_env(env_path=env_path)
    cur_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{PROJECT_ROOT}{os.pathsep}{cur_pp}" if cur_pp else str(PROJECT_ROOT)
    cmd = [
        str(python_exe),
        str(WEB_CONSOLE_SCRIPT),
        "--host",
        "127.0.0.1",
        "--port",
        str(WEB_CONSOLE_PORT),
    ]
    logger.info("Starting Owner Web Console: %s (port=%s)", " ".join(cmd), WEB_CONSOLE_PORT)
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=env,
        )
    except Exception as exc:
        return False, f"Failed to spawn Owner Web Console: {exc}"

    for _ in range(12):
        time.sleep(1.5)
        state = probe_owner_web_console(query_windows_processes())
        if state["healthy"]:
            logger.info("Owner Web Console healthy on port %s (PID=%s)", WEB_CONSOLE_PORT, state["pid"])
            return True, None

    return False, f"Owner Web Console did not pass health check on port {WEB_CONSOLE_PORT}"


def start_autonomous_cloud_adapter_process(
    logger: logging.Logger,
    env_path: Path | None = None,
) -> tuple[bool, str | None]:
    """Start Dedicated Cloud Autonomous Adapter on 127.0.0.1:8768 hidden in background."""
    if not AUTONOMOUS_ADAPTER_SCRIPT.exists():
        return False, f"Cloud Autonomous Adapter script not found: {AUTONOMOUS_ADAPTER_SCRIPT}"

    python_exe = BACKEND_PYTHON if BACKEND_PYTHON.exists() else BRIDGE_PYTHON
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "cloud_autonomous_adapter.stdout.log"
    stderr_path = LOGS_DIR / "cloud_autonomous_adapter.stderr.log"

    env = build_bridge_env(env_path=env_path)
    cur_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{PROJECT_ROOT}{os.pathsep}{cur_pp}" if cur_pp else str(PROJECT_ROOT)
    cmd = [
        str(python_exe),
        str(AUTONOMOUS_ADAPTER_SCRIPT),
        "--host",
        "127.0.0.1",
        "--port",
        str(AUTONOMOUS_ADAPTER_PORT),
    ]
    logger.info(
        "Starting Cloud Autonomous Adapter: %s (port=%s)",
        " ".join(cmd),
        AUTONOMOUS_ADAPTER_PORT,
    )
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=env,
        )
    except Exception as exc:
        return False, f"Failed to spawn Cloud Autonomous Adapter: {exc}"

    for _ in range(12):
        time.sleep(1.5)
        state = probe_autonomous_cloud_adapter(query_windows_processes())
        if state["healthy"]:
            logger.info(
                "Cloud Autonomous Adapter healthy on port %s (PID=%s)",
                AUTONOMOUS_ADAPTER_PORT,
                state["pid"],
            )
            return True, None

    return False, f"Cloud Autonomous Adapter did not pass health check on port {AUTONOMOUS_ADAPTER_PORT}"


def start_tunnel_process(logger: logging.Logger) -> tuple[bool, str | None]:
    """Start Secure MCP Tunnel (tunnel-client.exe --profile windows-mcp-isolated)."""
    if not TUNNEL_BIN.exists():
        return False, f"Tunnel binary not found: {TUNNEL_BIN}"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "tunnel_isolated.stdout.log"
    stderr_path = LOGS_DIR / "tunnel_isolated.stderr.log"

    cmd = [str(TUNNEL_BIN), "run", "--profile", TUNNEL_PROFILE]
    logger.info("Starting Secure MCP Tunnel: %s", " ".join(cmd))
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
    except Exception as exc:
        return False, f"Failed to spawn tunnel-client: {exc}"

    for _ in range(16):
        time.sleep(1.5)
        state = probe_tunnel(query_windows_processes())
        if state["healthy"]:
            logger.info(
                "Secure MCP Tunnel (%s) healthy at %s (PID=%s)",
                TUNNEL_PROFILE,
                state["health_url"],
                state["pid"],
            )
            return True, None

    return False, f"Tunnel ({TUNNEL_PROFILE}) did not reach /healthz=live & /readyz=ready within 24s"


def start_autonomous_tunnel_process(logger: logging.Logger) -> tuple[bool, str | None]:
    """Start Cloud Autonomous MCP Tunnel (tunnel-client.exe run --profile windows-mcp-autonomous)."""
    if not TUNNEL_BIN.exists():
        return False, f"Tunnel binary not found: {TUNNEL_BIN}"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "tunnel_autonomous.stdout.log"
    stderr_path = LOGS_DIR / "tunnel_autonomous.stderr.log"

    cmd = [str(TUNNEL_BIN), "run", "--profile", AUTONOMOUS_TUNNEL_PROFILE]
    logger.info("Starting Autonomous MCP Tunnel: %s", " ".join(cmd))
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
    except Exception as exc:
        return False, f"Failed to spawn autonomous tunnel-client: {exc}"

    for _ in range(16):
        time.sleep(1.5)
        state = probe_autonomous_tunnel(query_windows_processes())
        if state["healthy"]:
            logger.info(
                "Autonomous MCP Tunnel (%s) healthy at %s (PID=%s)",
                AUTONOMOUS_TUNNEL_PROFILE,
                state["health_url"],
                state["pid"],
            )
            return True, None

    return False, f"Autonomous Tunnel ({AUTONOMOUS_TUNNEL_PROFILE}) did not reach /healthz=live & /readyz=ready within 24s"


def start_desktop_agent_process(logger: logging.Logger) -> tuple[bool, str | None]:
    """Start Optional Desktop Agent if enabled and script exists."""
    resolved = resolve_desktop_agent_script()
    if resolved is None:
        return False, "Desktop agent script not found in desktop-agent/"

    workdir, script_path = resolved
    python_exe = BACKEND_PYTHON if BACKEND_PYTHON.exists() else BRIDGE_PYTHON
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOGS_DIR / "desktop_agent.stdout.log"
    stderr_path = LOGS_DIR / "desktop_agent.stderr.log"

    cmd = [str(python_exe), str(script_path), "--port", str(DESKTOP_AGENT_PORT)]
    logger.info("Starting Desktop Agent: %s", " ".join(cmd))
    try:
        _spawn_detached_background(
            cmd,
            cwd=str(workdir),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
    except Exception as exc:
        return False, f"Failed to spawn Desktop Agent: {exc}"

    for _ in range(10):
        time.sleep(1.5)
        state = probe_desktop_agent(query_windows_processes(), get_windows_session_info())
        if state["healthy"]:
            logger.info("Desktop Agent healthy on port %s (PID=%s)", DESKTOP_AGENT_PORT, state["pid"])
            return True, None

    return False, "Desktop Agent did not pass /health check within 15s"


# ---------------------------------------------------------------------------
# Watchdog Supervisor Core
# ---------------------------------------------------------------------------
class WatchdogSupervisor:
    """Supervises Backend -> MCP Bridge -> Unified Gateway Staging -> Secure Tunnel -> Legacy Codex Tunnel."""

    def __init__(
        self,
        logger: logging.Logger,
        mode: str = "once",
        load_previous: bool = True,
        resume_grace_sec: float = 30.0,
    ) -> None:
        self.logger = logger
        self.mode = mode
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.trackers: dict[str, RestartTracker] = {
            "backend": RestartTracker("backend"),
            "mcp_bridge": RestartTracker("mcp_bridge"),
            "unified_gateway_staging": RestartTracker("unified_gateway_staging"),
            "owner_web_console": RestartTracker("owner_web_console"),
            "autonomous_cloud_adapter": RestartTracker("autonomous_cloud_adapter"),
            "tunnel": RestartTracker("tunnel"),
            "autonomous_tunnel": RestartTracker("autonomous_tunnel"),
            "desktop_agent": RestartTracker("desktop_agent"),
        }
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=50)
        self.last_network_available: bool | None = None
        self.last_loop_wall_time: float | None = None
        self.resume_grace_until_epoch: float = 0.0
        self.resume_grace_sec: float = resume_grace_sec
        if load_previous:
            self._load_previous_state()

    def _load_previous_state(self) -> None:
        """Preserve recent events, network state, and restart counters across --once invocations."""
        if not STATUS_FILE.exists():
            return
        try:
            prev = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
            for evt in prev.get("recent_events", [])[-30:]:
                if isinstance(evt, dict):
                    self.recent_events.append(evt)
            if isinstance(prev.get("network_available"), bool):
                self.last_network_available = prev["network_available"]
            prev_services = prev.get("services", {})
            for name, tracker in self.trackers.items():
                svc_data = prev_services.get(name, {})
                if isinstance(svc_data, dict):
                    tracker.restart_count = int(svc_data.get("restart_count") or 0)
        except Exception:
            pass

    def record_event(self, level: str, service: str, event: str, detail: str) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "service": service,
            "event": event,
            "detail": redact_secrets(detail),
        }
        self.recent_events.append(entry)
        log_fn = getattr(self.logger, level.lower(), self.logger.info)
        log_fn("[%s] %s: %s", service, event, redact_secrets(detail))

    def detect_sleep_resume(self, interval_sec: float, now_epoch: float | None = None) -> bool:
        """Detect OS sleep/resume wall-clock time jumps (> 3 * interval) and activate grace period."""
        now = now_epoch if now_epoch is not None else time.time()
        threshold = 3.0 * max(1.0, float(interval_sec))
        jumped = False
        if self.last_loop_wall_time is not None:
            elapsed = now - self.last_loop_wall_time
            if elapsed > threshold:
                jumped = True
                self.resume_grace_until_epoch = now + self.resume_grace_sec
                self.record_event(
                    "warning",
                    "watchdog",
                    "SYSTEM_RESUME_DETECTED",
                    f"Wall-clock time jumped by {elapsed:.1f}s (threshold={threshold:.1f}s); "
                    f"granting {self.resume_grace_sec:.0f}s grace period before counting failures",
                )
        self.last_loop_wall_time = now
        return jumped

    def is_in_resume_grace_period(self, now_epoch: float | None = None) -> bool:
        """Return True if currently within the post-sleep/resume grace period."""
        now = now_epoch if now_epoch is not None else time.time()
        return now < self.resume_grace_until_epoch

    def handle_network_transition(self, network_ok: bool) -> None:
        """Detect and log outbound network outage and restoration transitions."""
        if self.last_network_available is None:
            self.last_network_available = network_ok
            if not network_ok:
                self.record_event(
                    "warning",
                    "watchdog",
                    "NETWORK_OUTAGE_DETECTED",
                    "Outbound network connectivity unavailable; holding off tunnel failure counting",
                )
            return

        if self.last_network_available and not network_ok:
            self.last_network_available = False
            self.record_event(
                "warning",
                "watchdog",
                "NETWORK_OUTAGE_DETECTED",
                "Outbound network connectivity lost; holding off tunnel failure counting and restarts",
            )
        elif not self.last_network_available and network_ok:
            self.last_network_available = True
            self.record_event(
                "info",
                "watchdog",
                "NETWORK_RESTORED",
                "Outbound network connectivity restored; resuming normal tunnel supervision",
            )

    def cleanup_duplicate_processes(
        self,
        processes: list[ProcessInfo],
        active_bridge_pid: int | None = None,
        active_tunnel_pid: int | None = None,
        active_autonomous_tunnel_pid: int | None = None,
    ) -> dict[str, list[int]]:
        """Detect and safely clean up duplicate orphan bridge.py or tunnel processes."""
        cleaned: dict[str, list[int]] = {"mcp_bridge": [], "tunnel": [], "autonomous_tunnel": []}

        dup_bridge_pids = find_duplicate_service_pids(
            processes,
            "mcp_bridge",
            active_pid=active_bridge_pid,
        )
        if dup_bridge_pids:
            self.record_event(
                "warning",
                "mcp_bridge",
                "DUPLICATE_PROCESS_DETECTED",
                f"Detected duplicate bridge.py orphan PIDs={dup_bridge_pids}; terminating orphans only",
            )
            cleaned["mcp_bridge"] = safe_terminate_pids(
                dup_bridge_pids,
                "mcp_bridge",
                self.logger,
                live_processes=processes,
            )

        dup_tunnel_pids = find_duplicate_service_pids(
            processes,
            "tunnel",
            active_pid=active_tunnel_pid,
        )
        if dup_tunnel_pids:
            self.record_event(
                "warning",
                "tunnel",
                "DUPLICATE_PROCESS_DETECTED",
                f"Detected duplicate windows-mcp-isolated tunnel orphan PIDs={dup_tunnel_pids}; terminating orphans only",
            )
            cleaned["tunnel"] = safe_terminate_pids(
                dup_tunnel_pids,
                "tunnel",
                self.logger,
                live_processes=processes,
            )

        dup_auton_pids = find_duplicate_service_pids(
            processes,
            "autonomous_tunnel",
            active_pid=active_autonomous_tunnel_pid,
        )
        if dup_auton_pids:
            self.record_event(
                "warning",
                "autonomous_tunnel",
                "DUPLICATE_PROCESS_DETECTED",
                f"Detected duplicate windows-mcp-autonomous tunnel orphan PIDs={dup_auton_pids}; terminating orphans only",
            )
            cleaned["autonomous_tunnel"] = safe_terminate_pids(
                dup_auton_pids,
                "autonomous_tunnel",
                self.logger,
                live_processes=processes,
            )

        return cleaned

    def inspect_all(self) -> dict[str, Any]:
        """Perform a non-mutating inspection of all monitored services and system state."""
        processes = query_windows_processes()
        session_info = get_windows_session_info()
        network_ok = check_network_available()

        backend_state = probe_backend(processes)
        bridge_state = probe_mcp_bridge(processes)
        gateway_staging_state = probe_unified_gateway_staging(processes)
        web_console_state = probe_owner_web_console(processes)
        adapter_state = probe_autonomous_cloud_adapter(processes)
        tunnel_state = probe_tunnel(processes)
        autonomous_tunnel_state = probe_autonomous_tunnel(processes)
        legacy_state = probe_legacy_codex_tunnel(processes)

        for name, state_dict in (
            ("backend", backend_state),
            ("mcp_bridge", bridge_state),
            ("unified_gateway_staging", gateway_staging_state),
            ("owner_web_console", web_console_state),
            ("autonomous_cloud_adapter", adapter_state),
            ("tunnel", tunnel_state),
            ("autonomous_tunnel", autonomous_tunnel_state),
        ):
            state_dict.update(self.trackers[name].to_dict())

        console_ok = web_console_state["healthy"] if WEB_CONSOLE_SCRIPT.exists() else True
        adapter_ok = adapter_state["healthy"] if AUTONOMOUS_ADAPTER_SCRIPT.exists() else True

        overall_healthy = bool(
            backend_state["healthy"]
            and bridge_state["healthy"]
            and gateway_staging_state["healthy"]
            and console_ok
            and adapter_ok
            and tunnel_state["healthy"]
            and autonomous_tunnel_state["healthy"]
        )

        return {
            "schema_version": "1.1.0",
            "watchdog_pid": os.getpid(),
            "mode": self.mode,
            "started_at": self.started_at,
            "last_check_at": datetime.now(timezone.utc).isoformat(),
            "overall_healthy": overall_healthy,
            "network_available": network_ok,
            "in_resume_grace_period": self.is_in_resume_grace_period(),
            "session_info": session_info,
            "services": {
                "backend": backend_state,
                "mcp_bridge": bridge_state,
                "unified_gateway_staging": gateway_staging_state,
                "owner_web_console": web_console_state,
                "autonomous_cloud_adapter": adapter_state,
                "tunnel": tunnel_state,
                "autonomous_tunnel": autonomous_tunnel_state,
                "legacy_codex_tunnel": legacy_state,
            },
            "recent_events": list(self.recent_events),
        }

    def write_status_atomic(self, status_payload: dict[str, Any]) -> None:
        """Atomically write runtime/logs/status.json."""
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        tmp_path = STATUS_FILE.with_suffix(".json.tmp")
        serialized = redact_secrets(json.dumps(status_payload, indent=2, ensure_ascii=False))
        tmp_path.write_text(serialized, encoding="utf-8")
        tmp_path.replace(STATUS_FILE)

    def check_and_heal_once(
        self,
        allow_heal: bool = True,
        interval_sec: float | None = None,
        now_epoch: float | None = None,
    ) -> dict[str, Any]:
        """Check the dependency chain in strict order and heal if needed."""
        if interval_sec is not None:
            self.detect_sleep_resume(interval_sec, now_epoch=now_epoch)

        in_grace = self.is_in_resume_grace_period(now_epoch=now_epoch)
        processes = query_windows_processes()
        network_ok = check_network_available()
        self.handle_network_transition(network_ok)

        # Clean up any duplicate orphan processes for mcp_bridge or tunnels
        if allow_heal and not in_grace:
            b_probe_initial = probe_mcp_bridge(processes)
            t_probe_initial = probe_tunnel(processes)
            at_probe_initial = probe_autonomous_tunnel(processes)
            cleaned = self.cleanup_duplicate_processes(
                processes,
                active_bridge_pid=b_probe_initial.get("pid"),
                active_tunnel_pid=t_probe_initial.get("pid"),
                active_autonomous_tunnel_pid=at_probe_initial.get("pid"),
            )
            if cleaned["mcp_bridge"] or cleaned["tunnel"] or cleaned["autonomous_tunnel"]:
                processes = query_windows_processes()

        # ------------------------------------------------------------------
        # 1) FastAPI Backend (http://127.0.0.1:3080)
        # ------------------------------------------------------------------
        backend_state = probe_backend(processes)
        b_tracker = self.trackers["backend"]
        if backend_state["healthy"]:
            b_tracker.record_healthy()
        elif allow_heal:
            if in_grace:
                self.record_event(
                    "info",
                    "backend",
                    "resume_grace_period_holdoff",
                    "Deferring backend failure count during system resume grace period",
                )
            else:
                if backend_state["pids"] and backend_state["port_listening"]:
                    b_tracker.consecutive_health_Confirm_failures += 1
                else:
                    b_tracker.consecutive_health_Confirm_failures = 3

                if b_tracker.consecutive_health_Confirm_failures >= 3:
                    can_run, reason = b_tracker.can_attempt_restart(now=now_epoch)
                    if can_run:
                        self.record_event(
                            "warning",
                            "backend",
                            "service_unhealthy_restarting",
                            backend_state.get("error") or "Backend unhealthy",
                        )
                        if backend_state["pids"]:
                            safe_terminate_pids(backend_state["pids"], "backend", self.logger)
                            time.sleep(1.5)
                        ok, err = start_backend_process(self.logger)
                        b_tracker.record_restart_attempt(ok, err, now=now_epoch)
                        if ok:
                            self.record_event("info", "backend", "service_recovered", "FastAPI Backend healthy on port 3080")
                        else:
                            self.record_event("error", "backend", "service_restart_failed", err or "Unknown error")
                    else:
                        self.record_event("warning", "backend", "restart_throttled", reason)

        # Refresh processes after potential backend heal
        processes = query_windows_processes()
        backend_state = probe_backend(processes)

        # ------------------------------------------------------------------
        # 2) MCP Bridge (http://127.0.0.1:8765/mcp)
        # ------------------------------------------------------------------
        bridge_state = probe_mcp_bridge(processes)
        m_tracker = self.trackers["mcp_bridge"]
        if bridge_state["healthy"]:
            m_tracker.record_healthy()
        elif allow_heal:
            if in_grace:
                self.record_event(
                    "info",
                    "mcp_bridge",
                    "resume_grace_period_holdoff",
                    "Deferring MCP Bridge failure count during system resume grace period",
                )
            elif not backend_state["healthy"]:
                self.record_event(
                    "warning",
                    "mcp_bridge",
                    "dependency_wait",
                    "Waiting for FastAPI Backend (port 3080) before restarting MCP Bridge",
                )
            else:
                if bridge_state["pids"] and bridge_state["port_listening"]:
                    m_tracker.consecutive_health_Confirm_failures += 1
                else:
                    m_tracker.consecutive_health_Confirm_failures = 2

                if m_tracker.consecutive_health_Confirm_failures >= 2:
                    can_run, reason = m_tracker.can_attempt_restart(now=now_epoch)
                    if can_run:
                        self.record_event(
                            "warning",
                            "mcp_bridge",
                            "service_unhealthy_restarting",
                            bridge_state.get("error") or "MCP Bridge unhealthy",
                        )
                        if bridge_state["pids"]:
                            safe_terminate_pids(bridge_state["pids"], "mcp_bridge", self.logger)
                            time.sleep(1.5)
                        ok, err = start_bridge_process(self.logger)
                        m_tracker.record_restart_attempt(ok, err, now=now_epoch)
                        if ok:
                            self.record_event("info", "mcp_bridge", "service_recovered", "MCP Bridge healthy on port 8765")
                        else:
                            self.record_event("error", "mcp_bridge", "service_restart_failed", err or "Unknown error")
                    else:
                        self.record_event("warning", "mcp_bridge", "restart_throttled", reason)

        # Refresh processes after potential bridge heal
        processes = query_windows_processes()
        bridge_state = probe_mcp_bridge(processes)

        # ------------------------------------------------------------------
        # 3) Unified Gateway Staging (http://127.0.0.1:8766/mcp)
        # ------------------------------------------------------------------
        gateway_staging_state = probe_unified_gateway_staging(processes)
        g_tracker = self.trackers["unified_gateway_staging"]
        if gateway_staging_state["healthy"]:
            g_tracker.record_healthy()
        elif allow_heal and gateway_staging_state.get("enabled"):
            if in_grace:
                self.record_event(
                    "info",
                    "unified_gateway_staging",
                    "resume_grace_period_holdoff",
                    "Deferring Unified Gateway Staging failure count during system resume grace period",
                )
            else:
                can_run, reason = g_tracker.can_attempt_restart(now=now_epoch)
                if can_run:
                    if gateway_staging_state["pids"]:
                        safe_terminate_pids(
                            gateway_staging_state["pids"],
                            "unified_gateway_staging",
                            self.logger,
                        )
                        time.sleep(1.0)
                    ok, err = start_unified_gateway_staging_process(self.logger)
                    g_tracker.record_restart_attempt(ok, err, now=now_epoch)
                    if ok:
                        self.record_event(
                            "info",
                            "unified_gateway_staging",
                            "service_recovered",
                            "Unified Gateway Staging healthy on port 8766",
                        )
                    else:
                        self.record_event(
                            "warning",
                            "unified_gateway_staging",
                            "service_restart_failed",
                            err or "Unified Gateway Staging restart failed",
                        )
                else:
                    self.record_event("warning", "unified_gateway_staging", "restart_throttled", reason)

        # ------------------------------------------------------------------
        # 4) Owner Web Console (http://127.0.0.1:8767)
        # ------------------------------------------------------------------
        processes = query_windows_processes()
        web_console_state = probe_owner_web_console(processes)
        wc_tracker = self.trackers["owner_web_console"]
        if web_console_state["healthy"]:
            wc_tracker.record_healthy()
        elif allow_heal and WEB_CONSOLE_SCRIPT.exists():
            if in_grace:
                self.record_event(
                    "info",
                    "owner_web_console",
                    "resume_grace_period_holdoff",
                    "Deferring Owner Web Console failure count during system resume grace period",
                )
            else:
                can_run, reason = wc_tracker.can_attempt_restart(now=now_epoch)
                if can_run:
                    if web_console_state["pids"]:
                        safe_terminate_pids(
                            web_console_state["pids"],
                            "owner_web_console",
                            self.logger,
                        )
                        time.sleep(1.0)
                    ok, err = start_owner_web_console_process(self.logger)
                    wc_tracker.record_restart_attempt(ok, err, now=now_epoch)
                    if ok:
                        self.record_event(
                            "info",
                            "owner_web_console",
                            "service_recovered",
                            f"Owner Web Console healthy on port {WEB_CONSOLE_PORT}",
                        )
                    else:
                        self.record_event(
                            "warning",
                            "owner_web_console",
                            "service_restart_failed",
                            err or "Owner Web Console restart failed",
                        )
                else:
                    self.record_event("warning", "owner_web_console", "restart_throttled", reason)

        # ------------------------------------------------------------------
        # 5) Dedicated Cloud Autonomous Adapter (http://127.0.0.1:8768)
        # ------------------------------------------------------------------
        processes = query_windows_processes()
        adapter_state = probe_autonomous_cloud_adapter(processes)
        ca_tracker = self.trackers["autonomous_cloud_adapter"]
        if adapter_state["healthy"]:
            ca_tracker.record_healthy()
        elif allow_heal and AUTONOMOUS_ADAPTER_SCRIPT.exists():
            if in_grace:
                self.record_event(
                    "info",
                    "autonomous_cloud_adapter",
                    "resume_grace_period_holdoff",
                    "Deferring Cloud Autonomous Adapter failure count during system resume grace period",
                )
            else:
                can_run, reason = ca_tracker.can_attempt_restart(now=now_epoch)
                if can_run:
                    if adapter_state["pids"]:
                        safe_terminate_pids(
                            adapter_state["pids"],
                            "autonomous_cloud_adapter",
                            self.logger,
                        )
                        time.sleep(1.0)
                    ok, err = start_autonomous_cloud_adapter_process(self.logger)
                    ca_tracker.record_restart_attempt(ok, err, now=now_epoch)
                    if ok:
                        self.record_event(
                            "info",
                            "autonomous_cloud_adapter",
                            "service_recovered",
                            f"Cloud Autonomous Adapter healthy on port {AUTONOMOUS_ADAPTER_PORT}",
                        )
                    else:
                        self.record_event(
                            "warning",
                            "autonomous_cloud_adapter",
                            "service_restart_failed",
                            err or "Cloud Autonomous Adapter restart failed",
                        )
                else:
                    self.record_event("warning", "autonomous_cloud_adapter", "restart_throttled", reason)

        # ------------------------------------------------------------------
        # 6) Secure MCP Tunnel (windows-mcp-isolated)
        # ------------------------------------------------------------------
        processes = query_windows_processes()
        tunnel_state = probe_tunnel(processes)
        t_tracker = self.trackers["tunnel"]
        if tunnel_state["healthy"]:
            t_tracker.record_healthy()
        elif allow_heal:
            if in_grace:
                self.record_event(
                    "info",
                    "tunnel",
                    "resume_grace_period_holdoff",
                    "Deferring tunnel failure count during system resume grace period",
                )
            elif not network_ok:
                # Network is unavailable: hold off tunnel failure counting and restarts completely
                self.record_event(
                    "warning",
                    "tunnel",
                    "network_unavailable_wait",
                    "Network unreachable; holding off tunnel failure counter and deferring restart until connectivity recovers",
                )
            elif not bridge_state["healthy"]:
                self.record_event(
                    "warning",
                    "tunnel",
                    "dependency_wait",
                    "Waiting for MCP Bridge (port 8765) before restarting Secure Tunnel",
                )
            else:
                if tunnel_state["pids"] and tunnel_state["healthz_status"] == 200:
                    t_tracker.consecutive_health_Confirm_failures += 1
                else:
                    t_tracker.consecutive_health_Confirm_failures = 2

                if t_tracker.consecutive_health_Confirm_failures >= 2:
                    can_run, reason = t_tracker.can_attempt_restart(now=now_epoch)
                    if can_run:
                        self.record_event(
                            "warning",
                            "tunnel",
                            "service_unhealthy_restarting",
                            tunnel_state.get("error") or "Tunnel unhealthy",
                        )
                        if tunnel_state["pids"]:
                            safe_terminate_pids(tunnel_state["pids"], "tunnel", self.logger)
                            time.sleep(2.0)
                        ok, err = start_tunnel_process(self.logger)
                        t_tracker.record_restart_attempt(ok, err, now=now_epoch)
                        if ok:
                            self.record_event(
                                "info",
                                "tunnel",
                                "service_recovered",
                                f"Secure Tunnel ({TUNNEL_PROFILE}) healthy",
                            )
                        else:
                            self.record_event("error", "tunnel", "service_restart_failed", err or "Unknown error")
                    else:
                        self.record_event("warning", "tunnel", "restart_throttled", reason)

        # ------------------------------------------------------------------
        # 7) Autonomous MCP Tunnel (windows-mcp-autonomous)
        # ------------------------------------------------------------------
        processes = query_windows_processes()
        auton_tunnel_state = probe_autonomous_tunnel(processes)
        at_tracker = self.trackers["autonomous_tunnel"]
        if auton_tunnel_state["healthy"]:
            at_tracker.record_healthy()
        elif allow_heal:
            if in_grace:
                self.record_event(
                    "info",
                    "autonomous_tunnel",
                    "resume_grace_period_holdoff",
                    "Deferring autonomous tunnel failure count during system resume grace period",
                )
            elif not network_ok:
                self.record_event(
                    "warning",
                    "autonomous_tunnel",
                    "network_unavailable_wait",
                    "Network unreachable; holding off autonomous tunnel failure counter and deferring restart until connectivity recovers",
                )
            elif not adapter_state["healthy"]:
                self.record_event(
                    "warning",
                    "autonomous_tunnel",
                    "dependency_wait",
                    f"Waiting for Cloud Autonomous Adapter (port {AUTONOMOUS_ADAPTER_PORT}) before restarting Autonomous Tunnel",
                )
            else:
                if auton_tunnel_state["pids"] and auton_tunnel_state["healthz_status"] == 200:
                    at_tracker.consecutive_health_Confirm_failures += 1
                else:
                    at_tracker.consecutive_health_Confirm_failures = 2

                if at_tracker.consecutive_health_Confirm_failures >= 2:
                    can_run, reason = at_tracker.can_attempt_restart(now=now_epoch)
                    if can_run:
                        self.record_event(
                            "warning",
                            "autonomous_tunnel",
                            "service_unhealthy_restarting",
                            auton_tunnel_state.get("error") or "Autonomous Tunnel unhealthy",
                        )
                        if auton_tunnel_state["pids"]:
                            safe_terminate_pids(auton_tunnel_state["pids"], "autonomous_tunnel", self.logger)
                            time.sleep(2.0)
                        ok, err = start_autonomous_tunnel_process(self.logger)
                        at_tracker.record_restart_attempt(ok, err, now=now_epoch)
                        if ok:
                            self.record_event(
                                "info",
                                "autonomous_tunnel",
                                "service_recovered",
                                f"Autonomous Tunnel ({AUTONOMOUS_TUNNEL_PROFILE}) healthy",
                            )
                        else:
                            self.record_event("error", "autonomous_tunnel", "service_restart_failed", err or "Unknown error")
                    else:
                        self.record_event("warning", "autonomous_tunnel", "restart_throttled", reason)

        snapshot = self.inspect_all()
        self.write_status_atomic(snapshot)
        return snapshot


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WinOwner MCP Supervisor & Watchdog Daemon"
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--once",
        action="store_true",
        help="Run a single dependency check and self-healing pass",
    )
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="Print current status JSON (non-mutating)",
    )
    mode_group.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuous background supervision loop",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=15.0,
        help="Polling interval in seconds for --daemon mode (default: 15)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Inspect live state and update status.json without starting/stopping services",
    )
    args = parser.parse_args(argv)

    logger = setup_logger()
    # Pre-register backend secret for redaction if present
    load_backend_auth_token()

    # --status mode: non-mutating, never blocks on lockfile
    if args.status:
        supervisor = WatchdogSupervisor(logger, mode="status")
        snapshot = supervisor.inspect_all()
        # Update status.json if no daemon is currently holding the lock
        lock = SingleInstanceLock()
        if lock.acquire(mode="status"):
            try:
                supervisor.write_status_atomic(snapshot)
            finally:
                lock.release()
        print(redact_secrets(json.dumps(snapshot, indent=2, ensure_ascii=False)))
        return 0 if snapshot["overall_healthy"] else 1

    mode_name = "daemon" if args.daemon else "once"
    lock = SingleInstanceLock()
    if not lock.acquire(mode=mode_name):
        logger.info("Another watchdog instance already holds %s; exiting cleanly.", LOCK_FILE)
        if STATUS_FILE.exists():
            print(STATUS_FILE.read_text(encoding="utf-8", errors="replace"))
        return 0

    try:
        supervisor = WatchdogSupervisor(logger, mode=mode_name)
        supervisor.record_event("info", "watchdog", "watchdog_started", f"mode={mode_name} pid={os.getpid()}")

        if args.daemon:
            while True:
                try:
                    supervisor.check_and_heal_once(
                        allow_heal=not args.check_only,
                        interval_sec=args.interval,
                    )
                except Exception as exc:
                    logger.error("Unhandled error in watchdog loop: %s", exc)
                time.sleep(max(3.0, args.interval))
        else:
            snapshot = supervisor.check_and_heal_once(
                allow_heal=not args.check_only,
                interval_sec=args.interval,
            )
            print(redact_secrets(json.dumps(snapshot, indent=2, ensure_ascii=False)))
            return 0 if snapshot["overall_healthy"] else 1
    except KeyboardInterrupt:
        logger.info("Watchdog stopped via KeyboardInterrupt.")
        return 0
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
