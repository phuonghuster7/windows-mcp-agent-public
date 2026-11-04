"""Stage S4 — Mode B Owner-Controlled Web Agent Console (Local-First, Account-Independent).

Provides a production-grade, local-first, browser-accessible Web Control Surface for the
WinOwner MCP when ChatGPT Web native MCP is unavailable (e.g., on ChatGPT Plus plans
where custom MCP connectors are plan-gated) or when direct owner-supervised browser control
is desired.

Security Architecture:
- Loopback-bound by default (127.0.0.1:8767) or mountable on the Unified Gateway ASGI server.
- Strong owner authentication via HMAC-verified master secret (`WINDOWS_MCP_CONSOLE_SECRET`
  or `MCP_AUTH_TOKEN`), issuing an `HttpOnly`, `SameSite=Strict` session cookie
  (`mcp_console_session`) and an in-memory per-session `csrf_token`.
- Strict login rate-limiting (default max 5 failed attempts per 60 seconds -> HTTP 429).
- Mandatory CSRF token (`X-CSRF-Token`) + loopback `Origin` / `Referer` validation on all
  state-changing POST endpoints.
- Human-in-the-loop separation between Pending Operation Proposals (`PENDING_OWNER_APPROVAL`)
  and Owner-Confirmed Windows Actions (`POST /console/api/proposals/{id}/execute` or
  `POST /console/api/execute`), backed by revocable, time-limited, scope-bounded
  `ControlSession` tokens (`allowed_paths`, `allowed_commands`, `allowed_tools`, `ttl_seconds`).
- Immediate session revocation (`revoke` / `revoke-all`) and global Emergency Stop kill-switch
  that halts privileged tiers, revokes all sessions, and terminates running jobs/processes.
- Zero secrets in HTML/JS bundles, `localStorage`, or redacted audit logs.
"""
from __future__ import annotations

import argparse
import asyncio
import difflib
import hashlib
import hmac
import inspect
import json
import logging
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from jsonschema import ValidationError
import uvicorn

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for _p in (HERE, PROJECT_ROOT, PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from policy import (  # noqa: E402
    ControlSession,
    PermissionTier,
    SecurityPolicy,
    TOOL_TIER_MAP,
    redact_secrets,
)
from gateway_server import ALL_TOOL_DEFINITIONS, MCPGatewayServer  # noqa: E402
from file_code_ops import detect_encoding_and_decode  # noqa: E402

logger = logging.getLogger("web_agent_console")

SESSION_COOKIE_NAME = "mcp_console_session"
ALLOWED_LOOPBACK_HOSTS = frozenset(("127.0.0.1", "localhost", "::1", "[::1]", "testserver"))

OPENAI_BILLING_DISCLOSURE = (
    "OpenAI Responses API usage requires an owner-supplied OPENAI_API_KEY and is billed "
    "separately via OpenAI API credits (not included in a ChatGPT Plus subscription)."
)


try:
    from runtime.task_grant import compute_proposal_scope_digest
except ImportError:
    def compute_proposal_scope_digest(proposal: dict[str, Any]) -> str:
        """Canonicalize proposal scope fields and return a SHA-256 hex digest (G01 fallback)."""
        ws_raw = proposal.get("workspace_root", "")
        ws_canonical = str(Path(ws_raw).resolve(strict=False))

        raw_paths = proposal.get("allowed_paths")
        if raw_paths is None:
            raw_paths = proposal.get("allowed_extra_paths") or []
        canonical_paths = sorted(str(Path(p).resolve(strict=False)) for p in raw_paths)

        raw_tiers = proposal.get("allowed_permission_tiers")
        if raw_tiers is None:
            raw_tiers = ["EXECUTE", "READ", "WRITE"]
        canonical_tiers = sorted(str(t) for t in raw_tiers)

        canonical_dict = {
            "allowed_commands": sorted(str(c) for c in proposal.get("allowed_commands", [])),
            "allowed_paths": canonical_paths,
            "allowed_permission_tiers": canonical_tiers,
            "allowed_tools": sorted(str(t) for t in proposal.get("allowed_tools", [])),
            "api_cost_budget": float(proposal.get("api_cost_budget", 5.0)),
            "duration_seconds": float(proposal.get("duration_seconds", 3600.0)),
            "max_retries": int(proposal.get("max_retries", 5)),
            "max_tool_calls": int(proposal.get("max_tool_calls", 500)),
            "objective": str(proposal.get("objective", "")).strip(),
            "task_id": str(proposal.get("task_id", "")).strip(),
            "workspace_root": ws_canonical,
        }
        canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _trigger_independent_worker(db_path: Path | str) -> int:
    """Spawn an independent external worker process for autonomous task execution (G04)."""
    try:
        from runtime.autonomous_agent import spawn_independent_worker_once
        return spawn_independent_worker_once(db_path)
    except Exception:
        cmd = [
            sys.executable,
            "-m",
            "runtime.autonomous_agent",
            "--db-path",
            str(db_path),
            "--max-tasks",
            "1",
            "--once",
        ]
        proc = subprocess.Popen(
            cmd,
            cwd=str(Path(__file__).resolve().parent.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.pid


def _safe_user_home() -> Path:
    """Return user home directory or safe fallback if USERPROFILE/HOME are unset."""
    try:
        return Path.home()
    except Exception:
        fallback = os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir()
        return Path(fallback)


DEFAULT_CONSOLE_DPAPI_FILE = PROJECT_ROOT / "runtime" / "secrets" / "console_owner_secret.dpapi"
DEFAULT_BACKEND_ENV_FILE = Path(
    os.getenv(
        "WINDOWS_MCP_BACKEND_ENV_FILE",
        str(_safe_user_home() / ".gemini" / "antigravity-ide" / "scratch" / "computer-mcp-server" / ".env"),
    )
)


def _decrypt_dpapi_file(dpapi_path: Path) -> str | None:
    """Decrypt a Windows DPAPI CurrentUser secret file in memory without logging."""
    if not dpapi_path.exists() or os.name != "nt":
        return None
    try:
        import base64
        import win32crypt

        raw_text = dpapi_path.read_text(encoding="utf-8", errors="replace").strip()
        if not raw_text:
            return None
        cipher_bytes = base64.b64decode(raw_text)
        _, plain_bytes = win32crypt.CryptUnprotectData(cipher_bytes, None, None, None, 0)
        return plain_bytes.decode("utf-8").strip()
    except Exception:
        pass
    return None


def _load_secret_from_env_files() -> str | None:
    """Load owner console master secret from environment, DPAPI file, or local .env without logging."""
    env_override = os.getenv("WINDOWS_MCP_CONSOLE_SECRET", "").strip()
    if env_override:
        return env_override

    dpapi_secret = _decrypt_dpapi_file(DEFAULT_CONSOLE_DPAPI_FILE)
    if dpapi_secret:
        return dpapi_secret

    for env_key in ("MCP_AUTH_TOKEN", "MCP_AGENT_APPROVAL_TOKEN", "COMPUTER_API_TOKEN"):
        val = os.getenv(env_key, "").strip()
        if val:
            return val

    for env_path in (PROJECT_ROOT / "backend" / ".env", PROJECT_ROOT / ".env", DEFAULT_BACKEND_ENV_FILE):
        if not env_path.exists():
            continue
        try:
            for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("\"'")
                if k in ("WINDOWS_MCP_CONSOLE_SECRET", "MCP_AUTH_TOKEN", "MCP_AGENT_APPROVAL_TOKEN", "COMPUTER_API_TOKEN") and v:
                    return v
        except OSError:
            continue
    return None


def _is_no_auth_enabled() -> bool:
    """Return True if password-free mode is enabled via environment or .env file.

    DEPRECATED / PROHIBITED: Zero-trust owner policy strictly prohibits password-free
    unauthenticated owner mode escalation. Always returns False.
    """
    return False


@dataclass
class WebConsoleAuthSession:
    web_session_id: str
    cookie_token: str
    csrf_token: str
    created_at: float
    expires_at: float
    client_ip: str
    revoked: bool = False

    def is_valid(self, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
        return (not self.revoked) and (ts < self.expires_at)


@dataclass
class OperationProposal:
    proposal_id: str
    tool_name: str
    tier: str
    raw_arguments: dict[str, Any]
    redacted_arguments: dict[str, Any]
    rationale: str
    preview: dict[str, Any]
    status: str = "PENDING_OWNER_APPROVAL"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decided_at: str | None = None
    decided_by_session_id: str | None = None
    rejection_reason: str | None = None
    execution_result: Any = None
    error_message: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "tool_name": self.tool_name,
            "tier": self.tier,
            "arguments": self.redacted_arguments,
            "rationale": self.rationale,
            "preview": self.preview,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "decided_by_session_id": self.decided_by_session_id,
            "rejection_reason": self.rejection_reason,
            "execution_result": self.execution_result,
            "error_message": self.error_message,
        }


@dataclass
class AgentPlanStep:
    step_id: str
    description: str
    tool_name: str
    arguments: dict[str, Any]
    max_retries: int = 2
    verify_path_exists: str | None = None
    verify_contains: str | None = None
    status: str = "PENDING"
    attempts: int = 0
    output: Any = None
    error: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "tool_name": self.tool_name,
            "arguments": redact_secrets(self.arguments),
            "max_retries": self.max_retries,
            "verify_path_exists": self.verify_path_exists,
            "verify_contains": self.verify_contains,
            "status": self.status,
            "attempts": self.attempts,
            "output": redact_secrets(self.output) if isinstance(self.output, (dict, list)) else self.output,
            "error": redact_secrets(self.error) if self.error else None,
        }


@dataclass
class AgentPlan:
    plan_id: str
    title: str
    workspace_root: str
    steps: list[AgentPlanStep]
    status: str = "PENDING_OWNER_APPROVAL"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approved_at: str | None = None
    executed_at: str | None = None
    backup_snapshots: dict[str, str | None] = field(default_factory=dict)
    execution_logs: list[str] = field(default_factory=list)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "title": self.title,
            "workspace_root": self.workspace_root,
            "status": self.status,
            "created_at": self.created_at,
            "approved_at": self.approved_at,
            "executed_at": self.executed_at,
            "steps": [s.to_public_dict() for s in self.steps],
            "execution_logs": [redact_secrets(log) for log in self.execution_logs],
            "backup_snapshots_count": len(self.backup_snapshots),
        }


def _serialize_control_session(sess: ControlSession) -> dict[str, Any]:
    now = time.time()
    return {
        "session_id": sess.session_id,
        "tiers": sorted(t.value for t in sess.tiers),
        "created_at": sess.created_at,
        "expires_at": sess.expires_at,
        "remaining_seconds": max(0, int(sess.expires_at - now)) if not sess.revoked else 0,
        "active": sess.is_active(now=now),
        "client_id": sess.client_id,
        "allowed_paths": [str(p) for p in sess.allowed_paths] if sess.allowed_paths is not None else None,
        "allowed_commands": list(sess.allowed_commands) if sess.allowed_commands is not None else None,
        "allowed_tools": sorted(sess.allowed_tools) if sess.allowed_tools is not None else None,
        "revoked": sess.revoked,
        "revoked_reason": sess.revoked_reason,
    }


def _compute_proposal_preview(
    gw: MCPGatewayServer,
    tool_name: str,
    args: dict[str, Any],
) -> dict[str, Any]:
    """Generate a non-mutating preview (unified diff, command summary, or GUI action summary)."""
    tier = TOOL_TIER_MAP.get(tool_name, PermissionTier.READ)
    if tool_name in ("write_file", "edit_file", "append_file", "apply_patch", "delete_file") and "path" in args:
        raw_path = args.get("path")
        try:
            resolved = gw.policy.validate_path(
                raw_path,
                tier=PermissionTier.WRITE,
                check_content=False,
                must_exist=False,
            )
            before_text = ""
            exists = resolved.exists() and resolved.is_file()
            if exists:
                try:
                    before_text, _ = detect_encoding_and_decode(resolved.read_bytes())
                except Exception:
                    before_text = "[binary or unreadable file]"

            after_text = before_text
            if tool_name == "write_file":
                after_text = str(args.get("content", ""))
            elif tool_name == "append_file":
                after_text = before_text + str(args.get("content", ""))
            elif tool_name == "edit_file":
                old_t = str(args.get("old_text", ""))
                new_t = str(args.get("new_text", ""))
                if old_t and old_t in before_text:
                    after_text = before_text.replace(old_t, new_t)
            elif tool_name == "delete_file":
                after_text = ""

            diff_lines = list(
                difflib.unified_diff(
                    before_text.splitlines(keepends=True),
                    after_text.splitlines(keepends=True),
                    fromfile=f"a/{resolved.name}" if exists else "/dev/null",
                    tofile="/dev/null" if tool_name == "delete_file" else f"b/{resolved.name}",
                    n=3,
                )
            )
            diff_str = "".join(diff_lines)[:12000]
            return {
                "type": "file_diff",
                "target_path": str(resolved),
                "exists_before": exists,
                "unified_diff": redact_secrets(diff_str),
            }
        except Exception as exc:
            return {
                "type": "file_diff_error",
                "target_path": str(raw_path),
                "warning": redact_secrets(str(exc)),
            }

    if tool_name in ("powershell_execute", "cmd_execute", "process_start", "job_create"):
        return {
            "type": "command_preview",
            "command": redact_secrets(str(args.get("command", ""))),
            "cwd": str(args.get("cwd", "")),
            "timeout_seconds": args.get("timeout_seconds"),
        }

    if tier == PermissionTier.DESKTOP:
        return {
            "type": "desktop_action_preview",
            "action": tool_name,
            "parameters": redact_secrets(args),
        }

    return {
        "type": "tool_preview",
        "tool_name": tool_name,
        "tier": tier.value,
        "parameters": redact_secrets(args),
    }


def _parse_allowed_hosts(extra_hosts: list[str] | set[str] | None = None) -> frozenset[str]:
    hosts = set(ALLOWED_LOOPBACK_HOSTS)
    env_hosts = os.getenv("MCP_CONSOLE_ALLOWED_HOSTS", "").strip()
    if env_hosts:
        for h in env_hosts.split(","):
            h_clean = h.strip().lower()
            if h_clean:
                hosts.add(h_clean)
    if extra_hosts:
        for h in extra_hosts:
            h_clean = str(h).strip().lower()
            if h_clean:
                hosts.add(h_clean)
    return frozenset(hosts)


def _verify_request_host(request: Request, allowed_hosts: frozenset[str]) -> tuple[bool, str]:
    """Ensure Host header exists and matches the allowed hostnames allowlist (DNS rebinding protection)."""
    raw_host = request.headers.get("host") or ""
    if not raw_host:
        return False, "Missing Host header (DNS rebinding protection)"
    host_clean = raw_host.split(":", 1)[0].strip().lower()
    if host_clean.startswith("[") and host_clean.endswith("]"):
        host_clean = host_clean[1:-1]
    if host_clean not in allowed_hosts and f"[{host_clean}]" not in allowed_hosts:
        return False, f"Invalid or untrusted Host header '{raw_host}' (DNS rebinding protection)"
    return True, "ok"


def _verify_loopback_origin(
    request: Request,
    allowed_hosts: frozenset[str] = ALLOWED_LOOPBACK_HOSTS,
    allowed_origins: frozenset[str] | None = None,
) -> tuple[bool, str]:
    """Ensure Origin and Referer headers (when present) strictly originate from allowed origins/hosts."""
    origin = request.headers.get("origin")
    if origin is not None:
        origin_clean = origin.strip()
        if not origin_clean or origin_clean.lower() == "null":
            return False, "Rejected null or empty Origin header"
        if allowed_origins and origin_clean in allowed_origins:
            pass
        else:
            parsed = urllib.parse.urlparse(origin_clean)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or (host not in allowed_hosts and f"[{host}]" not in allowed_hosts):
                return False, f"Cross-origin request rejected from Origin '{origin_clean}'"

    referer = request.headers.get("referer")
    if referer is not None:
        ref_clean = referer.strip()
        if ref_clean:
            if allowed_origins and any(ref_clean.startswith(ao) for ao in allowed_origins):
                pass
            else:
                parsed_ref = urllib.parse.urlparse(ref_clean)
                ref_host = (parsed_ref.hostname or "").lower()
                if parsed_ref.scheme not in ("http", "https") or (ref_host not in allowed_hosts and f"[{ref_host}]" not in allowed_hosts):
                    return False, f"Cross-origin request rejected from Referer '{ref_clean}'"

    return True, "ok"


CONSOLE_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WinOwner MCP — Mode B Owner Control Console</title>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #131b2e;
      --panel-alt: #19233c;
      --border: #2a395c;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --success: #22c55e;
      --warn: #f59e0b;
      --danger: #ef4444;
      --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
      --mono: 'Cascadia Code', 'Consolas', monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.5;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 20px;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 16px;
    }
    .badge {
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      background: var(--panel-alt);
      border: 1px solid var(--border);
      color: var(--accent);
    }
    .badge.warn { color: var(--warn); border-color: var(--warn); }
    .badge.danger { color: #fff; background: var(--danger); border-color: var(--danger); }
    .badge.success { color: var(--success); border-color: var(--success); }
    .top-controls {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    button {
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      padding: 7px 13px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 13px;
      transition: filter 0.15s;
    }
    button:hover { filter: brightness(1.15); }
    button.primary { background: #0284c7; border-color: #38bdf8; color: #fff; }
    button.success { background: #15803d; border-color: #22c55e; color: #fff; }
    button.warn { background: #b45309; border-color: #f59e0b; color: #fff; }
    button.danger {
      background: #dc2626;
      border-color: #f87171;
      color: #fff;
      font-weight: 700;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 16px;
      padding: 18px;
      max-width: 1600px;
      margin: 0 auto;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .col-4 { grid-column: span 4; }
    .col-6 { grid-column: span 6; }
    .col-8 { grid-column: span 8; }
    .col-12 { grid-column: span 12; }
    @media (max-width: 1100px) {
      .col-4, .col-6, .col-8 { grid-column: span 12; }
    }
    h2 {
      margin: 0 0 12px 0;
      font-size: 15px;
      color: var(--accent);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    label {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 4px;
    }
    input, select, textarea {
      width: 100%;
      padding: 8px 10px;
      background: #090d16;
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
      font-family: var(--mono);
      font-size: 12px;
      margin-bottom: 10px;
    }
    textarea { min-height: 76px; resize: vertical; }
    pre {
      background: #070a12;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      overflow: auto;
      max-height: 280px;
      font-family: var(--mono);
      font-size: 12px;
      margin: 8px 0 0 0;
      white-space: pre-wrap;
    }
    .proposal-item {
      border: 1px solid var(--border);
      background: var(--panel-alt);
      border-radius: 6px;
      padding: 10px;
      margin-bottom: 10px;
    }
    .proposal-actions {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }
    #login-overlay {
      position: fixed;
      inset: 0;
      background: rgba(8, 12, 22, 0.92);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
    }
    .login-box {
      width: 400px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
    }
    .hidden { display: none !important; }
    .notice {
      font-size: 12px;
      color: var(--muted);
      padding: 8px 10px;
      background: #0d1322;
      border-left: 3px solid var(--accent);
      margin-bottom: 10px;
    }
  </style>
</head>
<body>
  <div id="login-overlay">
    <div class="login-box">
      <h2>Owner Authentication (Mode B)</h2>
      <p class="notice">
        Local-first Owner-Controlled Web Agent Console. Credentials are verified via HMAC on loopback
        and bound to an HttpOnly SameSite=Strict cookie + in-memory CSRF token.
      </p>
      <label for="owner-password">Owner Console Secret / Master Token</label>
      <input type="password" id="owner-password" placeholder="Enter WINDOWS_MCP_CONSOLE_SECRET" autocomplete="current-password" />
      <div id="login-error" style="color: var(--danger); font-size: 12px; margin-bottom: 8px;"></div>
      <button class="primary" style="width: 100%;" onclick="loginOwner()">Sign In to Local Control Surface</button>
    </div>
  </div>

  <header>
    <div class="brand">
      <span>WinOwner MCP — Mode B Console</span>
      <span id="profile-badge" class="badge">Profile: loading...</span>
      <span id="session-badge" class="badge warn">No Active ControlSession</span>
      <span id="estop-badge" class="badge success">Emergency Stop: READY</span>
    </div>
    <div class="top-controls">
      <button class="warn" onclick="revokeAllSessions()">Revoke All Sessions</button>
      <button class="danger" onclick="triggerEmergencyStop()">EMERGENCY STOP</button>
      <button onclick="resetEmergencyStop()">Reset E-Stop</button>
      <button onclick="logoutOwner()">Logout</button>
    </div>
  </header>

  <div class="grid">
    <!-- 1. ControlSession Approval -->
    <div class="card col-4">
      <h2>1. Approve Bounded ControlSession</h2>
      <label>Capability Tiers (comma-separated)</label>
      <input type="text" id="sess-tiers" value="READ,WRITE,EXECUTE,DESKTOP" />
      <label>TTL Seconds (max 28800)</label>
      <input type="number" id="sess-ttl" value="900" />
      <label>Allowed Paths Scope (one per line, optional)</label>
      <textarea id="sess-paths" placeholder="D:\\ProjectsWindows-MCP-Agent"></textarea>
      <label>Allowed Command Prefixes (comma-separated, optional)</label>
      <input type="text" id="sess-cmds" placeholder="python,pytest,git,Write-Output" />
      <div style="display:flex; gap:8px;">
        <button class="success" onclick="approveSession()">Approve ControlSession</button>
        <button onclick="revokeActiveSession()">Revoke Current</button>
      </div>
      <pre id="session-output">No active ControlSession approved yet.</pre>
    </div>

    <!-- 2. Human-in-the-Loop Proposal Queue -->
    <div class="card col-8">
      <h2>
        <span>2. Pending Operation Proposals (Human-in-the-Loop Queue)</span>
        <button onclick="refreshProposals()">Refresh Queue</button>
      </h2>
      <div class="notice">
        Model suggestions and proposed edits wait in <strong>PENDING_OWNER_APPROVAL</strong> state.
        Review the unified diff or command preview before clicking <strong>Approve &amp; Execute</strong>.
      </div>
      <div style="display:grid; grid-template-columns: 1fr 2fr 1fr; gap:8px;">
        <div>
          <label>Proposed Tool</label>
          <input type="text" id="prop-tool" value="write_file" />
        </div>
        <div>
          <label>Arguments (JSON)</label>
          <input type="text" id="prop-args" value='{"path":"D:\\\\ProjectsWindows-MCP-Agent\\\\runtime\\\\notes.txt","content":"Hello\\n"}' />
        </div>
        <div>
          <label>Rationale</label>
          <input type="text" id="prop-rationale" value="Update notes file" />
        </div>
      </div>
      <button class="primary" onclick="createProposal()">Create Pending Proposal (Preview Only)</button>
      <div id="proposals-list" style="margin-top:12px;"></div>
    </div>

    <!-- 3. File & Git Inspector / Safe Edit -->
    <div class="card col-6">
      <h2>3. File, Diff &amp; Git Operations</h2>
      <label>Target File or Directory Path</label>
      <input type="text" id="file-path" value="D:\\ProjectsWindows-MCP-Agent" />
      <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">
        <button onclick="runDirectTool('list_directory', {path: val('file-path')})">List Dir</button>
        <button onclick="runDirectTool('read_file', {path: val('file-path')})">Read File</button>
        <button onclick="runDirectTool('git_status', {cwd: val('file-path')})">Git Status</button>
        <button onclick="runDirectTool('git_diff', {cwd: val('file-path')})">Git Diff</button>
        <button onclick="runDirectTool('git_log', {cwd: val('file-path'), n: 5})">Git Log</button>
      </div>
      <pre id="file-output">Ready for file/git inspection.</pre>
    </div>

    <!-- 4. Approved Command & Job Runner -->
    <div class="card col-6">
      <h2>4. Approved Command &amp; Background Job Runner</h2>
      <label>Working Directory (cwd)</label>
      <input type="text" id="exec-cwd" value="D:\\ProjectsWindows-MCP-Agent" />
      <label>PowerShell Command</label>
      <input type="text" id="exec-cmd" value="Write-Output 'Hello from Mode B Console'" />
      <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">
        <button class="primary" onclick="runDirectTool('powershell_execute', {command: val('exec-cmd'), cwd: val('exec-cwd')})">Run PowerShell</button>
        <button onclick="runDirectTool('job_create', {command: val('exec-cmd'), cwd: val('exec-cwd')})">Start Background Job</button>
      </div>
      <pre id="exec-output">Requires active EXECUTE ControlSession.</pre>
    </div>

    <!-- 5. Desktop Screenshot & Safe GUI Verification -->
    <div class="card col-6">
      <h2>5. Desktop Visual Control &amp; Screenshot</h2>
      <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">
        <button class="primary" onclick="captureScreenshot()">Capture Desktop Screenshot</button>
        <button onclick="runDirectTool('get_screen_geometry', {})">Screen Geometry</button>
        <button onclick="runDirectTool('list_windows', {max_results: 15})">List Windows</button>
        <button onclick="runDirectTool('get_desktop_session_status', {})">Session Status</button>
      </div>
      <img id="screenshot-img" alt="Screenshot preview" style="max-width:100%; border-radius:6px; border:1px solid var(--border); display:none; margin-top:8px;" />
      <pre id="desktop-output">Ready for desktop inspection.</pre>
    </div>

    <!-- 6. Redacted Audit Log & Optional OpenAI Assistant Connector -->
    <div class="card col-6">
      <h2>
        <span>6. Live Redacted Audit Log</span>
        <button onclick="refreshAudit()">Refresh Audit</button>
      </h2>
      <div class="notice">
        Optional OpenAI Responses API suggestions create <strong>PENDING_OWNER_APPROVAL</strong> proposals only
        (billed separately via OpenAI API credits if <code>OPENAI_API_KEY</code> is configured).
      </div>
      <pre id="audit-output">Loading audit entries...</pre>
    </div>
  </div>

  <script>
    // In-memory state ONLY — never persisted in localStorage or sessionStorage
    let csrfToken = null;
    let activeSessionId = null;

    function val(id) { return document.getElementById(id).value.trim(); }

    async function apiCall(path, method = 'GET', body = null) {
      const headers = { 'Accept': 'application/json' };
      if (csrfToken && method !== 'GET') {
        headers['X-CSRF-Token'] = csrfToken;
      }
      if (body !== null) {
        headers['Content-Type'] = 'application/json';
      }
      const res = await fetch(path, {
        method,
        headers,
        credentials: 'same-origin',
        body: body !== null ? JSON.stringify(body) : null
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || ('HTTP ' + res.status));
      }
      return data;
    }

    async function loginOwner() {
      const pwd = document.getElementById('owner-password').value;
      const errEl = document.getElementById('login-error');
      errEl.textContent = '';
      try {
        const res = await apiCall('/console/api/login', 'POST', { password: pwd });
        csrfToken = res.csrf_token;
        document.getElementById('owner-password').value = '';
        document.getElementById('login-overlay').classList.add('hidden');
        await refreshStatus();
        await refreshProposals();
        await refreshAudit();
      } catch (e) {
        errEl.textContent = e.message;
      }
    }

    async function logoutOwner() {
      try {
        await apiCall('/console/api/logout', 'POST', {});
      } catch (_) {}
      csrfToken = null;
      activeSessionId = null;
      document.getElementById('login-overlay').classList.remove('hidden');
    }

    async function refreshStatus() {
      const st = await apiCall('/console/api/status', 'GET');
      document.getElementById('profile-badge').textContent = 'Profile: ' + st.profile + ' (' + st.enabled_tiers.join(',') + ')';
      const estopBadge = document.getElementById('estop-badge');
      if (st.emergency_stop) {
        estopBadge.textContent = 'EMERGENCY STOP ENGAGED';
        estopBadge.className = 'badge danger';
      } else {
        estopBadge.textContent = 'Emergency Stop: READY';
        estopBadge.className = 'badge success';
      }
    }

    async function approveSession() {
      try {
        const tiers = val('sess-tiers').split(',').map(s => s.trim()).filter(Boolean);
        const ttl = parseInt(val('sess-ttl') || '900', 10);
        const pathsRaw = val('sess-paths').split('\\n').map(s => s.trim()).filter(Boolean);
        const cmdsRaw = val('sess-cmds').split(',').map(s => s.trim()).filter(Boolean);
        const payload = {
          tiers,
          ttl_seconds: ttl,
          allowed_paths: pathsRaw.length ? pathsRaw : null,
          allowed_commands: cmdsRaw.length ? cmdsRaw : null
        };
        const res = await apiCall('/console/api/sessions/approve', 'POST', payload);
        activeSessionId = res.session.session_id;
        const badge = document.getElementById('session-badge');
        badge.textContent = 'Session: ' + activeSessionId + ' (' + res.session.tiers.join(',') + ')';
        badge.className = 'badge success';
        document.getElementById('session-output').textContent = JSON.stringify(res.session, null, 2);
        await refreshAudit();
      } catch (e) {
        document.getElementById('session-output').textContent = 'Error: ' + e.message;
      }
    }

    async function revokeActiveSession() {
      if (!activeSessionId) return;
      try {
        const res = await apiCall('/console/api/sessions/' + encodeURIComponent(activeSessionId) + '/revoke', 'POST', { reason: 'owner_ui_revoke' });
        activeSessionId = null;
        const badge = document.getElementById('session-badge');
        badge.textContent = 'No Active ControlSession';
        badge.className = 'badge warn';
        document.getElementById('session-output').textContent = JSON.stringify(res, null, 2);
        await refreshAudit();
      } catch (e) {
        document.getElementById('session-output').textContent = 'Error: ' + e.message;
      }
    }

    async function revokeAllSessions() {
      try {
        const res = await apiCall('/console/api/sessions/revoke-all', 'POST', { reason: 'owner_ui_revoke_all' });
        activeSessionId = null;
        const badge = document.getElementById('session-badge');
        badge.textContent = 'No Active ControlSession';
        badge.className = 'badge warn';
        document.getElementById('session-output').textContent = JSON.stringify(res, null, 2);
        await refreshAudit();
      } catch (e) {
        alert('Error: ' + e.message);
      }
    }

    async function triggerEmergencyStop() {
      try {
        const res = await apiCall('/console/api/emergency-stop', 'POST', { reason: 'owner_ui_emergency_stop' });
        activeSessionId = null;
        await refreshStatus();
        await refreshProposals();
        await refreshAudit();
        document.getElementById('session-output').textContent = JSON.stringify(res, null, 2);
      } catch (e) {
        alert('Emergency Stop Error: ' + e.message);
      }
    }

    async function resetEmergencyStop() {
      try {
        await apiCall('/console/api/emergency-stop/reset', 'POST', {});
        await refreshStatus();
        await refreshAudit();
      } catch (e) {
        alert('Reset Error: ' + e.message);
      }
    }

    async function createProposal() {
      try {
        const tool_name = val('prop-tool');
        const args = JSON.parse(val('prop-args') || '{}');
        const rationale = val('prop-rationale');
        await apiCall('/console/api/proposals', 'POST', { tool_name, arguments: args, rationale });
        await refreshProposals();
        await refreshAudit();
      } catch (e) {
        alert('Proposal Error: ' + e.message);
      }
    }

    async function refreshProposals() {
      try {
        const res = await apiCall('/console/api/proposals', 'GET');
        const container = document.getElementById('proposals-list');
        container.innerHTML = '';
        for (const p of res.proposals) {
          const div = document.createElement('div');
          div.className = 'proposal-item';
          const header = document.createElement('div');
          header.innerHTML = '<strong>' + p.proposal_id + '</strong> — <code>' + p.tool_name + '</code> [' + p.tier + '] — Status: <strong>' + p.status + '</strong>';
          const pre = document.createElement('pre');
          pre.textContent = JSON.stringify({ arguments: p.arguments, preview: p.preview, result: p.execution_result, error: p.error_message }, null, 2);
          div.appendChild(header);
          div.appendChild(pre);
          if (p.status === 'PENDING_OWNER_APPROVAL') {
            const actions = document.createElement('div');
            actions.className = 'proposal-actions';
            const btnApprove = document.createElement('button');
            btnApprove.className = 'success';
            btnApprove.textContent = 'Approve & Execute';
            btnApprove.onclick = () => executeProposal(p.proposal_id);
            const btnReject = document.createElement('button');
            btnReject.className = 'danger';
            btnReject.textContent = 'Reject';
            btnReject.onclick = () => rejectProposal(p.proposal_id);
            actions.appendChild(btnApprove);
            actions.appendChild(btnReject);
            div.appendChild(actions);
          }
          container.appendChild(div);
        }
      } catch (_) {}
    }

    async function executeProposal(proposalId) {
      try {
        await apiCall('/console/api/proposals/' + encodeURIComponent(proposalId) + '/execute', 'POST', {
          session_id: activeSessionId
        });
      } catch (e) {
        alert('Execution Rejected: ' + e.message);
      }
      await refreshProposals();
      await refreshAudit();
    }

    async function rejectProposal(proposalId) {
      try {
        await apiCall('/console/api/proposals/' + encodeURIComponent(proposalId) + '/reject', 'POST', {
          reason: 'Rejected by owner in web console'
        });
        await refreshProposals();
        await refreshAudit();
      } catch (e) {
        alert('Reject Error: ' + e.message);
      }
    }

    async function runDirectTool(tool_name, args) {
      const targetOut = tool_name.startsWith('powershell') || tool_name.startsWith('job_')
        ? 'exec-output'
        : (tool_name.includes('window') || tool_name.includes('screen') || tool_name.includes('desktop') ? 'desktop-output' : 'file-output');
      try {
        const res = await apiCall('/console/api/execute', 'POST', {
          tool_name,
          arguments: args,
          session_id: activeSessionId
        });
        document.getElementById(targetOut).textContent = JSON.stringify(res.result, null, 2);
        await refreshAudit();
      } catch (e) {
        document.getElementById(targetOut).textContent = 'Blocked/Error: ' + e.message;
      }
    }

    async function captureScreenshot() {
      try {
        const q = activeSessionId ? ('?session_id=' + encodeURIComponent(activeSessionId)) : '';
        const res = await apiCall('/console/api/screenshot' + q, 'GET');
        const img = document.getElementById('screenshot-img');
        if (res.data_base64) {
          img.src = 'data:image/png;base64,' + res.data_base64;
          img.style.display = 'block';
        }
        const meta = Object.assign({}, res);
        delete meta.data_base64;
        delete meta.mcp_content;
        document.getElementById('desktop-output').textContent = JSON.stringify(meta, null, 2);
        await refreshAudit();
      } catch (e) {
        document.getElementById('desktop-output').textContent = 'Screenshot Error: ' + e.message;
      }
    }

    async function refreshAudit() {
      try {
        const res = await apiCall('/console/api/audit?limit=40', 'GET');
        document.getElementById('audit-output').textContent = JSON.stringify(res.entries, null, 2);
      } catch (_) {}
    }

    window.addEventListener('DOMContentLoaded', async () => {
      try {
        const res = await apiCall('/console/api/status', 'GET').catch(() => null);
        if (res && res.authenticated) {
          document.getElementById('login-overlay').classList.add('hidden');
          await refreshStatus();
          await refreshProposals();
          await refreshAudit();
        }
      } catch (_) {}
    });
  </script>
</body>
</html>
"""


def create_web_console_app(
    *,
    profile: str = "full_agent",
    policy_path: str | Path | None = None,
    gateway: MCPGatewayServer | None = None,
    owner_password: str | None = None,
    no_auth: bool | None = None,
    rate_limit_max_failures: int = 5,
    rate_limit_window_seconds: int = 60,
    session_cookie_ttl_seconds: int = 14400,
    allowed_hosts: list[str] | set[str] | None = None,
    allowed_origins: list[str] | set[str] | None = None,
    trust_proxy_headers: bool = False,
    max_concurrent_sessions: int = 5,
    task_store: Any | None = None,
    grant_broker: Any | None = None,
) -> FastAPI:
    """Create the Mode B Owner-Controlled Web Agent Console ASGI application."""
    if gateway is not None:
        gw = gateway
    else:
        pol = SecurityPolicy(policy_path=policy_path, profile=profile)
        gw = MCPGatewayServer(policy=pol)

    hosts_allowlist = _parse_allowed_hosts(allowed_hosts)
    origins_allowlist = frozenset(str(o).strip() for o in allowed_origins) if allowed_origins else None
    trust_proxy = trust_proxy_headers or bool(os.getenv("MCP_CONSOLE_TRUST_PROXY", "").strip() in ("1", "true", "yes"))

    if no_auth is True:
        raise PermissionError(
            "Password-free no_auth mode is prohibited on Owner Web Console; verified owner authentication is required"
        )
    no_auth_active = False

    resolved_secret = (
        owner_password
        if (owner_password is not None and owner_password.strip())
        else (_load_secret_from_env_files() or secrets.token_urlsafe(32))
    )
    cookie_signing_key = secrets.token_bytes(32)

    lock = threading.Lock()
    web_sessions: dict[str, WebConsoleAuthSession] = {}
    proposals: dict[str, OperationProposal] = {}
    plans: dict[str, AgentPlan] = {}
    failed_login_attempts: dict[str, list[float]] = {}

    app = FastAPI(
        title="WinOwner MCP — Mode B Owner Web Console",
        version=gw.server_version,
        docs_url=None,
        redoc_url=None,
    )
    app.state.gateway = gw

    @app.middleware("http")
    async def add_security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def _sign_session_id(web_session_id: str) -> str:
        sig = hmac.new(cookie_signing_key, web_session_id.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{web_session_id}.{sig}"

    default_noauth_session = WebConsoleAuthSession(
        web_session_id="local_owner_session",
        cookie_token=_sign_session_id("local_owner_session"),
        csrf_token=secrets.token_urlsafe(32),
        created_at=time.time(),
        expires_at=time.time() + 86400 * 365,
        client_ip="127.0.0.1",
        revoked=False,
    )
    if no_auth_active:
        with lock:
            web_sessions[default_noauth_session.web_session_id] = default_noauth_session

    def _verify_cookie_token(cookie_value: str | None) -> WebConsoleAuthSession | None:
        if not cookie_value or "." not in cookie_value:
            return None
        web_session_id, provided_sig = cookie_value.split(".", 1)
        expected_sig = hmac.new(cookie_signing_key, web_session_id.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            return None
        with lock:
            ws = web_sessions.get(web_session_id)
        if ws is None or not ws.is_valid():
            return None
        return ws

    def _authenticate_request(
        request: Request,
        *,
        require_csrf: bool = False,
    ) -> tuple[WebConsoleAuthSession | None, JSONResponse | None]:
        ok_host, host_reason = _verify_request_host(request, hosts_allowlist)
        if not ok_host:
            gw.policy.audit.log_event(
                tool_name="web_console_host_guard",
                tier="SECURITY",
                decision="DENY",
                reason=host_reason,
                arguments={"path": str(request.url.path), "host": request.headers.get("host")},
            )
            return None, JSONResponse(status_code=403, content={"error": host_reason})

        ok_origin, origin_reason = _verify_loopback_origin(request, hosts_allowlist, origins_allowlist)
        if not ok_origin:
            gw.policy.audit.log_event(
                tool_name="web_console_origin_guard",
                tier="SECURITY",
                decision="DENY",
                reason=origin_reason,
                arguments={"path": str(request.url.path)},
            )
            return None, JSONResponse(status_code=403, content={"error": origin_reason})

        cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
        ws = _verify_cookie_token(cookie_val)
        if ws is None and no_auth_active:
            ws = default_noauth_session
        if ws is None:
            gw.policy.audit.log_event(
                tool_name="web_console_auth_guard",
                tier="SECURITY",
                decision="DENY",
                reason="Missing, expired, or invalid web console session cookie",
                arguments={"path": str(request.url.path), "method": request.method},
            )
            return None, JSONResponse(
                status_code=401,
                content={"error": "Unauthorized: valid owner web console session required"},
            )

        if require_csrf:
            csrf_hdr = (request.headers.get("x-csrf-token") or "").strip()
            if not csrf_hdr or not hmac.compare_digest(
                csrf_hdr.encode("utf-8"), ws.csrf_token.encode("utf-8")
            ):
                gw.policy.audit.log_event(
                    tool_name="web_console_csrf_guard",
                    tier="SECURITY",
                    decision="DENY",
                    reason="Missing or mismatched X-CSRF-Token header",
                    arguments={"path": str(request.url.path), "method": request.method},
                )
                return None, JSONResponse(
                    status_code=403,
                    content={"error": "Forbidden: missing or invalid X-CSRF-Token header"},
                )

        return ws, None

    # ------------------------------------------------------------------
    # Public Health & UI Shell Routes
    # ------------------------------------------------------------------
    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "mode-b-owner-web-console",
            "server": gw.server_name,
            "version": gw.server_version,
            "profile": gw.policy.profile,
            "enabled_tiers": sorted(t.value for t in gw.policy.enabled_tiers),
            "emergency_stop": gw.policy.is_emergency_stop_active(),
            "tools_count": len(gw.exposed_tool_names()),
        }

    @app.get("/", response_class=HTMLResponse)
    @app.get("/console", response_class=HTMLResponse)
    async def console_ui() -> Response:
        html = CONSOLE_HTML_PAGE
        if no_auth_active:
            html = html.replace('id="login-overlay"', 'id="login-overlay" class="hidden"')
            html = html.replace("let csrfToken = null;", f'let csrfToken = "{default_noauth_session.csrf_token}";')
        resp = HTMLResponse(
            content=html,
            status_code=200,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",
            },
        )
        if no_auth_active:
            resp.set_cookie(
                key=SESSION_COOKIE_NAME,
                value=default_noauth_session.cookie_token,
                httponly=True,
                samesite="strict",
                max_age=session_cookie_ttl_seconds,
                path="/",
            )
        return resp

    # ------------------------------------------------------------------
    # 1. Owner Authentication Endpoints
    # ------------------------------------------------------------------
    @app.post("/console/api/login")
    async def console_login(request: Request) -> Response:
        ok_host, host_reason = _verify_request_host(request, hosts_allowlist)
        if not ok_host:
            gw.policy.audit.log_event(
                tool_name="console_login",
                tier="SECURITY",
                decision="DENY",
                reason=host_reason,
                arguments={"host": request.headers.get("host")},
            )
            return JSONResponse(status_code=403, content={"error": host_reason})

        ok_origin, origin_reason = _verify_loopback_origin(request, hosts_allowlist, origins_allowlist)
        if not ok_origin:
            gw.policy.audit.log_event(
                tool_name="console_login",
                tier="SECURITY",
                decision="DENY",
                reason=origin_reason,
            )
            return JSONResponse(status_code=403, content={"error": origin_reason})

        if no_auth_active:
            resp = JSONResponse(
                status_code=200,
                content={
                    "authenticated": True,
                    "csrf_token": default_noauth_session.csrf_token,
                    "web_session_id": default_noauth_session.web_session_id,
                },
            )
            resp.set_cookie(
                key=SESSION_COOKIE_NAME,
                value=default_noauth_session.cookie_token,
                httponly=True,
                samesite="strict",
                max_age=session_cookie_ttl_seconds,
                path="/",
            )
            return resp

        client_ip = (request.client.host if request.client else None) or "127.0.0.1"
        now = time.time()

        with lock:
            history = [
                ts for ts in failed_login_attempts.get(client_ip, [])
                if (now - ts) < rate_limit_window_seconds
            ]
            failed_login_attempts[client_ip] = history
            if len(history) >= rate_limit_max_failures:
                gw.policy.audit.log_event(
                    tool_name="console_login",
                    tier="SECURITY",
                    decision="DENY",
                    reason=f"Rate limit exceeded for client {client_ip}",
                )
                return JSONResponse(
                    status_code=429,
                    content={"error": "Too many failed login attempts. Try again later."},
                )

        try:
            body = await request.json()
        except Exception:
            body = {}
        provided_password = str(body.get("password") or "")

        is_match = bool(
            provided_password
            and hmac.compare_digest(
                provided_password.encode("utf-8"),
                resolved_secret.encode("utf-8"),
            )
        )
        if not is_match:
            with lock:
                history = [
                    ts for ts in failed_login_attempts.get(client_ip, [])
                    if (now - ts) < rate_limit_window_seconds
                ]
                history.append(now)
                failed_login_attempts[client_ip] = history
            gw.policy.audit.log_event(
                tool_name="console_login",
                tier="SECURITY",
                decision="DENY",
                reason="Invalid owner password",
                arguments={"client_ip": client_ip},
            )
            return JSONResponse(status_code=401, content={"error": "Invalid owner credentials"})

        with lock:
            failed_login_attempts.pop(client_ip, None)
            # Enforce max concurrent sessions
            active_s = {sid: s for sid, s in web_sessions.items() if s.is_valid(now=now)}
            if len(active_s) >= max_concurrent_sessions:
                oldest_sid = min(active_s.keys(), key=lambda k: active_s[k].created_at)
                active_s[oldest_sid].revoked = True
                active_s.pop(oldest_sid, None)
            web_sessions.clear()
            web_sessions.update(active_s)

            web_session_id = f"wsess_{uuid.uuid4().hex}"
            cookie_token = _sign_session_id(web_session_id)
            csrf_token = secrets.token_urlsafe(32)
            ws = WebConsoleAuthSession(
                web_session_id=web_session_id,
                cookie_token=cookie_token,
                csrf_token=csrf_token,
                created_at=now,
                expires_at=now + session_cookie_ttl_seconds,
                client_ip=client_ip,
            )
            web_sessions[web_session_id] = ws

        gw.policy.audit.log_event(
            tool_name="console_login",
            tier="SECURITY",
            decision="ALLOW",
            reason="Owner authenticated to Mode B web console",
            result_summary={"web_session_id": web_session_id, "client_ip": client_ip},
        )

        is_https = (request.url.scheme == "https") or (
            trust_proxy and request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        resp = JSONResponse(
            status_code=200,
            content={
                "authenticated": True,
                "web_session_id": web_session_id,
                "csrf_token": csrf_token,
                "expires_at": ws.expires_at,
                "profile": gw.policy.profile,
                "enabled_tiers": sorted(t.value for t in gw.policy.enabled_tiers),
            },
        )
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=cookie_token,
            httponly=True,
            secure=is_https,
            samesite="strict",
            max_age=session_cookie_ttl_seconds,
            path="/",
        )
        return resp

    @app.post("/console/api/logout")
    async def console_logout(request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None or ws is None:
            return err_resp  # type: ignore[return-value]

        with lock:
            ws.revoked = True
            web_sessions.pop(ws.web_session_id, None)

        gw.policy.audit.log_event(
            tool_name="console_logout",
            tier="SECURITY",
            decision="ALLOW",
            reason="Owner logged out of Mode B web console",
            result_summary={"web_session_id": ws.web_session_id},
        )
        resp = JSONResponse(status_code=200, content={"authenticated": False, "logged_out": True})
        resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
        return resp

    @app.get("/console/api/web-sessions")
    async def list_web_sessions(request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None or ws is None:
            return err_resp
        now = time.time()
        with lock:
            active_list = [
                {
                    "web_session_id": s.web_session_id,
                    "created_at": s.created_at,
                    "expires_at": s.expires_at,
                    "client_ip": s.client_ip,
                    "is_current": s.web_session_id == ws.web_session_id,
                }
                for s in web_sessions.values()
                if s.is_valid(now=now)
            ]
        return JSONResponse(status_code=200, content={"web_sessions": active_list, "count": len(active_list)})

    @app.post("/console/api/web-sessions/revoke-others")
    async def revoke_other_web_sessions(request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None or ws is None:
            return err_resp
        revoked_count = 0
        with lock:
            for sid, s in list(web_sessions.items()):
                if sid != ws.web_session_id and s.is_valid():
                    s.revoked = True
                    web_sessions.pop(sid, None)
                    revoked_count += 1
        return JSONResponse(status_code=200, content={"revoked_count": revoked_count, "kept_session": ws.web_session_id})

    # ------------------------------------------------------------------
    # 2. Console Status & Available Tools
    # ------------------------------------------------------------------
    @app.get("/console/api/status")
    async def console_status(request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None or ws is None:
            return err_resp  # type: ignore[return-value]

        with gw.policy.sessions._lock:
            all_ctrl = list(gw.policy.sessions._sessions.values())
        active_ctrl = [_serialize_control_session(s) for s in all_ctrl if s.is_active()]
        with lock:
            pending_count = sum(1 for p in proposals.values() if p.status == "PENDING_OWNER_APPROVAL")

        return JSONResponse(
            status_code=200,
            content={
                "authenticated": True,
                "web_session_id": ws.web_session_id,
                "profile": gw.policy.profile,
                "enabled_tiers": sorted(t.value for t in gw.policy.enabled_tiers),
                "emergency_stop": gw.policy.is_emergency_stop_active(),
                "active_control_sessions": active_ctrl,
                "pending_proposals_count": pending_count,
                "openai_responses_api_configured": bool(os.getenv("OPENAI_API_KEY", "").strip()),
                "openai_billing_disclosure": OPENAI_BILLING_DISCLOSURE,
            },
        )

    @app.get("/console/api/tools")
    async def console_list_tools(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        tools = gw.list_tools()
        return JSONResponse(
            status_code=200,
            content={
                "profile": gw.policy.profile,
                "tools": [
                    {
                        "name": t["name"],
                        "tier": TOOL_TIER_MAP.get(t["name"], PermissionTier.READ).value,
                        "description": t["description"],
                        "input_schema": t["input_schema"],
                    }
                    for t in tools
                ],
                "count": len(tools),
            },
        )

    # ------------------------------------------------------------------
    # 3. ControlSession Approval & Revocation
    # ------------------------------------------------------------------
    @app.get("/console/api/sessions")
    async def list_control_sessions(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        with gw.policy.sessions._lock:
            all_sessions = list(gw.policy.sessions._sessions.values())
        return JSONResponse(
            status_code=200,
            content={
                "sessions": [_serialize_control_session(s) for s in all_sessions],
                "count": len(all_sessions),
            },
        )

    @app.post("/console/api/sessions/approve")
    async def approve_control_session(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        if gw.policy.is_emergency_stop_active():
            gw.policy.audit.log_event(
                tool_name="session_approve",
                tier="SECURITY",
                decision="DENY",
                reason="Cannot approve ControlSession while Emergency Stop is active",
            )
            return JSONResponse(
                status_code=403,
                content={"error": "Emergency stop is active: cannot approve new control sessions"},
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        raw_tiers = body.get("tiers") or ["READ"]
        ttl_seconds = int(body.get("ttl_seconds") or 900)
        allowed_paths = body.get("allowed_paths")
        allowed_commands = body.get("allowed_commands")
        allowed_tools = body.get("allowed_tools")

        try:
            parsed_tiers = [PermissionTier(t) for t in raw_tiers]
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": f"Invalid permission tier: {exc}"})

        for t in parsed_tiers:
            if t not in gw.policy.enabled_tiers:
                gw.policy.audit.log_event(
                    tool_name="session_approve",
                    tier=t,
                    decision="DENY",
                    reason=f"Requested tier '{t.value}' exceeds outer profile '{gw.policy.profile}'",
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": f"Tier '{t.value}' is not enabled in outer profile '{gw.policy.profile}'"
                    },
                )

        # Validate that any scoped allowed_paths are inside approved roots and not sensitive
        if allowed_paths is not None:
            if not isinstance(allowed_paths, list):
                return JSONResponse(status_code=400, content={"error": "allowed_paths must be a list of paths"})
            check_tier = PermissionTier.WRITE if PermissionTier.WRITE in parsed_tiers else PermissionTier.READ
            for p_item in allowed_paths:
                try:
                    gw.policy.validate_path(p_item, tier=check_tier, check_content=False, must_exist=False)
                except PermissionError as exc:
                    return JSONResponse(status_code=403, content={"error": str(exc)})

        try:
            ctrl_sess = gw.policy.sessions.create_session(
                tiers=parsed_tiers,
                ttl_seconds=ttl_seconds,
                client_id="web_console_owner",
                allowed_paths=allowed_paths,
                allowed_commands=allowed_commands,
                allowed_tools=allowed_tools,
            )
        except (ValueError, PermissionError) as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

        serialized = _serialize_control_session(ctrl_sess)
        gw.policy.audit.log_event(
            tool_name="session_approve",
            tier=",".join(sorted(t.value for t in ctrl_sess.tiers)),
            decision="ALLOW",
            reason="Owner approved scoped ControlSession via Mode B Web Console",
            session_id=ctrl_sess.session_id,
            result_summary=serialized,
        )
        return JSONResponse(status_code=200, content={"approved": True, "session": serialized})

    @app.post("/console/api/sessions/revoke-all")
    async def revoke_all_control_sessions(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = str(body.get("reason") or "owner_web_console_revoke_all")
        count = gw.policy.sessions.revoke_all(reason=reason)
        gw.policy.audit.log_event(
            tool_name="session_revoke_all",
            tier="SECURITY",
            decision="ALLOW",
            reason=reason,
            result_summary={"revoked_count": count},
        )
        return JSONResponse(
            status_code=200,
            content={"revoked_all": True, "revoked_count": count, "reason": reason},
        )

    @app.post("/console/api/sessions/{session_id}/revoke")
    async def revoke_single_control_session(session_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = str(body.get("reason") or "owner_web_console_manual_revoke")
        ok = gw.policy.sessions.revoke_session(session_id, reason=reason)
        if not ok:
            return JSONResponse(status_code=404, content={"error": f"Unknown session: {session_id}"})
        gw.policy.audit.log_event(
            tool_name="session_revoke",
            tier="SECURITY",
            decision="ALLOW",
            reason=reason,
            session_id=session_id,
        )
        return JSONResponse(
            status_code=200,
            content={"revoked": True, "session_id": session_id, "reason": reason},
        )

    # ------------------------------------------------------------------
    # 4. Human-in-the-Loop Pending Operation Proposals Queue
    # ------------------------------------------------------------------
    @app.get("/console/api/proposals")
    async def list_proposals(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        with lock:
            items = [p.to_public_dict() for p in reversed(list(proposals.values()))]
        return JSONResponse(status_code=200, content={"proposals": items, "count": len(items)})

    @app.get("/console/api/proposals/{proposal_id}")
    async def get_proposal(proposal_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        with lock:
            prop = proposals.get(proposal_id)
        if prop is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown proposal: {proposal_id}"})
        return JSONResponse(status_code=200, content={"proposal": prop.to_public_dict()})

    @app.post("/console/api/proposals")
    async def create_proposal(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

        tool_name = str(body.get("tool_name") or "").strip()
        arguments = body.get("arguments") or {}
        rationale = str(body.get("rationale") or "").strip()

        if not isinstance(arguments, dict):
            return JSONResponse(status_code=400, content={"error": "arguments must be a JSON object"})

        tier = TOOL_TIER_MAP.get(tool_name)
        if tier is None or tool_name not in ALL_TOOL_DEFINITIONS:
            return JSONResponse(status_code=400, content={"error": f"Unknown tool: {tool_name}"})

        if tier == PermissionTier.SYSTEM_ADMIN:
            return JSONResponse(
                status_code=403,
                content={"error": "SYSTEM_ADMIN tools are blocked by policy"},
            )

        for smuggled in ("session_id", "_session_id", "approval_token", "_approval_token"):
            if smuggled in arguments:
                return JSONResponse(
                    status_code=403,
                    content={"error": f"Credential smuggling denied: '{smuggled}' not allowed in arguments"},
                )

        preview = await asyncio.to_thread(_compute_proposal_preview, gw, tool_name, arguments)
        prop = OperationProposal(
            proposal_id=f"prop_{uuid.uuid4().hex[:16]}",
            tool_name=tool_name,
            tier=tier.value,
            raw_arguments=dict(arguments),
            redacted_arguments=redact_secrets(dict(arguments)),
            rationale=redact_secrets(rationale),
            preview=preview,
        )
        with lock:
            proposals[prop.proposal_id] = prop

        gw.policy.audit.log_event(
            tool_name=tool_name,
            tier=tier,
            decision="PENDING_OWNER_APPROVAL",
            reason=f"Proposal {prop.proposal_id} queued for owner review: {rationale}",
            arguments=arguments,
            result_summary={"proposal_id": prop.proposal_id, "preview_type": preview.get("type")},
        )
        return JSONResponse(status_code=201, content={"proposal": prop.to_public_dict()})

    @app.post("/console/api/proposals/{proposal_id}/execute")
    async def execute_proposal(proposal_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        with lock:
            prop = proposals.get(proposal_id)
        if prop is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown proposal: {proposal_id}"})
        if prop.status != "PENDING_OWNER_APPROVAL":
            return JSONResponse(
                status_code=409,
                content={"error": f"Proposal {proposal_id} is not pending (current status: {prop.status})"},
            )

        if gw.policy.is_emergency_stop_active():
            prop.status = "DENIED"
            prop.decided_at = datetime.now(timezone.utc).isoformat()
            prop.error_message = "Emergency stop is active"
            return JSONResponse(
                status_code=403,
                content={"error": "Emergency stop is active: all actions halted", "proposal": prop.to_public_dict()},
            )

        try:
            body = await request.json()
        except Exception:
            body = {}
        session_id = body.get("session_id")
        if isinstance(session_id, str):
            session_id = session_id.strip() or None

        ctrl_sess = gw.policy.sessions.get_session(session_id) if session_id else None
        approval_token = ctrl_sess.approval_token if ctrl_sess is not None else None

        t0 = time.perf_counter()
        try:
            result = await asyncio.to_thread(
                gw.invoke_tool,
                prop.tool_name,
                prop.raw_arguments,
                session_id=session_id,
                approval_token=approval_token,
                caller_id="web_console_owner",
            )
            dur_ms = int((time.perf_counter() - t0) * 1000)
            prop.status = "EXECUTED"
            prop.decided_at = datetime.now(timezone.utc).isoformat()
            prop.decided_by_session_id = session_id
            prop.execution_result = redact_secrets(result)
            gw.policy.audit.log_event(
                tool_name=prop.tool_name,
                tier=prop.tier,
                decision="ALLOW",
                reason=f"Owner approved and executed proposal {proposal_id}",
                arguments=prop.raw_arguments,
                result_summary={"proposal_id": proposal_id, "status": "EXECUTED"},
                session_id=session_id,
                duration_ms=dur_ms,
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "EXECUTED",
                    "proposal_id": proposal_id,
                    "proposal": prop.to_public_dict(),
                    "result": result,
                },
            )
        except PermissionError as exc:
            prop.status = "DENIED"
            prop.decided_at = datetime.now(timezone.utc).isoformat()
            prop.decided_by_session_id = session_id
            prop.error_message = str(exc)
            return JSONResponse(
                status_code=403,
                content={
                    "error": str(exc),
                    "status": "DENIED",
                    "proposal_id": proposal_id,
                    "proposal": prop.to_public_dict(),
                },
            )
        except (ValueError, ValidationError, FileNotFoundError, NotADirectoryError, IsADirectoryError) as exc:
            prop.status = "FAILED"
            prop.decided_at = datetime.now(timezone.utc).isoformat()
            prop.decided_by_session_id = session_id
            prop.error_message = str(exc)
            return JSONResponse(
                status_code=400,
                content={
                    "error": str(exc),
                    "status": "FAILED",
                    "proposal_id": proposal_id,
                    "proposal": prop.to_public_dict(),
                },
            )

    @app.post("/console/api/proposals/{proposal_id}/reject")
    async def reject_proposal(proposal_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        with lock:
            prop = proposals.get(proposal_id)
        if prop is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown proposal: {proposal_id}"})
        if prop.status != "PENDING_OWNER_APPROVAL":
            return JSONResponse(
                status_code=409,
                content={"error": f"Proposal {proposal_id} is not pending (current status: {prop.status})"},
            )

        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = str(body.get("reason") or "Rejected by owner")

        prop.status = "REJECTED"
        prop.decided_at = datetime.now(timezone.utc).isoformat()
        prop.rejection_reason = redact_secrets(reason)

        gw.policy.audit.log_event(
            tool_name=prop.tool_name,
            tier=prop.tier,
            decision="DENY",
            reason=f"Owner rejected proposal {proposal_id}: {reason}",
            arguments=prop.raw_arguments,
        )
        return JSONResponse(
            status_code=200,
            content={"status": "REJECTED", "proposal_id": proposal_id, "proposal": prop.to_public_dict()},
        )

    # ------------------------------------------------------------------
    # 4b. Bounded Multi-Step Agent Plan Orchestrator
    # ------------------------------------------------------------------
    @app.post("/console/api/plans")
    async def create_plan(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

        title = str(body.get("title") or "Multi-Step Automation Plan").strip()
        workspace_root = str(body.get("workspace_root") or "").strip()
        raw_steps = body.get("steps") or []

        if not isinstance(raw_steps, list) or not raw_steps:
            return JSONResponse(status_code=400, content={"error": "steps must be a non-empty list"})

        plan_steps: list[AgentPlanStep] = []
        for idx, s_data in enumerate(raw_steps):
            if not isinstance(s_data, dict):
                return JSONResponse(status_code=400, content={"error": f"step {idx} must be an object"})
            t_name = str(s_data.get("tool_name") or "").strip()
            desc = str(s_data.get("description") or f"Step {idx + 1}: {t_name}").strip()
            t_args = s_data.get("arguments") or {}
            if not isinstance(t_args, dict):
                return JSONResponse(status_code=400, content={"error": f"step {idx} arguments must be an object"})
            if t_name not in TOOL_TIER_MAP or t_name not in ALL_TOOL_DEFINITIONS:
                return JSONResponse(status_code=400, content={"error": f"Unknown tool in step {idx}: {t_name}"})

            tier = TOOL_TIER_MAP[t_name]
            if tier == PermissionTier.SYSTEM_ADMIN:
                return JSONResponse(status_code=403, content={"error": f"SYSTEM_ADMIN tool '{t_name}' blocked"})

            # Check credential smuggling
            for smuggled in ("session_id", "_session_id", "approval_token", "_approval_token"):
                if smuggled in t_args:
                    return JSONResponse(status_code=403, content={"error": f"Credential smuggling denied in step {idx}"})

            step_id = str(s_data.get("step_id") or f"step_{idx + 1}_{t_name}")
            max_retries = max(0, min(3, int(s_data.get("max_retries", 2))))
            verify_path = s_data.get("verify_path_exists")
            verify_cont = s_data.get("verify_contains")

            plan_steps.append(
                AgentPlanStep(
                    step_id=step_id,
                    description=desc,
                    tool_name=t_name,
                    arguments=dict(t_args),
                    max_retries=max_retries,
                    verify_path_exists=str(verify_path) if verify_path else None,
                    verify_contains=str(verify_cont) if verify_cont else None,
                )
            )

        plan_id = f"plan_{uuid.uuid4().hex[:16]}"
        plan = AgentPlan(
            plan_id=plan_id,
            title=title,
            workspace_root=workspace_root,
            steps=plan_steps,
        )
        with lock:
            plans[plan_id] = plan

        gw.policy.audit.log_event(
            tool_name="plan_create",
            tier=PermissionTier.WRITE,
            decision="PENDING_OWNER_APPROVAL",
            reason=f"Multi-step plan created: {title} ({len(plan_steps)} steps)",
            result_summary={"plan_id": plan_id, "steps_count": len(plan_steps)},
        )
        return JSONResponse(status_code=201, content={"plan": plan.to_public_dict()})

    @app.get("/console/api/plans")
    async def list_plans(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        with lock:
            all_plans = [p.to_public_dict() for p in plans.values()]
        return JSONResponse(status_code=200, content={"plans": all_plans, "count": len(all_plans)})

    @app.get("/console/api/plans/{plan_id}")
    async def get_plan(plan_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        with lock:
            p = plans.get(plan_id)
        if p is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown plan: {plan_id}"})
        return JSONResponse(status_code=200, content={"plan": p.to_public_dict()})

    @app.post("/console/api/plans/{plan_id}/approve")
    async def approve_plan(plan_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        with lock:
            p = plans.get(plan_id)
        if p is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown plan: {plan_id}"})
        if p.status != "PENDING_OWNER_APPROVAL":
            return JSONResponse(status_code=409, content={"error": f"Plan {plan_id} is not pending (status: {p.status})"})

        p.status = "APPROVED"
        p.approved_at = datetime.now(timezone.utc).isoformat()
        p.execution_logs.append(f"Plan approved by owner at {p.approved_at}")
        gw.policy.audit.log_event(
            tool_name="plan_approve",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            reason=f"Owner approved plan {plan_id}",
            result_summary={"plan_id": plan_id},
        )
        return JSONResponse(status_code=200, content={"plan": p.to_public_dict()})

    @app.post("/console/api/plans/{plan_id}/execute")
    async def execute_plan(plan_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        with lock:
            p = plans.get(plan_id)
        if p is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown plan: {plan_id}"})
        if p.status not in ("APPROVED", "PENDING_OWNER_APPROVAL"):
            return JSONResponse(status_code=409, content={"error": f"Plan {plan_id} cannot be executed in status '{p.status}'"})

        if gw.policy.is_emergency_stop_active():
            p.status = "FAILED"
            p.execution_logs.append("Execution blocked: Emergency Stop is active")
            return JSONResponse(status_code=403, content={"error": "Emergency Stop is active", "plan": p.to_public_dict()})

        try:
            body = await request.json()
        except Exception:
            body = {}
        session_id = body.get("session_id")
        if isinstance(session_id, str):
            session_id = session_id.strip() or None

        ctrl_sess = gw.policy.sessions.get_session(session_id) if session_id else None
        approval_token = ctrl_sess.approval_token if ctrl_sess is not None else None

        p.status = "RUNNING"
        p.executed_at = datetime.now(timezone.utc).isoformat()

        all_passed = True
        for step in p.steps:
            if gw.policy.is_emergency_stop_active() or p.status == "CANCELLED":
                p.status = "CANCELLED"
                p.execution_logs.append(f"Step {step.step_id} aborted: Emergency Stop or Cancellation")
                all_passed = False
                break

            # Pre-mutation snapshot for file tools
            if step.tool_name in ("write_file", "edit_file", "append_file", "apply_patch", "delete_file") and "path" in step.arguments:
                target_p_str = str(step.arguments["path"])
                if target_p_str not in p.backup_snapshots:
                    try:
                        resolved_target = Path(target_p_str).resolve()
                        if resolved_target.exists() and resolved_target.is_file():
                            text_content, _ = detect_encoding_and_decode(resolved_target.read_bytes())
                            p.backup_snapshots[target_p_str] = text_content
                        else:
                            p.backup_snapshots[target_p_str] = None
                    except Exception as e:
                        p.execution_logs.append(f"Warning: snapshot failed for {target_p_str}: {e}")

            step_success = False
            last_err = None
            for attempt in range(step.max_retries + 1):
                step.attempts = attempt + 1
                try:
                    res = await asyncio.to_thread(
                        gw.invoke_tool,
                        step.tool_name,
                        step.arguments,
                        session_id=session_id,
                        approval_token=approval_token,
                        caller_id="web_console_owner",
                    )
                    # Verify conditions if specified
                    if step.verify_path_exists:
                        v_path = Path(step.verify_path_exists).resolve()
                        if not v_path.exists():
                            raise AssertionError(f"Post-step verification failed: path does not exist: {step.verify_path_exists}")
                    if step.verify_contains:
                        v_target = Path(step.arguments.get("path") or step.verify_path_exists or "").resolve()
                        if v_target.exists() and v_target.is_file():
                            v_text, _ = detect_encoding_and_decode(v_target.read_bytes())
                            if step.verify_contains not in v_text:
                                raise AssertionError(f"Post-step verification failed: '{step.verify_contains}' not in file")

                    step.output = redact_secrets(res)
                    step.status = "SUCCESS"
                    step_success = True
                    p.execution_logs.append(f"Step {step.step_id} ({step.tool_name}) succeeded on attempt {step.attempts}")
                    break
                except Exception as exc:
                    last_err = str(exc)
                    p.execution_logs.append(f"Step {step.step_id} attempt {step.attempts} failed: {redact_secrets(last_err)}")

            if not step_success:
                step.status = "FAILED"
                step.error = redact_secrets(last_err)
                all_passed = False
                p.status = "FAILED"
                p.execution_logs.append(f"Plan halted at failed step {step.step_id}")
                break

        if all_passed and p.status != "CANCELLED":
            p.status = "COMPLETED"
            p.execution_logs.append("All plan steps executed and verified successfully")

        gw.policy.audit.log_event(
            tool_name="plan_execute",
            tier=PermissionTier.WRITE,
            decision="ALLOW" if p.status == "COMPLETED" else "FAILED",
            reason=f"Plan {plan_id} execution finished with status {p.status}",
            result_summary={"plan_id": plan_id, "status": p.status},
        )
        return JSONResponse(status_code=200 if p.status == "COMPLETED" else 400, content={"plan": p.to_public_dict()})

    @app.post("/console/api/plans/{plan_id}/cancel")
    async def cancel_plan(plan_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        with lock:
            p = plans.get(plan_id)
        if p is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown plan: {plan_id}"})
        p.status = "CANCELLED"
        p.execution_logs.append("Plan cancelled by owner")
        return JSONResponse(status_code=200, content={"plan": p.to_public_dict()})

    @app.post("/console/api/plans/{plan_id}/rollback")
    async def rollback_plan(plan_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        with lock:
            p = plans.get(plan_id)
        if p is None:
            return JSONResponse(status_code=404, content={"error": f"Unknown plan: {plan_id}"})

        restored_count = 0
        for f_path, original_content in p.backup_snapshots.items():
            try:
                target_p = Path(f_path).resolve()
                if original_content is None:
                    if target_p.exists() and target_p.is_file():
                        target_p.unlink()
                        restored_count += 1
                else:
                    target_p.parent.mkdir(parents=True, exist_ok=True)
                    target_p.write_text(original_content, encoding="utf-8", newline="")
                    restored_count += 1
            except Exception as e:
                p.execution_logs.append(f"Rollback error for {f_path}: {e}")

        p.status = "ROLLED_BACK"
        p.execution_logs.append(f"Plan rolled back: {restored_count} files restored to pre-plan snapshot state")
        gw.policy.audit.log_event(
            tool_name="plan_rollback",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            reason=f"Plan {plan_id} rolled back ({restored_count} files restored)",
            result_summary={"plan_id": plan_id, "restored_files_count": restored_count},
        )
        return JSONResponse(status_code=200, content={"plan": p.to_public_dict(), "restored_files_count": restored_count})

    # ------------------------------------------------------------------
    # 5. Direct Owner-Confirmed Tool Execution & Screenshot
    # ------------------------------------------------------------------
    @app.post("/console/api/execute")
    async def execute_direct_tool(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

        tool_name = str(body.get("tool_name") or "").strip()
        arguments = body.get("arguments") or {}
        session_id = body.get("session_id")
        if isinstance(session_id, str):
            session_id = session_id.strip() or None

        if not isinstance(arguments, dict):
            return JSONResponse(status_code=400, content={"error": "arguments must be a JSON object"})

        tier = TOOL_TIER_MAP.get(tool_name)
        if tier is None:
            return JSONResponse(status_code=400, content={"error": f"Unknown tool: {tool_name}"})

        if gw.policy.is_emergency_stop_active() and tier != PermissionTier.READ:
            gw.policy.audit.log_event(
                tool_name=tool_name,
                tier=tier,
                decision="DENY",
                reason="Emergency stop is active: privileged tool execution halted",
                arguments=arguments,
                session_id=session_id,
            )
            return JSONResponse(
                status_code=403,
                content={"error": "Emergency stop is active: all privileged operations are halted"},
            )

        ctrl_sess = gw.policy.sessions.get_session(session_id) if session_id else None
        approval_token = ctrl_sess.approval_token if ctrl_sess is not None else None

        t0 = time.perf_counter()
        try:
            result = await asyncio.to_thread(
                gw.invoke_tool,
                tool_name,
                arguments,
                session_id=session_id,
                approval_token=approval_token,
                caller_id="web_console_owner",
            )
            dur_ms = int((time.perf_counter() - t0) * 1000)
            gw.policy.audit.log_event(
                tool_name=tool_name,
                tier=tier,
                decision="ALLOW",
                reason="Owner direct tool execution via Mode B Web Console",
                arguments=arguments,
                result_summary={"ok": True, "tool_name": tool_name},
                session_id=session_id,
                duration_ms=dur_ms,
            )
            return JSONResponse(
                status_code=200,
                content={
                    "ok": True,
                    "tool_name": tool_name,
                    "tier": tier.value,
                    "session_id": session_id,
                    "result": result,
                },
            )
        except PermissionError as exc:
            return JSONResponse(status_code=403, content={"error": str(exc), "tool_name": tool_name})
        except FileNotFoundError as exc:
            return JSONResponse(status_code=404, content={"error": str(exc), "tool_name": tool_name})
        except (ValueError, ValidationError, NotADirectoryError, IsADirectoryError) as exc:
            return JSONResponse(status_code=400, content={"error": str(exc), "tool_name": tool_name})

    @app.get("/console/api/screenshot")
    async def capture_screenshot_endpoint(
        request: Request,
        target: str = "desktop",
        monitor: int | None = None,
        hwnd: int | None = None,
        max_width: int = 1280,
        session_id: str | None = None,
    ) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp

        args: dict[str, Any] = {"target": target, "max_width": max_width}
        if monitor is not None:
            args["monitor"] = monitor
        if hwnd is not None:
            args["hwnd"] = hwnd

        ctrl_sess = gw.policy.sessions.get_session(session_id) if session_id else None
        approval_token = ctrl_sess.approval_token if ctrl_sess is not None else None

        try:
            res = await asyncio.to_thread(
                gw.invoke_tool,
                "screenshot",
                args,
                session_id=session_id,
                approval_token=approval_token,
                caller_id="web_console_owner",
            )
            if isinstance(res, dict) and "format" not in res:
                res["format"] = "png"
            return JSONResponse(status_code=200, content=res)
        except PermissionError as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    @app.get("/console/api/clipboard")
    async def get_clipboard_endpoint(
        request: Request,
        session_id: str | None = None,
        redact: bool = True,
    ) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp

        ctrl_sess = gw.policy.sessions.get_session(session_id) if session_id else None
        approval_token = ctrl_sess.approval_token if ctrl_sess is not None else None

        try:
            res = await asyncio.to_thread(
                gw.invoke_tool,
                "get_clipboard_text",
                {},
                session_id=session_id,
                approval_token=approval_token,
                caller_id="web_console_owner",
            )
            if redact and isinstance(res, dict) and "text" in res:
                res["text"] = redact_secrets(res["text"])
            return JSONResponse(status_code=200, content=res)
        except PermissionError as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    # ------------------------------------------------------------------
    # 6. Live Redacted Audit Log & Emergency Stop Kill-Switch
    # ------------------------------------------------------------------
    @app.get("/console/api/audit")
    async def get_audit_log(request: Request, limit: int = 100) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        bounded_limit = max(1, min(500, int(limit)))
        entries = gw.policy.audit.read_entries(limit=bounded_limit)
        redacted_entries = redact_secrets(entries)
        return JSONResponse(
            status_code=200,
            content={"entries": redacted_entries, "count": len(redacted_entries)},
        )

    @app.post("/console/api/emergency-stop")
    async def trigger_emergency_stop(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = str(body.get("reason") or "owner_web_console_emergency_stop")

        summary = gw.engage_emergency_stop(reason=reason)
        cancelled_proposals: list[str] = []
        with lock:
            for prop in proposals.values():
                if prop.status == "PENDING_OWNER_APPROVAL":
                    prop.status = "CANCELLED_EMERGENCY_STOP"
                    prop.decided_at = datetime.now(timezone.utc).isoformat()
                    prop.error_message = f"Cancelled by Emergency Stop: {reason}"
                    cancelled_proposals.append(prop.proposal_id)
            for p in plans.values():
                if p.status in ("PENDING_OWNER_APPROVAL", "APPROVED", "RUNNING"):
                    p.status = "CANCELLED_EMERGENCY_STOP"
                    p.execution_logs.append(f"Cancelled by Emergency Stop: {reason}")

        summary["cancelled_proposals"] = cancelled_proposals
        return JSONResponse(status_code=200, content=summary)

    @app.post("/console/api/emergency-stop/reset")
    async def reset_emergency_stop(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        summary = gw.reset_emergency_stop()
        return JSONResponse(status_code=200, content=summary)

    # ------------------------------------------------------------------
    # 7. Optional OpenAI Responses API Proposal Connector (Never Auto-Executes)
    # ------------------------------------------------------------------
    @app.post("/console/api/assistant/suggest")
    async def assistant_suggest_proposal(request: Request) -> Response:
        """Create a PENDING_OWNER_APPROVAL operation proposal from an assistant suggestion.

        Never auto-executes state-changing tools. Discloses separate OpenAI API billing.
        """
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

        prompt = str(body.get("prompt") or "").strip()
        suggested_tool = body.get("suggested_tool")

        # If a structured tool suggestion is provided (or offline proposal generation), queue it safely
        if isinstance(suggested_tool, dict) and suggested_tool.get("tool_name"):
            t_name = str(suggested_tool["tool_name"]).strip()
            t_args = suggested_tool.get("arguments") or {}
            if t_name not in TOOL_TIER_MAP or not isinstance(t_args, dict):
                return JSONResponse(status_code=400, content={"error": "Invalid suggested_tool specification"})
            tier = TOOL_TIER_MAP[t_name]
            preview = await asyncio.to_thread(_compute_proposal_preview, gw, t_name, t_args)
            prop = OperationProposal(
                proposal_id=f"prop_{uuid.uuid4().hex[:16]}",
                tool_name=t_name,
                tier=tier.value,
                raw_arguments=dict(t_args),
                redacted_arguments=redact_secrets(dict(t_args)),
                rationale=redact_secrets(prompt or "Assistant suggested operation"),
                preview=preview,
            )
            with lock:
                proposals[prop.proposal_id] = prop
            gw.policy.audit.log_event(
                tool_name=t_name,
                tier=tier,
                decision="PENDING_OWNER_APPROVAL",
                reason="Assistant suggestion queued for human-in-the-loop approval",
                arguments=t_args,
                result_summary={"proposal_id": prop.proposal_id},
            )
            return JSONResponse(
                status_code=201,
                content={
                    "billing_disclosure": OPENAI_BILLING_DISCLOSURE,
                    "auto_executed": False,
                    "proposal": prop.to_public_dict(),
                },
            )

        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "OPENAI_API_KEY is not configured in server environment.",
                    "billing_disclosure": OPENAI_BILLING_DISCLOSURE,
                    "auto_executed": False,
                },
            )

        return JSONResponse(
            status_code=200,
            content={
                "configured": True,
                "billing_disclosure": OPENAI_BILLING_DISCLOSURE,
                "auto_executed": False,
                "message": "Provide suggested_tool or use local proposal queue for human-in-the-loop review.",
            },
        )

    # ------------------------------------------------------------------
    # 8. Sprint 5 Autonomous Full Agent Dashboard & TaskGrant Endpoints
    # ------------------------------------------------------------------
    from runtime.task_grant import TaskGrantBroker
    from runtime.task_store import ExecutionMode, TaskState, TaskStore

    task_store = task_store or TaskStore()
    grant_broker = grant_broker or TaskGrantBroker(policy=gw.policy, db_path=task_store.db_path)

    @app.get("/console/api/autonomous/status")
    async def get_autonomous_status(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp

        try:
            from runtime.llm_adapter import get_llm_operating_status
            llm_status = get_llm_operating_status()
        except Exception as e:
            llm_status = {"status": "UNKNOWN", "error": str(e)}

        tasks = task_store.list_tasks(limit=2000)
        tasks_by_state: dict[str, int] = {}
        for s in TaskState:
            tasks_by_state[s.value] = 0
        for t in tasks:
            tasks_by_state[t.state] = tasks_by_state.get(t.state, 0) + 1

        return JSONResponse(
            status_code=200,
            content={
                "llm_status": llm_status,
                "total_tasks": len(tasks),
                "tasks_by_state": tasks_by_state,
            },
        )

    @app.get("/console/api/autonomous/tasks")
    async def list_autonomous_tasks(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        state_filter = request.query_params.get("state")
        limit = int(request.query_params.get("limit", 50))
        tasks = task_store.list_tasks(state=state_filter, limit=limit)
        return JSONResponse(
            status_code=200,
            content={
                "tasks": [
                    {
                        "task_id": t.task_id,
                        "objective": t.objective,
                        "workspace_root": t.workspace_root,
                        "mode": t.mode,
                        "state": t.state,
                        "grant_id": t.grant_id,
                        "created_at": t.created_at,
                        "tool_call_count": t.tool_call_count,
                        "retry_count": t.retry_count,
                        "result_summary": t.result_summary,
                        "error_message": t.error_message,
                        "file_write_count": getattr(t, "file_write_count", 0),
                        "api_cost_usd": getattr(t, "api_cost_usd", 0.0),
                        "worker_pid": getattr(t, "worker_pid", None),
                        "control_signal": getattr(t, "control_signal", None),
                        "proposal_digest": getattr(t, "proposal_digest", ""),
                    }
                    for t in tasks
                ],
                "count": len(tasks),
            },
        )

    @app.post("/console/api/autonomous/tasks")
    async def create_autonomous_task(request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None or ws is None:
            return err_resp  # type: ignore[return-value]

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

        objective = str(body.get("objective") or "").strip()
        workspace_root = str(body.get("workspace_root") or "").strip()
        if not objective or not workspace_root:
            return JSONResponse(status_code=400, content={"error": "objective and workspace_root are required"})

        allowed_tools = body.get("allowed_tools") or [
            "read_file", "write_file", "edit_file", "list_directory",
            "powershell_execute", "git_status", "git_diff",
        ]
        allowed_cmds = body.get("allowed_commands") or ["pytest*", "python*", "git*"]
        allowed_tiers = body.get("allowed_permission_tiers") or ["READ", "WRITE", "EXECUTE"]
        duration = float(body.get("duration_seconds", 3600.0))
        mode = body.get("mode", ExecutionMode.TRUSTED_TASK.value)
        auto_start = bool(body.get("auto_start", False))
        require_explicit_approval = bool(body.get("require_explicit_approval", False))
        api_cost_budget = float(body.get("api_cost_budget", 5.0))
        metadata = body.get("metadata") or {}
        allowed_paths = body.get("allowed_paths") or body.get("allowed_extra_paths") or []
        max_tool_calls = int(body.get("max_tool_calls", 500))
        max_retries = int(body.get("max_retries", 5))

        requested_scope = body.get("requested_scope") or {
            "workspace_root": workspace_root,
            "allowed_tools": allowed_tools,
            "allowed_commands": allowed_cmds,
            "allowed_permission_tiers": allowed_tiers,
            "allowed_paths": allowed_paths,
            "duration_seconds": duration,
            "api_cost_budget": api_cost_budget,
            "max_tool_calls": max_tool_calls,
            "max_retries": max_retries,
        }

        task_id = f"task_{uuid.uuid4().hex[:16]}"
        proposal_dict: dict[str, Any] = {
            "task_id": task_id,
            "objective": objective,
            "workspace_root": workspace_root,
            "allowed_tools": allowed_tools,
            "allowed_commands": allowed_cmds,
            "allowed_permission_tiers": allowed_tiers,
            "allowed_paths": allowed_paths,
            "duration_seconds": duration,
            "api_cost_budget": api_cost_budget,
            "max_tool_calls": max_tool_calls,
            "max_retries": max_retries,
        }
        proposal_digest = compute_proposal_scope_digest(proposal_dict)

        task = task_store.create_task(
            task_id=task_id,
            objective=objective,
            workspace_root=workspace_root,
            mode=mode,
            metadata=metadata,
            requested_scope=requested_scope,
            proposal_digest=proposal_digest,
        )

        if require_explicit_approval:
            return JSONResponse(
                status_code=201,
                content={
                    "task_id": task.task_id,
                    "grant_id": None,
                    "state": TaskState.AUTHORIZATION_PENDING.value,
                    "workspace_root": workspace_root,
                    "require_explicit_approval": True,
                    "proposal_digest": proposal_digest,
                },
            )

        issue_sig = inspect.signature(grant_broker.issue_grant)
        issue_kwargs: dict[str, Any] = {
            "task_id": task.task_id,
            "workspace_root": workspace_root,
            "allowed_tools": allowed_tools,
            "allowed_commands": allowed_cmds,
            "allowed_permission_tiers": allowed_tiers,
            "duration_seconds": duration,
            "owner_id": ws.web_session_id,
            "api_cost_budget": api_cost_budget,
        }
        if "proposal_digest" in issue_sig.parameters:
            issue_kwargs["proposal_digest"] = proposal_digest
        if "allowed_extra_paths" in issue_sig.parameters and allowed_paths:
            issue_kwargs["allowed_extra_paths"] = allowed_paths

        try:
            grant = grant_broker.issue_grant(**issue_kwargs)
        except PermissionError as pe:
            return JSONResponse(status_code=403, content={"error": str(pe)})
        except ValueError as ve:
            return JSONResponse(status_code=400, content={"error": str(ve)})

        if body.get("max_tool_calls") is not None:
            grant.max_tool_calls = int(body["max_tool_calls"])
        if body.get("max_retries") is not None:
            grant.max_retries = int(body["max_retries"])
        if body.get("max_tool_calls") is not None or body.get("max_retries") is not None:
            grant.sign(grant_broker.secret)
            grant_broker._save_grant(grant)
            grant_broker._grants[grant.grant_id] = grant

        task_store.bind_grant(task.task_id, grant.grant_id)

        worker_pid: int | None = None
        if auto_start:
            worker_pid = _trigger_independent_worker(task_store.db_path)

        resp_content: dict[str, Any] = {
            "task_id": task.task_id,
            "grant_id": grant.grant_id,
            "state": TaskState.QUEUED.value,
            "workspace_root": workspace_root,
            "expires_at": grant.expires_at,
            "proposal_digest": proposal_digest,
        }
        if worker_pid is not None:
            resp_content["worker_pid"] = worker_pid

        return JSONResponse(
            status_code=201,
            content=resp_content,
        )

    @app.post("/console/api/autonomous/tasks/{task_id}/approve")
    async def approve_autonomous_task(task_id: str, request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None or ws is None:
            return err_resp  # type: ignore[return-value]

        task = task_store.get_task(task_id)
        if not task:
            return JSONResponse(status_code=404, content={"error": f"Task '{task_id}' not found"})

        if task.state not in (TaskState.AUTHORIZATION_PENDING.value, TaskState.CREATED.value):
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Task '{task_id}' in state '{task.state}' cannot be approved (expected AUTHORIZATION_PENDING or CREATED)"
                },
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        req_scope = getattr(task, "requested_scope", {}) or {}
        meta = getattr(task, "metadata", {}) or {}

        # FINDING G01: Reject scope modification between review and approval
        proposed_ws = req_scope.get("workspace_root") or getattr(task, "workspace_root", "")
        if "workspace_root" in body and body["workspace_root"]:
            body_ws = str(body["workspace_root"]).strip()
            if proposed_ws and Path(body_ws).resolve(strict=False) != Path(proposed_ws).resolve(strict=False):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Scope modification rejected (G01): Cannot alter proposed workspace, tools, or commands during approval. Submit a new task proposal instead."
                    },
                )

        proposed_tools = req_scope.get("allowed_tools") or meta.get("allowed_tools")
        if "allowed_tools" in body and proposed_tools is not None:
            body_tools = sorted(str(t) for t in body["allowed_tools"])
            prop_tools = sorted(str(t) for t in proposed_tools)
            if body_tools != prop_tools:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Scope modification rejected (G01): Cannot alter proposed workspace, tools, or commands during approval. Submit a new task proposal instead."
                    },
                )

        proposed_cmds = req_scope.get("allowed_commands") or meta.get("allowed_commands")
        if "allowed_commands" in body and proposed_cmds is not None:
            body_cmds = sorted(str(c) for c in body["allowed_commands"])
            prop_cmds = sorted(str(c) for c in proposed_cmds)
            if body_cmds != prop_cmds:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Scope modification rejected (G01): Cannot alter proposed workspace, tools, or commands during approval. Submit a new task proposal instead."
                    },
                )

        allowed_tools = (
            proposed_tools
            or body.get("allowed_tools")
            or [
                "read_file", "write_file", "edit_file", "list_directory",
                "powershell_execute", "git_status", "git_diff",
            ]
        )
        allowed_cmds = (
            proposed_cmds
            or body.get("allowed_commands")
            or ["pytest*", "python*", "git*"]
        )
        allowed_tiers = (
            req_scope.get("allowed_permission_tiers")
            or meta.get("allowed_permission_tiers")
            or body.get("allowed_permission_tiers")
            or ["READ", "WRITE", "EXECUTE"]
        )
        duration = float(
            req_scope.get("duration_seconds")
            or meta.get("duration_seconds")
            or body.get("duration_seconds")
            or 3600.0
        )
        api_cost_budget = float(
            req_scope.get("api_cost_budget")
            or meta.get("api_cost_budget")
            or body.get("api_cost_budget")
            or 5.0
        )
        allowed_paths = (
            req_scope.get("allowed_paths")
            or req_scope.get("allowed_extra_paths")
            or meta.get("allowed_paths")
            or meta.get("allowed_extra_paths")
            or body.get("allowed_paths")
            or body.get("allowed_extra_paths")
            or []
        )
        max_tool_calls = (
            req_scope.get("max_tool_calls")
            or meta.get("max_tool_calls")
            or body.get("max_tool_calls")
        )
        max_retries = (
            req_scope.get("max_retries")
            or meta.get("max_retries")
            or body.get("max_retries")
        )
        auto_start = bool(body.get("auto_start", False))

        # Compute proposal scope digest (G01)
        proposal_dict: dict[str, Any] = {
            "task_id": task.task_id,
            "objective": task.objective,
            "workspace_root": task.workspace_root,
            "allowed_tools": allowed_tools,
            "allowed_commands": allowed_cmds,
            "allowed_permission_tiers": allowed_tiers,
            "allowed_paths": allowed_paths,
            "duration_seconds": duration,
            "api_cost_budget": api_cost_budget,
            "max_tool_calls": int(max_tool_calls) if max_tool_calls is not None else 500,
            "max_retries": int(max_retries) if max_retries is not None else 5,
        }
        computed_proposal_digest = compute_proposal_scope_digest(proposal_dict)

        task_p_digest = getattr(task, "proposal_digest", "") or ""
        expected_digest = body.get("expected_proposal_digest")

        if task_p_digest and expected_digest and task_p_digest != expected_digest:
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Proposal digest mismatch (G01): expected '{expected_digest}', task has '{task_p_digest}'"
                },
            )
        if expected_digest and computed_proposal_digest != expected_digest:
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Proposal digest mismatch (G01): expected '{expected_digest}', computed digest is '{computed_proposal_digest}'"
                },
            )

        proposal_digest = task_p_digest or computed_proposal_digest

        # Mint and consume a single-use scoped approval token internally via grant_broker
        owner_id = ws.web_session_id
        token_gen_sig = inspect.signature(grant_broker.generate_owner_approval_token)
        token_kwargs: dict[str, Any] = {
            "task_id": task.task_id,
            "workspace_root": task.workspace_root,
        }
        if "scope_digest" in token_gen_sig.parameters:
            token_kwargs["scope_digest"] = proposal_digest
        if "owner_id" in token_gen_sig.parameters:
            token_kwargs["owner_id"] = owner_id

        try:
            approval_token = grant_broker.generate_owner_approval_token(**token_kwargs)
        except TypeError:
            approval_token = grant_broker.generate_owner_approval_token(task.task_id, task.workspace_root)

        token_verify_sig = inspect.signature(grant_broker.verify_owner_approval_token)
        verify_kwargs: dict[str, Any] = {
            "task_id": task.task_id,
            "workspace_root": task.workspace_root,
            "token": approval_token,
            "consume": True,
        }
        if "expected_scope_digest" in token_verify_sig.parameters:
            verify_kwargs["expected_scope_digest"] = proposal_digest
        if "expected_owner_id" in token_verify_sig.parameters:
            verify_kwargs["expected_owner_id"] = owner_id

        try:
            token_valid = grant_broker.verify_owner_approval_token(**verify_kwargs)
        except TypeError:
            token_valid = grant_broker.verify_owner_approval_token(task.task_id, task.workspace_root, approval_token, consume=True)

        if not token_valid:
            return JSONResponse(status_code=403, content={"error": "Owner approval token verification failed"})

        # Issue the TaskGrant via grant_broker
        issue_sig = inspect.signature(grant_broker.issue_grant)
        issue_kwargs: dict[str, Any] = {
            "task_id": task.task_id,
            "workspace_root": task.workspace_root,
            "allowed_tools": allowed_tools,
            "allowed_commands": allowed_cmds,
            "allowed_permission_tiers": allowed_tiers,
            "duration_seconds": duration,
            "owner_id": owner_id,
            "api_cost_budget": api_cost_budget,
        }
        if "proposal_digest" in issue_sig.parameters:
            issue_kwargs["proposal_digest"] = proposal_digest
        if "allowed_extra_paths" in issue_sig.parameters and allowed_paths:
            issue_kwargs["allowed_extra_paths"] = allowed_paths

        try:
            grant = grant_broker.issue_grant(**issue_kwargs)
        except PermissionError as pe:
            return JSONResponse(status_code=403, content={"error": str(pe)})
        except ValueError as ve:
            return JSONResponse(status_code=400, content={"error": str(ve)})

        if max_tool_calls is not None or max_retries is not None:
            if max_tool_calls is not None:
                grant.max_tool_calls = int(max_tool_calls)
            if max_retries is not None:
                grant.max_retries = int(max_retries)
            grant.sign(grant_broker.secret)
            grant_broker._save_grant(grant)
            grant_broker._grants[grant.grant_id] = grant

        try:
            task_store.bind_grant(task.task_id, grant.grant_id)
        except PermissionError as pe:
            return JSONResponse(status_code=403, content={"error": str(pe)})
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

        # Trigger independent external worker process if auto_start is True (G04)
        worker_pid: int | None = None
        if auto_start:
            worker_pid = _trigger_independent_worker(task_store.db_path)

        # CRITICAL (G01): Zero Secret Exposure in Responses/Logs
        return JSONResponse(
            status_code=200,
            content={
                "task_id": task.task_id,
                "grant_id": grant.grant_id,
                "state": "QUEUED",
                "approved_by": ws.web_session_id,
                "proposal_digest": proposal_digest,
                "expires_at": grant.expires_at,
                "worker_pid": worker_pid,
            },
        )

    @app.get("/console/api/autonomous/roots")
    async def list_autonomous_roots(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        if hasattr(grant_broker, "list_preapproved_roots"):
            roots = grant_broker.list_preapproved_roots()
        else:
            roots = getattr(grant_broker, "preapproved_roots", []) or []
        return JSONResponse(
            status_code=200,
            content={"preapproved_roots": [str(p) for p in roots]},
        )

    @app.post("/console/api/autonomous/roots")
    async def onboard_autonomous_root(request: Request) -> Response:
        ws, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None or ws is None:
            return err_resp  # type: ignore[return-value]

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

        root_path = str(body.get("root_path") or "").strip()
        if not root_path:
            return JSONResponse(status_code=400, content={"error": "root_path is required"})

        try:
            canonical_root = grant_broker.onboard_workspace_root(root_path, owner_id=ws.web_session_id)
        except PermissionError as pe:
            return JSONResponse(status_code=403, content={"error": str(pe)})
        except ValueError as ve:
            return JSONResponse(status_code=400, content={"error": str(ve)})
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

        return JSONResponse(
            status_code=201,
            content={
                "onboarded_root": canonical_root,
                "approved_by": ws.web_session_id,
            },
        )

    @app.get("/console/api/autonomous/grants/{grant_id}")
    async def get_autonomous_grant(grant_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        grant = grant_broker.get_grant(grant_id)
        if not grant:
            return JSONResponse(status_code=404, content={"error": f"TaskGrant '{grant_id}' not found"})
        is_valid, reason = grant_broker.validate_grant(grant)
        return JSONResponse(
            status_code=200,
            content={
                "grant": grant.to_dict(),
                "valid": is_valid,
                "validation_reason": reason,
            },
        )

    @app.get("/console/api/autonomous/tasks/{task_id}")
    async def get_autonomous_task(task_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        task = task_store.get_task(task_id)
        if not task:
            return JSONResponse(status_code=404, content={"error": f"Task '{task_id}' not found"})
        chk = task_store.get_latest_checkpoint(task_id)
        grant_valid = None
        if task.grant_id:
            g = grant_broker.get_grant(task.grant_id)
            if g:
                grant_valid, _ = grant_broker.validate_grant(g)
            else:
                grant_valid = False

        return JSONResponse(
            status_code=200,
            content={
                "task_id": task.task_id,
                "objective": task.objective,
                "workspace_root": task.workspace_root,
                "mode": task.mode,
                "state": task.state,
                "grant_id": task.grant_id,
                "grant_valid": grant_valid,
                "tool_call_count": task.tool_call_count,
                "retry_count": task.retry_count,
                "current_plan": task.current_plan,
                "completed_steps": task.completed_steps,
                "files_modified": task.files_modified,
                "test_results": task.test_results,
                "error_message": task.error_message,
                "result_summary": task.result_summary,
                "latest_checkpoint": chk.checkpoint_id if chk else None,
                "file_write_count": getattr(task, "file_write_count", 0),
                "api_cost_usd": getattr(task, "api_cost_usd", 0.0),
                "verification_passed": getattr(task, "verification_passed", False),
                "worker_pid": getattr(task, "worker_pid", None),
                "control_signal": getattr(task, "control_signal", None),
                "proposal_digest": getattr(task, "proposal_digest", ""),
            },
        )

    @app.get("/console/api/autonomous/tasks/{task_id}/logs")
    async def get_autonomous_task_logs(task_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=False)
        if err_resp is not None:
            return err_resp
        limit = int(request.query_params.get("limit", 100))
        logs = task_store.get_logs(task_id, limit=limit)
        return JSONResponse(status_code=200, content={"task_id": task_id, "logs": logs, "count": len(logs)})

    @app.post("/console/api/autonomous/tasks/{task_id}/pause")
    async def pause_autonomous_task(task_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        task = task_store.get_task(task_id)
        if not task:
            return JSONResponse(status_code=404, content={"error": f"Task '{task_id}' not found"})
        if hasattr(task_store, "set_control_signal"):
            task_store.set_control_signal(task_id, "PAUSE")
        ok = task_store.update_task_state(task_id, TaskState.PAUSED.value)
        return JSONResponse(status_code=200, content={"task_id": task_id, "paused": ok, "state": TaskState.PAUSED.value})

    @app.post("/console/api/autonomous/tasks/{task_id}/resume")
    async def resume_autonomous_task(task_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        task = task_store.get_task(task_id)
        if not task:
            return JSONResponse(status_code=404, content={"error": f"Task '{task_id}' not found", "resumed": False})
        if not task.grant_id:
            return JSONResponse(
                status_code=403,
                content={"error": "Cannot resume: No TaskGrant bound to task", "resumed": False},
            )
        grant = grant_broker.get_grant(task.grant_id)
        if not grant:
            return JSONResponse(
                status_code=403,
                content={"error": f"Cannot resume: TaskGrant '{task.grant_id}' not found", "resumed": False},
            )
        is_valid, reason = grant_broker.validate_grant(grant)
        if not is_valid:
            return JSONResponse(
                status_code=403,
                content={"error": f"Cannot resume: {reason}", "resumed": False},
            )

        if hasattr(task_store, "set_control_signal"):
            task_store.set_control_signal(task_id, None)
        task_store.update_task_state(task_id, TaskState.QUEUED.value)

        # Trigger independent external worker process (G04)
        worker_pid = _trigger_independent_worker(task_store.db_path)

        return JSONResponse(
            status_code=200,
            content={
                "task_id": task_id,
                "resumed": True,
                "state": TaskState.QUEUED.value,
                "worker_pid": worker_pid,
            },
        )

    @app.post("/console/api/autonomous/tasks/{task_id}/cancel")
    async def cancel_autonomous_task(task_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        task = task_store.get_task(task_id)
        if not task:
            return JSONResponse(status_code=404, content={"error": f"Task '{task_id}' not found"})
        if hasattr(task_store, "set_control_signal"):
            task_store.set_control_signal(task_id, "CANCEL")
        if task.grant_id:
            grant_broker.revoke_grant(task.grant_id, reason="Operator cancelled via Web Console")
        ok = task_store.update_task_state(task_id, TaskState.CANCELLED.value, error_message="Cancelled by operator")
        return JSONResponse(status_code=200, content={"task_id": task_id, "cancelled": True, "state": TaskState.CANCELLED.value})

    @app.post("/console/api/autonomous/tasks/{task_id}/revoke")
    async def revoke_autonomous_grant(task_id: str, request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        task = task_store.get_task(task_id)
        if not task or not task.grant_id:
            return JSONResponse(status_code=404, content={"error": "Task or grant not found"})
        if hasattr(task_store, "set_control_signal"):
            task_store.set_control_signal(task_id, "CANCEL")
        ok = grant_broker.revoke_grant(task.grant_id, reason="Operator manual grant revocation")
        task_store.update_task_state(task_id, TaskState.CANCELLED.value, error_message="Grant revoked")
        return JSONResponse(status_code=200, content={"task_id": task_id, "grant_id": task.grant_id, "revoked": ok, "state": TaskState.CANCELLED.value})

    @app.post("/console/api/autonomous/emergency-stop")
    async def trigger_emergency_stop(request: Request) -> Response:
        _, err_resp = _authenticate_request(request, require_csrf=True)
        if err_resp is not None:
            return err_resp
        if gw and hasattr(gw, "policy") and getattr(gw.policy, "emergency_stop_file", None):
            emergency_file = Path(gw.policy.emergency_stop_file)
        else:
            emergency_file = Path(__file__).resolve().parent.parent / "runtime" / "EMERGENCY_STOP"
        emergency_file.parent.mkdir(parents=True, exist_ok=True)
        emergency_file.write_text(f"EMERGENCY STOP at {time.time()}\n", encoding="utf-8")

        all_tasks = task_store.list_tasks(limit=1000)
        cancelled_count = 0
        for t in all_tasks:
            if t.state in (
                TaskState.QUEUED.value,
                TaskState.PLANNING.value,
                TaskState.RUNNING.value,
                TaskState.VERIFYING.value,
                TaskState.REPAIRING.value,
                TaskState.PAUSED.value,
            ):
                if hasattr(task_store, "set_control_signal"):
                    task_store.set_control_signal(t.task_id, "CANCEL")
                if t.grant_id:
                    grant_broker.revoke_grant(t.grant_id, reason="Emergency stop engaged via Web Console")
                task_store.update_task_state(t.task_id, TaskState.CANCELLED.value, error_message="Emergency stop engaged")
                cancelled_count += 1

        gw.engage_emergency_stop(reason="Operator emergency stop via Web Console")
        return JSONResponse(
            status_code=200,
            content={
                "emergency_stop": True,
                "message": "All autonomous work halted",
                "cancelled_tasks_count": cancelled_count,
            },
        )

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mode B — Owner-Controlled Web Agent Console")
    parser.add_argument(
        "--host",
        default=os.getenv("WINDOWS_MCP_CONSOLE_HOST", "127.0.0.1"),
        help="Loopback bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("WINDOWS_MCP_CONSOLE_PORT", "8767")),
        help="TCP port (default: 8767)",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("MCP_AGENT_PROFILE", "full_agent"),
        help="Security policy profile (default: full_agent)",
    )
    parser.add_argument(
        "--policy-path",
        default=None,
        help="Optional path to policy.json",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        dest="no_auth",
        default=None,
        help="Run in password-free mode for local browser use (default: auto)",
    )
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"Refusing to bind Mode B Web Agent Console to non-loopback address: {args.host}"
        )

    app = create_web_console_app(profile=args.profile, policy_path=args.policy_path, no_auth=args.no_auth)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
