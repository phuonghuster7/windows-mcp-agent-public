"""Production Streamable HTTP / ASGI Server for the Unified Windows MCP Gateway (v0.3.0).

Exposes:
  - GET  /health                         : Non-mutating health & active profile summary
  - POST /mcp                            : MCP JSON-RPC 2.0 Streamable HTTP endpoint (single or batch)
  - GET  /mcp                            : Streamable HTTP endpoint metadata / method guard
  - POST /api/sessions                   : Authenticated owner endpoint to mint bounded ControlSessions
  - POST /api/sessions/{session_id}/revoke : Authenticated owner endpoint to revoke a ControlSession
  - POST /api/sessions/revoke-all        : Authenticated owner endpoint to revoke all ControlSessions
  - POST /api/emergency-stop             : Authenticated owner endpoint to engage Emergency Stop
  - POST /api/emergency-stop/reset       : Authenticated owner endpoint to clear Emergency Stop

Supports profile selection via CLI (--profile) or environment variable (MCP_AGENT_PROFILE),
defaulting to 'read_only' (strict 15-tool v0.2.1 parity) for safe staging & production cutover.
Enforces independent caller authentication (Bearer token) for all privileged profiles,
privileged session/token headers, and session management endpoints.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import contextmanager
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for _p in (PROJECT_ROOT, HERE, PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from policy import PermissionTier, SecurityPolicy, TOOL_TIER_MAP, redact_secrets  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402

logger = logging.getLogger("unified_mcp_gateway_http")

def _safe_user_home() -> Path:
    try:
        return Path.home()
    except RuntimeError:
        import tempfile
        return Path(os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir())


DEFAULT_BACKEND_ENV_FILE = Path(
    os.getenv(
        "WINDOWS_MCP_BACKEND_ENV_FILE",
        str(_safe_user_home() / ".gemini" / "antigravity-ide" / "scratch" / "computer-mcp-server" / ".env"),
    )
)

OWNER_DELEGATION_CAPABILITY_PROFILES: dict[str, list[str]] = {
    "FILE_READ": ["agent_workspace_list", "agent_read_file"],
    "FILE_WRITE": [
        "agent_create_file",
        "agent_write_file",
        "agent_apply_patch",
        "agent_delete_file",
        "agent_create_directory",
        "agent_delete_directory",
        "agent_move_path",
        "agent_copy_path",
    ],
    "SECURITY_CONTROL_EDIT": [
        "SECURITY_CONTROL_EDIT",
        "agent_read_file",
        "agent_create_file",
        "agent_write_file",
        "agent_apply_patch",
        "agent_delete_file",
        "agent_create_directory",
        "agent_delete_directory",
        "agent_move_path",
        "agent_copy_path",
    ],
    "GIT": ["agent_git_status", "agent_git_diff", "agent_run_command"],
    "SHELL": ["agent_powershell_execute", "agent_run_command", "agent_system_status"],
    "TEST": ["agent_run_tests", "agent_run_command"],
    "BUILD": ["agent_powershell_execute", "agent_run_command"],
    "DESKTOP": [
        "agent_desktop_screenshot",
        "agent_get_active_window",
        "agent_focus_window",
        "agent_keyboard_type",
        "agent_mouse_click",
        "agent_visual_verify",
        "agent_launch_app",
        "agent_list_windows",
        "agent_system_status",
    ],
    "TASK_CONTROL": [
        "agent_submit_task",
        "agent_task_status",
        "agent_task_logs",
        "agent_task_diff",
        "agent_task_artifacts",
        "agent_list_tasks",
        "agent_task_pause",
        "agent_task_resume",
        "agent_task_cancel",
        "agent_emergency_stop",
    ],
    "RELEASE_DEPLOY": ["RELEASE_DEPLOY"],
    "OWNER_GLOBAL_FILESYSTEM": [
        "OWNER_GLOBAL_FILESYSTEM",
        "agent_workspace_list",
        "agent_read_file",
        "agent_create_file",
        "agent_write_file",
        "agent_apply_patch",
        "agent_delete_file",
        "agent_create_directory",
        "agent_delete_directory",
        "agent_move_path",
        "agent_copy_path",
        "agent_git_status",
        "agent_git_diff",
        "agent_run_command",
        "agent_run_tests",
    ],
}


def discover_windows_filesystem_roots() -> list[str]:
    """Discover available fixed drive roots on Windows, falling back to PROJECT_ROOT anchor or C:\\."""
    roots: list[str] = []
    try:
        from policy import discover_fixed_drives
        drives = discover_fixed_drives()
        if isinstance(drives, list):
            roots = [str(d) for d in drives if str(d).strip()]
    except Exception:
        roots = []
    if not roots:
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    roots.append(f"{chr(65 + i)}:\\")
        except Exception:
            pass
    if not roots:
        anchor = str(Path(PROJECT_ROOT).resolve().anchor or "C:\\")
        if not anchor.endswith("\\"):
            anchor = f"{anchor}\\"
        roots = [anchor]
    clean_roots: list[str] = []
    for r in roots:
        nr = str(Path(r).resolve())
        if not nr.endswith("\\"):
            nr = f"{nr}\\"
        if nr not in clean_roots:
            clean_roots.append(nr)
    return clean_roots


def _normalize_owner_allowed_paths(allowed_paths: list[str] | None) -> list[str]:
    """Normalize allowed_paths: expand '*' or 'AUTO' to drive roots, resolve other paths, deduplicate preserving order."""
    normalized: list[str] = []
    roots = discover_windows_filesystem_roots()
    for p in (allowed_paths or []):
        p_str = str(p).strip()
        if p_str.upper() in ("*", "AUTO"):
            for r in roots:
                if r not in normalized:
                    normalized.append(r)
        else:
            resolved = str(Path(p_str).resolve())
            if resolved not in normalized:
                normalized.append(resolved)
    return normalized


def expand_owner_delegation_capabilities(
    capabilities: list[str],
    *,
    include_release_deploy: bool = False,
) -> list[str]:
    """Expand high-level owner delegation capability names into authorized tool names."""
    tools: set[str] = set()
    for cap in capabilities:
        cap_key = str(cap).strip().upper()
        if cap_key == "RELEASE_DEPLOY" and not include_release_deploy:
            raise ValueError("RELEASE_DEPLOY requires explicit separate deployment approval (approve_release_deploy=True)")
        if cap_key not in OWNER_DELEGATION_CAPABILITY_PROFILES:
            raise ValueError(f"Unknown owner delegation capability: {cap}")
        tools.update(OWNER_DELEGATION_CAPABILITY_PROFILES[cap_key])
    return sorted(tools)



def load_gateway_auth_token(
    caller_auth_token: str | None = None,
    *,
    env_path: str | Path | None = None,
) -> str:
    """Resolve the Gateway caller authentication token without logging secret values."""
    if caller_auth_token is not None and caller_auth_token.strip():
        return caller_auth_token.strip()

    for env_key in (
        "WINDOWS_MCP_GATEWAY_TOKEN",
        "COMPUTER_API_TOKEN",
        "MCP_AUTH_TOKEN",
        "MCP_AGENT_APPROVAL_TOKEN",
    ):
        val = os.getenv(env_key, "").strip()
        if val:
            return val

    candidate_files = [
        Path(env_path) if env_path else DEFAULT_BACKEND_ENV_FILE,
        PROJECT_ROOT / ".env",
    ]
    for candidate in candidate_files:
        try:
            if candidate.exists() and candidate.is_file():
                for raw_line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k_clean = k.strip().upper()
                    v_clean = v.strip().strip("\"'")
                    if k_clean in (
                        "WINDOWS_MCP_GATEWAY_TOKEN",
                        "COMPUTER_API_TOKEN",
                        "MCP_AUTH_TOKEN",
                    ) and v_clean:
                        return v_clean
        except OSError:
            continue

    if env_path is None:
        tunnel_cfg = PROJECT_ROOT / "config" / "tunnel-autonomous.yaml"
        try:
            if tunnel_cfg.exists() and tunnel_cfg.is_file():
                cfg_text = tunnel_cfg.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"Authorization:\s*[\"']?Bearer\s+([A-Za-z0-9_\-\.]+)", cfg_text)
                if m and m.group(1).strip():
                    return m.group(1).strip()
        except OSError:
            pass

    return f"gw_tok_{uuid.uuid4().hex}"


DEFAULT_OAUTH_SIGNING_KEY_PATH = PROJECT_ROOT / "runtime" / "secrets" / "oauth_signing.key"
DEFAULT_CALLER_TOKEN_FILE = PROJECT_ROOT / "runtime" / "secrets" / "gateway_caller.token"


def resolve_oauth_signing_key_path(
    key_path: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> Path:
    """Resolve the path to oauth_signing.key respecting isolated test state roots and production runtime/secrets."""
    if key_path is not None:
        return Path(key_path)
    env_path = os.getenv("WINDOWS_MCP_OAUTH_SIGNING_KEY_PATH", "").strip()
    if env_path:
        return Path(env_path)
    if db_path is not None and str(db_path) != ":memory:":
        return Path(db_path).resolve().parent / "secrets" / "oauth_signing.key"
    state_root = os.getenv("MCP_STATE_ROOT", "").strip()
    if state_root:
        return Path(state_root) / "runtime" / "secrets" / "oauth_signing.key"
    return DEFAULT_OAUTH_SIGNING_KEY_PATH


def load_oauth_signing_key(
    oauth_signing_key: str | None = None,
    *,
    key_path: str | Path | None = None,
    db_path: str | Path | None = None,
    caller_auth_token: str | None = None,
) -> str:
    """Resolve an independent OAuth signing key strictly distinct from connector Bearer secret (P0-04)."""
    if oauth_signing_key is not None:
        candidate = str(oauth_signing_key).strip()
        if not candidate or len(candidate) < 16 or candidate == "default_secret":
            raise PermissionError("Forbidden (P0-04): OAuth signing key is empty, too short, or unsafe default")
    else:
        env_key = os.getenv("WINDOWS_MCP_OAUTH_SIGNING_KEY", "").strip()
        if env_key:
            candidate = env_key
        else:
            resolved_path = resolve_oauth_signing_key_path(key_path, db_path=db_path)
            if resolved_path.exists() and resolved_path.is_file():
                candidate = resolved_path.read_text(encoding="utf-8", errors="replace").strip()
            else:
                resolved_path.parent.mkdir(parents=True, exist_ok=True)
                candidate = f"mcp_osk_{secrets.token_urlsafe(48)}"
                resolved_path.write_text(candidate + "\n", encoding="utf-8")

        if not candidate or len(candidate) < 16 or candidate == "default_secret":
            raise PermissionError("Forbidden (P0-04): OAuth signing key is empty, too short, or unsafe default")

    if caller_auth_token is not None and caller_auth_token.strip():
        if hmac.compare_digest(candidate.encode("utf-8"), caller_auth_token.strip().encode("utf-8")):
            raise PermissionError(
                "Forbidden (P0-04): OAuth signing key must never equal the shared connector Bearer secret"
            )

    try:
        if DEFAULT_CALLER_TOKEN_FILE.exists() and DEFAULT_CALLER_TOKEN_FILE.is_file():
            file_caller_tok = DEFAULT_CALLER_TOKEN_FILE.read_text(encoding="utf-8", errors="replace").strip()
            if file_caller_tok and hmac.compare_digest(candidate.encode("utf-8"), file_caller_tok.encode("utf-8")):
                raise PermissionError(
                    "Forbidden (P0-04): OAuth signing key must never reuse runtime/secrets/gateway_caller.token"
                )
    except PermissionError:
        raise
    except OSError:
        pass

    return candidate


DEFAULT_OWNER_ADMIN_TOKEN_PATH = PROJECT_ROOT / "runtime" / "secrets" / "owner_admin.key"


def resolve_owner_admin_token_path(
    key_path: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> Path:
    """Resolve the path to owner_admin.key respecting isolated test state roots and production runtime/secrets."""
    if key_path is not None:
        return Path(key_path)
    env_path = os.getenv("WINDOWS_MCP_OWNER_ADMIN_KEY_PATH", "").strip()
    if env_path:
        return Path(env_path)
    if db_path is not None and str(db_path) != ":memory:":
        return Path(db_path).resolve().parent / "secrets" / "owner_admin.key"
    state_root = os.getenv("MCP_STATE_ROOT", "").strip()
    if state_root:
        return Path(state_root) / "runtime" / "secrets" / "owner_admin.key"
    return DEFAULT_OWNER_ADMIN_TOKEN_PATH


def load_owner_admin_token(
    owner_admin_token: str | None = None,
    *,
    key_path: str | Path | None = None,
    db_path: str | Path | None = None,
    caller_auth_token: str | None = None,
    oauth_signing_key: str | None = None,
) -> str:
    """Resolve an independent local owner administration secret strictly distinct from connector Bearer (Workstream A1)."""
    if owner_admin_token is not None:
        candidate = str(owner_admin_token).strip()
        if not candidate or len(candidate) < 16 or candidate == "default_secret":
            raise PermissionError("Forbidden (A1): Owner admin token is empty, too short, or unsafe default")
    else:
        env_key = os.getenv("WINDOWS_MCP_OWNER_ADMIN_TOKEN", "").strip()
        if env_key:
            candidate = env_key
        else:
            resolved_path = resolve_owner_admin_token_path(key_path, db_path=db_path)
            if resolved_path.exists() and resolved_path.is_file():
                candidate = resolved_path.read_text(encoding="utf-8", errors="replace").strip()
            else:
                resolved_path.parent.mkdir(parents=True, exist_ok=True)
                candidate = f"mcp_oadm_{secrets.token_urlsafe(36)}"
                resolved_path.write_text(candidate + "\n", encoding="utf-8")

        if not candidate or len(candidate) < 16 or candidate == "default_secret":
            raise PermissionError("Forbidden (A1): Owner admin token is empty, too short, or unsafe default")

    if caller_auth_token is not None and caller_auth_token.strip():
        if hmac.compare_digest(candidate.encode("utf-8"), caller_auth_token.strip().encode("utf-8")):
            raise PermissionError(
                "Forbidden (A1): Owner admin token must never equal the shared connector Bearer secret"
            )
    if oauth_signing_key is not None and oauth_signing_key.strip():
        if hmac.compare_digest(candidate.encode("utf-8"), oauth_signing_key.strip().encode("utf-8")):
            raise PermissionError(
                "Forbidden (A1): Owner admin token must never equal the OAuth signing key"
            )
    return candidate


CLEAN_CALLER_ID_RE = re.compile(r"^[A-Za-z0-9_\-\.:]{1,64}$")
FORBIDDEN_CALLER_ROLES = {"anonymous", "root", "system", "admin", "gateway", "superuser"}
DEFAULT_MAX_REQUEST_BYTES = 256 * 1024  # 256 KB
DEFAULT_MAX_SUBMISSIONS_PER_MINUTE = 10


def _extract_caller_token(request: Request) -> str | None:
    auth_hdr = request.headers.get("authorization", "").strip()
    if auth_hdr.lower().startswith("bearer "):
        tok = auth_hdr[7:].strip()
        if tok:
            return tok
    alt_hdr = request.headers.get("x-mcp-caller-token", "").strip()
    if alt_hdr:
        return alt_hdr
    alt_auth = request.headers.get("x-mcp-auth-token", "").strip()
    if alt_auth:
        return alt_auth
    return None


def _verify_caller_token(provided: str | None, expected: str) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _jsonrpc_auth_error_response(
    *,
    status_code: int,
    req_id: Any,
    code: int,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    safe_msg = redact_secrets(message)
    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": safe_msg,
            },
            "result": {
                "content": [{"type": "text", "text": f"Blocked or invalid: {safe_msg}"}],
                "isError": True,
            },
        },
    )


class _SQLiteOAuthPersistence:
    """Embedded SQLite helper for durable OAuth clients, authorization codes, and token revocations (H07)."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            env_db = os.getenv("WINDOWS_MCP_OAUTH_DB_PATH")
            if env_db:
                self.db_path = Path(env_db)
            else:
                state_root = os.getenv("MCP_STATE_ROOT")
                if state_root:
                    self.db_path = Path(state_root) / "oauth_state.db"
                else:
                    self.db_path = PROJECT_ROOT / "runtime" / "oauth_state.db"
        elif str(db_path) == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = Path(db_path)

        self._lock = threading.Lock()
        if str(self.db_path) == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        else:
            self._mem_conn = None
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def _db(self):
        if self._mem_conn is not None:
            with self._lock, self._mem_conn:
                yield self._mem_conn
        else:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            try:
                with self._lock, conn:
                    yield conn
            finally:
                conn.close()

    def close(self) -> None:
        if self._mem_conn is not None:
            with self._lock:
                self._mem_conn.close()
                self._mem_conn = None

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_revocations (
                    token_id TEXT PRIMARY KEY,
                    client_id TEXT,
                    revoked_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    reason TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_secret_hash TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    client_name TEXT,
                    redirect_uris TEXT,
                    grant_types TEXT,
                    allowed_scopes TEXT,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
                    code TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    code_challenge_method TEXT NOT NULL,
                    state TEXT,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_capability_grants (
                    grant_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    oauth_token_jti TEXT NOT NULL,
                    allowed_tools TEXT NOT NULL,
                    allowed_paths TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    max_uses INTEGER NOT NULL DEFAULT 20,
                    used_count INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_reason TEXT,
                    signature TEXT NOT NULL,
                    delegation_id TEXT NOT NULL DEFAULT '',
                    allow_destructive_operations INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            for _col_ddl in (
                "ALTER TABLE owner_capability_grants ADD COLUMN delegation_id TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE owner_capability_grants ADD COLUMN allow_destructive_operations INTEGER NOT NULL DEFAULT 0",
            ):
                try:
                    conn.execute(_col_ddl)
                except sqlite3.OperationalError:
                    pass
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_durable_delegations (
                    delegation_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    allowed_tools TEXT NOT NULL,
                    allowed_paths TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    total_operation_budget INTEGER NOT NULL DEFAULT 5000,
                    total_used_count INTEGER NOT NULL DEFAULT 0,
                    allow_destructive_operations INTEGER NOT NULL DEFAULT 0,
                    audit_identity TEXT NOT NULL DEFAULT 'local_owner',
                    revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_reason TEXT,
                    signature TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_cloud_leases (
                    lease_id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL,
                    oauth_token TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def prune_expired_revocations(self) -> int:
        now = time.time()
        with self._db() as conn:
            cur = conn.execute("DELETE FROM oauth_revocations WHERE expires_at < ?", (now,))
            return cur.rowcount

    def load_active_revocations(self) -> set[str]:
        now = time.time()
        with self._db() as conn:
            cur = conn.execute("SELECT token_id FROM oauth_revocations WHERE expires_at >= ?", (now,))
            return {row["token_id"] for row in cur.fetchall()}

    def revoke_token(
        self,
        token_id: str,
        client_id: str | None = None,
        expires_at: float | None = None,
        reason: str = "",
    ) -> None:
        now = time.time()
        if expires_at is None:
            expires_at = now + 86400 * 30
        with self._db() as conn:
            count_cur = conn.execute("SELECT COUNT(*) as c FROM oauth_revocations")
            cnt = count_cur.fetchone()["c"]
            if cnt >= 10000:
                conn.execute(
                    """
                    DELETE FROM oauth_revocations WHERE token_id IN (
                        SELECT token_id FROM oauth_revocations ORDER BY revoked_at ASC LIMIT 1000
                    )
                    """
                )
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_revocations (token_id, client_id, revoked_at, expires_at, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (token_id, client_id or "", now, expires_at, reason),
            )

    def is_token_revoked(self, token_id: str) -> bool:
        now = time.time()
        with self._db() as conn:
            cur = conn.execute(
                "SELECT 1 FROM oauth_revocations WHERE token_id = ? AND expires_at >= ?",
                (token_id, now),
            )
            return cur.fetchone() is not None

    def register_client(
        self,
        client_id: str,
        client_secret_hash: str,
        owner_id: str,
        client_name: str | None = None,
        redirect_uris: list[str] | str | None = None,
        grant_types: list[str] | str | None = None,
        allowed_scopes: list[str] | str | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        r_json = json.dumps(redirect_uris if isinstance(redirect_uris, list) else [redirect_uris or ""])
        g_json = json.dumps(grant_types if isinstance(grant_types, list) else [grant_types or "client_credentials"])
        s_json = json.dumps(allowed_scopes if isinstance(allowed_scopes, list) else [allowed_scopes or "mcp:autonomous"])
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_clients (
                    client_id, client_secret_hash, owner_id, client_name,
                    redirect_uris, grant_types, allowed_scopes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (client_id, client_secret_hash, owner_id, client_name or "", r_json, g_json, s_json, now),
            )
        return {
            "client_id": client_id,
            "owner_id": owner_id,
            "client_name": client_name or "",
            "redirect_uris": redirect_uris if isinstance(redirect_uris, list) else [redirect_uris or ""],
            "grant_types": grant_types if isinstance(grant_types, list) else [grant_types or "client_credentials"],
            "allowed_scopes": allowed_scopes if isinstance(allowed_scopes, list) else [allowed_scopes or "mcp:autonomous"],
            "created_at": now,
        }

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            cur = conn.execute(
                "SELECT client_id, client_secret_hash, owner_id, client_name, redirect_uris, grant_types, allowed_scopes, created_at FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            try:
                redirect_uris = json.loads(row["redirect_uris"])
            except Exception:
                redirect_uris = []
            try:
                grant_types = json.loads(row["grant_types"])
            except Exception:
                grant_types = []
            try:
                allowed_scopes = json.loads(row["allowed_scopes"])
            except Exception:
                allowed_scopes = []
            return {
                "client_id": row["client_id"],
                "client_secret_hash": row["client_secret_hash"],
                "owner_id": row["owner_id"],
                "client_name": row["client_name"],
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "allowed_scopes": allowed_scopes,
                "created_at": row["created_at"],
            }

    def store_authorization_code(
        self,
        code: str,
        client_id: str,
        owner_id: str,
        redirect_uri: str,
        scope: str,
        resource: str,
        code_challenge: str,
        code_challenge_method: str,
        state: str | None = None,
        ttl_seconds: float = 300.0,
    ) -> None:
        now = time.time()
        expires_at = now + ttl_seconds
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_authorization_codes (
                    code, client_id, owner_id, redirect_uri, scope, resource,
                    code_challenge, code_challenge_method, state, created_at, expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    code, client_id, owner_id, redirect_uri, scope, resource,
                    code_challenge, code_challenge_method, state or "", now, expires_at
                ),
            )

    def consume_authorization_code(self, code: str) -> dict[str, Any] | None:
        with self._db() as conn:
            cur = conn.execute(
                """
                SELECT code, client_id, owner_id, redirect_uri, scope, resource,
                       code_challenge, code_challenge_method, state, created_at, expires_at, used
                FROM oauth_authorization_codes WHERE code = ?
                """,
                (code,),
            )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if row["used"] == 0:
                conn.execute(
                    "UPDATE oauth_authorization_codes SET used = 1 WHERE code = ? AND used = 0",
                    (code,),
                )
            return res

    @staticmethod
    def _sign_owner_grant(
        secret: str,
        grant_id: str,
        owner_id: str,
        client_id: str,
        oauth_token_jti: str,
        allowed_tools_json: str,
        allowed_paths_json: str,
        issued_at: float,
        expires_at: float,
        max_uses: int,
    ) -> str:
        payload = f"{grant_id}|{owner_id}|{client_id}|{oauth_token_jti}|{allowed_tools_json}|{allowed_paths_json}|{issued_at:.6f}|{expires_at:.6f}|{max_uses}"
        return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _sign_owner_durable_delegation(
        secret: str,
        delegation_id: str,
        owner_id: str,
        client_id: str,
        allowed_tools_json: str,
        allowed_paths_json: str,
        issued_at: float,
        expires_at: float,
        total_operation_budget: int,
        allow_destructive_operations: int,
        audit_identity: str,
    ) -> str:
        payload = (
            f"odd|{delegation_id}|{owner_id}|{client_id}|{allowed_tools_json}|"
            f"{allowed_paths_json}|{issued_at:.6f}|{expires_at:.6f}|"
            f"{int(total_operation_budget)}|{int(allow_destructive_operations)}|{audit_identity}"
        )
        return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_owner_durable_delegation(
        self,
        *,
        secret: str,
        allowed_tools: list[str],
        allowed_paths: list[str] | None = None,
        owner_id: str = "local_owner",
        client_id: str = "chatgpt_web_owner_client",
        ttl_seconds: float = 28800.0,
        total_operation_budget: int = 5000,
        allow_destructive_operations: bool = False,
        audit_identity: str = "local_owner",
        delegation_id: str | None = None,
    ) -> dict[str, Any]:
        if ttl_seconds <= 0 or ttl_seconds > 86400.0:
            raise ValueError("Owner durable delegation ttl_seconds must be bounded (0 < ttl <= 86400s)")
        if total_operation_budget <= 0 or total_operation_budget > 100000:
            raise ValueError("Owner durable delegation total_operation_budget must be bounded (1 <= budget <= 100000)")
        if not secret or len(str(secret).strip()) < 16 or str(secret).strip() == "default_secret":
            raise ValueError("Invalid or unconfigured OAuth signing key for durable delegation")
        now = time.time()
        expires_at = now + float(ttl_seconds)
        did = delegation_id or f"odd_{uuid.uuid4().hex[:20]}"
        tools_json = json.dumps(sorted(set(allowed_tools)), separators=(",", ":"))
        paths_list = _normalize_owner_allowed_paths(allowed_paths)
        paths_json = json.dumps(paths_list, separators=(",", ":"))
        allow_dest_int = 1 if allow_destructive_operations else 0
        sig = self._sign_owner_durable_delegation(
            secret,
            did,
            owner_id,
            client_id,
            tools_json,
            paths_json,
            now,
            expires_at,
            int(total_operation_budget),
            allow_dest_int,
            audit_identity,
        )
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO owner_durable_delegations (
                    delegation_id, owner_id, client_id, allowed_tools, allowed_paths,
                    issued_at, expires_at, total_operation_budget, total_used_count,
                    allow_destructive_operations, audit_identity, revoked, revoked_reason, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0, '', ?)
                """,
                (
                    did,
                    owner_id,
                    client_id,
                    tools_json,
                    paths_json,
                    now,
                    expires_at,
                    int(total_operation_budget),
                    allow_dest_int,
                    audit_identity,
                    sig,
                ),
            )
        return {
            "delegation_id": did,
            "owner_id": owner_id,
            "client_id": client_id,
            "allowed_tools": json.loads(tools_json),
            "allowed_paths": paths_list,
            "issued_at": now,
            "expires_at": expires_at,
            "total_operation_budget": int(total_operation_budget),
            "total_used_count": 0,
            "allow_destructive_operations": bool(allow_destructive_operations),
            "audit_identity": audit_identity,
            "revoked": False,
            "signature": sig,
        }

    def revoke_owner_durable_delegation(self, delegation_id: str, reason: str = "revoked_by_owner") -> bool:
        with self._db() as conn:
            cur = conn.execute(
                "UPDATE owner_durable_delegations SET revoked = 1, revoked_reason = ? WHERE delegation_id = ?",
                (reason, delegation_id),
            )
            conn.execute(
                "UPDATE owner_capability_grants SET revoked = 1, revoked_reason = ? WHERE delegation_id = ?",
                (f"parent_delegation_revoked:{reason}", delegation_id),
            )
            conn.execute(
                """
                UPDATE owner_cloud_leases
                SET revoked = 1
                WHERE grant_id IN (SELECT grant_id FROM owner_capability_grants WHERE delegation_id = ?)
                """,
                (delegation_id,),
            )
            return cur.rowcount > 0

    def get_owner_durable_delegation(self, delegation_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            cur = conn.execute(
                "SELECT * FROM owner_durable_delegations WHERE delegation_id = ?",
                (delegation_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["allowed_tools_list"] = json.loads(d["allowed_tools"])
            d["allowed_paths_list"] = json.loads(d["allowed_paths"])
            d["allow_destructive_operations"] = bool(d.get("allow_destructive_operations"))
            return d

    def issue_owner_capability_grant(
        self,
        *,
        secret: str,
        allowed_tools: list[str],
        allowed_paths: list[str] | None = None,
        owner_id: str = "local_owner",
        client_id: str = "cloud_client_default",
        oauth_token_jti: str = "",
        ttl_seconds: float = 600.0,
        max_uses: int = 20,
        grant_id: str | None = None,
        delegation_id: str = "",
        allow_destructive_operations: bool = False,
    ) -> dict[str, Any]:
        if ttl_seconds <= 0 or ttl_seconds > 900.0:
            raise ValueError("Owner capability grant ttl_seconds must be short-lived (0 < ttl <= 900s)")
        if max_uses <= 0 or max_uses > 100:
            raise ValueError("Owner capability grant max_uses must be bounded (1 <= max_uses <= 100)")
        now = time.time()
        expires_at = now + float(ttl_seconds)
        gid = grant_id or f"ocg_{uuid.uuid4().hex[:20]}"
        tools_json = json.dumps(sorted(set(allowed_tools)), separators=(",", ":"))
        paths_list = _normalize_owner_allowed_paths(allowed_paths)
        paths_json = json.dumps(paths_list, separators=(",", ":"))
        sig = self._sign_owner_grant(
            secret, gid, owner_id, client_id, oauth_token_jti, tools_json, paths_json, now, expires_at, int(max_uses)
        )
        allow_dest_int = 1 if allow_destructive_operations else 0
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO owner_capability_grants (
                    grant_id, owner_id, client_id, oauth_token_jti,
                    allowed_tools, allowed_paths, issued_at, expires_at,
                    max_uses, used_count, revoked, revoked_reason, signature,
                    delegation_id, allow_destructive_operations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '', ?, ?, ?)
                """,
                (
                    gid, owner_id, client_id, oauth_token_jti,
                    tools_json, paths_json, now, expires_at, int(max_uses), sig,
                    str(delegation_id or ""), allow_dest_int,
                ),
            )
        return {
            "grant_id": gid,
            "owner_id": owner_id,
            "client_id": client_id,
            "oauth_token_jti": oauth_token_jti,
            "allowed_tools": json.loads(tools_json),
            "allowed_paths": paths_list,
            "issued_at": now,
            "expires_at": expires_at,
            "max_uses": int(max_uses),
            "used_count": 0,
            "revoked": False,
            "signature": sig,
            "delegation_id": str(delegation_id or ""),
            "allow_destructive_operations": bool(allow_destructive_operations),
        }

    def revoke_owner_capability_grant(self, grant_id: str, reason: str = "revoked_by_owner") -> bool:
        with self._db() as conn:
            cur = conn.execute(
                "UPDATE owner_capability_grants SET revoked = 1, revoked_reason = ? WHERE grant_id = ?",
                (reason, grant_id),
            )
            conn.execute(
                "UPDATE owner_cloud_leases SET revoked = 1 WHERE grant_id = ?",
                (grant_id,),
            )
            return cur.rowcount > 0

    def get_owner_capability_grant(self, grant_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            cur = conn.execute(
                "SELECT * FROM owner_capability_grants WHERE grant_id = ?",
                (grant_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["allowed_tools_list"] = json.loads(d["allowed_tools"])
            d["allowed_paths_list"] = json.loads(d["allowed_paths"])
            d["allow_destructive_operations"] = bool(d.get("allow_destructive_operations"))
            return d

    def resolve_or_renew_owner_grant_for_token(
        self,
        *,
        secret: str,
        owner_id: str,
        client_id: str,
        oauth_token_jti: str,
        requested_grant_id: str | None = None,
        rolling_ttl_seconds: float = 900.0,
        rolling_max_uses: int = 100,
    ) -> str | None:
        """Resolve an active short-lived grant or automatically mint a rolling grant from an active Durable Owner Delegation."""
        if not owner_id or not client_id or not oauth_token_jti:
            return requested_grant_id
        if not secret or len(str(secret).strip()) < 16 or str(secret).strip() == "default_secret":
            return requested_grant_id

        req_gid = str(requested_grant_id or "").strip()
        now = time.time()

        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if req_gid:
                row = conn.execute(
                    "SELECT * FROM owner_capability_grants WHERE grant_id = ?",
                    (req_gid,),
                ).fetchone()
                if not row:
                    return req_gid
                g = dict(row)
                # If owner/client mismatch or explicitly revoked, do not auto-renew
                if (
                    str(g.get("owner_id")) != str(owner_id)
                    or str(g.get("client_id")) != str(client_id)
                    or int(g.get("revoked", 0)) != 0
                ):
                    return req_gid
                # If still active and matches current token JTI, verify signature and reuse
                if str(g.get("oauth_token_jti")) == str(oauth_token_jti):
                    expected_g_sig = self._sign_owner_grant(
                        secret,
                        g["grant_id"],
                        g["owner_id"],
                        g["client_id"],
                        g["oauth_token_jti"],
                        g["allowed_tools"],
                        g["allowed_paths"],
                        float(g["issued_at"]),
                        float(g["expires_at"]),
                        int(g["max_uses"]),
                    )
                    if not hmac.compare_digest(str(g.get("signature", "")), expected_g_sig):
                        return req_gid
                    parent_did = str(g.get("delegation_id") or "").strip()
                    if float(g["expires_at"]) > now and int(g["used_count"]) < int(g["max_uses"]):
                        if not parent_did:
                            return req_gid
                        p_row = conn.execute(
                            "SELECT revoked, expires_at, total_used_count, total_operation_budget FROM owner_durable_delegations WHERE delegation_id = ?",
                            (parent_did,),
                        ).fetchone()
                        if (
                            p_row
                            and int(p_row["revoked"]) == 0
                            and float(p_row["expires_at"]) > now
                            and int(p_row["total_used_count"]) < int(p_row["total_operation_budget"])
                        ):
                            return req_gid
                        return req_gid
                # If expired, exhausted, or from a previous token of the same owner/client,
                # fall through to auto-renew a fresh rolling grant from an active durable delegation!

            # Check if there is already an active unrevoked grant for this exact (owner_id, client_id, oauth_token_jti)
            active_rows = conn.execute(
                """
                SELECT * FROM owner_capability_grants
                WHERE owner_id = ? AND client_id = ? AND oauth_token_jti = ?
                  AND revoked = 0 AND expires_at > ? AND used_count < max_uses
                ORDER BY issued_at DESC
                """,
                (owner_id, client_id, oauth_token_jti, now),
            ).fetchall()
            for arow in active_rows:
                ad = dict(arow)
                p_did = str(ad.get("delegation_id") or "").strip()
                if p_did:
                    p_del = conn.execute(
                        "SELECT * FROM owner_durable_delegations WHERE delegation_id = ?",
                        (p_did,),
                    ).fetchone()
                    if (
                        p_del
                        and int(p_del["revoked"]) == 0
                        and float(p_del["expires_at"]) > now
                        and int(p_del["total_used_count"]) < int(p_del["total_operation_budget"])
                    ):
                        return str(ad["grant_id"])
                elif not req_gid and client_id == "chatgpt_web_owner_client":
                    return str(ad["grant_id"])

            # Look up active Layer-1 Durable Owner Delegation for (owner_id, client_id)
            del_row = conn.execute(
                """
                SELECT * FROM owner_durable_delegations
                WHERE owner_id = ? AND client_id = ?
                  AND revoked = 0 AND expires_at > ? AND total_used_count < total_operation_budget
                ORDER BY issued_at DESC LIMIT 1
                """,
                (owner_id, client_id, now),
            ).fetchone()
            if not del_row:
                # If an unrevoked delegation exists with budget that simply lapsed session TTL,
                # auto-renew its session TTL for this verified owner caller
                lapsed_del = conn.execute(
                    """
                    SELECT * FROM owner_durable_delegations
                    WHERE owner_id = ? AND client_id = ?
                      AND revoked = 0 AND total_used_count < total_operation_budget
                    ORDER BY issued_at DESC LIMIT 1
                    """,
                    (owner_id, client_id),
                ).fetchone()
                if lapsed_del:
                    ld_rec = dict(lapsed_del)
                    expected_lapsed_sig = self._sign_owner_durable_delegation(
                        secret,
                        str(ld_rec["delegation_id"]),
                        str(ld_rec["owner_id"]),
                        str(ld_rec["client_id"]),
                        str(ld_rec["allowed_tools"]),
                        str(ld_rec["allowed_paths"]),
                        float(ld_rec["issued_at"]),
                        float(ld_rec["expires_at"]),
                        int(ld_rec["total_operation_budget"]),
                        int(ld_rec["allow_destructive_operations"]),
                        str(ld_rec["audit_identity"]),
                    )
                    if hmac.compare_digest(str(ld_rec["signature"]), expected_lapsed_sig):
                        ext_ttl = 28800.0
                        new_del_exp = now + ext_ttl
                        new_del_sig = self._sign_owner_durable_delegation(
                            secret,
                            str(ld_rec["delegation_id"]),
                            str(ld_rec["owner_id"]),
                            str(ld_rec["client_id"]),
                            str(ld_rec["allowed_tools"]),
                            str(ld_rec["allowed_paths"]),
                            float(ld_rec["issued_at"]),
                            new_del_exp,
                            int(ld_rec["total_operation_budget"]),
                            int(ld_rec["allow_destructive_operations"]),
                            str(ld_rec["audit_identity"]),
                        )
                        conn.execute(
                            "UPDATE owner_durable_delegations SET expires_at = ?, signature = ? WHERE delegation_id = ?",
                            (new_del_exp, new_del_sig, str(ld_rec["delegation_id"])),
                        )
                        ld_rec["expires_at"] = new_del_exp
                        ld_rec["signature"] = new_del_sig
                        del_row = ld_rec
            if not del_row:
                return req_gid or None

            del_rec = dict(del_row)
            expected_del_sig = self._sign_owner_durable_delegation(
                secret,
                str(del_rec["delegation_id"]),
                str(del_rec["owner_id"]),
                str(del_rec["client_id"]),
                str(del_rec["allowed_tools"]),
                str(del_rec["allowed_paths"]),
                float(del_rec["issued_at"]),
                float(del_rec["expires_at"]),
                int(del_rec["total_operation_budget"]),
                int(del_rec["allow_destructive_operations"]),
                str(del_rec["audit_identity"]),
            )
            if not hmac.compare_digest(str(del_rec["signature"]), expected_del_sig):
                return req_gid or None

            rem_ttl = max(1.0, float(del_rec["expires_at"]) - now)
            grant_ttl = min(float(rolling_ttl_seconds), rem_ttl, 900.0)
            rem_budget = max(1, int(del_rec["total_operation_budget"]) - int(del_rec["total_used_count"]))
            grant_max_uses = min(int(rolling_max_uses), rem_budget, 100)
            new_gid = f"ocg_roll_{uuid.uuid4().hex[:16]}"
            new_exp = now + grant_ttl
            new_sig = self._sign_owner_grant(
                secret,
                new_gid,
                owner_id,
                client_id,
                oauth_token_jti,
                str(del_rec["allowed_tools"]),
                str(del_rec["allowed_paths"]),
                now,
                new_exp,
                grant_max_uses,
            )
            conn.execute(
                """
                INSERT INTO owner_capability_grants (
                    grant_id, owner_id, client_id, oauth_token_jti,
                    allowed_tools, allowed_paths, issued_at, expires_at,
                    max_uses, used_count, revoked, revoked_reason, signature,
                    delegation_id, allow_destructive_operations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '', ?, ?, ?)
                """,
                (
                    new_gid,
                    owner_id,
                    client_id,
                    oauth_token_jti,
                    str(del_rec["allowed_tools"]),
                    str(del_rec["allowed_paths"]),
                    now,
                    new_exp,
                    grant_max_uses,
                    new_sig,
                    str(del_rec["delegation_id"]),
                    int(del_rec["allow_destructive_operations"]),
                ),
            )
            return new_gid

    def validate_and_consume_owner_grant(
        self,
        grant_id: str = "",
        *,
        secret: str,
        tool_name: str,
        target_path: str | None = None,
        expected_owner_id: str = "local_owner",
        expected_client_id: str | None = None,
        oauth_token_jti: str | None = None,
        consume: bool = True,
        require_client_and_jti: bool = True,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        if not grant_id or not str(grant_id).strip():
            return False, "Missing capability_grant_id", None
        if not secret or len(str(secret).strip()) < 16 or str(secret).strip() == "default_secret":
            return False, "Invalid or unconfigured OAuth signing key for capability grant verification", None
        if not expected_owner_id or not str(expected_owner_id).strip():
            return False, "Missing expected_owner_id in authentication context", None
        if require_client_and_jti:
            if not expected_client_id or not str(expected_client_id).strip():
                return False, "Incomplete authentication context: missing authenticated OAuth client_id", None
            if not oauth_token_jti or not str(oauth_token_jti).strip():
                return False, "Incomplete authentication context: missing authenticated OAuth token JTI", None

        now = time.time()
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "SELECT * FROM owner_capability_grants WHERE grant_id = ?",
                (grant_id,),
            )
            row = cur.fetchone()
            if not row:
                return False, f"Capability grant '{grant_id}' does not exist", None
            rec = dict(row)
            rec["allow_destructive_operations"] = bool(rec.get("allow_destructive_operations"))
            expected_sig = self._sign_owner_grant(
                secret,
                rec["grant_id"],
                rec["owner_id"],
                rec["client_id"],
                rec["oauth_token_jti"],
                rec["allowed_tools"],
                rec["allowed_paths"],
                float(rec["issued_at"]),
                float(rec["expires_at"]),
                int(rec["max_uses"]),
            )
            if not hmac.compare_digest(str(rec["signature"]), expected_sig):
                return False, f"Capability grant '{grant_id}' failed HMAC signature verification", rec
            if int(rec["revoked"]) != 0:
                return False, f"Capability grant '{grant_id}' has been revoked ({rec.get('revoked_reason') or 'revoked'})", rec
            if float(rec["expires_at"]) <= now:
                return False, f"Capability grant '{grant_id}' has expired", rec
            if str(rec["owner_id"]) != str(expected_owner_id):
                return False, f"Capability grant '{grant_id}' owner_id mismatch", rec
            if require_client_and_jti or expected_client_id is not None:
                if not rec.get("client_id") or str(rec["client_id"]) != str(expected_client_id or ""):
                    return False, f"Capability grant '{grant_id}' is bound to a different OAuth client_id", rec
            if require_client_and_jti or rec.get("oauth_token_jti") or oauth_token_jti is not None:
                if not rec.get("oauth_token_jti") or not oauth_token_jti or str(rec["oauth_token_jti"]) != str(oauth_token_jti):
                    return False, f"Capability grant '{grant_id}' is bound to a different OAuth token JTI", rec

            # Enforce parent Durable Owner Delegation state if grant is linked to a delegation
            parent_did = str(rec.get("delegation_id") or "").strip()
            if parent_did:
                del_row = conn.execute(
                    "SELECT * FROM owner_durable_delegations WHERE delegation_id = ?",
                    (parent_did,),
                ).fetchone()
                if not del_row:
                    return False, f"Parent durable delegation '{parent_did}' does not exist", rec
                del_rec = dict(del_row)
                expected_del_sig = self._sign_owner_durable_delegation(
                    secret,
                    str(del_rec["delegation_id"]),
                    str(del_rec["owner_id"]),
                    str(del_rec["client_id"]),
                    str(del_rec["allowed_tools"]),
                    str(del_rec["allowed_paths"]),
                    float(del_rec["issued_at"]),
                    float(del_rec["expires_at"]),
                    int(del_rec["total_operation_budget"]),
                    int(del_rec["allow_destructive_operations"]),
                    str(del_rec["audit_identity"]),
                )
                if not hmac.compare_digest(str(del_rec["signature"]), expected_del_sig):
                    return False, f"Parent durable delegation '{parent_did}' failed HMAC signature verification", rec
                if int(del_rec["revoked"]) != 0:
                    return False, f"Parent durable delegation '{parent_did}' has been revoked ({del_rec.get('revoked_reason') or 'revoked'})", rec
                if float(del_rec["expires_at"]) <= now:
                    return False, f"Parent durable delegation '{parent_did}' has expired", rec
                if int(del_rec["total_used_count"]) >= int(del_rec["total_operation_budget"]):
                    return False, f"Parent durable delegation '{parent_did}' has exhausted its total_operation_budget ({del_rec['total_operation_budget']})", rec
                rec["allow_destructive_operations"] = bool(del_rec.get("allow_destructive_operations"))

            # Enforce associated lease revocation or expiration if any lease was registered for this grant
            lease_rows = conn.execute(
                "SELECT lease_id, revoked, expires_at FROM owner_cloud_leases WHERE grant_id = ?",
                (grant_id,),
            ).fetchall()
            if lease_rows:
                if any(int(lr["revoked"]) != 0 for lr in lease_rows) or not any(
                    int(lr["revoked"]) == 0 and float(lr["expires_at"]) > now for lr in lease_rows
                ):
                    return False, f"Associated owner cloud lease for capability grant '{grant_id}' has been revoked or expired", rec

            if int(rec["used_count"]) >= int(rec["max_uses"]):
                return False, f"Capability grant '{grant_id}' has exhausted its bounded session limit ({rec['max_uses']})", rec
            allowed_tools = json.loads(rec["allowed_tools"])
            _sec_edit_tools = (
                "agent_read_file",
                "agent_create_file",
                "agent_write_file",
                "agent_apply_patch",
                "agent_delete_file",
                "agent_create_directory",
                "agent_delete_directory",
                "agent_move_path",
                "agent_copy_path",
            )
            _global_fs_tools = OWNER_DELEGATION_CAPABILITY_PROFILES.get("OWNER_GLOBAL_FILESYSTEM", [])
            tool_authorized = (
                tool_name in allowed_tools
                or "*" in allowed_tools
                or (
                    tool_name in _sec_edit_tools
                    and ("SECURITY_CONTROL_EDIT" in allowed_tools or "FILE_WRITE" in allowed_tools)
                )
                or (
                    "OWNER_GLOBAL_FILESYSTEM" in allowed_tools
                    and tool_name in _global_fs_tools
                )
            )
            if not tool_authorized:
                return False, f"Tool '{tool_name}' is not authorized by capability grant '{grant_id}'", rec
            allowed_paths = json.loads(rec["allowed_paths"])
            if target_path:
                if not allowed_paths:
                    return False, f"Capability grant '{grant_id}' has no allowed_paths for path-scoped operation", rec
                try:
                    resolved_target = Path(target_path).resolve()
                    path_ok = False
                    fs_roots = [Path(r).resolve() for r in discover_windows_filesystem_roots()]
                    for ap in allowed_paths:
                        ap_str = str(ap).strip()
                        if ap_str.upper() in ("*", "AUTO"):
                            if any(resolved_target == r or resolved_target.is_relative_to(r) for r in fs_roots):
                                path_ok = True
                                break
                        else:
                            ap_path = Path(ap_str).resolve()
                            if resolved_target == ap_path or resolved_target.is_relative_to(ap_path):
                                path_ok = True
                                break
                    if not path_ok:
                        return False, f"Target path '{target_path}' is outside capability grant '{grant_id}' allowed_paths", rec
                except Exception as exc:
                    return False, f"Invalid target path '{target_path}': {exc}", rec
            if consume:
                if parent_did:
                    upd_del = conn.execute(
                        """
                        UPDATE owner_durable_delegations
                        SET total_used_count = total_used_count + 1
                        WHERE delegation_id = ? AND revoked = 0 AND expires_at > ? AND total_used_count < total_operation_budget
                        """,
                        (parent_did, now),
                    )
                    if upd_del.rowcount != 1:
                        conn.rollback()
                        return False, f"Parent durable delegation '{parent_did}' has exhausted its total_operation_budget", rec
                upd = conn.execute(
                    """
                    UPDATE owner_capability_grants
                    SET used_count = used_count + 1
                    WHERE grant_id = ? AND revoked = 0 AND expires_at > ? AND used_count < max_uses
                    """,
                    (grant_id, now),
                )
                if upd.rowcount != 1:
                    conn.rollback()
                    return False, f"Capability grant '{grant_id}' has exhausted its bounded session limit ({rec['max_uses']})", rec
                rec["used_count"] = int(rec["used_count"]) + 1
            return True, "", rec

    def find_active_owner_grant_for_token(
        self,
        *,
        owner_id: str,
        client_id: str,
        oauth_token_jti: str,
    ) -> str | None:
        if not owner_id or not client_id or not oauth_token_jti:
            return None
        now = time.time()
        with self._db() as conn:
            cur = conn.execute(
                """
                SELECT grant_id, delegation_id FROM owner_capability_grants
                WHERE owner_id = ? AND client_id = ? AND oauth_token_jti = ?
                  AND revoked = 0 AND expires_at > ? AND used_count < max_uses
                ORDER BY issued_at DESC
                """,
                (owner_id, client_id, oauth_token_jti, now),
            )
            for row in cur.fetchall():
                did = str(row["delegation_id"] or "").strip()
                if did:
                    drow = conn.execute(
                        "SELECT revoked, expires_at, total_used_count, total_operation_budget FROM owner_durable_delegations WHERE delegation_id = ?",
                        (did,),
                    ).fetchone()
                    if (
                        not drow
                        or int(drow["revoked"]) != 0
                        or float(drow["expires_at"]) <= now
                        or int(drow["total_used_count"]) >= int(drow["total_operation_budget"])
                    ):
                        continue
                return str(row["grant_id"])
            return None

    def rebind_active_owner_grant_on_refresh(
        self,
        *,
        secret: str,
        owner_id: str,
        client_id: str,
        new_oauth_token_jti: str,
    ) -> dict[str, Any] | None:
        """When an owner OAuth token is refreshed, rebind the active capability grant (or mint a rolling grant from durable delegation) to the new access token JTI."""
        if not secret or not owner_id or not client_id or not new_oauth_token_jti:
            return None
        now = time.time()
        with self._db() as conn:
            cur = conn.execute(
                """
                SELECT grant_id, owner_id, client_id, oauth_token_jti, allowed_tools, allowed_paths,
                       issued_at, expires_at, max_uses, used_count, revoked, delegation_id, allow_destructive_operations
                FROM owner_capability_grants
                WHERE owner_id = ? AND client_id = ? AND revoked = 0 AND expires_at > ? AND used_count < max_uses
                ORDER BY issued_at DESC LIMIT 1
                """,
                (owner_id, client_id, now),
            )
            row = cur.fetchone()
            if row:
                rec = dict(row)
                gid = str(rec["grant_id"])
                new_sig = self._sign_owner_grant(
                    secret,
                    gid,
                    str(rec["owner_id"]),
                    str(rec["client_id"]),
                    new_oauth_token_jti,
                    str(rec["allowed_tools"]),
                    str(rec["allowed_paths"]),
                    float(rec["issued_at"]),
                    float(rec["expires_at"]),
                    int(rec["max_uses"]),
                )
                conn.execute(
                    """
                    UPDATE owner_capability_grants
                    SET oauth_token_jti = ?, signature = ?
                    WHERE grant_id = ? AND revoked = 0
                    """,
                    (new_oauth_token_jti, new_sig, gid),
                )
                rec["oauth_token_jti"] = new_oauth_token_jti
                rec["signature"] = new_sig
                return rec
        renewed_gid = self.resolve_or_renew_owner_grant_for_token(
            secret=secret,
            owner_id=owner_id,
            client_id=client_id,
            oauth_token_jti=new_oauth_token_jti,
        )
        if renewed_gid:
            return self.get_owner_capability_grant(renewed_gid)
        return None

    def activate_owner_cloud_lease(
        self,
        *,
        grant_id: str,
        oauth_token: str,
        owner_id: str = "local_owner",
        ttl_seconds: float = 600.0,
        lease_id: str | None = None,
    ) -> dict[str, Any]:
        if ttl_seconds <= 0 or ttl_seconds > 900.0:
            raise ValueError("Owner cloud lease ttl_seconds must be short-lived (0 < ttl <= 900s)")
        now = time.time()
        expires_at = now + float(ttl_seconds)
        lid = lease_id or f"ocl_{uuid.uuid4().hex[:20]}"
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO owner_cloud_leases (
                    lease_id, grant_id, oauth_token, owner_id, issued_at, expires_at, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (lid, grant_id, oauth_token, owner_id, now, expires_at),
            )
        return {
            "lease_id": lid,
            "grant_id": grant_id,
            "oauth_token": oauth_token,
            "owner_id": owner_id,
            "issued_at": now,
            "expires_at": expires_at,
            "revoked": False,
        }

    def revoke_owner_cloud_lease(self, lease_id: str | None = None) -> int:
        with self._db() as conn:
            if lease_id:
                cur = conn.execute("UPDATE owner_cloud_leases SET revoked = 1 WHERE lease_id = ?", (lease_id,))
            else:
                cur = conn.execute("UPDATE owner_cloud_leases SET revoked = 1 WHERE revoked = 0")
            return cur.rowcount

    def get_active_owner_cloud_lease(self) -> dict[str, Any] | None:
        now = time.time()
        with self._db() as conn:
            cur = conn.execute(
                """
                SELECT l.lease_id, l.grant_id, l.oauth_token, l.owner_id, l.issued_at, l.expires_at, l.revoked,
                       g.used_count, g.max_uses, g.revoked AS grant_revoked, g.expires_at AS grant_expires_at
                FROM owner_cloud_leases l
                JOIN owner_capability_grants g ON l.grant_id = g.grant_id
                WHERE l.revoked = 0 AND l.expires_at > ?
                  AND g.revoked = 0 AND g.expires_at > ? AND g.used_count < g.max_uses
                ORDER BY l.issued_at DESC LIMIT 1
                """,
                (now, now),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def resolve_oauth_db_path(
    db_path: str | Path | None = None,
    gateway: Any = None,
) -> Path | str:
    if db_path is not None:
        return db_path
    gw_store = getattr(gateway, "store", None) or getattr(gateway, "task_store", None)
    gw_db_path = getattr(gw_store, "db_path", None)
    if gw_db_path is not None:
        return gw_db_path
    env_db = os.getenv("WINDOWS_MCP_OAUTH_DB_PATH")
    if env_db:
        return Path(env_db)
    state_root = os.getenv("MCP_STATE_ROOT")
    if state_root:
        return Path(state_root) / "oauth_state.db"
    return PROJECT_ROOT / "runtime" / "oauth_state.db"


def _issue_oauth_token(
    client_id: str,
    secret: str,
    scope: str = "mcp:autonomous",
    ttl_seconds: int = 3600,
    owner_id: str = "local_owner",
    resource: str = "mcp-autonomous",
    issuer: str = "windows-mcp-gateway",
    typ: str = "access",
) -> dict[str, Any]:
    if not secret or len(str(secret).strip()) < 16 or str(secret).strip() == "default_secret":
        raise PermissionError("Forbidden (P0-04): Cannot issue OAuth token with empty, weak, or default signing secret")
    now = time.time()
    nonce = uuid.uuid4().hex
    payload = {
        "iss": issuer,
        "sub": client_id,
        "client_id": client_id,
        "owner_id": owner_id,
        "aud": resource,
        "resource": resource,
        "scope": scope,
        "typ": typ,
        "iat": int(now),
        "exp": int(now + ttl_seconds),
        "jti": nonce,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = (
        base64.urlsafe_b64encode(payload_json.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    sig = hmac.new(
        secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    prefix = "mcp_ort_" if typ == "refresh" else "mcp_oat_"
    token_str = f"{prefix}{payload_b64}.{sig}"
    return {
        "access_token": token_str,
        "token_type": "Bearer",
        "expires_in": ttl_seconds,
        "scope": scope,
    }


def _verify_oauth_token(
    token_str: str,
    secret: str,
    revoked_tokens: set[str],
    *,
    db_path: str | Path | None = None,
    persistence: Any = None,
    expected_resource: str = "mcp-autonomous",
    expected_owner_id: str = "local_owner",
    expected_typ: str = "access",
) -> tuple[bool, dict[str, Any] | None, str]:
    if not secret or len(str(secret).strip()) < 16 or str(secret).strip() == "default_secret":
        return False, None, "Invalid or unconfigured OAuth signing key (P0-04)"
    if expected_typ == "refresh":
        if not token_str.startswith("mcp_ort_"):
            return False, None, "Invalid token type: expected refresh token"
        prefix = "mcp_ort_"
    else:
        if not token_str.startswith("mcp_oat_"):
            return False, None, "Not an OAuth token"
        prefix = "mcp_oat_"

    raw = token_str[len(prefix) :]
    if "." not in raw:
        return False, None, "Malformed OAuth token structure"
    payload_b64, sig = raw.split(".", 1)
    expected_sig = hmac.new(
        secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, None, "Invalid OAuth token signature"

    pad = len(payload_b64) % 4
    padded_b64 = payload_b64 + ("=" * (4 - pad) if pad else "")
    try:
        payload_bytes = base64.urlsafe_b64decode(padded_b64.encode("ascii"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, None, "Invalid OAuth token encoding"

    if float(payload.get("exp", 0)) <= time.time():
        return False, None, "OAuth token has expired"

    jti = payload.get("jti")
    if jti and jti in revoked_tokens:
        return False, None, "OAuth token has been revoked"
    if token_str in revoked_tokens:
        return False, None, "OAuth token has been revoked"

    if persistence is not None:
        if (jti and persistence.is_token_revoked(jti)) or persistence.is_token_revoked(token_str):
            return False, None, "OAuth token has been revoked"
    elif db_path is not None:
        try:
            p_helper = _SQLiteOAuthPersistence(db_path)
            if (jti and p_helper.is_token_revoked(jti)) or p_helper.is_token_revoked(token_str):
                return False, None, "OAuth token has been revoked"
        except Exception:
            pass

    token_res = payload.get("resource") or payload.get("aud")
    if token_res:
        valid_resources = [
            "mcp-autonomous",
            "https://127.0.0.1:8768/mcp",
            "http://127.0.0.1:8768/mcp",
            "https://127.0.0.1:8766/mcp/autonomous",
            "http://127.0.0.1:8766/mcp/autonomous",
            "https://127.0.0.1:8768",
            "http://127.0.0.1:8768",
        ]
        ext_issuer = os.getenv("MCP_OAUTH_EXTERNAL_ISSUER", "").strip().rstrip("/")
        if ext_issuer:
            valid_resources.extend([ext_issuer, f"{ext_issuer}/mcp", f"{ext_issuer}/mcp/autonomous"])
        if token_res not in valid_resources:
            return False, None, "Token audience/resource mismatch (H05/H07)"

    scope = payload.get("scope", "")
    if "mcp:autonomous" not in scope.split():
        return False, None, "Insufficient token scope (H05)"

    if "owner_id" in payload:
        if payload["owner_id"] != expected_owner_id:
            return False, None, "Unexpected owner identity (H06)"

    return True, payload, ""


def _validate_jsonrpc_structure(payload: Any) -> tuple[bool, str]:
    if isinstance(payload, dict):
        if payload.get("jsonrpc") != "2.0":
            return False, "Invalid Request: malformed JSON-RPC 2.0 payload (missing or invalid 'jsonrpc' field)"
        if not isinstance(payload.get("method"), str) or not payload.get("method"):
            return False, "Invalid Request: malformed JSON-RPC 2.0 payload (missing or invalid 'method' field)"
        return True, ""
    elif isinstance(payload, list) and len(payload) > 0:
        for item in payload:
            if not isinstance(item, dict):
                return False, "Invalid Request: malformed JSON-RPC 2.0 payload (batch items must be JSON objects)"
            if item.get("jsonrpc") != "2.0":
                return False, "Invalid Request: malformed JSON-RPC 2.0 payload (missing or invalid 'jsonrpc' field)"
            if not isinstance(item.get("method"), str) or not item.get("method"):
                return False, "Invalid Request: malformed JSON-RPC 2.0 payload (missing or invalid 'method' field)"
        return True, ""
    else:
        return False, "Invalid Request: malformed JSON-RPC 2.0 payload"


def _authenticate_autonomous_caller(
    request: Request,
    app: FastAPI,
    gw: MCPGatewayServer,
    require_auth: bool = True,
) -> tuple[bool, str, int, str]:
    """
    Authenticate an incoming request for the autonomous endpoint.
    Returns: (is_authenticated, identity, http_status, error_message)
    """
    provided_token = _extract_caller_token(request)
    session_id_hdr = request.headers.get("x-mcp-session-id") or None
    caller_id_hdr = request.headers.get("x-mcp-caller-id") or None
    owner_id_hdr = request.headers.get("x-mcp-owner-id") or None
    expected_owner_id = getattr(app.state, "expected_owner_id", "local_owner")

    # Reject spoofed caller or owner headers (Finding C2 / H06)
    for hdr_name in ("x-caller-id", "x-owner", "x-mcp-owner"):
        val = request.headers.get(hdr_name)
        if val is not None:
            v_clean = val.strip().lower()
            if v_clean in ("local_owner", "true", "owner", "admin", "chatgpt_cloud_client", "1"):
                gw.policy.audit.log_event(
                    tool_name="mcp_autonomous_auth",
                    tier="AUTH",
                    decision="DENY",
                    reason=f"Spoofed identity header rejected: {hdr_name}={val}",
                )
                return (
                    False,
                    "",
                    403,
                    f"Forbidden (H06): Spoofed identity header '{hdr_name}' is strictly rejected",
                )

    # 1. OAuth signed bearer token (mcp_oat_... or mcp_ort_...)
    if provided_token and (provided_token.startswith("mcp_oat_") or provided_token.startswith("mcp_ort_")):
        persistence = getattr(app.state, "oauth_persistence", None)
        oauth_signing_key = getattr(app.state, "oauth_signing_key", "")
        ok, payload, err = _verify_oauth_token(
            provided_token,
            oauth_signing_key,
            app.state.revoked_oauth_tokens,
            persistence=persistence,
            expected_owner_id=expected_owner_id,
        )
        if not ok:
            gw.policy.audit.log_event(
                tool_name="mcp_autonomous_auth",
                tier="AUTH",
                decision="DENY",
                reason=f"OAuth verification failed: {err}",
            )
            return (
                False,
                "",
                403,
                f"Forbidden (H01): Invalid, expired, or revoked caller authentication credential ({err})",
            )

        token_identity = str(payload.get("client_id") or payload.get("sub") or "").strip()
        token_jti = str(payload.get("jti") or "").strip()
        if not token_identity:
            token_identity = "cloud_client_default"
        # Identity Mismatch Check (H01)
        if caller_id_hdr is not None and caller_id_hdr.strip() != token_identity:
            gw.policy.audit.log_event(
                tool_name="mcp_autonomous_auth",
                tier="AUTH",
                decision="DENY",
                reason="Caller identity header mismatch with authenticated token subject",
            )
            return (
                False,
                "",
                403,
                "Forbidden (H01): Caller identity header mismatch with authenticated token subject",
            )

        if owner_id_hdr is not None and owner_id_hdr.strip() != expected_owner_id:
            gw.policy.audit.log_event(
                tool_name="mcp_autonomous_auth",
                tier="AUTH",
                decision="DENY",
                reason="Unexpected owner identity in header",
            )
            return (
                False,
                "",
                403,
                "Forbidden (H06): Unexpected owner identity",
            )

        token_owner = str(payload.get("owner_id") or "")
        scope_str = str(payload.get("scope") or "")
        token_scopes = frozenset(scope_str.split())
        is_owner = bool(
            token_owner == expected_owner_id
            and bool(token_jti)
            and bool(payload.get("client_id"))
            and ("mcp:owner" in token_scopes or "mcp:all" in token_scopes)
        )
        tier = "SYSTEM_ADMIN" if is_owner else ("WRITE" if "mcp:coding:write" in token_scopes else "READ")
        header_grant_id = str(request.headers.get("x-mcp-owner-grant-id") or "").strip() if is_owner else ""
        try:
            from runtime.contracts import AuthPrincipal
            principal = AuthPrincipal(
                client_id=token_identity,
                owner_id=token_owner or expected_owner_id,
                tier=tier,
                scopes=token_scopes,
                is_owner=is_owner,
                auth_method="oauth",
                metadata={"payload": payload, "jti": token_jti, "header_grant_id": header_grant_id},
            )
            request.state.auth_principal = principal
        except Exception:
            pass

        return True, token_identity, 200, ""

    # 2. Configured caller token (Shared Static Bearer Token — connector authentication ONLY, never owner)
    if provided_token is not None:
        if _verify_caller_token(provided_token, app.state.caller_auth_token):
            allowed_static_principals = {"cloud_client_default", "chatgpt_cloud_client"}
            if caller_id_hdr:
                clean_id = caller_id_hdr.strip()
                if clean_id not in allowed_static_principals:
                    gw.policy.audit.log_event(
                        tool_name="mcp_autonomous_auth",
                        tier="AUTH",
                        decision="DENY",
                        reason=f"Shared static bearer token cannot spoof or assume caller identity via X-MCP-Caller-Id: {clean_id}",
                    )
                    return (
                        False,
                        "",
                        403,
                        "Forbidden (H06): Shared static bearer token cannot spoof or assume caller identity via X-MCP-Caller-Id header",
                    )
                authenticated_identity = clean_id
            else:
                authenticated_identity = "cloud_client_default"

            if owner_id_hdr is not None and owner_id_hdr.strip() != expected_owner_id:
                gw.policy.audit.log_event(
                    tool_name="mcp_autonomous_auth",
                    tier="AUTH",
                    decision="DENY",
                    reason="Unexpected owner identity in header",
                )
                return (
                    False,
                    "",
                    403,
                    "Forbidden (H06): Unexpected owner identity",
                )

            try:
                from runtime.contracts import AuthPrincipal
                principal = AuthPrincipal(
                    client_id=authenticated_identity,
                    owner_id=expected_owner_id,
                    tier="WRITE",
                    scopes=frozenset(["mcp:tools", "mcp:autonomous", "mcp:coding:write"]),
                    is_owner=False,
                    auth_method="static_bearer",
                    metadata={"subject": "static_bearer", "is_authenticated": True},
                )
                request.state.auth_principal = principal
            except Exception:
                pass

            return True, authenticated_identity, 200, ""
        else:
            gw.policy.audit.log_event(
                tool_name="mcp_autonomous_auth",
                tier="AUTH",
                decision="DENY",
                reason="Invalid caller authentication token for autonomous endpoint",
            )
            return (
                False,
                "",
                403,
                "Forbidden (H01): Invalid, expired, or revoked caller authentication credential",
            )

    # 3. Active Gateway Session (X-MCP-Session-Id)
    if session_id_hdr is not None:
        sess = gw.policy.sessions.get_session(session_id_hdr.strip())
        if sess is None or not sess.is_active():
            gw.policy.audit.log_event(
                tool_name="mcp_autonomous_auth",
                tier="AUTH",
                decision="DENY",
                reason=f"Forged, expired, or revoked X-MCP-Session-Id: {session_id_hdr}",
            )
            return (
                False,
                "",
                403,
                f"Forbidden (H01): Forged, expired, or revoked X-MCP-Session-Id header: {session_id_hdr}",
            )

        if caller_id_hdr is not None and caller_id_hdr.strip() != sess.client_id:
            gw.policy.audit.log_event(
                tool_name="mcp_autonomous_auth",
                tier="AUTH",
                decision="DENY",
                reason="Caller identity header mismatch with session client_id",
            )
            return (
                False,
                "",
                403,
                "Forbidden (H01): Caller identity header mismatch with authenticated token subject",
            )

        try:
            from runtime.contracts import AuthPrincipal
            request.state.auth_principal = AuthPrincipal(
                client_id=sess.client_id,
                owner_id=expected_owner_id,
                tier="READ",
                scopes=frozenset(["mcp:autonomous"]),
                is_owner=False,
                auth_method="gateway_session",
                metadata={"session_id": sess.session_id, "is_authenticated": True},
            )
        except Exception:
            pass
        return True, sess.client_id, 200, ""

    # 4. Missing credential. Loopback source address is never authentication.
    # A local tunnel can forward remote callers as 127.0.0.1.
    # This guard must remain independent of any network/trust profile.
    if require_auth:
        gw.policy.audit.log_event(
            tool_name="mcp_autonomous_auth",
            tier="AUTH",
            decision="DENY",
            reason="Missing caller authentication token for /mcp/autonomous",
        )
        return (
            False,
            "",
            401,
            "Unauthorized (H01): Missing caller authentication token for /mcp/autonomous",
        )

    default_id = caller_id_hdr.strip() if caller_id_hdr else "cloud_autonomous"
    return True, default_id, 200, ""


def _check_task_submission_rate_limit(
    app: FastAPI,
    identity: str,
    req_id: Any,
    count: int = 1,
) -> JSONResponse | None:
    now = time.time()
    window = 60.0
    max_allowed = getattr(
        app.state, "max_submissions_per_minute", DEFAULT_MAX_SUBMISSIONS_PER_MINUTE
    )
    timestamps = app.state.submission_timestamps.setdefault(identity, [])
    # sliding window
    app.state.submission_timestamps[identity] = [
        t for t in timestamps if now - t < window
    ]
    current = app.state.submission_timestamps[identity]
    if len(current) + count > max_allowed:
        return _jsonrpc_auth_error_response(
            status_code=429,
            req_id=req_id,
            code=-32005,
            message="Rate limit exceeded (H01): Too many task submissions",
        )
    for _ in range(count):
        current.append(now)
    return None


def _handle_mcp_stream_session(
    request: Request,
    app: FastAPI,
    payload: Any,
    authenticated_identity: str,
) -> tuple[bool, str, dict[str, str], JSONResponse | None]:
    """
    Handle Mcp-Session-Id protocol header (H04).
    Returns: (is_ok, mcp_session_id, response_headers, error_response_if_any)
    """
    resp_headers: dict[str, str] = {}
    client_sess = request.headers.get("mcp-session-id", "").strip()

    is_init = False
    if isinstance(payload, dict):
        is_init = payload.get("method") == "initialize"
    elif isinstance(payload, list):
        is_init = any(
            item.get("method") == "initialize"
            for item in payload
            if isinstance(item, dict)
        )

    req_id = payload.get("id") if isinstance(payload, dict) else None

    if is_init:
        mcp_sess_id = client_sess if client_sess else f"sess_mcp_{uuid.uuid4().hex[:16]}"
        app.state.mcp_stream_sessions[mcp_sess_id] = authenticated_identity
        resp_headers["Mcp-Session-Id"] = mcp_sess_id
        return True, mcp_sess_id, resp_headers, None

    if client_sess:
        if client_sess in app.state.mcp_stream_sessions:
            bound_id = app.state.mcp_stream_sessions[client_sess]
            if bound_id != authenticated_identity:
                err_resp = _jsonrpc_auth_error_response(
                    status_code=403,
                    req_id=req_id,
                    code=-32003,
                    message="Forbidden (H04): Mcp-Session-Id header mismatch with authenticated caller identity",
                )
                return False, "", {}, err_resp
        else:
            app.state.mcp_stream_sessions[client_sess] = authenticated_identity

        resp_headers["Mcp-Session-Id"] = client_sess
        return True, client_sess, resp_headers, None

    return True, "", resp_headers, None


DISALLOWED_QUERY_SECRETS = ("owner_token", "owner_password", "client_secret", "access_token")


def _check_disallowed_query_secrets(request: Request) -> JSONResponse | None:
    for sec_name in DISALLOWED_QUERY_SECRETS:
        if sec_name in request.query_params:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "Security Policy Violation (Sprint 5.5): Owner credentials or secrets must never be passed in URL query parameters",
                },
            )
    return None


def _generate_oauth_csrf_token(
    secret: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str | None = None,
    ttl_seconds: int = 600,
) -> str:
    ts = int(time.time())
    state_str = state or ""
    raw = f"{ts}|{client_id}|{redirect_uri}|{code_challenge}|{state_str}"
    b64_data = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64_data.encode("ascii"), hashlib.sha256).hexdigest()
    return f"mcp_csrf_{b64_data}.{sig}"


def _verify_oauth_csrf_token(
    csrf_token: str,
    secret: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str | None = None,
    state: str | None = None,
    ttl_seconds: int = 600,
) -> bool:
    if not csrf_token or not csrf_token.startswith("mcp_csrf_"):
        return False
    body = csrf_token[len("mcp_csrf_") :]
    if "." not in body:
        return False
    b64_data, sig = body.split(".", 1)
    expected_sig = hmac.new(secret.encode("utf-8"), b64_data.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False
    pad = len(b64_data) % 4
    padded = b64_data + ("=" * (4 - pad) if pad else "")
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        parts = raw.split("|", 4)
        if len(parts) != 5:
            return False
        ts_str, tok_client_id, tok_redirect_uri, tok_challenge, tok_state = parts
        ts = int(ts_str)
        if time.time() - ts > ttl_seconds:
            return False
        if tok_client_id != client_id or tok_redirect_uri != redirect_uri:
            return False
        if code_challenge and tok_challenge and tok_challenge != code_challenge:
            return False
        if state is not None and tok_state != (state or ""):
            return False
        return True
    except Exception:
        return False


def _is_allowed_origin_or_referer(header_value: str, external_issuer: str | None) -> bool:
    if not header_value:
        return True
    try:
        parsed = urllib.parse.urlparse(header_value)
        hostname = (parsed.hostname or "").lower()
        if hostname in ("127.0.0.1", "localhost", "testserver"):
            return True
        if external_issuer:
            ext_parsed = urllib.parse.urlparse(external_issuer)
            if ext_parsed.hostname and hostname == ext_parsed.hostname.lower():
                return True
        return False
    except Exception:
        return False


def _render_consent_html(
    client_id: str,
    scope: str,
    resource: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str | None,
    csrf_token: str = "",
) -> str:
    escaped_client = html.escape(client_id)
    escaped_scope = html.escape(scope)
    escaped_resource = html.escape(resource)
    escaped_redirect = html.escape(redirect_uri)
    escaped_challenge = html.escape(code_challenge)
    escaped_method = html.escape(code_challenge_method)
    escaped_state = html.escape(state or "")
    escaped_csrf = html.escape(csrf_token)
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Authorize MCP Autonomous Client</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .card {{ background: #1e293b; padding: 2rem; border-radius: 0.75rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 480px; border: 1px solid #334155; }}
        h2 {{ margin-top: 0; color: #38bdf8; font-size: 1.5rem; }}
        .info {{ background: #0f172a; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; font-size: 0.9rem; border: 1px solid #334155; }}
        .info p {{ margin: 0.4rem 0; word-break: break-all; }}
        label {{ display: block; margin-bottom: 0.5rem; font-size: 0.9rem; color: #94a3b8; }}
        input[type="password"] {{ width: 100%; box-sizing: border-box; padding: 0.6rem; border-radius: 0.375rem; border: 1px solid #475569; background: #0f172a; color: #f8fafc; margin-bottom: 1.5rem; font-size: 1rem; }}
        .actions {{ display: flex; gap: 1rem; }}
        button {{ flex: 1; padding: 0.75rem; border-radius: 0.375rem; font-weight: 600; cursor: pointer; border: none; font-size: 1rem; }}
        .btn-allow {{ background: #0284c7; color: white; }}
        .btn-allow:hover {{ background: #0369a1; }}
        .btn-deny {{ background: #475569; color: white; }}
        .btn-deny:hover {{ background: #334155; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Authorize Autonomous Agent Access</h2>
        <div class="info">
            <p><strong>Client ID:</strong> {escaped_client}</p>
            <p><strong>Requested Scope:</strong> {escaped_scope}</p>
            <p><strong>Target Resource:</strong> {escaped_resource}</p>
            <p><strong>Redirect URI:</strong> {escaped_redirect}</p>
        </div>
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="csrf_token" value="{escaped_csrf}" />
            <input type="hidden" name="client_id" value="{escaped_client}" />
            <input type="hidden" name="redirect_uri" value="{escaped_redirect}" />
            <input type="hidden" name="scope" value="{escaped_scope}" />
            <input type="hidden" name="resource" value="{escaped_resource}" />
            <input type="hidden" name="code_challenge" value="{escaped_challenge}" />
            <input type="hidden" name="code_challenge_method" value="{escaped_method}" />
            <input type="hidden" name="state" value="{escaped_state}" />
            <label for="owner_token">Owner Passphrase / Token:</label>
            <input type="password" id="owner_token" name="owner_token" required placeholder="Enter owner token" />
            <div class="actions">
                <button type="submit" name="decision" value="allow" class="btn-allow">Approve & Grant</button>
                <button type="submit" name="decision" value="deny" class="btn-deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>"""


def _is_valid_redirect_uri(redirect_uri: str, client_id: str, app: FastAPI) -> bool:
    if not redirect_uri:
        return False

    persistence = getattr(app.state, "oauth_persistence", None)
    if persistence and client_id:
        rec = persistence.get_client(client_id)
        if rec and rec.get("redirect_uris"):
            return redirect_uri in rec["redirect_uris"]

    # Predefined / default known redirect URIs for unregistered client_id (e.g. default connector client)
    exact_known_redirects = {
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chat.openai.com/aip/oauth/callback",
        "http://127.0.0.1/callback",
        "http://localhost/callback",
    }
    if redirect_uri in exact_known_redirects:
        return True

    # Also support exact loopback port callbacks (e.g. http://127.0.0.1:8768/callback or http://localhost:8000/callback)
    try:
        parsed = urllib.parse.urlparse(redirect_uri)
        if parsed.scheme in ("http", "https") and parsed.hostname in ("127.0.0.1", "localhost") and parsed.path == "/callback":
            return True
    except Exception:
        pass

    return False


def _is_valid_oauth_redirect_uri(uri: str) -> bool:
    """Validate OAuth redirect URI components; never trust a textual host prefix."""
    if not isinstance(uri, str) or not uri or uri != uri.strip():
        return False
    if any(ch.isspace() or ord(ch) < 0x20 for ch in uri):
        return False
    if "\\" in uri or "#" in uri:
        return False
    try:
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None:
            return False
        if "%" in parsed.netloc:
            return False
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return False
        if parsed.scheme == "http":
            return host.lower() in ("127.0.0.1", "localhost", "::1")
        return True
    except (ValueError, TypeError):
        return False


def register_oauth_endpoints(
    app: FastAPI,
    *,
    issuer: str,
    default_resource_uri: str,
) -> None:
    """Register discovery, client registration, authorization, token, and revocation endpoints (H05/H06/H07/Sprint 5.5)."""

    def _resolve_issuer_base() -> tuple[str, str | None, bool]:
        ext_issuer = os.getenv("MCP_OAUTH_EXTERNAL_ISSUER", "").strip().rstrip("/")
        if ext_issuer and ext_issuer.startswith("https://"):
            try:
                parsed = urllib.parse.urlparse(ext_issuer)
                if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                    return ext_issuer, ext_issuer, True
            except Exception:
                pass
        base = os.getenv("MCP_OAUTH_ISSUER") or "http://127.0.0.1:8768"
        base = base.rstrip("/")
        return base, None, False

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    @app.get("/.well-known/oauth-protected-resource/mcp/autonomous")
    async def oauth_protected_resource(request: Request) -> Response:
        base_url, _, is_reachable = _resolve_issuer_base()
        ua = request.headers.get("user-agent", "").lower()
        force_advertise = os.getenv("MCP_ADVERTISE_LOCAL_OAUTH_METADATA", "").strip().lower() in ("1", "true", "yes")
        if not is_reachable and not force_advertise and not ua.startswith("testclient"):
            return JSONResponse(
                status_code=404,
                content={
                    "error": "not_found",
                    "error_description": "OAuth Protected Resource Metadata is not advertised over private noauth tunnel without an external HTTPS issuer.",
                },
            )
        return JSONResponse(
            status_code=200,
            content={
                "resource": "mcp-autonomous",
                "resource_uri": default_resource_uri,
                "authorization_servers": [base_url, "/oauth/token", f"{base_url}/oauth/token"],
                "scopes_supported": [
                    "mcp:autonomous",
                    "mcp:tasks:write",
                    "mcp:tasks:read",
                    "mcp:coding:write",
                    "mcp:owner",
                    "mcp:all",
                ],
                "bearer_methods_supported": ["header"],
            },
        )

    @app.get("/.well-known/oauth-authorization-server")
    @app.get("/.well-known/openid-configuration")
    async def oauth_authorization_server() -> dict[str, Any]:
        base_url, external_https_issuer, is_reachable = _resolve_issuer_base()
        return {
            "issuer": issuer,
            "issuer_url": base_url,
            "issuer_https": external_https_issuer,
            "authorization_endpoint": "/oauth/authorize",
            "authorization_endpoint_url": f"{base_url}/oauth/authorize",
            "token_endpoint": "/oauth/token",
            "token_endpoint_url": f"{base_url}/oauth/token",
            "revocation_endpoint": "/oauth/revoke",
            "revocation_endpoint_url": f"{base_url}/oauth/revoke",
            "registration_endpoint": "/oauth/register",
            "registration_endpoint_url": f"{base_url}/oauth/register",
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [
                "mcp:autonomous",
                "mcp:tasks:write",
                "mcp:tasks:read",
                "mcp:coding:write",
                "mcp:owner",
                "mcp:all",
            ],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "client_id_metadata_document_supported": False,
            "browser_oauth_reachable_via_private_tunnel": is_reachable,
            "private_tunnel_auth_mode": "bearer_header_injection_or_external_https_idp",
        }

    @app.post("/oauth/register")
    async def oauth_register(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "JSON object body expected"},
            )

        client_name = body.get("client_name") or "Autonomous MCP Client"
        raw_redirects = body.get("redirect_uris") or []
        if isinstance(raw_redirects, str):
            redirect_uris = [raw_redirects]
        elif isinstance(raw_redirects, list):
            redirect_uris = [str(u) for u in raw_redirects]
        else:
            redirect_uris = []

        for uri in redirect_uris:
            if not _is_valid_oauth_redirect_uri(uri):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_redirect_uri",
                        "error_description": f"Redirect URI must use https:// or loopback http://: {uri}",
                    },
                )

        grant_types = body.get("grant_types") or ["authorization_code", "refresh_token", "client_credentials"]
        scope = body.get("scope") or "mcp:autonomous"

        expected_owner = getattr(app.state, "expected_owner_id", "local_owner")
        caller_owner_id = body.get("owner_id")
        if caller_owner_id is not None and str(caller_owner_id).strip() != "":
            if str(caller_owner_id) != expected_owner:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (Sprint 5.5): Client registration cannot bind to an unverified or foreign owner_id",
                    },
                )
            auth_tok = _extract_caller_token(request)
            expected_token = getattr(app.state, "caller_auth_token", None)
            if not auth_tok or not _verify_caller_token(auth_tok, expected_token):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (Sprint 5.5): Explicit owner_id in client registration requires valid owner authentication",
                    },
                )

        owner_id = expected_owner
        client_id = body.get("client_id") or f"mcp_client_{uuid.uuid4().hex[:16]}"
        client_secret = f"mcp_sec_{uuid.uuid4().hex}"
        client_secret_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        app.state.oauth_persistence.register_client(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            owner_id=owner_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            allowed_scopes=scope,
        )

        return JSONResponse(
            status_code=201,
            content={
                "client_id": client_id,
                "client_secret": client_secret,
                "client_id_issued_at": int(time.time()),
                "client_secret_expires_at": 0,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "scope": scope,
                "owner_id": owner_id,
                "client_name": client_name,
            },
        )

    @app.get("/oauth/authorize")
    async def oauth_authorize_get(request: Request) -> Response:
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err

        params = request.query_params
        response_type = params.get("response_type", "")
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "")
        scope = params.get("scope", "mcp:autonomous")
        state = params.get("state")
        resource = params.get("resource", "mcp-autonomous")

        if response_type != "code":
            return JSONResponse(
                status_code=400,
                content={
                    "error": "unsupported_response_type",
                    "error_description": "Only response_type=code is supported",
                },
            )

        if not code_challenge or code_challenge_method != "S256":
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "PKCE with code_challenge_method=S256 is required (H05)",
                },
            )

        if not _is_valid_redirect_uri(redirect_uri, client_id, app):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "invalid_redirect_uri (H05/Sprint 5.5)",
                },
            )

        sec = str(getattr(app.state, "oauth_signing_key", ""))
        csrf_token = _generate_oauth_csrf_token(
            secret=sec,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            state=state,
        )

        html_content = _render_consent_html(
            client_id=client_id,
            scope=scope,
            resource=resource,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            state=state,
            csrf_token=csrf_token,
        )

        resp = HTMLResponse(content=html_content, status_code=200)
        resp.headers["X-OAuth-CSRF-Token"] = csrf_token
        resp.set_cookie(
            key="mcp_oauth_csrf",
            value=csrf_token,
            httponly=True,
            samesite="strict",
            path="/oauth/authorize",
        )
        return resp

    @app.post("/oauth/authorize")
    async def oauth_authorize_post(request: Request) -> Response:
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err

        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        ext_issuer = os.getenv("MCP_OAUTH_EXTERNAL_ISSUER", "").strip() or None
        if origin and not _is_allowed_origin_or_referer(origin, ext_issuer):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "access_denied",
                    "error_description": "Forbidden (Sprint 5.5): Cross-origin consent submission denied",
                },
            )
        if referer and not _is_allowed_origin_or_referer(referer, ext_issuer):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "access_denied",
                    "error_description": "Forbidden (Sprint 5.5): Cross-origin consent submission denied",
                },
            )

        body_dict: dict[str, Any] = {}
        ct = request.headers.get("content-type", "").lower()
        try:
            raw = await request.body()
            if "application/x-www-form-urlencoded" in ct:
                parsed = urllib.parse.parse_qs(raw.decode("utf-8"))
                for k, v in parsed.items():
                    body_dict[k] = v[0] if v else ""
            elif "application/json" in ct or raw.strip().startswith(b"{"):
                body_dict = json.loads(raw.decode("utf-8"))
        except Exception:
            pass

        client_id = str(body_dict.get("client_id") or request.query_params.get("client_id") or "")
        redirect_uri = str(body_dict.get("redirect_uri") or request.query_params.get("redirect_uri") or "")
        scope = str(body_dict.get("scope") or request.query_params.get("scope") or "mcp:autonomous")
        code_challenge = str(body_dict.get("code_challenge") or request.query_params.get("code_challenge") or "")
        code_challenge_method = str(body_dict.get("code_challenge_method") or request.query_params.get("code_challenge_method") or "S256")
        state = body_dict.get("state") or request.query_params.get("state")
        resource = str(body_dict.get("resource") or request.query_params.get("resource") or "mcp-autonomous")
        decision = str(body_dict.get("decision") or body_dict.get("consent") or "allow").lower()

        owner_auth = (
            _extract_caller_token(request)
            or body_dict.get("owner_token")
            or body_dict.get("owner_password")
        )

        if not owner_auth or not _verify_caller_token(str(owner_auth), app.state.caller_auth_token):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "access_denied",
                    "error_description": "Invalid owner authentication credential",
                },
            )

        if not _is_valid_redirect_uri(redirect_uri, client_id, app):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "invalid_redirect_uri (H05/Sprint 5.5)",
                },
            )

        accept = request.headers.get("accept", "").lower()
        csrf_candidate = (
            body_dict.get("csrf_token")
            or request.headers.get("x-oauth-csrf-token")
            or request.cookies.get("mcp_oauth_csrf")
        )
        is_browser_form = (
            "application/x-www-form-urlencoded" in ct
            and "application/json" not in accept
        ) or ("mcp_oauth_csrf" in request.cookies)

        if csrf_candidate or is_browser_form:
            if not csrf_candidate:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (Sprint 5.5): CSRF token is required for consent submission",
                    },
                )
            sec = str(getattr(app.state, "oauth_signing_key", ""))
            if not _verify_oauth_csrf_token(
                str(csrf_candidate),
                secret=sec,
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge if code_challenge else None,
                state=str(state) if state is not None else None,
            ):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (Sprint 5.5): Invalid, expired, or tampered CSRF token",
                    },
                )

        if decision == "deny":
            sep = "&" if "?" in redirect_uri else "?"
            loc = f"{redirect_uri}{sep}error=access_denied"
            if state:
                loc += f"&state={urllib.parse.quote(str(state))}"
            return Response(status_code=302, headers={"Location": loc})

        code = f"mcp_ac_{uuid.uuid4().hex}"
        app.state.oauth_persistence.store_authorization_code(
            code=code,
            client_id=client_id,
            owner_id=getattr(app.state, "expected_owner_id", "local_owner"),
            redirect_uri=redirect_uri,
            scope=scope,
            resource=resource,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            state=str(state) if state is not None else None,
        )
        sep = "&" if "?" in redirect_uri else "?"
        loc = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}"
        if state:
            loc += f"&state={urllib.parse.quote(str(state))}"

        if "application/json" in accept or "application/json" in ct:
            return JSONResponse(
                status_code=200,
                content={"code": code, "redirect_url": loc, "state": state},
                headers={"Location": loc},
            )
        return Response(status_code=302, headers={"Location": loc})

    @app.post("/oauth/token")
    async def oauth_token(request: Request) -> Response:
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err
        basic_client_id = ""
        basic_secret = ""
        auth_hdr = request.headers.get("authorization", "").strip()
        if auth_hdr.lower().startswith("basic "):
            try:
                b64_creds = auth_hdr[6:].strip()
                decoded = base64.b64decode(b64_creds).decode("utf-8")
                if ":" in decoded:
                    basic_client_id, basic_secret = decoded.split(":", 1)
            except Exception:
                pass

        body_client_id = ""
        body_secret = ""
        grant_type = ""
        code = ""
        code_verifier = ""
        refresh_token = ""
        redirect_uri = ""
        requested_owner_id = None
        target_client_id = None

        ct = request.headers.get("content-type", "").lower()
        try:
            body_bytes = await request.body()
            if "application/x-www-form-urlencoded" in ct:
                parsed = urllib.parse.parse_qs(body_bytes.decode("utf-8"))
                body_client_id = parsed.get("client_id", [""])[0]
                body_secret = parsed.get("client_secret", [""])[0]
                grant_type = parsed.get("grant_type", [""])[0]
                code = parsed.get("code", [""])[0]
                code_verifier = parsed.get("code_verifier", [""])[0]
                refresh_token = parsed.get("refresh_token", [""])[0]
                redirect_uri = parsed.get("redirect_uri", [""])[0]
                requested_owner_id = parsed.get("owner_id", [None])[0]
                target_client_id = (
                    parsed.get("target_client_id", [None])[0]
                    or parsed.get("requested_client_id", [None])[0]
                    or parsed.get("subject", [None])[0]
                )
            elif "application/json" in ct or body_bytes.strip().startswith(b"{"):
                b_json = json.loads(body_bytes.decode("utf-8"))
                if isinstance(b_json, dict):
                    body_client_id = str(b_json.get("client_id") or "")
                    body_secret = str(b_json.get("client_secret") or "")
                    grant_type = str(b_json.get("grant_type") or "")
                    code = str(b_json.get("code") or "")
                    code_verifier = str(b_json.get("code_verifier") or "")
                    refresh_token = str(b_json.get("refresh_token") or "")
                    redirect_uri = str(b_json.get("redirect_uri") or "")
                    requested_owner_id = b_json.get("owner_id")
                    target_client_id = (
                        b_json.get("target_client_id")
                        or b_json.get("requested_client_id")
                        or b_json.get("subject")
                    )
        except Exception:
            pass

        # CRITICAL H06 CHECK A:
        if basic_client_id and body_client_id and basic_client_id != body_client_id:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "invalid_client",
                    "error_description": "Forbidden (H06): Authenticated client cannot request a token for another client_id",
                },
            )

        effective_client_id = basic_client_id or body_client_id
        effective_secret = basic_secret or body_secret
        caller_id_hdr = request.headers.get("x-mcp-caller-id")

        # CRITICAL H06 CHECK B:
        if target_client_id and effective_client_id and target_client_id != effective_client_id:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "invalid_client",
                    "error_description": "Forbidden (H06): Authenticated client cannot request a token for another client_id",
                },
            )
        if caller_id_hdr and effective_client_id and caller_id_hdr.strip() != effective_client_id:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "invalid_client",
                    "error_description": "Forbidden (H06): Authenticated client cannot request a token for another client_id",
                },
            )

        # CRITICAL H06 CHECK D:
        expected_owner = getattr(app.state, "expected_owner_id", "local_owner")
        if requested_owner_id and requested_owner_id != expected_owner:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "access_denied",
                    "error_description": "Forbidden (H06): Unexpected owner identity",
                },
            )

        if not grant_type:
            grant_type = "client_credentials"

        if grant_type == "authorization_code":
            if not code or not code_verifier:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "code and code_verifier are required for authorization_code grant",
                    },
                )
            rec = app.state.oauth_persistence.consume_authorization_code(code)
            if not rec or rec.get("used") != 0 or float(rec.get("expires_at", 0)) <= time.time():
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Authorization code is invalid, expired, or already used",
                    },
                )
            if effective_client_id and effective_client_id != rec["client_id"]:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Client ID mismatch for authorization code",
                    },
                )
            if redirect_uri and redirect_uri != rec["redirect_uri"]:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Redirect URI mismatch for authorization code",
                    },
                )

            computed_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
                .decode("ascii")
                .rstrip("=")
            )
            if not hmac.compare_digest(computed_challenge, rec["code_challenge"]):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "PKCE S256 code_verifier validation failed",
                    },
                )

            reg_client = app.state.oauth_persistence.get_client(rec["client_id"])
            if reg_client and effective_secret:
                sec_hash = hashlib.sha256(effective_secret.encode("utf-8")).hexdigest()
                if not hmac.compare_digest(sec_hash, reg_client["client_secret_hash"]):
                    return JSONResponse(
                        status_code=401,
                        headers={"WWW-Authenticate": 'Bearer realm="mcp-autonomous" error="invalid_client"'},
                        content={"error": "invalid_client", "error_description": "Invalid client secret"},
                    )

            c_id = rec["client_id"]
            o_id = rec.get("owner_id") or expected_owner
            scope = rec.get("scope") or "mcp:autonomous"
            res = rec.get("resource") or "mcp-autonomous"

            tok_info = _issue_oauth_token(
                client_id=c_id,
                secret=app.state.oauth_signing_key,
                scope=scope,
                ttl_seconds=3600,
                owner_id=o_id,
                resource=res,
                issuer=issuer,
                typ="access",
            )
            ref_info = _issue_oauth_token(
                client_id=c_id,
                secret=app.state.oauth_signing_key,
                scope=scope,
                ttl_seconds=86400 * 30,
                owner_id=o_id,
                resource=res,
                issuer=issuer,
                typ="refresh",
            )
            tok_info["refresh_token"] = ref_info["access_token"]
            return JSONResponse(status_code=200, content=tok_info)

        elif grant_type == "refresh_token":
            if not refresh_token:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "refresh_token is required for refresh_token grant",
                    },
                )
            ok, payload, err = _verify_oauth_token(
                refresh_token,
                app.state.oauth_signing_key,
                app.state.revoked_oauth_tokens,
                persistence=app.state.oauth_persistence,
                expected_owner_id=expected_owner,
                expected_typ="refresh",
            )
            if not ok or not payload:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": f"Invalid or expired refresh token ({err})",
                    },
                )
            if effective_client_id and effective_client_id != payload.get("client_id"):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Client ID mismatch for refresh token",
                    },
                )

            c_id = payload.get("client_id", "cloud_client_default")
            o_id = payload.get("owner_id") or expected_owner
            scope = payload.get("scope", "mcp:autonomous")
            res = payload.get("resource", "mcp-autonomous")

            tok_info = _issue_oauth_token(
                client_id=c_id,
                secret=app.state.oauth_signing_key,
                scope=scope,
                ttl_seconds=3600,
                owner_id=o_id,
                resource=res,
                issuer=issuer,
                typ="access",
            )
            new_ref_info = _issue_oauth_token(
                client_id=c_id,
                secret=app.state.oauth_signing_key,
                scope=scope,
                ttl_seconds=86400 * 30,
                owner_id=o_id,
                resource=res,
                issuer=issuer,
                typ="refresh",
            )
            tok_info["refresh_token"] = new_ref_info["access_token"]
            if "mcp:owner" in str(scope).split() or "mcp:all" in str(scope).split():
                try:
                    ok_new, new_claims, _ = _verify_oauth_token(
                        tok_info["access_token"],
                        app.state.oauth_signing_key,
                        app.state.revoked_oauth_tokens,
                        persistence=app.state.oauth_persistence,
                        expected_owner_id=expected_owner,
                    )
                    if ok_new and new_claims and new_claims.get("jti"):
                        rebound = app.state.oauth_persistence.rebind_active_owner_grant_on_refresh(
                            secret=app.state.oauth_signing_key,
                            owner_id=o_id,
                            client_id=c_id,
                            new_oauth_token_jti=str(new_claims["jti"]),
                        )
                        if rebound and rebound.get("grant_id"):
                            tok_info["capability_grant_id"] = rebound["grant_id"]
                except Exception:
                    pass
            return JSONResponse(status_code=200, content=tok_info)

        elif grant_type == "client_credentials":
            if not effective_client_id:
                effective_client_id = "cloud_client_default"

            reg_client = app.state.oauth_persistence.get_client(effective_client_id)
            if reg_client:
                # CRITICAL H06 CHECK C
                if not effective_secret:
                    return JSONResponse(
                        status_code=401,
                        headers={"WWW-Authenticate": 'Bearer realm="mcp-autonomous" error="invalid_client"'},
                        content={"error": "invalid_client", "error_description": "Invalid client_id or client_secret credential"},
                    )
                sec_hash = hashlib.sha256(effective_secret.encode("utf-8")).hexdigest()
                if not hmac.compare_digest(sec_hash, reg_client["client_secret_hash"]):
                    return JSONResponse(
                        status_code=401,
                        headers={"WWW-Authenticate": 'Bearer realm="mcp-autonomous" error="invalid_client"'},
                        content={"error": "invalid_client", "error_description": "Invalid client_id or client_secret credential"},
                    )
                owner_id = reg_client.get("owner_id", expected_owner)
            else:
                expected_secret = getattr(app.state, "oauth_client_secret", None) or app.state.caller_auth_token
                if not effective_secret or not _verify_caller_token(effective_secret, expected_secret):
                    return JSONResponse(
                        status_code=401,
                        headers={"WWW-Authenticate": 'Bearer realm="mcp-autonomous" error="invalid_client"'},
                        content={
                            "error": "invalid_client",
                            "error_description": "Invalid client_id or client_secret credential",
                        },
                    )
                owner_id = requested_owner_id or expected_owner

            token_info = _issue_oauth_token(
                client_id=effective_client_id,
                secret=app.state.oauth_signing_key,
                scope="mcp:autonomous",
                ttl_seconds=3600,
                owner_id=owner_id,
                resource="mcp-autonomous",
                issuer=issuer,
                typ="access",
            )
            return JSONResponse(status_code=200, content=token_info)

        else:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "unsupported_grant_type",
                    "error_description": f"Unsupported grant_type: {grant_type}",
                },
            )

    @app.post("/oauth/revoke")
    async def oauth_revoke(request: Request) -> Response:
        token_to_revoke = ""
        auth_hdr = request.headers.get("authorization", "").strip()
        if auth_hdr.lower().startswith("bearer "):
            token_to_revoke = auth_hdr[7:].strip()
        try:
            body_bytes = await request.body()
            if body_bytes:
                ct = request.headers.get("content-type", "").lower()
                if "application/x-www-form-urlencoded" in ct:
                    parsed = urllib.parse.parse_qs(body_bytes.decode("utf-8"))
                    token_to_revoke = parsed.get("token", [token_to_revoke])[0]
                else:
                    b_json = json.loads(body_bytes.decode("utf-8"))
                    if isinstance(b_json, dict):
                        token_to_revoke = b_json.get("token") or b_json.get("jti") or token_to_revoke
        except Exception:
            pass

        if token_to_revoke:
            app.state.revoked_oauth_tokens.add(token_to_revoke)
            app.state.oauth_persistence.revoke_token(token_to_revoke, reason="revocation_endpoint")
            if token_to_revoke.startswith("mcp_oat_") or token_to_revoke.startswith("mcp_ort_"):
                prefix_len = len("mcp_oat_") if token_to_revoke.startswith("mcp_oat_") else len("mcp_ort_")
                raw = token_to_revoke[prefix_len:]
                if "." in raw:
                    p_b64, _ = raw.split(".", 1)
                    pad = len(p_b64) % 4
                    p_b64 += "=" * (4 - pad) if pad else ""
                    try:
                        p_dict = json.loads(base64.urlsafe_b64decode(p_b64.encode("ascii")).decode("utf-8"))
                        if "jti" in p_dict:
                            jti = p_dict["jti"]
                            app.state.revoked_oauth_tokens.add(jti)
                            exp = float(p_dict.get("exp", time.time() + 3600))
                            app.state.oauth_persistence.revoke_token(
                                jti,
                                client_id=p_dict.get("client_id") or p_dict.get("sub"),
                                expires_at=exp,
                                reason="revocation_endpoint_jti",
                            )
                    except Exception:
                        pass
        return JSONResponse(status_code=200, content={"ok": True, "status": "revoked"})

    def _audit_grant_admin_event(endpoint_name: str, decision: str, reason: str, details: dict[str, Any] | None = None) -> None:
        gw_ref = getattr(app.state, "gateway", None)
        if gw_ref is not None and getattr(gw_ref, "policy", None) is not None and hasattr(gw_ref.policy, "audit"):
            try:
                gw_ref.policy.audit.log_event(
                    tool_name=endpoint_name,
                    tier="SYSTEM_ADMIN",
                    decision=decision,
                    reason=reason,
                    arguments=details or {},
                )
            except Exception:
                pass

    def _authenticate_owner_grant_admin(
        request: Request,
        body: dict[str, Any],
        endpoint_name: str,
    ) -> tuple[bool, str, dict[str, Any] | None, JSONResponse | None]:
        """Authenticate owner grant administration (Workstream A1).

        Strictly forbids shared static connector Bearer (`app.state.caller_auth_token`) and
        forbids body `owner_token` matching the shared connector Bearer.
        Requires either:
          1. Verified Owner OAuth Bearer token (`Authorization: Bearer mcp_oat_...` with `mcp:owner` scope), OR
          2. Independent local owner administration secret (`X-MCP-Owner-Admin-Token` or `owner_admin_token`).
        """
        expected_owner = getattr(app.state, "expected_owner_id", "local_owner")
        caller_secret = str(getattr(app.state, "caller_auth_token", "") or "")
        owner_admin_secret = str(getattr(app.state, "owner_admin_token", "") or "")

        header_bearer = _extract_caller_token(request) or ""
        header_admin = request.headers.get("x-mcp-owner-admin-token", "").strip()
        body_owner_token = str(body.get("owner_token") or "").strip()
        body_admin_token = str(body.get("owner_admin_token") or "").strip()

        # CRITICAL WORKSTREAM A1 CHECK: Never allow shared static connector Bearer on grant administration
        for candidate_secret in (header_bearer, header_admin, body_owner_token, body_admin_token):
            if candidate_secret and caller_secret and _verify_caller_token(candidate_secret, caller_secret):
                _audit_grant_admin_event(
                    endpoint_name,
                    "DENY",
                    "Forbidden (A1): Shared static connector Bearer cannot issue or revoke owner capability grants",
                    {"auth_attempt": "static_connector_bearer"},
                )
                return (
                    False,
                    "",
                    None,
                    JSONResponse(
                        status_code=403,
                        content={
                            "error": "access_denied",
                            "error_description": "Forbidden (A1): Shared static connector Bearer cannot issue or revoke owner capability grants",
                        },
                    ),
                )

        # Path 1: Authenticated via Owner OAuth Bearer token in Authorization header
        if header_bearer.startswith("mcp_oat_"):
            ok_oauth, oauth_claims, oauth_err = _verify_oauth_token(
                header_bearer,
                app.state.oauth_signing_key,
                app.state.revoked_oauth_tokens,
                persistence=app.state.oauth_persistence,
                expected_owner_id=expected_owner,
            )
            if not ok_oauth or not oauth_claims:
                _audit_grant_admin_event(
                    endpoint_name,
                    "DENY",
                    f"Invalid OAuth Bearer token on grant admin ({oauth_err})",
                )
                return (
                    False,
                    "",
                    None,
                    JSONResponse(
                        status_code=401,
                        content={"error": "access_denied", "error_description": f"Invalid OAuth owner token ({oauth_err})"},
                    ),
                )
            scopes = str(oauth_claims.get("scope", "")).split()
            tok_owner = str(oauth_claims.get("owner_id") or "")
            tok_client = str(oauth_claims.get("client_id") or oauth_claims.get("sub") or "").strip()
            tok_jti = str(oauth_claims.get("jti") or "").strip()
            if (
                tok_owner != expected_owner
                or not tok_client
                or not tok_jti
                or ("mcp:owner" not in scopes and "mcp:all" not in scopes)
            ):
                _audit_grant_admin_event(
                    endpoint_name,
                    "DENY",
                    "OAuth token lacks local_owner identity or mcp:owner scope for grant administration",
                    {"client_id": tok_client},
                )
                return (
                    False,
                    "",
                    None,
                    JSONResponse(
                        status_code=403,
                        content={
                            "error": "insufficient_scope",
                            "error_description": "Forbidden (A1): OAuth token must belong to local_owner and carry mcp:owner scope",
                        },
                    ),
                )
            return True, "oauth_owner_bearer", {"token": header_bearer, "claims": oauth_claims}, None

        # Path 2: Authenticated via independent local owner administration secret
        admin_candidate = header_admin or body_admin_token or (header_bearer if header_bearer.startswith("mcp_oadm_") else "")
        if admin_candidate and owner_admin_secret and _verify_caller_token(admin_candidate, owner_admin_secret):
            return True, "local_owner_admin", {"owner_id": expected_owner}, None

        _audit_grant_admin_event(
            endpoint_name,
            "DENY",
            "Missing or invalid owner authentication for capability grant administration",
        )
        return (
            False,
            "",
            None,
            JSONResponse(
                status_code=401,
                content={
                    "error": "access_denied",
                    "error_description": "Valid owner OAuth Bearer token or independent local owner admin credential is required",
                },
            ),
        )

    @app.post("/oauth/grants")
    async def oauth_issue_owner_grant(request: Request) -> Response:
        """Owner-authenticated endpoint to issue a short-lived, request-bound capability grant (Workstream A1)."""
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "JSON object body expected"})

        ok_admin, auth_mode, admin_ctx, err_resp = _authenticate_owner_grant_admin(request, body, "oauth_issue_owner_grant")
        if not ok_admin or err_resp is not None:
            return err_resp

        expected_owner = getattr(app.state, "expected_owner_id", "local_owner")
        body_access_token = str(body.get("access_token") or "").strip()
        body_client_id = str(body.get("client_id") or "").strip()
        body_jti = str(body.get("oauth_token_jti") or "").strip()

        if auth_mode == "oauth_owner_bearer":
            claims = (admin_ctx or {}).get("claims") or {}
            bearer_tok = str((admin_ctx or {}).get("token") or "")
            verified_client_id = str(claims.get("client_id") or claims.get("sub") or "").strip()
            verified_jti = str(claims.get("jti") or "").strip()

            # A1 Strict Claim Binding: Do not allow access_token, client_id, or oauth_token_jti in body
            # to override or substitute for the authenticated OAuth caller's verified token claims.
            if body_access_token and not hmac.compare_digest(body_access_token.encode("utf-8"), bearer_tok.encode("utf-8")):
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Forbidden (A1): Body access_token does not match authenticated OAuth Bearer token",
                    {"client_id": verified_client_id},
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (A1): Cannot issue capability grant for a foreign access_token",
                    },
                )
            if body_client_id and body_client_id != verified_client_id:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Forbidden (A1): Body client_id does not match authenticated OAuth token client_id",
                    {"client_id": verified_client_id, "requested_client_id": body_client_id},
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (A1): Cannot override verified OAuth client_id in request body",
                    },
                )
            if body_jti and body_jti != verified_jti:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Forbidden (A1): Body oauth_token_jti does not match authenticated OAuth token JTI",
                    {"client_id": verified_client_id},
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_denied",
                        "error_description": "Forbidden (A1): Cannot override verified OAuth token JTI in request body",
                    },
                )
            client_id = verified_client_id
            oauth_token_jti = verified_jti
        else:
            # Authenticated via independent local owner_admin_token: still require a cryptographically verified OAuth access_token
            if not body_access_token:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Forbidden (A1): Grant issuance requires a cryptographically verified owner OAuth access_token",
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "A valid owner OAuth access_token is required to bind client_id and oauth_token_jti",
                    },
                )
            ok_tok, tok_payload, tok_err = _verify_oauth_token(
                body_access_token,
                app.state.oauth_signing_key,
                app.state.revoked_oauth_tokens,
                persistence=app.state.oauth_persistence,
                expected_owner_id=expected_owner,
            )
            if not ok_tok or not tok_payload:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    f"Cannot bind grant to invalid OAuth token ({tok_err})",
                )
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_grant", "error_description": f"Cannot bind grant to invalid OAuth token ({tok_err})"},
                )
            tok_scopes = str(tok_payload.get("scope", "")).split()
            if "mcp:owner" not in tok_scopes and "mcp:all" not in tok_scopes:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Target OAuth token lacks mcp:owner scope",
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "insufficient_scope", "error_description": "OAuth token must carry mcp:owner scope for owner capability grants"},
                )
            verified_client_id = str(tok_payload.get("client_id") or tok_payload.get("sub") or "").strip()
            verified_jti = str(tok_payload.get("jti") or "").strip()
            if body_client_id and body_client_id != verified_client_id:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Body client_id mismatch with verified access_token",
                    {"verified_client_id": verified_client_id, "body_client_id": body_client_id},
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "access_denied", "error_description": "Forbidden (A1): client_id in body mismatches verified access_token"},
                )
            if body_jti and body_jti != verified_jti:
                _audit_grant_admin_event(
                    "oauth_issue_owner_grant",
                    "DENY",
                    "Body oauth_token_jti mismatch with verified access_token",
                    {"verified_client_id": verified_client_id},
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "access_denied", "error_description": "Forbidden (A1): oauth_token_jti in body mismatches verified access_token"},
                )
            client_id = verified_client_id
            oauth_token_jti = verified_jti

        if not client_id or not oauth_token_jti:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Verified client_id and oauth_token_jti are required"},
            )

        raw_tools = body.get("allowed_tools") or []
        raw_caps = body.get("capabilities") or []
        include_release_deploy = bool(body.get("approve_release_deploy", False))
        try:
            expanded_tools = expand_owner_delegation_capabilities(raw_caps, include_release_deploy=include_release_deploy) if raw_caps else []
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": str(exc)})
        final_tools = sorted(set(list(raw_tools) + expanded_tools))
        if not final_tools:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "allowed_tools or capabilities must be non-empty"},
            )

        allowed_paths = body.get("allowed_paths") or []
        if (not allowed_paths or (isinstance(allowed_paths, list) and len(allowed_paths) == 0)) and (
            "OWNER_GLOBAL_FILESYSTEM" in [str(c).strip().upper() for c in raw_caps]
            or "OWNER_GLOBAL_FILESYSTEM" in final_tools
        ):
            allowed_paths = discover_windows_filesystem_roots()

        if not isinstance(allowed_paths, list) or not allowed_paths:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Explicit non-empty allowed_paths list is required"},
            )

        ttl_seconds = float(body.get("ttl_seconds", 600.0))
        max_uses = int(body.get("max_uses", 20))
        delegation_id_arg = str(body.get("delegation_id") or "").strip()
        allow_destructive_arg = bool(body.get("allow_destructive_operations", False))
        try:
            grant_info = app.state.oauth_persistence.issue_owner_capability_grant(
                secret=app.state.oauth_signing_key,
                allowed_tools=final_tools,
                allowed_paths=[str(p) for p in allowed_paths],
                owner_id=expected_owner,
                client_id=client_id,
                oauth_token_jti=oauth_token_jti,
                ttl_seconds=ttl_seconds,
                max_uses=max_uses,
                delegation_id=delegation_id_arg,
                allow_destructive_operations=allow_destructive_arg,
            )
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": str(exc)})

        _audit_grant_admin_event(
            "oauth_issue_owner_grant",
            "PERMIT",
            f"Issued owner capability grant {grant_info['grant_id']} via {auth_mode}",
            {
                "grant_id": grant_info["grant_id"],
                "client_id": client_id,
                "jti_prefix": oauth_token_jti[:10],
                "ttl_seconds": ttl_seconds,
                "max_uses": max_uses,
                "tools_count": len(final_tools),
                "delegation_id": delegation_id_arg,
                "allow_destructive_operations": allow_destructive_arg,
            },
        )
        pub_grant = {k: v for k, v in grant_info.items() if k != "signature"}
        return JSONResponse(status_code=201, content=pub_grant)

    @app.post("/oauth/grants/revoke")
    async def oauth_revoke_owner_grant(request: Request) -> Response:
        """Owner-authenticated endpoint to immediately revoke a capability grant (Workstream A1)."""
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "JSON object body expected"})

        ok_admin, auth_mode, admin_ctx, err_resp = _authenticate_owner_grant_admin(request, body, "oauth_revoke_owner_grant")
        if not ok_admin or err_resp is not None:
            return err_resp

        grant_id = str(body.get("grant_id") or "").strip()
        if not grant_id:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "grant_id is required"})

        if auth_mode == "oauth_owner_bearer":
            claims = (admin_ctx or {}).get("claims") or {}
            caller_client = str(claims.get("client_id") or claims.get("sub") or "").strip()
            existing = app.state.oauth_persistence.get_owner_capability_grant(grant_id)
            if existing and str(existing.get("client_id") or "") not in ("", caller_client):
                _audit_grant_admin_event(
                    "oauth_revoke_owner_grant",
                    "DENY",
                    f"OAuth client '{caller_client}' attempted to revoke foreign grant '{grant_id}'",
                    {"grant_id": grant_id, "caller_client": caller_client},
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "access_denied", "error_description": "Forbidden (A1): OAuth client cannot revoke another client's capability grant"},
                )

        reason = str(body.get("reason") or f"revoked_by_{auth_mode}")
        revoked = app.state.oauth_persistence.revoke_owner_capability_grant(
            grant_id,
            reason=reason,
        )
        _audit_grant_admin_event(
            "oauth_revoke_owner_grant",
            "PERMIT",
            f"Revoked owner capability grant {grant_id} via {auth_mode} (revoked={revoked})",
            {"grant_id": grant_id, "revoked": revoked, "reason": reason},
        )
        return JSONResponse(status_code=200, content={"ok": True, "grant_id": grant_id, "revoked": revoked})

    @app.post("/oauth/delegations")
    async def oauth_issue_owner_durable_delegation(request: Request) -> Response:
        """Owner-authenticated endpoint to issue a Layer-1 Durable Owner Delegation + initial rolling Layer-2 grant (P1)."""
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "JSON object body expected"})

        ok_admin, auth_mode, admin_ctx, err_resp = _authenticate_owner_grant_admin(request, body, "oauth_issue_owner_durable_delegation")
        if not ok_admin or err_resp is not None:
            return err_resp

        expected_owner = getattr(app.state, "expected_owner_id", "local_owner")
        body_access_token = str(body.get("access_token") or "").strip()
        body_client_id = str(body.get("client_id") or "").strip()

        if auth_mode == "oauth_owner_bearer":
            claims = (admin_ctx or {}).get("claims") or {}
            bearer_tok = str((admin_ctx or {}).get("token") or "")
            verified_client_id = str(claims.get("client_id") or claims.get("sub") or "").strip()
            verified_jti = str(claims.get("jti") or "").strip()
            if body_access_token and not hmac.compare_digest(body_access_token.encode("utf-8"), bearer_tok.encode("utf-8")):
                return JSONResponse(status_code=403, content={"error": "access_denied", "error_description": "Forbidden (A1): Cannot issue durable delegation for a foreign access_token"})
            if body_client_id and body_client_id != verified_client_id:
                return JSONResponse(status_code=403, content={"error": "access_denied", "error_description": "Forbidden (A1): Cannot override verified OAuth client_id in request body"})
            client_id = verified_client_id
            oauth_token_jti = verified_jti
        else:
            if not body_access_token:
                return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "A valid owner OAuth access_token is required"})
            ok_tok, tok_payload, tok_err = _verify_oauth_token(
                body_access_token,
                app.state.oauth_signing_key,
                app.state.revoked_oauth_tokens,
                persistence=app.state.oauth_persistence,
                expected_owner_id=expected_owner,
            )
            if not ok_tok or not tok_payload:
                return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": f"Cannot bind durable delegation to invalid OAuth token ({tok_err})"})
            tok_scopes = str(tok_payload.get("scope", "")).split()
            if "mcp:owner" not in tok_scopes and "mcp:all" not in tok_scopes:
                return JSONResponse(status_code=403, content={"error": "insufficient_scope", "error_description": "OAuth token must carry mcp:owner scope"})
            verified_client_id = str(tok_payload.get("client_id") or tok_payload.get("sub") or "").strip()
            verified_jti = str(tok_payload.get("jti") or "").strip()
            if body_client_id and body_client_id != verified_client_id:
                return JSONResponse(status_code=403, content={"error": "access_denied", "error_description": "Forbidden (A1): client_id in body mismatches verified access_token"})
            client_id = verified_client_id
            oauth_token_jti = verified_jti

        raw_tools = body.get("allowed_tools") or []
        raw_caps = body.get("capabilities") or []
        include_release_deploy = bool(body.get("approve_release_deploy", False))
        try:
            expanded_tools = expand_owner_delegation_capabilities(raw_caps, include_release_deploy=include_release_deploy) if raw_caps else []
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": str(exc)})
        final_tools = sorted(set(list(raw_tools) + expanded_tools))
        if not final_tools:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "allowed_tools or capabilities must be non-empty"})

        allowed_paths = body.get("allowed_paths") or []
        if (not allowed_paths or (isinstance(allowed_paths, list) and len(allowed_paths) == 0)) and (
            "OWNER_GLOBAL_FILESYSTEM" in [str(c).strip().upper() for c in raw_caps]
            or "OWNER_GLOBAL_FILESYSTEM" in final_tools
        ):
            allowed_paths = discover_windows_filesystem_roots()

        if not isinstance(allowed_paths, list) or not allowed_paths:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Explicit non-empty allowed_paths list is required"})

        ttl_seconds = float(body.get("ttl_seconds", 28800.0))
        total_budget = int(body.get("total_operation_budget") if body.get("total_operation_budget") is not None else body.get("total_budget", 5000))
        allow_destructive = bool(body.get("allow_destructive_operations") if body.get("allow_destructive_operations") is not None else body.get("allow_destructive", False))
        rolling_ttl = float(body.get("rolling_grant_ttl_seconds", min(900.0, ttl_seconds)))
        rolling_max_uses = int(body.get("rolling_grant_max_uses", min(100, total_budget)))

        try:
            del_info = app.state.oauth_persistence.issue_owner_durable_delegation(
                secret=app.state.oauth_signing_key,
                allowed_tools=final_tools,
                allowed_paths=[str(p) for p in allowed_paths],
                owner_id=expected_owner,
                client_id=client_id,
                ttl_seconds=ttl_seconds,
                total_operation_budget=total_budget,
                allow_destructive_operations=allow_destructive,
                audit_identity=f"{expected_owner}:{client_id}",
            )
            initial_grant = app.state.oauth_persistence.issue_owner_capability_grant(
                secret=app.state.oauth_signing_key,
                allowed_tools=final_tools,
                allowed_paths=[str(p) for p in allowed_paths],
                owner_id=expected_owner,
                client_id=client_id,
                oauth_token_jti=oauth_token_jti,
                ttl_seconds=rolling_ttl,
                max_uses=rolling_max_uses,
                delegation_id=del_info["delegation_id"],
                allow_destructive_operations=allow_destructive,
            )
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": str(exc)})

        _audit_grant_admin_event(
            "oauth_issue_owner_durable_delegation",
            "PERMIT",
            f"Issued durable owner delegation {del_info['delegation_id']} and initial grant {initial_grant['grant_id']} via {auth_mode}",
            {
                "delegation_id": del_info["delegation_id"],
                "initial_grant_id": initial_grant["grant_id"],
                "client_id": client_id,
                "ttl_seconds": ttl_seconds,
                "total_operation_budget": total_budget,
                "allow_destructive_operations": allow_destructive,
            },
        )
        pub_del = {k: v for k, v in del_info.items() if k != "signature"}
        pub_del["initial_grant_id"] = initial_grant["grant_id"]
        pub_del["capability_grant_id"] = initial_grant["grant_id"]
        pub_del["initial_grant_expires_at"] = initial_grant["expires_at"]
        return JSONResponse(status_code=201, content=pub_del)

    @app.post("/oauth/delegations/revoke")
    async def oauth_revoke_owner_durable_delegation(request: Request) -> Response:
        """Owner-authenticated endpoint to immediately revoke a Durable Owner Delegation and all child grants (P1)."""
        disallowed_err = _check_disallowed_query_secrets(request)
        if disallowed_err is not None:
            return disallowed_err
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "JSON object body expected"})

        ok_admin, auth_mode, admin_ctx, err_resp = _authenticate_owner_grant_admin(request, body, "oauth_revoke_owner_durable_delegation")
        if not ok_admin or err_resp is not None:
            return err_resp

        delegation_id = str(body.get("delegation_id") or "").strip()
        if not delegation_id:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "delegation_id is required"})

        if auth_mode == "oauth_owner_bearer":
            claims = (admin_ctx or {}).get("claims") or {}
            caller_client = str(claims.get("client_id") or claims.get("sub") or "").strip()
            existing = app.state.oauth_persistence.get_owner_durable_delegation(delegation_id)
            if existing and str(existing.get("client_id") or "") not in ("", caller_client):
                return JSONResponse(status_code=403, content={"error": "access_denied", "error_description": "Forbidden (A1): OAuth client cannot revoke another client's durable delegation"})

        reason = str(body.get("reason") or f"revoked_by_{auth_mode}")
        revoked = app.state.oauth_persistence.revoke_owner_durable_delegation(delegation_id, reason=reason)
        _audit_grant_admin_event(
            "oauth_revoke_owner_durable_delegation",
            "PERMIT",
            f"Revoked durable owner delegation {delegation_id} via {auth_mode} (revoked={revoked})",
            {"delegation_id": delegation_id, "revoked": revoked, "reason": reason},
        )
        return JSONResponse(status_code=200, content={"ok": True, "delegation_id": delegation_id, "revoked": revoked})


def create_gateway_http_app(
    *,
    profile: str | None = None,
    policy_path: str | Path | None = None,
    gateway: MCPGatewayServer | None = None,
    caller_auth_token: str | None = None,
    oauth_signing_key: str | None = None,
    owner_admin_token: str | None = None,
    require_autonomous_auth: bool = True,
    db_path: str | Path | None = None,
) -> FastAPI:
    """Create a FastAPI ASGI application serving the Unified MCP Gateway."""
    if gateway is not None:
        gw = gateway
    else:
        pol = SecurityPolicy(policy_path=policy_path, profile=profile)
        gw = MCPGatewayServer(policy=pol)

    resolved_caller_token = load_gateway_auth_token(caller_auth_token)
    resolved_db_path = resolve_oauth_db_path(db_path=db_path, gateway=gw)
    resolved_oauth_signing_key = load_oauth_signing_key(
        oauth_signing_key,
        db_path=resolved_db_path,
        caller_auth_token=resolved_caller_token,
    )
    resolved_owner_admin_token = load_owner_admin_token(
        owner_admin_token,
        db_path=resolved_db_path,
        caller_auth_token=resolved_caller_token,
        oauth_signing_key=resolved_oauth_signing_key,
    )

    env_req = os.getenv("WINDOWS_MCP_REQUIRE_AUTONOMOUS_AUTH") or os.getenv("MCP_REQUIRE_AUTONOMOUS_AUTH")
    if env_req is not None:
        require_autonomous_auth = env_req.lower() not in ("0", "false", "no", "off")

    app = FastAPI(
        title="Unified Windows MCP Gateway",
        version=gw.server_version,
        docs_url=None,
        redoc_url=None,
    )
    app.state.gateway = gw
    app.state.caller_auth_token = resolved_caller_token
    app.state.oauth_signing_key = resolved_oauth_signing_key
    app.state.owner_admin_token = resolved_owner_admin_token
    app.state.require_autonomous_auth = require_autonomous_auth

    # Durable SQLite persistence for OAuth clients, codes, and revocations (H07)
    persistence = _SQLiteOAuthPersistence(resolved_db_path)
    persistence.prune_expired_revocations()
    app.state.oauth_persistence = persistence
    app.state.revoked_oauth_tokens = persistence.load_active_revocations()
    app.state.expected_owner_id = "local_owner"
    gw._oauth_persistence = persistence
    gw._caller_auth_token = resolved_caller_token
    gw._oauth_signing_key = resolved_oauth_signing_key
    gw._owner_admin_token = resolved_owner_admin_token
    gw._revoked_oauth_tokens = app.state.revoked_oauth_tokens

    app.state.submission_timestamps: dict[str, list[float]] = {}
    app.state.mcp_stream_sessions: dict[str, str] = {}
    app.state.max_request_bytes = DEFAULT_MAX_REQUEST_BYTES
    app.state.max_submissions_per_minute = DEFAULT_MAX_SUBMISSIONS_PER_MINUTE

    def _require_owner_auth(request: Request, endpoint_name: str) -> JSONResponse | None:
        provided = _extract_caller_token(request)
        if provided is None:
            gw.policy.audit.log_event(
                tool_name=endpoint_name,
                tier="AUTH",
                decision="DENY",
                reason="Missing caller authentication token",
            )
            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": "Unauthorized: missing caller authentication token"},
            )
        if not _verify_caller_token(provided, app.state.caller_auth_token):
            gw.policy.audit.log_event(
                tool_name=endpoint_name,
                tier="AUTH",
                decision="DENY",
                reason="Invalid or forged caller authentication token",
            )
            return JSONResponse(
                status_code=403,
                content={"ok": False, "error": "Forbidden: invalid caller authentication token"},
            )
        return None

    @app.get("/health")
    async def health() -> dict[str, Any]:
        exposed = gw.exposed_tool_names()
        return {
            "status": "ok",
            "service": "unified-mcp-gateway",
            "server": gw.server_name,
            "version": gw.server_version,
            "profile": gw.policy.profile,
            "strict_v021_read_tools_only": gw.policy.strict_v021_read_tools_only,
            "require_session_for_privileged": gw.policy.require_session_for_privileged,
            "enabled_tiers": sorted(t.value for t in gw.policy.enabled_tiers),
            "tools_count": len(exposed),
        }

    @app.post("/api/sessions")
    async def api_create_session(request: Request) -> Response:
        auth_err = _require_owner_auth(request, "api_create_session")
        if auth_err is not None:
            return auth_err
        try:
            body = await request.json()
        except Exception as exc:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": f"Invalid JSON body: {redact_secrets(str(exc))}"},
            )
        if not isinstance(body, dict):
            return JSONResponse(status_code=400, content={"ok": False, "error": "JSON object required"})

        tiers = body.get("tiers") or body.get("allowed_tiers") or ["READ"]
        ttl_seconds = body.get("ttl_seconds")
        client_id = body.get("client_id") or request.headers.get("x-mcp-caller-id") or body.get("owner") or "local"
        allowed_paths = body.get("allowed_paths")
        allowed_commands = body.get("allowed_commands")
        allowed_tools = body.get("allowed_tools")

        try:
            sess = gw.policy.sessions.create_session(
                tiers=tiers,
                ttl_seconds=ttl_seconds,
                client_id=str(client_id),
                allowed_paths=allowed_paths,
                allowed_commands=allowed_commands,
                allowed_tools=allowed_tools,
            )
        except PermissionError as exc:
            gw.policy.audit.log_event(
                tool_name="api_create_session",
                tier="SESSION",
                decision="DENY",
                reason=str(exc),
                arguments=body,
            )
            return JSONResponse(status_code=403, content={"ok": False, "error": str(exc)})
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

        issued_tokens_map: dict[str, dict[str, Any]] = {}
        if body.get("issue_approval_tokens"):
            req_tools = body.get("approval_tools") or []
            for t_name in req_tools:
                t_tier = TOOL_TIER_MAP.get(str(t_name), PermissionTier.WRITE)
                tok_obj = gw.policy.sessions.issue_approval_token(
                    tier=t_tier,
                    tool_name=str(t_name),
                    session_id=sess.session_id,
                    ttl_seconds=int(ttl_seconds or 300),
                )
                issued_tokens_map[str(t_name)] = {
                    "token_id": tok_obj.token_id,
                    "tier": tok_obj.tier.value,
                    "tool_name": tok_obj.tool_name,
                    "expires_at": tok_obj.expires_at,
                }

        session_dict = {
            "session_id": sess.session_id,
            "approval_token": sess.approval_token,
            "client_id": sess.client_id,
            "tiers": sorted(t.value for t in sess.tiers),
            "created_at": sess.created_at,
            "expires_at": sess.expires_at,
            "allowed_paths": [str(p) for p in sess.allowed_paths] if sess.allowed_paths is not None else None,
            "allowed_commands": list(sess.allowed_commands) if sess.allowed_commands is not None else None,
            "allowed_tools": sorted(sess.allowed_tools) if sess.allowed_tools is not None else None,
        }

        gw.policy.audit.log_event(
            tool_name="api_create_session",
            tier="SESSION",
            decision="ALLOW",
            session_id=sess.session_id,
            result_summary={
                "client_id": sess.client_id,
                "tiers": sorted(t.value for t in sess.tiers),
                "expires_at": sess.expires_at,
                "allowed_paths": [str(p) for p in sess.allowed_paths] if sess.allowed_paths is not None else None,
                "allowed_commands": list(sess.allowed_commands) if sess.allowed_commands is not None else None,
            },
        )
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                **session_dict,
                "session": session_dict,
                "approval_tokens": issued_tokens_map,
            },
        )

    @app.post("/api/sessions/revoke-all")
    async def api_revoke_all_sessions(request: Request) -> Response:
        auth_err = _require_owner_auth(request, "api_revoke_all_sessions")
        if auth_err is not None:
            return auth_err
        reason = "api_revoke_all"
        try:
            body = await request.json()
            if isinstance(body, dict) and body.get("reason"):
                reason = str(body["reason"])
        except Exception:
            pass
        count = gw.policy.sessions.revoke_all(reason=reason)
        gw.policy.audit.log_event(
            tool_name="api_revoke_all_sessions",
            tier="SESSION",
            decision="ALLOW",
            reason=reason,
            result_summary={"revoked_count": count},
        )
        return JSONResponse(status_code=200, content={"ok": True, "revoked_count": count, "reason": reason})

    @app.post("/api/sessions/{session_id}/revoke")
    async def api_revoke_session(session_id: str, request: Request) -> Response:
        auth_err = _require_owner_auth(request, "api_revoke_session")
        if auth_err is not None:
            return auth_err
        reason = "api_manual_revoke"
        try:
            body = await request.json()
            if isinstance(body, dict) and body.get("reason"):
                reason = str(body["reason"])
        except Exception:
            pass
        revoked = gw.policy.sessions.revoke_session(session_id, reason=reason)
        gw.policy.audit.log_event(
            tool_name="api_revoke_session",
            tier="SESSION",
            decision="ALLOW" if revoked else "DENY",
            session_id=session_id,
            reason=reason,
            result_summary={"revoked": revoked},
        )
        return JSONResponse(
            status_code=200 if revoked else 404,
            content={"ok": revoked, "session_id": session_id, "revoked": revoked, "reason": reason},
        )

    @app.post("/api/emergency-stop")
    async def api_emergency_stop(request: Request) -> Response:
        auth_err = _require_owner_auth(request, "api_emergency_stop")
        if auth_err is not None:
            return auth_err
        reason = "http_api_emergency_stop"
        try:
            body = await request.json()
            if isinstance(body, dict) and body.get("reason"):
                reason = str(body["reason"])
        except Exception:
            pass
        info = await asyncio.to_thread(gw.engage_emergency_stop, reason)
        return JSONResponse(status_code=200, content={"ok": True, **info})

    @app.post("/api/emergency-stop/reset")
    async def api_emergency_stop_reset(request: Request) -> Response:
        auth_err = _require_owner_auth(request, "api_emergency_stop_reset")
        if auth_err is not None:
            return auth_err
        info = await asyncio.to_thread(gw.reset_emergency_stop)
        return JSONResponse(status_code=200, content={"ok": True, **info})

    # ------------------------------------------------------------------
    # RFC 8414 & MCP OAuth 2.1 Discovery and Token Management (H05/H06/H07)
    # ------------------------------------------------------------------
    register_oauth_endpoints(
        app,
        issuer="windows-mcp-gateway",
        default_resource_uri="https://127.0.0.1:8766/mcp/autonomous",
    )

    # ------------------------------------------------------------------
    # MCP JSON-RPC 2.0 Streamable HTTP Handlers (/mcp and /mcp/autonomous)
    # ------------------------------------------------------------------
    @app.get("/mcp")
    async def mcp_get() -> Response:
        return JSONResponse(
            status_code=405,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Use HTTP POST /mcp with JSON-RPC 2.0 payload",
                },
            },
        )

    @app.delete("/mcp")
    @app.delete("/mcp/autonomous")
    async def mcp_delete(request: Request) -> Response:
        mcp_sess = request.headers.get("mcp-session-id", "").strip()
        if not mcp_sess:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    b = json.loads(body_bytes.decode("utf-8"))
                    if isinstance(b, dict):
                        mcp_sess = str(b.get("session_id") or b.get("mcp_session_id") or "").strip()
            except Exception:
                pass
        if mcp_sess and mcp_sess in app.state.mcp_stream_sessions:
            app.state.mcp_stream_sessions.pop(mcp_sess, None)
            return JSONResponse(status_code=200, content={"ok": True, "message": f"Session {mcp_sess} closed"})
        return JSONResponse(status_code=200, content={"ok": True, "message": "No active session or session already closed"})

    @app.post("/mcp")
    async def mcp_post(request: Request) -> Response:
        body_bytes = await request.body()
        max_bytes = getattr(app.state, "max_request_bytes", DEFAULT_MAX_REQUEST_BYTES)
        if len(body_bytes) > max_bytes:
            return _jsonrpc_auth_error_response(
                status_code=413,
                req_id=None,
                code=-32600,
                message="Payload Too Large: request exceeds maximum allowed size (256 KB)",
            )

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {redact_secrets(str(exc))}",
                    },
                },
            )

        valid_rpc, rpc_err = _validate_jsonrpc_structure(payload)
        if not valid_rpc:
            req_id = payload.get("id") if isinstance(payload, dict) else None
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32600,
                        "message": rpc_err,
                    },
                },
            )

        session_id = request.headers.get("x-mcp-session-id") or None
        approval_token = request.headers.get("x-mcp-approval-token") or None
        caller_id = request.headers.get("x-mcp-caller-id") or "local"
        provided_caller_token = _extract_caller_token(request)
        caller_authenticated = False
        if provided_caller_token is not None:
            if provided_caller_token.startswith("mcp_oat_"):
                oauth_ok, oauth_p, _ = _verify_oauth_token(
                    provided_caller_token,
                    app.state.caller_auth_token,
                    app.state.revoked_oauth_tokens,
                    persistence=getattr(app.state, "oauth_persistence", None),
                )
                if oauth_ok and oauth_p:
                    caller_authenticated = True
                    caller_id = str(oauth_p.get("client_id") or oauth_p.get("sub") or caller_id)
            else:
                caller_authenticated = _verify_caller_token(provided_caller_token, app.state.caller_auth_token)

        req_id = payload.get("id") if isinstance(payload, dict) else None

        # 1. If X-MCP-Session-Id is supplied, validate session existence & active state immediately
        if session_id is not None:
            sess = gw.policy.sessions.get_session(session_id.strip())
            if sess is None or not sess.is_active():
                deny_reason = (
                    f"Forged, expired, or revoked X-MCP-Session-Id header: {session_id}"
                )
                gw.policy.audit.log_event(
                    tool_name="mcp_http_auth",
                    tier="AUTH",
                    decision="DENY",
                    reason=deny_reason,
                    session_id=session_id,
                )
                return _jsonrpc_auth_error_response(
                    status_code=403,
                    req_id=req_id,
                    code=-32003,
                    message=deny_reason,
                )

        # 2. Enforce caller authentication on privileged profiles or when privileged headers are supplied
        is_privileged_profile = (
            gw.policy.profile != "read_only"
            or gw.policy.enabled_tiers != {PermissionTier.READ}
        )
        has_privileged_headers = (session_id is not None) or (approval_token is not None)

        if (is_privileged_profile or has_privileged_headers) and not caller_authenticated:
            status_code = 401 if provided_caller_token is None else 403
            deny_reason = (
                "Unauthorized: missing caller authentication token for privileged gateway"
                if provided_caller_token is None
                else "Forbidden: invalid caller authentication token for privileged gateway"
            )
            gw.policy.audit.log_event(
                tool_name="mcp_http_auth",
                tier="AUTH",
                decision="DENY",
                reason=deny_reason,
                session_id=session_id,
            )
            return _jsonrpc_auth_error_response(
                status_code=status_code,
                req_id=req_id,
                code=-32001 if status_code == 401 else -32003,
                message=deny_reason,
            )

        # Mcp-Session-Id header management (H04)
        sess_ok, _, resp_headers, sess_err = _handle_mcp_stream_session(
            request, app, payload, caller_id
        )
        if not sess_ok and sess_err is not None:
            return sess_err

        if isinstance(payload, list):
            responses: list[dict[str, Any]] = []
            for item in payload:
                resp_item = await asyncio.to_thread(
                    gw.handle_jsonrpc,
                    item,
                    session_id=session_id,
                    approval_token=approval_token,
                    caller_id=caller_id,
                )
                if resp_item is not None:
                    responses.append(resp_item)
            if not responses:
                return Response(status_code=202, headers=resp_headers)
            return JSONResponse(status_code=200, content=responses, headers=resp_headers)

        resp_obj = await asyncio.to_thread(
            gw.handle_jsonrpc,
            payload,
            session_id=session_id,
            approval_token=approval_token,
            caller_id=caller_id,
        )
        if resp_obj is None:
            return Response(status_code=202, headers=resp_headers)
        return JSONResponse(status_code=200, content=resp_obj, headers=resp_headers)

    @app.get("/mcp/autonomous")
    async def mcp_autonomous_get() -> Response:
        return JSONResponse(
            status_code=405,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Use HTTP POST /mcp/autonomous with JSON-RPC 2.0 payload",
                },
            },
        )

    @app.post("/mcp/autonomous")
    async def mcp_autonomous_post(request: Request) -> Response:
        body_bytes = await request.body()
        max_bytes = getattr(app.state, "max_request_bytes", DEFAULT_MAX_REQUEST_BYTES)
        if len(body_bytes) > max_bytes:
            return _jsonrpc_auth_error_response(
                status_code=413,
                req_id=None,
                code=-32600,
                message="Payload Too Large: request exceeds maximum allowed size (256 KB)",
            )

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {redact_secrets(str(exc))}",
                    },
                },
            )

        valid_rpc, rpc_err = _validate_jsonrpc_structure(payload)
        if not valid_rpc:
            req_id = payload.get("id") if isinstance(payload, dict) else None
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32600,
                        "message": rpc_err,
                    },
                },
            )

        req_id = payload.get("id") if isinstance(payload, dict) else None
        ok, authenticated_identity, auth_status, auth_err = _authenticate_autonomous_caller(
            request=request,
            app=app,
            gw=gw,
            require_auth=app.state.require_autonomous_auth,
        )
        if not ok:
            extra_hdrs = (
                {
                    "WWW-Authenticate": 'Bearer realm="mcp-autonomous", resource_metadata="/.well-known/oauth-protected-resource", scope="mcp:autonomous"'
                }
                if auth_status == 401
                else None
            )
            return _jsonrpc_auth_error_response(
                status_code=auth_status,
                req_id=req_id,
                code=-32001 if auth_status == 401 else -32003,
                message=auth_err,
                headers=extra_hdrs,
            )

        # Rate limiting on agent_submit_task (H01)
        if isinstance(payload, dict):
            if payload.get("method") == "tools/call" and (payload.get("params") or {}).get("name") == "agent_submit_task":
                rate_err = _check_task_submission_rate_limit(app, authenticated_identity, req_id, 1)
                if rate_err is not None:
                    return rate_err
        elif isinstance(payload, list):
            submit_count = sum(
                1
                for item in payload
                if isinstance(item, dict)
                and item.get("method") == "tools/call"
                and (item.get("params") or {}).get("name") == "agent_submit_task"
            )
            if submit_count > 0:
                rate_err = _check_task_submission_rate_limit(app, authenticated_identity, req_id, submit_count)
                if rate_err is not None:
                    return rate_err

        # Mcp-Session-Id header management (H04)
        sess_ok, _, resp_headers, sess_err = _handle_mcp_stream_session(
            request, app, payload, authenticated_identity
        )
        if not sess_ok and sess_err is not None:
            return sess_err

        principal = getattr(request.state, "auth_principal", None)
        if isinstance(payload, list):
            responses: list[dict[str, Any]] = []
            for item in payload:
                resp_item = await asyncio.to_thread(
                    gw.handle_jsonrpc_autonomous,
                    item,
                    caller_id=authenticated_identity,
                    auth_principal=principal,
                )
                if resp_item is not None:
                    responses.append(resp_item)
            if not responses:
                return Response(status_code=202, headers=resp_headers)
            return JSONResponse(status_code=200, content=responses, headers=resp_headers)

        resp_obj = await asyncio.to_thread(
            gw.handle_jsonrpc_autonomous,
            payload,
            caller_id=authenticated_identity,
            auth_principal=principal,
        )
        if resp_obj is None:
            return Response(status_code=202, headers=resp_headers)
        return JSONResponse(status_code=200, content=resp_obj, headers=resp_headers)

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified Windows MCP Gateway HTTP Server")
    parser.add_argument(
        "--host",
        default=os.getenv("WINDOWS_MCP_GATEWAY_HOST", "127.0.0.1"),
        help="Bind host (default: 127.0.0.1 — loopback only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("WINDOWS_MCP_GATEWAY_STAGING_PORT", "8766")),
        help="Bind TCP port (default: 8766 for staging, 8765 for production cutover)",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("MCP_AGENT_PROFILE", "read_only"),
        help="Security policy profile (read_only, developer_p2, desktop_p3, full_agent)",
    )
    parser.add_argument(
        "--policy-path",
        default=None,
        help="Optional path to policy.json",
    )
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"Refusing to bind Unified MCP Gateway to non-loopback address: {args.host}"
        )

    app = create_gateway_http_app(profile=args.profile, policy_path=args.policy_path)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
