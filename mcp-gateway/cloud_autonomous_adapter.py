"""Dedicated Local Loopback Adapter for Cloud Autonomous MCP (Port 8768).

Remediates Critical Findings H01, H03, H04:
  - H03: OpenAI's tunnel-client.exe routes tunnel traffic to conventional /mcp on a local port.
    Pointing tunnel-client to port 8766 would expose the full staging gateway.
    This adapter binds strictly to 127.0.0.1:8768 and maps /mcp exclusively to
    six Cloud-Safe Autonomous tools and eight trusted workspace coding tools.
  - H01: Enforces mandatory caller authentication (OAuth 2.0 Bearer tokens, configured caller token,
    request size limits (256 KB), task submission rate limiting (max 10/min),
    and rejects token/caller-id mismatches.
  - H04: Supports MCP protocol versions through 2025-11-25, Mcp-Session-Id header
    lifecycle (initialize, verify, DELETE session), and tool annotations in tools/list.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for _p in (HERE, PROJECT_ROOT, PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from policy import SecurityPolicy, redact_secrets  # noqa: E402
from gateway_server import MCPGatewayServer  # noqa: E402
from http_server import (  # noqa: E402
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_SUBMISSIONS_PER_MINUTE,
    _SQLiteOAuthPersistence,
    _authenticate_autonomous_caller,
    _check_task_submission_rate_limit,
    _jsonrpc_auth_error_response,
    _is_allowed_origin_or_referer,
    _validate_jsonrpc_structure,
    _verify_oauth_token,
    load_gateway_auth_token,
    load_oauth_signing_key,
    load_owner_admin_token,
    register_oauth_endpoints,
    resolve_oauth_db_path,
)
from runtime.agent_mcp_tools import CLOUD_SAFE_AUTONOMOUS_TOOLS  # noqa: E402
from runtime.coding_tools import CODING_TOOL_NAMES  # noqa: E402

logger = logging.getLogger("cloud_autonomous_adapter")
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")


def validate_loopback_bind(host: str) -> str:
    """Validate that host is strictly a loopback address (H03)."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"Refusing to bind Cloud Autonomous Adapter to non-loopback address: {host}. "
            "Only 127.0.0.1 / localhost permitted."
        )
    return host


class _SQLiteMcpSessionStore:
    """Lightweight SQLite helper for durable MCP stream session persistence (Task 1)."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._is_memory = self.db_path == ":memory:"
        self._mem_conn: sqlite3.Connection | None = None
        if self._is_memory:
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        else:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._is_memory and self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS mcp_stream_sessions (
                            session_id TEXT PRIMARY KEY,
                            identity TEXT NOT NULL,
                            protocol_version TEXT NOT NULL,
                            updated_at REAL NOT NULL,
                            terminated INTEGER NOT NULL DEFAULT 0
                        )
                        """
                    )
            finally:
                if not self._is_memory:
                    conn.close()

    def save_session(
        self,
        session_id: str,
        identity: str,
        protocol_version: str,
        terminated: bool = False,
        updated_at: float | None = None,
    ) -> None:
        if updated_at is None:
            updated_at = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO mcp_stream_sessions (session_id, identity, protocol_version, updated_at, terminated)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(session_id) DO UPDATE SET
                            identity=excluded.identity,
                            protocol_version=excluded.protocol_version,
                            updated_at=excluded.updated_at,
                            terminated=excluded.terminated
                        """,
                        (session_id, identity, protocol_version, updated_at, 1 if terminated else 0),
                    )
            finally:
                if not self._is_memory:
                    conn.close()

    def mark_terminated(self, session_id: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    conn.execute(
                        "UPDATE mcp_stream_sessions SET terminated = 1, updated_at = ? WHERE session_id = ?",
                        (now, session_id),
                    )
            finally:
                if not self._is_memory:
                    conn.close()

    def touch_session(self, session_id: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    conn.execute(
                        "UPDATE mcp_stream_sessions SET updated_at = ? WHERE session_id = ? AND terminated = 0",
                        (now, session_id),
                    )
            finally:
                if not self._is_memory:
                    conn.close()

    def load_sessions(self, idle_seconds: float) -> tuple[dict[str, str], dict[str, str], set[str]]:
        now = time.time()
        cutoff = now - idle_seconds
        active_sessions: dict[str, str] = {}
        active_protocols: dict[str, str] = {}
        terminated_sessions: set[str] = set()
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "SELECT session_id, identity, protocol_version, updated_at, terminated FROM mcp_stream_sessions"
                )
                to_terminate: list[str] = []
                for row in cur.fetchall():
                    sid = row["session_id"]
                    term = row["terminated"]
                    upd = row["updated_at"]
                    if term == 1:
                        terminated_sessions.add(sid)
                    elif upd < cutoff:
                        terminated_sessions.add(sid)
                        to_terminate.append(sid)
                    else:
                        active_sessions[sid] = row["identity"]
                        active_protocols[sid] = row["protocol_version"]
                if to_terminate:
                    with conn:
                        conn.executemany(
                            "UPDATE mcp_stream_sessions SET terminated = 1 WHERE session_id = ?",
                            [(s,) for s in to_terminate],
                        )
            finally:
                if not self._is_memory:
                    conn.close()
        return active_sessions, active_protocols, terminated_sessions


def create_cloud_autonomous_adapter_app(
    *,
    gateway: MCPGatewayServer | None = None,
    caller_auth_token: str | None = None,
    oauth_signing_key: str | None = None,
    owner_admin_token: str | None = None,
    require_autonomous_auth: bool = True,
    allow_loopback_tunnel_identity: bool = False,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    max_submissions_per_minute: int = DEFAULT_MAX_SUBMISSIONS_PER_MINUTE,
    profile: str | None = "read_only",
    policy_path: str | Path | None = None,
    db_path: str | Path | None = None,
    enable_direct_coding: bool | None = None,
) -> FastAPI:
    """Create a FastAPI ASGI application serving the Dedicated Cloud Autonomous Adapter on Port 8768."""
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

    app = FastAPI(
        title="Cloud Autonomous Dedicated Loopback Adapter",
        version=gw.server_version,
        docs_url=None,
        redoc_url=None,
    )
    app.state.gateway = gw
    app.state.caller_auth_token = resolved_caller_token
    app.state.oauth_signing_key = resolved_oauth_signing_key
    app.state.owner_admin_token = resolved_owner_admin_token
    # This dedicated coding surface never turns private tunnel discovery into
    # backend authorization. Legacy compatibility switches cannot disable auth.
    app.state.require_autonomous_auth = True
    app.state.allow_loopback_tunnel_identity = False

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

    # Durable SQLite persistence for MCP Stream sessions (Task 1)
    session_store = _SQLiteMcpSessionStore(resolved_db_path)
    app.state.mcp_session_store = session_store
    app.state.mcp_session_idle_seconds = 3600
    app.state.max_mcp_sessions = 1024
    app.state.terminated_mcp_sessions = set()

    active_sess, active_protos, term_sess = session_store.load_sessions(
        app.state.mcp_session_idle_seconds
    )
    app.state.mcp_stream_sessions = active_sess
    app.state.mcp_session_protocols = active_protos
    now_mono = time.monotonic()
    app.state.mcp_session_last_seen = {sid: now_mono for sid in active_sess}
    app.state.terminated_mcp_sessions = term_sess

    def save_mcp_session(
        session_id: str,
        identity: str,
        protocol_version: str,
        terminated: bool = False,
    ) -> None:
        session_store.save_session(
            session_id, identity, protocol_version, terminated=terminated
        )

    app.state.save_mcp_session = save_mcp_session

    app.state.submission_timestamps: dict[str, list[float]] = {}
    app.state.max_request_bytes = max_request_bytes
    app.state.max_submissions_per_minute = max_submissions_per_minute

    if enable_direct_coding is None:
        enable_direct_coding = os.getenv("WINDOWS_MCP_ENABLE_DIRECT_CODING_TOOLS", "1").strip().lower() in ("1", "true", "yes")
    app.state.enable_direct_coding = enable_direct_coding

    @app.middleware("http")
    async def validate_mcp_origin(request: Request, call_next):
        if request.url.path in {"/mcp", "/mcp/autonomous"}:
            origin = request.headers.get("origin")
            if origin and not _is_allowed_origin_or_referer(origin, os.getenv("MCP_OAUTH_EXTERNAL_ISSUER")):
                return _jsonrpc_auth_error_response(status_code=403, req_id=None, code=-32003, message="Origin is not allowed")
        return await call_next(request)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        from runtime.release_identity import get_release_identity
        rel_id = get_release_identity()
        coding_enabled = getattr(app.state, "enable_direct_coding", True)
        is_owner_full_control = bool(gw.policy and getattr(gw.policy, "unrestricted_workspace_access", False))
        exposed = list(CLOUD_SAFE_AUTONOMOUS_TOOLS) + (sorted(CODING_TOOL_NAMES) if coding_enabled else [])
        if is_owner_full_control:
            if coding_enabled:
                from runtime.coding_tools import OWNER_FILESYSTEM_TOOL_NAMES
                exposed.extend(sorted(OWNER_FILESYSTEM_TOOL_NAMES))
            exposed.extend([
                "agent_powershell_execute",
                "agent_desktop_screenshot",
                "agent_get_active_window",
                "agent_focus_window",
                "agent_keyboard_type",
                "agent_mouse_click",
                "agent_visual_verify",
                "agent_launch_app",
                "agent_list_windows",
                "agent_system_status",
                "agent_task_pause",
                "agent_task_resume",
                "agent_task_cancel",
                "agent_emergency_stop",
            ])
        return {
            "status": "ok",
            "service": "cloud-autonomous-loopback-adapter",
            "server": gw.server_name,
            "version": gw.server_version,
            "release_version": rel_id["release_version"],
            "git_sha": rel_id["source_commit"],
            "build_id": rel_id["build_id"],
            "zip_sha256": rel_id["zip_sha256"],
            "host": "127.0.0.1",
            "port": 8768,
            "surface": "cloud_autonomous",
            "strict_autonomous_tools_only": not coding_enabled,
            "exposed_tools": exposed,
            "require_autonomous_auth": app.state.require_autonomous_auth,
            "allow_loopback_tunnel_identity": app.state.allow_loopback_tunnel_identity,
        }

    # ------------------------------------------------------------------
    # RFC 8414 & MCP OAuth 2.1 Discovery and Token Management (H05/H06/H07/Sprint 5.5)
    # ------------------------------------------------------------------
    external_issuer_env = os.getenv("MCP_OAUTH_EXTERNAL_ISSUER", "").strip().rstrip("/")
    if not (external_issuer_env.startswith("https://") and not any(h in external_issuer_env for h in ("127.0.0.1", "localhost", "::1"))):
        external_issuer_env = ""
    default_res = os.getenv("MCP_OAUTH_RESOURCE_URI") or (f"{external_issuer_env}/mcp" if external_issuer_env else "http://127.0.0.1:8768/mcp")
    register_oauth_endpoints(
        app,
        issuer="windows-mcp-gateway-autonomous-adapter",
        default_resource_uri=default_res,
    )

    # ------------------------------------------------------------------
    # MCP Handlers (/mcp and /mcp/autonomous)
    # ------------------------------------------------------------------
    def authenticate(request: Request, req_id: Any = None) -> tuple[str, Response | None]:
        authorization = request.headers.get("authorization", "")
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() != "bearer" or not credential.strip():
            return "", _jsonrpc_auth_error_response(
                status_code=401, req_id=req_id, code=-32001,
                message="Bearer authentication is required",
                headers={"WWW-Authenticate": 'Bearer realm="mcp-autonomous", resource_metadata="/.well-known/oauth-protected-resource", scope="mcp:autonomous"'},
            )
        ok, identity, status, error = _authenticate_autonomous_caller(request, app, gw, require_auth=True)
        if not ok:
            return "", _jsonrpc_auth_error_response(status_code=status, req_id=req_id, code=-32001 if status == 401 else -32003, message=error)
        return identity, None

    def validate_session(
        request: Request,
        identity: str,
        req_id: Any = None,
        allow_session_recovery: bool = False,
    ) -> Response | None:
        prune_sessions()
        protocol = request.headers.get("mcp-protocol-version")
        if protocol and protocol not in SUPPORTED_PROTOCOL_VERSIONS:
            return _jsonrpc_auth_error_response(status_code=400, req_id=req_id, code=-32600, message="Unsupported MCP-Protocol-Version")
        session_id = request.headers.get("mcp-session-id", "").strip()
        if not session_id:
            return None
        if session_id in app.state.terminated_mcp_sessions:
            return _jsonrpc_auth_error_response(
                status_code=404,
                req_id=req_id,
                code=-32000,
                message="MCP session expired or unknown; initialize a new session without Mcp-Session-Id",
            )
        bound_identity = app.state.mcp_stream_sessions.get(session_id)
        if bound_identity is None:
            if (
                allow_session_recovery
                and request.method == "POST"
                and re.fullmatch(r"sess_mcp_[0-9a-f]{32,64}", session_id)
                and session_id not in app.state.terminated_mcp_sessions
            ):
                negotiated = protocol if (protocol and protocol in SUPPORTED_PROTOCOL_VERSIONS) else "2025-03-26"
                app.state.mcp_stream_sessions[session_id] = identity
                app.state.mcp_session_protocols[session_id] = negotiated
                app.state.mcp_session_last_seen[session_id] = time.monotonic()
                save_mcp_session(session_id, identity, negotiated, terminated=False)
                bound_identity = identity
            else:
                return _jsonrpc_auth_error_response(
                    status_code=404,
                    req_id=req_id,
                    code=-32000,
                    message="MCP session expired or unknown; initialize a new session without Mcp-Session-Id",
                )
        if bound_identity != identity:
            return _jsonrpc_auth_error_response(status_code=403, req_id=req_id, code=-32003, message="MCP session belongs to a different authenticated caller")
        if protocol and protocol != app.state.mcp_session_protocols.get(session_id):
            return _jsonrpc_auth_error_response(status_code=400, req_id=req_id, code=-32600, message="MCP-Protocol-Version does not match negotiated session version")
        app.state.mcp_session_last_seen[session_id] = time.monotonic()
        session_store.touch_session(session_id)
        return None

    def prune_sessions() -> None:
        cutoff = time.monotonic() - app.state.mcp_session_idle_seconds
        for session_id, seen_at in list(app.state.mcp_session_last_seen.items()):
            if seen_at < cutoff:
                app.state.terminated_mcp_sessions.add(session_id)
                session_store.mark_terminated(session_id)
                app.state.mcp_stream_sessions.pop(session_id, None)
                app.state.mcp_session_protocols.pop(session_id, None)
                app.state.mcp_session_last_seen.pop(session_id, None)

    def coding_caller_tier(request: Request) -> str:
        principal = getattr(request.state, "auth_principal", None)
        if principal is not None:
            return principal.tier
        token = request.headers.get("authorization", "").partition(" ")[2].strip()
        if token.startswith(("mcp_oat_", "mcp_ort_")):
            ok, claims, _ = _verify_oauth_token(
                token, app.state.oauth_signing_key, app.state.revoked_oauth_tokens,
                persistence=app.state.oauth_persistence, expected_owner_id=app.state.expected_owner_id,
            )
            scopes = str(claims.get("scope", "")).split() if ok and claims else []
            if "mcp:owner" in scopes or "mcp:all" in scopes:
                return "SYSTEM_ADMIN"
            return "WRITE" if "mcp:coding:write" in scopes else "READ"
        # Reached only after successful verification against owner-configured
        # shared Bearer token. No session/header identity can reach this path.
        return "WRITE"

    @app.get("/mcp")
    @app.get("/mcp/autonomous")
    async def mcp_get(request: Request) -> Response:
        if request.headers.get("mcp-session-id"):
            identity, auth_error = authenticate(request)
            if auth_error is not None:
                return auth_error
            session_error = validate_session(request, identity)
            if session_error is not None:
                return session_error
        return JSONResponse(
            status_code=405,
            headers={"Allow": "POST, DELETE"},
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
        identity, auth_error = authenticate(request)
        if auth_error is not None:
            return auth_error
        session_error = validate_session(request, identity)
        if session_error is not None:
            return session_error
        mcp_sess = request.headers.get("mcp-session-id", "").strip()
        if not mcp_sess:
            return _jsonrpc_auth_error_response(status_code=400, req_id=None, code=-32600, message="Mcp-Session-Id header is required for DELETE")
        if mcp_sess:
            app.state.terminated_mcp_sessions.add(mcp_sess)
            if session_store is not None:
                session_store.mark_terminated(mcp_sess)
            app.state.mcp_stream_sessions.pop(mcp_sess, None)
            app.state.mcp_session_protocols.pop(mcp_sess, None)
            app.state.mcp_session_last_seen.pop(mcp_sess, None)
        return JSONResponse(status_code=200, content={"ok": True, "message": "Session closed"})

    @app.post("/mcp")
    @app.post("/mcp/autonomous")
    async def mcp_autonomous_post(request: Request) -> Response:
        # Authenticate before consuming a potentially large request body.
        authenticated_identity, auth_error = authenticate(request)
        if auth_error is not None:
            return auth_error
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
        messages = payload if isinstance(payload, list) else [payload]
        for item in messages:
            if not isinstance(item.get("params", {}), dict):
                return _jsonrpc_auth_error_response(status_code=400, req_id=item.get("id"), code=-32602, message="params must be an object")
        protocol_header = request.headers.get("mcp-protocol-version")
        if protocol_header and protocol_header not in SUPPORTED_PROTOCOL_VERSIONS:
            return _jsonrpc_auth_error_response(status_code=400, req_id=req_id, code=-32600, message="Unsupported MCP-Protocol-Version")
        is_initialize = any(isinstance(item, dict) and item.get("method") == "initialize" for item in messages)
        if is_initialize and (len(messages) != 1 or "id" not in messages[0]):
            return _jsonrpc_auth_error_response(status_code=400, req_id=req_id, code=-32600, message="initialize must be a single JSON-RPC request")
        session_error = validate_session(request, authenticated_identity, req_id, allow_session_recovery=not is_initialize)
        if session_error is not None:
            return session_error
        effective_protocol = protocol_header or app.state.mcp_session_protocols.get(request.headers.get("mcp-session-id", "").strip(), "2025-03-26")
        if isinstance(payload, list) and effective_protocol in {"2025-06-18", "2025-11-25"}:
            return _jsonrpc_auth_error_response(status_code=400, req_id=None, code=-32600, message="This protocol version requires a single JSON-RPC message")

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

        # Never adopt a client-selected ID. Unknown IDs must return 404 so SDKs
        # can clear stale state and initialize again after an adapter restart.
        resp_headers: dict[str, str] = {}
        client_session = request.headers.get("mcp-session-id", "").strip()
        if is_initialize:
            while len(app.state.mcp_stream_sessions) >= app.state.max_mcp_sessions:
                oldest = min(app.state.mcp_session_last_seen, key=app.state.mcp_session_last_seen.get)
                app.state.terminated_mcp_sessions.add(oldest)
                session_store.mark_terminated(oldest)
                app.state.mcp_stream_sessions.pop(oldest, None)
                app.state.mcp_session_protocols.pop(oldest, None)
                app.state.mcp_session_last_seen.pop(oldest, None)
            new_session = "sess_mcp_" + secrets.token_hex(24)
            app.state.mcp_stream_sessions[new_session] = authenticated_identity
            app.state.mcp_session_last_seen[new_session] = time.monotonic()
            version = messages[0].get("params", {}).get("protocolVersion", "2024-11-05")
            negotiated_version = version if version in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[-1]
            app.state.mcp_session_protocols[new_session] = negotiated_version
            save_mcp_session(new_session, authenticated_identity, negotiated_version, terminated=False)
            resp_headers["Mcp-Session-Id"] = new_session
        elif client_session:
            negotiated_version = app.state.mcp_session_protocols.get(client_session)
            if protocol_header and protocol_header != negotiated_version:
                return _jsonrpc_auth_error_response(status_code=400, req_id=req_id, code=-32600, message="MCP-Protocol-Version does not match negotiated session version")
            resp_headers["Mcp-Session-Id"] = client_session

        def _sanitize_jsonrpc_payload(raw: Any) -> Any:
            if isinstance(raw, dict):
                raw.pop("_caller_id", None)
                if isinstance(raw.get("params"), dict):
                    raw["params"].pop("_caller_id", None)
            elif isinstance(raw, list):
                for elem in raw:
                    if isinstance(elem, dict):
                        elem.pop("_caller_id", None)
                        if isinstance(elem.get("params"), dict):
                            elem["params"].pop("_caller_id", None)
            return raw

        payload = _sanitize_jsonrpc_payload(payload)

        coding_enabled = getattr(app.state, "enable_direct_coding", True)
        principal = getattr(request.state, "auth_principal", None)
        if isinstance(payload, list):
            responses: list[dict[str, Any]] = []
            for item in payload:
                resp_item = await asyncio.to_thread(
                    gw.handle_jsonrpc_autonomous,
                    item,
                    caller_id=authenticated_identity,
                    include_coding_tools=coding_enabled,
                    caller_tier=coding_caller_tier(request),
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
            include_coding_tools=coding_enabled,
            caller_tier=coding_caller_tier(request),
            auth_principal=principal,
        )
        if resp_obj is None:
            return Response(status_code=202, headers=resp_headers)
        return JSONResponse(status_code=200, content=resp_obj, headers=resp_headers)

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dedicated Loopback Cloud Autonomous MCP Adapter (Port 8768)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host (default: 127.0.0.1 — strictly loopback only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("WINDOWS_MCP_AUTONOMOUS_ADAPTER_PORT", "8768")),
        help="Bind TCP port (default: 8768)",
    )
    parser.add_argument(
        "--allow-tunnel-identity",
        action="store_true",
        help="Deprecated compatibility option; Bearer auth is always required",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("MCP_AGENT_PROFILE", "read_only"),
        help="Security policy profile",
    )
    parser.add_argument(
        "--policy-path",
        default=None,
        help="Optional path to policy.json",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Path to SQLite persistence database for OAuth and revocations",
    )
    parser.add_argument(
        "--caller-token",
        default=None,
        help="Shared caller authentication token",
    )
    args = parser.parse_args(argv)

    # Strictly bind to loopback address (H03)
    validate_loopback_bind(args.host)

    app = create_cloud_autonomous_adapter_app(
        allow_loopback_tunnel_identity=args.allow_tunnel_identity,
        profile=args.profile,
        policy_path=args.policy_path,
        db_path=args.db_path,
        caller_auth_token=args.caller_token,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
