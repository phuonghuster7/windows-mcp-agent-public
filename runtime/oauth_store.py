"""Durable SQLite OAuth State Store for Windows MCP Agent (RFC 8414, RFC 7636, Finding H07).

Provides durable, multi-process SQLite persistence for:
1. Token Revocations (oauth_revocations): Survives process restarts and pruning on expiry.
2. Registered OAuth Clients (oauth_clients): Client metadata and hashed secrets.
3. OAuth 2.1 Authorization Codes (oauth_authorization_codes): Single-use codes with PKCE S256 verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("oauth_store")

DEFAULT_MAX_REVOCATION_RECORDS = 10000


def verify_pkce_s256(code_verifier: str, code_challenge: str) -> bool:
    """Verify RFC 7636 PKCE S256 code challenge against plain code_verifier.

    code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
    """
    if not code_verifier or not code_challenge:
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(computed, code_challenge.rstrip("="))


def _extract_jti_and_exp(token_or_jti: str) -> tuple[str | None, float | None]:
    """Extract jti and exp claims from signed OAuth token format (mcp_oat_... or mcp_ort_...)."""
    if not token_or_jti:
        return None, None
    for prefix in ("mcp_oat_", "mcp_ort_"):
        if token_or_jti.startswith(prefix):
            raw = token_or_jti[len(prefix) :]
            if "." in raw:
                p_b64 = raw.split(".", 1)[0]
                pad = len(p_b64) % 4
                padded = p_b64 + ("=" * (4 - pad) if pad else "")
                try:
                    payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
                    jti = payload.get("jti")
                    exp_val = payload.get("exp")
                    exp = float(exp_val) if exp_val is not None else None
                    return jti, exp
                except Exception:
                    pass
    return None, None


class DurableOAuthStore:
    """Thread-safe, transaction-isolated SQLite OAuth store with WAL mode.

    Survives OS process restarts, enforces bounded revocation tables,
    and handles RFC 7636 PKCE S256 authorization codes.
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        max_records: int = DEFAULT_MAX_REVOCATION_RECORDS,
    ) -> None:
        if db_path is None:
            env_db = os.getenv("WINDOWS_MCP_OAUTH_DB_PATH") or os.getenv("MCP_OAUTH_DB_PATH")
            state_root = os.getenv("MCP_STATE_ROOT")
            if env_db:
                db_path = Path(env_db)
            elif state_root:
                db_path = Path(state_root) / "oauth.db"
            else:
                db_path = Path(__file__).resolve().parent / "oauth.db"

        if str(db_path) == ":memory:":
            self._is_memory = True
            self.db_path_str = ":memory:"
            self.db_path = Path(":memory:")
        else:
            self._is_memory = False
            self.db_path = Path(db_path).resolve()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.db_path_str = str(self.db_path)

        self.max_records = max_records
        self._memory_conn: sqlite3.Connection | None = None
        if self._is_memory:
            # Keep a persistent connection for in-memory database across calls
            self._memory_conn = sqlite3.connect(":memory:", timeout=30.0)
            self._memory_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._is_memory and self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path_str, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS oauth_revocations (
                    token_id TEXT PRIMARY KEY,
                    client_id TEXT,
                    revoked_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    reason TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_oauth_revocations_expires_at ON oauth_revocations(expires_at);

                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_secret_hash TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    client_name TEXT,
                    redirect_uris TEXT,
                    grant_types TEXT,
                    allowed_scopes TEXT,
                    created_at REAL NOT NULL
                );

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
                );
                CREATE INDEX IF NOT EXISTS idx_oauth_codes_client_id ON oauth_authorization_codes(client_id);
                """
            )

    # -------------------------------------------------------------------------
    # Revocation Management (H07)
    # -------------------------------------------------------------------------
    def revoke_token(
        self,
        token_or_jti: str,
        client_id: str = "",
        expires_at: float | int | None = None,
        reason: str = "revoked",
    ) -> None:
        """Durable token revocation.

        Stores both raw token and extracted jti claim (if mcp_oat_ / mcp_ort_).
        Enforces bounded table size by pruning expired entries first, then oldest entries.
        """
        if not token_or_jti:
            return

        now = time.time()
        jti, extracted_exp = _extract_jti_and_exp(token_or_jti)
        if expires_at is None:
            expires_at = extracted_exp if extracted_exp is not None else (now + 86400 * 30)
        else:
            expires_at = float(expires_at)

        with self._get_connection() as conn:
            # 1. Prune expired entries
            conn.execute("DELETE FROM oauth_revocations WHERE expires_at < ?", (now,))

            # 2. Store raw token/jti
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_revocations (
                    token_id, client_id, revoked_at, expires_at, reason
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (token_or_jti, client_id, now, expires_at, reason),
            )

            # 3. Store extracted jti if present and distinct
            if jti and jti != token_or_jti:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO oauth_revocations (
                        token_id, client_id, revoked_at, expires_at, reason
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (jti, client_id, now, expires_at, reason),
                )

            # 4. Enforce bounded capacity
            cursor = conn.execute("SELECT COUNT(*) FROM oauth_revocations")
            total = cursor.fetchone()[0]
            if total > self.max_records:
                excess = total - self.max_records
                conn.execute(
                    f"""
                    DELETE FROM oauth_revocations
                    WHERE token_id IN (
                        SELECT token_id FROM oauth_revocations
                        ORDER BY revoked_at ASC
                        LIMIT {int(excess)}
                    )
                    """
                )

    def close(self) -> None:
        """Close persistent in-memory connection if active."""
        if self._memory_conn is not None:
            try:
                self._memory_conn.close()
            except Exception:
                pass
            self._memory_conn = None

    def is_revoked(self, token_or_jti: str) -> bool:
        """Check if a token or jti is in the active revocation list."""
        if not token_or_jti:
            return False

        now = time.time()
        jti, _ = _extract_jti_and_exp(token_or_jti)
        candidates = [token_or_jti]
        if jti and jti != token_or_jti:
            candidates.append(jti)

        placeholders = ",".join("?" for _ in candidates)
        with self._get_connection() as conn:
            cursor = conn.execute(
                f"""
                SELECT 1 FROM oauth_revocations
                WHERE token_id IN ({placeholders}) AND expires_at > ?
                LIMIT 1
                """,
                (*candidates, now),
            )
            return cursor.fetchone() is not None

    def load_active_revocations(self) -> set[str]:
        """Load all currently active (non-expired) revoked token IDs and JTIs."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT token_id FROM oauth_revocations WHERE expires_at > ?",
                (now,),
            )
            return {row[0] for row in cursor.fetchall()}

    def cleanup_expired(self) -> int:
        """Delete all expired revocation records and authorization codes. Returns total deleted records count."""
        now = time.time()
        with self._get_connection() as conn:
            cursor1 = conn.execute(
                "DELETE FROM oauth_revocations WHERE expires_at < ?",
                (now,),
            )
            count1 = cursor1.rowcount if cursor1.rowcount != -1 else 0
            cursor2 = conn.execute(
                "DELETE FROM oauth_authorization_codes WHERE expires_at < ?",
                (now,),
            )
            count2 = cursor2.rowcount if cursor2.rowcount != -1 else 0
            return count1 + count2

    # -------------------------------------------------------------------------
    # Client Registration & Lookup (H05/H06)
    # -------------------------------------------------------------------------
    def register_client(
        self,
        client_id: str,
        client_secret: str,
        owner_id: str,
        client_name: str = "",
        redirect_uris: list[str] | str = "",
        grant_types: list[str] | str = "",
        allowed_scopes: list[str] | str = "",
    ) -> dict[str, Any]:
        """Register or update an OAuth 2.1 client with hashed secret."""
        now = time.time()
        secret_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()
        red_str = json.dumps(redirect_uris) if isinstance(redirect_uris, list) else str(redirect_uris)
        grants_str = json.dumps(grant_types) if isinstance(grant_types, list) else str(grant_types)
        scopes_str = json.dumps(allowed_scopes) if isinstance(allowed_scopes, list) else str(allowed_scopes)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_clients (
                    client_id, client_secret_hash, owner_id, client_name,
                    redirect_uris, grant_types, allowed_scopes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (client_id, secret_hash, owner_id, client_name, red_str, grants_str, scopes_str, now),
            )

        return {
            "client_id": client_id,
            "owner_id": owner_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris if isinstance(redirect_uris, list) else [redirect_uris],
            "grant_types": grant_types if isinstance(grant_types, list) else [grant_types],
            "allowed_scopes": allowed_scopes if isinstance(allowed_scopes, list) else [allowed_scopes],
            "created_at": now,
        }

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        """Fetch client record by client_id."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            for k in ("redirect_uris", "grant_types", "allowed_scopes"):
                val = data.get(k)
                if isinstance(val, str) and (val.startswith("[") or val.startswith("{")):
                    try:
                        data[k] = json.loads(val)
                    except Exception:
                        pass
            return data

    def verify_client_secret(self, client_id: str, client_secret: str) -> tuple[bool, dict[str, Any] | None]:
        """Verify client_secret against stored SHA-256 hash."""
        client = self.get_client(client_id)
        if not client:
            return False, None
        candidate_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()
        stored_hash = client.get("client_secret_hash", "")
        if hmac.compare_digest(stored_hash, candidate_hash) or hmac.compare_digest(stored_hash, client_secret):
            return True, client
        return False, None

    # -------------------------------------------------------------------------
    # Authorization Code & PKCE S256 (H05)
    # -------------------------------------------------------------------------
    def create_authorization_code(
        self,
        client_id: str,
        owner_id: str,
        redirect_uri: str,
        scope: str,
        resource: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        state: str | None = "",
        ttl_seconds: int = 300,
    ) -> str:
        """Generate and store an RFC 7636 authorization code with PKCE parameters."""
        now = time.time()
        code = f"mcp_code_{secrets.token_urlsafe(32)}"
        expires_at = now + ttl_seconds
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO oauth_authorization_codes (
                    code, client_id, owner_id, redirect_uri, scope, resource,
                    code_challenge, code_challenge_method, state, created_at,
                    expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    code,
                    client_id,
                    owner_id,
                    redirect_uri,
                    scope,
                    resource,
                    code_challenge,
                    code_challenge_method,
                    state or "",
                    now,
                    expires_at,
                ),
            )
        return code

    def consume_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> tuple[bool, dict[str, Any] | None, str]:
        """Atomically validate and consume a single-use authorization code with PKCE verification."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM oauth_authorization_codes WHERE code = ?",
                (code,),
            )
            row = cursor.fetchone()
            if not row:
                return False, None, "Invalid authorization code"

            rec = dict(row)
            if rec.get("used", 0) != 0:
                return False, None, "Authorization code has already been used"

            if float(rec.get("expires_at", 0)) < time.time():
                return False, None, "Authorization code has expired"

            if rec.get("client_id") != client_id:
                return False, None, f"Client ID mismatch (expected {rec.get('client_id')}, got {client_id})"

            if rec.get("redirect_uri") != redirect_uri:
                return False, None, f"Redirect URI mismatch (expected {rec.get('redirect_uri')}, got {redirect_uri})"

            method = (rec.get("code_challenge_method") or "S256").upper()
            challenge = rec.get("code_challenge", "")
            if method == "S256":
                if not verify_pkce_s256(code_verifier, challenge):
                    return False, None, "Invalid PKCE code_verifier (S256 challenge mismatch)"
            elif method == "PLAIN":
                if not hmac.compare_digest(code_verifier, challenge):
                    return False, None, "Invalid PKCE code_verifier (plain challenge mismatch)"
            else:
                return False, None, f"Unsupported code_challenge_method: {method}"

            # Atomically mark as used
            conn.execute("UPDATE oauth_authorization_codes SET used = 1 WHERE code = ?", (code,))
            rec["used"] = 1
            return True, rec, ""
