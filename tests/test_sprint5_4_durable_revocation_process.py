"""Real Windows Multi-Process End-to-End Test Suite for Finding H07 (Sprint 5.4).

Covers:
- Test 01: Unit & Bounded Cleanup of DurableOAuthStore (durability, WAL, pruning, bounded limit, PKCE S256).
- Test 02: Mandatory 8-Step Real Windows OS Process Restart E2E (Section 4 / Finding H07).
  * Launches genuine Windows OS subprocess (sys.executable mcp-gateway/cloud_autonomous_adapter.py).
  * Step 1: Issue valid OAuth token.
  * Step 2: Authenticate successfully (/mcp tools/list -> 200).
  * Step 3: Revoke token (/oauth/revoke -> 200).
  * Step 4: Verify immediate access denial (/mcp -> 403).
  * Step 5: Terminate process 1, record proc1.pid, verify proc1 is dead.
  * Step 6: Start fresh process 2 on same port & DB, wait for /health, verify proc2.pid != proc1.pid.
  * Steps 7 & 8: Reuse revoked token against process 2 -> confirms access REMAINS DENIED (403).
- Test 03: Reject Expired & Wrong Resource/Audience Tokens After Process Restart.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any, Generator

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
for _p in (str(PROJECT_ROOT), str(GATEWAY_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from http_server import _issue_oauth_token  # noqa: E402
from runtime.oauth_store import DurableOAuthStore, verify_pkce_s256  # noqa: E402  # gitleaks:allow  (synthetic regression fixture; reviewed)
from runtime.task_store import is_pid_alive  # noqa: E402

logger = logging.getLogger("test_sprint5_4")

TEST_CALLER_SECRET = "test-caller-secret-sprint5-4-998877"


def get_free_port() -> int:
    """Acquire a free local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_health(port: int, timeout: float = 25.0) -> bool:
    """Poll GET /health until HTTP 200 or timeout."""
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/health"
    with httpx.Client(timeout=1.0) as client:
        while time.time() < deadline:
            try:
                res = client.get(url)
                if res.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.2)
    return False


def start_adapter_process(port: int, db_path: Path, secret: str) -> subprocess.Popen:
    """Launch a real Windows OS subprocess running cloud_autonomous_adapter.py."""
    env = os.environ.copy()
    current_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{PROJECT_ROOT}{os.pathsep}{current_pp}" if current_pp else str(PROJECT_ROOT)
    env["WINDOWS_MCP_OAUTH_DB_PATH"] = str(db_path)
    env["WINDOWS_MCP_GATEWAY_TOKEN"] = secret
    env["MCP_AGENT_PROFILE"] = "read_only"
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "mcp-gateway" / "cloud_autonomous_adapter.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]

    # If --db-path / --caller-token CLI arguments are supported by cloud_autonomous_adapter, add them
    try:
        with open(PROJECT_ROOT / "mcp-gateway" / "cloud_autonomous_adapter.py", encoding="utf-8") as f:
            adapter_src = f.read()
        if "--db-path" in adapter_src:
            cmd.extend(["--db-path", str(db_path)])
        if "--caller-token" in adapter_src:
            cmd.extend(["--caller-token", secret])
    except Exception:
        pass

    proc = subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc


def terminate_process_tree(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    """Safely terminate a subprocess on Windows."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)


# =============================================================================
# Test 01: Unit & Bounded Cleanup of DurableOAuthStore
# =============================================================================
class Test01_DurableOAuthStoreUnit:
    """Verify DurableOAuthStore durability, pruning, bounded limits, and PKCE S256."""

    def test_01_durability_across_separate_instances(self, tmp_path: Path) -> None:
        """Revocations persisted in SQLite WAL survive across separate DurableOAuthStore instances."""
        db_path = tmp_path / "durability_test.db"

        # 1. Store 1 writes revocations
        store1 = DurableOAuthStore(db_path)
        raw_token = "raw_opaque_revoked_token_12345"
        store1.revoke_token(raw_token, client_id="client_1", reason="explicit_user_logout")

        # Also mint and revoke a signed token with extracted jti
        jti_nonce = "jti_cross_instance_test_999"
        p_data = {"sub": "client_1", "jti": jti_nonce, "exp": int(time.time() + 7200)}
        p_b64 = base64.urlsafe_b64encode(json.dumps(p_data).encode("utf-8")).decode("ascii").rstrip("=")
        signed_token = f"mcp_oat_{p_b64}.synthetic_sig_xyz"
        store1.revoke_token(signed_token, client_id="client_1", reason="compromised_key")

        # 2. Store 2 opens the same DB file afresh
        store2 = DurableOAuthStore(db_path)
        assert store2.is_revoked(raw_token) is True
        assert store2.is_revoked(signed_token) is True
        assert store2.is_revoked(jti_nonce) is True

        active = store2.load_active_revocations()
        assert raw_token in active
        assert signed_token in active
        assert jti_nonce in active

    def test_02_expiration_based_cleanup(self, tmp_path: Path) -> None:
        """Expired revocation records and auth codes are pruned automatically on cleanup."""
        db_path = tmp_path / "expiry_test.db"
        store = DurableOAuthStore(db_path)

        now = time.time()
        # Active token (exp in future)
        store.revoke_token("active_tok_1", client_id="c1", expires_at=now + 3600, reason="fresh")

        # Expired revocation record (directly inserted or expired)
        with store._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO oauth_revocations VALUES (?, ?, ?, ?, ?)",
                ("expired_tok_1", "c1", now - 200, now - 100, "old"),
            )

        # is_revoked should fail-open for expired entry (token has expired anyway, no need to block)
        assert store.is_revoked("expired_tok_1") is False
        assert store.is_revoked("active_tok_1") is True

        # Also insert an expired authorization code
        store.create_authorization_code(
            client_id="c1",
            owner_id="owner1",
            redirect_uri="https://client.example/cb",
            scope="mcp:autonomous",
            resource="mcp-autonomous",
            code_challenge="dummy_challenge",
            ttl_seconds=-50,  # expired
        )

        cleaned_count = store.cleanup_expired()
        assert cleaned_count >= 1

        active = store.load_active_revocations()
        assert "active_tok_1" in active
        assert "expired_tok_1" not in active

    def test_03_bounded_capacity_limit(self, tmp_path: Path) -> None:
        """Verify bounded table capacity limits table growth to max_records, evicting oldest."""
        db_path = tmp_path / "bounded_test.db"
        max_limit = 5
        store = DurableOAuthStore(db_path, max_records=max_limit)

        now = time.time()
        # Insert 12 revocations
        for i in range(1, 13):
            store.revoke_token(
                f"bounded_token_{i:02d}",
                client_id="c_test",
                expires_at=now + 5000 + i,
                reason=f"rev_{i}",
            )
            time.sleep(0.005)

        with store._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM oauth_revocations")
            count = cursor.fetchone()[0]

        assert count <= max_limit, f"Expected <= {max_limit} revocations, found {count}"
        # Newest tokens (e.g. 11, 12) must be present, oldest (01, 02) must have been evicted
        assert store.is_revoked("bounded_token_12") is True
        assert store.is_revoked("bounded_token_11") is True
        assert store.is_revoked("bounded_token_01") is False

    def test_04_pkce_s256_verification_and_single_use_auth_codes(self, tmp_path: Path) -> None:
        """RFC 7636 PKCE S256 verification and single-use authorization code enforcement."""
        db_path = tmp_path / "pkce_test.db"
        store = DurableOAuthStore(db_path)

        # RFC 7636 Appendix B test vector
        code_verifier = "dBjftJeZ4CVP-mkDnmwuWQnxnh69mqhl-5wx31a-6V1"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        # 1. verify_pkce_s256 directly
        assert verify_pkce_s256(code_verifier, code_challenge) is True
        assert verify_pkce_s256("wrong_verifier_string_12345", code_challenge) is False

        # 2. Issue authorization code with S256 challenge
        code = store.create_authorization_code(
            client_id="pkce_client",
            owner_id="owner_admin",
            redirect_uri="https://myapp.local/callback",
            scope="mcp:autonomous",
            resource="mcp-autonomous",
            code_challenge=code_challenge,
            code_challenge_method="S256",
            state="state_xyz",
        )
        assert code.startswith("mcp_code_")

        # 3. Invalid PKCE verifier -> rejected
        ok_bad_pkce, _, err_bad_pkce = store.consume_authorization_code(
            code=code,
            client_id="pkce_client",
            redirect_uri="https://myapp.local/callback",
            code_verifier="wrong_verifier_abcdef",
        )
        assert ok_bad_pkce is False
        assert "Invalid PKCE code_verifier" in err_bad_pkce

        # 4. Valid verifier -> successfully consumed
        ok_valid, rec, err_valid = store.consume_authorization_code(
            code=code,
            client_id="pkce_client",
            redirect_uri="https://myapp.local/callback",
            code_verifier=code_verifier,
        )
        assert ok_valid is True, f"Failed to consume auth code: {err_valid}"
        assert rec is not None
        assert rec["client_id"] == "pkce_client"
        assert rec["used"] == 1

        # 5. Single-use enforcement: re-using the code fails immediately
        ok_reuse, _, err_reuse = store.consume_authorization_code(
            code=code,
            client_id="pkce_client",
            redirect_uri="https://myapp.local/callback",
            code_verifier=code_verifier,
        )
        assert ok_reuse is False
        assert "already been used" in err_reuse

    def test_05_client_registration_and_secret_hashing(self, tmp_path: Path) -> None:
        """Register client stores SHA-256 hash (never plaintext) and verifies correctly."""
        db_path = tmp_path / "clients_test.db"
        store = DurableOAuthStore(db_path)

        secret = "super_confidential_secret_value_888"
        cli = store.register_client(
            client_id="client_hash_check",
            client_secret=secret,
            owner_id="user_admin",
            client_name="Audited App",
            redirect_uris=["https://client.local/cb"],
            grant_types=["authorization_code", "client_credentials"],
            allowed_scopes=["mcp:autonomous"],
        )
        assert cli["client_id"] == "client_hash_check"

        # Verify plaintext secret is NOT stored in raw table
        with store._get_connection() as conn:
            cursor = conn.execute("SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?", ("client_hash_check",))
            stored_hash = cursor.fetchone()[0]

        expected_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        assert stored_hash == expected_hash
        assert stored_hash != secret

        # Test verify_client_secret
        ok_verify, verified_cli = store.verify_client_secret("client_hash_check", secret)
        assert ok_verify is True
        assert verified_cli["client_id"] == "client_hash_check"

        ok_bad, _ = store.verify_client_secret("client_hash_check", "wrong_secret")
        assert ok_bad is False


# =============================================================================
# Test 02: Mandatory 8-Step Real Windows OS Process Restart E2E (Section 4 / H07)
# =============================================================================
class Test02_RealWindowsProcessRestartE2E:
    """Mandatory Real OS Subprocess Restart Test Suite (Finding H07).

    Validates that token revocations persist across distinct Windows OS processes
    sharing the same durable SQLite store.
    """

    def test_06_mandatory_8_step_process_restart_e2e(self, tmp_path: Path) -> None:
        """Execute the exact 8-step lifecycle across separate Windows OS adapter processes."""
        port = get_free_port()
        db_path = tmp_path / "durable_oauth_e2e.db"
        secret = TEST_CALLER_SECRET

        list_rpc = {
            "jsonrpc": "2.0",
            "id": "e2e-list-tools",
            "method": "tools/list",
            "params": {},
        }

        proc1: subprocess.Popen | None = None
        proc2: subprocess.Popen | None = None

        try:
            # -------------------------------------------------------------
            # Startup: Launch Process 1 (proc1)
            # -------------------------------------------------------------
            print(f"\n[E2E-H07] Binding adapter on port {port} with SQLite DB: {db_path.name}")
            proc1 = start_adapter_process(port=port, db_path=db_path, secret=secret)
            pid1 = proc1.pid
            print(f"[E2E-H07] Step 0: Process 1 launched with PID={pid1}")
            assert is_pid_alive(pid1), f"Process 1 (PID {pid1}) failed to start"

            healthy1 = wait_for_health(port=port, timeout=25.0)
            if not healthy1:
                stdout1, stderr1 = proc1.communicate(timeout=2.0)
                pytest.fail(f"Process 1 failed healthcheck. Stdout: {stdout1}\nStderr: {stderr1}")
            print(f"[E2E-H07] Step 0: Process 1 (PID={pid1}) healthy at http://127.0.0.1:{port}/health -> HTTP 200")

            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10.0) as client:
                # ---------------------------------------------------------
                # Step 1: Issue valid OAuth credential via POST /oauth/token
                # ---------------------------------------------------------
                mint_res = client.post(
                    "/oauth/token",
                    json={"client_id": "e2e_restart_client", "client_secret": secret},
                )
                assert mint_res.status_code == 200, f"Step 1 failed: {mint_res.text}"
                mint_data = mint_res.json()
                token = mint_data["access_token"]
                assert token.startswith("mcp_oat_"), f"Malformed token: {token}"
                print(f"[E2E-H07] Step 1: POST /oauth/token -> HTTP {mint_res.status_code} (issued access_token: [REDACTED_OAUTH_TOKEN])")

                # ---------------------------------------------------------
                # Step 2: Authenticate successfully against POST /mcp (200)
                # ---------------------------------------------------------
                mcp_ok = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {token}"},
                    json=list_rpc,
                )
                assert mcp_ok.status_code == 200, f"Step 2 failed: {mcp_ok.text}"
                assert "result" in mcp_ok.json()
                assert "tools" in mcp_ok.json()["result"]
                tool_count = len(mcp_ok.json()["result"]["tools"])
                print(f"[E2E-H07] Step 2: POST /mcp (tools/list) -> HTTP {mcp_ok.status_code} OK ({tool_count} autonomous tools)")

                # ---------------------------------------------------------
                # Step 3: Revoke credential via POST /oauth/revoke (200)
                # ---------------------------------------------------------
                rev_res = client.post(
                    "/oauth/revoke",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"token": token},
                )
                assert rev_res.status_code == 200, f"Step 3 failed: {rev_res.text}"
                rev_json = rev_res.json()
                assert rev_json.get("status") == "revoked" or rev_json.get("ok") is True
                print(f"[E2E-H07] Step 3: POST /oauth/revoke -> HTTP {rev_res.status_code} {rev_json}")

                # ---------------------------------------------------------
                # Step 4: Verify access is immediately denied (403)
                # ---------------------------------------------------------
                mcp_denied = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {token}"},
                    json=list_rpc,
                )
                assert mcp_denied.status_code == 403, (
                    f"Step 4 failed: expected 403 Forbidden immediately after revocation, got {mcp_denied.status_code}"
                )
                print(f"[E2E-H07] Step 4: POST /mcp with revoked token -> HTTP {mcp_denied.status_code} (access immediately denied)")

            # -------------------------------------------------------------
            # Step 5: Terminate process 1, record pid1, verify pid1 is dead
            # -------------------------------------------------------------
            terminate_process_tree(proc1, timeout=10.0)
            time.sleep(0.5)
            assert not is_pid_alive(pid1), f"Step 5 failed: Process 1 (PID {pid1}) is still alive!"
            print(f"[E2E-H07] Step 5: Process 1 (PID={pid1}) terminated cleanly; verified dead: {not is_pid_alive(pid1)}")

            # -------------------------------------------------------------
            # Step 6: Start fresh process 2 (proc2) on same port & DB
            # -------------------------------------------------------------
            proc2 = start_adapter_process(port=port, db_path=db_path, secret=secret)
            pid2 = proc2.pid
            assert pid2 != pid1, f"Step 6 failed: Process 2 PID ({pid2}) must differ from Process 1 PID ({pid1})"
            assert is_pid_alive(pid2), f"Step 6 failed: Process 2 (PID {pid2}) failed to start"

            healthy2 = wait_for_health(port=port, timeout=25.0)
            if not healthy2:
                stdout2, stderr2 = proc2.communicate(timeout=2.0)
                pytest.fail(f"Process 2 failed healthcheck. Stdout: {stdout2}\nStderr: {stderr2}")
            print(f"[E2E-H07] Step 6: Process 2 started with fresh PID={pid2} (!= {pid1}); health verified at http://127.0.0.1:{port}/health -> HTTP 200")

            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10.0) as client:
                # ---------------------------------------------------------
                # Step 7 & 8: Reuse revoked credential against proc2 -> HTTP 403!
                # ---------------------------------------------------------
                mcp_reuse = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {token}"},
                    json=list_rpc,
                )
                assert mcp_reuse.status_code == 403, (
                    f"Step 7/8 VULNERABILITY DETECTED: Revoked token was accepted by restarted process! "
                    f"Status: {mcp_reuse.status_code}, Body: {mcp_reuse.text}"
                )
                err_msg = mcp_reuse.json().get("error", {}).get("message", "").lower()
                assert "revoked" in err_msg or "forbidden" in err_msg or "invalid" in err_msg
                print(f"[E2E-H07] Step 7 & 8: Reused revoked token against Process 2 (PID={pid2}) -> HTTP {mcp_reuse.status_code} (access REMAINS DENIED durably)")

                # Verify newly minted token on proc2 works normally
                new_mint = client.post(
                    "/oauth/token",
                    json={"client_id": "e2e_restart_client_fresh", "client_secret": secret},
                )
                assert new_mint.status_code == 200
                fresh_tok = new_mint.json()["access_token"]
                mcp_fresh = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {fresh_tok}"},
                    json=list_rpc,
                )
                assert mcp_fresh.status_code == 200
                print(f"[E2E-H07] Step 9 (Bonus): Freshly minted token on Process 2 -> HTTP {mcp_fresh.status_code} OK")

        finally:
            if proc1 is not None:
                terminate_process_tree(proc1)
            if proc2 is not None:
                terminate_process_tree(proc2)


# =============================================================================
# Test 03: Reject Expired & Wrong Resource/Audience Tokens After Process Restart
# =============================================================================
class Test03_ExpiredAndWrongResourceTokensAfterRestart:
    """Verify restarted process strictly enforces expiration and resource/audience binding."""

    def test_07_reject_expired_and_wrong_resource_tokens(self, tmp_path: Path) -> None:
        """Process 2 rejects expired tokens and wrong-resource tokens, but allows fresh valid tokens."""
        port = get_free_port()
        db_path = tmp_path / "exp_res_oauth.db"
        secret = TEST_CALLER_SECRET

        proc: subprocess.Popen | None = None
        try:
            proc = start_adapter_process(port=port, db_path=db_path, secret=secret)
            assert wait_for_health(port=port, timeout=25.0)

            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10.0) as client:
                list_rpc = {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}}
                signing_secret = (db_path.parent / "secrets" / "oauth_signing.key").read_text(encoding="utf-8").strip()

                # 1. Expired token (exp in past) -> 403
                expired_info = _issue_oauth_token("test_client", signing_secret, ttl_seconds=-60)
                expired_tok = expired_info["access_token"]

                res_exp = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {expired_tok}"},
                    json=list_rpc,
                )
                assert res_exp.status_code == 403, f"Expected 403 for expired token, got {res_exp.status_code}"
                assert "expired" in res_exp.text.lower() or "forbidden" in res_exp.text.lower()

                # 2. Token minted for wrong resource/audience -> 403
                now = time.time()
                wrong_payload = {
                    "sub": "test_client",
                    "client_id": "test_client",
                    "resource": "unauthorized_foreign_resource",
                    "aud": "https://foreign-service.internal",
                    "scope": "foreign:scope",
                    "iat": int(now),
                    "exp": int(now + 3600),
                    "jti": secrets.token_hex(16),
                }
                p_json = json.dumps(wrong_payload, separators=(",", ":"), sort_keys=True)
                p_b64 = base64.urlsafe_b64encode(p_json.encode("utf-8")).decode("ascii").rstrip("=")
                sig = hmac.new(signing_secret.encode("utf-8"), p_b64.encode("utf-8"), hashlib.sha256).hexdigest()
                wrong_res_tok = f"mcp_oat_{p_b64}.{sig}"

                res_wrong = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {wrong_res_tok}"},
                    json=list_rpc,
                )
                assert res_wrong.status_code == 403, (
                    f"Expected 403 for wrong resource/audience token, got {res_wrong.status_code}"
                )

                # 3. Valid token issued for autonomous surface -> 200
                valid_res = client.post(
                    "/oauth/token",
                    json={"client_id": "test_client", "client_secret": secret},
                )
                assert valid_res.status_code == 200
                valid_tok = valid_res.json()["access_token"]

                res_ok = client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {valid_tok}"},
                    json=list_rpc,
                )
                assert res_ok.status_code == 200
                assert "result" in res_ok.json()
        finally:
            if proc is not None:
                terminate_process_tree(proc)
