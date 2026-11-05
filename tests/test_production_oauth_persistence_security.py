"""Tests the actual production OAuth persistence and HTTP token exchange.

Unlike runtime.oauth_store.DurableOAuthStore, the class under test is the
implementation used by mcp-gateway/cloud_autonomous_adapter.py.
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
for folder in (ROOT, ROOT / "mcp-gateway", ROOT / "backend", ROOT / "desktop-agent"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app  # noqa: E402
from http_server import _SQLiteOAuthPersistence  # noqa: E402


def _production_app(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MCP_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("WINDOWS_MCP_BACKEND_ENV_FILE", str(tmp_path / "missing.env"))
    return create_cloud_autonomous_adapter_app(
        caller_auth_token="synthetic_shared_transport_secret_for_test_only",
        profile="read_only",
        policy_path=ROOT / "config" / "policy.example.json",
        db_path=tmp_path / "production.sqlite",
        enable_direct_coding=False,
    )


def test_production_token_endpoint_rejects_stored_hash_as_client_secret(tmp_path, monkeypatch):
    app = _production_app(tmp_path, monkeypatch)
    actual_store = app.state.oauth_persistence
    assert isinstance(actual_store, _SQLiteOAuthPersistence)
    original_secret = "synthetic_nonproduction_client_secret_123456"
    stored_hash = hashlib.sha256(original_secret.encode("utf-8")).hexdigest()
    actual_store.register_client(
        client_id="isolated-production-client",
        client_secret_hash=stored_hash,
        owner_id="local_owner",
        client_name="Production auth regression",
        redirect_uris=["http://127.0.0.1:48152/cb"],
    )
    with TestClient(app) as client:
        invalid = client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "isolated-production-client",
                "client_secret": stored_hash,
            },
        )
        assert invalid.status_code == 401, invalid.text
        assert invalid.json()["error"] == "invalid_client"

        valid = client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "isolated-production-client",
                "client_secret": original_secret,
            },
        )
        assert valid.status_code == 200, valid.text
        assert valid.json().get("access_token")


def test_production_revocation_is_durable_across_store_instances(tmp_path):
    path = tmp_path / "oauth_state.sqlite"
    first = _SQLiteOAuthPersistence(path)
    token_id = "synthetic_token_jti_durable_revocation"
    assert first.is_token_revoked(token_id) is False
    first.revoke_token(
        token_id,
        client_id="isolated-production-client",
        expires_at=time.time() + 3600,
        reason="test_revoke",
    )
    second = _SQLiteOAuthPersistence(path)
    assert second.is_token_revoked(token_id) is True
    assert token_id in second.load_active_revocations()


def test_production_authorization_code_is_one_time(tmp_path):
    store = _SQLiteOAuthPersistence(tmp_path / "auth_code.sqlite")
    code = "synthetic_auth_code_test_only"
    store.store_authorization_code(
        code=code,
        client_id="isolated-production-client",
        owner_id="local_owner",
        redirect_uri="http://127.0.0.1:48152/cb",
        scope="mcp:autonomous",
        resource="mcp-autonomous",
        code_challenge="synthetic_pkce_challenge",
        code_challenge_method="S256",
        ttl_seconds=300,
    )
    first = store.consume_authorization_code(code)
    second = store.consume_authorization_code(code)
    assert first is not None and first["used"] == 0
    assert second is not None and second["used"] == 1
