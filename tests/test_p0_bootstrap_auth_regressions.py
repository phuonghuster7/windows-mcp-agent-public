"""P0 regression tests: production OAuth redirect validation and owner auth boundaries."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
for part in (ROOT, ROOT / "mcp-gateway", ROOT / "backend", ROOT / "desktop-agent"):
    if str(part) not in sys.path:
        sys.path.insert(0, str(part))

from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app  # noqa: E402
from http_server import _is_valid_oauth_redirect_uri  # noqa: E402
from runtime.oauth_store import DurableOAuthStore  # noqa: E402


@pytest.mark.parametrize(
    "uri",
    [
        "http://127.0.0.1.evil.com/callback",
        "http://localhost.evil.com/callback",
        "http://localhost@evil.com/callback",
        "https://user:password@example.org/cb",
        "https://example.org/cb#frag",
        "https://example.org:99999/cb",
        "http://[::1].evil.invalid/cb",
        "http://127.0.0.1\\@evil.com/cb",
        "http://127.0.0.1:0/cb",
        "http://evil.example/cb",
        "https://exa mple.org/cb",
        "ftp://example.org/cb",
    ],
)
def test_redirect_uri_rejects_forged_authority(uri: str) -> None:
    assert _is_valid_oauth_redirect_uri(uri) is False


@pytest.mark.parametrize(
    "uri",
    [
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://example.org/oauth/callback?state=ok",
        "http://localhost:46876/callback",
        "http://127.0.0.1:49152/cb",
        "http://[::1]:49152/cb",
    ],
)
def test_redirect_uri_accepts_legitimate_callbacks(uri: str) -> None:
    assert _is_valid_oauth_redirect_uri(uri) is True


def test_runtime_oauth_store_does_not_accept_secret_hash(tmp_path: Path) -> None:
    store = DurableOAuthStore(db_path=tmp_path / "isolated-oauth.sqlite")
    secret = "synthetic_client_secret_for_negative_test_only"
    store.register_client("test-client", secret, "owner-test")
    stored_hash = hashlib.sha256(secret.encode()).hexdigest()
    assert store.verify_client_secret("test-client", secret)[0] is True
    assert store.verify_client_secret("test-client", stored_hash)[0] is False


def test_production_registration_and_loopback_denial(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MCP_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("WINDOWS_MCP_BACKEND_ENV_FILE", str(tmp_path / "absent.env"))
    app = create_cloud_autonomous_adapter_app(
        caller_auth_token="synthetic_caller_secret_for_test_only",
        profile="read_only",
        policy_path=ROOT / "config" / "policy.example.json",
        db_path=tmp_path / "production-oauth.sqlite",
        allow_loopback_tunnel_identity=True,
        enable_direct_coding=False,
    )
    client = TestClient(app)
    for redirect in (
        "http://127.0.0.1.evil.com/cb",
        "http://localhost.evil.com/cb",
        "https://user@example.org/cb",
        "https://example.org/cb#fragment",
    ):
        resp = client.post("/oauth/register", json={"redirect_uris": [redirect]})
        assert resp.status_code == 400, (redirect, resp.text)
        assert resp.json()["error"] == "invalid_redirect_uri"

    good = client.post(
        "/oauth/register",
        json={"client_name": "synthetic-fixture", "redirect_uris": ["http://127.0.0.1:8431/cb"]},
    )
    assert good.status_code == 201

    # Explicit compatibility flag must never grant read, owner, or any identity.
    denied = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert denied.status_code == 401
    assert app.state.allow_loopback_tunnel_identity is False
