"""Unit tests for read-only Cloud connector triage."""
import importlib.util
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "scripts" / "diagnose_autonomous_cloud.py"
spec = importlib.util.spec_from_file_location("cloud_diagnostics", FILE)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def test_blocks_remote_probes():
    for target in ("https://example.com/x", "http://8.8.8.8/", "file:///etc/passwd", "http://user:secret@127.0.0.1/"):
        assert not d.loopback_url(target)
        assert d.http_probe(target)["error"] == "non_loopback_url_rejected"
    assert d.loopback_url("http://127.0.0.1:8768/health")


def test_classifies_cloud_session_separately_from_local():
    health = {"ok": True}
    status = {"present": True, "services": {"autonomous_cloud_adapter": {"healthy": True}}}
    assert d.classify(health, status, {"available": True, "ok": True, "running": True, "healthy": True}) == "LOCAL_PATH_HEALTHY_CLOUD_SESSION_UNVERIFIED"
    assert d.classify({"ok": False}, status, {}) == "LOCAL_ADAPTER_NOT_HEALTHY"
    assert d.classify(health, status, {"available": True, "ok": True, "running": False}) == "AUTONOMOUS_TUNNEL_NOT_HEALTHY"


def test_missing_watchdog_safe(tmp_path):
    assert d.read_watchdog(tmp_path / "nonexistent.json") == {"present": False}


def test_watchdog_exposes_no_secrets(tmp_path):
    p = tmp_path / "status.json"
    p.write_text('{"last_check_at":"2026-10-27T09:00:00Z","services":{"autonomous_cloud_adapter":{"healthy":true,"pid":5,"token":"secret"}},"bearer":"secret"}')
    report = d.read_watchdog(p)
    assert report["services"]["autonomous_cloud_adapter"] == {"status": None, "healthy": True, "pid": 5}
    assert "secret" not in str(report)


def test_profile_health_fallback_success(tmp_path, monkeypatch):
    health_file = tmp_path / "windows-mcp-autonomous-health.url"
    health_file.write_text("http://127.0.0.1:9999\n", encoding="utf-8")

    class MockResp:
        def __init__(self, data: bytes):
            self.data = data
            self.status = 200

        def read(self, n=None):
            return self.data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    import urllib.request
    import urllib.error

    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith("/healthz"):
            return MockResp(b"live\n")
        if url.endswith("/readyz"):
            return MockResp(b"ready\n")
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    res = d.tunnel_cli_status(tmp_path / "fake-tunnel.exe", "windows-mcp-autonomous", health_url_file=health_file)
    assert res == {"available": True, "ok": True, "running": True, "healthy": True, "mode": "profile_daemon"}

