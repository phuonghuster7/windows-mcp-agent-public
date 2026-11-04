#!/usr/bin/env python3
"""Read-only diagnostics for Windows MCP Autonomous Cloud connector.

Never reads auth tokens, modifies workspaces, or restarts processes.
Run on the Windows owner host; local health cannot prove ChatGPT Cloud reachability.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_ADAPTER = "http://127.0.0.1:8768/health"
DEFAULT_TUNNEL_NAME = "windows-mcp-autonomous"
DEFAULT_AUTONOMOUS_HEALTH_URL_FILE = (
    Path(__file__).resolve().parents[1] / "runtime" / "logs" / "windows-mcp-autonomous-health.url"
)


def loopback_url(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
        return u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1") and u.username is None and u.password is None
    except ValueError:
        return False


def http_probe(url: str, timeout: float = 3.0) -> dict[str, Any]:
    if not loopback_url(url):
        return {"ok": False, "error": "non_loopback_url_rejected"}
    try:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as resp:
            payload = resp.read(8192)
            parsed = json.loads(payload.decode("utf-8")) if payload else {}
            healthy = resp.status == 200 and isinstance(parsed, dict) and parsed.get("status") in ("ok", "healthy", "live")
            return {"ok": healthy, "http_status": resp.status, "service": parsed.get("service") if isinstance(parsed, dict) else None, "surface": parsed.get("surface") if isinstance(parsed, dict) else None}
    except (ValueError, OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": type(exc).__name__}


def read_watchdog(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        services = data.get("services", {})
        keep = ("autonomous_cloud_adapter", "tunnel", "autonomous_tunnel", "legacy_codex_tunnel", "mcp_bridge")
        return {
            "present": True,
            "last_check_at": data.get("last_check_at"),
            "overall_healthy": data.get("overall_healthy"),
            "services": {k: {"status": services.get(k, {}).get("status"), "healthy": services.get(k, {}).get("healthy"), "pid": services.get(k, {}).get("pid")} for k in keep},
        }
    except (OSError, ValueError, TypeError):
        return {"present": False}


def probe_profile_health_fallback(health_url_file: Path | None = None, timeout: float = 3.0) -> dict[str, Any] | None:
    target_file = health_url_file if health_url_file is not None else DEFAULT_AUTONOMOUS_HEALTH_URL_FILE
    if not target_file.is_file():
        return None
    try:
        raw_url = target_file.read_text(encoding="utf-8", errors="replace").strip()
        if not loopback_url(raw_url):
            return None
        base_url = raw_url.rstrip("/")

        # Probe /healthz
        req_hz = urllib.request.Request(f"{base_url}/healthz")
        with urllib.request.urlopen(req_hz, timeout=timeout) as resp_hz:
            body_hz = resp_hz.read(256).decode("utf-8", errors="replace").strip().lower()
            if resp_hz.status != 200 or body_hz != "live":
                return None

        # Probe /readyz
        req_rz = urllib.request.Request(f"{base_url}/readyz")
        with urllib.request.urlopen(req_rz, timeout=timeout) as resp_rz:
            body_rz = resp_rz.read(256).decode("utf-8", errors="replace").strip().lower()
            if resp_rz.status != 200 or body_rz != "ready":
                return None

        return {"available": True, "ok": True, "running": True, "healthy": True, "mode": "profile_daemon"}
    except (OSError, ValueError, urllib.error.URLError):
        return None


def tunnel_cli_status(
    exe: Path,
    name: str,
    timeout: float = 6.0,
    health_url_file: Path | None = None,
) -> dict[str, Any]:
    if not exe.is_file():
        fallback = probe_profile_health_fallback(health_url_file, timeout=min(3.0, timeout))
        if fallback is not None:
            return fallback
        return {"available": False, "reason": "tunnel_client_not_found"}
    try:
        cp = subprocess.run([str(exe), "runtimes", "status", name, "--json"], text=True, capture_output=True, timeout=timeout, check=False)
        if cp.returncode != 0:
            fallback = probe_profile_health_fallback(health_url_file, timeout=min(3.0, timeout))
            if fallback is not None:
                return fallback
            return {"available": True, "ok": False, "exit_code": cp.returncode}
        obj = json.loads(cp.stdout)
        # Never echo tool output: it may contain identifiers or local paths.
        running = obj.get("running", obj.get("status") == "running")
        healthy = obj.get("healthy")
        if not running or not healthy:
            fallback = probe_profile_health_fallback(health_url_file, timeout=min(3.0, timeout))
            if fallback is not None:
                return fallback
        return {"available": True, "ok": True, "running": running, "healthy": healthy}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        fallback = probe_profile_health_fallback(health_url_file, timeout=min(3.0, timeout))
        if fallback is not None:
            return fallback
        return {"available": True, "ok": False, "reason": "status_command_failed"}


def classify(adapter: dict[str, Any], watchdog: dict[str, Any], tunnel: dict[str, Any]) -> str:
    if not adapter.get("ok"):
        return "LOCAL_ADAPTER_NOT_HEALTHY"
    if tunnel.get("available") and (not tunnel.get("ok") or tunnel.get("running") is False or tunnel.get("healthy") is False):
        return "AUTONOMOUS_TUNNEL_NOT_HEALTHY"
    if watchdog.get("present") and watchdog.get("services", {}).get("autonomous_cloud_adapter", {}).get("healthy") is False:
        return "WATCHDOG_REPORTS_ADAPTER_UNHEALTHY"
    return "LOCAL_PATH_HEALTHY_CLOUD_SESSION_UNVERIFIED"


def _safe_home() -> Path:
    try:
        return Path.home()
    except RuntimeError:
        fallback = os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir()
        return Path(fallback)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--tunnel-client", type=Path, default=_safe_home() / ".codex-chatgpt-web" / "bin" / "tunnel-client.exe")
    p.add_argument("--json", action="store_true")
    ns = p.parse_args(argv)
    root = ns.project_root.resolve()
    adapter = http_probe(DEFAULT_ADAPTER)
    watchdog = read_watchdog(root / "runtime" / "logs" / "status.json")
    tunnel = tunnel_cli_status(
        ns.tunnel_client,
        DEFAULT_TUNNEL_NAME,
        health_url_file=root / "runtime" / "logs" / "windows-mcp-autonomous-health.url",
    )
    verdict = classify(adapter, watchdog, tunnel)
    report = {"read_only": True, "adapter": adapter, "watchdog": watchdog, "tunnel": tunnel, "verdict": verdict}
    if ns.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Windows Autonomous Connector: {verdict}")
        print(f"Local 8768 health: {'PASS' if adapter.get('ok') else 'FAIL'}")
        print(f"Tunnel CLI: {tunnel}")
        print(f"Watchdog last check: {watchdog.get('last_check_at', 'unknown')}")
        if verdict == "LOCAL_PATH_HEALTHY_CLOUD_SESSION_UNVERIFIED":
            print("Local health is NOT a ChatGPT tool-call test. If ChatGPT reports 'Session terminated', reconnect/refresh the ChatGPT plugin session; do not rotate tokens or change working tunnels blindly.")
        else:
            print("Investigate the named local component before changing the ChatGPT plugin; keep the READ and legacy Codex tunnels untouched.")
    return 0 if verdict == "LOCAL_PATH_HEALTHY_CLOUD_SESSION_UNVERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
