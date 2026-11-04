"""Exercise the real authenticated direct coding MCP endpoint; never mocks a tool.

Only a fresh subdirectory of the existing trusted benchmark is modified. This is
client-driven acceptance, not evidence of an LLM provider or Cloud reasoning run.
No credentials, MCP session IDs, or request authorization headers enter reports.
Run with Python 3.12 and no third-party dependencies.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_ROOT = PROJECT_ROOT / "benchmarks" / "codex_like_eval"
CODING = {
    "agent_workspace_list", "agent_read_file", "agent_write_file",
    "agent_apply_patch", "agent_run_command", "agent_run_tests",
    "agent_git_status", "agent_git_diff",
}


def validate_endpoint(endpoint: str) -> str:
    """Never send a locally stored credential outside the dedicated adapter."""
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 8768
            or parsed.path not in ("/mcp", "/mcp/autonomous") or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError("Acceptance endpoint must be the dedicated http://127.0.0.1:8768/mcp adapter")
    return endpoint


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib can forward Authorization through a redirect; reject all 3xx.
        return None


def _safe_home() -> Path:
    try:
        return Path.home()
    except RuntimeError:
        fallback = os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir()
        return Path(fallback)


def configured_token() -> str:
    """Use the existing configured credential without printing or changing it."""
    keys = ("WINDOWS_MCP_GATEWAY_TOKEN", "COMPUTER_API_TOKEN", "MCP_AUTH_TOKEN", "MCP_AGENT_APPROVAL_TOKEN")
    for key in keys:
        if os.getenv(key, "").strip():
            return os.environ[key].strip()
    default = _safe_home() / ".gemini" / "antigravity-ide" / "scratch" / "computer-mcp-server" / ".env"
    for candidate in (default, PROJECT_ROOT / ".env"):
        try:
            for line in candidate.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip() in keys[:3] and value.strip().strip("\"'"):
                    return value.strip().strip("\"'")
        except OSError:
            pass
    try:
        match = re.search(r"Authorization:\s*[\"']?Bearer\s+([A-Za-z0-9_.-]+)",
                          (PROJECT_ROOT / "config/tunnel-autonomous.yaml").read_text(encoding="utf-8"))
        if match and not match.group(1).startswith("env"):
            return match.group(1)
    except OSError:
        pass
    raise RuntimeError("Existing caller credential is unavailable; no credential was created")


class Client:
    def __init__(self, endpoint: str, token: str):
        self.endpoint, self.token, self.session = validate_endpoint(endpoint), token, ""
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.counter = 0
        self.records: list[dict] = []

    def request(self, method: str, params=None, *, auth=True, session=True,
                headers=None, http_method="POST") -> tuple[int, dict]:
        self.counter += 1
        hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-03-26"}
        if auth:
            hdr["Authorization"] = "Bearer " + self.token
        if session and self.session:
            hdr["Mcp-Session-Id"] = self.session
        hdr.update(headers or {})
        payload = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params or {}}
        req = urllib.request.Request(self.endpoint, json.dumps(payload).encode(), hdr, method=http_method)
        started = time.perf_counter()
        try:
            response = self.opener.open(req, timeout=145)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            status, raw = response.status, response.read().decode("utf-8", errors="replace").strip()
            new_session = response.headers.get("Mcp-Session-Id")
            if new_session and auth and method == "initialize":
                self.session = new_session
        if raw.startswith("{"):
            data = json.loads(raw)
        else:
            messages = [json.loads(line[5:].strip()) for line in raw.splitlines() if line.startswith("data:")]
            data = messages[-1] if messages else {"raw_body": raw[:1000]}
        # Response objects contain no authorization headers; redact credential defensively.
        serialized = json.dumps(data).replace(self.token, "[REDACTED]")
        if self.session:
            serialized = serialized.replace(self.session, "[SESSION_REDACTED]")
        safe = json.loads(serialized)
        self.records.append({"method": method, "tool": (params or {}).get("name"), "http_status": status,
                             "latency_ms": round((time.perf_counter() - started) * 1000, 2), "response": safe})
        return status, data

    def initialize(self):
        status, data = self.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "direct-coding-real-endpoint-acceptance", "version": "1.0"}}, session=False)
        assert status == 200 and data.get("result", {}).get("protocolVersion") == "2025-03-26", data
        assert self.session, "Server did not issue an MCP session"

    def call(self, name: str, args: dict, *, rejected=False) -> dict:
        status, data = self.request("tools/call", {"name": name, "arguments": args})
        result = data.get("result", {})
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            text = "\n".join(item.get("text", "") for item in result.get("content", []) if item.get("type") == "text")
            try:
                structured = json.loads(text)
            except (ValueError, TypeError):
                structured = {"text": text}
        failed = status >= 400 or "error" in data or result.get("isError") is True or structured.get("ok") is False
        assert bool(failed) == rejected, {"tool": name, "status": status, "response": data}
        return structured


def run(endpoint: str, report_path: Path, *, preflight=False) -> int:
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "endpoint": endpoint,
              "mode": "real HTTP client-driven acceptance", "llm_execution_claimed": False,
              "cloud_multi_round_status": "NOT_TESTED", "checks": {}}
    client = None
    try:
        validate_endpoint(endpoint)
        client = Client(endpoint, configured_token())
        # Verify unauthenticated and forged credentials cannot list tools.
        status, _ = client.request("tools/list", auth=False, session=False)
        assert status == 401, f"Unauthenticated request returned {status}"
        status, _ = client.request("tools/list", auth=False, session=False,
                                   headers={"Authorization": "Bearer invalid-acceptance-credential"})
        assert status == 403, f"Invalid bearer returned {status}"
        report["checks"]["authentication"] = "PASS"
        client.initialize()
        status, data = client.request("tools/list")
        assert status == 200
        catalog = data.get("result", {}).get("tools", [])
        names = {item["name"] for item in catalog}
        report["catalog"] = sorted(names)
        report["checks"]["initialize_and_session"] = "PASS"
        assert CODING <= names, f"Direct coding catalog missing {sorted(CODING - names)}"
        assert len(names) == 14, f"Unexpected tool count {len(names)}"
        report["checks"]["catalog_14"] = "PASS"
        if preflight:
            report["status"] = "PREFLIGHT_PASS"
            return 0
        workspace_list = client.call("agent_workspace_list", {})
        approved = {Path(item["workspace_root"]).resolve() for item in workspace_list["workspaces"]}
        assert TRUSTED_ROOT.resolve() in approved, "Existing trusted benchmark unavailable"
        workspace = TRUSTED_ROOT / ("direct_coding_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6])
        workspace.mkdir()
        report["workspace"] = str(workspace)
        root_args = {"workspace_root": str(workspace)}
        # Setup is separate from the MCP actions; never commit, modify other repos, or install packages.
        git = Path(r"C:\Program Files\Git\cmd\git.exe")
        subprocess.run([str(git), "init", "--quiet", str(workspace)], check=True, capture_output=True)

        def write(path, content):
            result = client.call("agent_write_file", {**root_args, "path": path, "content": content,
                                                       "expected_sha256": "missing"})
            assert result["sha256"] == hashlib.sha256(content.encode("utf-8")).hexdigest()
            actual = client.call("agent_read_file", {**root_args, "path": path})
            assert actual["content"] == content
            assert (workspace / path).read_bytes() == content.encode("utf-8"), "Host byte equality mismatch"
            return result

        def patch(path, old, new):
            before = client.call("agent_read_file", {**root_args, "path": path})
            result = client.call("agent_apply_patch", {**root_args, "path": path, "old_text": old,
                                    "new_text": new, "expected_sha256": before["sha256"]})
            assert result.get("backup_id"), "No backup recorded"
            after = client.call("agent_read_file", {**root_args, "path": path})
            assert after["content"] == before["content"].replace(old, new, 1)
            return after

        write("byte_exact.txt", "CRLF\r\nUnicode: café Ω 雪\nLiteral: $value `tick` \\path\n")
        report["checks"]["byte_exact_write_read"] = "PASS"
        write("stock.py", "def pick_batches(available, requested):\n    return min(available, requested)\n")
        write("quote.py", "from stock import pick_batches\n\ndef quote(available, requested, unit_cents):\n    units = pick_batches(available, requested)\n    return {'units': units, 'total_cents': units * unit_cents}\n")
        write("test_quote.py", "from quote import quote\n\ndef test_caps_stock():\n    assert quote(3, 9, 125) == {'units': 3, 'total_cents': 375}\n\ndef test_no_negative_stock():\n    assert quote(-2, 4, 90) == {'units': 0, 'total_cents': 0}\n\ndef test_ceil_bulk_discount():\n    assert quote(10, 5, 101) == {'units': 5, 'total_cents': 455}\n")
        # Intent-to-add enables real diff without a commit or baseline fabrication.
        subprocess.run([str(git), "-C", str(workspace), "add", "-N", "stock.py", "quote.py", "test_quote.py"], check=True, capture_output=True)
        command = client.call("agent_run_command", {**root_args, "argv": ["python", "-m", "compileall", "-q", "."]})
        assert command["returncode"] == 0 and not command["timed_out"], command
        report["checks"]["structured_command"] = "PASS"
        test_args = {**root_args, "argv": ["python", "-m", "pytest", "-q", "--tb=short"], "timeout_seconds": 60}
        first = client.call("agent_run_tests", test_args)
        assert first["returncode"] == 1 and "2 failed" in first["stdout"], first
        patch("stock.py", "return min(available, requested)", "return max(0, min(available, requested))")
        second = client.call("agent_run_tests", test_args)
        assert second["returncode"] == 1 and "1 failed" in second["stdout"] and "2 passed" in second["stdout"], second
        patch("quote.py", "return {'units': units, 'total_cents': units * unit_cents}",
              "total = units * unit_cents\n    if units >= 5:\n        total = (total * 90 + 99) // 100\n    return {'units': units, 'total_cents': total}")
        third = client.call("agent_run_tests", test_args)
        assert third["returncode"] == 0 and "3 passed" in third["stdout"], third
        report["checks"]["two_real_edit_test_cycles"] = "PASS"
        report["test_progression"] = ["2 failed, 1 passed", "1 failed, 2 passed", "3 passed"]
        status = client.call("agent_git_status", root_args)
        diff = client.call("agent_git_diff", root_args)
        assert status["returncode"] == 0 and "stock.py" in status["stdout"]
        assert diff["returncode"] == 0 and "+    return max(0, min(available, requested))" in diff["stdout"]
        report["checks"]["git_status_and_diff"] = "PASS"
        before = (workspace / "stock.py").read_bytes()
        client.call("agent_write_file", {**root_args, "path": "stock.py", "content": "wrong", "expected_sha256": "0" * 64}, rejected=True)
        assert (workspace / "stock.py").read_bytes() == before
        for args in ({**root_args, "path": "../outside.txt"}, {**root_args, "path": ".env"},
                     {"workspace_root": str(PROJECT_ROOT), "path": "README.md"}):
            client.call("agent_read_file", args, rejected=True)
        client.call("agent_run_command", {**root_args, "argv": ["python", "-c", "print('blocked')"]}, rejected=True)
        report["checks"]["security_rejections"] = "PASS"
        status, _ = client.request("tools/list", headers={"Mcp-Session-Id": "stale-acceptance-session"})
        assert status == 404, status
        client.initialize()
        status, _ = client.request("tools/list")
        assert status == 200
        report["checks"]["fresh_initialize_after_stale_session"] = "PASS"
        report["status"] = "PASS"
        return 0
    except Exception as exc:
        report["status"] = "FAIL"
        error = str(exc)
        if client:
            error = error.replace(client.token, "[REDACTED]")
        report["error"] = error
        return 1
    finally:
        if client and client.session:
            try:
                # Close only this acceptance client's session using its credential.
                client.request("session/close", http_method="DELETE")
            except Exception:
                pass
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["requests"] = client.records if client else []
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"status": report["status"], "report": str(report_path), "checks": report["checks"],
                          "error": report.get("error")}, ensure_ascii=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8768/mcp")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "runtime/logs/direct_coding_e2e.json")
    parser.add_argument("--preflight", action="store_true")
    options = parser.parse_args()
    raise SystemExit(run(options.endpoint, options.report, preflight=options.preflight))
