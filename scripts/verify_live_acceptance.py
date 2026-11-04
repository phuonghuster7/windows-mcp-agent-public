"""Live Acceptance Verification (L4-A, L4-B, L4-C, L4-D) against running port 8768."""
import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def main() -> int:
    bundle_file = PROJECT_ROOT / "runtime" / "secrets" / "owner_delegation_bundle.json"
    if not bundle_file.exists():
        print(f"FAIL: {bundle_file} does not exist", file=sys.stderr)
        return 1

    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    access_token = bundle["access_token"]
    grant_id = bundle.get("capability_grant_id")
    delegation_id = bundle.get("delegation_id")

    base_url = "http://127.0.0.1:8768/mcp"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2025-03-26",
    }

    def jsonrpc_call(method: str, params: dict, req_id: int = 1) -> dict:
        req_body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(base_url, data=req_body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
                if sid:
                    headers["Mcp-Session-Id"] = sid
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_text = e.read().decode("utf-8", errors="replace")
            return {"http_code": e.code, "error": err_text}

    # 1. Initialize
    init_res = jsonrpc_call("initialize", {"protocolVersion": "2025-03-26"}, 1)
    if "result" not in init_res:
        print(f"FAIL: initialize failed: {init_res}", file=sys.stderr)
        return 1
    session_id = headers.get("Mcp-Session-Id")

    # 2. tools/list (verify 34 tools for owner full control)
    list_res = jsonrpc_call("tools/list", {}, 2)
    tools = list_res.get("result", {}).get("tools", [])
    tool_names = [t["name"] for t in tools]
    print(f"tools/list count: {len(tool_names)}")
    assert len(tool_names) == 34, f"Expected 34 tools, got {len(tool_names)}: {tool_names}"

    # L4-A: PowerShell Execution
    ps_res = jsonrpc_call(
        "tools/call",
        {"name": "agent_powershell_execute", "arguments": {"command": "Write-Output 'L4_A_LIVE_SUCCESS'"}},
        3,
    )
    ps_content = ps_res.get("result", {}).get("content", [{}])[0].get("text", "")
    assert "L4_A_LIVE_SUCCESS" in ps_content, f"L4-A failed: {ps_res}"
    print("L4-A: PASS (PowerShell executed successfully)")

    # L4-B: Filesystem Operations on Probe File
    probe_rel = "mcp-gateway/_chatgpt_owner_e2e_probe_20261102.txt"
    probe_abs = PROJECT_ROOT / probe_rel
    probe_content = "CHATGPT_OWNER_E2E_PROBE_V2_20261102\n"
    probe_abs.write_text(probe_content, encoding="utf-8")
    probe_bytes = probe_abs.read_bytes()
    expected_sha = hashlib.sha256(probe_bytes).hexdigest()

    # Read probe file
    read_res = jsonrpc_call(
        "tools/call",
        {"name": "agent_read_file", "arguments": {"workspace_root": str(PROJECT_ROOT), "path": probe_rel}},
        4,
    )
    read_text = read_res.get("result", {}).get("content", [{}])[0].get("text", "")
    assert expected_sha in read_text, f"Read failed: {read_res}"

    # Delete probe file via agent_delete_file (requires expected_sha256)
    del_res = jsonrpc_call(
        "tools/call",
        {"name": "agent_delete_file", "arguments": {"workspace_root": str(PROJECT_ROOT), "path": probe_rel, "expected_sha256": expected_sha}},
        5,
    )
    del_payload = json.loads(del_res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    assert del_payload.get("deleted") is True, f"Delete failed: {del_res}"
    backup_id = del_payload["backup_id"]
    assert not probe_abs.exists(), "Probe file still exists on disk after delete"

    # Restore probe file using rollback_backup_id via agent_write_file
    restore_res = jsonrpc_call(
        "tools/call",
        {
            "name": "agent_write_file",
            "arguments": {
                "workspace_root": str(PROJECT_ROOT),
                "path": probe_rel,
                "content": "",
                "expected_sha256": "missing",
                "rollback_backup_id": backup_id,
            },
        },
        6,
    )
    restore_payload = json.loads(restore_res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    assert probe_abs.exists(), "Probe file missing after rollback"
    assert hashlib.sha256(probe_abs.read_bytes()).hexdigest() == expected_sha, "Restored SHA mismatch"

    # Delete probe file finally so git tree is pristine
    del_final_res = jsonrpc_call(
        "tools/call",
        {"name": "agent_delete_file", "arguments": {"workspace_root": str(PROJECT_ROOT), "path": probe_rel, "expected_sha256": expected_sha}},
        7,
    )
    assert not probe_abs.exists(), "Probe file not removed after final delete"
    print("L4-B: PASS (Read -> Delete anti-TOCTOU -> Restore verified -> Final Delete)")

    # L4-C: Security Negative Boundary Verification
    # 1. Non-owner / static bearer cannot run powershell
    static_hdr = {
        "Authorization": f"Bearer mcp_sec_99887766554433221100",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2025-03-26",
    }
    req_s = urllib.request.Request(
        base_url,
        data=json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "agent_powershell_execute", "arguments": {"command": "whoami"}}}).encode("utf-8"),
        headers=static_hdr,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req_s, timeout=5) as r:
            body_s = json.loads(r.read().decode("utf-8"))
            assert body_s.get("result", {}).get("isError") is True or "error" in body_s
    except urllib.error.HTTPError as he:
        assert he.code in (401, 403)

    # 2. Raw secret read denied
    sec_call = jsonrpc_call(
        "tools/call",
        {"name": "agent_read_file", "arguments": {"workspace_root": str(PROJECT_ROOT), "path": "runtime/secrets/oauth_signing.key"}},
        9,
    )
    assert sec_call.get("result", {}).get("isError") is True

    # 3. Path traversal denied
    trav_call = jsonrpc_call(
        "tools/call",
        {"name": "agent_read_file", "arguments": {"workspace_root": str(PROJECT_ROOT), "path": "../../Windows/win.ini"}},
        10,
    )
    assert trav_call.get("result", {}).get("isError") is True

    print("L4-C: PASS (Negative boundary tests verified on live socket)")

    # L4-D: Desktop / System status tool execution
    status_res = jsonrpc_call("tools/call", {"name": "agent_system_status", "arguments": {}}, 11)
    status_payload = json.loads(status_res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    assert status_payload.get("is_owner") is True and status_res.get("result", {}).get("isError") is False, f"System status failed: {status_res}"
    print("L4-D: PASS (agent_system_status verified on live socket)")

    report = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "PASS",
        "endpoint": base_url,
        "session_id": session_id,
        "owner_client_id": bundle["client_id"],
        "delegation_id": delegation_id,
        "capability_grant_id": grant_id,
        "tool_count": len(tool_names),
        "l4_a_powershell": "PASS",
        "l4_b_probe_filesystem": "PASS",
        "l4_c_security_negatives": "PASS",
        "l4_d_system_status": "PASS",
    }
    rep_path = PROJECT_ROOT / "runtime" / "evidence" / "live_acceptance_report.json"
    rep_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
