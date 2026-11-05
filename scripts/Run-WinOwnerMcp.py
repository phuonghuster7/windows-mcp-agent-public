"""WinOwner MCP scheduled-task entrypoint (local owner, read-only).

No bearer secrets in Scheduled Task arguments, Git history, or command line.
This process directly hosts uvicorn, allowing Task Scheduler to stop it.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import runpy
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def start(port: int) -> None:
    if os.name != "nt":
        raise SystemExit("WinOwner task launcher requires Windows")
    policy = ROOT / "config" / "policy.json"
    bearer = ROOT / "runtime" / "secrets" / "gateway_caller.token"
    db_path = ROOT / "runtime" / "secrets" / "oauth.db"
    adapter = ROOT / "mcp-gateway" / "cloud_autonomous_adapter.py"
    if not adapter.is_file() or not policy.is_file() or not bearer.is_file():
        raise SystemExit("Local adapter, policy or protected bearer token is missing")
    if json.loads(policy.read_text(encoding="utf-8")).get("default_profile") != "read_only":
        raise SystemExit("Refusing to start: local policy must default to read_only")

    secret = bearer.read_text(encoding="utf-8").strip()
    if not secret:
        raise SystemExit("Protected bearer token is empty")

    os.environ["WINDOWS_MCP_GATEWAY_TOKEN"] = secret
    os.environ["MCP_STATE_ROOT"] = str(ROOT)
    os.environ["WINDOWS_MCP_BACKEND_ENV_FILE"] = str(ROOT / "runtime" / "not-configured.env")
    os.environ["MCP_AGENT_PROFILE"] = "read_only"

    log_dir = ROOT / "runtime" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = log_dir / f"adapter-{port}-{stamp}.stdout.log"
    err_path = log_dir / f"adapter-{port}-{stamp}.stderr.log"
    with out_path.open("a", encoding="utf-8", buffering=1) as out_file, err_path.open(
        "a", encoding="utf-8", buffering=1
    ) as err_file:
        sys.stdout = out_file
        sys.stderr = err_file
        os.chdir(ROOT)
        sys.path.insert(0, str(ROOT))
        sys.path.insert(0, str(ROOT / "mcp-gateway"))
        sys.argv = [
            str(adapter),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--profile", "read_only",
            "--policy-path", str(policy),
            "--db-path", str(db_path),
        ]
        runpy.run_path(str(adapter), run_name="__main__")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinOwner MCP local read-only task")
    parser.add_argument("--port", type=int, default=8768)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    start(args.port)
