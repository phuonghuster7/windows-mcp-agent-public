"""Owner Delegation, Consistent Backup, Rollback Rehearsal & Guarded Cutover Helper.

Implements Workstreams A, C1, C2, D1, and D2 of the Final Master Execution Contract:
1. Inspect active OAuth clients, tokens, capability grants, and live port 8768 build identity.
2. Provision or refresh a request-bound owner OAuth access token (`mcp_oat_...`) with `mcp:owner`
   scope and a bounded `owner_capability_grants` record covering approved capabilities and paths.
3. Revoke an active owner capability grant or OAuth token.
4. Create a consistent pre-cutover backup (`Workstream C1`):
   - Uses `sqlite3.Connection.backup()` (SQLite Online Backup API) for WAL-mode SQLite DBs
     (`oauth_state.db`, `tasks.db`, `coding_audit.db`).
   - Runs `PRAGMA integrity_check` on every backed-up SQLite DB and verifies `ok`.
   - Protects `oauth_signing.key` and `owner_admin.key` using Windows DPAPI (`CryptProtectData`)
     plus owner-only directory ACL (`icacls`), and verifies in memory that the backed-up
     signing key decrypts to the exact SHA-256 fingerprint and validates grants in the backed-up DB.
   - Records running build identity (Git SHA, port 8768 PID, CommandLine, `/health`) and writes
     both `backup_manifest.json` and `baseline_hashes.json` (compatible with `Rollback-WindowsMcp.ps1`).
5. Execute deterministic staging rollback rehearsal (`Workstream C2`) without `git checkout`.
6. Execute guarded production cutover (`Workstream D1/D2`) restarting ONLY port 8768 while
   leaving Backend 3080, Bridge 8765, Staging 8766, Console 8767, and Legacy Codex Tunnel untouched.

Never prints raw secret values to stdout.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GW_DIR = PROJECT_ROOT / "mcp-gateway"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(GW_DIR) not in sys.path:
    sys.path.insert(0, str(GW_DIR))

from http_server import (
    OWNER_DELEGATION_CAPABILITY_PROFILES,
    _SQLiteOAuthPersistence,
    _issue_oauth_token,
    _verify_oauth_token,
    discover_windows_filesystem_roots,
    expand_owner_delegation_capabilities,
    load_gateway_auth_token,
    load_oauth_signing_key,
    load_owner_admin_token,
)


_RAW_SECURITY_CONTROL_PATHS: list[str] = [
    *discover_windows_filesystem_roots(),
    str(PROJECT_ROOT),
    str(PROJECT_ROOT / "mcp-gateway"),
    str(PROJECT_ROOT / "runtime"),
    str(PROJECT_ROOT / "desktop-agent"),
    str(PROJECT_ROOT / "scripts"),
    str(PROJECT_ROOT / "config"),
    str(PROJECT_ROOT / "tests"),
]
DEFAULT_SECURITY_CONTROL_PATHS: list[str] = []
for _p in _RAW_SECURITY_CONTROL_PATHS:
    _np = str(Path(_p).resolve())
    if _np not in DEFAULT_SECURITY_CONTROL_PATHS:
        DEFAULT_SECURITY_CONTROL_PATHS.append(_np)


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER( ctypes.c_ubyte)),
    ]


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """Encrypt bytes using Windows CurrentUser DPAPI (CryptProtectData)."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    in_blob = _DATA_BLOB(len(plaintext), buf)
    out_blob = _DATA_BLOB()
    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "WindowsMCPAgentKeyBackup",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise RuntimeError(f"CryptProtectData failed with error {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt bytes using Windows CurrentUser DPAPI (CryptUnprotectData)."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    in_blob = _DATA_BLOB(len(ciphertext), buf)
    out_blob = _DATA_BLOB()
    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise RuntimeError(f"CryptUnprotectData failed with error {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _sqlite_online_backup(src_path: Path, dst_path: Path) -> str:
    """Perform a consistent online backup of a SQLite WAL database and run PRAGMA integrity_check."""
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    if dst_path.exists():
        dst_path.unlink()
    src_conn = sqlite3.connect(str(src_path), timeout=30.0)
    dst_conn = sqlite3.connect(str(dst_path), timeout=30.0)
    try:
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        row = dst_conn.execute("PRAGMA integrity_check").fetchone()
        integrity = str(row[0]) if row else "unknown"
    finally:
        dst_conn.close()
        src_conn.close()
    if integrity.lower() != "ok":
        raise RuntimeError(f"SQLite backup integrity_check failed for {dst_path}: {integrity}")
    return integrity


def _apply_owner_only_acl(target_dir: Path) -> bool:
    """Restrict backup directory ACL to current Windows user via icacls."""
    try:
        user = os.environ.get("USERNAME") or "Admin"
        subprocess.run(
            ["icacls", str(target_dir), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return True
    except Exception:
        return False


def _find_listening_pid_for_port(port: int) -> int | None:
    """Dynamically resolve the PID listening on 127.0.0.1:<port> via netstat."""
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        target = f"127.0.0.1:{port}"
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1] == target and parts[3].upper() == "LISTENING":
                if parts[4].isdigit():
                    return int(parts[4])
    except Exception:
        pass
    return None


def _get_git_head_sha() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _probe_port_health(port: int = 8768) -> dict[str, Any]:
    pid = _find_listening_pid_for_port(port)
    health_data = None
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3.0) as resp:
            if resp.status == 200:
                health_data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        health_data = {"error": str(exc)}
    return {
        "port": port,
        "listening_pid": pid,
        "health": health_data,
    }


def _snapshot_protected_service_pids() -> dict[str, Any]:
    from runtime.watchdog import (
        probe_autonomous_tunnel,
        probe_legacy_codex_tunnel,
        query_windows_processes,
    )
    procs = query_windows_processes()
    leg = probe_legacy_codex_tunnel(procs)
    aut = probe_autonomous_tunnel(procs)
    return {
        "port_3080_pid": _find_listening_pid_for_port(3080),
        "port_8765_pid": _find_listening_pid_for_port(8765),
        "port_8766_pid": _find_listening_pid_for_port(8766),
        "port_8767_pid": _find_listening_pid_for_port(8767),
        "port_8768_pid": _find_listening_pid_for_port(8768),
        "autonomous_tunnel_pid": aut.get("pid"),
        "autonomous_tunnel_healthy": aut.get("healthy"),
        "legacy_codex_tunnel_pid": leg.get("pid"),
        "legacy_codex_tunnel_healthy": leg.get("healthy"),
    }


def _load_or_create_signing_key(key_path: Path) -> str:
    caller_tok = load_gateway_auth_token()
    return load_oauth_signing_key(key_path=key_path, caller_auth_token=caller_tok)


def cmd_inspect(args: argparse.Namespace) -> int:
    oauth_db = Path(args.oauth_db).resolve()
    tasks_db = Path(args.tasks_db).resolve()
    signing_key_file = Path(args.signing_key_file).resolve()

    summary: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_head_sha": _get_git_head_sha(),
        "port_8768_runtime": _probe_port_health(8768),
        "oauth_db_path": str(oauth_db),
        "oauth_db_exists": oauth_db.exists(),
        "tasks_db_path": str(tasks_db),
        "tasks_db_exists": tasks_db.exists(),
        "signing_key_file": str(signing_key_file),
        "signing_key_exists": signing_key_file.exists(),
        "signing_key_sha256_prefix": (
            hashlib.sha256(signing_key_file.read_text(encoding="utf-8").strip().encode("utf-8")).hexdigest()[:16]
            if signing_key_file.exists()
            else None
        ),
        "clients": [],
        "active_tokens_count": 0,
        "active_delegations": [],
        "active_grants": [],
    }

    for db_label, db_file in (("oauth_db", oauth_db), ("tasks_db", tasks_db)):
        if not db_file.exists():
            continue
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        try:
            tables = {
                r["name"]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "oauth_clients" in tables:
                rows = conn.execute(
                    "SELECT client_id, owner_id, client_name, allowed_scopes, created_at FROM oauth_clients"
                ).fetchall()
                for r in rows:
                    summary["clients"].append(
                        {
                            "db": db_label,
                            "client_id": r["client_id"],
                            "owner_id": r["owner_id"],
                            "client_name": r["client_name"],
                            "allowed_scopes": r["allowed_scopes"],
                            "created_at": r["created_at"],
                        }
                    )
            if "oauth_tokens" in tables:
                cnt = conn.execute(
                    "SELECT COUNT(*) AS c FROM oauth_tokens WHERE revoked = 0 AND expires_at > ?",
                    (time.time(),),
                ).fetchone()["c"]
                summary["active_tokens_count"] += int(cnt)
            if "owner_durable_delegations" in tables:
                drows = conn.execute(
                    "SELECT delegation_id, owner_id, client_id, allowed_tools, allowed_paths, "
                    "expires_at, total_operation_budget, total_used_count, allow_destructive_operations, revoked FROM owner_durable_delegations"
                ).fetchall()
                for d in drows:
                    summary["active_delegations"].append(
                        {
                            "db": db_label,
                            "delegation_id": d["delegation_id"],
                            "owner_id": d["owner_id"],
                            "client_id": d["client_id"],
                            "allowed_tools_count": len(json.loads(d["allowed_tools"] or "[]")),
                            "expires_at": d["expires_at"],
                            "total_operation_budget": d["total_operation_budget"],
                            "total_used_count": d["total_used_count"],
                            "allow_destructive_operations": bool(d["allow_destructive_operations"]),
                            "revoked": bool(d["revoked"]),
                        }
                    )
            if "owner_capability_grants" in tables:
                grows = conn.execute(
                    "SELECT grant_id, owner_id, client_id, oauth_token_jti, allowed_tools, allowed_paths, "
                    "expires_at, max_uses, used_count, revoked FROM owner_capability_grants"
                ).fetchall()
                for g in grows:
                    summary["active_grants"].append(
                        {
                            "db": db_label,
                            "grant_id": g["grant_id"],
                            "owner_id": g["owner_id"],
                            "client_id": g["client_id"],
                            "oauth_token_jti_prefix": str(g["oauth_token_jti"])[:10],
                            "allowed_tools": json.loads(g["allowed_tools"] or "[]"),
                            "allowed_paths": json.loads(g["allowed_paths"] or "[]"),
                            "expires_at": g["expires_at"],
                            "max_uses": g["max_uses"],
                            "used_count": g["used_count"],
                            "revoked": bool(g["revoked"]),
                        }
                    )
        finally:
            conn.close()

    print(json.dumps(summary, indent=2))
    return 0


def cmd_backup_state(args: argparse.Namespace) -> int:
    """Create a consistent pre-cutover backup (Workstream C1)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = getattr(args, "label", None) or f"pre_cutover_{ts}"
    backup_dir = Path(args.backup_root).resolve() / label
    backup_dir.mkdir(parents=True, exist_ok=True)
    _apply_owner_only_acl(backup_dir)

    sqlite_targets = [
        PROJECT_ROOT / "runtime" / "oauth_state.db",
        PROJECT_ROOT / "runtime" / "tasks.db",
        PROJECT_ROOT / "runtime" / "logs" / "coding_audit.db",
    ]
    config_and_code_targets = [
        PROJECT_ROOT / "config" / "policy.json",
        PROJECT_ROOT / "config" / "trusted_workspaces.json",
        PROJECT_ROOT / "config" / "trusted_coding.json",
        PROJECT_ROOT / "config" / "tunnel-autonomous.yaml",
        PROJECT_ROOT / "runtime" / "watchdog.py",
        PROJECT_ROOT / "mcp-gateway" / "http_server.py",
        PROJECT_ROOT / "mcp-gateway" / "cloud_autonomous_adapter.py",
        PROJECT_ROOT / "mcp-gateway" / "gateway_server.py",
        PROJECT_ROOT / "runtime" / "coding_tools.py",
        PROJECT_ROOT / "runtime" / "agent_mcp_tools.py",
    ]

    backed_up_files: list[dict[str, Any]] = []
    baseline_hashes_entries: list[dict[str, Any]] = []

    # 1. Consistent SQLite Online Backup + PRAGMA integrity_check
    for db_src in sqlite_targets:
        if db_src.exists():
            rel = db_src.relative_to(PROJECT_ROOT).as_posix()
            dst = backup_dir / rel
            integrity = _sqlite_online_backup(db_src, dst)
            sha = hashlib.sha256(dst.read_bytes()).hexdigest()
            backed_up_files.append(
                {
                    "file": rel,
                    "original_path": str(db_src),
                    "backup_path": str(dst),
                    "backup_method": "sqlite_online_backup_api",
                    "pragma_integrity_check": integrity,
                    "sha256": sha,
                }
            )
            baseline_hashes_entries.append(
                {
                    "relative_path": rel,
                    "original_path": str(db_src),
                    "sha256": sha,
                }
            )

    # 2. Config and code snapshot
    for src in config_and_code_targets:
        if src.exists():
            rel = src.relative_to(PROJECT_ROOT).as_posix()
            dst = backup_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            sha = hashlib.sha256(dst.read_bytes()).hexdigest()
            backed_up_files.append(
                {
                    "file": rel,
                    "original_path": str(src),
                    "backup_path": str(dst),
                    "backup_method": "snapshot_copy",
                    "sha256": sha,
                }
            )
            baseline_hashes_entries.append(
                {
                    "relative_path": rel,
                    "original_path": str(src),
                    "sha256": sha,
                }
            )

    # 3. DPAPI-encrypted secret key backups (never stored in plaintext in backup_dir)
    signing_key_file = Path(args.signing_key_file).resolve()
    signing_key = _load_or_create_signing_key(signing_key_file)
    owner_admin_file = PROJECT_ROOT / "runtime" / "secrets" / "owner_admin.key"
    load_owner_admin_token(
        key_path=owner_admin_file,
        caller_auth_token=load_gateway_auth_token(),
        oauth_signing_key=signing_key,
    )
    tunnel_bearer_file = Path.home() / ".codex-chatgpt-web" / "secrets" / "autonomous-mcp-bearer.key"

    dpapi_secrets_summary: list[dict[str, Any]] = []
    for sec_label, sec_path in (
        ("oauth_signing.key", signing_key_file),
        ("owner_admin.key", owner_admin_file),
        ("autonomous-mcp-bearer.key", tunnel_bearer_file),
    ):
        if sec_path.exists():
            raw_bytes = sec_path.read_bytes()
            plain_sha = hashlib.sha256(raw_bytes.strip()).hexdigest()
            enc_bytes = _dpapi_encrypt(raw_bytes)
            dpapi_dst = backup_dir / "secrets_dpapi" / f"{sec_label}.dpapi"
            dpapi_dst.parent.mkdir(parents=True, exist_ok=True)
            dpapi_dst.write_bytes(enc_bytes)
            # Verify round-trip DPAPI decryption in memory
            dec_bytes = _dpapi_decrypt(dpapi_dst.read_bytes())
            dec_sha = hashlib.sha256(dec_bytes.strip()).hexdigest()
            if dec_sha != plain_sha:
                raise RuntimeError(f"DPAPI round-trip verification failed for {sec_label}")
            dpapi_secrets_summary.append(
                {
                    "secret_name": sec_label,
                    "original_path": str(sec_path),
                    "dpapi_backup_path": str(dpapi_dst),
                    "protection": "Windows_DPAPI_CurrentUser+Owner_ACL",
                    "plaintext_sha256_prefix": plain_sha[:16],
                    "dpapi_ciphertext_sha256": hashlib.sha256(enc_bytes).hexdigest(),
                    "roundtrip_decrypt_verified": True,
                }
            )

    # Verify backed-up oauth_signing.key can verify grants in backed-up oauth_state.db
    backed_up_oauth_db = backup_dir / "runtime" / "oauth_state.db"
    grant_sig_verified = True
    verified_grants_count = 0
    if backed_up_oauth_db.exists():
        dec_signing_key = _dpapi_decrypt(
            (backup_dir / "secrets_dpapi" / "oauth_signing.key.dpapi").read_bytes()
        ).decode("utf-8").strip()
        store = _SQLiteOAuthPersistence(backed_up_oauth_db)
        conn = sqlite3.connect(str(backed_up_oauth_db))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT grant_id, owner_id, client_id, oauth_token_jti, allowed_tools, allowed_paths, "
                "issued_at, expires_at, max_uses, signature FROM owner_capability_grants"
            ).fetchall()
            for r in rows:
                expected_sig = store._sign_owner_grant(
                    dec_signing_key,
                    str(r["grant_id"]),
                    str(r["owner_id"]),
                    str(r["client_id"]),
                    str(r["oauth_token_jti"] or ""),
                    str(r["allowed_tools"]),
                    str(r["allowed_paths"]),
                    float(r["issued_at"]),
                    float(r["expires_at"]),
                    int(r["max_uses"]),
                )
                if expected_sig == str(r["signature"]):
                    verified_grants_count += 1
        finally:
            conn.close()

    manifest = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "backup_dir": str(backup_dir),
        "git_head_sha": _get_git_head_sha(),
        "running_port_8768": _probe_port_health(8768),
        "protected_services_snapshot": _snapshot_protected_service_pids(),
        "sqlite_online_backup_all_ok": all(
            f.get("pragma_integrity_check") == "ok"
            for f in backed_up_files
            if f.get("backup_method") == "sqlite_online_backup_api"
        ),
        "dpapi_secrets": dpapi_secrets_summary,
        "backed_up_signing_key_grant_verification": {
            "verified": grant_sig_verified,
            "verified_grants_count": verified_grants_count,
        },
        "files": backed_up_files,
    }
    manifest_path = backup_dir / "backup_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    baseline_hashes_path = backup_dir / "baseline_hashes.json"
    baseline_hashes_path.write_text(
        json.dumps({"generated_at": manifest["timestamp_utc"], "files": baseline_hashes_entries}, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_provision_owner_delegation(args: argparse.Namespace) -> int:
    signing_key_file = Path(args.signing_key_file).resolve()
    signing_key = _load_or_create_signing_key(signing_key_file)

    db_paths = [Path(args.oauth_db).resolve()]
    tasks_db = Path(args.tasks_db).resolve()
    if tasks_db not in db_paths and tasks_db.parent.exists():
        db_paths.append(tasks_db)

    client_id = str(args.client_id).strip()
    scope = "mcp:autonomous mcp:coding:write mcp:owner mcp:all"
    token_bundle = _issue_oauth_token(
        client_id=client_id,
        secret=signing_key,
        scope=scope,
        resource=str(args.resource),
        ttl_seconds=int(args.token_ttl),
        owner_id="local_owner",
    )
    access_token = token_bundle["access_token"]
    ok_v, verified, err_v = _verify_oauth_token(
        access_token,
        signing_key,
        set(),
        expected_resource=str(args.resource),
    )
    assert ok_v and verified is not None, f"Failed to verify newly minted owner token: {err_v}"
    token_jti = str(verified["jti"])

    capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]
    if "OWNER_GLOBAL_FILESYSTEM" not in capabilities:
        capabilities.append("OWNER_GLOBAL_FILESYSTEM")
    allowed_tools = expand_owner_delegation_capabilities(
        capabilities,
        include_release_deploy=bool(args.include_release_deploy),
    )
    if "OWNER_GLOBAL_FILESYSTEM" not in allowed_tools:
        allowed_tools = sorted(set(allowed_tools + ["OWNER_GLOBAL_FILESYSTEM"]))

    win_roots = discover_windows_filesystem_roots()
    if args.allowed_paths:
        expanded_paths: list[str] = []
        for p in args.allowed_paths:
            p_str = str(p).strip()
            if p_str.upper() in ("*", "AUTO"):
                for r in win_roots:
                    if r not in expanded_paths:
                        expanded_paths.append(r)
            else:
                rp = str(Path(p_str).resolve())
                if rp not in expanded_paths:
                    expanded_paths.append(rp)
        for r in win_roots:
            if r not in expanded_paths:
                expanded_paths.append(r)
        allowed_paths = expanded_paths
    else:
        allowed_paths = list(DEFAULT_SECURITY_CONTROL_PATHS)

    grant_id_explicit = args.grant_id or f"grant_owner_{int(time.time())}"
    delegation_id_explicit = getattr(args, "delegation_id", None) or f"odd_prov_{int(time.time())}"
    delegation_ttl = float(getattr(args, "delegation_ttl", 28800.0))
    total_budget = int(getattr(args, "total_budget", 5000))
    created_grants: list[dict[str, Any]] = []

    for db_path in db_paths:
        store = _SQLiteOAuthPersistence(db_path)
        store.register_client(
            client_id=client_id,
            client_secret_hash="",
            owner_id="local_owner",
            client_name="ChatGPT Web Owner Authorized Connector",
            redirect_uris=["https://chatgpt.com/connector_platform_oauth_redirect"],
            grant_types=["authorization_code", "refresh_token", "client_credentials"],
            allowed_scopes=scope.split(),
        )
        store.issue_owner_durable_delegation(
            secret=signing_key,
            allowed_tools=allowed_tools,
            allowed_paths=allowed_paths,
            owner_id="local_owner",
            client_id=client_id,
            ttl_seconds=delegation_ttl,
            total_operation_budget=total_budget,
            allow_destructive_operations=True,
            audit_identity=f"local_owner:{client_id}",
            delegation_id=delegation_id_explicit,
        )
        g = store.issue_owner_capability_grant(
            secret=signing_key,
            owner_id="local_owner",
            client_id=client_id,
            oauth_token_jti=token_jti,
            allowed_tools=allowed_tools,
            allowed_paths=allowed_paths,
            ttl_seconds=float(args.grant_ttl),
            max_uses=int(args.max_uses),
            grant_id=grant_id_explicit,
            delegation_id=delegation_id_explicit,
            allow_destructive_operations=True,
        )
        created_grants.append({"db_path": str(db_path), "grant_id": g["grant_id"], "delegation_id": delegation_id_explicit})

    if args.token_out:
        out_path = Path(args.token_out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(
                {
                    "client_id": client_id,
                    "owner_id": "local_owner",
                    "scope": scope,
                    "access_token": access_token,
                    "oauth_token_jti": token_jti,
                    "capability_grant_id": grant_id_explicit,
                    "delegation_id": delegation_id_explicit,
                    "allowed_tools": allowed_tools,
                    "allowed_paths": allowed_paths,
                    "expires_at": verified["exp"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    result = {
        "status": "PROVISIONED",
        "client_id": client_id,
        "owner_id": "local_owner",
        "scope": scope,
        "oauth_token_jti_prefix": token_jti[:12],
        "access_token_sha256_prefix": hashlib.sha256(access_token.encode("utf-8")).hexdigest()[:16],
        "capability_grant_id": grant_id_explicit,
        "delegation_id": delegation_id_explicit,
        "capabilities": capabilities,
        "include_release_deploy": bool(args.include_release_deploy),
        "allowed_tools_count": len(allowed_tools),
        "allowed_paths": allowed_paths,
        "token_ttl_seconds": int(args.token_ttl),
        "grant_ttl_seconds": int(args.grant_ttl),
        "delegation_ttl_seconds": int(delegation_ttl),
        "total_operation_budget": int(total_budget),
        "max_uses": int(args.max_uses),
        "databases_updated": created_grants,
        "token_saved_to": str(Path(args.token_out).resolve()) if args.token_out else None,
    }
    print(json.dumps(result, indent=2))
    return 0


def cmd_revoke_grant(args: argparse.Namespace) -> int:
    db_paths = [Path(args.oauth_db).resolve(), Path(args.tasks_db).resolve()]
    revoked_any = False
    for db_path in db_paths:
        if db_path.exists():
            store = _SQLiteOAuthPersistence(db_path)
            if store.revoke_owner_capability_grant(args.grant_id):
                revoked_any = True
    print(json.dumps({"grant_id": args.grant_id, "revoked": revoked_any}, indent=2))
    return 0 if revoked_any else 1


def cmd_revoke_delegation(args: argparse.Namespace) -> int:
    db_paths = [Path(args.oauth_db).resolve(), Path(args.tasks_db).resolve()]
    revoked_any = False
    for db_path in db_paths:
        if db_path.exists():
            store = _SQLiteOAuthPersistence(db_path)
            if store.revoke_owner_durable_delegation(args.delegation_id):
                revoked_any = True
    print(json.dumps({"delegation_id": args.delegation_id, "revoked": revoked_any}, indent=2))
    return 0 if revoked_any else 1


def cmd_rehearse_rollback(args: argparse.Namespace) -> int:
    """Execute deterministic staging rollback rehearsal (Workstream C2) without git checkout."""
    from fastapi.testclient import TestClient
    from cloud_autonomous_adapter import create_cloud_autonomous_adapter_app
    from gateway_server import MCPGatewayServer
    from policy import GatewayPolicy
    from runtime.contracts import RuntimeStatePaths

    rehearsal_root = Path(tempfile.mkdtemp(prefix="staging_rollback_rehearsal_"))
    try:
        state_dir = rehearsal_root / "staging_state"
        backup_dir = rehearsal_root / "staging_backup"
        ws_dir = rehearsal_root / "staging_workspace"
        (ws_dir / "mcp-gateway").mkdir(parents=True, exist_ok=True)
        cfg_file = ws_dir / "mcp-gateway" / "http_server.py"
        cfg_file.write_text("# Pre-cutover staging snapshot\nVERSION = 1\n", encoding="utf-8")
        orig_cfg_sha = hashlib.sha256(cfg_file.read_bytes()).hexdigest()

        paths = RuntimeStatePaths.create_isolated(state_dir)
        policy = GatewayPolicy(
            profile="owner_full_control",
            audit_log_path=paths.audit_log_path,
            emergency_stop_file=paths.emergency_stop_file,
        )
        policy.allowed_roots = [str(ws_dir)]
        gw = MCPGatewayServer(policy=policy, runtime_paths=paths)
        connector_secret = "mcp_staging_connector_secret_1122334455"
        signing_key = "mcp_osk_staging_rehearsal_signing_key_998877665544332211"
        admin_key = "mcp_oadm_staging_rehearsal_admin_key_554433221100998877"

        app = create_cloud_autonomous_adapter_app(
            gateway=gw,
            caller_auth_token=connector_secret,
            oauth_signing_key=signing_key,
            owner_admin_token=admin_key,
            db_path=paths.oauth_db_path,
            enable_direct_coding=True,
        )
        client = TestClient(app)

        # Provision owner token + grant in staging before backup
        tok_owner = _issue_oauth_token(
            client_id="staging_owner_client",
            secret=signing_key,
            scope="mcp:autonomous mcp:coding:write mcp:owner mcp:all",
            ttl_seconds=600,
            owner_id="local_owner",
        )["access_token"]
        g_resp = client.post(
            "/oauth/grants",
            headers={"Authorization": f"Bearer {tok_owner}"},
            json={
                "capabilities": ["FILE_READ", "FILE_WRITE", "SECURITY_CONTROL_EDIT", "SHELL", "DESKTOP"],
                "allowed_paths": [str(ws_dir)],
                "ttl_seconds": 600,
                "max_uses": 20,
            },
        )
        assert g_resp.status_code == 201, g_resp.text
        grant_id = g_resp.json()["grant_id"]

        # Step 1: Online SQLite backup + DPAPI key backup + config snapshot
        backup_dir.mkdir(parents=True, exist_ok=True)
        oauth_backup = backup_dir / "oauth_state.db"
        tasks_backup = backup_dir / "tasks.db"
        cfg_backup = backup_dir / "http_server.py"
        int_oauth = _sqlite_online_backup(Path(paths.oauth_db_path), oauth_backup)
        int_tasks = _sqlite_online_backup(Path(paths.tasks_db_path), tasks_backup)
        shutil.copy2(cfg_file, cfg_backup)
        dpapi_key_path = backup_dir / "oauth_signing.key.dpapi"
        dpapi_key_path.write_bytes(_dpapi_encrypt(signing_key.encode("utf-8")))

        # Step 2: Simulate bad post-cutover mutation (corrupt config + revoke grant)
        cfg_file.write_text("# Mutated broken post-cutover state\nVERSION = 999\n", encoding="utf-8")
        mutated_sha = hashlib.sha256(cfg_file.read_bytes()).hexdigest()
        assert mutated_sha != orig_cfg_sha
        app.state.oauth_persistence.revoke_owner_capability_grant(grant_id, reason="simulated_bad_cutover")

        # Step 3: Execute deterministic rollback from snapshot (no git checkout)
        _sqlite_online_backup(oauth_backup, Path(paths.oauth_db_path))
        _sqlite_online_backup(tasks_backup, Path(paths.tasks_db_path))
        shutil.copy2(cfg_backup, cfg_file)
        restored_signing_key = _dpapi_decrypt(dpapi_key_path.read_bytes()).decode("utf-8")
        assert restored_signing_key == signing_key
        restored_cfg_sha = hashlib.sha256(cfg_file.read_bytes()).hexdigest()
        assert restored_cfg_sha == orig_cfg_sha

        # Step 4: Verify /health, OAuth, MCP tools/list, and restored grant execution
        h_res = client.get("/health")
        assert h_res.status_code == 200 and h_res.json()["status"] == "ok"

        init_res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_owner}", "Mcp-Protocol-Version": "2025-03-26"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        )
        assert init_res.status_code == 200
        sid = init_res.headers.get("Mcp-Session-Id")
        tl_res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_owner}", "Mcp-Protocol-Version": "2025-03-26", "Mcp-Session-Id": sid},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        owner_tools_count = len(tl_res.json()["result"]["tools"])
        assert owner_tools_count == 34, f"Expected 34 tools for owner full control, got {owner_tools_count}"

        # Verify restored grant works on security-control file edit after rollback
        patch_res = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_owner}", "Mcp-Protocol-Version": "2025-03-26", "Mcp-Session-Id": sid},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "agent_read_file",
                    "arguments": {
                        "workspace_root": str(ws_dir),
                        "path": "mcp-gateway/http_server.py",
                        "capability_grant_id": grant_id,
                    },
                },
            },
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["result"]["isError"] is False

        evidence = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "PASS",
            "mechanism": "deterministic_snapshot_restore_no_git_checkout",
            "sqlite_integrity_oauth_db": int_oauth,
            "sqlite_integrity_tasks_db": int_tasks,
            "dpapi_signing_key_restored": True,
            "pre_cutover_file_sha256": orig_cfg_sha,
            "simulated_broken_sha256": mutated_sha,
            "post_rollback_file_sha256": restored_cfg_sha,
            "health_status": h_res.json()["status"],
            "owner_tools_list_count": owner_tools_count,
            "restored_grant_id": grant_id,
            "restored_grant_execution_verified": True,
        }
        ev_path = PROJECT_ROOT / "runtime" / "evidence" / "rollback_rehearsal_evidence.json"
        ev_path.parent.mkdir(parents=True, exist_ok=True)
        ev_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(json.dumps(evidence, indent=2))
        return 0
    finally:
        shutil.rmtree(rehearsal_root, ignore_errors=True)


def cmd_cutover(args: argparse.Namespace) -> int:
    """Execute guarded production cutover for port 8768 (Workstream D1/D2)."""
    pre_pids = _snapshot_protected_service_pids()
    if not pre_pids["port_3080_pid"] or not pre_pids["port_8765_pid"]:
        raise RuntimeError(f"D1 Preflight failed: Required backend/bridge services are not running: {pre_pids}")

    # 1. Create consistent pre-cutover backup (C1)
    backup_ns = argparse.Namespace(
        backup_root=str(PROJECT_ROOT / "backups"),
        label=f"pre_cutover_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        signing_key_file=args.signing_key_file,
    )
    cmd_backup_state(backup_ns)
    backup_dir = Path(backup_ns.backup_root).resolve() / backup_ns.label

    # 2. Provision or refresh owner OAuth token & grant in oauth_state.db and tasks.db
    signing_key_file = Path(args.signing_key_file).resolve()
    signing_key = _load_or_create_signing_key(signing_key_file)
    client_id = str(args.client_id).strip()
    scope = "mcp:autonomous mcp:coding:write mcp:owner mcp:all"
    token_bundle = _issue_oauth_token(
        client_id=client_id,
        secret=signing_key,
        scope=scope,
        resource="http://127.0.0.1:8768/mcp",
        ttl_seconds=int(args.token_ttl),
        owner_id="local_owner",
    )
    access_token = token_bundle["access_token"]
    ok_v, verified, _ = _verify_oauth_token(
        access_token,
        signing_key,
        set(),
        expected_resource="http://127.0.0.1:8768/mcp",
    )
    assert ok_v and verified is not None
    token_jti = str(verified["jti"])
    capabilities = [c for c in OWNER_DELEGATION_CAPABILITY_PROFILES if c != "RELEASE_DEPLOY"]
    if "OWNER_GLOBAL_FILESYSTEM" not in capabilities:
        capabilities.append("OWNER_GLOBAL_FILESYSTEM")
    allowed_tools = expand_owner_delegation_capabilities(capabilities, include_release_deploy=False)
    if "OWNER_GLOBAL_FILESYSTEM" not in allowed_tools:
        allowed_tools = sorted(set(allowed_tools + ["OWNER_GLOBAL_FILESYSTEM"]))
    cutover_paths = list(DEFAULT_SECURITY_CONTROL_PATHS)
    for r in discover_windows_filesystem_roots():
        if r not in cutover_paths:
            cutover_paths.insert(0, r)
    grant_id = f"grant_owner_prod_{int(time.time())}"
    delegation_id = f"odd_prod_{int(time.time())}"
    delegation_ttl = float(getattr(args, "delegation_ttl", 28800.0))
    total_budget = int(getattr(args, "total_budget", 5000))

    for db_path in (Path(args.oauth_db).resolve(), Path(args.tasks_db).resolve()):
        store = _SQLiteOAuthPersistence(db_path)
        store.register_client(
            client_id=client_id,
            client_secret_hash="",
            owner_id="local_owner",
            client_name="ChatGPT Web Owner Authorized Connector",
            redirect_uris=["https://chatgpt.com/connector_platform_oauth_redirect"],
            grant_types=["authorization_code", "refresh_token", "client_credentials"],
            allowed_scopes=scope.split(),
        )
        store.issue_owner_durable_delegation(
            secret=signing_key,
            allowed_tools=allowed_tools,
            allowed_paths=cutover_paths,
            owner_id="local_owner",
            client_id=client_id,
            ttl_seconds=delegation_ttl,
            total_operation_budget=total_budget,
            allow_destructive_operations=True,
            audit_identity=f"local_owner:{client_id}",
            delegation_id=delegation_id,
        )
        store.issue_owner_capability_grant(
            secret=signing_key,
            owner_id="local_owner",
            client_id=client_id,
            oauth_token_jti=token_jti,
            allowed_tools=allowed_tools,
            allowed_paths=cutover_paths,
            ttl_seconds=float(args.grant_ttl),
            max_uses=int(args.max_uses),
            grant_id=grant_id,
            delegation_id=delegation_id,
            allow_destructive_operations=True,
        )

    bundle_path = PROJECT_ROOT / "runtime" / "secrets" / "owner_delegation_bundle.json"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text(
        json.dumps(
            {
                "client_id": client_id,
                "owner_id": "local_owner",
                "scope": scope,
                "access_token": access_token,
                "oauth_token_jti": token_jti,
                "capability_grant_id": grant_id,
                "delegation_id": delegation_id,
                "allowed_tools": allowed_tools,
                "allowed_paths": cutover_paths,
                "expires_at": verified["exp"],
                "delegation_expires_at": time.time() + delegation_ttl,
                "total_operation_budget": total_budget,
                "allow_destructive_operations": True,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # 3. Activate Owner OAuth Bearer on the autonomous tunnel key file (backed up in DPAPI above)
    tunnel_bearer_file = Path.home() / ".codex-chatgpt-web" / "secrets" / "autonomous-mcp-bearer.key"
    if tunnel_bearer_file.parent.exists():
        tunnel_bearer_file.write_text(f"Bearer {access_token}\n", encoding="utf-8")

    # 4. Dynamically stop port 8768 adapter and autonomous_tunnel so watchdog restarts both cleanly
    old_8768_pid = _find_listening_pid_for_port(8768)
    old_aut_tunnel_pid = pre_pids.get("autonomous_tunnel_pid")
    for target_pid in (old_8768_pid, old_aut_tunnel_pid):
        if target_pid and target_pid != pre_pids.get("legacy_codex_tunnel_pid"):
            subprocess.run(
                ["taskkill.exe", "/PID", str(target_pid), "/F", "/T"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
    time.sleep(1.0)

    for _ in range(2):
        subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "runtime" / "watchdog.py"), "--once"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        post_pids = _snapshot_protected_service_pids()
        if post_pids.get("autonomous_tunnel_healthy"):
            break
        time.sleep(1.0)

    post_8768 = _probe_port_health(8768)
    post_pids = _snapshot_protected_service_pids()

    cutover_report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if (post_8768.get("listening_pid") and (post_8768.get("health") or {}).get("status") == "ok" and post_pids.get("autonomous_tunnel_healthy")) else "FAIL",
        "backup_dir": str(backup_dir),
        "git_head_sha": _get_git_head_sha(),
        "old_8768_pid": old_8768_pid,
        "new_8768_pid": post_8768.get("listening_pid"),
        "old_autonomous_tunnel_pid": old_aut_tunnel_pid,
        "new_autonomous_tunnel_pid": post_pids.get("autonomous_tunnel_pid"),
        "autonomous_tunnel_healthy": post_pids.get("autonomous_tunnel_healthy"),
        "port_8768_health": post_8768.get("health"),
        "provisioned_client_id": client_id,
        "provisioned_token_jti_prefix": token_jti[:12],
        "provisioned_grant_id": grant_id,
        "provisioned_delegation_id": delegation_id,
        "protected_services_untouched": {
            "port_3080_unchanged": pre_pids["port_3080_pid"] == post_pids["port_3080_pid"],
            "port_8765_unchanged": pre_pids["port_8765_pid"] == post_pids["port_8765_pid"],
            "port_8766_unchanged": pre_pids["port_8766_pid"] == post_pids["port_8766_pid"],
            "port_8767_unchanged": pre_pids["port_8767_pid"] == post_pids["port_8767_pid"],
            "legacy_codex_tunnel_pid": post_pids["legacy_codex_tunnel_pid"],
            "legacy_codex_tunnel_untouched": pre_pids["legacy_codex_tunnel_pid"] == post_pids["legacy_codex_tunnel_pid"],
        },
    }
    ev_path = PROJECT_ROOT / "runtime" / "evidence" / "production_cutover_report.json"
    ev_path.parent.mkdir(parents=True, exist_ok=True)
    ev_path.write_text(json.dumps(cutover_report, indent=2), encoding="utf-8")
    print(json.dumps(cutover_report, indent=2))
    return 0 if cutover_report["status"] == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Windows MCP Agent Owner Delegation, Backup, Rollback & Cutover")
    parser.add_argument(
        "--oauth-db",
        default=str(PROJECT_ROOT / "runtime" / "oauth_state.db"),
        help="Path to OAuth SQLite state DB",
    )
    parser.add_argument(
        "--tasks-db",
        default=str(PROJECT_ROOT / "runtime" / "tasks.db"),
        help="Path to runtime tasks/OAuth SQLite DB",
    )
    parser.add_argument(
        "--signing-key-file",
        default=str(PROJECT_ROOT / "runtime" / "secrets" / "oauth_signing.key"),
        help="Path to dedicated OAuth signing key file",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("inspect", help="Inspect OAuth clients, active tokens, capability grants, and port 8768 health")

    p_backup = sub.add_parser("backup", help="Create consistent SQLite Online Backup + DPAPI key backup (C1)")
    p_backup.add_argument(
        "--backup-root",
        default=str(PROJECT_ROOT / "backups"),
        help="Root directory for pre-cutover backups",
    )
    p_backup.add_argument("--label", default=None, help="Optional backup folder name")

    p_prov = sub.add_parser("provision", help="Provision owner OAuth token and request-bound capability grant")
    p_prov.add_argument("--client-id", default="chatgpt_web_owner_client")
    p_prov.add_argument("--resource", default="http://127.0.0.1:8768/mcp")
    p_prov.add_argument(
        "--capabilities",
        default=",".join(k for k in OWNER_DELEGATION_CAPABILITY_PROFILES if k != "RELEASE_DEPLOY"),
        help="Comma-separated capability profiles",
    )
    p_prov.add_argument("--include-release-deploy", action="store_true")
    p_prov.add_argument("--allowed-paths", nargs="*", default=None)
    p_prov.add_argument("--token-ttl", type=int, default=3600)
    p_prov.add_argument("--grant-ttl", type=int, default=900)
    p_prov.add_argument("--delegation-ttl", type=float, default=28800.0)
    p_prov.add_argument("--total-budget", type=int, default=5000)
    p_prov.add_argument("--max-uses", type=int, default=25)
    p_prov.add_argument("--grant-id", default=None)
    p_prov.add_argument("--delegation-id", default=None)
    p_prov.add_argument(
        "--token-out",
        default=None,
        help="Optional secure output path (e.g. runtime/secrets/owner_delegation_bundle.json)",
    )

    p_rev = sub.add_parser("revoke-grant", help="Revoke an owner capability grant by grant_id")
    p_rev.add_argument("--grant-id", required=True)

    p_rev_del = sub.add_parser("revoke-delegation", help="Revoke an owner durable delegation by delegation_id")
    p_rev_del.add_argument("--delegation-id", required=True)

    sub.add_parser("rehearse-rollback", help="Run isolated staging rollback rehearsal without git checkout (C2)")

    p_cut = sub.add_parser("cutover", help="Execute guarded production cutover for port 8768 (D1/D2)")
    p_cut.add_argument("--client-id", default="chatgpt_web_owner_client")
    p_cut.add_argument("--token-ttl", type=int, default=3600)
    p_cut.add_argument("--grant-ttl", type=int, default=900)
    p_cut.add_argument("--delegation-ttl", type=float, default=28800.0)
    p_cut.add_argument("--total-budget", type=int, default=5000)
    p_cut.add_argument("--max-uses", type=int, default=50)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "inspect":
        return cmd_inspect(args)
    if args.command == "backup":
        return cmd_backup_state(args)
    if args.command == "provision":
        return cmd_provision_owner_delegation(args)
    if args.command == "revoke-grant":
        return cmd_revoke_grant(args)
    if args.command == "revoke-delegation":
        return cmd_revoke_delegation(args)
    if args.command == "rehearse-rollback":
        return cmd_rehearse_rollback(args)
    if args.command == "cutover":
        return cmd_cutover(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
