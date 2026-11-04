"""Direct coding capabilities under the owner's existing trusted workspace policy.

This is a capability boundary, not an OS sandbox: owner-approved test/script code
runs as the service account. No shell strings, package installation, network Git
operations, arbitrary interpreters, or policy editing are exposed.
"""
from __future__ import annotations

import ctypes
import contextlib
import difflib
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from runtime.task_grant import TaskGrant, _has_reparse_point_or_symlink, _is_sensitive_path
from policy import PermissionTier, discover_fixed_drives, redact_secrets

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAX_FILE_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 65_536
MAX_TIMEOUT = 120


def _schema(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


_WS = {"type": "string", "minLength": 1, "maxLength": 1024}
_PATH = {"type": "string", "minLength": 1, "maxLength": 1024}
_HASH = {"type": "string", "pattern": r"^(?:[0-9a-f]{64}|missing)$"}
_HASH_STRICT = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
_GRANT_ID = {"type": "string", "minLength": 1, "maxLength": 256}
_BACKUP_ID = {"type": "string", "pattern": r"^[0-9a-f]{32}$"}
_ARGV = {"type": "array", "minItems": 1, "maxItems": 64,
         "items": {"type": "string", "minLength": 1, "maxLength": 2048}}
_COMMAND = {"workspace_root": _WS, "argv": _ARGV, "cwd": _PATH,
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT},
            "capability_grant_id": _GRANT_ID}
CODING_TOOL_DEFINITIONS = {
    "agent_workspace_list": ("List owner-approved workspaces, or bounded directory entries within one.", _schema({"workspace_root": _WS, "path": _PATH, "recursive": {"type": "boolean"}, "max_entries": {"type": "integer", "minimum": 1, "maximum": 2000}, "capability_grant_id": _GRANT_ID}, [])),
    "agent_read_file": ("Read bounded UTF-8 text and its SHA-256 in a trusted workspace.",
                        _schema({"workspace_root": _WS, "path": _PATH, "max_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_FILE_BYTES}, "start_line": {"type": "integer", "minimum": 1, "maximum": 1000000}, "end_line": {"type": "integer", "minimum": 1, "maximum": 1000000}, "capability_grant_id": _GRANT_ID}, ["workspace_root", "path"])),
    "agent_write_file": ("Atomically write UTF-8 text with expected SHA-256 (missing for new files) and durable backup.",
                         _schema({"workspace_root": _WS, "path": _PATH, "content": {"type": "string", "maxLength": MAX_FILE_BYTES}, "expected_sha256": _HASH, "capability_grant_id": _GRANT_ID, "rollback_backup_id": _BACKUP_ID}, ["workspace_root", "path", "content", "expected_sha256"])),
    "agent_apply_patch": ("Replace one unique exact text context, atomically, with expected SHA-256 and backup.",
                          _schema({"workspace_root": _WS, "path": _PATH, "old_text": {"type": "string", "minLength": 1, "maxLength": MAX_FILE_BYTES}, "new_text": {"type": "string", "maxLength": MAX_FILE_BYTES}, "expected_sha256": _HASH, "capability_grant_id": _GRANT_ID}, ["workspace_root", "path", "old_text", "new_text", "expected_sha256"])),
    "agent_run_command": ("Run structured owner-approved coding argv, never a shell. Test/script code is trusted execution, not an OS sandbox.", _schema(_COMMAND, ["workspace_root", "argv"])),
    "agent_run_tests": ("Run bounded pytest argv under owner-approved trusted execution policy.", _schema(_COMMAND, ["workspace_root"])),
    "agent_git_status": ("Read bounded Git status without external hooks or user configuration.", _schema({"workspace_root": _WS, "capability_grant_id": _GRANT_ID}, ["workspace_root"])),
    "agent_git_diff": ("Read bounded Git diff, excluding sensitive paths and external diff programs.", _schema({"workspace_root": _WS, "path": _PATH, "capability_grant_id": _GRANT_ID}, ["workspace_root"])),
}
OWNER_FILESYSTEM_TOOL_DEFINITIONS = {
    "agent_create_file": (
        "Atomically create a new UTF-8 file in an owner-approved workspace (fails if file exists unless overwrite=True).",
        _schema(
            {
                "workspace_root": _WS,
                "path": _PATH,
                "content": {"type": "string", "maxLength": MAX_FILE_BYTES},
                "overwrite": {"type": "boolean"},
                "capability_grant_id": _GRANT_ID,
            },
            ["workspace_root", "path", "content"],
        ),
    ),
    "agent_delete_file": (
        "Atomically delete an existing regular file after verifying expected SHA-256 and writing a restorable backup.",
        _schema(
            {
                "workspace_root": _WS,
                "path": _PATH,
                "expected_sha256": _HASH_STRICT,
                "capability_grant_id": _GRANT_ID,
            },
            ["workspace_root", "path", "expected_sha256"],
        ),
    ),
    "agent_create_directory": (
        "Create a directory inside an owner-approved workspace.",
        _schema(
            {
                "workspace_root": _WS,
                "path": _PATH,
                "exist_ok": {"type": "boolean"},
                "capability_grant_id": _GRANT_ID,
            },
            ["workspace_root", "path"],
        ),
    ),
    "agent_delete_directory": (
        "Delete a directory inside an owner-approved workspace (requires explicit recursive=True and destructive approval for non-empty directories).",
        _schema(
            {
                "workspace_root": _WS,
                "path": _PATH,
                "recursive": {"type": "boolean"},
                "destructive_operations_approved": {"type": "boolean"},
                "preview_only": {"type": "boolean"},
                "capability_grant_id": _GRANT_ID,
            },
            ["workspace_root", "path"],
        ),
    ),
    "agent_move_path": (
        "Atomically move or rename a file or directory within an owner-approved workspace with backup.",
        _schema(
            {
                "workspace_root": _WS,
                "source_path": _PATH,
                "destination_path": _PATH,
                "src_path": _PATH,
                "dst_path": _PATH,
                "overwrite": {"type": "boolean"},
                "capability_grant_id": _GRANT_ID,
            },
            ["workspace_root"],
        ),
    ),
    "agent_copy_path": (
        "Atomically copy a regular file within an owner-approved workspace with backup if overwriting.",
        _schema(
            {
                "workspace_root": _WS,
                "source_path": _PATH,
                "destination_path": _PATH,
                "src_path": _PATH,
                "dst_path": _PATH,
                "overwrite": {"type": "boolean"},
                "capability_grant_id": _GRANT_ID,
            },
            ["workspace_root"],
        ),
    ),
}
CODING_TOOL_NAMES = frozenset(CODING_TOOL_DEFINITIONS)
OWNER_FILESYSTEM_TOOL_NAMES = frozenset(OWNER_FILESYSTEM_TOOL_DEFINITIONS)
ALL_CODING_TOOL_DEFINITIONS = {**CODING_TOOL_DEFINITIONS, **OWNER_FILESYSTEM_TOOL_DEFINITIONS}
ALL_CODING_TOOL_NAMES = frozenset(ALL_CODING_TOOL_DEFINITIONS)
_ALIASES = {
    "agent_workspace_list": "list_directory", "agent_read_file": "read_file",
    "agent_write_file": "write_file", "agent_apply_patch": "edit_file",
    "agent_create_file": "write_file", "agent_delete_file": "write_file",
    "agent_create_directory": "create_directory", "agent_delete_directory": "write_file",
    "agent_move_path": "write_file", "agent_copy_path": "write_file",
    "agent_run_command": "powershell_execute", "agent_run_tests": "powershell_execute",
    "agent_git_status": "git_status", "agent_git_diff": "git_diff",
}
_WRITE = frozenset((
    "agent_write_file",
    "agent_apply_patch",
    "agent_create_file",
    "agent_delete_file",
    "agent_create_directory",
    "agent_delete_directory",
    "agent_move_path",
    "agent_copy_path",
    "agent_run_command",
    "agent_run_tests",
))
_SENSITIVE_PARTS = frozenset((".git", ".ssh", ".aws", ".azure", ".gcp", ".gnupg", ".kube", ".docker", ".codex", ".agents", "secrets", "credentials", "protect", "tunnel-client", "user data", "wallets"))
_SECRET_NAME = re.compile(r"(?:^\.env(?:\.|$)|(?:credential|secret|token|password|api[_-]?key)|^id_(?:rsa|ed25519|ecdsa|dsa)$|^\.(?:npmrc|pypirc|netrc|gitconfig|git-credentials)$)", re.I)
_DEVICE = re.compile(r"^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)", re.I)
_SECURITY_CONTROL_DIRS = frozenset(("runtime", "mcp-gateway", "desktop-agent", "scripts", ".github", "config"))
_SECURITY_CONTROL_FILES = frozenset((
    "http_server.py",
    "gateway_server.py",
    "cloud_autonomous_adapter.py",
    "policy.py",
    "security_policy.py",
    "task_grant.py",
    "coding_tools.py",
    "trusted_workspaces.json",
    "policy.json",
))


def _validate(value: Any, schema: dict, name: str = "arguments") -> None:
    typ = schema.get("type")
    valid = {"object": type(value) is dict, "array": type(value) is list,
             "string": type(value) is str, "integer": type(value) is int, "boolean": type(value) is bool}.get(typ, False)
    if not valid:
        raise ValueError(f"{name} must be {typ}")
    if typ == "object":
        if set(value) - set(schema["properties"]):
            raise ValueError("Unknown argument fields are not permitted")
        if set(schema.get("required", [])) - set(value):
            raise ValueError("Missing required argument fields")
        for key, item in value.items():
            _validate(item, schema["properties"][key], key)
    elif typ == "array":
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 100):
            raise ValueError(f"{name} has invalid length")
        for item in value:
            _validate(item, schema["items"], name)
    elif typ == "string":
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", MAX_FILE_BYTES):
            raise ValueError(f"{name} has invalid length")
        if schema.get("pattern") and not re.fullmatch(schema["pattern"], value):
            raise ValueError(f"{name} has invalid format")
        if "\x00" in value:
            raise ValueError("NUL is not permitted")
    elif typ == "integer" and not schema.get("minimum", value) <= value <= schema.get("maximum", value):
        raise ValueError(f"{name} is outside its bounds")


class CodingToolHandler:
    def __init__(self, store, broker, *, trusted_config_path=None, audit_path=None):
        self.store, self.broker = store, broker
        self.trusted_config_path = Path(trusted_config_path or os.environ.get("WINDOWS_MCP_TRUSTED_WORKSPACES_CONFIG") or PROJECT_ROOT / "config/trusted_workspaces.json")
        state_root = os.environ.get("MCP_STATE_ROOT")
        default_audit_db = (Path(state_root) / "logs" / "coding_audit.db") if state_root else (PROJECT_ROOT / "runtime/logs/coding_audit.db")
        self.audit_path = Path(audit_path or default_audit_db)
        self.backup_dir = self.audit_path.parent / "coding_backups"
        self._lock = threading.RLock()
        self._tls = threading.local()

    def _req_ctx(self) -> dict[str, Any]:
        return getattr(self._tls, "ctx", None) or {}

    def _audit(self, event: dict) -> None:
        # The audit location is configuration-only, never a tool argument.
        if _has_reparse_point_or_symlink(self.audit_path):
            raise PermissionError("Audit path contains a reparse point")
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("CREATE TABLE IF NOT EXISTS coding_audit (event_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, record TEXT NOT NULL)")
            conn.execute("INSERT INTO coding_audit VALUES (?, ?, ?)", (uuid.uuid4().hex, time.time(), json.dumps(redact_secrets(event), ensure_ascii=False)))

    def _stopped(self) -> bool:
        policy = getattr(self.broker, "policy", None)
        if policy is not None:
            return bool(policy.is_emergency_stop_active())
        state_root = os.environ.get("MCP_STATE_ROOT")
        stop_file = (Path(state_root) / "EMERGENCY_STOP") if state_root else (PROJECT_ROOT / "runtime/EMERGENCY_STOP")
        return bool(stop_file.exists())

    @staticmethod
    def _raw_path(raw: str) -> Path:
        if raw.startswith(("\\\\", "//")) or any(ord(c) < 32 for c in raw):
            raise PermissionError("UNC, device, or control-character paths are denied")
        # Reject ADS, Win32 normalization aliases and device names before resolution.
        tail = raw[2:] if re.match(r"^[A-Za-z]:", raw) else raw
        if ":" in tail or any(p in ("..",) or (p != "." and p.endswith((" ", "."))) or _DEVICE.match(p)
                              for p in re.split(r"[/\\]", tail) if p):
            raise PermissionError("Traversal, ADS, reserved, and ambiguous paths are denied")
        return Path(raw)

    def _path(self, root: Path, raw: str, *, write=False) -> Path:
        p = self._raw_path(raw)
        candidate = p if p.is_absolute() else root / p
        if _has_reparse_point_or_symlink(candidate):
            raise PermissionError("Symlink or reparse-point paths are denied")
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise PermissionError("Path escapes approved workspace")
        if self._sensitive(resolved, write=write, root=root):
            raise PermissionError("Sensitive or security-control path is denied")
        if resolved.exists() and resolved.is_file() and resolved.stat().st_nlink > 1:
            raise PermissionError("Hard-linked files are denied")
        return resolved

    def _is_raw_secret_or_protected_state(self, path: Path) -> bool:
        parts = [p.casefold() for p in path.parts]
        if any(p in _SENSITIVE_PARTS for p in parts):
            return True
        if _SECRET_NAME.search(path.name) or path.suffix.casefold() in (".pem", ".key", ".pfx", ".p12", ".kdbx", ".dpapi", ".db", ".sqlite", ".sqlite3"):
            return True
        if path.name.casefold() == "emergency_stop":
            return True
        if path == self.audit_path.resolve() or path.is_relative_to(self.backup_dir.resolve()):
            return True
        if re.match(r"^tunnel[-_].*\.(?:json|ya?ml)$", path.name, re.I):
            return True
        return False

    def _is_security_control_target(self, path: Path, *, write: bool = False, root: Path | None = None) -> bool:
        if path == self.trusted_config_path.resolve():
            return True
        for chk_root in (PROJECT_ROOT, root):
            if chk_root is not None and path.is_relative_to(chk_root):
                rel = path.relative_to(chk_root)
                if rel.parts:
                    top = rel.parts[0].casefold()
                    if top == "config":
                        return True
                    if write and top in ("runtime", "mcp-gateway", "desktop-agent", "scripts", ".github"):
                        return True
        if write and path.name.casefold() in _SECURITY_CONTROL_FILES:
            return True
        return False

    def _authorize_owner_security_control_access(self, path: Path, *, write: bool = False) -> bool:
        if self._stopped():
            raise PermissionError("Emergency Stop is active")
        ctx = self._req_ctx()
        principal = ctx.get("auth_principal")
        persistence = ctx.get("oauth_persistence")
        signing_key = str(ctx.get("oauth_signing_key") or "").strip()
        tool_name = str(ctx.get("tool_name") or ("agent_write_file" if write else "agent_read_file"))

        if principal is None or getattr(principal, "auth_method", "") != "oauth":
            return False
        if getattr(principal, "is_owner", False) is not True or getattr(principal, "owner_id", "") != "local_owner":
            return False
        scopes = getattr(principal, "scopes", frozenset()) or frozenset()
        if "mcp:owner" not in scopes:
            return False
        meta = getattr(principal, "metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        payload_tok = meta.get("payload") if isinstance(meta.get("payload"), dict) else {}
        client_id = str(getattr(principal, "client_id", "") or payload_tok.get("client_id") or "").strip()
        jti = str(getattr(principal, "jti", "") or payload_tok.get("jti") or meta.get("jti") or "").strip()
        if not client_id or not jti or persistence is None or len(signing_key) < 16:
            return False

        # Reuse already-consumed grant within the same atomic tool call after re-verifying path containment
        consumed = ctx.get("consumed_grant")
        if consumed is not None:
            allowed_paths = consumed.get("allowed_paths_list")
            if allowed_paths is None:
                try:
                    allowed_paths = json.loads(consumed.get("allowed_paths", "[]"))
                except Exception:
                    allowed_paths = []
            if not allowed_paths:
                return False
            resolved_target = path.resolve()
            for ap in allowed_paths:
                if str(ap).strip() in ("*", "AUTO"):
                    if self._is_security_control_target(path, write=write):
                        ctx["security_control_edit"] = True
                        ctx["authorization_mode"] = "OWNER_AUTHORIZED_SECURITY_EDIT"
                    return True
                try:
                    ap_path = Path(ap).resolve()
                    if resolved_target == ap_path or resolved_target.is_relative_to(ap_path):
                        if self._is_security_control_target(path, write=write):
                            ctx["security_control_edit"] = True
                            ctx["authorization_mode"] = "OWNER_AUTHORIZED_SECURITY_EDIT"
                        return True
                except (ValueError, OSError):
                    continue
            return False

        grant_id = str(ctx.get("capability_grant_id") or "").strip()
        if hasattr(persistence, "resolve_or_renew_owner_grant_for_token"):
            grant_id = str(
                persistence.resolve_or_renew_owner_grant_for_token(
                    secret=signing_key,
                    owner_id="local_owner",
                    client_id=client_id,
                    oauth_token_jti=jti,
                    requested_grant_id=grant_id or None,
                )
                or ""
            ).strip()
        elif not grant_id and hasattr(persistence, "find_active_owner_grant_for_token"):
            grant_id = str(
                persistence.find_active_owner_grant_for_token(
                    owner_id="local_owner",
                    client_id=client_id,
                    oauth_token_jti=jti,
                )
                or ""
            ).strip()
        if not grant_id:
            return False

        ok, _err, grant_rec = persistence.validate_and_consume_owner_grant(
            grant_id,
            secret=signing_key,
            tool_name=tool_name,
            target_path=str(path),
            expected_owner_id="local_owner",
            expected_client_id=client_id,
            oauth_token_jti=jti,
            consume=True,
            require_client_and_jti=True,
        )
        if not ok or not grant_rec:
            return False
        ctx["consumed_grant"] = grant_rec
        if self._is_security_control_target(path, write=write):
            ctx["security_control_edit"] = True
            ctx["authorization_mode"] = "OWNER_AUTHORIZED_SECURITY_EDIT"
        else:
            ctx["owner_global_filesystem"] = True
            ctx["authorization_mode"] = "OWNER_GLOBAL_FILESYSTEM"
        return True

    def _has_owner_global_filesystem_authority(self, target_path: Path | None = None) -> bool:
        if self._stopped():
            return False
        ctx = self._req_ctx()
        principal = ctx.get("auth_principal")
        if principal is None or getattr(principal, "auth_method", "") != "oauth":
            return False
        if getattr(principal, "is_owner", False) is not True or getattr(principal, "owner_id", "") != "local_owner":
            return False
        scopes = getattr(principal, "scopes", frozenset()) or frozenset()
        if "mcp:owner" not in scopes:
            return False

        persistence = ctx.get("oauth_persistence")
        signing_key = str(ctx.get("oauth_signing_key") or "").strip()
        if persistence is None or len(signing_key) < 16:
            return False

        meta = getattr(principal, "metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        payload_tok = meta.get("payload") if isinstance(meta.get("payload"), dict) else {}
        client_id = str(getattr(principal, "client_id", "") or payload_tok.get("client_id") or "").strip()
        jti = str(getattr(principal, "jti", "") or payload_tok.get("jti") or meta.get("jti") or "").strip()
        if not client_id or not jti:
            return False

        if target_path is not None:
            tool_name = str(ctx.get("tool_name") or "")
            is_write = tool_name in _WRITE
            if not self._authorize_owner_security_control_access(target_path, write=is_write):
                return False
            consumed = ctx.get("consumed_grant")
            if not consumed:
                return False
            allowed_tools = consumed.get("allowed_tools_list")
            if allowed_tools is None:
                try:
                    allowed_tools = json.loads(consumed.get("allowed_tools", "[]"))
                except Exception:
                    allowed_tools = []
            if "OWNER_GLOBAL_FILESYSTEM" in allowed_tools or "*" in allowed_tools:
                return True
            allowed_paths = consumed.get("allowed_paths_list")
            if allowed_paths is None:
                try:
                    allowed_paths = json.loads(consumed.get("allowed_paths", "[]"))
                except Exception:
                    allowed_paths = []
            resolved_target = target_path.resolve()
            for ap in allowed_paths:
                if str(ap).strip() in ("*", "AUTO"):
                    return True
                try:
                    ap_path = Path(ap).resolve()
                    if resolved_target == ap_path or resolved_target.is_relative_to(ap_path):
                        return True
                except (ValueError, OSError):
                    continue
            return False

        grant_id = str(ctx.get("capability_grant_id") or "").strip()
        if hasattr(persistence, "resolve_or_renew_owner_grant_for_token"):
            grant_id = str(
                persistence.resolve_or_renew_owner_grant_for_token(
                    secret=signing_key,
                    owner_id="local_owner",
                    client_id=client_id,
                    oauth_token_jti=jti,
                    requested_grant_id=grant_id or None,
                )
                or ""
            ).strip()
        elif not grant_id and hasattr(persistence, "find_active_owner_grant_for_token"):
            grant_id = str(
                persistence.find_active_owner_grant_for_token(
                    owner_id="local_owner",
                    client_id=client_id,
                    oauth_token_jti=jti,
                )
                or ""
            ).strip()
        if not grant_id:
            return False

        ok, _err, grant_rec = persistence.validate_and_consume_owner_grant(
            grant_id,
            secret=signing_key,
            tool_name=str(ctx.get("tool_name") or "agent_workspace_list"),
            target_path=None,
            expected_owner_id="local_owner",
            expected_client_id=client_id,
            oauth_token_jti=jti,
            consume=False,
            require_client_and_jti=True,
        )
        if not ok or not grant_rec:
            return False
        allowed_tools = grant_rec.get("allowed_tools_list")
        if allowed_tools is None:
            try:
                allowed_tools = json.loads(grant_rec.get("allowed_tools", "[]"))
            except Exception:
                allowed_tools = []
        if "OWNER_GLOBAL_FILESYSTEM" in allowed_tools or "*" in allowed_tools or "agent_workspace_list" in allowed_tools:
            return True
        return False

    def _sensitive(self, path: Path, *, write=False, root: Path | None = None) -> bool:
        if self._is_raw_secret_or_protected_state(path):
            return True

        policy = getattr(self.broker, "policy", None)
        ctx = self._req_ctx()
        surface = str(ctx.get("surface") or "local")
        principal = ctx.get("auth_principal")
        has_explicit_grant = bool(ctx.get("capability_grant_id"))
        tool_name = str(ctx.get("tool_name") or "")
        is_owner_fs_tool = tool_name in OWNER_FILESYSTEM_TOOL_NAMES

        # Local in-process unrestricted mode applies only when not on Cloud/HTTP and no principal/grant is bound
        is_local_unrestricted = (
            surface == "local"
            and principal is None
            and not has_explicit_grant
            and bool(policy and getattr(policy, "unrestricted_workspace_access", False))
        )
        if is_local_unrestricted:
            return False

        is_sec_control = self._is_security_control_target(path, write=write, root=root)
        if is_sec_control or has_explicit_grant or is_owner_fs_tool:
            if self._authorize_owner_security_control_access(path, write=write):
                return False
            return True

        if _is_sensitive_path(path):
            return True
        return bool(policy is not None and policy.is_sensitive_path_str(path, check_content=False))

    def _entries(self) -> list[dict]:
        try:
            policy = getattr(self.broker, "policy", None)
            allowed_roots = getattr(policy, "allowed_roots", None)
            is_unrestricted = bool(policy and getattr(policy, "unrestricted_workspace_access", False))
            tool_name = str(self._req_ctx().get("tool_name") or "")
            has_owner_global = (
                tool_name == "agent_workspace_list"
                and self._has_owner_global_filesystem_authority(None)
            )
            if has_owner_global or (is_unrestricted and not allowed_roots):
                drives: list[str] = []
                try:
                    drives = discover_fixed_drives()
                except Exception:
                    drives = []
                if not drives and policy:
                    drives = [str(d) for d in policy.get_roots_for_tier(PermissionTier.WRITE)]
                if not drives:
                    drives = ["C:\\"]
                entries = [
                    {
                        "workspace_root": str(d),
                        "include_subdirectories": True,
                        "allowed_tools": list(ALL_CODING_TOOL_NAMES),
                        "allowed_commands": ["*"],
                        "allowed_callers": None,
                        "owner_global_filesystem": True,
                    }
                    for d in drives
                ]
                if self.trusted_config_path.exists() and not _has_reparse_point_or_symlink(self.trusted_config_path):
                    try:
                        data = json.loads(self.trusted_config_path.read_text(encoding="utf-8"))
                        for entry in data.get("trusted_workspaces", []):
                            if not any(entry.get("workspace_root") == e.get("workspace_root") for e in entries):
                                entries.append(entry)
                    except Exception:
                        pass
                return entries
            elif is_unrestricted and allowed_roots:
                return [
                    {
                        "workspace_root": str(ar),
                        "include_subdirectories": True,
                        "allowed_tools": list(ALL_CODING_TOOL_NAMES),
                        "allowed_commands": ["*"],
                        "allowed_callers": None,
                    }
                    for ar in allowed_roots
                ]

            if _has_reparse_point_or_symlink(self.trusted_config_path):
                return []
            data = json.loads(self.trusted_config_path.read_text(encoding="utf-8"))
            if type(data) is not dict or data.get("trusted_mode_enabled") is not True:
                return []
            approved = [Path(p).resolve() for p in self.broker.list_preapproved_roots()]
            entries = []
            for entry in data.get("trusted_workspaces", []):
                root = self._raw_path(entry["workspace_root"])
                if not root.is_absolute() or _has_reparse_point_or_symlink(root):
                    continue
                root = root.resolve()
                if root.parent == root or not root.is_dir() or self._is_raw_secret_or_protected_state(root) or _is_sensitive_path(root):
                    continue
                if approved and not any(root == p or root.is_relative_to(p) for p in approved):
                    continue
                entries.append({**entry, "workspace_root": str(root)})
            return entries
        except (OSError, ValueError, TypeError, KeyError):
            return []

    def _workspace(self, raw: str, name: str, caller: str) -> tuple[Path, dict]:
        candidate = self._raw_path(raw)
        if not candidate.is_absolute() or _has_reparse_point_or_symlink(candidate):
            raise PermissionError("Workspace must be an absolute non-reparse directory")
        root = candidate.resolve()
        policy = getattr(self.broker, "policy", None)
        allowed_roots = getattr(policy, "allowed_roots", None)
        is_unrestricted = bool(policy and getattr(policy, "unrestricted_workspace_access", False))
        if is_unrestricted:
            if allowed_roots:
                in_allowed = any(root == Path(ar).resolve() or root.is_relative_to(Path(ar).resolve()) for ar in allowed_roots)
                if in_allowed:
                    if not root.is_dir():
                        raise PermissionError(f"Workspace directory does not exist: {root}")
                    if _has_reparse_point_or_symlink(root):
                        raise PermissionError("Symlink or reparse-point paths are denied")
                    entry = {
                        "workspace_root": str(root),
                        "include_subdirectories": True,
                        "allowed_tools": list(ALL_CODING_TOOL_NAMES),
                        "allowed_commands": ["*"],
                    }
                    return root, entry
            else:
                if not root.is_dir():
                    raise PermissionError(f"Workspace directory does not exist: {root}")
                if _has_reparse_point_or_symlink(root):
                    raise PermissionError("Symlink or reparse-point paths are denied")
                entry = {
                    "workspace_root": str(root),
                    "include_subdirectories": True,
                    "allowed_tools": list(ALL_CODING_TOOL_NAMES),
                    "allowed_commands": ["*"],
                }
                return root, entry

        for entry in self._entries():
            if entry.get("owner_global_filesystem"):
                continue
            trusted = Path(entry["workspace_root"])
            if root != trusted and not (entry.get("include_subdirectories", False) and root.is_relative_to(trusted)):
                continue
            if not root.is_dir() or self._is_raw_secret_or_protected_state(root) or _is_sensitive_path(root):
                continue
            callers = entry.get("allowed_callers")
            if callers is not None and caller not in callers:
                continue
            tools = entry.get("allowed_tools", [])
            if name not in tools and _ALIASES[name] not in tools:
                continue
            return root, entry

        if self._has_owner_global_filesystem_authority(root):
            if not root.is_dir():
                raise PermissionError(f"Workspace directory does not exist: {root}")
            if _has_reparse_point_or_symlink(root):
                raise PermissionError("Symlink or reparse-point paths are denied")
            if self._is_raw_secret_or_protected_state(root) or _is_sensitive_path(root):
                raise PermissionError("Sensitive or security-control path is denied")
            if not self._req_ctx().get("security_control_edit"):
                self._req_ctx()["owner_global_filesystem"] = True
            entry = {
                "workspace_root": str(root),
                "include_subdirectories": True,
                "allowed_tools": list(ALL_CODING_TOOL_NAMES),
                "allowed_commands": ["*"],
                "owner_global_filesystem": True,
            }
            return root, entry

        raise PermissionError("Workspace/tool has no owner-approved trusted workspace policy")

    def execute_tool(
        self,
        name,
        args,
        caller_tier=None,
        surface="local",
        caller_id=None,
        *,
        auth_principal=None,
        oauth_persistence=None,
        oauth_signing_key="",
    ) -> dict:
        event = {"tool": str(name), "caller_id": str(caller_id or ""), "surface": str(surface)}
        self._tls.ctx = {
            "tool_name": str(name),
            "surface": str(surface),
            "caller_id": str(caller_id or ""),
            "auth_principal": auth_principal,
            "oauth_persistence": oauth_persistence,
            "oauth_signing_key": str(oauth_signing_key or ""),
            "capability_grant_id": args.get("capability_grant_id") if isinstance(args, dict) else None,
            "consumed_grant": None,
            "security_control_edit": False,
            "owner_global_filesystem": False,
            "authorization_mode": None,
        }
        try:
            if name not in ALL_CODING_TOOL_NAMES:
                raise ValueError("Unknown coding tool")
            if isinstance(args, dict) and args.get("owner_oauth_token") is not None:
                raise PermissionError(
                    "Permission Denied (P0-02): owner_oauth_token in tool arguments is not accepted as proof of owner authorization"
                )
            _validate(args, ALL_CODING_TOOL_DEFINITIONS[name][1])
            if not isinstance(caller_id, str) or not caller_id.strip() or caller_id.casefold() in ("anonymous", "unknown", "unauthenticated", "cloud", "remote"):
                raise PermissionError("Authenticated caller identity is required")
            if caller_tier not in ("READ", "WRITE", "EXECUTE", "SYSTEM_ADMIN") or (name in _WRITE and caller_tier not in ("WRITE", "EXECUTE", "SYSTEM_ADMIN")):
                raise PermissionError("Caller capability tier does not permit this operation")
            if self._stopped():
                raise PermissionError("Emergency Stop is active")
            event.update({
                "workspace_root": args.get("workspace_root"),
                "path": args.get("path") or args.get("source_path"),
                "destination_path": args.get("destination_path"),
                "decision": "STARTED",
            })
            self._audit(event)
            if name == "agent_workspace_list" and "workspace_root" not in args:
                if any(k != "capability_grant_id" for k in args):
                    raise ValueError("Directory listing options require workspace_root")
                result = {"workspaces": [{"workspace_root": e["workspace_root"], "include_subdirectories": e.get("include_subdirectories", False), "allowed_tools": e.get("allowed_tools", [])} for e in self._entries() if e.get("allowed_callers") is None or caller_id in e["allowed_callers"]]}
            else:
                root, entry = self._workspace(args["workspace_root"], name, caller_id)
                result = self._dispatch(name, args, root, entry)
            self._audit({
                **event,
                "decision": "COMPLETED",
                "summary": {
                    k: v
                    for k, v in result.items()
                    if k in (
                        "sha256",
                        "previous_sha256",
                        "bytes_written",
                        "bytes_deleted",
                        "bytes_copied",
                        "deleted",
                        "created",
                        "moved",
                        "copied",
                        "returncode",
                        "timed_out",
                        "backup_id",
                        "audit_id",
                        "grant_id",
                        "delegation_id",
                        "authorization_mode",
                    )
                },
            })
            return {"ok": True, **redact_secrets(result)}
        except Exception as exc:
            message = redact_secrets(str(exc))
            try:
                self._audit({**event, "decision": "DENIED_OR_FAILED", "error": message})
            except Exception:
                message = "Durable audit unavailable; operation denied"
            return {"ok": False, "error": message, "status": "REJECTED"}
        finally:
            self._tls.ctx = None

    def rollback_backup(
        self,
        workspace_root: str | Path,
        path: str,
        backup_id: str,
        *,
        expected_sha256: str | None = None,
        caller_id: str = "local_owner",
        caller_tier: str = "SYSTEM_ADMIN",
        surface: str = "cloud_coding",
        auth_principal: Any = None,
        capability_grant_id: str | None = None,
        oauth_persistence: Any = None,
        oauth_signing_key: str = "",
    ) -> dict:
        """Atomically restore a durable backup created by agent_write_file, agent_apply_patch, or agent_delete_file."""
        root_p = Path(workspace_root).resolve()
        target_p = (Path(path) if Path(path).is_absolute() else root_p / path).resolve(strict=False)
        exp_sha = expected_sha256
        if exp_sha is None:
            exp_sha = hashlib.sha256(target_p.read_bytes()).hexdigest() if target_p.exists() else "missing"
        call_args: dict[str, Any] = {
            "workspace_root": str(root_p),
            "path": str(path),
            "content": "",
            "expected_sha256": exp_sha,
            "rollback_backup_id": str(backup_id),
        }
        if capability_grant_id:
            call_args["capability_grant_id"] = str(capability_grant_id)
        return self.execute_tool(
            "agent_write_file",
            call_args,
            caller_tier=caller_tier,
            surface=surface,
            caller_id=caller_id,
            auth_principal=auth_principal,
            oauth_persistence=oauth_persistence,
            oauth_signing_key=oauth_signing_key,
        )

    def _enrich_owner_audit_fields(self, audit_summary: dict[str, Any]) -> None:
        ctx = self._req_ctx()
        consumed_grant = ctx.get("consumed_grant")
        principal = ctx.get("auth_principal")
        if consumed_grant is not None:
            if ctx.get("security_control_edit"):
                audit_summary["security_control_edit"] = True
                audit_summary["authorization_mode"] = "OWNER_AUTHORIZED_SECURITY_EDIT"
            elif ctx.get("owner_global_filesystem"):
                audit_summary["owner_global_filesystem"] = True
                audit_summary["authorization_mode"] = "OWNER_GLOBAL_FILESYSTEM"
            else:
                audit_summary["security_control_edit"] = bool(ctx.get("security_control_edit", True))
                audit_summary["authorization_mode"] = ctx.get("authorization_mode") or "OWNER_AUTHORIZED_SECURITY_EDIT"
            audit_summary["grant_id"] = consumed_grant.get("grant_id")
            audit_summary["grant_used_count"] = consumed_grant.get("used_count")
            if consumed_grant.get("delegation_id"):
                audit_summary["delegation_id"] = consumed_grant.get("delegation_id")
            if principal is not None:
                p_meta = getattr(principal, "metadata", {}) if isinstance(getattr(principal, "metadata", {}), dict) else {}
                p_tok = p_meta.get("payload") if isinstance(p_meta.get("payload"), dict) else {}
                audit_summary["client_id"] = getattr(principal, "client_id", "") or p_tok.get("client_id", "")
                audit_summary["owner_id"] = getattr(principal, "owner_id", "") or p_tok.get("owner_id", "")
                audit_summary["oauth_token_jti"] = getattr(principal, "jti", "") or p_tok.get("jti", "") or p_meta.get("jti", "")

    @staticmethod
    def _read(path: Path, limit=MAX_FILE_BYTES) -> bytes:
        if not path.is_file():
            raise ValueError("Path must be an existing regular file")
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
        if len(data) > limit or b"\x00" in data:
            raise ValueError("File exceeds byte limit or is binary")
        data.decode("utf-8")
        return data

    def _write(self, root: Path, args: dict, patch=False) -> dict:
        with self._lock:
            # SQLite write lock serializes concurrent writes across worker processes.
            with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                path = self._path(root, args["path"], write=True)
                old = self._read(path) if path.exists() else None
                digest = hashlib.sha256(old).hexdigest() if old is not None else "missing"
                if digest != args["expected_sha256"]:
                    raise ValueError("Expected SHA-256 mismatch; file was not modified")
                rollback_id = args.get("rollback_backup_id")
                if rollback_id:
                    b_file = (self.backup_dir / str(rollback_id)).resolve()
                    if not b_file.is_file() or b_file.parent != self.backup_dir.resolve():
                        raise ValueError(f"Backup ID '{rollback_id}' does not exist")
                    new = b_file.read_bytes()
                    content = new.decode("utf-8")
                elif patch:
                    if old is None:
                        raise ValueError("Patch requires an existing file")
                    original = old.decode("utf-8")
                    if original.count(args["old_text"]) != 1:
                        raise ValueError("Patch context must match exactly once")
                    content = original.replace(args["old_text"], args["new_text"], 1)
                    new = content.encode("utf-8")
                else:
                    content = args["content"]
                    new = content.encode("utf-8")
                if len(new) > MAX_FILE_BYTES:
                    raise ValueError("Content exceeds byte limit")
                if self._stopped():
                    raise PermissionError("Emergency Stop is active")
                path.parent.mkdir(parents=True, exist_ok=True)
                self._path(root, args["path"], write=True)
                backup_id = None
                if old is not None:
                    if _has_reparse_point_or_symlink(self.backup_dir):
                        raise PermissionError("Backup path contains a reparse point")
                    self.backup_dir.mkdir(parents=True, exist_ok=True)
                    backup_id = uuid.uuid4().hex
                    with (self.backup_dir / backup_id).open("xb") as backup:
                        backup.write(old)
                        backup.flush()
                        os.fsync(backup.fileno())
                temp_name = None
                try:
                    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".coding-", delete=False) as temp:
                        temp_name = temp.name
                        temp.write(new)
                        temp.flush()
                        os.fsync(temp.fileno())
                    # Recheck canonical containment and precondition immediately before replace.
                    self._path(root, args["path"], write=True)
                    latest = self._read(path) if path.exists() else None
                    if latest != old or self._stopped():
                        raise PermissionError("File or emergency state changed before atomic write")
                    os.replace(temp_name, path)
                    temp_name = None
                    rel_display = str(path.relative_to(root)).replace("\\", "/") if path.is_relative_to(root) else path.name
                    diff_text = "".join(
                        difflib.unified_diff(
                            (old.decode("utf-8") if old is not None else "").splitlines(keepends=True),
                            content.splitlines(keepends=True),
                            fromfile=f"a/{rel_display}" if old is not None else "/dev/null",
                            tofile=f"b/{rel_display}",
                        )
                    )
                    audit_id = uuid.uuid4().hex
                    audit_summary: dict[str, Any] = {
                        "sha256": hashlib.sha256(new).hexdigest(),
                        "previous_sha256": digest,
                        "bytes_written": len(new),
                        "backup_id": backup_id,
                        "audit_id": audit_id,
                        "modified_paths": [str(path)],
                    }
                    if rollback_id:
                        audit_summary["rolled_back_from_backup_id"] = str(rollback_id)
                    self._enrich_owner_audit_fields(audit_summary)
                    conn.execute(
                        "INSERT INTO coding_audit VALUES (?, ?, ?)",
                        (
                            audit_id,
                            time.time(),
                            json.dumps({"decision": "WRITE_COMMITTED", "path": str(path), **audit_summary}),
                        ),
                    )
                    return {**audit_summary, "diff": diff_text}
                finally:
                    if temp_name:
                        Path(temp_name).unlink(missing_ok=True)

    def _create_file(self, root: Path, args: dict) -> dict:
        path = self._path(root, args["path"], write=True)
        overwrite = bool(args.get("overwrite", False))
        if path.exists():
            if not path.is_file():
                raise ValueError("Target path exists and is not a regular file")
            if not overwrite:
                raise ValueError("File already exists; set overwrite=True or use agent_write_file")
            exp_sha = hashlib.sha256(self._read(path)).hexdigest()
        else:
            exp_sha = "missing"
        res = self._write(
            root,
            {
                "path": args["path"],
                "content": args["content"],
                "expected_sha256": exp_sha,
            },
            patch=False,
        )
        return {"created": True, "path": str(path), **res}

    def _delete_file(self, root: Path, args: dict) -> dict:
        with self._lock:
            with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                path = self._path(root, args["path"], write=True)
                if not path.exists() or not path.is_file():
                    raise ValueError("Target path must be an existing regular file")
                old = self._read(path)
                digest = hashlib.sha256(old).hexdigest()
                if digest != args["expected_sha256"]:
                    raise ValueError("Expected SHA-256 mismatch; file was not deleted")
                if self._stopped():
                    raise PermissionError("Emergency Stop is active")
                if _has_reparse_point_or_symlink(self.backup_dir):
                    raise PermissionError("Backup path contains a reparse point")
                self.backup_dir.mkdir(parents=True, exist_ok=True)
                backup_id = uuid.uuid4().hex
                with (self.backup_dir / backup_id).open("xb") as backup:
                    backup.write(old)
                    backup.flush()
                    os.fsync(backup.fileno())
                meta_payload = {
                    "backup_id": backup_id,
                    "operation": "agent_delete_file",
                    "workspace_root": str(root),
                    "path": str(path),
                    "rel_path": str(path.relative_to(root)),
                    "previous_sha256": digest,
                    "bytes_deleted": len(old),
                    "timestamp": time.time(),
                }
                (self.backup_dir / f"{backup_id}.meta.json").write_text(
                    json.dumps(meta_payload, indent=2),
                    encoding="utf-8",
                )
                # Anti-TOCTOU recheck immediately prior to unlink
                self._path(root, args["path"], write=True)
                latest = self._read(path) if path.exists() else None
                if latest != old or self._stopped():
                    raise PermissionError("File or emergency state changed before atomic delete")
                path.unlink()
                audit_id = uuid.uuid4().hex
                audit_summary: dict[str, Any] = {
                    "deleted": True,
                    "backup_id": backup_id,
                    "path": str(path),
                    "previous_sha256": digest,
                    "bytes_deleted": len(old),
                    "audit_id": audit_id,
                    "modified_paths": [str(path)],
                }
                self._enrich_owner_audit_fields(audit_summary)
                conn.execute(
                    "INSERT INTO coding_audit VALUES (?, ?, ?)",
                    (
                        audit_id,
                        time.time(),
                        json.dumps({"decision": "DELETE_COMMITTED", **audit_summary}),
                    ),
                )
                return audit_summary

    def _create_directory(self, root: Path, args: dict) -> dict:
        with self._lock:
            with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                target = self._path(root, args["path"], write=True)
                exist_ok = bool(args.get("exist_ok", True))
                if target.exists():
                    if not target.is_dir():
                        raise ValueError("A non-directory entry already exists at target path")
                    if not exist_ok:
                        raise ValueError("Directory already exists")
                if self._stopped():
                    raise PermissionError("Emergency Stop is active")
                target.mkdir(parents=True, exist_ok=True)
                if _has_reparse_point_or_symlink(target):
                    raise PermissionError("Symlink or reparse-point paths are denied")
                audit_id = uuid.uuid4().hex
                audit_summary: dict[str, Any] = {
                    "created": True,
                    "path": str(target),
                    "audit_id": audit_id,
                    "modified_paths": [str(target)],
                }
                self._enrich_owner_audit_fields(audit_summary)
                conn.execute(
                    "INSERT INTO coding_audit VALUES (?, ?, ?)",
                    (
                        audit_id,
                        time.time(),
                        json.dumps({"decision": "MKDIR_COMMITTED", **audit_summary}),
                    ),
                )
                return audit_summary

    def _delete_directory(self, root: Path, args: dict) -> dict:
        with self._lock:
            with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                target = self._path(root, args["path"], write=True)
                if target == root:
                    raise PermissionError("Cannot delete workspace root directory")
                if not target.exists() or not target.is_dir():
                    raise ValueError("Target path must be an existing directory")
                recursive = bool(args.get("recursive", False))
                preview_only = bool(args.get("preview_only", False))

                affected_paths: list[str] = []
                files_to_backup: list[tuple[Path, str, bytes, str]] = []
                for parent, dirs, files in os.walk(target, topdown=False, followlinks=False):
                    parent_p = Path(parent)
                    for fname in files:
                        fp = parent_p / fname
                        if _has_reparse_point_or_symlink(fp):
                            raise PermissionError("Symlink or reparse-point inside directory is denied")
                        self._path(root, str(fp), write=True)
                        rel_str = str(fp.relative_to(root)).replace("\\", "/")
                        affected_paths.append(rel_str)
                        if not preview_only and recursive:
                            raw_b = self._read(fp)
                            files_to_backup.append((fp, rel_str, raw_b, hashlib.sha256(raw_b).hexdigest()))
                    for dname in dirs:
                        dp = parent_p / dname
                        if _has_reparse_point_or_symlink(dp):
                            raise PermissionError("Symlink or reparse-point inside directory is denied")
                        self._path(root, str(dp), write=True)
                        affected_paths.append(str(dp.relative_to(root)).replace("\\", "/"))

                affected_paths.sort()
                if preview_only:
                    return {
                        "deleted": False,
                        "preview_only": True,
                        "path": str(target),
                        "affected_paths": affected_paths,
                        "items_count": len(affected_paths),
                    }

                if affected_paths:
                    if not recursive:
                        raise PermissionError(
                            f"Directory is not empty ({len(affected_paths)} items); explicit recursive=True is required. Affected paths: {affected_paths[:20]}"
                        )
                    if args.get("destructive_operations_approved") is False:
                        raise PermissionError(
                            "Destructive recursive directory deletion was rejected by caller (destructive_operations_approved=False)"
                        )
                    ctx = self._req_ctx()
                    consumed_grant = ctx.get("consumed_grant")
                    surface = str(ctx.get("surface") or "local")
                    principal = ctx.get("auth_principal")
                    if surface != "local" or principal is not None or consumed_grant is not None:
                        if not consumed_grant or not bool(consumed_grant.get("allow_destructive_operations")):
                            raise PermissionError(
                                "Unapproved recursive directory deletion: active owner grant/delegation does not permit destructive recursive directory deletion (allow_destructive_operations=False)"
                            )

                if self._stopped():
                    raise PermissionError("Emergency Stop is active")
                if _has_reparse_point_or_symlink(self.backup_dir):
                    raise PermissionError("Backup path contains a reparse point")
                self.backup_dir.mkdir(parents=True, exist_ok=True)
                backup_id = uuid.uuid4().hex
                bundle_manifest = {
                    "backup_id": backup_id,
                    "operation": "agent_delete_directory",
                    "workspace_root": str(root),
                    "path": str(target),
                    "recursive": recursive,
                    "affected_paths": affected_paths,
                    "files": [
                        {
                            "rel_path": rel_s,
                            "sha256": f_sha,
                            "content": f_bytes.decode("utf-8"),
                        }
                        for (_fp, rel_s, f_bytes, f_sha) in files_to_backup
                    ],
                    "timestamp": time.time(),
                }
                (self.backup_dir / f"{backup_id}.dir_backup.json").write_text(
                    json.dumps(bundle_manifest, indent=2),
                    encoding="utf-8",
                )
                if len(files_to_backup) == 1:
                    with (self.backup_dir / backup_id).open("xb") as b_single:
                        b_single.write(files_to_backup[0][2])
                        b_single.flush()
                        os.fsync(b_single.fileno())

                if recursive:
                    shutil.rmtree(target)
                else:
                    target.rmdir()

                audit_id = uuid.uuid4().hex
                audit_summary: dict[str, Any] = {
                    "deleted": True,
                    "backup_id": backup_id,
                    "path": str(target),
                    "recursive": recursive,
                    "affected_paths": affected_paths,
                    "audit_id": audit_id,
                    "modified_paths": [str(target)],
                }
                self._enrich_owner_audit_fields(audit_summary)
                conn.execute(
                    "INSERT INTO coding_audit VALUES (?, ?, ?)",
                    (
                        audit_id,
                        time.time(),
                        json.dumps({"decision": "RMDIR_COMMITTED", **audit_summary}),
                    ),
                )
                return audit_summary

    def _move_path(self, root: Path, args: dict) -> dict:
        with self._lock:
            with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                raw_src = args.get("source_path") or args.get("src_path")
                raw_dst = args.get("destination_path") or args.get("dst_path")
                if not raw_src or not raw_dst:
                    raise ValueError("Both source_path and destination_path are required")
                src = self._path(root, raw_src, write=True)
                dst = self._path(root, raw_dst, write=True)
                if src == root or dst == root:
                    raise PermissionError("Cannot move workspace root directory")
                if not src.exists():
                    raise ValueError("Source path does not exist")
                overwrite = bool(args.get("overwrite", False))
                if dst.exists() and not overwrite:
                    raise ValueError("Destination path already exists; set overwrite=True")
                if self._stopped():
                    raise PermissionError("Emergency Stop is active")
                if _has_reparse_point_or_symlink(self.backup_dir):
                    raise PermissionError("Backup path contains a reparse point")
                self.backup_dir.mkdir(parents=True, exist_ok=True)
                backup_id = uuid.uuid4().hex
                sha256_val = None
                if src.is_file():
                    raw_src = self._read(src)
                    sha256_val = hashlib.sha256(raw_src).hexdigest()
                    with (self.backup_dir / backup_id).open("xb") as backup:
                        backup.write(raw_src)
                        backup.flush()
                        os.fsync(backup.fileno())
                dst.parent.mkdir(parents=True, exist_ok=True)
                os.replace(src, dst)
                audit_id = uuid.uuid4().hex
                audit_summary: dict[str, Any] = {
                    "moved": True,
                    "source_path": str(src),
                    "destination_path": str(dst),
                    "sha256": sha256_val,
                    "backup_id": backup_id,
                    "audit_id": audit_id,
                    "modified_paths": [str(src), str(dst)],
                }
                self._enrich_owner_audit_fields(audit_summary)
                conn.execute(
                    "INSERT INTO coding_audit VALUES (?, ?, ?)",
                    (
                        audit_id,
                        time.time(),
                        json.dumps({"decision": "MOVE_COMMITTED", **audit_summary}),
                    ),
                )
                return audit_summary

    def _copy_path(self, root: Path, args: dict) -> dict:
        with self._lock:
            with contextlib.closing(sqlite3.connect(self.audit_path, timeout=15)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                raw_src = args.get("source_path") or args.get("src_path")
                raw_dst = args.get("destination_path") or args.get("dst_path")
                if not raw_src or not raw_dst:
                    raise ValueError("Both source_path and destination_path are required")
                src = self._path(root, raw_src, write=False)
                dst = self._path(root, raw_dst, write=True)
                if not src.exists() or not src.is_file():
                    raise ValueError("Source path must be an existing regular file")
                overwrite = bool(args.get("overwrite", False))
                if dst.exists() and not overwrite:
                    raise ValueError("Destination path already exists; set overwrite=True")
                data = self._read(src)
                sha256_val = hashlib.sha256(data).hexdigest()
                if self._stopped():
                    raise PermissionError("Emergency Stop is active")
                backup_id = None
                if dst.exists() and dst.is_file():
                    old_dst = self._read(dst)
                    if _has_reparse_point_or_symlink(self.backup_dir):
                        raise PermissionError("Backup path contains a reparse point")
                    self.backup_dir.mkdir(parents=True, exist_ok=True)
                    backup_id = uuid.uuid4().hex
                    with (self.backup_dir / backup_id).open("xb") as backup:
                        backup.write(old_dst)
                        backup.flush()
                        os.fsync(backup.fileno())
                dst.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=dst.parent, prefix=".coding-copy-", delete=False) as temp:
                    temp_name = temp.name
                    temp.write(data)
                    temp.flush()
                    os.fsync(temp.fileno())
                os.replace(temp_name, dst)
                audit_id = uuid.uuid4().hex
                audit_summary: dict[str, Any] = {
                    "copied": True,
                    "source_path": str(src),
                    "destination_path": str(dst),
                    "sha256": sha256_val,
                    "bytes_copied": len(data),
                    "backup_id": backup_id,
                    "audit_id": audit_id,
                    "modified_paths": [str(dst)],
                }
                self._enrich_owner_audit_fields(audit_summary)
                conn.execute(
                    "INSERT INTO coding_audit VALUES (?, ?, ?)",
                    (
                        audit_id,
                        time.time(),
                        json.dumps({"decision": "COPY_COMMITTED", **audit_summary}),
                    ),
                )
                return audit_summary

    def _dispatch(self, name, args, root, entry):
        if name == "agent_workspace_list":
            directory = self._path(root, args.get("path", "."))
            if not directory.is_dir():
                raise ValueError("Listing path must be a directory")
            pending, entries = [directory], []
            maximum = args.get("max_entries", 200)
            scanned = 0
            while pending:
                current = pending.pop()
                with os.scandir(current) as scan:
                    for child in scan:
                        scanned += 1
                        if scanned > 10000:
                            return {"entries": entries, "truncated": True}
                        try:
                            path = self._path(root, child.path)
                        except (PermissionError, ValueError, OSError):
                            continue
                        if len(entries) >= maximum:
                            return {"entries": entries, "truncated": True}
                        is_dir = path.is_dir()
                        entries.append({"path": str(path.relative_to(root)), "type": "directory" if is_dir else "file", "bytes": None if is_dir else path.stat().st_size})
                        if is_dir and args.get("recursive", False):
                            pending.append(path)
            return {"entries": entries, "truncated": False}
        if name == "agent_read_file":
            data = self._read(self._path(root, args["path"]), args.get("max_bytes", MAX_FILE_BYTES))
            lines = data.decode("utf-8").splitlines(keepends=True)
            start, end = args.get("start_line", 1), args.get("end_line", len(lines))
            if end < start and lines:
                raise ValueError("end_line cannot precede start_line")
            text_slice = "".join(lines[start - 1:end])
            res_read: dict[str, Any] = {
                "file_text": text_slice,
                "text": text_slice,
                "content": text_slice,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "start_line": start,
                "end_line": min(end, len(lines)),
                "total_lines": len(lines),
            }
            consumed_grant = self._req_ctx().get("consumed_grant")
            if consumed_grant is not None:
                res_read["grant_id"] = consumed_grant.get("grant_id")
                res_read["grant_used_count"] = consumed_grant.get("used_count")
                if self._req_ctx().get("owner_global_filesystem") and not self._req_ctx().get("security_control_edit"):
                    res_read["authorization_mode"] = self._req_ctx().get("authorization_mode", "OWNER_GLOBAL_FILESYSTEM")
            return res_read
        if name == "agent_create_file":
            return self._create_file(root, args)
        if name == "agent_delete_file":
            return self._delete_file(root, args)
        if name == "agent_create_directory":
            return self._create_directory(root, args)
        if name == "agent_delete_directory":
            return self._delete_directory(root, args)
        if name == "agent_move_path":
            return self._move_path(root, args)
        if name == "agent_copy_path":
            return self._copy_path(root, args)
        if name in ("agent_write_file", "agent_apply_patch"):
            return self._write(root, args, name == "agent_apply_patch")
        if name in ("agent_git_status", "agent_git_diff"):
            return self._git(root, entry, name, args)
        cwd = self._path(root, args.get("cwd", "."))
        if not cwd.is_dir():
            raise ValueError("cwd must be a directory")
        argv = args.get("argv", ["python", "-m", "pytest"])
        argv = self._command(root, cwd, entry, argv, tests_only=name == "agent_run_tests")
        return self._run(argv, cwd, args.get("timeout_seconds", 60))

    def _command(self, root, cwd, entry, argv, tests_only=False):
        policy = getattr(self.broker, "policy", None)
        ctx = self._req_ctx()
        surface = str(ctx.get("surface") or "local")
        principal = ctx.get("auth_principal")
        is_owner_oauth = (
            principal is not None
            and getattr(principal, "auth_method", "") == "oauth"
            and getattr(principal, "is_owner", False) is True
            and "mcp:owner" in (getattr(principal, "scopes", frozenset()) or frozenset())
        )
        is_unrestricted = bool(
            (
                policy
                and getattr(policy, "unrestricted_workspace_access", False)
                and ((surface == "local" and principal is None) or is_owner_oauth)
            )
            or (is_owner_oauth and entry.get("owner_global_filesystem"))
        )
        if is_unrestricted:
            if not argv:
                raise PermissionError("Empty command argv is not permitted")
            exe = argv[0].casefold()
            if tests_only:
                if exe not in ("pytest", "python", "python3"):
                    raise PermissionError("agent_run_tests accepts pytest argv only")
            resolved = shutil.which(argv[0])
            if not resolved:
                raise PermissionError(f"Executable '{argv[0]}' not found on system PATH")
            if exe in ("python", "python3") and len(argv) >= 3 and argv[1:3] == ["-m", "pytest"]:
                return [sys.executable, "-I", "-m", "pytest", *argv[3:]]
            if exe == "pytest":
                return [sys.executable, "-I", "-m", "pytest", *argv[1:]]
            if exe in ("python", "python3"):
                return [sys.executable, "-I", *argv[1:]]
            return [resolved, *argv[1:]]

        # Existing grant parser adds the owner's command-pattern boundary; below
        # we narrow broad historical python*/git* patterns to reviewed forms.
        grant = TaskGrant.__new__(TaskGrant)
        grant.workspace_root, grant.allowed_paths = str(root), []
        grant.allowed_commands = entry.get("allowed_commands", [])
        valid, _, reason = grant.parse_and_validate_command(argv, cwd=cwd)
        if not valid:
            raise PermissionError(reason)
        exe = argv[0].casefold()
        if exe not in ("python", "python3", "pytest", "git"):
            raise PermissionError("Only reviewed coding executable names are permitted")
        tail = argv[1:]
        pytest_args = tail[2:] if exe in ("python", "python3") and tail[:2] == ["-m", "pytest"] else tail if exe == "pytest" else None
        if pytest_args is not None:
            # No plugin/import/config injection flags; all path operands checked.
            flags = {"-q", "-qq", "-v", "-vv", "-x", "-s", "-rA", "-ra", "--disable-warnings", "--collect-only", "--tb=short", "--tb=line", "--tb=no"}
            idx = 0
            while idx < len(pytest_args):
                arg = pytest_args[idx]
                if arg in flags or re.fullmatch(r"--maxfail=[1-9][0-9]?", arg):
                    idx += 1
                    continue
                if arg == "-k" and idx + 1 < len(pytest_args):
                    k_expr = pytest_args[idx + 1]
                    if not re.fullmatch(r"[A-Za-z0-9_.\-\s()\[\]]{1,256}", k_expr):
                        raise PermissionError("Unsupported pytest -k expression")
                    idx += 2
                    continue
                if arg.startswith("-"):
                    raise PermissionError("Unsupported pytest option")
                self._path(root, str(cwd / arg.split("::", 1)[0]))
                idx += 1
            return [sys.executable, "-I", "-m", "pytest", *pytest_args]
        if tests_only:
            raise PermissionError("agent_run_tests accepts pytest argv only")
        if exe in ("python", "python3") and tail[:2] == ["-m", "compileall"]:
            for arg in tail[2:]:
                if arg != "-q":
                    if arg.startswith("-"):
                        raise PermissionError("Unsupported compileall option")
                    self._path(root, str(cwd / arg), write=True)
            return [sys.executable, "-I", "-m", "compileall", *tail[2:]]
        # Exact structured owner opt-in can run a workspace script, never -c/-m.
        if exe in ("python", "python3") and argv in entry.get("allowed_argv", []) and tail and not tail[0].startswith("-"):
            script = self._path(root, str(cwd / tail[0]))
            if script.suffix != ".py" or not script.is_file():
                raise PermissionError("Approved script must be a workspace Python file")
            for arg in tail[1:]:
                if "/" in arg or "\\" in arg or ":" in arg or ".." in arg:
                    self._path(root, str(cwd / arg))
            return [sys.executable, "-I", str(script), *tail[1:]]
        if exe == "git" and tail in (["status"], ["diff"]):
            raise PermissionError("Use agent_git_status or agent_git_diff")
        raise PermissionError("Command form is not an approved coding capability")

    def _git(self, root, entry, name, args):
        gitdir = root / ".git"
        if not gitdir.is_dir() or _has_reparse_point_or_symlink(gitdir):
            raise PermissionError("Git requires an ordinary .git directory at workspace root")
        for relative in ("commondir", "objects/info/alternates", "objects/info/http-alternates"):
            if (gitdir / relative).exists():
                raise PermissionError("External Git object/worktree stores are denied")
        scanned = 0
        for parent, dirs, files in os.walk(gitdir, followlinks=False):
            for child in (*dirs, *files):
                scanned += 1
                if scanned > 100000 or _has_reparse_point_or_symlink(Path(parent) / child, stop_at=gitdir):
                    raise PermissionError("Git metadata is reparse-linked or exceeds inspection bounds")
        executable = shutil.which("git", path=os.environ.get("PATH", ""))
        if not executable or Path(executable).resolve().is_relative_to(root):
            raise PermissionError("Trusted Git executable unavailable")
        argv = [executable, "--no-pager", "--git-dir=" + str(gitdir), "--work-tree=" + str(root),
                "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + str(self.backup_dir / "no-hooks"), "-c", "core.untrackedCache=false"]
        # Worktree conversion can invoke clean/process filters even with
        # --no-ext-diff. Reject executable/config-include drivers before any
        # status/diff operation; never expose the raw local config to callers.
        config = self._run(argv + ["config", "--local", "--no-includes", "--null", "--list"], root, 15, redact=False)
        if config["returncode"] != 0 or config["truncated"]:
            raise PermissionError("Cannot safely inspect repository configuration")
        for record in config["stdout"].split("\x00"):
            key = record.split("\n", 1)[0].casefold()
            if key.startswith(("include.", "includeif.", "filter.", "credential.", "diff.")) or key in ("core.sshcommand", "core.worktree"):
                raise PermissionError("Repository executable drivers or external includes are denied")
        if name == "agent_git_status":
            argv += ["status", "--porcelain=v1", "--untracked-files=normal"]
        else:
            # Enumerate actual files and validate each before selecting it. This
            # prevents diff from disclosing protected files (including deletions).
            listed = self._run(argv + ["ls-files", "-z"], root, 15, redact=False)
            untracked = self._run(argv + ["ls-files", "--others", "--exclude-standard", "-z"], root, 15, redact=False)
            if listed["returncode"] != 0 or listed["truncated"] or untracked["returncode"] != 0 or untracked["truncated"]:
                raise PermissionError("Cannot safely enumerate Git file paths")
            selected = []
            requested = self._path(root, args["path"]) if "path" in args else None
            for filename in (listed["stdout"] + untracked["stdout"]).split("\x00"):
                if not filename:
                    continue
                try:
                    path = self._path(root, filename)
                except (PermissionError, ValueError):
                    continue
                if requested is None or path == requested or path.is_relative_to(requested):
                    selected.append(filename)
            if not selected:
                return {"stdout": "", "stderr": "", "returncode": 0, "timed_out": False, "truncated": False}
            if len(selected) > 512 or sum(map(len, selected)) > 20000:
                raise ValueError("Diff selection exceeds bounds; provide a narrower path")
            diff_args = ["--no-ext-diff", "--no-textconv", "--no-color", "--", *selected]
            staged = self._run(argv + ["diff", "--cached", *diff_args], root, 30)
            working = self._run(argv + ["diff", *diff_args], root, 30)
            chunks = [staged["stdout"], working["stdout"]]
            for filename in untracked["stdout"].split("\x00"):
                if filename not in selected:
                    continue
                path = self._path(root, filename)
                try:
                    lines = self._read(path).decode("utf-8").splitlines(keepends=True)
                except ValueError:
                    continue
                chunks.append("".join(difflib.unified_diff([], lines, fromfile="/dev/null", tofile="b/" + filename)))
                if sum(map(len, chunks)) > MAX_OUTPUT_BYTES:
                    break
            encoded = "".join(chunks).encode("utf-8")
            return {**working, "stdout": encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), "stderr": (staged["stderr"] + working["stderr"])[:MAX_OUTPUT_BYTES], "truncated": staged["truncated"] or working["truncated"] or len(encoded) > MAX_OUTPUT_BYTES, "timed_out": staged["timed_out"] or working["timed_out"], "returncode": staged["returncode"] or working["returncode"]}
        return self._run(argv, root, 30)

    @staticmethod
    def _job(proc):
        """Assign suspended Windows child to a kill-on-close Job before resuming."""
        if os.name != "nt":
            return None
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        handle = kernel.CreateJobObjectW(None, None)
        limits = EXTENDED()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not handle or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle, wintypes.HANDLE(int(proc._handle))):
            if handle:
                kernel.CloseHandle(handle)
            proc.kill()
            raise PermissionError("Cannot establish process-tree containment Job")
        resume = ctypes.WinDLL("ntdll").NtResumeProcess
        resume.argtypes, resume.restype = [wintypes.HANDLE], ctypes.c_long
        if resume(wintypes.HANDLE(int(proc._handle))) < 0:
            kernel.CloseHandle(handle)
            raise PermissionError("Cannot resume contained process")
        return lambda: kernel.CloseHandle(handle)

    def _run(self, argv, cwd, timeout, redact=True):
        if self._stopped():
            raise PermissionError("Emergency Stop is active")
        # Do not pass bearer/cloud credentials or Python/Git injection variables.
        safe_names = ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH", "PATHEXT", "SYSTEMDRIVE")
        env = {key: os.environ[key] for key in safe_names if key in os.environ}
        env.update({"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_LITERAL_PATHSPECS": "1", "GIT_OPTIONAL_LOCKS": "0"})
        proc = subprocess.Popen(argv, cwd=cwd, env=env, shell=False, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=(0x4 | 0x200 | 0x08000000) if os.name == "nt" else 0,
                                start_new_session=os.name != "nt")
        closer = None
        buffers = [bytearray(), bytearray()]
        truncated = [False, False]
        def drain(stream, idx):
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                keep = max(0, MAX_OUTPUT_BYTES - len(buffers[idx]))
                buffers[idx].extend(chunk[:keep])
                truncated[idx] |= len(chunk) > keep
        threads = []
        timed_out = stopped = False
        try:
            closer = self._job(proc)
            for idx, stream in enumerate((proc.stdout, proc.stderr)):
                thread = threading.Thread(target=drain, args=(stream, idx), daemon=True)
                thread.start()
                threads.append(thread)
            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                stopped = self._stopped()
                timed_out = time.monotonic() >= deadline
                if stopped or timed_out:
                    if closer:
                        closer()
                        closer = None
                    else:
                        import signal
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                    break
                time.sleep(0.05)
        finally:
            if closer:
                closer()  # Also kills descendants surviving normal parent exit.
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=5)
            for stream in (proc.stdout, proc.stderr):
                stream.close()
        result = {"stdout": bytes(buffers[0]).decode("utf-8", errors="replace"), "stderr": bytes(buffers[1]).decode("utf-8", errors="replace"), "returncode": proc.returncode, "timed_out": timed_out, "emergency_stopped": stopped, "truncated": any(truncated)}
        return redact_secrets(result) if redact else result
