"""TaskGrant Security Contract & Cryptographic Verification Broker.

Defines the TaskGrant dataclass, signing/verification logic, scope containment,
and fail-closed authorization checks for Mode 2 (TRUSTED_TASK) and Mode 3 (UNATTENDED_WORKER).
"""
from __future__ import annotations

import base64
import contextlib
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import sys

_GW_DIR = str(Path(__file__).resolve().parent.parent / "mcp-gateway")
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

from policy import (
    PermissionTier,
    TOOL_TIER_MAP,
    ControlSession,
    GatewayPolicy,
)

# Sensitive paths and filenames that are NEVER permitted for autonomous modification
SENSITIVE_FILE_PATTERNS = frozenset((
    ".env",
    ".env.*",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
    "authorized_keys",
    "windows-mcp-isolated.api_key.dpapi",
    "codex-chatgpt-web.api_key.dpapi",
    "broker_hmac.key",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*.kdbx",
    "*.dpapi",
    ".git/config",
    ".git/hooks/*",
))

SENSITIVE_SUBDIRS = frozenset((
    ".ssh",
    ".aws",
    ".azure",
    "runtime/secrets",
    "C:\\Windows",
    "C:\\Program Files",
))


def get_default_secret_path() -> Path:
    state_root = os.getenv("MCP_STATE_ROOT")
    base = Path(state_root) if state_root else Path(__file__).resolve().parent
    return base / "secrets" / "broker_hmac.key"


def get_or_create_broker_key(key_path: Path | None = None) -> bytes:
    """Retrieve or generate the local HMAC secret key stored safely outside Git."""
    target = key_path or get_default_secret_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.stat().st_size >= 32:
        try:
            os.chmod(target, 0o600)
        except Exception:
            pass
        data = target.read_bytes()
        if len(data) == 32:
            return data
        stripped = data.strip()
        if len(stripped) >= 32:
            return stripped
        return data
    import secrets
    new_key = secrets.token_bytes(32)
    target.write_bytes(new_key)
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass
    return new_key


def _has_reparse_point_or_symlink(path: Path, stop_at: Path | None = None) -> bool:
    """Check if path or any existing ancestor directory up to stop_at is a symlink or reparse point."""
    try:
        cur = path if path.is_absolute() else path.absolute()
        resolved_stop = stop_at.resolve(strict=False) if stop_at else None
        while True:
            try:
                if cur.is_symlink():
                    return True
                if cur.exists():
                    st = os.lstat(cur)
                    attrs = getattr(st, "st_file_attributes", 0)
                    if attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT (0x0400)
                        return True
            except (OSError, ValueError):
                pass
            if resolved_stop and (cur == resolved_stop or cur.resolve(strict=False) == resolved_stop):
                break
            parent = cur.parent
            if parent == cur:
                break
            cur = parent
    except Exception:
        pass
    return False


def _is_sensitive_path(path: Path) -> bool:
    """Determine if a resolved path matches any sensitive file patterns or sensitive subdirs."""
    try:
        resolved = Path(path).resolve(strict=False)
        name = resolved.name.lower()
        parts = [p.lower() for p in resolved.parts]

        # Match credential directories at every depth. Resolving a relative
        # '.aws' against the service cwd misses '<workspace>/.aws/credentials'.
        sensitive_components = {".ssh", ".aws", ".azure", ".gcp", ".gnupg", ".kube", "secrets"}
        if sensitive_components.intersection(parts):
            return True

        # Autonomous writes must not change the policy that authorizes them,
        # erase the stop latch, or alter durable authentication/task state.
        controls = {
            ("config", "trusted_workspaces.json"),
            ("config", "policy.json"),
            ("config", "tunnel-autonomous.json"),
            ("config", "tunnel-autonomous.yaml"),
            ("config", "tunnel-autonomous.yml"),
            ("runtime", "emergency_stop"),
            ("runtime", "oauth_state.db"),
            ("runtime", "tasks.db"),
        }
        if any(tuple(parts[i:i + 2]) in controls for i in range(len(parts) - 1)):
            return True

        # Check .git/config and .git/hooks/*
        for i, part in enumerate(parts):
            if part == ".git":
                if i + 1 < len(parts):
                    if parts[i + 1] in ("config", "hooks"):
                        return True

        # Check against sensitive subdirectories
        for sens_sub in SENSITIVE_SUBDIRS:
            sens_p = Path(sens_sub).resolve(strict=False)
            try:
                if resolved == sens_p or resolved.is_relative_to(sens_p):
                    return True
            except Exception:
                pass

        # The public example exception applies only after directory/control
        # checks, so a credential directory cannot hide behind this basename.
        if name == ".env.example":
            return False

        # Check sensitive file patterns
        for pat in SENSITIVE_FILE_PATTERNS:
            pat_lower = pat.lower()
            if "/" in pat_lower or "\\" in pat_lower:
                resolved_fwd = str(resolved).replace("\\", "/").lower()
                clean_pat = pat_lower.replace("/*", "")
                if f"/{clean_pat}" in resolved_fwd or resolved_fwd.endswith(f"/{clean_pat}"):
                    return True
            else:
                if fnmatch.fnmatch(name, pat_lower):
                    return True

        # Extensions: *.pem, *.key, *.pfx, *.p12, *.kdbx, *.dpapi
        sensitive_exts = (".pem", ".key", ".pfx", ".p12", ".kdbx", ".dpapi")
        if any(name.endswith(ext) for ext in sensitive_exts):
            return True

        # Any other .env variant (.env.local, .env.prod, etc.)
        if name.startswith(".env"):
            return True

        return False
    except Exception:
        return True


def compute_proposal_scope_digest(proposal: dict[str, Any]) -> str:
    """Canonicalize proposal scope fields and return a SHA-256 hex digest (G01)."""
    ws_raw = proposal.get("workspace_root", "")
    ws_canonical = str(Path(ws_raw).resolve(strict=False))

    raw_paths = proposal.get("allowed_paths")
    if raw_paths is None:
        raw_paths = proposal.get("allowed_extra_paths") or []
    canonical_paths = sorted(str(Path(p).resolve(strict=False)) for p in raw_paths)

    raw_tiers = proposal.get("allowed_permission_tiers")
    if raw_tiers is None:
        raw_tiers = ["EXECUTE", "READ", "WRITE"]
    canonical_tiers = sorted(str(t) for t in raw_tiers)

    canonical_dict = {
        "allowed_commands": sorted(str(c) for c in proposal.get("allowed_commands", [])),
        "allowed_paths": canonical_paths,
        "allowed_permission_tiers": canonical_tiers,
        "allowed_tools": sorted(str(t) for t in proposal.get("allowed_tools", [])),
        "api_cost_budget": float(proposal.get("api_cost_budget", 5.0)),
        "duration_seconds": float(proposal.get("duration_seconds", 3600.0)),
        "max_retries": int(proposal.get("max_retries", 5)),
        "max_tool_calls": int(proposal.get("max_tool_calls", 500)),
        "objective": str(proposal.get("objective", "")).strip(),
        "task_id": str(proposal.get("task_id", "")).strip(),
        "workspace_root": ws_canonical,
    }
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclass
class TaskGrant:
    grant_id: str
    task_id: str
    owner_id: str
    client_id: str
    workspace_root: str
    allowed_paths: list[str]
    allowed_tools: list[str]
    allowed_commands: list[str]
    allowed_permission_tiers: list[str]
    issued_at: float
    expires_at: float
    max_wall_time: float
    max_tool_calls: int
    max_retries: int
    max_concurrent_workers: int = 1
    resource_budget: dict[str, Any] = field(default_factory=lambda: {
        "max_cpu_percent": 80.0,
        "max_memory_mb": 2048,
        "max_file_writes": 200,
    })
    api_cost_budget: float = 5.0
    revoked: bool = False
    revoked_reason: str | None = None
    revoked_at: float | None = None
    policy_version: str = "1.3.0"
    audit_metadata: dict[str, Any] = field(default_factory=dict)
    proposal_digest: str = ""
    signature: str = ""

    def canonical_payload(self) -> str:
        """Serialize grant fields (excluding mutable state and signature) in canonical sorted JSON."""
        d = asdict(self)
        d.pop("signature", None)
        d.pop("revoked", None)
        d.pop("revoked_reason", None)
        d.pop("revoked_at", None)
        # Ensure canonical workspace root and sorted normalized paths
        d["workspace_root"] = str(Path(self.workspace_root).resolve(strict=False))
        d["allowed_paths"] = sorted(str(Path(p).resolve(strict=False)) for p in self.allowed_paths)
        d["allowed_tools"] = sorted(self.allowed_tools)
        d["allowed_commands"] = sorted(self.allowed_commands)
        d["allowed_permission_tiers"] = sorted(self.allowed_permission_tiers)
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    def sign(self, secret: bytes) -> str:
        """Sign canonical payload with HMAC-SHA256."""
        payload_bytes = self.canonical_payload().encode("utf-8")
        sig = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
        self.signature = sig
        return sig

    def verify_signature(self, secret: bytes) -> bool:
        """Constant-time verification of HMAC-SHA256 signature."""
        if not self.signature:
            return False
        payload_bytes = self.canonical_payload().encode("utf-8")
        expected = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def is_valid(self, secret: bytes, now: float | None = None) -> tuple[bool, str]:
        """Perform comprehensive validity check."""
        current_time = now if now is not None else time.time()
        if self.revoked:
            return False, f"TaskGrant {self.grant_id} is revoked: {self.revoked_reason or 'No reason provided'}"
        if current_time >= self.expires_at:
            return False, f"TaskGrant {self.grant_id} expired at {self.expires_at} (current {current_time})"
        if not self.verify_signature(secret):
            return False, f"TaskGrant {self.grant_id} has invalid cryptographic signature"
        return True, "VALID"

    def allows_tool(self, tool_name: str) -> bool:
        """Check if tool is in allowed_tools and its tier is in allowed_permission_tiers."""
        if tool_name not in self.allowed_tools:
            return False
        tier = TOOL_TIER_MAP.get(tool_name)
        if tier is None:
            return False
        if tier.value not in self.allowed_permission_tiers:
            return False
        return True

    def allows_path(self, target_path: str | Path, is_write: bool = False) -> bool:
        """Verify target path is within workspace_root or allowed_paths, and not sensitive or escaping."""
        try:
            target_str = str(target_path)
            # Rejection of UNC and ADS streams
            if target_str.startswith(("\\\\", "//")):
                return False
            if ":" in target_str[2:]:  # Alternate Data Stream check on Windows
                return False

            resolved = Path(target_path).resolve(strict=False)
            resolved_str = str(resolved).lower()
            if resolved_str.startswith(("\\\\", "//")):
                return False
            if ":" in resolved_str[2:]:
                return False

            # Realpath resolution for symlink/junction target check
            try:
                real_path = Path(os.path.realpath(target_path))
            except Exception:
                real_path = resolved

            # Sensitive path check on both resolved and realpath
            if _is_sensitive_path(resolved) or _is_sensitive_path(real_path):
                return False

            ws_root = Path(self.workspace_root).resolve(strict=False)
            allowed_roots = [Path(p).resolve(strict=False) for p in self.allowed_paths]

            # Resolved path containment check
            resolved_contained = (resolved == ws_root or resolved.is_relative_to(ws_root)) or any(
                resolved == ap or resolved.is_relative_to(ap) for ap in allowed_roots
            )
            if not resolved_contained:
                return False

            # Real path containment check (guarantees symlinks/junctions do not escape)
            real_contained = (real_path == ws_root or real_path.is_relative_to(ws_root)) or any(
                real_path == ap or real_path.is_relative_to(ap) for ap in allowed_roots
            )
            if not real_contained:
                return False

            # Check for reparse point or symlink escaping workspace
            if _has_reparse_point_or_symlink(Path(target_path), stop_at=ws_root):
                if not real_contained:
                    return False

            return True
        except Exception:
            return False

    def parse_and_validate_command(
        self, cmd: str | list[str], cwd: str | Path | None = None
    ) -> tuple[bool, list[str], str]:
        """Parse and strictly validate a shell command against grant policy and injection defenses."""
        if isinstance(cmd, list):
            argv = [str(x) for x in cmd]
            raw_cmd = " ".join(argv)
        else:
            raw_cmd = cmd.strip()
            if not raw_cmd:
                return False, [], "Empty command"
            argv = []

        # Check for forbidden control, chaining, redirection, piping, subshell, or env-expansion characters
        # ;, &&, ||, |, >, >>, <, `, $(, %, \n, \r
        forbidden_chars = [";", "&&", "||", "|", ">", "<", "`", "$(", "%", "\n", "\r"]
        for fc in forbidden_chars:
            if fc in raw_cmd:
                return False, argv, f"Command contains forbidden character or sequence: {fc!r}"

        if not argv:
            try:
                # Use posix=False on Windows so backslashes in paths aren't swallowed
                tokens = shlex.split(raw_cmd, posix=False)
                argv = [t.strip('"\'') for t in tokens if t.strip()]
            except Exception as e:
                return False, [], f"Command parse error: {e}"

        if not argv:
            return False, [], "No command tokens parsed"

        # Block dangerous flags or PowerShell/Cmd wrapper tokens anywhere in argv
        dangerous_flags = {"-encodedcommand", "-enc", "invoke-expression", "iex", "start-process"}
        for arg in argv:
            if arg.lower() in dangerous_flags:
                return False, argv, f"Forbidden dangerous flag or wrapper: {arg}"

        # Dangerous wrapper executables that should never be invoked directly
        dangerous_wrappers = {
            "cmd", "powershell", "pwsh", "bash", "sh", "wsl",
            "curl", "wget", "certutil", "bitsadmin", "reg", "sc", "schtasks", "netsh"
        }

        # Extract executable
        exe_raw = argv[0]
        exe_path = Path(exe_raw)
        exe_stem = exe_path.stem.lower()
        if exe_stem.endswith(".exe"):
            exe_stem = exe_stem[:-4]

        if exe_stem in dangerous_wrappers:
            return False, argv, f"Forbidden executable or wrapper: {exe_stem}"

        effective_cwd = Path(cwd or self.workspace_root).resolve(strict=False)

        # Path traversal / separator check on argv[0]
        if ".." in exe_raw or ("\\" in exe_raw) or ("/" in exe_raw):
            # Allow standard python/git/pytest executables or files strictly inside workspace
            if exe_stem in ("python", "python3", "git", "pytest"):
                pass
            else:
                resolved_exe = (effective_cwd / exe_raw).resolve(strict=False)
                if not self.allows_path(resolved_exe, is_write=False):
                    return False, argv, f"Executable path {exe_raw} is outside workspace"

        norm_exe_stem = "python" if exe_stem == "python3" else exe_stem

        # Specific dangerous flags for git / python
        if norm_exe_stem in ("python", "git"):
            if "-c" in argv[1:]:
                has_c_pat = any(
                    p.strip().lower().startswith(f"{norm_exe_stem} -c") or p.strip().lower() == f"{norm_exe_stem} -c*"
                    for p in self.allowed_commands
                )
                if not has_c_pat:
                    return False, argv, f"Flag -c is forbidden for {norm_exe_stem} without explicit pattern grant"

        if norm_exe_stem == "git":
            dangerous_git_flags = ("--git-dir", "--work-tree", "--upload-pack", "--exec")
            for arg in argv[1:]:
                arg_l = arg.lower()
                if any(arg_l == dgf or arg_l.startswith(f"{dgf}=") for dgf in dangerous_git_flags):
                    return False, argv, f"Dangerous git flag forbidden: {arg}"

        # Check path-like arguments in argv[1:]
        for arg in argv[1:]:
            val_to_check = arg
            if "=" in arg and arg.startswith("-"):
                val_to_check = arg.split("=", 1)[1].strip('"\'')
            if norm_exe_stem in ("pytest", "python") and "::" in val_to_check and not val_to_check.startswith("-"):
                val_to_check = val_to_check.split("::", 1)[0]
            is_path_like = (
                ("\\" in val_to_check)
                or ("/" in val_to_check)
                or (".." in val_to_check)
                or bool(re.match(r"^[a-zA-Z]:", val_to_check))
            )
            if is_path_like:
                arg_p = Path(val_to_check)
                target = arg_p if arg_p.is_absolute() else (effective_cwd / arg_p)
                if not self.allows_path(target, is_write=False):
                    return False, argv, f"Argument path {val_to_check} is outside workspace or forbidden"

        # Match against allowed_commands patterns
        matched = False
        for pattern in self.allowed_commands:
            pat = pattern.strip()
            if not pat:
                continue
            if pat.endswith("*"):
                prefix_str = pat[:-1].strip()
                if not prefix_str:
                    matched = True
                    break
                try:
                    pat_tokens = [t.strip('"\'').lower() for t in shlex.split(prefix_str, posix=False)]
                except Exception:
                    pat_tokens = [t.lower() for t in prefix_str.split()]

                if len(pat_tokens) == 1:
                    pat_exe = pat_tokens[0]
                    if pat_exe.endswith(".exe"):
                        pat_exe = pat_exe[:-4]
                    if norm_exe_stem == pat_exe:
                        matched = True
                        break
                elif len(pat_tokens) > 1:
                    pat_exe = pat_tokens[0]
                    if pat_exe.endswith(".exe"):
                        pat_exe = pat_exe[:-4]
                    if norm_exe_stem == pat_exe:
                        prefix_args = pat_tokens[1:]
                        actual_args = [a.lower() for a in argv[1:1 + len(prefix_args)]]
                        if actual_args == prefix_args:
                            matched = True
                            break
            else:
                try:
                    pat_tokens = [t.strip('"\'').lower() for t in shlex.split(pat, posix=False)]
                except Exception:
                    pat_tokens = [t.lower() for t in pat.split()]

                pat_exe = pat_tokens[0]
                if pat_exe.endswith(".exe"):
                    pat_exe = pat_exe[:-4]
                if norm_exe_stem == pat_exe:
                    if len(pat_tokens) == 1:
                        if len(argv) == 1:
                            matched = True
                            break
                    else:
                        if [a.lower() for a in argv[1:]] == pat_tokens[1:]:
                            matched = True
                            break

        if not matched:
            return False, argv, f"Command {argv[0]} does not match any allowed_commands pattern"

        return True, argv, "VALID"

    def allows_command(self, cmd: str, cwd: str | Path | None = None) -> bool:
        """Check if a shell command conforms to allowed command templates and passes security checks."""
        allowed, _, _ = self.parse_and_validate_command(cmd, cwd=cwd)
        return allowed

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskGrant:
        return cls(**data)

    def to_control_session(self) -> ControlSession:
        """Convert TaskGrant to a Gateway ControlSession for seamless Gateway integration."""
        tiers = {PermissionTier(t) for t in self.allowed_permission_tiers if t in PermissionTier._value2member_map_}
        paths = tuple(Path(p).resolve(strict=False) for p in self.allowed_paths + [self.workspace_root])
        return ControlSession(
            session_id=self.task_id,
            tiers=tiers,
            created_at=self.issued_at,
            expires_at=self.expires_at,
            approval_token=self.signature,
            client_id=self.client_id,
            allowed_paths=paths,
            allowed_commands=tuple(self.allowed_commands),
            allowed_tools=frozenset(self.allowed_tools),
            revoked=self.revoked,
            revoked_reason=self.revoked_reason,
        )


def _row_to_grant(row: sqlite3.Row) -> TaskGrant:
    """Convert a SQLite row to a TaskGrant dataclass instance."""
    row_keys = row.keys() if hasattr(row, "keys") else ()
    return TaskGrant(
        grant_id=row["grant_id"],
        task_id=row["task_id"],
        owner_id=row["owner_id"],
        client_id=row["client_id"],
        workspace_root=row["workspace_root"],
        allowed_paths=json.loads(row["allowed_paths"]),
        allowed_tools=json.loads(row["allowed_tools"]),
        allowed_commands=json.loads(row["allowed_commands"]),
        allowed_permission_tiers=json.loads(row["allowed_permission_tiers"]),
        issued_at=float(row["issued_at"]),
        expires_at=float(row["expires_at"]),
        max_wall_time=float(row["max_wall_time"]),
        max_tool_calls=int(row["max_tool_calls"]),
        max_retries=int(row["max_retries"]),
        max_concurrent_workers=int(row["max_concurrent_workers"]),
        resource_budget=json.loads(row["resource_budget"]),
        api_cost_budget=float(row["api_cost_budget"]),
        revoked=bool(row["revoked"]),
        revoked_reason=row["revoked_reason"],
        revoked_at=float(row["revoked_at"]) if row["revoked_at"] is not None else None,
        policy_version=row["policy_version"],
        audit_metadata=json.loads(row["audit_metadata"]) if row["audit_metadata"] else {},
        proposal_digest=row["proposal_digest"] if "proposal_digest" in row_keys else "",
        signature=row["signature"],
    )


class TaskGrantBroker:
    """Local Trusted Broker for minting, validating, and managing TaskGrants."""

    def __init__(
        self,
        key_path: Path | None = None,
        policy: GatewayPolicy | None = None,
        db_path: Path | str | None = None,
        preapproved_roots: list[str | Path] | None = None,
        require_preapproved_roots: bool = False,
    ):
        state_root = os.getenv("MCP_STATE_ROOT")
        default_db = (Path(state_root) / "tasks.db") if state_root else (Path(__file__).resolve().parent / "tasks.db")
        self.db_path = (
            Path(db_path).resolve()
            if db_path is not None
            else default_db.resolve()
        )
        if key_path is None and db_path is not None:
            key_path = self.db_path.parent / "secrets" / "broker_hmac.key"
        self.key_path = Path(key_path).resolve() if key_path is not None else get_default_secret_path()
        self.secret = get_or_create_broker_key(self.key_path)
        self.policy = policy
        self.preapproved_roots: list[Path] = (
            [Path(r).resolve(strict=False) for r in preapproved_roots]
            if preapproved_roots is not None
            else []
        )
        self.require_preapproved_roots = bool(require_preapproved_roots)
        self._init_db()
        self._grants: dict[str, TaskGrant] = {}

    @contextlib.contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS task_grants (
                    grant_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    allowed_paths TEXT NOT NULL,
                    allowed_tools TEXT NOT NULL,
                    allowed_commands TEXT NOT NULL,
                    allowed_permission_tiers TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    max_wall_time REAL NOT NULL,
                    max_tool_calls INTEGER NOT NULL,
                    max_retries INTEGER NOT NULL,
                    max_concurrent_workers INTEGER NOT NULL,
                    resource_budget TEXT NOT NULL,
                    api_cost_budget REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_reason TEXT,
                    revoked_at REAL,
                    policy_version TEXT NOT NULL,
                    audit_metadata TEXT NOT NULL,
                    proposal_digest TEXT NOT NULL DEFAULT '',
                    signature TEXT NOT NULL
                )
                """
            )
            try:
                conn.execute("ALTER TABLE task_grants ADD COLUMN proposal_digest TEXT NOT NULL DEFAULT ''")
            except Exception:
                pass

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_task_grants_task_id ON task_grants(task_id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_tokens_used (
                    nonce TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    scope_digest TEXT NOT NULL,
                    used_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preapproved_roots (
                    root_path TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    added_at REAL NOT NULL
                )
                """
            )

    def _save_grant(self, grant: TaskGrant) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO task_grants (
                    grant_id, task_id, owner_id, client_id, workspace_root,
                    allowed_paths, allowed_tools, allowed_commands, allowed_permission_tiers,
                    issued_at, expires_at, max_wall_time, max_tool_calls, max_retries,
                    max_concurrent_workers, resource_budget, api_cost_budget,
                    revoked, revoked_reason, revoked_at, policy_version,
                    audit_metadata, proposal_digest, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    grant.grant_id,
                    grant.task_id,
                    grant.owner_id,
                    grant.client_id,
                    grant.workspace_root,
                    json.dumps(grant.allowed_paths),
                    json.dumps(grant.allowed_tools),
                    json.dumps(grant.allowed_commands),
                    json.dumps(grant.allowed_permission_tiers),
                    grant.issued_at,
                    grant.expires_at,
                    grant.max_wall_time,
                    grant.max_tool_calls,
                    grant.max_retries,
                    grant.max_concurrent_workers,
                    json.dumps(grant.resource_budget),
                    grant.api_cost_budget,
                    1 if grant.revoked else 0,
                    grant.revoked_reason,
                    grant.revoked_at,
                    grant.policy_version,
                    json.dumps(grant.audit_metadata),
                    grant.proposal_digest,
                    grant.signature,
                ),
            )

    def onboard_workspace_root(self, root_path: str | Path, owner_id: str = "local_admin") -> str:
        """Onboard and persist an approved workspace root with strict directory validation (G03)."""
        p = Path(root_path).resolve(strict=False)

        # 1. Drive root rejection
        if p == Path(p.anchor) or len(p.parts) <= 1 or p.parent == p:
            raise PermissionError(f"Drive root {p} cannot be onboarded as a workspace root (G03)")

        # 2. Sensitive directory rejection
        for sens_sub in SENSITIVE_SUBDIRS:
            sens_p = Path(sens_sub).resolve(strict=False)
            is_sens = False
            try:
                is_sens = (p == sens_p or p.is_relative_to(sens_p))
            except (ValueError, OSError):
                pass
            if is_sens:
                raise PermissionError(f"Cannot onboard sensitive directory as workspace root (G03): {p}")

        # 3. Sensitive file rejection
        if _is_sensitive_path(p):
            raise PermissionError(f"Path {p} matches sensitive path rules and cannot be onboarded (G03)")

        # 4. Check for symlinks/reparse point escaping
        if _has_reparse_point_or_symlink(p):
            raise PermissionError("Cannot onboard path containing reparse points or symlinks (G03)")
        try:
            real_p = Path(os.path.realpath(p))
            if real_p != p and not real_p.is_relative_to(p):
                raise PermissionError("Path contains reparse/junction escape (G03)")
        except Exception:
            pass

        canonical = str(p)
        owner = owner_id.strip() if owner_id else "local_admin"
        now = time.time()

        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO preapproved_roots (root_path, owner_id, added_at) VALUES (?, ?, ?)",
                (canonical, owner, now),
            )

        if self.preapproved_roots is None:
            self.preapproved_roots = []
        if p not in self.preapproved_roots:
            self.preapproved_roots.append(p)

        return canonical

    def list_preapproved_roots(self) -> list[Path]:
        """Return union of in-memory preapproved roots and roots persisted in SQLite (G03)."""
        roots: set[Path] = set()
        if self.preapproved_roots:
            roots.update(self.preapproved_roots)
        with self._get_conn() as conn:
            rows = conn.execute("SELECT root_path FROM preapproved_roots").fetchall()
            for row in rows:
                roots.add(Path(row["root_path"]).resolve(strict=False))
        return sorted(roots)

    def generate_owner_approval_token(
        self,
        task_id: str,
        workspace_root: str | Path,
        scope_digest: str = "",
        owner_id: str = "local_admin",
        ttl_seconds: float = 600.0,
    ) -> str:
        """Generate cryptographically scoped, single-use owner approval token (G01)."""
        if not task_id or task_id.strip() == "*" or "*" in task_id:
            raise PermissionError("Wildcard task_id approval ('*') is strictly forbidden (G01)")
        if not owner_id or owner_id.strip().lower() in ("", "anonymous", "untrusted", "none"):
            raise PermissionError("Explicit authorizing owner_id is required (G01)")

        task_id_clean = task_id.strip()
        owner_id_clean = owner_id.strip()
        ws_canonical = str(Path(workspace_root).resolve(strict=False))
        nonce = secrets.token_hex(16)
        expires_at = time.time() + float(ttl_seconds)

        sign_data = f"OWNER_APPROVAL_V2|{task_id_clean}|{ws_canonical}|{scope_digest}|{owner_id_clean}|{expires_at:.3f}|{nonce}"
        sig = hmac.new(self.secret, sign_data.encode("utf-8"), hashlib.sha256).hexdigest()

        payload = {
            "v": 2,
            "task_id": task_id_clean,
            "workspace_root": ws_canonical,
            "owner_id": owner_id_clean,
            "expires_at": expires_at,
            "nonce": nonce,
            "scope_digest": scope_digest,
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
        return f"v2.{payload_b64}.{sig}"

    def verify_owner_approval_token(
        self,
        task_id: str,
        workspace_root: str | Path,
        token: str,
        expected_scope_digest: str | None = None,
        expected_owner_id: str | None = None,
        consume: bool = True,
    ) -> bool:
        """Verify owner approval token with anti-replay and scope digest verification (G01)."""
        if not task_id or "*" in task_id or not token:
            return False
        if not isinstance(token, str):
            return False

        task_id_clean = task_id.strip()
        ws_canonical = str(Path(workspace_root).resolve(strict=False))

        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "v2":
            return False

        payload_b64, sig = parts[1], parts[2]
        rem = len(payload_b64) % 4
        if rem:
            payload_b64 += "=" * (4 - rem)
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return False

        for k in ("task_id", "workspace_root", "owner_id", "expires_at", "nonce", "scope_digest"):
            if k not in payload:
                return False

        token_task_id = payload["task_id"]
        token_ws = payload["workspace_root"]
        token_scope = payload["scope_digest"]
        token_owner = payload["owner_id"]
        try:
            token_expires = float(payload["expires_at"])
        except (ValueError, TypeError):
            return False
        token_nonce = payload["nonce"]

        # Constant-time HMAC verification
        sign_data = f"OWNER_APPROVAL_V2|{token_task_id}|{token_ws}|{token_scope}|{token_owner}|{token_expires:.3f}|{token_nonce}"
        expected_sig = hmac.new(self.secret, sign_data.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False

        # Task ID verification
        if token_task_id != task_id_clean:
            return False

        # Workspace root verification
        if str(Path(token_ws).resolve(strict=False)) != ws_canonical:
            return False

        # Expiration verification
        if time.time() >= token_expires:
            return False

        # Owner ID verification
        if not token_owner or token_owner.lower() in ("", "anonymous", "untrusted", "none"):
            return False
        if expected_owner_id is not None and token_owner != expected_owner_id:
            return False

        # Scope digest verification
        if expected_scope_digest:
            if not hmac.compare_digest(token_scope, expected_scope_digest):
                return False
        elif token_scope and expected_scope_digest is not None:
            if not hmac.compare_digest(token_scope, expected_scope_digest):
                return False

        # Anti-replay check & single-use consumption
        with self._get_conn() as conn:
            row = conn.execute("SELECT 1 FROM approval_tokens_used WHERE nonce = ?", (token_nonce,)).fetchone()
            if row is not None:
                return False
            if consume:
                try:
                    conn.execute(
                        "INSERT INTO approval_tokens_used (nonce, task_id, owner_id, scope_digest, used_at) VALUES (?, ?, ?, ?, ?)",
                        (token_nonce, token_task_id, token_owner, token_scope, time.time()),
                    )
                except sqlite3.IntegrityError:
                    return False

        return True

    def issue_grant(
        self,
        task_id: str,
        workspace_root: str | Path,
        allowed_tools: list[str],
        allowed_commands: list[str],
        allowed_permission_tiers: list[str],
        duration_seconds: float = 3600.0,
        owner_id: str = "local_admin",
        client_id: str = "autonomous_worker",
        resource_budget: dict[str, Any] | None = None,
        api_cost_budget: float = 5.0,
        allowed_extra_paths: list[str] | None = None,
        audit_metadata: dict[str, Any] | None = None,
        proposal_digest: str = "",
    ) -> TaskGrant:
        """Mint and cryptographically sign a new TaskGrant with preapproved scope enforcement."""
        now = time.time()
        grant_id = f"grant_{uuid.uuid4().hex[:16]}"

        # G01: Reject empty or wildcard task_id
        if not task_id or task_id.strip() == "*" or "*" in task_id:
            raise PermissionError("Wildcard task_id ('*') is strictly forbidden for TaskGrant (G01)")

        # 1. Reject SYSTEM_ADMIN permission tier
        for tier in allowed_permission_tiers:
            tier_val = tier.value if hasattr(tier, "value") else str(tier)
            if tier_val == PermissionTier.SYSTEM_ADMIN.value or tier_val == "SYSTEM_ADMIN":
                raise PermissionError("SYSTEM_ADMIN tier is not permitted for autonomous task grants")

        # 2. Reject SYSTEM_ADMIN tools
        system_admin_tools = {"modify_firewall", "modify_defender", "edit_registry"}
        for tool in allowed_tools:
            if tool in system_admin_tools:
                raise PermissionError(f"Tool {tool} requires SYSTEM_ADMIN tier and is not permitted")
            t_tier = TOOL_TIER_MAP.get(tool)
            if t_tier == PermissionTier.SYSTEM_ADMIN:
                raise PermissionError(f"Tool {tool} requires SYSTEM_ADMIN tier and is not permitted")

        # G03: Active preapproved roots fail-closed check
        active_roots = self.list_preapproved_roots()
        if self.require_preapproved_roots and not active_roots:
            raise PermissionError("Fail-closed (G03): No preapproved workspace roots configured in TaskGrantBroker")

        # 3. Validate workspace_root and allowed_extra_paths containment
        def _check_and_normalize_path(p_in: str | Path, is_extra: bool = False) -> Path:
            p = Path(p_in).resolve(strict=False)

            # Check drive root
            if p == Path(p.anchor) or len(p.parts) <= 1 or p.parent == p:
                raise PermissionError(
                    f"Drive root {p} is not permitted as {'extra path' if is_extra else 'workspace_root'}"
                )

            # Check sensitive directories
            for sens_sub in SENSITIVE_SUBDIRS:
                sens_p = Path(sens_sub).resolve(strict=False)
                is_sens = False
                try:
                    is_sens = (p == sens_p or p.is_relative_to(sens_p))
                except (ValueError, OSError):
                    pass
                if is_sens:
                    raise PermissionError(f"Path {p} is inside sensitive directory {sens_sub}")

            # Check sensitive files
            if _is_sensitive_path(p):
                raise PermissionError(f"Path {p} matches sensitive path rules")

            # Check active preapproved_roots if configured
            if active_roots:
                if self.policy and getattr(self.policy, "unrestricted_workspace_access", False):
                    pass
                elif not any(p == pr or p.is_relative_to(pr) for pr in active_roots):
                    raise PermissionError("Requested workspace is outside owner preapproved roots")

            return p

        ws_resolved = _check_and_normalize_path(workspace_root, is_extra=False)
        ws_canonical = str(ws_resolved)

        allowed_paths = [ws_canonical]
        if allowed_extra_paths:
            for ep in allowed_extra_paths:
                ep_resolved = _check_and_normalize_path(ep, is_extra=True)
                allowed_paths.append(str(ep_resolved))

        eff_budget = {
            "max_cpu_percent": 80.0,
            "max_memory_mb": 2048,
            "max_file_writes": 200,
            **(resource_budget or {}),
        }
        grant = TaskGrant(
            grant_id=grant_id,
            task_id=task_id,
            owner_id=owner_id,
            client_id=client_id,
            workspace_root=ws_canonical,
            allowed_paths=allowed_paths,
            allowed_tools=allowed_tools,
            allowed_commands=allowed_commands,
            allowed_permission_tiers=allowed_permission_tiers,
            issued_at=now,
            expires_at=now + duration_seconds,
            max_wall_time=duration_seconds,
            max_tool_calls=int(eff_budget.get("max_tool_calls", 500)),
            max_retries=int(eff_budget.get("max_retries", 5)),
            resource_budget=eff_budget,
            api_cost_budget=api_cost_budget,
            revoked=False,
            revoked_reason=None,
            revoked_at=None,
            policy_version="1.3.0",
            audit_metadata=audit_metadata or {},
            proposal_digest=proposal_digest,
        )
        grant.sign(self.secret)
        self._save_grant(grant)
        self._grants[grant.grant_id] = grant

        # Register session in GatewayPolicy if attached
        if self.policy is not None:
            sess = grant.to_control_session()
            self.policy.sessions.register_session(sess)

        return grant

    def validate_grant(
        self,
        grant: TaskGrant | str,
        now: float | None = None,
        expected_task_id: str | None = None,
    ) -> tuple[bool, str]:
        """Validate an existing grant against signature, durable revocation in SQLite, cross-task binding, and expiration."""
        if isinstance(grant, str):
            g = self.get_grant(grant)
            if g is None:
                return False, f"TaskGrant {grant} not found in durable store"
            grant = g

        # ALWAYS query durable SQLite store to ensure cross-process revocations & integrity are observed
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM task_grants WHERE grant_id = ?",
                (grant.grant_id,),
            ).fetchone()
            if row is None:
                return False, "TaskGrant not found in durable store"

            if row["revoked"] == 1:
                grant.revoked = True
                grant.revoked_reason = row["revoked_reason"]
                return False, f"TaskGrant {grant.grant_id} is revoked in durable store: {grant.revoked_reason}"

            # Detect field tampering between SQLite and in-memory object (G02)
            if row["task_id"] != grant.task_id:
                return False, f"Tampering detected: task_id mismatch between memory ({grant.task_id}) and store ({row['task_id']})"
            if row["owner_id"] != grant.owner_id:
                return False, f"Tampering detected: owner_id mismatch between memory ({grant.owner_id}) and store ({row['owner_id']})"
            if row["client_id"] != grant.client_id:
                return False, f"Tampering detected: client_id mismatch between memory ({grant.client_id}) and store ({row['client_id']})"
            if row["signature"] != grant.signature:
                return False, f"Tampering detected: signature mismatch between memory ({grant.signature}) and store ({row['signature']})"

        # Cross-task grant reuse rejection (G02)
        if expected_task_id is not None and grant.task_id != expected_task_id:
            return False, f"Cross-task grant reuse denied (G02): Grant {grant.grant_id} is bound to task {grant.task_id}, not {expected_task_id}"

        return grant.is_valid(self.secret, now=now)

    def revoke_grant(self, grant_id: str, reason: str = "Owner manual revocation") -> bool:
        """Revoke a grant in durable SQLite store, in-memory cache, and invalidate Gateway session."""
        now = time.time()
        task_id: str | None = None
        with self._get_conn() as conn:
            row = conn.execute("SELECT task_id FROM task_grants WHERE grant_id = ?", (grant_id,)).fetchone()
            if row is not None:
                task_id = row["task_id"]
            elif grant_id in self._grants:
                task_id = self._grants[grant_id].task_id

            cursor = conn.execute(
                "UPDATE task_grants SET revoked = 1, revoked_reason = ?, revoked_at = ? WHERE grant_id = ?",
                (reason, now, grant_id),
            )
            row_updated = cursor.rowcount > 0

        if grant_id in self._grants:
            self._grants[grant_id].revoked = True
            self._grants[grant_id].revoked_reason = reason
            self._grants[grant_id].revoked_at = now

        if self.policy is not None and task_id:
            self.policy.sessions.revoke_session(task_id, reason=reason)

        return row_updated or (grant_id in self._grants)

    def get_grant(self, grant_id: str) -> TaskGrant | None:
        """Retrieve grant from durable SQLite store, syncing in-memory cache and revocations."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM task_grants WHERE grant_id = ?", (grant_id,)).fetchone()
            if row is None:
                return self._grants.get(grant_id)

            if grant_id in self._grants:
                cached = self._grants[grant_id]
                if row["revoked"] == 1:
                    cached.revoked = True
                    cached.revoked_reason = row["revoked_reason"]
                    cached.revoked_at = float(row["revoked_at"]) if row["revoked_at"] is not None else None
                elif cached.signature != row["signature"]:
                    self._save_grant(cached)
                return cached

            grant = _row_to_grant(row)
            self._grants[grant.grant_id] = grant
            return grant

    def get_grant_for_task(self, task_id: str) -> TaskGrant | None:
        """Find the active grant bound to a specific task_id from durable SQLite store."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM task_grants WHERE task_id = ? ORDER BY issued_at DESC LIMIT 1",
                (task_id,),
            ).fetchone()
            if row is None:
                for g in self._grants.values():
                    if g.task_id == task_id:
                        return g
                return None

            grant_id = row["grant_id"]
            if grant_id in self._grants:
                cached = self._grants[grant_id]
                if row["revoked"] == 1:
                    cached.revoked = True
                    cached.revoked_reason = row["revoked_reason"]
                    cached.revoked_at = float(row["revoked_at"]) if row["revoked_at"] is not None else None
                elif cached.signature != row["signature"]:
                    self._save_grant(cached)
                return cached

            grant = _row_to_grant(row)
            self._grants[grant.grant_id] = grant
            return grant
