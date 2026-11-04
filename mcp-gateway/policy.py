"""Phase P5.1 - P5.3 & SEC-03 Security Policy, Capability Tiers, Path/Command Safeguards,
Revocable Time-Limited Control Sessions, and Structured Audit Logging with Redaction.
"""
from __future__ import annotations

import ctypes
import gc
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import psutil

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "policy.json"

_DRIVE_FIXED = 3


class PermissionTier(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    DESKTOP = "DESKTOP"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


# 15 reviewed read-only tools from Bridge v0.2.1
V021_READ_TOOLS: frozenset[str] = frozenset((
    "get_roots",
    "list_directory",
    "list_tree",
    "stat_path",
    "read_file",
    "read_file_range",
    "get_file",
    "search_files",
    "search_code",
    "grep",
    "disk_usage",
    "path_exists",
    "git_status",
    "git_diff",
    "git_log",
))

TOOL_TIER_MAP: dict[str, PermissionTier] = {
    # V0.2.1 Read Tools
    **{name: PermissionTier.READ for name in V021_READ_TOOLS},
    # Additional Read / Inspection Tools
    "git_worktree_list": PermissionTier.READ,
    "get_desktop_session_status": PermissionTier.READ,
    "get_screen_geometry": PermissionTier.READ,
    "screenshot": PermissionTier.READ,
    "list_windows": PermissionTier.READ,
    "get_active_window": PermissionTier.READ,
    # P2.1 & P2.2 Write Tools
    "create_directory": PermissionTier.WRITE,
    "write_file": PermissionTier.WRITE,
    "append_file": PermissionTier.WRITE,
    "edit_file": PermissionTier.WRITE,
    "apply_patch": PermissionTier.WRITE,
    "copy_file": PermissionTier.WRITE,
    "move_file": PermissionTier.WRITE,
    "rename_file": PermissionTier.WRITE,
    "delete_file": PermissionTier.WRITE,
    "put_file": PermissionTier.WRITE,
    "restore_file": PermissionTier.WRITE,
    "git_branch_create": PermissionTier.WRITE,
    "git_add_commit": PermissionTier.WRITE,
    # P2.3 Execute & Job Tools
    "powershell_execute": PermissionTier.EXECUTE,
    "cmd_execute": PermissionTier.EXECUTE,
    "process_start": PermissionTier.EXECUTE,
    "process_status": PermissionTier.EXECUTE,
    "process_stop": PermissionTier.EXECUTE,
    "job_create": PermissionTier.EXECUTE,
    "job_poll": PermissionTier.EXECUTE,
    "job_cancel": PermissionTier.EXECUTE,
    "job_logs": PermissionTier.EXECUTE,
    # P3 Desktop Manipulation Tools
    "focus_window": PermissionTier.DESKTOP,
    "mouse_move": PermissionTier.DESKTOP,
    "mouse_click": PermissionTier.DESKTOP,
    "mouse_double_click": PermissionTier.DESKTOP,
    "mouse_right_click": PermissionTier.DESKTOP,
    "mouse_scroll": PermissionTier.DESKTOP,
    "mouse_drag": PermissionTier.DESKTOP,
    "keyboard_type": PermissionTier.DESKTOP,
    "keyboard_keypress": PermissionTier.DESKTOP,
    "keyboard_hotkey": PermissionTier.DESKTOP,
    "get_clipboard_text": PermissionTier.DESKTOP,
    "set_clipboard_text": PermissionTier.DESKTOP,
    "visual_action_verify": PermissionTier.DESKTOP,
    # P5 System Admin (blocked by default)
    "system_admin_exec": PermissionTier.SYSTEM_ADMIN,
    "modify_firewall": PermissionTier.SYSTEM_ADMIN,
    "modify_defender": PermissionTier.SYSTEM_ADMIN,
    "edit_registry": PermissionTier.SYSTEM_ADMIN,
    # Sprint 5 Autonomous Full Agent Tools
    "agent_submit_task": PermissionTier.WRITE,
    "agent_approve_task": PermissionTier.WRITE,
    "agent_task_status": PermissionTier.READ,
    "agent_task_logs": PermissionTier.READ,
    "agent_task_diff": PermissionTier.READ,
    "agent_task_artifacts": PermissionTier.READ,
    "agent_list_tasks": PermissionTier.READ,
    "agent_task_pause": PermissionTier.WRITE,
    "agent_task_resume": PermissionTier.WRITE,
    "agent_task_cancel": PermissionTier.WRITE,
    "agent_emergency_stop": PermissionTier.WRITE,
}

# Patterns for automatic secret redaction in audit logs & command outputs
_SECRET_KEY_NAMES = frozenset((
    "token", "api_key", "apikey", "secret", "password", "passwd", "pwd",
    "authorization", "auth_token", "access_token", "refresh_token",
    "private_key", "client_secret", "approval_token", "master_key",
))

_SECRET_TEXT_PATTERNS = (
    re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(
        r"((?:api[_-]?key|secret|token|password|passwd|pwd|authorization|client_secret)\s*[:=]\s*['\"]?)([^\s'\",;}{]+)",
        re.IGNORECASE,
    ),
    re.compile(r"\b(sk-[A-Za-z0-9_\-]{12,})\b"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b(AIza[0-9A-Za-z\-_]{20,})\b"),
    re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{12,})\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
)


def redact_secrets(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact secrets, tokens, keys, and passwords from strings, dicts, and lists."""
    if _depth > 8:
        return "[MAX_DEPTH_REDACTED]"
    if isinstance(value, str):
        text = value
        # Replace PEM blocks first
        text = _SECRET_TEXT_PATTERNS[-1].sub("[REDACTED_PRIVATE_KEY]", text)
        text = _SECRET_TEXT_PATTERNS[0].sub(r"\1[REDACTED]", text)
        text = _SECRET_TEXT_PATTERNS[1].sub(r"\1[REDACTED]", text)
        for pat in _SECRET_TEXT_PATTERNS[2:-1]:
            text = pat.sub("[REDACTED_SECRET]", text)
        return text
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            k_str = str(k)
            if k_str.casefold() in _SECRET_KEY_NAMES or any(
                s in k_str.casefold() for s in ("secret", "password", "api_key", "private_key", "token")
            ):
                out[k_str] = "[REDACTED]" if v not in (None, "", False) else v
            else:
                out[k_str] = redact_secrets(v, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item, _depth=_depth + 1) for item in value]
    return value


def discover_fixed_drives() -> list[str]:
    """Return list of fixed local drive roots on Windows (e.g. ['C:\\', 'D:\\'])."""
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    except (AttributeError, OSError):
        return []
    drives: list[str] = []
    for i in range(26):
        if bitmask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            try:
                if ctypes.windll.kernel32.GetDriveTypeW(root) == _DRIVE_FIXED:
                    drives.append(root)
            except OSError:
                continue
    return drives


PolicyError = PermissionError
PolicyViolationError = PermissionError


def _safe_expanduser(p: str | Path) -> Path:
    """Safely expand user home directory (~), falling back gracefully if USERPROFILE/HOME are unset."""
    try:
        return Path(p).expanduser()
    except RuntimeError:
        s = str(p)
        fallback = os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir()
        if s == "~":
            return Path(fallback)
        if s.startswith("~/") or s.startswith("~\\"):
            return Path(fallback) / s[2:]
        if s.startswith("~"):
            return Path(fallback) / s.lstrip("~").lstrip("/\\")
        return Path(p)


@dataclass
class ApprovalToken:
    token_id: str
    tier: PermissionTier
    tool_name: str | None
    session_id: str | None
    created_at: float
    expires_at: float
    used: bool = False

    @property
    def token(self) -> str:
        return self.token_id


@dataclass
class ControlSession:
    session_id: str
    tiers: set[PermissionTier]
    created_at: float
    expires_at: float
    approval_token: str
    client_id: str = "local"
    allowed_paths: tuple[Path, ...] | None = None
    allowed_commands: tuple[str, ...] | None = None
    allowed_tools: frozenset[str] | None = None
    revoked: bool = False
    revoked_reason: str | None = None

    def is_active(self, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
        return (not self.revoked) and (ts < self.expires_at)

    def has_tier(self, tier: PermissionTier, now: float | None = None) -> bool:
        return self.is_active(now=now) and (tier in self.tiers)

    def allows_tool(self, tool_name: str) -> bool:
        if self.allowed_tools is None:
            return True
        return tool_name in self.allowed_tools

    def allows_path(self, resolved_path: Path) -> bool:
        if self.allowed_paths is None:
            return True
        return any(
            resolved_path == allowed_p or resolved_path.is_relative_to(allowed_p)
            for allowed_p in self.allowed_paths
        )

    def allows_command(self, command: str) -> bool:
        if self.allowed_commands is None:
            return True
        cleaned = command.strip()
        if not cleaned:
            return False
        if any(ch in cleaned for ch in (";", "|", "&", "\n", "\r", "`", "$(")):
            return False
        cleaned_low = cleaned.lower()
        for pat in self.allowed_commands:
            pat_clean = pat.strip()
            if not pat_clean:
                continue
            pat_low = pat_clean.lower()
            if cleaned_low == pat_low:
                return True
            if cleaned_low.startswith(pat_low):
                rem = cleaned[len(pat_clean):]
                if not rem or rem[0].isspace():
                    return True
            try:
                if re.search(pat_clean, cleaned, re.IGNORECASE):
                    return True
            except re.error:
                pass
        return False


class SessionManager:
    """Manages revocable, time-limited, scope-bounded control sessions for elevated capabilities."""

    def __init__(self, default_ttl: int = 3600, max_ttl: int = 28800) -> None:
        self.default_ttl = default_ttl
        self.max_ttl = max_ttl
        self._sessions: dict[str, ControlSession] = {}
        self._issued_tokens: dict[str, ApprovalToken] = {}
        self._consumed_tokens: set[str] = set()
        self._lock = threading.Lock()
        self._on_revoke_all_callbacks: list[Any] = []

    def create_session(
        self,
        tiers: list[str | PermissionTier] | None = None,
        ttl_seconds: int | None = None,
        client_id: str | None = None,
        allowed_paths: list[str | Path] | tuple[str | Path, ...] | None = None,
        allowed_commands: list[str] | tuple[str, ...] | None = None,
        allowed_tools: list[str] | set[str] | frozenset[str] | None = None,
        *,
        owner: str | None = None,
        allowed_tiers: list[str | PermissionTier] | None = None,
    ) -> ControlSession:
        raw_tiers = tiers if tiers is not None else (allowed_tiers if allowed_tiers is not None else ["READ"])
        resolved_client_id = client_id or owner or "local"
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        if ttl <= 0 or ttl > self.max_ttl:
            raise ValueError(f"Session TTL must be between 1 and {self.max_ttl} seconds; got {ttl}")
        parsed_tiers = {PermissionTier(t) for t in raw_tiers} | {PermissionTier.READ}
        if PermissionTier.SYSTEM_ADMIN in parsed_tiers:
            raise PermissionError("SYSTEM_ADMIN tier cannot be granted to standard control sessions")

        resolved_paths: tuple[Path, ...] | None = None
        if allowed_paths is not None:
            resolved_paths = tuple(
                Path(os.path.realpath(str(_safe_expanduser(p).resolve(strict=False))))
                for p in allowed_paths
                if str(p).strip()
            )

        resolved_cmds: tuple[str, ...] | None = None
        if allowed_commands is not None:
            resolved_cmds = tuple(str(c).strip() for c in allowed_commands if str(c).strip())

        resolved_tools: frozenset[str] | None = None
        if allowed_tools is not None:
            resolved_tools = frozenset(str(t).strip() for t in allowed_tools if str(t).strip())

        now = time.time()
        session = ControlSession(
            session_id=f"sess_{uuid.uuid4().hex[:16]}",
            tiers=parsed_tiers,
            created_at=now,
            expires_at=now + ttl,
            approval_token=f"tok_{uuid.uuid4().hex}",
            client_id=resolved_client_id,
            allowed_paths=resolved_paths,
            allowed_commands=resolved_cmds,
            allowed_tools=resolved_tools,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def register_session(self, session: ControlSession) -> None:
        """Register a pre-constructed or broker-minted ControlSession."""
        with self._lock:
            self._sessions[session.session_id] = session

    def issue_approval_token(
        self,
        *,
        tier: str | PermissionTier,
        tool_name: str | None = None,
        session_id: str | None = None,
        ttl_seconds: int = 300,
    ) -> ApprovalToken:
        parsed_tier = PermissionTier(tier)
        if parsed_tier == PermissionTier.SYSTEM_ADMIN:
            raise PermissionError("SYSTEM_ADMIN approval tokens cannot be issued via SessionManager")
        now = time.time()
        tok = ApprovalToken(
            token_id=f"appr_{uuid.uuid4().hex}",
            tier=parsed_tier,
            tool_name=tool_name,
            session_id=session_id,
            created_at=now,
            expires_at=now + max(1, int(ttl_seconds)),
            used=False,
        )
        with self._lock:
            self._issued_tokens[tok.token_id] = tok
        return tok

    def validate_and_check_approval_token(
        self,
        token_str: str,
        *,
        session: ControlSession | None,
        required_tier: PermissionTier,
        tool_name: str | None,
        master_token: str | None,
    ) -> bool:
        tok_clean = token_str.strip()
        if not tok_clean:
            raise PermissionError("Empty or invalid approval_token")
        with self._lock:
            if tok_clean in self._consumed_tokens:
                raise PermissionError(
                    f"Single-use approval_token '{tok_clean[:12]}...' has already been used (replay denied)"
                )
            issued = self._issued_tokens.get(tok_clean)
            if issued is not None:
                if issued.used:
                    raise PermissionError(
                        f"Single-use approval_token '{tok_clean[:12]}...' has already been used (replay denied)"
                    )
                if time.time() >= issued.expires_at:
                    raise PermissionError("Single-use approval_token has expired")
                if session is not None and issued.session_id is not None and issued.session_id != session.session_id:
                    raise PermissionError("Single-use approval_token does not match session_id")
                if issued.tier != required_tier:
                    raise PermissionError(
                        f"Single-use approval_token is scoped to tier '{issued.tier.value}', not '{required_tier.value}'"
                    )
                if issued.tool_name is not None and tool_name is not None and issued.tool_name != tool_name:
                    raise PermissionError(
                        f"Single-use approval_token is scoped to tool '{issued.tool_name}', not '{tool_name}'"
                    )
                return True

        if session is not None and tok_clean == session.approval_token:
            return True
        if master_token and tok_clean == master_token:
            return True
        raise PermissionError("Invalid or forged approval_token")

    def mark_token_consumed(self, token_str: str) -> None:
        tok_clean = token_str.strip()
        if not tok_clean:
            return
        with self._lock:
            issued = self._issued_tokens.get(tok_clean)
            if issued is not None or tok_clean.startswith("appr_"):
                self._consumed_tokens.add(tok_clean)
                if issued is not None:
                    issued.used = True

    def get_session(self, session_id: str) -> ControlSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def revoke_session(self, session_id: str, reason: str = "manual_revocation") -> bool:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                return False
            sess.revoked = True
            sess.revoked_reason = reason
            return True

    def revoke_all(self, reason: str = "emergency_revoke_all") -> int:
        with self._lock:
            count = 0
            for sess in self._sessions.values():
                if not sess.revoked:
                    sess.revoked = True
                    sess.revoked_reason = reason
                    count += 1
            callbacks = list(self._on_revoke_all_callbacks)
        for cb in callbacks:
            try:
                cb(reason)
            except Exception:
                pass
        return count

    def validate_session(
        self,
        session_id: str,
        required_tier: PermissionTier,
        now: float | None = None,
        caller_id: str | None = None,
        tool_name: str | None = None,
    ) -> ControlSession:
        sess = self.get_session(session_id)
        if sess is None:
            raise PermissionError(f"Unknown control session: {session_id}")
        ts = now if now is not None else time.time()
        if sess.revoked:
            raise PermissionError(f"Control session {session_id} has been revoked ({sess.revoked_reason})")
        if ts >= sess.expires_at:
            raise PermissionError(f"Control session {session_id} has expired")
        if caller_id is not None and sess.client_id not in ("*", "local") and caller_id != sess.client_id:
            raise PermissionError(
                f"Control session {session_id} is bound to client '{sess.client_id}', not '{caller_id}'"
            )
        if required_tier not in sess.tiers:
            raise PermissionError(
                f"Control session {session_id} does not grant tier {required_tier.value}"
            )
        if tool_name is not None and not sess.allows_tool(tool_name):
            raise PermissionError(
                f"Control session {session_id} does not allow tool '{tool_name}'"
            )
        return sess


class AuditLogger:
    """Structured JSONL audit logger with automatic secret redaction."""

    def __init__(self, log_path: str | Path | None = None, redact: bool = True) -> None:
        state_root = os.getenv("MCP_STATE_ROOT")
        default_audit = (Path(state_root) / "logs" / "audit.jsonl") if state_root else (PROJECT_ROOT / "runtime" / "logs" / "audit.jsonl")
        self.log_path = Path(
            log_path or default_audit
        ).resolve(strict=False)
        self.redact = redact
        self._lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        *,
        tool_name: str,
        tier: str | PermissionTier,
        decision: str,
        reason: str = "",
        arguments: Any = None,
        result_summary: Any = None,
        session_id: str | None = None,
        duration_ms: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tier_val = tier.value if isinstance(tier, PermissionTier) else str(tier)
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": uuid.uuid4().hex[:16],
            "session_id": session_id,
            "tool_name": tool_name,
            "tier": tier_val,
            "decision": decision,
            "reason": redact_secrets(reason) if self.redact else reason,
            "arguments": redact_secrets(arguments) if self.redact else arguments,
            "result_summary": redact_secrets(result_summary) if self.redact else result_summary,
            "duration_ms": duration_ms,
        }
        if extra:
            entry["extra"] = redact_secrets(extra) if self.redact else extra

        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry

    def read_entries(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        with self._lock:
            lines = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        out: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out


def _has_reparse_point(path: Path) -> bool:
    """Return True if path itself is a symlink or NTFS junction/reparse point."""
    try:
        st = os.lstat(path)
        file_attrs = getattr(st, "st_file_attributes", 0)
        if file_attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return True
        return stat.S_ISLNK(st.st_mode)
    except OSError:
        return False


def _kill_pid_tree_fast(pid: int) -> list[int]:
    """Terminate a process and its entire descendant tree on Windows."""
    killed_pids: list[int] = []
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                killed_pids.append(child.pid)
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        killed_pids.append(parent.pid)
        parent.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except Exception:
            pass
    return killed_pids


class SecurityPolicy:
    """Enforces P5, SEC-03 & Sprint 3 Stage S1 capability tiers, fail-closed session/token
    verification, outer profile boundary, session path/command/tool scoping, emergency stop
    job cancellation, path & symlink guards, sensitive file filters, and audit logging.
    """

    def __init__(
        self,
        policy_path: str | Path | None = None,
        *,
        profile: str | None = None,
        allowed_read_roots: list[str | Path] | None = None,
        allowed_write_roots: list[str | Path] | None = None,
        allowed_git_repos: list[str | Path] | None = None,
        allowed_exec_roots: list[str | Path] | None = None,
        enabled_tiers: list[str | PermissionTier] | None = None,
        audit_log_path: str | Path | None = None,
        approval_token: str | None = None,
        require_session_for_privileged: bool | None = None,
        emergency_stop_file: str | Path | None = None,
    ) -> None:
        if policy_path is not None:
            self.policy_path = Path(policy_path).resolve(strict=False)
            if not self.policy_path.exists():
                raise FileNotFoundError(f"Explicit policy file does not exist: {self.policy_path}")
        else:
            default_cand = DEFAULT_POLICY_PATH.resolve(strict=False)
            example_cand = (PROJECT_ROOT / "config" / "policy.example.json").resolve(strict=False)
            if not default_cand.exists() and example_cand.exists():
                self.policy_path = example_cand
            else:
                self.policy_path = default_cand

        if self.policy_path.exists():
            try:
                self.config = json.loads(self.policy_path.read_text(encoding="utf-8"))
            except Exception as e:
                raise ValueError(f"Corrupted or invalid policy configuration file {self.policy_path}: {e}") from e
        else:
            self.config = {}

        self.profile = profile or os.getenv("MCP_AGENT_PROFILE") or self.config.get("default_profile", "read_only")
        profiles_cfg = self.config.get("profiles", {})
        known_profiles = set(profiles_cfg.keys()) | {
            "read_only",
            "developer_p2",
            "desktop_p3",
            "full_agent",
            "owner_full_control",
            "restricted_read",
        }
        if self.profile not in known_profiles:
            raise ValueError(f"Unknown or invalid security profile: {self.profile!r}. Known profiles: {sorted(known_profiles)}")
        profile_cfg = profiles_cfg.get(self.profile, {})
        self.strict_v021_read_tools_only: bool = bool(
            profile_cfg.get("strict_v021_read_tools_only", self.profile == "read_only")
        )
        self.unrestricted_workspace_access: bool = bool(
            profile_cfg.get("unrestricted_workspace_access", self.profile == "owner_full_control")
        )

        tiers_cfg = self.config.get("tiers", {})
        self.tier_require_approval_token: dict[PermissionTier, bool] = {}
        for t in PermissionTier:
            t_cfg = tiers_cfg.get(t.value, {}) if isinstance(tiers_cfg, dict) else {}
            default_req = t != PermissionTier.READ
            self.tier_require_approval_token[t] = bool(
                t_cfg.get("require_approval_token", default_req)
                if isinstance(t_cfg, dict)
                else default_req
            )

        # Determine active tiers (outer profile boundary)
        if enabled_tiers is not None:
            self.enabled_tiers: set[PermissionTier] = {PermissionTier(t) for t in enabled_tiers}
            if PermissionTier.READ != enabled_tiers and len(self.enabled_tiers) > 1:
                self.strict_v021_read_tools_only = False
        elif "enabled_tiers" in profile_cfg:
            self.enabled_tiers = {PermissionTier(t) for t in profile_cfg["enabled_tiers"]}
        else:
            self.enabled_tiers = {
                PermissionTier(k)
                for k, v in tiers_cfg.items()
                if isinstance(v, dict) and v.get("enabled", False)
            }
            if not self.enabled_tiers:
                self.enabled_tiers = {PermissionTier.READ}

        # Resolve roots
        self.read_roots = self._resolve_roots(
            allowed_read_roots if allowed_read_roots is not None else self.config.get("allowed_read_roots", ["AUTO"])
        )
        self.write_roots = self._resolve_roots(
            allowed_write_roots if allowed_write_roots is not None else self.config.get("allowed_write_roots", [str(PROJECT_ROOT)])
        )
        self.git_repos = self._resolve_roots(
            allowed_git_repos if allowed_git_repos is not None else self.config.get("allowed_git_repos", [str(PROJECT_ROOT)])
        )
        self.exec_roots = self._resolve_roots(
            allowed_exec_roots if allowed_exec_roots is not None else self.config.get("allowed_exec_roots", [str(PROJECT_ROOT)])
        )

        sens = self.config.get("sensitive_paths", {})
        self.blocked_path_parts: frozenset[str] = frozenset(
            p.casefold() for p in sens.get("blocked_path_parts", [
                ".env", ".ssh", ".aws", ".azure", ".gcp", ".git-credentials",
                "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".gnupg", ".pgp",
                "credentials.json", "secrets.json", "token.json", "private.key",
                "private.pem", "service-account.json", ".npmrc", ".pypirc",
                ".docker", ".kube", "login data", "cookies", "web data", "user data",
                "wallets", ".bitcoin", ".ethereum", "vault", "credentials",
                "tunnel-client", "protect",
            ])
        )
        self.blocked_subpaths: tuple[str, ...] = tuple(
            s.replace("/", "\\").casefold() for s in sens.get("blocked_subpaths", [
                "appdata\\roaming\\tunnel-client",
                "appdata\\roaming\\microsoft\\protect",
                "appdata\\local\\microsoft\\credentials",
                "appdata\\roaming\\microsoft\\credentials",
                "appdata\\local\\google\\chrome\\user data",
                "appdata\\local\\microsoft\\edge\\user data",
                "appdata\\roaming\\mozilla\\firefox\\profiles",
                ".git\\config",
            ])
        )
        self.blocked_filenames: frozenset[str] = frozenset(
            f.casefold() for f in sens.get("blocked_filenames", [
                ".env", ".env.local", ".env.production", ".env.development",
                ".netrc", "_netrc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                "known_hosts", "authorized_keys", ".git-credentials", ".gitconfig",
                "credentials.json", "secrets.json", "token.json", "service-account.json",
                "private.key", "private.pem", "master.key", "encryption.key",
                "tunnel-runtime-automatic.key",
            ])
        )
        self.blocked_extensions: frozenset[str] = frozenset(
            e.casefold() for e in sens.get("blocked_extensions", [
                ".pem", ".p12", ".pfx", ".key", ".keystore", ".jks",
                ".kdbx", ".kdb", ".rdp",
            ])
        )

        cmd_cfg = self.config.get("command_policy", {})
        self.allowlisted_prefixes: tuple[str, ...] = tuple(
            cmd_cfg.get("allowlisted_prefixes", ["python", "pytest", "git", "ruff", "echo", "Write-Output", "Get-"])
        )
        default_blocked_patterns = [
            r"Format-Volume",
            r"Format-Disk",
            r"Clear-Disk",
            r"Initialize-Disk",
            r"Set-MpPreference",
            r"Add-MpPreference",
            r"Remove-MpPreference",
            r"DisableRealtimeMonitoring",
            r"WinDefend",
            r"MpCmdRun",
            r"netsh\s+advfirewall",
            r"netsh\s+firewall",
            r"New-NetFirewallRule",
            r"Set-NetFirewallProfile",
            r"Set-NetFirewallRule",
            r"Disable-NetFirewallRule",
            r"Remove-NetFirewallRule",
            r"EnableLUA",
            r"ConsentPromptBehavior",
            r"PromptOnSecureDesktop",
            r"CurrentVersion\\Policies\\System",
            r"schtasks(?:\.exe)?\s+/(?:create|change|delete|run)\b",
            r"\b(?:Register-ScheduledTask|New-ScheduledTask|Set-ScheduledTask|Unregister-ScheduledTask)\b",
            r"\bsc(?:\.exe)?\s+(?:create|config|delete|stop|start|failure)\b",
            r"\b(?:New-Service|Set-Service|Remove-Service)\b",
            r"vssadmin\s+delete\s+shadows",
            r"wbadmin\s+delete",
            r"bcdedit",
            r"cipher\s+/w",
            r"diskpart",
            r"reg\s+(?:add|delete)\s+HKLM",
            r"Stop-Computer",
            r"Restart-Computer",
            r"shutdown\s+/[sr]",
            r"-(?:EncodedCommand|enc|ec)\b",
            r"\b(?:Invoke-Expression|iex)\b",
            r"Start-Process\b.*-Verb\s+['\"]?RunAs",
            r"-Verb\s+['\"]?RunAs",
            r"\b(?:DownloadString|DownloadFile)\b",
        ]
        configured_patterns = list(cmd_cfg.get("blocked_patterns", default_blocked_patterns))
        for req_pat in default_blocked_patterns:
            if req_pat not in configured_patterns:
                configured_patterns.append(req_pat)
        self.blocked_command_regexes: tuple[re.Pattern[str], ...] = tuple(
            re.compile(pat, re.IGNORECASE) for pat in configured_patterns
        )
        self.default_timeout_seconds: int = int(cmd_cfg.get("default_timeout_seconds", 30))
        self.max_timeout_seconds: int = int(cmd_cfg.get("max_timeout_seconds", 300))
        self.max_output_bytes: int = int(cmd_cfg.get("max_output_bytes", 120_000))

        self.approval_token = approval_token if approval_token is not None else os.getenv("MCP_AGENT_APPROVAL_TOKEN", "")
        sess_cfg = self.config.get("session_policy", {})
        if require_session_for_privileged is not None:
            self.require_session_for_privileged: bool = bool(require_session_for_privileged)
        else:
            self.require_session_for_privileged = bool(
                sess_cfg.get("require_session_for_privileged", True)
            )

        state_root = os.getenv("MCP_STATE_ROOT")
        default_rt = Path(state_root) if state_root else (PROJECT_ROOT / "runtime")
        desk_cfg = self.config.get("desktop_policy", {})
        raw_estop = (
            emergency_stop_file
            or (None if state_root else desk_cfg.get("emergency_stop_file"))
            or (default_rt / "EMERGENCY_STOP")
        )
        p_estop = Path(raw_estop)
        if not p_estop.is_absolute():
            p_estop = PROJECT_ROOT / p_estop
        self.emergency_stop_file = p_estop.resolve(strict=False)
        self._emergency_latch: bool = False
        self._emergency_reason: str | None = None
        self._exec_managers: list[Any] = []
        self._desktop_agents: list[Any] = []

        self.sessions = SessionManager(
            default_ttl=int(sess_cfg.get("default_ttl_seconds", 3600)),
            max_ttl=int(sess_cfg.get("max_ttl_seconds", 28800)),
        )
        self.sessions._on_revoke_all_callbacks.append(self._on_sessions_revoke_all)
        self._tls = threading.local()

        audit_cfg = self.config.get("audit", {})
        raw_audit = (
            audit_log_path
            or (None if state_root else audit_cfg.get("log_path"))
            or (default_rt / "logs" / "audit.jsonl")
        )
        p_audit = Path(raw_audit)
        if not p_audit.is_absolute():
            p_audit = PROJECT_ROOT / p_audit
        self.audit = AuditLogger(
            log_path=p_audit.resolve(strict=False),
            redact=bool(audit_cfg.get("redact_secrets", True)),
        )
        _orig_log_event = self.audit.log_event

        def _hooked_log_event(**kwargs: Any) -> dict[str, Any]:
            if kwargs.get("tool_name") == "reset_emergency_stop":
                self._emergency_latch = False
                self._emergency_reason = None
            return _orig_log_event(**kwargs)

        self.audit.log_event = _hooked_log_event  # type: ignore[method-assign]

    @property
    def session_manager(self) -> SessionManager:
        return self.sessions

    def _enter_invocation(self) -> None:
        depth = getattr(self._tls, "depth", 0)
        self._tls.depth = depth + 1
        if depth == 0:
            self._tls.pending_tokens = []

    def _exit_invocation(self) -> None:
        depth = getattr(self._tls, "depth", 0)
        if depth <= 1:
            self._tls.depth = 0
            pending = getattr(self._tls, "pending_tokens", [])
            self._tls.pending_tokens = []
            for tok in pending:
                self.sessions.mark_token_consumed(tok)
        else:
            self._tls.depth = depth - 1

    def register_subsystems(self, *, exec_ops: Any = None, desktop_agent: Any = None) -> None:
        """Register ExecutionJobManager and DesktopAgent instances for emergency-stop coordination."""
        if exec_ops is not None and exec_ops not in self._exec_managers:
            self._exec_managers.append(exec_ops)
        if desktop_agent is not None and desktop_agent not in self._desktop_agents:
            self._desktop_agents.append(desktop_agent)
            if hasattr(desktop_agent, "emergency_stop_file"):
                self.emergency_stop_file = Path(desktop_agent.emergency_stop_file).resolve(strict=False)

    def _discover_bound_subsystems(self) -> None:
        """Discover ExecutionJobManager or DesktopAgent instances bound to this policy."""
        try:
            for obj in gc.get_objects():
                cls_name = type(obj).__name__
                if cls_name == "ExecutionJobManager" and getattr(obj, "policy", None) is self:
                    if obj not in self._exec_managers:
                        self._exec_managers.append(obj)
                elif cls_name == "DesktopAgent" and getattr(obj, "policy", None) is self:
                    if obj not in self._desktop_agents:
                        self._desktop_agents.append(obj)
                        if hasattr(obj, "emergency_stop_file"):
                            self.emergency_stop_file = Path(obj.emergency_stop_file).resolve(strict=False)
        except Exception:
            pass

    def _on_sessions_revoke_all(self, reason: str) -> None:
        if "emergency_stop" in str(reason).lower():
            self._emergency_latch = True
            self._emergency_reason = reason
            self._cancel_all_running_jobs()

    def is_emergency_stop_active(self) -> bool:
        if self.emergency_stop_file.exists():
            return True
        if self._emergency_latch:
            self._emergency_latch = False
            self._emergency_reason = None
        for da in self._desktop_agents:
            ef = getattr(da, "emergency_stop_file", None)
            if ef and Path(ef).exists():
                return True
            if getattr(da, "_emergency_latch", False):
                da._emergency_latch = False
                da._emergency_reason = None
        return False

    def _cancel_all_running_jobs(self) -> dict[str, list[str]]:
        """Immediately cancel all active background jobs and processes in bound ExecutionJobManagers."""
        if not self._exec_managers:
            self._discover_bound_subsystems()
        cancelled_jobs: list[str] = []
        stopped_procs: list[str] = []
        for mgr in list(self._exec_managers):
            try:
                lock = getattr(mgr, "_lock", None)
                active_jobs = list(getattr(mgr, "_active_jobs", set()))
                for job_id in active_jobs:
                    try:
                        # Wait briefly if worker thread is still spawning subprocess
                        for _ in range(15):
                            if job_id in getattr(mgr, "_job_procs", {}):
                                break
                            time.sleep(0.02)
                        if lock:
                            with lock:
                                mgr._active_jobs.discard(job_id)
                                state = mgr._read_job_state(job_id)
                                proc = mgr._job_procs.get(job_id)
                                pid = proc.pid if proc is not None else state.get("pid")
                                state["cancelled"] = True
                                state["status"] = "cancelled"
                                state["finished_at"] = datetime.now(timezone.utc).isoformat()
                                mgr._write_job_state(job_id, state)
                        else:
                            pid = None
                        if pid:
                            _kill_pid_tree_fast(int(pid))
                        mgr._append_job_audit(job_id, "JOB_EMERGENCY_STOPPED", {"pid": pid})
                        cancelled_jobs.append(job_id)
                    except Exception:
                        pass

                procs_dict = getattr(mgr, "_processes", {})
                for proc_id, info in list(procs_dict.items()):
                    try:
                        proc_obj = info.get("popen")
                        if not info.get("stopped", False) and proc_obj is not None and proc_obj.poll() is None:
                            _kill_pid_tree_fast(int(proc_obj.pid))
                            info["stopped"] = True
                            stopped_procs.append(proc_id)
                    except Exception:
                        pass
            except Exception:
                pass
        return {"cancelled_jobs": cancelled_jobs, "stopped_processes": stopped_procs}

    def engage_emergency_stop(self, reason: str = "emergency_stop") -> dict[str, Any]:
        """Engage Emergency Stop across Policy, SessionManager, ExecutionJobManager, and DesktopAgent."""
        self._discover_bound_subsystems()
        self._emergency_latch = True
        self._emergency_reason = reason
        self.emergency_stop_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "engaged": True,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.emergency_stop_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        for da in self._desktop_agents:
            da._emergency_latch = True
            da._emergency_reason = reason
            da_ef = getattr(da, "emergency_stop_file", None)
            if da_ef:
                Path(da_ef).parent.mkdir(parents=True, exist_ok=True)
                Path(da_ef).write_text(json.dumps(payload, indent=2), encoding="utf-8")

        cancel_summary = self._cancel_all_running_jobs()
        revoked_count = self.sessions.revoke_all(reason=f"emergency_stop:{reason}")
        extra_cancel = self._cancel_all_running_jobs()
        for jid in extra_cancel["cancelled_jobs"]:
            if jid not in cancel_summary["cancelled_jobs"]:
                cancel_summary["cancelled_jobs"].append(jid)
        for pid_s in extra_cancel["stopped_processes"]:
            if pid_s not in cancel_summary["stopped_processes"]:
                cancel_summary["stopped_processes"].append(pid_s)
        self.audit.log_event(
            tool_name="emergency_stop",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            reason=f"Emergency stop engaged: {reason}",
            result_summary={
                "revoked_sessions": revoked_count,
                "cancelled_jobs": cancel_summary["cancelled_jobs"],
                "stopped_processes": cancel_summary["stopped_processes"],
                "file": str(self.emergency_stop_file),
            },
        )
        return {
            "emergency_stop": True,
            "reason": reason,
            "file": str(self.emergency_stop_file),
            "revoked_sessions": revoked_count,
            "cancelled_jobs": cancel_summary["cancelled_jobs"],
            "stopped_processes": cancel_summary["stopped_processes"],
        }

    def reset_emergency_stop(self) -> dict[str, Any]:
        """Reset Emergency Stop latch and remove emergency stop file(s)."""
        self._discover_bound_subsystems()
        self._emergency_latch = False
        self._emergency_reason = None
        if self.emergency_stop_file.exists():
            try:
                self.emergency_stop_file.unlink()
            except OSError:
                pass
        for da in self._desktop_agents:
            da._emergency_latch = False
            da._emergency_reason = None
            da_ef = getattr(da, "emergency_stop_file", None)
            if da_ef and Path(da_ef).exists():
                try:
                    Path(da_ef).unlink()
                except OSError:
                    pass
        self.audit.log_event(
            tool_name="reset_emergency_stop",
            tier=PermissionTier.DESKTOP,
            decision="ALLOW",
            reason="Emergency stop reset",
        )
        return {"emergency_stop": False, "file_exists": self.emergency_stop_file.exists()}

    @staticmethod
    def _resolve_roots(raw_list: list[str | Path]) -> tuple[Path, ...]:
        expanded: list[Path] = []
        for item in raw_list:
            s = str(item).strip()
            if not s:
                continue
            if s.upper() == "AUTO":
                for d in discover_fixed_drives():
                    expanded.append(Path(d).resolve(strict=False))
            else:
                p = _safe_expanduser(s)
                if not p.is_absolute():
                    p = (PROJECT_ROOT / p).resolve(strict=False)
                else:
                    p = p.resolve(strict=False)
                expanded.append(p)
        return tuple(expanded)

    def get_roots_for_tier(self, tier: PermissionTier) -> tuple[Path, ...]:
        if self.profile == "owner_full_control" or getattr(self, "unrestricted_workspace_access", False):
            fixed = [Path(d).resolve(strict=False) for d in discover_fixed_drives()]
            return tuple(fixed) if fixed else self.read_roots
        if tier == PermissionTier.WRITE:
            return self.write_roots
        if tier == PermissionTier.EXECUTE:
            return self.exec_roots
        return self.read_roots

    def _verify_tier_authorization(
        self,
        tier: PermissionTier,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        arguments: dict[str, Any] | None = None,
        caller_id: str | None = None,
        tool_name: str | None = None,
        consume_token: bool = False,
    ) -> ControlSession | None:
        """Sprint 3 Stage S1 + SEC-03 strict fail-closed credential & tier authorization check."""
        # 1. Unconditionally reject credential smuggling inside tool arguments
        if isinstance(arguments, dict):
            for smuggled_key in ("session_id", "_session_id", "approval_token", "_approval_token"):
                if smuggled_key in arguments:
                    raise PermissionError(
                        f"Credential smuggling denied: '{smuggled_key}' is not permitted inside tool arguments"
                    )

        # 2. If session_id is provided, ALWAYS validate session first
        validated_session: ControlSession | None = None
        if session_id is not None:
            if not isinstance(session_id, str) or not session_id.strip():
                raise PermissionError("Invalid or empty control session ID")
            validated_session = self.sessions.validate_session(
                session_id.strip(),
                tier,
                caller_id=caller_id,
                tool_name=tool_name,
            )
            if approval_token is not None:
                if not isinstance(approval_token, str) or not approval_token.strip():
                    raise PermissionError("Invalid approval_token for session")
                tok_clean = approval_token.strip()
                if not (not consume_token and tok_clean == getattr(self._tls, "last_authorized_token", None)):
                    self.sessions.validate_and_check_approval_token(
                        tok_clean,
                        session=validated_session,
                        required_tier=tier,
                        tool_name=tool_name,
                        master_token=self.approval_token,
                    )

        # 3. If approval_token is provided (without session_id), ALWAYS validate it first
        elif approval_token is not None:
            if not isinstance(approval_token, str) or not approval_token.strip():
                raise PermissionError("Invalid or forged approval_token")
            tok_clean = approval_token.strip()
            if not (not consume_token and tok_clean == getattr(self._tls, "last_authorized_token", None)):
                self.sessions.validate_and_check_approval_token(
                    tok_clean,
                    session=None,
                    required_tier=tier,
                    tool_name=tool_name,
                    master_token=self.approval_token,
                )

        # 4. Enforce outer profile boundary
        if tier == PermissionTier.SYSTEM_ADMIN:
            if PermissionTier.SYSTEM_ADMIN not in self.enabled_tiers:
                raise PermissionError("SYSTEM_ADMIN tier is blocked by default and not enabled in profile")
            if self.profile != "owner_full_control":
                if not (self.approval_token and approval_token and approval_token.strip() == self.approval_token):
                    raise PermissionError("SYSTEM_ADMIN tier requires explicit master approval token")
                if self.require_session_for_privileged and validated_session is None:
                    raise PermissionError("SYSTEM_ADMIN tier requires an active control session")
            return validated_session

        if tier not in self.enabled_tiers:
            raise PermissionError(
                f"Capability tier '{tier.value}' is not enabled in profile '{self.profile}' (outer profile boundary)"
            )

        # 5. Enforce fail-closed default for privileged tiers (WRITE, EXECUTE, DESKTOP)
        if tier != PermissionTier.READ:
            if self.profile == "owner_full_control":
                return validated_session
            if self.require_session_for_privileged and validated_session is None:
                raise PermissionError(
                    f"Privileged tier '{tier.value}' requires an active authorized ControlSession (fail-closed)"
                )
            if self.tier_require_approval_token.get(tier, False):
                has_valid_tok = bool(
                    (validated_session is not None and bool(validated_session.approval_token))
                    or (self.approval_token and approval_token and approval_token.strip() == self.approval_token)
                )
                if not has_valid_tok:
                    raise PermissionError(
                        f"Capability tier '{tier.value}' requires an explicit approval token"
                    )

        return validated_session

    def is_tier_authorized(
        self,
        tier: PermissionTier,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        caller_id: str | None = None,
    ) -> bool:
        try:
            self._verify_tier_authorization(
                tier,
                session_id=session_id,
                approval_token=approval_token,
                caller_id=caller_id,
            )
            return True
        except PermissionError:
            return False

    def _enforce_session_scope(
        self,
        sess: ControlSession,
        tool_name: str,
        tier: PermissionTier,
        arguments: dict[str, Any] | None,
    ) -> None:
        """Enforce per-session tool, path, and command boundaries."""
        if not sess.allows_tool(tool_name):
            raise PermissionError(
                f"Control session {sess.session_id} does not allow tool '{tool_name}'"
            )
        if not isinstance(arguments, dict):
            return

        if sess.allowed_paths is not None:
            path_tier = (
                tier
                if tier in (PermissionTier.READ, PermissionTier.WRITE, PermissionTier.EXECUTE)
                else PermissionTier.READ
            )
            candidate_paths: list[tuple[str, Any, PermissionTier]] = []
            for key in ("path", "dest", "destination", "target_path", "cwd", "root"):
                if key in arguments and arguments[key] is not None:
                    candidate_paths.append((key, arguments[key], path_tier))
            for src_key in ("src", "source"):
                if src_key in arguments and arguments[src_key] is not None:
                    src_tier = PermissionTier.READ if tool_name == "copy_file" else path_tier
                    candidate_paths.append((src_key, arguments[src_key], src_tier))
            if "new_name" in arguments and arguments.get("new_name") and arguments.get("src"):
                new_name_str = str(arguments["new_name"])
                src_p = Path(str(arguments["src"]))
                dest_cand = Path(new_name_str) if Path(new_name_str).is_absolute() else (src_p.parent / new_name_str)
                candidate_paths.append(("new_name", str(dest_cand), path_tier))
            if "files" in arguments and isinstance(arguments["files"], list):
                base_dir = Path(
                    str(arguments.get("cwd") or (self.write_roots[0] if self.write_roots else PROJECT_ROOT))
                )
                for f_item in arguments["files"]:
                    fp = Path(str(f_item))
                    full_fp = fp if fp.is_absolute() else (base_dir / fp)
                    candidate_paths.append(("files", str(full_fp), path_tier))

            for key_label, raw_p, p_tier in candidate_paths:
                resolved_p = self.validate_path(
                    raw_p,
                    tier=p_tier,
                    check_content=False,
                    must_exist=False,
                    session_id=sess.session_id,
                )
                if not sess.allows_path(resolved_p):
                    raise PermissionError(
                        f"Target path '{resolved_p}' ({key_label}) is outside allowed_paths scope for session {sess.session_id}"
                    )

        if sess.allowed_commands is not None and "command" in arguments and arguments["command"] is not None:
            cmd_str = str(arguments["command"])
            if not sess.allows_command(cmd_str):
                raise PermissionError(
                    f"Command is outside allowed_commands scope for session {sess.session_id}"
                )

    def authorize_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        caller_id: str | None = None,
    ) -> PermissionTier:
        tier = TOOL_TIER_MAP.get(tool_name)
        if tier is None:
            self.audit.log_event(
                tool_name=tool_name,
                tier="UNKNOWN",
                decision="DENY",
                reason=f"Tool '{tool_name}' is unknown and not registered in policy",
                arguments=arguments,
                session_id=session_id,
            )
            raise PermissionError(f"Unknown or unapproved tool: {tool_name}")

        # Emergency stop check for privileged capabilities
        if self.is_emergency_stop_active() and tier != PermissionTier.READ:
            self.sessions.revoke_all(reason="emergency_stop_active")
            self._cancel_all_running_jobs()
            reason_msg = "Emergency stop is active: all privileged operations are halted"
            self.audit.log_event(
                tool_name=tool_name,
                tier=tier,
                decision="DENY",
                reason=reason_msg,
                arguments=arguments,
                session_id=session_id,
            )
            raise PermissionError(reason_msg)

        # Always validate argument smuggling, session_id, approval_token, and outer profile boundary FIRST
        try:
            validated_session = self._verify_tier_authorization(
                tier,
                session_id=session_id,
                approval_token=approval_token,
                arguments=arguments,
                caller_id=caller_id,
                tool_name=tool_name,
                consume_token=True,
            )
            if self.strict_v021_read_tools_only and tool_name not in V021_READ_TOOLS:
                raise PermissionError(f"Tool '{tool_name}' is disabled in strict read_only profile")
            if validated_session is not None:
                self._enforce_session_scope(validated_session, tool_name, tier, arguments)
        except PermissionError as exc:
            self.audit.log_event(
                tool_name=tool_name,
                tier=tier,
                decision="DENY",
                reason=str(exc),
                arguments=arguments,
                session_id=session_id,
            )
            raise

        if approval_token is not None and isinstance(approval_token, str) and approval_token.strip():
            tok_clean = approval_token.strip()
            self._tls.last_authorized_token = tok_clean
            if getattr(self._tls, "depth", 0) > 0:
                pending = getattr(self._tls, "pending_tokens", None)
                if isinstance(pending, list) and tok_clean not in pending:
                    pending.append(tok_clean)
            else:
                self.sessions.mark_token_consumed(tok_clean)

        return tier

    def is_sensitive_path_str(self, raw_or_resolved: str | Path, *, check_content: bool = True) -> bool:
        """Check whether a path string or Path points to a sensitive file or directory."""
        s = str(raw_or_resolved).strip()
        if not s:
            return False
        norm = s.replace("/", "\\")
        norm_low = norm.casefold()
        for sub in self.blocked_subpaths:
            if norm_low.endswith(sub) or f"\\{sub}\\" in norm_low or norm_low.endswith(f"\\{sub}"):
                return True
        p = Path(norm)
        for part in p.parts:
            low = part.casefold()
            if low in self.blocked_path_parts or low in self.blocked_filenames:
                return True
            if low.startswith(".env"):
                return True
        if p.name.casefold() in self.blocked_filenames:
            return True
        if check_content and p.suffix.casefold() in self.blocked_extensions:
            return True
        return False

    def validate_path(
        self,
        raw_path: Any,
        *,
        tier: PermissionTier = PermissionTier.READ,
        check_content: bool = False,
        must_exist: bool = False,
        session_id: str | None = None,
    ) -> Path:
        """Validate and resolve a filesystem path against traversal, UNC, device paths,
        ADS, symlink/junction escapes, approved roots, session scope, and sensitive file rules.
        """
        roots = self.get_roots_for_tier(tier)
        if not roots:
            raise PermissionError(f"No approved roots configured for tier {tier.value}")

        if not isinstance(raw_path, (str, Path)):
            raise PermissionError("Invalid path type")
        raw_str = str(raw_path).strip()
        if not raw_str or "\x00" in raw_str:
            raise PermissionError("Invalid or empty path")

        # 1. Block UNC paths (\\server\share or //server/share) and Device paths (\\.\, \\?\, \??\)
        if raw_str.startswith("\\\\") or raw_str.startswith("//") or raw_str.startswith("\\??\\"):
            raise PermissionError("UNC and Windows device paths are disallowed")

        # 2. Block NTFS Alternate Data Streams (e.g., file.txt:secret or C:\dir\file.txt:$DATA)
        if ":" in raw_str:
            # Only allow standard drive letter at index 1 (e.g. C:\...)
            if len(raw_str) < 2 or raw_str[1] != ":" or not raw_str[0].isalpha() or ":" in raw_str[2:]:
                raise PermissionError("NTFS Alternate Data Streams (ADS) are disallowed")

        candidate = _safe_expanduser(raw_str)
        if not candidate.is_absolute():
            candidate = roots[0] / candidate

        # Normalize lexical '..' without resolving symlinks first so we can inspect components
        lexical_norm = Path(os.path.abspath(str(candidate)))

        # Check sensitive components on lexical path before touching filesystem
        if self.is_sensitive_path_str(lexical_norm, check_content=check_content):
            raise PermissionError(f"Access to sensitive path is disallowed: {candidate.name}")

        # 3. Check for symlink/junction escape along existing ancestor chain
        cur = Path(lexical_norm.anchor) if lexical_norm.anchor else Path(".")
        for part in lexical_norm.parts[1 if lexical_norm.anchor else 0 :]:
            cur = cur / part
            if cur.exists() or _has_reparse_point(cur):
                if _has_reparse_point(cur):
                    real_target = Path(os.path.realpath(str(cur)))
                    if not any(real_target == r or real_target.is_relative_to(r) for r in roots):
                        raise PermissionError(
                            f"Symlink or junction escape detected outside approved {tier.value} roots"
                        )

        # Resolve final real path
        resolved = Path(os.path.realpath(str(lexical_norm)))

        # 4. Verify resolved path is inside approved roots for the requested tier
        if not any(resolved == r or resolved.is_relative_to(r) for r in roots):
            raise PermissionError(f"Path '{resolved}' is outside approved {tier.value} roots")

        # 5. Re-verify sensitive path rules on resolved target (catches symlink to .env)
        if self.is_sensitive_path_str(resolved, check_content=check_content):
            raise PermissionError(f"Access to sensitive path is disallowed: {resolved.name}")

        # 6. Verify session path scope if a control session was provided
        if session_id is not None and isinstance(session_id, str) and session_id.strip():
            sess = self.sessions.get_session(session_id.strip())
            if sess is not None and not sess.allows_path(resolved):
                raise PermissionError(
                    f"Path '{resolved}' is outside allowed_paths scope for session {sess.session_id}"
                )

        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"Path does not exist: {resolved}")

        return resolved

    def validate_git_repo(
        self,
        raw_cwd: Any,
        *,
        write: bool = False,
        session_id: str | None = None,
    ) -> Path:
        """Validate that raw_cwd is inside an approved Git repository."""
        req_tier = PermissionTier.WRITE if write else PermissionTier.READ
        resolved = self.validate_path(raw_cwd, tier=req_tier, check_content=False, session_id=session_id)

        cur = resolved
        git_root: Path | None = None
        while True:
            if (cur / ".git").exists():
                git_root = cur
                break
            if cur.parent == cur:
                break
            cur = cur.parent

        if git_root is None:
            raise PermissionError(f"Directory '{resolved}' is not inside any Git repository")

        if not any(git_root == repo or git_root.is_relative_to(repo) for repo in self.git_repos):
            raise PermissionError(
                f"Git repository '{git_root}' is outside approved Git repositories"
            )

        if write and not any(git_root == r or git_root.is_relative_to(r) for r in self.write_roots):
            raise PermissionError(
                f"Git repository '{git_root}' is not inside an approved writable root"
            )

        return resolved

    def validate_command(
        self,
        command: str,
        cwd: str | Path,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        caller_id: str | None = None,
    ) -> Path:
        """Validate a shell/process command and its working directory."""
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise ValueError("Command must be a non-empty string without NUL bytes")

        validated_session = self._verify_tier_authorization(
            PermissionTier.EXECUTE,
            session_id=session_id,
            approval_token=approval_token,
            caller_id=caller_id,
        )

        resolved_cwd = self.validate_path(
            cwd,
            tier=PermissionTier.EXECUTE,
            must_exist=True,
            session_id=session_id,
        )
        if not resolved_cwd.is_dir():
            raise NotADirectoryError(f"Working directory is not a directory: {resolved_cwd}")

        cleaned = command.strip()
        if validated_session is not None and not validated_session.allows_command(cleaned):
            self.audit.log_event(
                tool_name="validate_command",
                tier=PermissionTier.EXECUTE,
                decision="DENY",
                reason=f"Command outside session {validated_session.session_id} allowed_commands scope",
                arguments={"command": cleaned, "cwd": str(resolved_cwd)},
                session_id=session_id,
            )
            raise PermissionError(
                f"Command is outside allowed_commands scope for session {validated_session.session_id}"
            )

        # Check destructive/system admin blocklist
        for pat in self.blocked_command_regexes:
            if pat.search(cleaned):
                self.audit.log_event(
                    tool_name="validate_command",
                    tier=PermissionTier.EXECUTE,
                    decision="DENY",
                    reason=f"Blocked destructive/system command pattern: {pat.pattern}",
                    arguments={"command": cleaned, "cwd": str(resolved_cwd)},
                    session_id=session_id,
                )
                raise PermissionError(
                    f"Command matches blocked destructive/system pattern: {pat.pattern}"
                )

        # Check allowlist if required by tier config
        exec_cfg = self.config.get("tiers", {}).get("EXECUTE", {})
        if exec_cfg.get("allowlisted_commands_only", False):
            has_token = bool(self.approval_token and approval_token == self.approval_token)
            if not has_token:
                first_token = cleaned.split()[0].strip("\"'")
                base_cmd = Path(first_token).stem if ("\\" in first_token or "/" in first_token) else first_token
                if not any(
                    cleaned.lower().startswith(pref.lower()) or base_cmd.lower().startswith(pref.lower())
                    for pref in self.allowlisted_prefixes
                ):
                    raise PermissionError(
                        f"Command '{first_token}' is not in allowlisted prefixes and no approval token was provided"
                    )

        return resolved_cwd


PolicyEngine = SecurityPolicy
GatewayPolicy = SecurityPolicy
