"""Unified Architectural Contracts across Subagents (Audit 28D9ED5).

Freezes the three mandatory interfaces:
1. AuthPrincipal: Verified principal & capability context (Agent A).
2. RuntimeStatePaths: Injected state isolation paths & emergency stop latch (Agent B).
3. ProcessExecutionResult: Process tree execution, bounded streaming & cleanup evidence (Agent C).
"""
from __future__ import annotations

import builtins
import io
import os
import pathlib
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, FrozenSet


@dataclass(frozen=True)
class AuthPrincipal:
    """Verified caller principal and capability context.

    Identity (client_id) is separate from authorization (is_owner / tier / scopes).
    Supports dynamic OAuth client IDs without relying on hardcoded whitelists.
    """
    client_id: str
    owner_id: str = "local_owner"
    tier: str = "READ"
    scopes: FrozenSet[str] = field(default_factory=frozenset)
    is_owner: bool = False
    auth_method: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def allows_tier(self, required_tier: str) -> bool:
        hierarchy = {"READ": 1, "WRITE": 2, "EXECUTE": 3, "SYSTEM_ADMIN": 4}
        return hierarchy.get(self.tier, 0) >= hierarchy.get(required_tier, 0)

    def allows_scope(self, scope: str) -> bool:
        return scope in self.scopes or "mcp:all" in self.scopes or (self.is_owner and "mcp:owner" in self.scopes)


@dataclass(frozen=True)
class RuntimeStatePaths:
    r"""Injected runtime paths ensuring test state never leaks to production.

    Guards tests against touching D:\ExampleProjects\Windows-MCP-Agent\runtime directly.
    """
    base_dir: Path
    emergency_stop_file: Path
    audit_db_path: Path
    tasks_db_path: Path
    oauth_db_path: Path
    evidence_dir: Path
    grant_key_path: Path | None = None
    audit_log_path: Path | None = None
    locks_dir: Path | None = None
    config_dir: Path | None = None
    process_registry_path: Path | None = None
    jobs_dir: Path | None = None
    is_isolated: bool = True
    root_dir_override: Path | None = None

    def __post_init__(self) -> None:
        root = Path(self.root_dir_override or self.base_dir).resolve()
        runtime_dir = root / "runtime"
        if self.grant_key_path is None:
            object.__setattr__(self, "grant_key_path", runtime_dir / "secrets" / "task_grant.key")
        if self.audit_log_path is None:
            object.__setattr__(self, "audit_log_path", runtime_dir / "logs" / "audit.log")
        if self.locks_dir is None:
            object.__setattr__(self, "locks_dir", runtime_dir / "locks")
        if self.config_dir is None:
            object.__setattr__(self, "config_dir", root / "config")
        if self.process_registry_path is None:
            object.__setattr__(self, "process_registry_path", runtime_dir / "process_registry.json")
        if self.jobs_dir is None:
            object.__setattr__(self, "jobs_dir", runtime_dir / "jobs")

    @property
    def root_dir(self) -> Path:
        return Path(self.root_dir_override or self.base_dir).resolve()

    @classmethod
    def create_isolated(cls, temp_dir: Path | str) -> RuntimeStatePaths:
        root = Path(temp_dir).resolve()
        runtime_dir = root / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir = runtime_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        config_dir = root / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        locks_dir = runtime_dir / "locks"
        locks_dir.mkdir(parents=True, exist_ok=True)
        logs_dir = runtime_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        jobs_dir = runtime_dir / "jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)
        secrets_dir = runtime_dir / "secrets"
        secrets_dir.mkdir(parents=True, exist_ok=True)

        return cls(
            base_dir=root,
            emergency_stop_file=runtime_dir / "EMERGENCY_STOP",
            audit_db_path=runtime_dir / "audit.db",
            tasks_db_path=runtime_dir / "tasks.db",
            oauth_db_path=runtime_dir / "oauth.db",
            evidence_dir=evidence_dir,
            grant_key_path=secrets_dir / "task_grant.key",
            audit_log_path=logs_dir / "audit.log",
            locks_dir=locks_dir,
            config_dir=config_dir,
            process_registry_path=runtime_dir / "process_registry.json",
            jobs_dir=jobs_dir,
            is_isolated=True,
            root_dir_override=root,
        )

    @classmethod
    def get_production_default(cls, project_root: Path | str | None = None) -> RuntimeStatePaths:
        root = Path(project_root or Path(__file__).resolve().parent.parent).resolve()
        runtime_dir = root / "runtime"
        evidence_dir = runtime_dir / "evidence"
        config_dir = root / "config"
        locks_dir = runtime_dir / "locks"
        logs_dir = runtime_dir / "logs"
        secrets_dir = runtime_dir / "secrets"
        return cls(
            base_dir=root,
            emergency_stop_file=runtime_dir / "EMERGENCY_STOP",
            audit_db_path=runtime_dir / "audit.db",
            tasks_db_path=runtime_dir / "tasks.db",
            oauth_db_path=runtime_dir / "oauth.db",
            evidence_dir=evidence_dir,
            grant_key_path=secrets_dir / "broker_hmac.key",
            audit_log_path=logs_dir / "audit.log",
            locks_dir=locks_dir,
            config_dir=config_dir,
            process_registry_path=runtime_dir / "process_registry.json",
            is_isolated=False,
            root_dir_override=root,
        )

    def is_emergency_stop_active(self) -> bool:
        return self.emergency_stop_file.exists()

    def trigger_emergency_stop(self, reason: str = "EMERGENCY_STOP_TRIGGERED") -> None:
        self.emergency_stop_file.parent.mkdir(parents=True, exist_ok=True)
        self.emergency_stop_file.write_text(reason, encoding="utf-8")

    def clear_emergency_stop(self) -> None:
        try:
            self.emergency_stop_file.unlink(missing_ok=True)
        except Exception:
            pass

    def to_env_dict(self) -> dict[str, str]:
        return {
            "MCP_STATE_ROOT": str(self.root_dir),
            "MCP_RUNTIME_DIR": str(self.root_dir / "runtime"),
            "MCP_EMERGENCY_STOP_FILE": str(self.emergency_stop_file),
            "MCP_TASKS_DB_PATH": str(self.tasks_db_path),
            "MCP_AUDIT_DB_PATH": str(self.audit_db_path),
            "MCP_OAUTH_DB_PATH": str(self.oauth_db_path),
            "MCP_EVIDENCE_DIR": str(self.evidence_dir),
            "MCP_GRANT_KEY_PATH": str(self.grant_key_path),
            "MCP_AUDIT_LOG_PATH": str(self.audit_log_path),
            "MCP_LOCKS_DIR": str(self.locks_dir),
            "MCP_CONFIG_DIR": str(self.config_dir),
            "MCP_PROCESS_REGISTRY_PATH": str(self.process_registry_path),
            "MCP_JOBS_DIR": str(self.jobs_dir),
            "MCP_IS_ISOLATED": "1" if self.is_isolated else "0",
        }


@dataclass(frozen=True)
class ProcessExecutionResult:
    """Execution result with process-tree verification and bounded output metadata."""
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    interrupted: bool = False
    cleanup_verified: bool = True
    descendants_killed: int = 0
    truncated: bool = False
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "interrupted": self.interrupted,
            "cleanup_verified": self.cleanup_verified,
            "descendants_killed": self.descendants_killed,
            "truncated": self.truncated,
            "duration_seconds": self.duration_seconds,
        }


def _is_subpath(target: Path | str, parent: Path | str) -> bool:
    """Determine if target path is identical to or located inside parent directory."""
    try:
        norm_target = Path(target).resolve(strict=False)
        norm_parent = Path(parent).resolve(strict=False)
        if os.name == "nt":
            t_str = str(norm_target).lower().rstrip("\\/")
            p_str = str(norm_parent).lower().rstrip("\\/")
            return t_str == p_str or t_str.startswith(p_str + "\\") or t_str.startswith(p_str + "/")
        else:
            return norm_target == norm_parent or norm_parent in norm_target.parents
    except Exception:
        return False


def _check_and_block(target: Any, op_name: str) -> None:
    """Validate target path against all active ProductionWriteGuard instances."""
    if target is None or isinstance(target, int):
        return
    try:
        if isinstance(target, bytes):
            target = os.fsdecode(target)
        target_str = str(target)
        if target_str.startswith("file:"):
            target_str = target_str[5:].split("?")[0]
            if target_str.startswith("///"):
                target_str = target_str[3:]
            elif target_str.startswith("//"):
                target_str = target_str[2:]
        resolved = Path(target_str).resolve(strict=False)
    except Exception:
        return

    with ProductionWriteGuard._lock:
        active_guards = list(ProductionWriteGuard._active_guards)

    for guard in active_guards:
        if guard.is_path_protected(resolved):
            event = {
                "run_id": guard.run_id,
                "operation": op_name,
                "normalized_target": str(resolved),
                "timestamp": time.time(),
            }
            guard.record_blocked_event(event)
            raise PermissionError(
                f"PRODUCTION_STATE_WRITE_BLOCKED [{guard.run_id}]: operation={op_name} target={resolved}"
            )


_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
if hasattr(os, "O_EXCL"):
    _WRITE_FLAGS |= os.O_EXCL


def _guarded_builtins_open(file, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    if any(m in str(mode) for m in ("w", "a", "x", "+")):
        _check_and_block(file, "open")
    return ProductionWriteGuard._orig_builtins_open(file, *args, **kwargs)


def _guarded_io_open(file, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    if any(m in str(mode) for m in ("w", "a", "x", "+")):
        _check_and_block(file, "io.open")
    return ProductionWriteGuard._orig_io_open(file, *args, **kwargs)


def _guarded_os_open(path, flags, *args, **kwargs):
    if flags & _WRITE_FLAGS:
        _check_and_block(path, "os.open")
    return ProductionWriteGuard._orig_os_open(path, flags, *args, **kwargs)


def _guarded_os_remove(path, *args, **kwargs):
    _check_and_block(path, "os.remove")
    return ProductionWriteGuard._orig_os_remove(path, *args, **kwargs)


def _guarded_os_unlink(path, *args, **kwargs):
    _check_and_block(path, "os.unlink")
    return ProductionWriteGuard._orig_os_unlink(path, *args, **kwargs)


def _guarded_os_mkdir(path, *args, **kwargs):
    _check_and_block(path, "os.mkdir")
    return ProductionWriteGuard._orig_os_mkdir(path, *args, **kwargs)


def _guarded_os_makedirs(name, *args, **kwargs):
    _check_and_block(name, "os.makedirs")
    return ProductionWriteGuard._orig_os_makedirs(name, *args, **kwargs)


def _guarded_os_rmdir(path, *args, **kwargs):
    _check_and_block(path, "os.rmdir")
    return ProductionWriteGuard._orig_os_rmdir(path, *args, **kwargs)


def _guarded_os_rename(src, dst, *args, **kwargs):
    _check_and_block(dst, "os.rename")
    _check_and_block(src, "os.rename")
    return ProductionWriteGuard._orig_os_rename(src, dst, *args, **kwargs)


def _guarded_os_replace(src, dst, *args, **kwargs):
    _check_and_block(dst, "os.replace")
    _check_and_block(src, "os.replace")
    return ProductionWriteGuard._orig_os_replace(src, dst, *args, **kwargs)


def _guarded_path_open(self, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    if any(m in str(mode) for m in ("w", "a", "x", "+")):
        _check_and_block(self, "Path.open")
    return ProductionWriteGuard._orig_path_open(self, *args, **kwargs)


def _guarded_path_write_text(self, *args, **kwargs):
    _check_and_block(self, "Path.write_text")
    return ProductionWriteGuard._orig_path_write_text(self, *args, **kwargs)


def _guarded_path_write_bytes(self, *args, **kwargs):
    _check_and_block(self, "Path.write_bytes")
    return ProductionWriteGuard._orig_path_write_bytes(self, *args, **kwargs)


def _guarded_path_unlink(self, *args, **kwargs):
    _check_and_block(self, "Path.unlink")
    return ProductionWriteGuard._orig_path_unlink(self, *args, **kwargs)


def _guarded_path_mkdir(self, *args, **kwargs):
    _check_and_block(self, "Path.mkdir")
    return ProductionWriteGuard._orig_path_mkdir(self, *args, **kwargs)


def _guarded_path_rmdir(self, *args, **kwargs):
    _check_and_block(self, "Path.rmdir")
    return ProductionWriteGuard._orig_path_rmdir(self, *args, **kwargs)


def _guarded_path_rename(self, target, *args, **kwargs):
    _check_and_block(target, "Path.rename")
    _check_and_block(self, "Path.rename")
    return ProductionWriteGuard._orig_path_rename(self, target, *args, **kwargs)


def _guarded_path_replace(self, target, *args, **kwargs):
    _check_and_block(target, "Path.replace")
    _check_and_block(self, "Path.replace")
    return ProductionWriteGuard._orig_path_replace(self, target, *args, **kwargs)


def _guarded_path_touch(self, *args, **kwargs):
    _check_and_block(self, "Path.touch")
    return ProductionWriteGuard._orig_path_touch(self, *args, **kwargs)


def _guarded_sqlite3_connect(*args, **kwargs):
    db_target = args[0] if args else kwargs.get("database")
    if db_target is not None:
        db_str = str(db_target)
        is_uri = kwargs.get("uri", False) or db_str.startswith("file:")
        is_memory = db_str == ":memory:" or (is_uri and "file::memory:" in db_str)
        is_ro = is_uri and ("mode=ro" in db_str or kwargs.get("mode") == "ro")
        if not is_memory and not is_ro:
            clean_target = db_str
            if is_uri and clean_target.startswith("file:"):
                clean_target = clean_target[5:].split("?")[0]
                if clean_target.startswith("///"):
                    clean_target = clean_target[3:]
                elif clean_target.startswith("//"):
                    clean_target = clean_target[2:]
            _check_and_block(clean_target, "sqlite3.connect")
    return ProductionWriteGuard._orig_sqlite3_connect(*args, **kwargs)


class ProductionWriteGuard:
    """Real-time Write-Boundary State Isolation Guard.

    Enforces that tests or subagents never touch production runtime state.
    Hooks OS and Python I/O write primitives and blocks prohibited operations
    immediately before execution, preventing transient file mutations.
    """
    _active_guards: list[ProductionWriteGuard] = []
    _lock = threading.RLock()
    _hooks_installed: bool = False

    _orig_builtins_open = None
    _orig_io_open = None
    _orig_os_open = None
    _orig_os_remove = None
    _orig_os_unlink = None
    _orig_os_mkdir = None
    _orig_os_makedirs = None
    _orig_os_rmdir = None
    _orig_os_rename = None
    _orig_os_replace = None
    _orig_path_open = None
    _orig_path_write_text = None
    _orig_path_write_bytes = None
    _orig_path_unlink = None
    _orig_path_mkdir = None
    _orig_path_rmdir = None
    _orig_path_rename = None
    _orig_path_replace = None
    _orig_path_touch = None
    _orig_sqlite3_connect = None

    def __init__(
        self,
        protected_roots: list[Path | str] | None = None,
        allowed_subpaths: list[Path | str] | None = None,
        run_id: str | None = None,
    ) -> None:
        self.protected_roots: list[Path] = [
            Path(p).resolve(strict=False) for p in (protected_roots or [])
        ]
        self.allowed_subpaths: list[Path] = [
            Path(p).resolve(strict=False) for p in (allowed_subpaths or [])
        ]
        self.run_id: str = run_id or f"guard_{uuid.uuid4().hex[:8]}"
        self.blocked_events: list[dict[str, Any]] = []
        self._is_active: bool = False
        self._event_lock = threading.Lock()
        self._bootstrap_dir: Path | None = None

    @classmethod
    def _install_hooks(cls) -> None:
        if cls._hooks_installed:
            return
        cls._orig_builtins_open = builtins.open
        cls._orig_io_open = io.open
        cls._orig_os_open = os.open
        cls._orig_os_remove = os.remove
        cls._orig_os_unlink = os.unlink
        cls._orig_os_mkdir = os.mkdir
        cls._orig_os_makedirs = os.makedirs
        cls._orig_os_rmdir = os.rmdir
        cls._orig_os_rename = os.rename
        cls._orig_os_replace = os.replace
        cls._orig_path_open = pathlib.Path.open
        cls._orig_path_write_text = pathlib.Path.write_text
        cls._orig_path_write_bytes = pathlib.Path.write_bytes
        cls._orig_path_unlink = pathlib.Path.unlink
        cls._orig_path_mkdir = pathlib.Path.mkdir
        cls._orig_path_rmdir = pathlib.Path.rmdir
        cls._orig_path_rename = pathlib.Path.rename
        cls._orig_path_replace = pathlib.Path.replace
        cls._orig_path_touch = pathlib.Path.touch
        cls._orig_sqlite3_connect = sqlite3.connect

        builtins.open = _guarded_builtins_open
        io.open = _guarded_io_open
        os.open = _guarded_os_open
        os.remove = _guarded_os_remove
        os.unlink = _guarded_os_unlink
        os.mkdir = _guarded_os_mkdir
        os.makedirs = _guarded_os_makedirs
        os.rmdir = _guarded_os_rmdir
        os.rename = _guarded_os_rename
        os.replace = _guarded_os_replace
        pathlib.Path.open = _guarded_path_open
        pathlib.Path.write_text = _guarded_path_write_text
        pathlib.Path.write_bytes = _guarded_path_write_bytes
        pathlib.Path.unlink = _guarded_path_unlink
        pathlib.Path.mkdir = _guarded_path_mkdir
        pathlib.Path.rmdir = _guarded_path_rmdir
        pathlib.Path.rename = _guarded_path_rename
        pathlib.Path.replace = _guarded_path_replace
        pathlib.Path.touch = _guarded_path_touch
        sqlite3.connect = _guarded_sqlite3_connect

        cls._hooks_installed = True

    @classmethod
    def _uninstall_hooks(cls) -> None:
        if not cls._hooks_installed:
            return
        builtins.open = cls._orig_builtins_open
        io.open = cls._orig_io_open
        os.open = cls._orig_os_open
        os.remove = cls._orig_os_remove
        os.unlink = cls._orig_os_unlink
        os.mkdir = cls._orig_os_mkdir
        os.makedirs = cls._orig_os_makedirs
        os.rmdir = cls._orig_os_rmdir
        os.rename = cls._orig_os_rename
        os.replace = cls._orig_os_replace
        pathlib.Path.open = cls._orig_path_open
        pathlib.Path.write_text = cls._orig_path_write_text
        pathlib.Path.write_bytes = cls._orig_path_write_bytes
        pathlib.Path.unlink = cls._orig_path_unlink
        pathlib.Path.mkdir = cls._orig_path_mkdir
        pathlib.Path.rmdir = cls._orig_path_rmdir
        pathlib.Path.rename = cls._orig_path_rename
        pathlib.Path.replace = cls._orig_path_replace
        pathlib.Path.touch = cls._orig_path_touch
        sqlite3.connect = cls._orig_sqlite3_connect

        cls._hooks_installed = False

    def is_path_protected(self, path: Path | str) -> bool:
        norm_path = Path(path).resolve(strict=False)
        for allowed in self.allowed_subpaths:
            if _is_subpath(norm_path, allowed):
                return False
        for root in self.protected_roots:
            if _is_subpath(norm_path, root):
                return True
        return False

    def record_blocked_event(self, event: dict[str, Any]) -> None:
        with self._event_lock:
            self.blocked_events.append(event)

    def activate(self) -> ProductionWriteGuard:
        with ProductionWriteGuard._lock:
            if self not in ProductionWriteGuard._active_guards:
                ProductionWriteGuard._active_guards.append(self)
            ProductionWriteGuard._install_hooks()
            self._is_active = True
        return self

    def deactivate(self) -> None:
        with ProductionWriteGuard._lock:
            if self in ProductionWriteGuard._active_guards:
                ProductionWriteGuard._active_guards.remove(self)
            if not ProductionWriteGuard._active_guards:
                ProductionWriteGuard._uninstall_hooks()
            self._is_active = False

    def __enter__(self) -> ProductionWriteGuard:
        return self.activate()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.deactivate()

    def get_subprocess_env(self, base_env: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(os.environ if base_env is None else base_env)

        if self._bootstrap_dir is None or not self._bootstrap_dir.exists():
            boot_dir = Path(tempfile.mkdtemp(prefix=f"mcp_guard_boot_{self.run_id}_")).resolve()
            sitecustomize_content = f'''"""Subprocess Write-Boundary State Isolation Guard Bootstrap."""
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
_project_root = os.environ.get("PROJECT_ROOT", "")
if _project_root and _project_root not in sys.path:
    sys.path.insert(0, _project_root)

_prot_str = os.environ.get("MCP_GUARD_PROTECTED_ROOTS", "")
_allow_str = os.environ.get("MCP_GUARD_ALLOWED_SUBPATHS", "")
_run_id = os.environ.get("MCP_GUARD_RUN_ID", "subproc")

if _prot_str:
    _protected = [Path(p) for p in _prot_str.split(os.pathsep) if p.strip()]
    _allowed = [Path(p) for p in _allow_str.split(os.pathsep) if p.strip()]
    try:
        from runtime.contracts import ProductionWriteGuard
        _guard = ProductionWriteGuard(protected_roots=_protected, allowed_subpaths=_allowed, run_id=_run_id)
        _guard.activate()
    except Exception as _exc:
        sys.stderr.write(f"WARNING: sitecustomize ProductionWriteGuard activation failed: {{_exc}}\\n")
'''
            (boot_dir / "sitecustomize.py").write_text(sitecustomize_content, encoding="utf-8")
            self._bootstrap_dir = boot_dir

        project_root = str(Path(__file__).resolve().parent.parent)
        env["PROJECT_ROOT"] = project_root
        env["MCP_GUARD_PROTECTED_ROOTS"] = os.pathsep.join(
            str(Path(p).resolve(strict=False)) for p in self.protected_roots
        )
        env["MCP_GUARD_ALLOWED_SUBPATHS"] = os.pathsep.join(
            str(Path(p).resolve(strict=False)) for p in self.allowed_subpaths
        )
        env["MCP_GUARD_RUN_ID"] = self.run_id

        existing_pp = env.get("PYTHONPATH", "")
        parts = [str(self._bootstrap_dir), project_root]
        if existing_pp:
            parts.append(existing_pp)
        env["PYTHONPATH"] = os.pathsep.join(parts)

        return env
