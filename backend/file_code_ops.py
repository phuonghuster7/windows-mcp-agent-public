"""Phase P2.1 (File Management) & Phase P2.2 (Coding & Git Operations).

Implements safe, atomic, policy-gated file and Git operations:
- Atomic writes (temp file in same directory + os.replace)
- Windows file-lock retry & clear diagnostics
- UTF-8 / UTF-16 (LE/BE/BOM) encoding preservation and auto-detection
- Automatic versioned backups in backups/file_versions/ before overwrite
- Recoverable deletion to backups/trash/ (and Windows Recycle Bin optional)
- Concurrency protection via expected_sha256 / ETag verification
- Unified diff preview and dry_run support for text edits
- Git repository allowlist enforcement & safe Git operations (fsmonitor/hooks disabled)
"""
from __future__ import annotations

import base64
import difflib
import fnmatch
import hashlib
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
GATEWAY_DIR = PROJECT_ROOT / "mcp-gateway"
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

from policy import PermissionTier, SecurityPolicy, redact_secrets  # noqa: E402


class ConcurrencyConflictError(ValueError):
    """Raised when expected_sha256 / ETag does not match current file content."""


class FileLockError(PermissionError):
    """Raised when a file is locked by another process on Windows."""


def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def detect_encoding_and_decode(raw: bytes) -> tuple[str, str]:
    """Detect text encoding (including UTF-8 BOM, UTF-16 LE/BE) and return (text, encoding_name)."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="strict"), "utf-8-sig"
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="strict"), "utf-16"
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="strict"), "utf-16-be"
    # Heuristic for BOM-less UTF-16 LE/BE
    if len(raw) >= 4 and len(raw) % 2 == 0:
        even_nulls = sum(1 for b in raw[0:min(len(raw), 512):2] if b == 0)
        odd_nulls = sum(1 for b in raw[1:min(len(raw), 512):2] if b == 0)
        sample_pairs = min(len(raw), 512) // 2
        if sample_pairs > 0 and odd_nulls / sample_pairs > 0.6 and even_nulls == 0:
            return raw.decode("utf-16-le", errors="strict"), "utf-16-le"
        if sample_pairs > 0 and even_nulls / sample_pairs > 0.6 and odd_nulls == 0:
            return raw.decode("utf-16-be", errors="strict"), "utf-16-be"
    if b"\x00" in raw[:8192]:
        raise ValueError("Binary file cannot be decoded as text")
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc, errors="strict"), enc
        except UnicodeDecodeError:
            continue
    raise ValueError("Unable to determine text encoding")


def encode_text(text: str, encoding: str = "utf-8") -> bytes:
    enc = encoding.lower().strip()
    if enc in ("utf-8", "utf8"):
        return text.encode("utf-8")
    if enc == "utf-8-sig":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    if enc == "utf-16":
        return b"\xff\xfe" + text.encode("utf-16-le")
    if enc == "utf-16-le":
        return text.encode("utf-16-le")
    if enc == "utf-16-be":
        return text.encode("utf-16-be")
    return text.encode(encoding)


def make_unified_diff(old_text: str, new_text: str, path_label: str) -> str:
    diff_lines = difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=f"a/{path_label}",
        tofile=f"b/{path_label}",
    )
    return "".join(diff_lines)


def _with_file_lock_retry(func, *args, retries: int = 5, delay: float = 0.08, **kwargs):
    """Execute file operation with Windows sharing-violation (WinError 32) retry."""
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            return func(*args, **kwargs)
        except PermissionError as err:
            last_err = err
            winerr = getattr(err, "winerror", None)
            if winerr in (5, 32, 33) and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
            if winerr in (32, 33):
                raise FileLockError(f"File is locked by another process: {err}") from err
            raise
        except OSError as err:
            last_err = err
            winerr = getattr(err, "winerror", None)
            if winerr in (32, 33) and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
            if winerr in (32, 33):
                raise FileLockError(f"File is locked by another process: {err}") from err
            raise
    if last_err:
        raise last_err


class FileCodeOperations:
    """Implements P2.1 File Management and P2.2 Coding & Git Operations."""

    def __init__(
        self,
        policy: SecurityPolicy | None = None,
        *,
        backups_root: str | Path | None = None,
        max_write_bytes: int = 25 * 1024 * 1024,
    ) -> None:
        self.policy = policy or SecurityPolicy()
        self.max_write_bytes: int = max(1, int(max_write_bytes))
        self.backups_root = Path(backups_root or (PROJECT_ROOT / "backups")).resolve(strict=False)
        self.versions_dir = self.backups_root / "file_versions"
        self.trash_dir = self.backups_root / "trash"
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self.trash_dir.mkdir(parents=True, exist_ok=True)

    def _check_write_size(self, num_bytes: int) -> None:
        if num_bytes > self.max_write_bytes:
            raise ValueError(
                f"Write size {num_bytes} bytes exceeds max_write_bytes limit ({self.max_write_bytes} bytes)"
            )

    def _backup_before_overwrite(self, target: Path) -> dict[str, Any] | None:
        if not target.exists() or not target.is_file():
            return None
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        uid = uuid.uuid4().hex[:8]
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", target.name)
        backup_name = f"{ts}_{uid}_{safe_name}"
        backup_path = self.versions_dir / backup_name
        shutil.copy2(target, backup_path)
        sha = compute_file_sha256(backup_path)
        meta = {
            "original_path": str(target),
            "backup_path": str(backup_path),
            "sha256": sha,
            "size": backup_path.stat().st_size,
            "timestamp": ts,
        }
        meta_path = self.versions_dir / f"{backup_name}.meta.json"
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        return meta

    def _check_expected_sha256(self, target: Path, expected_sha256: str | None) -> str | None:
        if not target.exists():
            if expected_sha256 is not None:
                raise ConcurrencyConflictError(
                    f"expected_sha256 '{expected_sha256}' provided, but file does not exist: {target}"
                )
            return None
        current_sha = compute_file_sha256(target)
        if expected_sha256 is not None and current_sha.lower() != expected_sha256.strip().lower():
            raise ConcurrencyConflictError(
                f"Concurrency conflict (ETag/SHA256 mismatch) for {target.name}: "
                f"expected {expected_sha256}, actual {current_sha}"
            )
        return current_sha

    def _atomic_write_bytes(self, target: Path, data: bytes) -> None:
        self._check_write_size(len(data))
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".tmp_{target.name}_",
            dir=str(target.parent),
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            _with_file_lock_retry(os.replace, str(tmp_path), str(target))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # P2.1 Read & Inspection Operations
    # ------------------------------------------------------------------
    def read_file(
        self,
        path: str,
        *,
        start_line: int | None = None,
        end_line: int | None = None,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool("read_file", {"path": path}, session_id=session_id, approval_token=approval_token)
        target = self.policy.validate_path(path, tier=PermissionTier.READ, check_content=True, must_exist=True)
        if not target.is_file():
            raise IsADirectoryError(f"Path is a directory, not a file: {target}")
        raw = _with_file_lock_retry(target.read_bytes)
        text, detected_encoding = detect_encoding_and_decode(raw)
        sha = compute_sha256_bytes(raw)
        lines = text.splitlines(keepends=True)
        total_lines = len(lines)

        if start_line is not None or end_line is not None:
            s = start_line if start_line is not None else 1
            e = end_line if end_line is not None else total_lines
            if s < 1 or e < s:
                raise ValueError(f"Invalid line range: {s}..{e}")
            content = "".join(lines[s - 1 : e])
        else:
            content = text

        res = {
            "path": str(target),
            "content": content,
            "encoding": detected_encoding,
            "sha256": sha,
            "size": len(raw),
            "total_lines": total_lines,
        }
        self.policy.audit.log_event(
            tool_name="read_file",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"path": str(target), "start_line": start_line, "end_line": end_line},
            result_summary={"sha256": sha, "size": len(raw)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def get_file(
        self,
        path: str,
        *,
        max_bytes: int = 15 * 1024 * 1024,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool("get_file", {"path": path}, session_id=session_id, approval_token=approval_token)
        target = self.policy.validate_path(path, tier=PermissionTier.READ, check_content=True, must_exist=True)
        if not target.is_file():
            raise IsADirectoryError(f"Target is not a regular file: {target}")
        size = target.stat().st_size
        if size > max_bytes:
            raise ValueError(f"File size {size} exceeds max_bytes limit ({max_bytes})")
        raw = _with_file_lock_retry(target.read_bytes)
        sha = compute_sha256_bytes(raw)
        mime, _ = mimetypes.guess_type(str(target))
        b64 = base64.b64encode(raw).decode("ascii")
        res = {
            "path": str(target),
            "name": target.name,
            "size": size,
            "sha256": sha,
            "mime_type": mime or "application/octet-stream",
            "data_base64": b64,
            "resource": {
                "uri": target.as_uri(),
                "mimeType": mime or "application/octet-stream",
                "blob": b64,
            },
        }
        self.policy.audit.log_event(
            tool_name="get_file",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"path": str(target)},
            result_summary={"size": size, "sha256": sha},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def search_files(
        self,
        root: str,
        pattern: str = "*",
        *,
        recursive: bool = True,
        max_results: int = 200,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "search_files", {"root": root, "pattern": pattern}, session_id=session_id, approval_token=approval_token
        )
        root_path = self.policy.validate_path(root, tier=PermissionTier.READ, must_exist=True)
        if not root_path.is_dir():
            raise NotADirectoryError(f"Search root is not a directory: {root_path}")

        matches: list[dict[str, Any]] = []
        iterator = root_path.rglob("*") if recursive else root_path.glob("*")
        for entry in iterator:
            if len(matches) >= max_results:
                break
            try:
                if self.policy.is_sensitive_path_str(entry, check_content=True):
                    continue
                if fnmatch.fnmatch(entry.name.casefold(), pattern.casefold()):
                    # Ensure no symlink escape
                    real_entry = Path(os.path.realpath(str(entry)))
                    if not any(real_entry == r or real_entry.is_relative_to(r) for r in self.policy.read_roots):
                        continue
                    st = entry.stat()
                    matches.append({
                        "path": str(entry),
                        "name": entry.name,
                        "is_dir": entry.is_dir(),
                        "size": st.st_size if entry.is_file() else 0,
                    })
            except OSError:
                continue

        res = {"root": str(root_path), "pattern": pattern, "results": matches, "count": len(matches)}
        self.policy.audit.log_event(
            tool_name="search_files",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"root": str(root_path), "pattern": pattern},
            result_summary={"count": len(matches)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def search_code(
        self,
        root: str,
        query: str,
        *,
        file_pattern: str = "*",
        case_sensitive: bool = False,
        max_results: int = 200,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        return self._search_text_in_files(
            tool_name="search_code",
            root=root,
            query=query,
            file_pattern=file_pattern,
            is_regex=False,
            case_sensitive=case_sensitive,
            max_results=max_results,
            session_id=session_id,
            approval_token=approval_token,
        )

    def grep(
        self,
        root: str,
        pattern: str,
        *,
        file_pattern: str = "*",
        case_sensitive: bool = False,
        max_results: int = 200,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        return self._search_text_in_files(
            tool_name="grep",
            root=root,
            query=pattern,
            file_pattern=file_pattern,
            is_regex=True,
            case_sensitive=case_sensitive,
            max_results=max_results,
            session_id=session_id,
            approval_token=approval_token,
        )

    def _search_text_in_files(
        self,
        *,
        tool_name: str,
        root: str,
        query: str,
        file_pattern: str = "*",
        is_regex: bool = False,
        case_sensitive: bool = False,
        max_results: int = 200,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            tool_name,
            {"root": root, "query": query, "file_pattern": file_pattern},
            session_id=session_id,
            approval_token=approval_token,
        )
        root_path = self.policy.validate_path(root, tier=PermissionTier.READ, must_exist=True)
        if not root_path.is_dir():
            raise NotADirectoryError(f"Search root is not a directory: {root_path}")
        flags = 0 if case_sensitive else re.IGNORECASE
        regex = re.compile(query if is_regex else re.escape(query), flags)
        matches: list[dict[str, Any]] = []
        for entry in root_path.rglob("*"):
            if len(matches) >= max_results:
                break
            try:
                if not entry.is_file():
                    continue
                if self.policy.is_sensitive_path_str(entry, check_content=True):
                    continue
                if not fnmatch.fnmatch(entry.name.casefold(), file_pattern.casefold()):
                    continue
                real_entry = Path(os.path.realpath(str(entry)))
                if not any(real_entry == r or real_entry.is_relative_to(r) for r in self.policy.read_roots):
                    continue
                if self.policy.is_sensitive_path_str(real_entry, check_content=True):
                    continue
                raw = entry.read_bytes()
                text, _ = detect_encoding_and_decode(raw)
                for idx, line in enumerate(text.splitlines(), start=1):
                    if regex.search(line):
                        matches.append({
                            "path": str(entry),
                            "line_number": idx,
                            "line": redact_secrets(line),
                        })
                        if len(matches) >= max_results:
                            break
            except Exception:
                continue
        res = {"root": str(root_path), "query": query, "matches": matches, "results": matches, "count": len(matches)}
        self.policy.audit.log_event(
            tool_name=tool_name,
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"root": str(root_path), "query": query},
            result_summary={"count": len(matches)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    # ------------------------------------------------------------------
    # P2.1 Write Operations
    # ------------------------------------------------------------------
    def create_directory(
        self,
        path: str,
        *,
        exist_ok: bool = True,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "create_directory", {"path": path}, session_id=session_id, approval_token=approval_token
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=False)
        already_existed = target.exists()
        target.mkdir(parents=True, exist_ok=exist_ok)
        res = {"ok": True, "path": str(target), "created": not already_existed}
        self.policy.audit.log_event(
            tool_name="create_directory",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target)},
            result_summary=res,
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def write_file(
        self,
        path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        overwrite: bool = True,
        create_parents: bool = True,
        expected_sha256: str | None = None,
        dry_run: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "write_file",
            {"path": path, "encoding": encoding, "overwrite": overwrite, "dry_run": dry_run},
            session_id=session_id,
            approval_token=approval_token,
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=True)
        existed = target.exists()
        if existed and not overwrite:
            raise FileExistsError(f"File already exists and overwrite=False: {target}")

        prev_sha = self._check_expected_sha256(target, expected_sha256)
        old_text = ""
        if existed:
            try:
                old_text, _ = detect_encoding_and_decode(target.read_bytes())
            except Exception:
                old_text = ""

        encoded = encode_text(content, encoding)
        self._check_write_size(len(encoded))
        new_sha = compute_sha256_bytes(encoded)
        diff = make_unified_diff(old_text, content, target.name)

        backup_meta = None
        if not dry_run:
            if create_parents:
                target.parent.mkdir(parents=True, exist_ok=True)
            if existed:
                backup_meta = self._backup_before_overwrite(target)
            self._atomic_write_bytes(target, encoded)

        res = {
            "ok": True,
            "path": str(target),
            "dry_run": dry_run,
            "overwritten": existed,
            "encoding": encoding,
            "previous_sha256": prev_sha,
            "sha256": new_sha,
            "bytes_written": len(encoded),
            "diff": diff,
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="write_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target), "encoding": encoding, "dry_run": dry_run},
            result_summary={"sha256": new_sha, "bytes_written": len(encoded), "overwritten": existed},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def append_file(
        self,
        path: str,
        content: str,
        *,
        encoding: str | None = None,
        expected_sha256: str | None = None,
        dry_run: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "append_file", {"path": path, "dry_run": dry_run}, session_id=session_id, approval_token=approval_token
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=True)
        prev_sha = self._check_expected_sha256(target, expected_sha256)

        if target.exists():
            raw = _with_file_lock_retry(target.read_bytes)
            old_text, detected_enc = detect_encoding_and_decode(raw)
            use_enc = encoding or detected_enc
        else:
            old_text = ""
            use_enc = encoding or "utf-8"

        new_text = old_text + content
        encoded = encode_text(new_text, use_enc)
        self._check_write_size(len(encoded))
        new_sha = compute_sha256_bytes(encoded)
        diff = make_unified_diff(old_text, new_text, target.name)

        backup_meta = None
        if not dry_run:
            if target.exists():
                backup_meta = self._backup_before_overwrite(target)
            self._atomic_write_bytes(target, encoded)

        res = {
            "ok": True,
            "path": str(target),
            "dry_run": dry_run,
            "encoding": use_enc,
            "previous_sha256": prev_sha,
            "sha256": new_sha,
            "bytes_written": len(encoded),
            "diff": diff,
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="append_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target), "dry_run": dry_run},
            result_summary={"sha256": new_sha, "bytes_written": len(encoded)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def edit_file(
        self,
        path: str,
        old_text: str,
        new_text: str,
        *,
        expected_occurrences: int = 1,
        expected_sha256: str | None = None,
        dry_run: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "edit_file",
            {"path": path, "expected_occurrences": expected_occurrences, "dry_run": dry_run},
            session_id=session_id,
            approval_token=approval_token,
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=True, must_exist=True)
        prev_sha = self._check_expected_sha256(target, expected_sha256)

        raw = _with_file_lock_retry(target.read_bytes)
        current_text, detected_enc = detect_encoding_and_decode(raw)

        count = current_text.count(old_text)
        if count == 0:
            raise ValueError(f"Target text not found in {target.name}")
        if expected_occurrences > 0 and count != expected_occurrences:
            raise ValueError(
                f"Expected {expected_occurrences} occurrence(s) of target text in {target.name}, found {count}"
            )

        updated_text = current_text.replace(old_text, new_text, expected_occurrences if expected_occurrences > 0 else -1)
        encoded = encode_text(updated_text, detected_enc)
        self._check_write_size(len(encoded))
        new_sha = compute_sha256_bytes(encoded)
        diff = make_unified_diff(current_text, updated_text, target.name)

        backup_meta = None
        if not dry_run:
            backup_meta = self._backup_before_overwrite(target)
            self._atomic_write_bytes(target, encoded)

        res = {
            "ok": True,
            "path": str(target),
            "dry_run": dry_run,
            "encoding": detected_enc,
            "replacements": count if expected_occurrences <= 0 else expected_occurrences,
            "previous_sha256": prev_sha,
            "sha256": new_sha,
            "diff": diff,
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="edit_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target), "expected_occurrences": expected_occurrences, "dry_run": dry_run},
            result_summary={"sha256": new_sha, "replacements": res["replacements"]},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def apply_patch(
        self,
        path: str,
        patch: str,
        *,
        expected_sha256: str | None = None,
        dry_run: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Apply search/replace blocks (<<<<<<< SEARCH ... ======= ... >>>>>>> REPLACE)
        or unified diff hunks (@@ -l,c +l,c @@) atomically.
        """
        t0 = time.time()
        self.policy.authorize_tool(
            "apply_patch", {"path": path, "dry_run": dry_run}, session_id=session_id, approval_token=approval_token
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=True, must_exist=True)
        prev_sha = self._check_expected_sha256(target, expected_sha256)

        raw = _with_file_lock_retry(target.read_bytes)
        current_text, detected_enc = detect_encoding_and_decode(raw)
        updated_text = current_text

        # Format 1: <<<<<<< SEARCH ... ======= ... >>>>>>> REPLACE
        sr_pattern = re.compile(
            r"<{5,9}\s*SEARCH\r?\n([\s\S]*?)\r?\n={5,9}\r?\n([\s\S]*?)\r?\n>{5,9}\s*REPLACE"
        )
        sr_blocks = sr_pattern.findall(patch)
        if sr_blocks:
            for search_part, replace_part in sr_blocks:
                if search_part not in updated_text:
                    raise ValueError(f"SEARCH block not found in {target.name}")
                updated_text = updated_text.replace(search_part, replace_part, 1)
        elif "@@" in patch:
            # Format 2: Unified diff hunks
            updated_text = self._apply_unified_diff_text(current_text, patch)
        else:
            raise ValueError("Unsupported patch format: must contain SEARCH/REPLACE blocks or unified diff @@ hunks")

        encoded = encode_text(updated_text, detected_enc)
        self._check_write_size(len(encoded))
        new_sha = compute_sha256_bytes(encoded)
        diff = make_unified_diff(current_text, updated_text, target.name)

        backup_meta = None
        if not dry_run:
            backup_meta = self._backup_before_overwrite(target)
            self._atomic_write_bytes(target, encoded)

        res = {
            "ok": True,
            "path": str(target),
            "dry_run": dry_run,
            "encoding": detected_enc,
            "previous_sha256": prev_sha,
            "sha256": new_sha,
            "diff": diff,
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="apply_patch",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target), "dry_run": dry_run},
            result_summary={"sha256": new_sha},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    @staticmethod
    def _apply_unified_diff_text(original: str, patch_text: str) -> str:
        orig_lines = original.splitlines(keepends=False)
        out_lines = list(orig_lines)
        hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
        lines = patch_text.splitlines(keepends=False)
        offset = 0
        i = 0
        while i < len(lines):
            m = hunk_re.match(lines[i])
            if not m:
                i += 1
                continue
            start_old = int(m.group(1)) - 1 + offset
            i += 1
            hunk_old: list[str] = []
            hunk_new: list[str] = []
            while i < len(lines) and not lines[i].startswith("@@ "):
                line = lines[i]
                if line.startswith(("---", "+++", "\\ No newline")):
                    i += 1
                    continue
                if line.startswith("-"):
                    hunk_old.append(line[1:])
                elif line.startswith("+"):
                    hunk_new.append(line[1:])
                elif line.startswith(" "):
                    hunk_old.append(line[1:])
                    hunk_new.append(line[1:])
                else:
                    hunk_old.append(line)
                    hunk_new.append(line)
                i += 1
            slice_end = start_old + len(hunk_old)
            if out_lines[start_old:slice_end] != hunk_old:
                raise ValueError("Unified diff hunk context mismatch")
            out_lines[start_old:slice_end] = hunk_new
            offset += len(hunk_new) - len(hunk_old)

        trailing_nl = "\n" if original.endswith("\n") else ""
        return "\n".join(out_lines) + trailing_nl

    def copy_file(
        self,
        src: str,
        dest: str,
        *,
        overwrite: bool = True,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "copy_file", {"src": src, "dest": dest}, session_id=session_id, approval_token=approval_token
        )
        src_path = self.policy.validate_path(src, tier=PermissionTier.READ, check_content=True, must_exist=True)
        dest_path = self.policy.validate_path(dest, tier=PermissionTier.WRITE, check_content=True)
        if not src_path.is_file():
            raise IsADirectoryError(f"Source is not a regular file: {src_path}")
        if dest_path.exists() and not overwrite:
            raise FileExistsError(f"Destination exists and overwrite=False: {dest_path}")

        backup_meta = self._backup_before_overwrite(dest_path) if dest_path.exists() else None
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        data = _with_file_lock_retry(src_path.read_bytes)
        self._atomic_write_bytes(dest_path, data)
        sha = compute_sha256_bytes(data)

        res = {
            "ok": True,
            "src": str(src_path),
            "dest": str(dest_path),
            "sha256": sha,
            "size": len(data),
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="copy_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"src": str(src_path), "dest": str(dest_path)},
            result_summary={"sha256": sha, "size": len(data)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def move_file(
        self,
        src: str,
        dest: str,
        *,
        overwrite: bool = True,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "move_file", {"src": src, "dest": dest}, session_id=session_id, approval_token=approval_token
        )
        src_path = self.policy.validate_path(src, tier=PermissionTier.WRITE, check_content=True, must_exist=True)
        dest_path = self.policy.validate_path(dest, tier=PermissionTier.WRITE, check_content=True)
        if dest_path.exists() and not overwrite:
            raise FileExistsError(f"Destination exists and overwrite=False: {dest_path}")

        backup_meta = self._backup_before_overwrite(dest_path) if dest_path.exists() else None
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        _with_file_lock_retry(os.replace, str(src_path), str(dest_path))
        sha = compute_file_sha256(dest_path) if dest_path.is_file() else None

        res = {
            "ok": True,
            "src": str(src_path),
            "dest": str(dest_path),
            "sha256": sha,
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="move_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"src": str(src_path), "dest": str(dest_path)},
            result_summary={"sha256": sha},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def rename_file(
        self,
        src: str,
        new_name: str,
        *,
        overwrite: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "rename_file", {"src": src, "new_name": new_name}, session_id=session_id, approval_token=approval_token
        )
        src_path = self.policy.validate_path(src, tier=PermissionTier.WRITE, check_content=True, must_exist=True)
        dest_candidate = Path(new_name) if Path(new_name).is_absolute() else (src_path.parent / new_name)
        return self.move_file(
            str(src_path),
            str(dest_candidate),
            overwrite=overwrite,
            session_id=session_id,
            approval_token=approval_token,
        )

    def delete_file(
        self,
        path: str,
        *,
        expected_sha256: str | None = None,
        dry_run: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Recoverable delete: moves file to backups/trash/ with manifest before removal."""
        t0 = time.time()
        self.policy.authorize_tool(
            "delete_file", {"path": path, "dry_run": dry_run}, session_id=session_id, approval_token=approval_token
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=False, must_exist=True)
        if not target.is_file():
            raise IsADirectoryError(f"delete_file only deletes regular files: {target}")

        prev_sha = self._check_expected_sha256(target, expected_sha256)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        uid = uuid.uuid4().hex[:8]
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", target.name)
        trash_path = self.trash_dir / f"{ts}_{uid}_{safe_name}"

        if not dry_run:
            self.trash_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, trash_path)
            meta = {
                "original_path": str(target),
                "trash_path": str(trash_path),
                "sha256": prev_sha,
                "deleted_at": ts,
            }
            (self.trash_dir / f"{ts}_{uid}_{safe_name}.trash.json").write_text(
                json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            _with_file_lock_retry(target.unlink)

        res = {
            "ok": True,
            "path": str(target),
            "dry_run": dry_run,
            "sha256": prev_sha,
            "recoverable_trash_path": str(trash_path),
        }
        self.policy.audit.log_event(
            tool_name="delete_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target), "dry_run": dry_run},
            result_summary=res,
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def restore_file(
        self,
        target_path: str,
        backup_path: str | None = None,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Restore a file from backups/file_versions/ or backups/trash/."""
        t0 = time.time()
        self.policy.authorize_tool(
            "restore_file",
            {"target_path": target_path, "backup_path": backup_path},
            session_id=session_id,
            approval_token=approval_token,
        )
        dest = self.policy.validate_path(target_path, tier=PermissionTier.WRITE, check_content=True)

        chosen_backup: Path | None = None
        if backup_path:
            bp = Path(backup_path).resolve(strict=False)
            if not (bp.is_relative_to(self.versions_dir) or bp.is_relative_to(self.trash_dir)):
                raise PermissionError("backup_path must reside inside backups/file_versions or backups/trash")
            if not bp.exists():
                raise FileNotFoundError(f"Backup file not found: {bp}")
            chosen_backup = bp
        else:
            # Find latest backup metadata matching dest
            candidates: list[tuple[str, Path]] = []
            for meta_file in list(self.versions_dir.glob("*.meta.json")) + list(self.trash_dir.glob("*.trash.json")):
                try:
                    data = json.loads(meta_file.read_text(encoding="utf-8"))
                    if Path(data.get("original_path", "")).resolve(strict=False) == dest:
                        b_file = Path(data.get("backup_path") or data.get("trash_path"))
                        if b_file.exists():
                            candidates.append((data.get("timestamp") or data.get("deleted_at") or "", b_file))
                except Exception:
                    continue
            if not candidates:
                raise FileNotFoundError(f"No backup found for {dest}")
            candidates.sort(key=lambda item: item[0], reverse=True)
            chosen_backup = candidates[0][1]

        raw = chosen_backup.read_bytes()
        self._atomic_write_bytes(dest, raw)
        sha = compute_sha256_bytes(raw)
        res = {
            "ok": True,
            "path": str(dest),
            "restored_from": str(chosen_backup),
            "sha256": sha,
            "size": len(raw),
        }
        self.policy.audit.log_event(
            tool_name="restore_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"target_path": str(dest), "backup_path": str(chosen_backup)},
            result_summary={"sha256": sha},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def put_file(
        self,
        path: str,
        data_base64: str,
        *,
        overwrite: bool = True,
        expected_sha256: str | None = None,
        dry_run: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "put_file", {"path": path, "dry_run": dry_run}, session_id=session_id, approval_token=approval_token
        )
        target = self.policy.validate_path(path, tier=PermissionTier.WRITE, check_content=True)
        if target.exists() and not overwrite:
            raise FileExistsError(f"File already exists and overwrite=False: {target}")
        prev_sha = self._check_expected_sha256(target, expected_sha256)
        raw = base64.b64decode(data_base64, validate=True)
        self._check_write_size(len(raw))
        new_sha = compute_sha256_bytes(raw)

        backup_meta = None
        if not dry_run:
            if target.exists():
                backup_meta = self._backup_before_overwrite(target)
            self._atomic_write_bytes(target, raw)

        res = {
            "ok": True,
            "path": str(target),
            "dry_run": dry_run,
            "previous_sha256": prev_sha,
            "sha256": new_sha,
            "size": len(raw),
            "backup": backup_meta,
        }
        self.policy.audit.log_event(
            tool_name="put_file",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"path": str(target), "dry_run": dry_run},
            result_summary={"sha256": new_sha, "size": len(raw)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    # ------------------------------------------------------------------
    # P2.2 Coding & Safe Git Operations
    # ------------------------------------------------------------------
    @staticmethod
    def _build_sanitized_git_env() -> dict[str, str]:
        """Build a sanitized environment for Git child processes."""
        sensitive_exact = {
            "MCP_AUTH_TOKEN",
            "COMPUTER_API_TOKEN",
            "OPENAI_API_KEY",
            "CONTROL_PLANE_API_KEY",
            "ANTIGRAVITY_CSRF_TOKEN",
            "VNSTOCK_API_KEY",
            "MCP_AGENT_APPROVAL_TOKEN",
        }
        sensitive_re = re.compile(
            r"(?:_SECRET|SECRET_|^SECRET$|_TOKEN|TOKEN_|^TOKEN$|_API_KEY|API_KEY_|^API_KEY$|_PASSWORD|PASSWORD_|^PASSWORD$)",
            re.IGNORECASE,
        )
        env: dict[str, str] = {}
        for k, v in os.environ.items():
            if not isinstance(k, str) or "\x00" in k:
                continue
            upper = k.strip().upper()
            if upper in sensitive_exact or sensitive_re.search(upper):
                continue
            env[str(k)] = str(v)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "echo"
        env["SSH_ASKPASS"] = "echo"
        env["GCM_INTERACTIVE"] = "never"
        return env

    def _run_safe_git(self, repo_dir: Path, git_args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        """Run git with external hooks, fsmonitor, and local file protocol disabled."""
        cmd = [
            "git",
            "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=NUL",
            "-c", "protocol.file.allow=never",
            *git_args,
        ]
        env = self._build_sanitized_git_env()
        return subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )

    def git_status(
        self, cwd: str, *, session_id: str | None = None, approval_token: str | None = None
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool("git_status", {"cwd": cwd}, session_id=session_id, approval_token=approval_token)
        repo_dir = self.policy.validate_git_repo(cwd, write=False)
        proc = self._run_safe_git(repo_dir, ["status", "--short", "--branch"])
        if proc.returncode != 0:
            raise RuntimeError(f"git status failed: {proc.stderr.strip()}")
        lines = [
            ln for ln in proc.stdout.splitlines()
            if not self.policy.is_sensitive_path_str(ln[3:].strip(), check_content=False)
        ]
        res = {"cwd": str(repo_dir), "output": "\n".join(lines), "clean": len(lines) <= 1}
        self.policy.audit.log_event(
            tool_name="git_status",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"cwd": str(repo_dir)},
            result_summary={"clean": res["clean"]},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def git_diff(
        self,
        cwd: str,
        *,
        staged: bool = False,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "git_diff", {"cwd": cwd, "staged": staged}, session_id=session_id, approval_token=approval_token
        )
        repo_dir = self.policy.validate_git_repo(cwd, write=False)
        args = ["diff", "--no-ext-diff"]
        if staged:
            args.append("--staged")
        proc = self._run_safe_git(repo_dir, args)
        if proc.returncode != 0:
            raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")
        res = {"cwd": str(repo_dir), "staged": staged, "diff": redact_secrets(proc.stdout)}
        self.policy.audit.log_event(
            tool_name="git_diff",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"cwd": str(repo_dir), "staged": staged},
            result_summary={"diff_len": len(proc.stdout)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def git_log(
        self,
        cwd: str,
        *,
        n: int = 10,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool("git_log", {"cwd": cwd, "n": n}, session_id=session_id, approval_token=approval_token)
        repo_dir = self.policy.validate_git_repo(cwd, write=False)
        n = max(1, min(100, int(n)))
        proc = self._run_safe_git(repo_dir, ["log", f"-n{n}", "--oneline", "--no-decorate"])
        if proc.returncode != 0:
            raise RuntimeError(f"git log failed: {proc.stderr.strip()}")
        res = {"cwd": str(repo_dir), "n": n, "log": redact_secrets(proc.stdout.strip())}
        self.policy.audit.log_event(
            tool_name="git_log",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"cwd": str(repo_dir), "n": n},
            result_summary={"lines": len(proc.stdout.splitlines())},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def git_worktree_list(
        self, cwd: str, *, session_id: str | None = None, approval_token: str | None = None
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "git_worktree_list", {"cwd": cwd}, session_id=session_id, approval_token=approval_token
        )
        repo_dir = self.policy.validate_git_repo(cwd, write=False)
        proc = self._run_safe_git(repo_dir, ["worktree", "list", "--porcelain"])
        if proc.returncode != 0:
            raise RuntimeError(f"git worktree list failed: {proc.stderr.strip()}")
        worktrees: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            if not line.strip():
                if current:
                    worktrees.append(current)
                    current = {}
                continue
            parts = line.split(" ", 1)
            current[parts[0]] = parts[1] if len(parts) > 1 else "true"
        if current:
            worktrees.append(current)
        res = {"cwd": str(repo_dir), "worktrees": worktrees}
        self.policy.audit.log_event(
            tool_name="git_worktree_list",
            tier=PermissionTier.READ,
            decision="ALLOW",
            arguments={"cwd": str(repo_dir)},
            result_summary={"count": len(worktrees)},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def git_branch_create(
        self,
        cwd: str,
        branch_name: str,
        *,
        checkout: bool = True,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        t0 = time.time()
        self.policy.authorize_tool(
            "git_branch_create",
            {"cwd": cwd, "branch_name": branch_name, "checkout": checkout},
            session_id=session_id,
            approval_token=approval_token,
        )
        repo_dir = self.policy.validate_git_repo(cwd, write=True)
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch_name) or ".." in branch_name or branch_name.startswith("-"):
            raise ValueError(f"Invalid git branch name: {branch_name}")

        args = ["checkout", "-b", branch_name] if checkout else ["branch", branch_name]
        proc = self._run_safe_git(repo_dir, args)
        if proc.returncode != 0:
            raise RuntimeError(f"git branch creation failed: {proc.stderr.strip()}")

        res = {"ok": True, "cwd": str(repo_dir), "branch_name": branch_name, "checked_out": checkout}
        self.policy.audit.log_event(
            tool_name="git_branch_create",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"cwd": str(repo_dir), "branch_name": branch_name},
            result_summary=res,
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res

    def git_add_commit(
        self,
        cwd: str,
        message: str,
        files: list[str],
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Policy-gated git stage + commit that never alters history or stages secret files."""
        t0 = time.time()
        self.policy.authorize_tool(
            "git_add_commit",
            {"cwd": cwd, "message": message, "files": files},
            session_id=session_id,
            approval_token=approval_token,
        )
        repo_dir = self.policy.validate_git_repo(cwd, write=True)
        if not message or not message.strip():
            raise ValueError("Commit message must not be empty")
        if not files:
            raise ValueError("Explicit list of files is required for git_add_commit")

        validated_rel_files: list[str] = []
        for f in files:
            f_path = Path(f) if Path(f).is_absolute() else (repo_dir / f)
            resolved_f = self.policy.validate_path(f_path, tier=PermissionTier.WRITE, check_content=True)
            if not resolved_f.is_relative_to(repo_dir):
                raise PermissionError(f"File '{resolved_f}' is outside repository '{repo_dir}'")
            validated_rel_files.append(str(resolved_f.relative_to(repo_dir)))

        add_proc = self._run_safe_git(repo_dir, ["add", "--", *validated_rel_files])
        if add_proc.returncode != 0:
            raise RuntimeError(f"git add failed: {add_proc.stderr.strip()}")

        commit_proc = self._run_safe_git(
            repo_dir,
            ["commit", "--no-verify", "-m", message.strip()],
        )
        if commit_proc.returncode != 0:
            raise RuntimeError(f"git commit failed: {commit_proc.stderr.strip() or commit_proc.stdout.strip()}")

        rev_proc = self._run_safe_git(repo_dir, ["rev-parse", "HEAD"])
        commit_sha = rev_proc.stdout.strip() if rev_proc.returncode == 0 else ""

        res = {
            "ok": True,
            "cwd": str(repo_dir),
            "commit_sha": commit_sha,
            "message": message.strip(),
            "files": validated_rel_files,
        }
        self.policy.audit.log_event(
            tool_name="git_add_commit",
            tier=PermissionTier.WRITE,
            decision="ALLOW",
            arguments={"cwd": str(repo_dir), "message": message.strip(), "files": validated_rel_files},
            result_summary={"commit_sha": commit_sha},
            session_id=session_id,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return res
