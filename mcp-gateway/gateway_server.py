"""Unified MCP Gateway Server (v0.3.0 / Bridge v0.2.1 Compatible).

Preserves 100% compatibility with the 15 reviewed read-only tools from Bridge v0.2.1:
  get_roots, list_directory, list_tree, stat_path, read_file, read_file_range,
  get_file, search_files, search_code, grep, disk_usage, path_exists,
  git_status, git_diff, git_log

Supports profile-gated publication and execution of:
- Phase P2.1 File Management (create_directory, write_file, append_file, edit_file,
  apply_patch, copy_file, move_file, rename_file, delete_file, put_file, restore_file)
- Phase P2.2 Coding & Git (git_worktree_list, git_branch_create, git_add_commit)
- Phase P2.3 Shell, Process & Jobs (powershell_execute, cmd_execute, process_start,
  process_status, process_stop, job_create, job_poll, job_cancel, job_logs)
- Phase P3.1 - P3.5 Desktop Agent (get_desktop_session_status, get_screen_geometry,
  screenshot, list_windows, get_active_window, focus_window, mouse_move, mouse_click,
  mouse_double_click, mouse_right_click, mouse_scroll, mouse_drag, keyboard_type,
  keyboard_keypress, keyboard_hotkey, get_clipboard_text, set_clipboard_text,
  visual_action_verify)
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
DESKTOP_DIR = PROJECT_ROOT / "desktop-agent"

for _d in (PROJECT_ROOT, HERE, BACKEND_DIR, DESKTOP_DIR):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from policy import (  # noqa: E402
    PermissionTier,
    SecurityPolicy,
    TOOL_TIER_MAP,
    V021_READ_TOOLS,
    redact_secrets,
)
from file_code_ops import FileCodeOperations, detect_encoding_and_decode  # noqa: E402
from exec_jobs import ExecutionJobManager  # noqa: E402
from agent import DesktopAgent  # noqa: E402

LOG = logging.getLogger("mcp_gateway")
RESPONSE_LIMIT = 120_000

CODE_FILE_GLOBS = frozenset((
    "*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.go", "*.rs", "*.java",
    "*.c", "*.cpp", "*.h", "*.hpp", "*.cs", "*.rb", "*.php", "*.swift",
    "*.kt", "*.scala", "*.lua", "*.sh", "*.bash", "*.zsh", "*.ps1",
    "*.bat", "*.cmd", "*.sql", "*.r", "*.R", "*.m", "*.mm",
    "*.html", "*.htm", "*.css", "*.scss", "*.less", "*.sass",
    "*.xml", "*.json", "*.yaml", "*.yml", "*.toml", "*.ini", "*.cfg",
    "*.md", "*.rst", "*.txt", "*.csv", "*.log", "*.vue", "*.svelte",
    "*.dart", "*.ex", "*.exs", "*.erl", "*.hs", "*.ml", "*.jl",
    "*.dockerfile", "*.tf", "*.hcl", "*.proto", "*.graphql",
    "*.makefile", "Makefile",
))


def _load_v021_catalog() -> dict[str, dict[str, Any]]:
    cat_path = HERE / "tools_catalog.json"
    if not cat_path.exists():
        return {}
    raw = json.loads(cat_path.read_text(encoding="utf-8"))
    return {item["name"]: item for item in raw.get("tools", [])}


_V021_BY_NAME = _load_v021_catalog()


def _build_all_tool_definitions() -> dict[str, dict[str, Any]]:
    """Build complete tool metadata and JSON schemas for all Gateway tools."""
    defs: dict[str, dict[str, Any]] = {}

    # 1. Load exact v0.2.1 schemas for the 15 read tools
    for name in V021_READ_TOOLS:
        if name in _V021_BY_NAME:
            defs[name] = {
                "name": name,
                "description": _V021_BY_NAME[name]["description"],
                "input_schema": _V021_BY_NAME[name]["input_schema"],
            }

    # Ensure fallback schemas if catalog missing any of the 15
    _fallback_15 = {
        "get_roots": ("READ-ONLY. Retrieve all approved filesystem roots.", {"type": "object", "properties": {}, "required": [], "additionalProperties": False}),
        "list_directory": ("READ-ONLY. List contents of a directory.", {"type": "object", "properties": {"path": {"type": "string"}, "include_hidden": {"type": "boolean"}}, "required": ["path"], "additionalProperties": False}),
        "list_tree": ("READ-ONLY. Get recursive tree view.", {"type": "object", "properties": {"path": {"type": "string"}, "max_depth": {"type": "integer"}, "max_entries": {"type": "integer"}}, "required": ["path"], "additionalProperties": False}),
        "stat_path": ("READ-ONLY. Get file or directory metadata.", {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}),
        "read_file": ("READ-ONLY. Read a text file from the local computer.", {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}),
        "read_file_range": ("READ-ONLY. Read a specific range of lines.", {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, "required": ["path", "start_line", "end_line"], "additionalProperties": False}),
        "get_file": ("READ-ONLY. Read binary or text file safely (max 15MB).", {"type": "object", "properties": {"path": {"type": "string"}, "max_bytes": {"type": "integer"}}, "required": ["path"], "additionalProperties": False}),
        "search_files": ("READ-ONLY. Search for files by name/glob.", {"type": "object", "properties": {"root": {"type": "string"}, "pattern": {"type": "string"}, "recursive": {"type": "boolean"}, "max_results": {"type": "integer"}}, "required": ["root", "pattern"], "additionalProperties": False}),
        "search_code": ("READ-ONLY. Search text/regex in source code.", {"type": "object", "properties": {"cwd": {"type": "string"}, "pattern": {"type": "string"}, "file_glob": {"type": "string"}, "max_results": {"type": "integer"}}, "required": ["cwd", "pattern"], "additionalProperties": False}),
        "grep": ("READ-ONLY. Search for text/regex inside files.", {"type": "object", "properties": {"root": {"type": "string"}, "pattern": {"type": "string"}, "file_glob": {"type": "string"}, "regex": {"type": "boolean"}, "case_sensitive": {"type": "boolean"}, "max_results": {"type": "integer"}}, "required": ["root", "pattern"], "additionalProperties": False}),
        "disk_usage": ("READ-ONLY. Get disk usage for a path.", {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}),
        "path_exists": ("READ-ONLY. Check if path exists.", {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}),
        "git_status": ("READ-ONLY. View git working tree status.", {"type": "object", "properties": {"cwd": {"type": "string"}}, "required": ["cwd"], "additionalProperties": False}),
        "git_diff": ("READ-ONLY. View git diff.", {"type": "object", "properties": {"cwd": {"type": "string"}, "staged": {"type": "boolean"}}, "required": ["cwd"], "additionalProperties": False}),
        "git_log": ("READ-ONLY. View recent git commit log.", {"type": "object", "properties": {"cwd": {"type": "string"}, "n": {"type": "integer"}}, "required": ["cwd"], "additionalProperties": False}),
    }
    for k, (desc, sch) in _fallback_15.items():
        if k not in defs:
            defs[k] = {"name": k, "description": desc, "input_schema": sch}

    # 2. P2.1 File Management Tools
    p2_file_tools = {
        "create_directory": (
            "WRITE. Create a directory inside an approved writable root.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "exist_ok": {"type": "boolean"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        "write_file": (
            "WRITE. Atomically write a text file with automatic versioned backup, diff preview, and optional expected_sha256.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "encoding": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                    "create_parents": {"type": "boolean"},
                    "expected_sha256": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        ),
        "append_file": (
            "WRITE. Atomically append text to a file with backup and diff preview.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "encoding": {"type": "string"},
                    "expected_sha256": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        ),
        "edit_file": (
            "WRITE. Replace exact text in a file with backup, unified diff, and concurrency check.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_text": {"type": "string"},
                    "new_text": {"type": "string"},
                    "expected_occurrences": {"type": "integer"},
                    "expected_sha256": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["path", "old_text", "new_text"],
                "additionalProperties": False,
            },
        ),
        "apply_patch": (
            "WRITE. Apply SEARCH/REPLACE blocks or unified diff hunks to a file atomically.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "patch": {"type": "string"},
                    "expected_sha256": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["path", "patch"],
                "additionalProperties": False,
            },
        ),
        "copy_file": (
            "WRITE. Copy a file into an approved writable root.",
            {
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dest": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
                "required": ["src", "dest"],
                "additionalProperties": False,
            },
        ),
        "move_file": (
            "WRITE. Move a file within approved writable roots.",
            {
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dest": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
                "required": ["src", "dest"],
                "additionalProperties": False,
            },
        ),
        "rename_file": (
            "WRITE. Rename a file within an approved writable root.",
            {
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "new_name": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
                "required": ["src", "new_name"],
                "additionalProperties": False,
            },
        ),
        "delete_file": (
            "WRITE. Recoverably delete a file by moving a copy to backups/trash before unlink.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "expected_sha256": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        "restore_file": (
            "WRITE. Restore an overwritten or deleted file from backups/file_versions or backups/trash.",
            {
                "type": "object",
                "properties": {
                    "target_path": {"type": "string"},
                    "backup_path": {"type": "string"},
                },
                "required": ["target_path"],
                "additionalProperties": False,
            },
        ),
        "put_file": (
            "WRITE. Atomically write base64-encoded binary content to an approved writable path.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "data_base64": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                    "expected_sha256": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["path", "data_base64"],
                "additionalProperties": False,
            },
        ),
    }

    # 3. P2.2 Git Extended Tools
    p2_git_tools = {
        "git_worktree_list": (
            "READ. List git worktrees for an approved Git repository.",
            {
                "type": "object",
                "properties": {"cwd": {"type": "string"}},
                "required": ["cwd"],
                "additionalProperties": False,
            },
        ),
        "git_branch_create": (
            "WRITE. Create a new Git branch in an approved repository without altering history.",
            {
                "type": "object",
                "properties": {
                    "cwd": {"type": "string"},
                    "branch_name": {"type": "string"},
                    "checkout": {"type": "boolean"},
                },
                "required": ["cwd", "branch_name"],
                "additionalProperties": False,
            },
        ),
        "git_add_commit": (
            "WRITE. Safely stage specified files and create a commit with hooks/fsmonitor disabled.",
            {
                "type": "object",
                "properties": {
                    "cwd": {"type": "string"},
                    "message": {"type": "string"},
                    "files": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["cwd", "message", "files"],
                "additionalProperties": False,
            },
        ),
    }

    # 4. P2.3 Shell, Process & Job Tools
    p2_exec_tools = {
        "powershell_execute": (
            "EXECUTE. Run an approved PowerShell command with timeout, output limits, and secret redaction.",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "timeout_seconds": {"type": "number"},
                },
                "required": ["command", "cwd"],
                "additionalProperties": False,
            },
        ),
        "cmd_execute": (
            "EXECUTE. Run an approved CMD command with timeout, output limits, and secret redaction.",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "timeout_seconds": {"type": "number"},
                },
                "required": ["command", "cwd"],
                "additionalProperties": False,
            },
        ),
        "process_start": (
            "EXECUTE. Start a managed background process in an approved working directory.",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "shell": {"type": "string"},
                },
                "required": ["command", "cwd"],
                "additionalProperties": False,
            },
        ),
        "process_status": (
            "EXECUTE. Inspect status and redacted logs of a managed background process.",
            {
                "type": "object",
                "properties": {"process_id": {"type": "string"}},
                "required": ["process_id"],
                "additionalProperties": False,
            },
        ),
        "process_stop": (
            "EXECUTE. Stop a managed background process and its child process tree.",
            {
                "type": "object",
                "properties": {"process_id": {"type": "string"}},
                "required": ["process_id"],
                "additionalProperties": False,
            },
        ),
        "job_create": (
            "EXECUTE. Create a durable background job persisted in runtime/jobs/<job_id>.json.",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "shell": {"type": "string"},
                    "timeout_seconds": {"type": "number"},
                },
                "required": ["command", "cwd"],
                "additionalProperties": False,
            },
        ),
        "job_poll": (
            "EXECUTE. Poll the durable state of a background job.",
            {
                "type": "object",
                "properties": {"job_id": {"type": "string"}},
                "required": ["job_id"],
                "additionalProperties": False,
            },
        ),
        "job_cancel": (
            "EXECUTE. Cancel a running background job and kill its process tree.",
            {
                "type": "object",
                "properties": {"job_id": {"type": "string"}},
                "required": ["job_id"],
                "additionalProperties": False,
            },
        ),
        "job_logs": (
            "EXECUTE. Retrieve redacted stdout, stderr, and audit trail for a background job.",
            {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                "required": ["job_id"],
                "additionalProperties": False,
            },
        ),
    }

    # 5. P3 Desktop Agent Tools
    p3_desktop_tools = {
        "get_desktop_session_status": (
            "READ. Check Windows Session ID, interactive workstation, and lock/Secure Desktop status.",
            {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        ),
        "get_screen_geometry": (
            "READ. Retrieve DPI scaling and multi-monitor geometry.",
            {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        ),
        "screenshot": (
            "READ. Capture desktop, monitor, window, or region screenshot with sensitive window blackout.",
            {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "monitor": {"type": "integer"},
                    "hwnd": {"type": "integer"},
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "width": {"type": "integer"},
                    "height": {"type": "integer"},
                    "max_width": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        "list_windows": (
            "READ. List visible top-level windows with HWND, PID, title, and bounds.",
            {
                "type": "object",
                "properties": {
                    "title_contains": {"type": "string"},
                    "include_untitled": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        "get_active_window": (
            "READ. Get the current foreground window metadata.",
            {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        ),
        "focus_window": (
            "DESKTOP. Focus a top-level window by HWND.",
            {
                "type": "object",
                "properties": {
                    "hwnd": {"type": "integer"},
                    "restore_if_minimized": {"type": "boolean"},
                },
                "required": ["hwnd"],
                "additionalProperties": False,
            },
        ),
        "mouse_move": (
            "DESKTOP. Move mouse cursor to screen coordinates (x, y).",
            {
                "type": "object",
                "properties": {
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "duration_ms": {"type": "integer"},
                },
                "required": ["x", "y"],
                "additionalProperties": False,
            },
        ),
        "mouse_click": (
            "DESKTOP. Click mouse button at (x, y) or current cursor position.",
            {
                "type": "object",
                "properties": {
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "button": {"type": "string"},
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        "mouse_double_click": (
            "DESKTOP. Double-click mouse button at (x, y) or current cursor position.",
            {
                "type": "object",
                "properties": {
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "button": {"type": "string"},
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        "mouse_right_click": (
            "DESKTOP. Right-click mouse button at (x, y) or current cursor position.",
            {
                "type": "object",
                "properties": {
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        "mouse_scroll": (
            "DESKTOP. Scroll mouse wheel vertically or horizontally.",
            {
                "type": "object",
                "properties": {
                    "clicks": {"type": "integer"},
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "horizontal": {"type": "boolean"},
                },
                "required": ["clicks"],
                "additionalProperties": False,
            },
        ),
        "mouse_drag": (
            "DESKTOP. Drag mouse from (start_x, start_y) to (end_x, end_y).",
            {
                "type": "object",
                "properties": {
                    "start_x": {"type": "integer"},
                    "start_y": {"type": "integer"},
                    "end_x": {"type": "integer"},
                    "end_y": {"type": "integer"},
                    "button": {"type": "string"},
                    "steps": {"type": "integer"},
                    "duration_ms": {"type": "integer"},
                },
                "required": ["start_x", "start_y", "end_x", "end_y"],
                "additionalProperties": False,
            },
        ),
        "keyboard_type": (
            "DESKTOP. Type Unicode text via Win32 SendInput.",
            {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "interval_ms": {"type": "integer"},
                },
                "required": ["text"],
                "additionalProperties": False,
            },
        ),
        "keyboard_keypress": (
            "DESKTOP. Press and release a single virtual key.",
            {
                "type": "object",
                "properties": {"key": {"type": "string"}},
                "required": ["key"],
                "additionalProperties": False,
            },
        ),
        "keyboard_hotkey": (
            "DESKTOP. Send a key combination chord (e.g. ['ctrl', 'c']).",
            {
                "type": "object",
                "properties": {
                    "keys": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 5},
                    "interval_ms": {"type": "integer"},
                },
                "required": ["keys"],
                "additionalProperties": False,
            },
        ),
        "get_clipboard_text": (
            "DESKTOP. Read Unicode text from Windows clipboard.",
            {
                "type": "object",
                "properties": {"max_chars": {"type": "integer"}},
                "required": [],
                "additionalProperties": False,
            },
        ),
        "set_clipboard_text": (
            "DESKTOP. Write Unicode text to Windows clipboard.",
            {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": False,
            },
        ),
        "visual_action_verify": (
            "DESKTOP. Capture before-state, execute GUI action, capture after-screenshot, and verify change.",
            {
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "action_args": {"type": "object"},
                    "settle_ms": {"type": "integer"},
                    "region": {"type": "object"},
                },
                "required": ["action"],
                "additionalProperties": False,
            },
        ),
    }

    for group in (p2_file_tools, p2_git_tools, p2_exec_tools, p3_desktop_tools):
        for name, (desc, schema) in group.items():
            defs[name] = {"name": name, "description": desc, "input_schema": schema}

    # 5. Sprint 5 Autonomous Full Agent Tools
    try:
        from runtime.agent_mcp_tools import AUTONOMOUS_TOOL_DEFINITIONS
        for name, (desc, schema) in AUTONOMOUS_TOOL_DEFINITIONS.items():
            defs[name] = {"name": name, "description": desc, "input_schema": schema}
    except Exception:
        pass

    return defs


ALL_TOOL_DEFINITIONS = _build_all_tool_definitions()


def safe_json_result(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, default=str)
    return raw if len(raw) <= RESPONSE_LIMIT else raw[:RESPONSE_LIMIT] + "...[TRUNCATED]"


def simulate_chatgpt_mcp_client_parse(call_tool_result: dict[str, Any]) -> dict[str, Any]:
    """Simulate OpenAI ChatGPT MCP client normalization of a CallToolResult payload (B1).

    When result.content[0].text is a JSON object whose top-level dict contains a scalar/string
    key named 'content' (instead of a list of MCP content blocks), OpenAI's ChatGPT MCP connector
    treats it as a nested CallToolResult with an invalid 'content' block list and drops it to `{}`.
    """
    if not isinstance(call_tool_result, dict):
        return {}
    content_blocks = call_tool_result.get("content")
    if not isinstance(content_blocks, list) or not content_blocks:
        return {}
    first = content_blocks[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        return {}
    raw_text = first.get("text", "")
    if not isinstance(raw_text, str) or not raw_text.strip():
        return {}
    try:
        parsed = json.loads(raw_text)
    except Exception:
        return {"text": raw_text}
    if isinstance(parsed, dict):
        if "content" in parsed and not isinstance(parsed.get("content"), list):
            # Reproduce ChatGPT Web connector normalization bug: scalar 'content' key -> {}
            return {}
        return parsed
    return {"value": parsed}


def serialize_autonomous_read_file_result(output: Any) -> str:
    """Serialize agent_read_file output for ChatGPT MCP wire transport without the colliding 'content' key (B1)."""
    if not isinstance(output, dict):
        return safe_json_result(output)
    wire_dict: dict[str, Any] = {}
    for k, v in output.items():
        if k == "content":
            continue
        wire_dict[k] = v
    if output.get("ok") is True or "content" in output or "file_text" in output or "text" in output:
        text_val = output.get("file_text")
        if text_val is None:
            text_val = output.get("text")
        if text_val is None:
            text_val = output.get("content", "")
        wire_dict["file_text"] = text_val
        wire_dict["text"] = text_val
    wire_str = safe_json_result(wire_dict)
    client_visible = simulate_chatgpt_mcp_client_parse(
        {"content": [{"type": "text", "text": wire_str}], "isError": False}
    )
    is_nonempty_slice = (
        output.get("ok") is True
        and int(output.get("bytes", 0) or 0) > 0
        and int(output.get("total_lines", 0) or 0) > 0
        and int(output.get("end_line", 0) or 0) >= int(output.get("start_line", 1) or 1)
    )
    if is_nonempty_slice:
        if not client_visible or client_visible == {}:
            raise ValueError("B1 Contract Violation: Client-visible read_file result normalized to '{}' for nonempty file")
        visible_text = client_visible.get("file_text") or client_visible.get("text") or ""
        if not isinstance(visible_text, str) or len(visible_text) == 0:
            raise ValueError("B1 Contract Violation: Client-visible read_file text is empty for nonempty file")
    return wire_str


OWNER_EXEC_AND_DESKTOP_TOOLS = frozenset({
    "agent_powershell_execute",
    "agent_desktop_screenshot",
    "agent_get_active_window",
    "agent_focus_window",
    "agent_keyboard_type",
    "agent_mouse_click",
    "agent_visual_verify",
    "agent_launch_app",
    "agent_list_windows",
    "agent_system_status",
})


def assemble_autonomous_tool_catalog(
    auth_principal: Any = None,
    is_owner_full_control: bool = False,
    include_coding_tools: bool = True,
    active_grant_default: str | None = None,
    advertised_schemes: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Assemble tool definitions exposed to autonomous MCP callers according to authorization tier.

    - Unauthenticated or non-owner: Exactly 14 baseline tools (6 task tools + 8 coding tools).
    - Verified owner full control: Exactly 34 tools (14 baseline + 6 owner filesystem + 4 task control + 10 desktop/exec).
    """
    from runtime.agent_mcp_tools import CLOUD_AUTONOMOUS_TOOL_DEFINITIONS
    try:
        from runtime.agent_mcp_tools import CLOUD_AUTONOMOUS_TOOL_ANNOTATIONS
    except ImportError:
        CLOUD_AUTONOMOUS_TOOL_ANNOTATIONS = None

    annotations_map = dict(CLOUD_AUTONOMOUS_TOOL_ANNOTATIONS or {
        "agent_submit_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "agent_task_status": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "agent_task_logs": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "agent_task_diff": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "agent_task_artifacts": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "agent_list_tasks": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    })

    schemes = advertised_schemes or [{"type": "noauth"}]
    definitions = dict(CLOUD_AUTONOMOUS_TOOL_DEFINITIONS)

    if include_coding_tools:
        from runtime.coding_tools import CODING_TOOL_DEFINITIONS
        definitions.update(CODING_TOOL_DEFINITIONS)
        for name in CODING_TOOL_DEFINITIONS:
            readonly = name in {"agent_workspace_list", "agent_read_file", "agent_git_status", "agent_git_diff"}
            annotations_map[name] = {
                "readOnlyHint": readonly,
                "destructiveHint": not readonly,
                "idempotentHint": readonly,
                "openWorldHint": name in {"agent_run_command", "agent_run_tests"},
            }

    if is_owner_full_control:
        if include_coding_tools:
            from runtime.coding_tools import OWNER_FILESYSTEM_TOOL_DEFINITIONS
            definitions.update(OWNER_FILESYSTEM_TOOL_DEFINITIONS)
            for name in OWNER_FILESYSTEM_TOOL_DEFINITIONS:
                annotations_map[name] = {
                    "readOnlyHint": False,
                    "destructiveHint": name in ("agent_delete_file", "agent_delete_directory"),
                    "idempotentHint": False,
                    "openWorldHint": False,
                }

        from runtime.agent_mcp_tools import AUTONOMOUS_TOOL_DEFINITIONS
        for t in ("agent_task_pause", "agent_task_resume", "agent_task_cancel", "agent_emergency_stop"):
            if t in AUTONOMOUS_TOOL_DEFINITIONS:
                definitions[t] = AUTONOMOUS_TOOL_DEFINITIONS[t]
                annotations_map[t] = {
                    "readOnlyHint": False,
                    "destructiveHint": t in ("agent_task_cancel", "agent_emergency_stop"),
                    "idempotentHint": False,
                    "openWorldHint": False,
                }

        grant_prop: dict[str, Any] = {
            "type": "string",
            "description": (
                f"Optional short-lived owner capability grant ID (active session grant: {active_grant_default})."
                if active_grant_default
                else "Optional short-lived owner capability grant ID."
            ),
        }
        if active_grant_default:
            grant_prop["default"] = active_grant_default

        owner_common_props = {
            "capability_grant_id": grant_prop,
            "owner_oauth_token": {"type": "string", "description": "Optional owner OAuth bearer token."},
        }

        definitions["agent_powershell_execute"] = (
            "Execute a PowerShell command with full terminal output, stdout, stderr, and exit code.",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "PowerShell command string to execute."},
                    "cwd": {"type": "string", "description": "Optional working directory."},
                    "timeout_seconds": {"type": "integer", "description": "Timeout in seconds (default 60)."},
                    **owner_common_props,
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        )
        definitions["agent_desktop_screenshot"] = (
            "Capture a screenshot of the Windows interactive desktop session or a specific window.",
            {
                "type": "object",
                "properties": {
                    "monitor": {"type": "integer", "description": "Monitor index (default 0)."},
                    "hwnd": {"type": "integer", "description": "Optional window handle (HWND) to capture."},
                    "max_width": {"type": "integer", "description": "Maximum width downscale constraint."},
                    "save_path": {"type": "string", "description": "Optional file path to save the PNG screenshot."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_get_active_window"] = (
            "Get the currently active foreground window and optionally find matching visible windows.",
            {
                "type": "object",
                "properties": {
                    "title_contains": {"type": "string", "description": "Optional substring filter to find matching windows."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_focus_window"] = (
            "Focus and bring a top-level desktop window to the foreground by HWND or title substring.",
            {
                "type": "object",
                "properties": {
                    "hwnd": {"type": "integer", "description": "Target window handle (HWND)."},
                    "title_contains": {"type": "string", "description": "Optional window title substring if hwnd is not provided."},
                    "restore_if_minimized": {"type": "boolean", "description": "Restore window if minimized (default true)."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_keyboard_type"] = (
            "Send keyboard text typing, single keypress, or hotkey chord to the active or specified desktop window.",
            {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Unicode text to type."},
                    "key": {"type": "string", "description": "Optional single virtual key (e.g. 'enter', 'tab', 'escape')."},
                    "keys": {"type": "array", "items": {"type": "string"}, "description": "Optional hotkey chord (e.g. ['ctrl', 's'])."},
                    "hwnd": {"type": "integer", "description": "Optional window handle (HWND) to focus before typing."},
                    "title_contains": {"type": "string", "description": "Optional window title substring to focus before typing."},
                    "interval_ms": {"type": "integer", "description": "Delay between keystrokes in milliseconds."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_mouse_click"] = (
            "Click mouse button at screen coordinates (x, y) or window-relative (offset_x, offset_y).",
            {
                "type": "object",
                "properties": {
                    "x": {"type": "integer", "description": "Screen X coordinate."},
                    "y": {"type": "integer", "description": "Screen Y coordinate."},
                    "hwnd": {"type": "integer", "description": "Optional target window HWND for relative click."},
                    "title_contains": {"type": "string", "description": "Optional window title substring for relative click."},
                    "offset_x": {"type": "integer", "description": "Window-relative X offset from window left edge."},
                    "offset_y": {"type": "integer", "description": "Window-relative Y offset from window top edge."},
                    "button": {"type": "string", "description": "Mouse button ('left', 'right', 'middle')."},
                    "double": {"type": "boolean", "description": "Perform a double click if true."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_visual_verify"] = (
            "Verify desktop GUI state, capture window/screen visual hash, and optionally verify a GUI-saved file on disk.",
            {
                "type": "object",
                "properties": {
                    "hwnd": {"type": "integer", "description": "Optional window HWND to inspect and capture."},
                    "title_contains": {"type": "string", "description": "Optional window title substring to locate."},
                    "save_path": {"type": "string", "description": "Optional file path to save the verification screenshot PNG."},
                    "verify_path": {"type": "string", "description": "Optional file path written by the GUI to verify existence, SHA-256, and text."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_launch_app"] = (
            "Launch a Windows desktop application or process in the active session.",
            {
                "type": "object",
                "properties": {
                    "app_path": {"type": "string", "description": "Path or executable name to launch."},
                    "arguments": {"type": "string", "description": "Optional command-line arguments."},
                    **owner_common_props,
                },
                "required": ["app_path"],
                "additionalProperties": False,
            },
        )
        definitions["agent_list_windows"] = (
            "List open visible application windows on the desktop.",
            {
                "type": "object",
                "properties": {
                    "title_contains": {"type": "string", "description": "Optional title filter."},
                    "max_results": {"type": "integer", "description": "Max results to return."},
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        definitions["agent_system_status"] = (
            "Get Windows system status including CPU, memory, drives, and host info.",
            {
                "type": "object",
                "properties": {
                    **owner_common_props,
                },
                "required": [],
                "additionalProperties": False,
            },
        )
        for name in OWNER_EXEC_AND_DESKTOP_TOOLS:
            readonly = name in ("agent_desktop_screenshot", "agent_get_active_window", "agent_visual_verify", "agent_list_windows", "agent_system_status")
            annotations_map[name] = {
                "readOnlyHint": readonly,
                "destructiveHint": not readonly,
                "idempotentHint": readonly,
                "openWorldHint": name in ("agent_powershell_execute", "agent_launch_app"),
            }

    return [
        {
            "name": name,
            "description": desc,
            "inputSchema": schema,
            "annotations": annotations_map.get(
                name,
                {
                    "readOnlyHint": False,
                    "destructiveHint": False,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
            ),
            "securitySchemes": schemes,
        }
        for name, (desc, schema) in definitions.items()
    ]


class MCPGatewayServer:
    """Unified MCP Gateway server supporting Bridge v0.2.1 read-only mode and profile-gated P2/P3 execution."""

    def __init__(
        self,
        policy: SecurityPolicy | None = None,
        *,
        profile: str | None = None,
        file_ops: FileCodeOperations | None = None,
        exec_ops: ExecutionJobManager | None = None,
        desktop_agent: DesktopAgent | None = None,
        runtime_paths: Any = None,
    ) -> None:
        self.policy = policy or SecurityPolicy(profile=profile)
        self.runtime_paths = runtime_paths
        self.file_ops = file_ops or FileCodeOperations(policy=self.policy)
        self.exec_ops = exec_ops or ExecutionJobManager(
            policy=self.policy,
            jobs_dir=getattr(runtime_paths, "jobs_dir", None) if runtime_paths else None,
        )
        self.desktop = desktop_agent or DesktopAgent(
            policy=self.policy,
            emergency_stop_file=getattr(runtime_paths, "emergency_stop_file", None) if runtime_paths else None,
        )
        self.policy.register_subsystems(exec_ops=self.exec_ops, desktop_agent=self.desktop)
        self.server_name = "Local Computer MCP Gateway"
        self.server_version = "0.2.1" if self.policy.strict_v021_read_tools_only else "0.3.0"

    def is_emergency_stop_active(self) -> bool:
        """Check emergency stop status respecting injected isolated runtime state."""
        if self.policy and self.policy.is_emergency_stop_active():
            return True
        if getattr(self, "runtime_paths", None) is not None:
            return self.runtime_paths.is_emergency_stop_active()
        return (PROJECT_ROOT / "runtime" / "EMERGENCY_STOP").exists()

    def engage_emergency_stop(self, reason: str = "emergency_stop") -> dict[str, Any]:
        """Engage Emergency Stop across Policy, SessionManager, ExecutionJobManager, and DesktopAgent."""
        self.policy.register_subsystems(exec_ops=self.exec_ops, desktop_agent=self.desktop)
        return self.policy.engage_emergency_stop(reason=reason)

    def reset_emergency_stop(self) -> dict[str, Any]:
        """Clear Emergency Stop across Policy and DesktopAgent."""
        self.policy.register_subsystems(exec_ops=self.exec_ops, desktop_agent=self.desktop)
        return self.policy.reset_emergency_stop()

    def exposed_tool_names(self) -> list[str]:
        """Return sorted list of tool names exposed by the current policy profile."""
        if self.policy.strict_v021_read_tools_only:
            return sorted(V021_READ_TOOLS)
        exposed: list[str] = []
        for name, tier in TOOL_TIER_MAP.items():
            if tier == PermissionTier.SYSTEM_ADMIN:
                continue
            if tier in self.policy.enabled_tiers and name in ALL_TOOL_DEFINITIONS:
                exposed.append(name)
        return sorted(exposed)

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP-formatted tool definitions for the active profile."""
        names = self.exposed_tool_names()
        out: list[dict[str, Any]] = []
        for name in names:
            d = ALL_TOOL_DEFINITIONS[name]
            out.append({
                "name": name,
                "description": d["description"],
                "inputSchema": d["input_schema"],
                "input_schema": d["input_schema"],
            })
        return out

    # ------------------------------------------------------------------
    # Built-in Read-Only Tool Implementations (15 Bridge v0.2.1 Tools)
    # ------------------------------------------------------------------
    def _exec_v021_read_tool(
        self,
        name: str,
        args: dict[str, Any],
        *,
        session_id: str | None = None,
    ) -> Any:
        if name == "get_roots":
            self.policy.authorize_tool("get_roots", {}, session_id=session_id)
            return [{"path": str(r), "label": str(r)[:3]} for r in self.policy.read_roots]

        if name == "path_exists":
            self.policy.authorize_tool("path_exists", args, session_id=session_id)
            target = self.policy.validate_path(args["path"], tier=PermissionTier.READ, check_content=False)
            return {
                "path": str(target),
                "exists": target.exists(),
                "is_file": target.is_file() if target.exists() else False,
                "is_dir": target.is_dir() if target.exists() else False,
            }

        if name == "stat_path":
            self.policy.authorize_tool("stat_path", args, session_id=session_id)
            target = self.policy.validate_path(args["path"], tier=PermissionTier.READ, check_content=False, must_exist=True)
            st = target.stat()
            return {
                "path": str(target),
                "name": target.name,
                "is_file": target.is_file(),
                "is_dir": target.is_dir(),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "ctime": st.st_ctime,
            }

        if name == "disk_usage":
            self.policy.authorize_tool("disk_usage", args, session_id=session_id)
            target = self.policy.validate_path(args["path"], tier=PermissionTier.READ, check_content=False, must_exist=True)
            usage = shutil.disk_usage(str(target))
            return {
                "path": str(target),
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
            }

        if name == "list_directory":
            self.policy.authorize_tool("list_directory", args, session_id=session_id)
            target = self.policy.validate_path(args["path"], tier=PermissionTier.READ, check_content=False, must_exist=True)
            if not target.is_dir():
                raise NotADirectoryError(f"Not a directory: {target}")
            include_hidden = bool(args.get("include_hidden", False))
            items: list[dict[str, Any]] = []
            for entry in sorted(target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
                if not include_hidden and entry.name.startswith("."):
                    continue
                if self.policy.is_sensitive_path_str(entry, check_content=False):
                    continue
                try:
                    st = entry.stat()
                    items.append({
                        "name": entry.name,
                        "path": str(entry),
                        "is_dir": entry.is_dir(),
                        "size": st.st_size if entry.is_file() else 0,
                    })
                except OSError:
                    continue
            return {"path": str(target), "entries": items, "count": len(items)}

        if name == "list_tree":
            self.policy.authorize_tool("list_tree", args, session_id=session_id)
            target = self.policy.validate_path(args["path"], tier=PermissionTier.READ, check_content=False, must_exist=True)
            max_depth = max(1, min(10, int(args.get("max_depth", 3))))
            max_entries = max(1, min(1000, int(args.get("max_entries", 200))))
            entries: list[dict[str, Any]] = []

            def _walk(cur: Path, depth: int) -> None:
                if depth > max_depth or len(entries) >= max_entries:
                    return
                try:
                    children = sorted(cur.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
                except OSError:
                    return
                for child in children:
                    if len(entries) >= max_entries:
                        return
                    if self.policy.is_sensitive_path_str(child, check_content=False):
                        continue
                    is_dir = child.is_dir()
                    entries.append({
                        "path": str(child),
                        "rel_path": str(child.relative_to(target)),
                        "is_dir": is_dir,
                        "depth": depth,
                    })
                    if is_dir:
                        _walk(child, depth + 1)

            _walk(target, 1)
            return {"path": str(target), "entries": entries, "count": len(entries)}

        if name == "read_file":
            return self.file_ops.read_file(args["path"], session_id=session_id)

        if name == "read_file_range":
            return self.file_ops.read_file(
                args["path"],
                start_line=int(args["start_line"]),
                end_line=int(args["end_line"]),
                session_id=session_id,
            )

        if name == "get_file":
            return self.file_ops.get_file(
                args["path"],
                max_bytes=int(args.get("max_bytes", 15 * 1024 * 1024)),
                session_id=session_id,
            )

        if name == "search_files":
            return self.file_ops.search_files(
                args["root"],
                args["pattern"],
                recursive=bool(args.get("recursive", True)),
                max_results=int(args.get("max_results", 200)),
                session_id=session_id,
            )

        if name in ("search_code", "grep"):
            self.policy.authorize_tool(name, args, session_id=session_id)
            root_arg = args.get("cwd") if name == "search_code" else args.get("root")
            root_path = self.policy.validate_path(root_arg, tier=PermissionTier.READ, must_exist=True)
            file_glob = args.get("file_glob")
            if name == "search_code" and file_glob not in CODE_FILE_GLOBS:
                raise PermissionError(
                    f"search_code requires a recognized source-code file_glob (e.g. *.py); got: {file_glob}"
                )
            if name == "grep" and file_glob is not None and file_glob not in CODE_FILE_GLOBS:
                raise PermissionError(
                    f"grep requires a recognized source-code file_glob (e.g. *.py); got: {file_glob}"
                )
            pattern_str = str(args["pattern"])
            use_regex = bool(args.get("regex", True))
            case_sensitive = bool(args.get("case_sensitive", False))
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern_str if use_regex else re.escape(pattern_str), flags)
            max_results = max(1, min(500, int(args.get("max_results", 100))))

            matches: list[dict[str, Any]] = []
            for fp in root_path.rglob(file_glob or "*"):
                if len(matches) >= max_results:
                    break
                if not fp.is_file():
                    continue
                if self.policy.is_sensitive_path_str(fp, check_content=True):
                    continue
                if file_glob is None and fp.suffix.lower() not in {g[1:].lower() for g in CODE_FILE_GLOBS if g.startswith("*.")}:
                    continue
                try:
                    text, _ = detect_encoding_and_decode(fp.read_bytes())
                except Exception:
                    continue
                for line_no, line in enumerate(text.splitlines(), start=1):
                    if rx.search(line):
                        matches.append({
                            "file": str(fp),
                            "line": line_no,
                            "text": redact_secrets(line.strip()[:300]),
                        })
                        if len(matches) >= max_results:
                            break
            return {"root": str(root_path), "pattern": pattern_str, "results": matches, "count": len(matches)}

        if name == "git_status":
            return self.file_ops.git_status(args["cwd"], session_id=session_id)

        if name == "git_diff":
            return self.file_ops.git_diff(
                args["cwd"], staged=bool(args.get("staged", False)), session_id=session_id
            )

        if name == "git_log":
            return self.file_ops.git_log(
                args["cwd"], n=int(args.get("n", 10)), session_id=session_id
            )

        raise ValueError(f"Unhandled read tool: {name}")

    # ------------------------------------------------------------------
    # Unified Tool Invocation
    # ------------------------------------------------------------------
    def invoke_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        caller_id: str | None = None,
    ) -> Any:
        args = dict(arguments or {})
        self.policy._enter_invocation()
        try:
            # 1. Policy tier & profile check
            self.policy.authorize_tool(
                name,
                args,
                session_id=session_id,
                approval_token=approval_token,
                caller_id=caller_id,
            )

            # 2. Schema validation
            if name not in ALL_TOOL_DEFINITIONS:
                raise PermissionError(f"Tool '{name}' is not defined in Gateway")
            schema = ALL_TOOL_DEFINITIONS[name]["input_schema"]
            Draft202012Validator(schema).validate(args)

            # 3. Dispatch to subsystem
            if name in V021_READ_TOOLS:
                return self._exec_v021_read_tool(name, args, session_id=session_id)

            if hasattr(self.file_ops, name):
                fn = getattr(self.file_ops, name)
                try:
                    return fn(**args, session_id=session_id, approval_token=approval_token)
                except TypeError:
                    return fn(**args, session_id=session_id)

            if hasattr(self.exec_ops, name):
                fn = getattr(self.exec_ops, name)
                return fn(**args, session_id=session_id, approval_token=approval_token)

            if hasattr(self.desktop, name):
                fn = getattr(self.desktop, name)
                try:
                    return fn(**args, session_id=session_id, approval_token=approval_token)
                except TypeError:
                    return fn(**args, session_id=session_id)

            if name.startswith("agent_"):
                from runtime.agent_mcp_tools import AUTONOMOUS_TOOL_DEFINITIONS
                if name in AUTONOMOUS_TOOL_DEFINITIONS:
                    handler = self.get_agent_tool_handler()
                    caller_tier = None
                    if session_id:
                        sess = self.policy.sessions.get_session(session_id)
                        if sess:
                            if any(t.value == "WRITE" or t == PermissionTier.WRITE for t in sess.tiers):
                                caller_tier = "WRITE"
                            elif any(t.value == "READ" or t == PermissionTier.READ for t in sess.tiers):
                                caller_tier = "READ"
                    try:
                        return handler.execute_tool(
                            name,
                            args,
                            caller_tier=caller_tier,
                            surface="local",
                            caller_id=caller_id or "local",
                        )
                    except TypeError:
                        try:
                            return handler.execute_tool(name, args, caller_tier=caller_tier, surface="local")
                        except TypeError:
                            return handler.execute_tool(name, args)

            raise PermissionError(f"No handler bound for tool: {name}")
        finally:
            self.policy._exit_invocation()

    def get_agent_tool_handler(self) -> Any:
        """Get or initialize the shared AgentMCPToolHandler instance."""
        if not hasattr(self, "_agent_tool_handler") or self._agent_tool_handler is None:
            from runtime.agent_mcp_tools import AgentMCPToolHandler
            from runtime.task_grant import TaskGrantBroker
            from runtime.task_store import TaskStore
            rp = getattr(self, "runtime_paths", None)
            if not hasattr(self, "store") or self.store is None:
                self.store = TaskStore(db_path=getattr(rp, "tasks_db_path", None) if rp else None)
            broker = TaskGrantBroker(
                policy=self.policy,
                db_path=self.store.db_path,
                key_path=getattr(rp, "grant_key_path", None) if rp else None,
            )
            self._agent_tool_handler = AgentMCPToolHandler(self.store, broker)
        return self._agent_tool_handler

    def _get_owner_desktop_agent(self) -> DesktopAgent:
        """Return an owner-authorized DesktopAgent that preserves Emergency Stop, interactive session lock checks, and durable audit logging without disabling gateway policy globally."""
        if getattr(self, "desktop", None) is not None and not isinstance(self.desktop, DesktopAgent):
            return self.desktop
        if self.policy and PermissionTier.DESKTOP in getattr(self.policy, "enabled_tiers", frozenset()):
            return self.desktop
        if not hasattr(self, "_owner_desktop_agent") or self._owner_desktop_agent is None:
            rp = getattr(self, "runtime_paths", None)
            stop_file = (
                getattr(rp, "emergency_stop_file", None)
                if rp and getattr(rp, "emergency_stop_file", None)
                else getattr(self.policy, "emergency_stop_file", None)
            )
            audit_path = (
                getattr(self.policy.audit, "log_path", None)
                if self.policy and hasattr(self.policy, "audit")
                else None
            )
            owner_pol = SecurityPolicy(
                profile="full_agent",
                require_session_for_privileged=False,
                emergency_stop_file=stop_file,
                audit_log_path=audit_path,
            )
            owner_pol.tier_require_approval_token[PermissionTier.DESKTOP] = False
            self._owner_desktop_agent = DesktopAgent(
                policy=owner_pol,
                emergency_stop_file=stop_file,
            )
        return self._owner_desktop_agent

    def _log_owner_cloud_audit(
        self,
        *,
        tool_name: str,
        tier: str,
        decision: str,
        reason: str,
        caller_id: str | None,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        safe_args = {}
        if isinstance(arguments, dict):
            for k, v in arguments.items():
                if k in ("owner_oauth_token", "access_token", "client_secret"):
                    safe_args[k] = "[REDACTED]"
                elif isinstance(v, str) and len(v) > 240:
                    safe_args[k] = v[:240] + "...[TRUNCATED]"
                else:
                    safe_args[k] = v
        if self.policy and hasattr(self.policy, "audit"):
            try:
                self.policy.audit.log_event(
                    tool_name=tool_name,
                    tier=tier,
                    decision=decision,
                    reason=reason,
                    arguments=safe_args,
                )
            except Exception:
                pass
        try:
            if not hasattr(self, "_coding_tool_handler"):
                agent_handler = self.get_agent_tool_handler()
                rp = getattr(self, "runtime_paths", None)
                coding_audit_p = (Path(rp.root_dir) / "logs" / "coding_audit.db") if rp and getattr(rp, "root_dir", None) else None
                from runtime.coding_tools import CodingToolHandler
                self._coding_tool_handler = CodingToolHandler(
                    agent_handler.store,
                    agent_handler.broker,
                    audit_path=coding_audit_p,
                )
            audit_db = getattr(self._coding_tool_handler, "_audit", None)
            if audit_db is not None:
                audit_db.record(
                    caller_id=caller_id or "unknown",
                    surface="cloud_autonomous",
                    tool_name=tool_name,
                    workspace_root=str(safe_args.get("cwd") or safe_args.get("save_path") or safe_args.get("verify_path") or PROJECT_ROOT),
                    decision=decision,
                    status=decision,
                    arguments=safe_args,
                    result_summary={"reason": reason, "tier": tier},
                )
        except Exception:
            pass

    def _validate_owner_execution_and_capability(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        caller_id: str | None,
        caller_tier: str,
        auth_principal: Any,
        server_owner_profile: bool,
        is_authenticated_owner: bool,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Validate Emergency Stop, OAuth owner identity, and short-lived capability grant server-side (B2/B3)."""
        tier_label = "EXECUTE" if tool_name == "agent_powershell_execute" else "DESKTOP"
        if self.is_emergency_stop_active():
            msg = "Permission Denied (R3): Emergency Stop is active"
            self._log_owner_cloud_audit(
                tool_name=tool_name,
                tier=tier_label,
                decision="DENY",
                reason=msg,
                caller_id=caller_id,
                arguments=tool_args,
            )
            return False, msg, {}

        persistence = getattr(self, "_oauth_persistence", None)
        signing_key = getattr(self, "_oauth_signing_key", None)

        # P0-02: Never allow owner_oauth_token in tool arguments to authenticate or upgrade a request
        if tool_args.get("owner_oauth_token"):
            msg = "Permission Denied (P0-02): owner_oauth_token in tool arguments is forbidden; owner OAuth token must be presented in the request Authorization header"
            self._log_owner_cloud_audit(
                tool_name=tool_name,
                tier=tier_label,
                decision="DENY",
                reason=msg,
                caller_id=caller_id,
                arguments=tool_args,
            )
            return False, msg, {}

        arg_grant_id = str(tool_args.get("capability_grant_id") or "").strip()

        if auth_principal is not None:
            auth_method = str(getattr(auth_principal, "auth_method", "") or "")
            if auth_method != "oauth":
                if tool_name == "agent_powershell_execute":
                    msg = "Permission Denied (R2): Caller is not authorized for owner-level powershell execution"
                else:
                    msg = "Permission Denied (R2): Caller is not authorized for desktop operations"
                self._log_owner_cloud_audit(
                    tool_name=tool_name,
                    tier=tier_label,
                    decision="DENY",
                    reason=msg,
                    caller_id=caller_id,
                    arguments=tool_args,
                )
                return False, msg, {}

            meta = getattr(auth_principal, "metadata", {})
            if not isinstance(meta, dict):
                meta = {}
            payload_tok = meta.get("payload") if isinstance(meta.get("payload"), dict) else {}
            tok_owner = str(getattr(auth_principal, "owner_id", "") or payload_tok.get("owner_id") or "")
            tok_scopes = getattr(auth_principal, "scopes", frozenset()) or frozenset()
            if (
                not getattr(auth_principal, "is_owner", False)
                or tok_owner != "local_owner"
                or ("mcp:owner" not in tok_scopes and "mcp:all" not in tok_scopes)
            ):
                suffix = (
                    "not authorized for owner-level powershell execution"
                    if tool_name == "agent_powershell_execute"
                    else "not authorized for desktop operations"
                )
                msg = f"Permission Denied (B2/B3): OAuth principal is not local_owner or lacks mcp:owner scope ({suffix})"
                self._log_owner_cloud_audit(
                    tool_name=tool_name,
                    tier=tier_label,
                    decision="DENY",
                    reason=msg,
                    caller_id=caller_id,
                    arguments=tool_args,
                )
                return False, msg, {}

            verified_client_id = str(
                getattr(auth_principal, "client_id", "") or payload_tok.get("client_id") or ""
            ).strip()
            verified_jti = str(payload_tok.get("jti") or meta.get("jti") or "").strip()
            if not verified_client_id or not verified_jti:
                msg = "Permission Denied (P0-02): Authenticated OAuth principal is missing required client_id or token JTI"
                self._log_owner_cloud_audit(
                    tool_name=tool_name,
                    tier=tier_label,
                    decision="DENY",
                    reason=msg,
                    caller_id=caller_id,
                    arguments=tool_args,
                )
                return False, msg, {}

            if not arg_grant_id:
                arg_grant_id = str(meta.get("header_grant_id") or "").strip()

            if (
                persistence is not None
                and hasattr(persistence, "resolve_or_renew_owner_grant_for_token")
                and signing_key
            ):
                arg_grant_id = str(
                    persistence.resolve_or_renew_owner_grant_for_token(
                        secret=str(signing_key),
                        owner_id="local_owner",
                        client_id=verified_client_id,
                        oauth_token_jti=verified_jti,
                        requested_grant_id=arg_grant_id or None,
                    )
                    or ""
                ).strip()
            elif (
                not arg_grant_id
                and verified_client_id == "chatgpt_web_owner_client"
                and persistence is not None
                and hasattr(persistence, "find_active_owner_grant_for_token")
            ):
                arg_grant_id = str(
                    persistence.find_active_owner_grant_for_token(
                        owner_id="local_owner",
                        client_id=verified_client_id,
                        oauth_token_jti=verified_jti,
                    )
                    or ""
                ).strip()

            if not arg_grant_id:
                msg = f"Permission Denied (B2/B3): Short-lived owner capability_grant_id is required for '{tool_name}' on cloud surface"
                self._log_owner_cloud_audit(
                    tool_name=tool_name,
                    tier=tier_label,
                    decision="DENY",
                    reason=msg,
                    caller_id=caller_id,
                    arguments=tool_args,
                )
                return False, msg, {}

            if persistence is None or not hasattr(persistence, "validate_and_consume_owner_grant") or not signing_key:
                msg = "Permission Denied (B2/B3): Owner capability grant persistence store or signing key is not available"
                self._log_owner_cloud_audit(
                    tool_name=tool_name,
                    tier=tier_label,
                    decision="DENY",
                    reason=msg,
                    caller_id=caller_id,
                    arguments=tool_args,
                )
                return False, msg, {}

            target_path = (
                tool_args.get("cwd")
                or tool_args.get("save_path")
                or tool_args.get("verify_path")
                or tool_args.get("path")
                or tool_args.get("workspace_root")
            )
            ok_g, err_g, grant_rec = persistence.validate_and_consume_owner_grant(
                grant_id=arg_grant_id,
                secret=str(signing_key),
                tool_name=tool_name,
                target_path=str(target_path) if target_path else None,
                expected_owner_id="local_owner",
                expected_client_id=verified_client_id,
                oauth_token_jti=verified_jti,
                consume=True,
                require_client_and_jti=True,
            )
            if not ok_g:
                msg = f"Permission Denied (B2/B3): {err_g}"
                self._log_owner_cloud_audit(
                    tool_name=tool_name,
                    tier=tier_label,
                    decision="DENY",
                    reason=msg,
                    caller_id=caller_id,
                    arguments=tool_args,
                )
                return False, msg, {}
            return True, "", {"grant_id": arg_grant_id, "used_count": grant_rec.get("used_count") if grant_rec else None}

        # Local-only in-process invocation (auth_principal is None)
        if not (is_authenticated_owner and server_owner_profile):
            if tool_name == "agent_powershell_execute":
                msg = "Permission Denied (R2): Caller is not authorized for owner-level powershell execution"
            else:
                msg = "Permission Denied (R2): Caller is not authorized for desktop operations"
            self._log_owner_cloud_audit(
                tool_name=tool_name,
                tier=tier_label,
                decision="DENY",
                reason=msg,
                caller_id=caller_id,
                arguments=tool_args,
            )
            return False, msg, {}

        return True, "", {"grant_id": arg_grant_id or None}

    def _resolve_runtime_git_sha(self) -> str:
        cached = getattr(self, "_cached_runtime_git_sha", None)
        if cached:
            return str(cached)
        try:
            from runtime.release_identity import get_release_identity
            rel = get_release_identity()
            if rel.get("source_commit") and rel["source_commit"] != "unknown":
                self._cached_runtime_git_sha = rel["source_commit"]
                return self._cached_runtime_git_sha
        except Exception:
            pass
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                self._cached_runtime_git_sha = proc.stdout.strip()
                return self._cached_runtime_git_sha
        except Exception:
            pass
        return "unknown"

    def handle_jsonrpc_autonomous(
        self,
        message: dict[str, Any],
        *,
        caller_id: str | None = None,
        include_coding_tools: bool = False,
        caller_tier: str = "READ",
        auth_principal: Any = None,
    ) -> dict[str, Any] | None:
        """Process a standard MCP JSON-RPC 2.0 request for the isolated Cloud Autonomous surface (G05)."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id") if isinstance(message, dict) else None,
                "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request"},
            }

        method = message.get("method", "")
        req_id = message.get("id")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32602, "message": "params must be an object"}}

        # Notifications do not return a response
        if method.startswith("notifications/"):
            return None

        server_owner_profile = bool(self.policy and getattr(self.policy, "unrestricted_workspace_access", False))
        from runtime.process_runner import verify_cloud_principal
        _, is_owner_principal, verified_identity = verify_cloud_principal(
            auth_principal,
            internal_local_trusted=bool(
                caller_id == "local_owner"
                and auth_principal is None
                and getattr(self, "_internal_local_trusted", True)
            ),
        )
        if auth_principal is not None:
            caller_id = verified_identity or caller_id
            caller_tier = getattr(auth_principal, "tier", caller_tier)
        is_authenticated_owner = bool(is_owner_principal and caller_tier in ("WRITE", "EXECUTE", "SYSTEM_ADMIN"))
        is_owner_full_control = bool(
            is_authenticated_owner
            if auth_principal is not None
            else (server_owner_profile and is_authenticated_owner)
        )

        if method == "initialize":
            from runtime.release_identity import get_release_identity
            rel_id = get_release_identity()
            client_proto = params.get("protocolVersion", "2024-11-05")
            supported = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
            negotiated_proto = client_proto if client_proto in supported else supported[-1]
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated_proto,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "windows-mcp-autonomous",
                        "version": self.server_version,
                        "release_version": rel_id["release_version"],
                        "build_id": rel_id["build_id"],
                        "zip_sha256": rel_id["zip_sha256"],
                        "git_sha": rel_id["source_commit"],
                        "profile": "cloud_autonomous",
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            ext_issuer = os.getenv("MCP_OAUTH_EXTERNAL_ISSUER", "").strip()
            auth_scheme_override = os.getenv("MCP_AUTONOMOUS_AUTH_SCHEME", "").strip().lower()
            if (ext_issuer.startswith("https://") and "127.0.0.1" not in ext_issuer and "localhost" not in ext_issuer) or auth_scheme_override == "oauth2":
                advertised_schemes: list[dict[str, Any]] = [{"type": "oauth2", "scopes": ["mcp:autonomous"]}]
            else:
                advertised_schemes = [{"type": "noauth"}]

            active_grant_default = None
            if is_owner_full_control and auth_principal is not None and getattr(self, "_oauth_persistence", None) is not None:
                try:
                    meta = getattr(auth_principal, "metadata", {}) or {}
                    p_tok = meta.get("payload") if isinstance(meta.get("payload"), dict) else {}
                    v_cid = str(getattr(auth_principal, "client_id", "") or p_tok.get("client_id") or "").strip()
                    v_jti = str(p_tok.get("jti") or meta.get("jti") or "").strip()
                    signing_key_str = str(getattr(self, "_oauth_signing_key", "") or "")
                    if v_cid and v_jti:
                        if hasattr(self._oauth_persistence, "resolve_or_renew_owner_grant_for_token") and signing_key_str:
                            active_grant_default = self._oauth_persistence.resolve_or_renew_owner_grant_for_token(
                                secret=signing_key_str,
                                owner_id="local_owner",
                                client_id=v_cid,
                                oauth_token_jti=v_jti,
                            )
                        elif hasattr(self._oauth_persistence, "find_active_owner_grant_for_token"):
                            active_grant_default = self._oauth_persistence.find_active_owner_grant_for_token(
                                owner_id="local_owner",
                                client_id=v_cid,
                                oauth_token_jti=v_jti,
                            )
                except Exception:
                    active_grant_default = None

            tools_list = assemble_autonomous_tool_catalog(
                auth_principal=auth_principal,
                is_owner_full_control=is_owner_full_control,
                include_coding_tools=include_coding_tools,
                active_grant_default=active_grant_default,
                advertised_schemes=advertised_schemes,
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }

        if method == "tools/call":
            from runtime.agent_mcp_tools import (
                CLOUD_AUTONOMOUS_TOOL_DEFINITIONS,
                CLOUD_SAFE_AUTONOMOUS_TOOLS,
                OWNER_CONTROL_AUTONOMOUS_TOOLS,
            )
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            if not isinstance(tool_name, str):
                return {"jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32602, "message": "Tool name must be a string"}}

            if include_coding_tools:
                from runtime.coding_tools import ALL_CODING_TOOL_DEFINITIONS, CodingToolHandler
                if tool_name in ALL_CODING_TOOL_DEFINITIONS:
                    try:
                        if not caller_id or not caller_id.strip():
                            raise PermissionError("Authenticated caller identity is required")
                        if isinstance(tool_args, dict) and tool_args.get("owner_oauth_token") is not None:
                            raise PermissionError(
                                "Permission Denied (P0-02): owner_oauth_token in tool arguments is not accepted as proof of owner authorization"
                            )
                        Draft202012Validator(ALL_CODING_TOOL_DEFINITIONS[tool_name][1]).validate(tool_args)
                        if not hasattr(self, "_coding_tool_handler"):
                            agent_handler = self.get_agent_tool_handler()
                            rp = getattr(self, "runtime_paths", None)
                            coding_audit_p = (Path(rp.root_dir) / "logs" / "coding_audit.db") if rp and getattr(rp, "root_dir", None) else None
                            self._coding_tool_handler = CodingToolHandler(
                                agent_handler.store,
                                agent_handler.broker,
                                audit_path=coding_audit_p,
                            )
                        output = self._coding_tool_handler.execute_tool(
                            tool_name, tool_args, caller_tier=caller_tier,
                            surface="cloud_coding", caller_id=caller_id,
                            auth_principal=auth_principal,
                            oauth_persistence=getattr(self, "_oauth_persistence", None),
                            oauth_signing_key=str(getattr(self, "_oauth_signing_key", "") or ""),
                        )
                        wire_text = (
                            serialize_autonomous_read_file_result(output)
                            if tool_name == "agent_read_file"
                            else safe_json_result(output)
                        )
                        return {"jsonrpc": "2.0", "id": req_id, "result": {
                            "content": [{"type": "text", "text": wire_text}],
                            "isError": bool(isinstance(output, dict) and output.get("error")),
                        }}
                    except Exception as err:
                        return {"jsonrpc": "2.0", "id": req_id, "result": {
                            "content": [{"type": "text", "text": f"Blocked or invalid: {redact_secrets(str(err))}"}],
                            "isError": True,
                        }}

            if server_owner_profile or is_owner_full_control or tool_name in OWNER_EXEC_AND_DESKTOP_TOOLS:
                if tool_name in OWNER_CONTROL_AUTONOMOUS_TOOLS and (server_owner_profile or is_owner_full_control):
                    # 1. Require authenticated caller (R2 / V04)
                    if not caller_id or caller_id.casefold() in ("anonymous", "untrusted", "unknown"):
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": "Permission Denied (R2): Authenticated caller identity is required"}],
                                "isError": True,
                            },
                        }

                    # Emergency stop requires authenticated owner authority
                    if tool_name == "agent_emergency_stop" and not is_authenticated_owner:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": "Permission Denied (R2): Caller is not authorized for emergency stop"}],
                                "isError": True,
                            },
                        }

                    # 2. Check task ownership for task-specific controls (pause, resume, cancel)
                    agent_handler = self.get_agent_tool_handler()
                    task_id = tool_args.get("task_id")
                    if task_id:
                        task_rec = agent_handler.store.get_task(task_id)
                        if not task_rec:
                            return {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": f"Task not found: {task_id}"}],
                                    "isError": True,
                                },
                            }
                        task_owner = getattr(task_rec, "owner_id", None)
                        if not is_authenticated_owner and task_owner != caller_id:
                            return {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": "Permission Denied (R2): Caller does not own this task"}],
                                    "isError": True,
                                },
                            }

                    out = agent_handler.execute_tool(tool_name, tool_args)
                    if self.policy and hasattr(self.policy, "audit"):
                        self.policy.audit.log_event(
                            tool_name=tool_name,
                            tier="WRITE" if tool_name != "agent_emergency_stop" else "SYSTEM_ADMIN",
                            decision="PERMIT" if not (isinstance(out, dict) and out.get("error")) else "DENIED",
                            reason=f"Caller {caller_id} (is_owner={is_authenticated_owner}) via cloud_autonomous",
                            arguments=tool_args,
                        )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out)}],
                            "isError": bool(isinstance(out, dict) and out.get("error")),
                        },
                    }

                if tool_name in OWNER_EXEC_AND_DESKTOP_TOOLS:
                    ok_owner, err_owner, grant_meta = self._validate_owner_execution_and_capability(
                        tool_name=tool_name,
                        tool_args=tool_args,
                        caller_id=caller_id,
                        caller_tier=caller_tier,
                        auth_principal=auth_principal,
                        server_owner_profile=server_owner_profile,
                        is_authenticated_owner=is_authenticated_owner,
                    )
                    if not ok_owner:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": err_owner}],
                                "isError": True,
                            },
                        }

                if tool_name == "agent_powershell_execute":
                    cmd = tool_args.get("command", "")
                    cwd = tool_args.get("cwd") or "."
                    timeout_sec = min(max(1, int(tool_args.get("timeout_seconds", 60))), 300)

                    from runtime.process_runner import execute_powershell_tree
                    tree_res = execute_powershell_tree(
                        command=cmd,
                        cwd=cwd,
                        timeout_seconds=float(timeout_sec),
                        max_output_bytes=65536,
                        stop_check_fn=self.is_emergency_stop_active,
                    )
                    res = tree_res.to_dict()
                    res["ok"] = tree_res.exit_code == 0 and not tree_res.timed_out and not tree_res.interrupted
                    if grant_meta.get("grant_id"):
                        res["capability_grant_id"] = grant_meta["grant_id"]
                        res["grant_used_count"] = grant_meta.get("used_count")
                    exit_code = tree_res.exit_code
                    timed_out = tree_res.timed_out
                    interrupted = tree_res.interrupted

                    self._log_owner_cloud_audit(
                        tool_name="agent_powershell_execute",
                        tier="EXECUTE",
                        decision="PERMIT" if exit_code == 0 else "FAILED",
                        reason=f"Exit: {exit_code}, timed_out: {timed_out}, interrupted: {interrupted}",
                        caller_id=caller_id,
                        arguments={"command": cmd[:200], "cwd": cwd, "grant_id": grant_meta.get("grant_id")},
                    )

                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(res)}],
                            "isError": res["exit_code"] != 0,
                        },
                    }

                if tool_name == "agent_desktop_screenshot":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    target_mode = "window" if tool_args.get("hwnd") else "desktop"
                    try:
                        res = desk.screenshot(
                            target=target_mode,
                            monitor=int(tool_args.get("monitor", 0)),
                            hwnd=tool_args.get("hwnd"),
                            max_width=tool_args.get("max_width") or 1280,
                        )
                    except TypeError:
                        res = desk.screenshot(
                            monitor=int(tool_args.get("monitor", 0)),
                            max_width=tool_args.get("max_width"),
                        )
                    out_dict = dict(res) if isinstance(res, dict) else {"result": res}
                    save_path = tool_args.get("save_path")
                    if save_path and isinstance(out_dict.get("data_base64"), str):
                        import base64 as _b64
                        raw_png = _b64.b64decode(out_dict["data_base64"].encode("ascii"))
                        sp = Path(save_path).resolve()
                        sp.parent.mkdir(parents=True, exist_ok=True)
                        sp.write_bytes(raw_png)
                        out_dict["saved_path"] = str(sp)
                        out_dict["saved_bytes"] = len(raw_png)
                    # Strip huge base64 / mcp_content from text JSON so it never truncates or collides
                    if save_path or len(str(out_dict.get("data_base64", ""))) > 32000:
                        out_dict.pop("data_base64", None)
                    out_dict.pop("mcp_content", None)
                    out_dict["ok"] = True
                    if grant_meta.get("grant_id"):
                        out_dict["capability_grant_id"] = grant_meta["grant_id"]
                        out_dict["grant_used_count"] = grant_meta.get("used_count")
                    self._log_owner_cloud_audit(
                        tool_name="agent_desktop_screenshot",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"Screenshot captured (sha256={out_dict.get('sha256')})",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out_dict)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_get_active_window":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    active_info = desk.get_active_window()
                    title_filter = str(tool_args.get("title_contains") or "").strip()
                    matching = []
                    if title_filter:
                        win_res = desk.list_windows(title_contains=title_filter, max_results=20)
                        matching = win_res.get("windows", []) if isinstance(win_res, dict) else []
                    out_dict = {
                        "ok": True,
                        "active_window": active_info.get("active_window") if isinstance(active_info, dict) else active_info,
                        "matching_windows": matching,
                    }
                    if grant_meta.get("grant_id"):
                        out_dict["capability_grant_id"] = grant_meta["grant_id"]
                    self._log_owner_cloud_audit(
                        tool_name="agent_get_active_window",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason="Active window inspected",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out_dict)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_focus_window":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    target_hwnd = tool_args.get("hwnd")
                    title_filter = str(tool_args.get("title_contains") or "").strip()
                    if not target_hwnd and title_filter:
                        win_res = desk.list_windows(title_contains=title_filter, max_results=10)
                        wins = win_res.get("windows", []) if isinstance(win_res, dict) else []
                        if not wins:
                            return {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": safe_json_result({"ok": False, "error": f"No visible window matching '{title_filter}'"})}],
                                    "isError": True,
                                },
                            }
                        target_hwnd = wins[0]["hwnd"]
                    if not target_hwnd:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": safe_json_result({"ok": False, "error": "Either hwnd or title_contains is required"})}],
                                "isError": True,
                            },
                        }
                    focus_res = desk.focus_window(
                        hwnd=int(target_hwnd),
                        restore_if_minimized=bool(tool_args.get("restore_if_minimized", True)),
                    )
                    out_dict = dict(focus_res) if isinstance(focus_res, dict) else {"result": focus_res}
                    out_dict["ok"] = True
                    self._log_owner_cloud_audit(
                        tool_name="agent_focus_window",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"Focused hwnd={target_hwnd}",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out_dict)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_keyboard_type":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    target_hwnd = tool_args.get("hwnd")
                    title_filter = str(tool_args.get("title_contains") or "").strip()
                    if not target_hwnd and title_filter:
                        win_res = desk.list_windows(title_contains=title_filter, max_results=10)
                        wins = win_res.get("windows", []) if isinstance(win_res, dict) else []
                        if not wins:
                            return {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": safe_json_result({"ok": False, "error": f"No visible window matching '{title_filter}'"})}],
                                    "isError": True,
                                },
                            }
                        target_hwnd = wins[0]["hwnd"]
                    if target_hwnd:
                        desk.focus_window(hwnd=int(target_hwnd), restore_if_minimized=True)
                        time.sleep(0.08)
                    results_list = []
                    if tool_args.get("text"):
                        r_type = desk.keyboard_type(
                            text=str(tool_args["text"]),
                            interval_ms=int(tool_args.get("interval_ms", 10)),
                        )
                        results_list.append(r_type)
                    if tool_args.get("key"):
                        r_key = desk.keyboard_keypress(key=str(tool_args["key"]))
                        results_list.append(r_key)
                    if tool_args.get("keys"):
                        r_hk = desk.keyboard_hotkey(
                            keys=[str(k) for k in tool_args["keys"]],
                            interval_ms=int(tool_args.get("interval_ms", 20)),
                        )
                        results_list.append(r_hk)
                    out_dict = {
                        "ok": True,
                        "focused_hwnd": target_hwnd,
                        "actions": results_list,
                    }
                    self._log_owner_cloud_audit(
                        tool_name="agent_keyboard_type",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"Keyboard input sent (actions={len(results_list)}, hwnd={target_hwnd})",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out_dict)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_mouse_click":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    target_hwnd = tool_args.get("hwnd")
                    title_filter = str(tool_args.get("title_contains") or "").strip()
                    win_info = None
                    if not target_hwnd and title_filter:
                        win_res = desk.list_windows(title_contains=title_filter, max_results=10)
                        wins = win_res.get("windows", []) if isinstance(win_res, dict) else []
                        if not wins:
                            return {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": safe_json_result({"ok": False, "error": f"No visible window matching '{title_filter}'"})}],
                                    "isError": True,
                                },
                            }
                        target_hwnd = wins[0]["hwnd"]
                        win_info = wins[0]
                    if target_hwnd:
                        f_res = desk.focus_window(hwnd=int(target_hwnd), restore_if_minimized=True)
                        if isinstance(f_res, dict) and isinstance(f_res.get("window"), dict):
                            win_info = f_res["window"]
                        time.sleep(0.08)
                    click_x = tool_args.get("x")
                    click_y = tool_args.get("y")
                    if (click_x is None or click_y is None) and isinstance(win_info, dict):
                        rect = win_info.get("rect") if isinstance(win_info.get("rect"), dict) else win_info
                        if "left" in rect and "top" in rect:
                            off_x = int(tool_args.get("offset_x", max(10, int(rect.get("width", 100)) // 2)))
                            off_y = int(tool_args.get("offset_y", max(10, int(rect.get("height", 100)) // 2)))
                            click_x = int(rect["left"]) + off_x
                            click_y = int(rect["top"]) + off_y
                    button = str(tool_args.get("button", "left"))
                    if tool_args.get("double"):
                        c_res = desk.mouse_double_click(x=click_x, y=click_y, button=button)
                    else:
                        c_res = desk.mouse_click(x=click_x, y=click_y, button=button)
                    out_dict = dict(c_res) if isinstance(c_res, dict) else {"result": c_res}
                    out_dict["ok"] = True
                    out_dict["focused_hwnd"] = target_hwnd
                    self._log_owner_cloud_audit(
                        tool_name="agent_mouse_click",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"Mouse click at ({click_x}, {click_y}) button={button}",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out_dict)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_visual_verify":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    target_hwnd = tool_args.get("hwnd")
                    title_filter = str(tool_args.get("title_contains") or "").strip()
                    win_info = None
                    if not target_hwnd and title_filter:
                        win_res = desk.list_windows(title_contains=title_filter, max_results=10)
                        wins = win_res.get("windows", []) if isinstance(win_res, dict) else []
                        if not wins:
                            return {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": safe_json_result({"ok": False, "error": f"No visible window matching '{title_filter}'"})}],
                                    "isError": True,
                                },
                            }
                        target_hwnd = wins[0]["hwnd"]
                        win_info = wins[0]
                    target_mode = "window" if target_hwnd else "desktop"
                    shot = desk.screenshot(
                        target=target_mode,
                        hwnd=int(target_hwnd) if target_hwnd else None,
                        max_width=1280,
                    )
                    saved_path_str = None
                    saved_bytes_len = 0
                    if tool_args.get("save_path") and isinstance(shot.get("data_base64"), str):
                        import base64 as _b64
                        raw_png = _b64.b64decode(shot["data_base64"].encode("ascii"))
                        sp = Path(tool_args["save_path"]).resolve()
                        sp.parent.mkdir(parents=True, exist_ok=True)
                        sp.write_bytes(raw_png)
                        saved_path_str = str(sp)
                        saved_bytes_len = len(raw_png)
                    verify_file_info = None
                    if tool_args.get("verify_path"):
                        vp = Path(tool_args["verify_path"]).resolve()
                        if vp.exists() and vp.is_file():
                            v_bytes = vp.read_bytes()
                            import hashlib as _hl
                            verify_file_info = {
                                "path": str(vp),
                                "exists": True,
                                "bytes": len(v_bytes),
                                "sha256": _hl.sha256(v_bytes).hexdigest(),
                                "file_text": v_bytes.decode("utf-8", errors="replace"),
                            }
                        else:
                            verify_file_info = {"path": str(vp), "exists": False}
                    verify_ok = bool(
                        (not title_filter or win_info is not None)
                        and (verify_file_info is None or verify_file_info.get("exists"))
                    )
                    out_dict = {
                        "ok": verify_ok,
                        "hwnd": target_hwnd,
                        "window": win_info,
                        "screenshot_sha256": shot.get("sha256"),
                        "screenshot_width": shot.get("width"),
                        "screenshot_height": shot.get("height"),
                        "screenshot_byte_length": shot.get("byte_length"),
                        "saved_screenshot_path": saved_path_str,
                        "saved_screenshot_bytes": saved_bytes_len,
                        "verified_file": verify_file_info,
                    }
                    self._log_owner_cloud_audit(
                        tool_name="agent_visual_verify",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"Visual verification completed (screenshot_sha256={shot.get('sha256')})",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(out_dict)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_launch_app":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    app_path_val = str(tool_args.get("app_path", "")).strip()
                    app_args_val = str(tool_args.get("arguments", "")).strip()
                    if hasattr(desk, "launch_app"):
                        res = desk.launch_app(app_path_val, arguments=app_args_val)
                    else:
                        import shlex as _shlex
                        cmd_list = [app_path_val]
                        if app_args_val:
                            cmd_list.extend(_shlex.split(app_args_val, posix=False))
                        proc = subprocess.Popen(cmd_list)
                        res = {"ok": True, "pid": proc.pid, "app_path": app_path_val, "arguments": app_args_val}
                    self._log_owner_cloud_audit(
                        tool_name="agent_launch_app",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"Launched {tool_args.get('app_path', '')}",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(res)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_list_windows":
                    desk = getattr(self, "desktop_agent", None) or self._get_owner_desktop_agent()
                    res = desk.list_windows(
                        title_contains=tool_args.get("title_contains", ""),
                        max_results=int(tool_args.get("max_results", 50)),
                    )
                    self._log_owner_cloud_audit(
                        tool_name="agent_list_windows",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason="Listed windows",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(res)}],
                            "isError": False,
                        },
                    }

                if tool_name == "agent_system_status":
                    if not is_owner_full_control:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": "Permission Denied (R2): Caller is not authorized for owner system status"}],
                                "isError": True,
                            },
                        }
                    import platform
                    import shutil as sh
                    drives_info = []
                    for drive in ("C:\\", "D:\\"):
                        try:
                            usage = sh.disk_usage(drive)
                            drives_info.append({
                                "drive": drive,
                                "total_gb": round(usage.total / (1024**3), 2),
                                "free_gb": round(usage.free / (1024**3), 2),
                            })
                        except Exception:
                            pass
                    from runtime.release_identity import get_release_identity
                    rel_id = get_release_identity()
                    sys_info = {
                        "os": platform.platform(),
                        "python": platform.python_version(),
                        "drives": drives_info,
                        "git_sha": rel_id["source_commit"],
                        "release_version": rel_id["release_version"],
                        "build_id": rel_id["build_id"],
                        "zip_sha256": rel_id["zip_sha256"],
                        "server_version": self.server_version,
                        "pid": os.getpid(),
                        "authenticated_caller": caller_id,
                        "auth_method": getattr(auth_principal, "auth_method", "local") if auth_principal else "local",
                        "is_owner": is_authenticated_owner,
                        "capability_grant_id": grant_meta.get("grant_id"),
                        "grant_used_count": grant_meta.get("used_count"),
                    }
                    self._log_owner_cloud_audit(
                        tool_name="agent_system_status",
                        tier="DESKTOP",
                        decision="PERMIT",
                        reason=f"System status queried (git_sha={sys_info['git_sha']})",
                        caller_id=caller_id,
                        arguments=tool_args,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": safe_json_result(sys_info)}],
                            "isError": False,
                        },
                    }

            if tool_name in OWNER_CONTROL_AUTONOMOUS_TOOLS:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "Permission Denied (G05): Owner control tool is restricted to authenticated local Owner Web Console"}],
                        "isError": True,
                    },
                }

            if tool_name not in CLOUD_SAFE_AUTONOMOUS_TOOLS:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Permission Denied (G05): Tool '{tool_name}' is not exposed on cloud autonomous surface"}],
                        "isError": True,
                    },
                }

            try:
                schema = CLOUD_AUTONOMOUS_TOOL_DEFINITIONS[tool_name][1]
                Draft202012Validator(schema).validate(tool_args)
            except ValidationError as err:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Validation error: {err.message}"}],
                        "isError": True,
                    },
                }

            try:
                handler = self.get_agent_tool_handler()
                try:
                    output = handler.execute_tool(
                        tool_name,
                        tool_args,
                        caller_tier="READ",
                        surface="cloud_autonomous",
                        caller_id=caller_id or "cloud_autonomous",
                    )
                except TypeError:
                    try:
                        output = handler.execute_tool(
                            tool_name,
                            tool_args,
                            caller_tier="READ",
                            surface="cloud_autonomous",
                        )
                    except TypeError:
                        output = handler.execute_tool(
                            tool_name,
                            tool_args,
                            surface="cloud_autonomous",
                        )
                is_err = bool(isinstance(output, dict) and output.get("error"))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": safe_json_result(output)}],
                        "isError": is_err,
                    },
                }
            except Exception as err:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Tool execution error: {err}"}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    # ------------------------------------------------------------------
    # MCP JSON-RPC 2.0 Protocol Handler
    # ------------------------------------------------------------------
    def handle_jsonrpc(
        self,
        message: dict[str, Any],
        *,
        session_id: str | None = None,
        approval_token: str | None = None,
        caller_id: str | None = None,
        caller_tier: str = "READ",
        auth_principal: Any = None,
    ) -> dict[str, Any] | None:
        """Process a standard MCP JSON-RPC 2.0 request and return the JSON-RPC response dict."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id") if isinstance(message, dict) else None,
                "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request"},
            }

        method = message.get("method", "")
        req_id = message.get("id")
        params = message.get("params") or {}

        # Notifications do not return a response
        if method.startswith("notifications/"):
            return None

        server_owner_profile = bool(self.policy and getattr(self.policy, "unrestricted_workspace_access", False))
        from runtime.process_runner import verify_cloud_principal
        _, is_owner_principal, verified_identity = verify_cloud_principal(
            auth_principal,
            internal_local_trusted=bool(
                caller_id == "local_owner"
                and auth_principal is None
                and getattr(self, "_internal_local_trusted", True)
            ),
        )
        if auth_principal is not None:
            caller_id = verified_identity or caller_id
            caller_tier = getattr(auth_principal, "tier", caller_tier)
        is_authenticated_owner = bool(is_owner_principal and caller_tier in ("WRITE", "EXECUTE", "SYSTEM_ADMIN"))
        is_owner_full_control = bool(server_owner_profile or is_authenticated_owner)

        if method == "initialize":
            client_proto = params.get("protocolVersion", "2024-11-05")
            negotiated_proto = "2025-03-26" if client_proto == "2025-03-26" else "2024-11-05"
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated_proto,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": self.server_name,
                        "version": self.server_version,
                        "profile": self.policy.profile,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            tools_list = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "inputSchema": t["inputSchema"],
                }
                for t in self.list_tools()
            ]
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            try:
                output = self.invoke_tool(
                    tool_name,
                    tool_args,
                    session_id=session_id,
                    approval_token=approval_token,
                    caller_id=caller_id,
                )
                content_blocks: list[dict[str, Any]] = []
                if tool_name == "screenshot" and isinstance(output, dict) and "mcp_content" in output:
                    meta_copy = {k: v for k, v in output.items() if k not in ("data_base64", "mcp_content")}
                    content_blocks.extend(output["mcp_content"])
                    content_blocks.append({"type": "text", "text": safe_json_result(meta_copy)})
                else:
                    content_blocks.append({"type": "text", "text": safe_json_result(output)})

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": content_blocks,
                        "isError": False,
                    },
                }
            except (PermissionError, ValueError, ValidationError, FileNotFoundError, IsADirectoryError, NotADirectoryError, KeyError) as err:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Blocked or invalid: {err}"}],
                        "isError": True,
                    },
                }
            except Exception as err:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Tool execution error: {err}"}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def create_mcp_sdk_server(gateway: MCPGatewayServer | None = None):
    """Create an official MCP SDK Server wrapping MCPGatewayServer."""
    from mcp.server import Server, ServerRequestContext
    from mcp.types import (
        CallToolRequestParams,
        CallToolResult,
        ImageContent,
        ListToolsResult,
        PaginatedRequestParams,
        TextContent,
        Tool,
    )

    gw = gateway or MCPGatewayServer()

    async def _on_list_tools(
        ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name=t["name"],
                    description=t["description"],
                    input_schema=t["input_schema"],
                )
                for t in gw.list_tools()
            ]
        )

    async def _on_call_tool(
        ctx: ServerRequestContext, params: CallToolRequestParams
    ) -> CallToolResult:
        try:
            res = await asyncio.to_thread(gw.invoke_tool, params.name, params.arguments or {})
            if params.name == "screenshot" and isinstance(res, dict) and "data_base64" in res:
                meta = {k: v for k, v in res.items() if k not in ("data_base64", "mcp_content")}
                return CallToolResult(
                    content=[
                        ImageContent(type="image", data=res["data_base64"], mimeType="image/png"),
                        TextContent(type="text", text=safe_json_result(meta)),
                    ]
                )
            return CallToolResult(content=[TextContent(type="text", text=safe_json_result(res))])
        except Exception as err:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Blocked or invalid: {err}")],
                is_error=True,
            )

    return Server(
        gw.server_name,
        version=gw.server_version,
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for Unified MCP Gateway (supports --http-local and --stdio)."""
    import argparse

    parser = argparse.ArgumentParser(description="Unified Windows MCP Gateway v0.3.0")
    parser.add_argument(
        "--http-local",
        action="store_true",
        help="Run Streamable HTTP server on loopback (default port 8766)",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run MCP STDIO JSON-RPC loop",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Loopback bind address for HTTP mode (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("WINDOWS_MCP_GATEWAY_STAGING_PORT", "8766")),
        help="TCP port for HTTP mode (default: 8766)",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("MCP_AGENT_PROFILE", "read_only"),
        help="Active security profile (read_only, developer_p2, desktop_p3, full_agent)",
    )
    args = parser.parse_args(argv)

    if args.stdio:
        pol = SecurityPolicy(profile=args.profile)
        gw = MCPGatewayServer(policy=pol)
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                resp = gw.handle_jsonrpc(msg)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                    sys.stdout.flush()
            except Exception as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        return 0

    from http_server import main as http_main

    return http_main(["--host", args.host, "--port", str(args.port), "--profile", args.profile])


if __name__ == "__main__":
    raise SystemExit(main())

