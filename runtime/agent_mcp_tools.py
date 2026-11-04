"""High-Level MCP Autonomous Agent Tool Handlers.

Exposes 11 high-level MCP tools for ChatGPT / Remote Web Clients to submit,
approve, monitor, inspect, pause, resume, and cancel autonomous tasks under a TaskGrant:
- agent_submit_task
- agent_approve_task
- agent_task_status
- agent_task_logs
- agent_task_diff
- agent_task_artifacts
- agent_task_pause
- agent_task_resume
- agent_task_cancel
- agent_list_tasks
- agent_emergency_stop
"""
from __future__ import annotations

import base64
import difflib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_GW_DIR = str(Path(__file__).resolve().parent.parent / "mcp-gateway")
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

from policy import (
    PermissionTier,
    TOOL_TIER_MAP,
)
from runtime.autonomous_agent import AutonomousAgentController
from runtime.task_grant import (
    SENSITIVE_SUBDIRS,
    TaskGrant,
    TaskGrantBroker,
    _is_sensitive_path,
    compute_proposal_scope_digest,
)
from runtime.task_store import ExecutionMode, TaskRecord, TaskState, TaskStore

AUTONOMOUS_TOOL_DEFINITIONS = {
    "agent_submit_task": (
        "AUTONOMOUS. Submit a new task with a scoped TaskGrant for autonomous execution.",
        {
            "type": "object",
            "properties": {
                "objective": {"type": "string", "description": "Goal/objective description for the task."},
                "workspace_root": {"type": "string", "description": "Canonical workspace directory."},
                "allowed_tools": {"type": "array", "items": {"type": "string"}, "description": "Tools allowed under this grant."},
                "allowed_commands": {"type": "array", "items": {"type": "string"}, "description": "Shell commands allowed (e.g. ['pytest*', 'python*'])."},
                "duration_seconds": {"type": "number", "description": "Maximum execution duration (seconds). Default 3600."},
                "mode": {"type": "string", "enum": ["TRUSTED_TASK", "UNATTENDED_WORKER"], "description": "Execution mode."},
                "grant_id": {"type": "string", "description": "Pre-issued owner TaskGrant ID."},
                "owner_approval_token": {"type": "string", "description": "Cryptographic HMAC owner approval token."},
                "spawn_worker": {"type": "boolean", "description": "Whether to spawn a background worker thread."},
                "auto_start": {"type": "boolean", "description": "Alias for spawn_worker."},
            },
            "required": ["objective", "workspace_root"],
            "additionalProperties": False,
        },
    ),
    "agent_approve_task": (
        "AUTONOMOUS. Approve an authorization-pending task and issue a TaskGrant.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID to approve."},
                "owner_approval_token": {"type": "string", "description": "Owner HMAC approval token."},
                "allowed_tools": {"type": "array", "items": {"type": "string"}, "description": "Tools allowed under this grant."},
                "allowed_commands": {"type": "array", "items": {"type": "string"}, "description": "Shell commands allowed."},
                "duration_seconds": {"type": "number", "description": "Maximum execution duration in seconds. Default 3600."},
                "spawn_worker": {"type": "boolean", "description": "Whether to spawn a background worker thread."},
            },
            "required": ["task_id", "owner_approval_token"],
            "additionalProperties": False,
        },
    ),
    "agent_task_status": (
        "AUTONOMOUS. Get status, current state, progress, and error message of a task.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_task_logs": (
        "AUTONOMOUS. Retrieve chronological execution logs and audit entries for a task.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "limit": {"type": "integer", "description": "Maximum number of logs to return. Default 50."},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_task_diff": (
        "AUTONOMOUS. View Git diff or file modifications made during task execution.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_task_artifacts": (
        "AUTONOMOUS. List files modified, created, or tested by the task.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_task_pause": (
        "AUTONOMOUS. Pause an active autonomous task.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_task_resume": (
        "AUTONOMOUS. Resume a paused autonomous task.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "spawn_worker": {"type": "boolean", "description": "Whether to spawn a background worker. Default True."},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_task_cancel": (
        "AUTONOMOUS. Cancel an autonomous task and revoke its TaskGrant.",
        {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    ),
    "agent_list_tasks": (
        "AUTONOMOUS. List existing tasks and their current states.",
        {
            "type": "object",
            "properties": {
                "state": {"type": "string", "description": "Filter by TaskState (e.g. RUNNING, COMPLETED)."},
                "limit": {"type": "integer", "description": "Max entries to return. Default 20."},
            },
            "additionalProperties": False,
        },
    ),
    "agent_emergency_stop": (
        "AUTONOMOUS. Trigger Emergency Stop halting all autonomous tasks immediately.",
        {
            "type": "object",
            "properties": {
                "reason": {"type": "string"},
            },
            "additionalProperties": False,
        },
    ),
}

CLOUD_SAFE_AUTONOMOUS_TOOLS = (
    "agent_submit_task",
    "agent_task_status",
    "agent_task_logs",
    "agent_task_diff",
    "agent_task_artifacts",
    "agent_list_tasks",
)

OWNER_CONTROL_AUTONOMOUS_TOOLS = (
    "agent_approve_task",
    "agent_task_pause",
    "agent_task_resume",
    "agent_task_cancel",
    "agent_emergency_stop",
)

CLOUD_AUTONOMOUS_TOOL_DEFINITIONS = {
    "agent_submit_task": (
        "AUTONOMOUS. Submit a new task proposal for autonomous execution. Task will be created in AUTHORIZATION_PENDING state awaiting owner approval.",
        {
            "type": "object",
            "properties": {
                "objective": {"type": "string", "description": "Goal/objective description for the task."},
                "workspace_root": {"type": "string", "description": "Canonical workspace directory."},
                "allowed_tools": {"type": "array", "items": {"type": "string"}, "description": "Tools requested for this task."},
                "allowed_commands": {"type": "array", "items": {"type": "string"}, "description": "Shell commands requested (e.g. ['pytest*', 'python*'])."},
                "duration_seconds": {"type": "number", "description": "Maximum execution duration (seconds). Default 3600."},
                "mode": {"type": "string", "enum": ["TRUSTED_TASK", "UNATTENDED_WORKER"], "description": "Execution mode."},
            },
            "required": ["objective", "workspace_root"],
            "additionalProperties": False,
        },
    ),
    "agent_task_status": AUTONOMOUS_TOOL_DEFINITIONS["agent_task_status"],
    "agent_task_logs": AUTONOMOUS_TOOL_DEFINITIONS["agent_task_logs"],
    "agent_task_diff": AUTONOMOUS_TOOL_DEFINITIONS["agent_task_diff"],
    "agent_task_artifacts": AUTONOMOUS_TOOL_DEFINITIONS["agent_task_artifacts"],
    "agent_list_tasks": AUTONOMOUS_TOOL_DEFINITIONS["agent_list_tasks"],
}

CLOUD_AUTONOMOUS_TOOL_ANNOTATIONS: dict[str, dict[str, Any]] = {
    "agent_submit_task": {
        "title": "Submit Autonomous Task Proposal",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    "agent_task_status": {
        "title": "Get Autonomous Task Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "agent_task_logs": {
        "title": "Get Autonomous Task Logs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "agent_task_diff": {
        "title": "Get Autonomous Task Git Diff",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "agent_task_artifacts": {
        "title": "Get Autonomous Task Artifacts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "agent_list_tasks": {
        "title": "List Authorized Autonomous Tasks",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}

CLOUD_AUTONOMOUS_TOOL_SECURITY_SCHEMES: dict[str, list[dict[str, Any]]] = {
    "agent_submit_task": [{"type": "noauth"}],
    "agent_task_status": [{"type": "noauth"}],
    "agent_task_logs": [{"type": "noauth"}],
    "agent_task_diff": [{"type": "noauth"}],
    "agent_task_artifacts": [{"type": "noauth"}],
    "agent_list_tasks": [{"type": "noauth"}],
}

_REDACT_PATTERNS = [
    # Private key contents
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----", re.MULTILINE), "[REDACTED_PRIVATE_KEY]"),
    # OpenAI / Anthropic API keys (sk-...)
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{10,}\b"), "[REDACTED_API_KEY]"),
    # Bearer tokens
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{16,}\b", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # v2 approval tokens
    (re.compile(r"\bv2\.[A-Za-z0-9_\-]+\.[0-9a-f]{64}\b"), "[REDACTED_APPROVAL_TOKEN]"),
    # Sensitive environment variable assignments
    (re.compile(r"\b(OPENAI_API_KEY|MCP_AUTH_TOKEN|SECRET_KEY|PASSWORD|API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\s*([=:])\s*\S+", re.IGNORECASE), r"\1\2[REDACTED]"),
    # DPAPI markers / blobs
    (re.compile(r"\b(?:dpapi[:=]\s*\S+|AQAAANCMnd8BFdERjHoAwE\S+)", re.IGNORECASE), "[REDACTED_DPAPI]"),
    # Sensitive secret files assignments (.env, id_rsa, broker_hmac.key)
    (re.compile(r"\b(?:broker_hmac\.key|id_rsa|id_ed25519|\.env(?:\.[a-zA-Z0-9_-]+)?)\s*[=:]\s*\S+", re.IGNORECASE), "[REDACTED_SECRET]"),
]


def redact_task_output(text: str) -> str:
    """Sanitize secret keys, tokens, and credentials from output text."""
    if not text or not isinstance(text, str):
        return text
    redacted = text
    for pat, repl in _REDACT_PATTERNS:
        redacted = pat.sub(repl, redacted)
    return redacted


def redact_task_dict(data: Any) -> Any:
    """Recursively redact secrets across dictionary/list structures."""
    if isinstance(data, str):
        return redact_task_output(data)
    elif isinstance(data, dict):
        return {k: redact_task_dict(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_task_dict(v) for v in data]
    elif isinstance(data, tuple):
        return tuple(redact_task_dict(v) for v in data)
    return data

_SYSTEM_ADMIN_TOOLS = frozenset((
    "modify_firewall",
    "modify_defender",
    "edit_registry",
    "system_admin_exec",
))

_INJECTION_CHARS = (";", "&&", "||", "|", ">", "<", "`", "$(")


class AgentMCPToolHandler:
    """Dispatches autonomous agent MCP tool calls."""

    def __init__(self, store: TaskStore, broker: TaskGrantBroker):
        self.store = store
        self.broker = broker

    def _validate_scope(
        self,
        raw_ws_root: str,
        allowed_tools: list[str] | None,
        allowed_commands: list[str] | None,
    ) -> tuple[bool, str, str]:
        """Validate requested scope upfront before creating or approving a task."""
        if not raw_ws_root or not isinstance(raw_ws_root, str):
            return False, "", "workspace_root must be a non-empty string"

        # Traversal check on raw input
        if ".." in raw_ws_root:
            return False, "", "workspace_root cannot contain traversal sequence '..'"

        ws_p = Path(raw_ws_root).resolve(strict=False)
        canonical_ws = str(ws_p)

        # Drive root check
        if ws_p == Path(ws_p.anchor) or len(ws_p.parts) <= 1 or ws_p.parent == ws_p:
            return False, "", f"Drive root {canonical_ws} is not permitted as workspace_root"

        # Sensitive directory check
        for sens_sub in SENSITIVE_SUBDIRS:
            sens_p = Path(sens_sub).resolve(strict=False)
            try:
                if ws_p == sens_p or ws_p.is_relative_to(sens_p):
                    return False, "", f"Path {canonical_ws} is inside sensitive directory {sens_sub}"
            except Exception:
                pass

        parts_lower = [p.lower() for p in ws_p.parts]
        if ".ssh" in parts_lower:
            return False, "", f"Path {canonical_ws} contains sensitive .ssh directory"

        fwd = canonical_ws.replace("\\", "/").lower()
        if "runtime/secrets" in fwd or fwd.endswith("/secrets"):
            return False, "", f"Path {canonical_ws} contains sensitive secrets directory"

        if _is_sensitive_path(ws_p):
            return False, "", f"Path {canonical_ws} matches sensitive path rules"

        # Validate allowed_tools
        if allowed_tools is not None:
            for tool in allowed_tools:
                if tool not in TOOL_TIER_MAP:
                    return False, "", f"Unknown tool: '{tool}'"
                if tool in _SYSTEM_ADMIN_TOOLS or TOOL_TIER_MAP.get(tool) == PermissionTier.SYSTEM_ADMIN:
                    return False, "", f"SYSTEM_ADMIN tool is not permitted: '{tool}'"

        # Validate allowed_commands
        if allowed_commands is not None:
            for cmd in allowed_commands:
                for ic in _INJECTION_CHARS:
                    if ic in cmd:
                        return False, "", f"Command contains forbidden injection sequence {ic!r}: '{cmd}'"

        return True, canonical_ws, ""

    def _is_caller_unprivileged(self, caller_tier: str | None, args: dict[str, Any]) -> tuple[bool, str]:
        """Check if caller lacks WRITE privileges to mint grants or approve tasks."""
        if caller_tier == "READ":
            return True, "Caller tier is READ"

        if hasattr(self.broker, "policy") and self.broker.policy is not None:
            policy = self.broker.policy
            if getattr(policy, "profile", None) == "read_only":
                sess_id = args.get("session_id")
                has_write = False
                if sess_id and hasattr(policy, "sessions"):
                    try:
                        sess = policy.sessions.validate_session(sess_id, PermissionTier.WRITE)
                        if sess:
                            has_write = True
                    except Exception:
                        has_write = False
                if not has_write and caller_tier != "WRITE":
                    return True, "Gateway policy is in read_only profile and caller has no valid WRITE session"

        return False, ""

    def _match_trusted_workspace(
        self,
        canonical_ws: str,
        allowed_tools: list[str],
        allowed_commands: list[str],
    ) -> dict[str, Any] | None:
        """Check if canonical_ws and requested tools/commands match an owner-configured Trusted Workspace."""
        cfg_path_env = os.getenv("WINDOWS_MCP_TRUSTED_WORKSPACES_CONFIG", "").strip()
        cfg_path = (
            Path(cfg_path_env)
            if cfg_path_env
            else Path(__file__).resolve().parent.parent / "config" / "trusted_workspaces.json"
        )
        if not cfg_path.exists():
            return None
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict) or not data.get("trusted_mode_enabled", False):
            return None

        ws_p = Path(canonical_ws).resolve(strict=False)
        for entry in data.get("trusted_workspaces", []) or []:
            if not isinstance(entry, dict):
                continue
            raw_root = entry.get("workspace_root", "")
            if not raw_root:
                continue
            trusted_p = Path(raw_root).resolve(strict=False)
            inc_sub = bool(entry.get("include_subdirectories", True))
            try:
                is_match = (ws_p == trusted_p) or (inc_sub and ws_p.is_relative_to(trusted_p))
            except Exception:
                is_match = False
            if not is_match:
                continue

            trusted_tools = set(entry.get("allowed_tools") or [])
            if trusted_tools and not set(allowed_tools).issubset(trusted_tools):
                continue

            trusted_cmds = set(entry.get("allowed_commands") or [])
            if trusted_cmds and not set(allowed_commands).issubset(trusted_cmds):
                continue

            return entry
        return None

    def _spawn_independent_worker_process(self, target_task_id: str | None = None) -> int:
        """Spawn an independent OS worker process for asynchronous task execution (G04/B4)."""
        key_path = (
            getattr(self.broker, "key_path", None)
            or getattr(self.broker, "_key_path", "")
            or (Path(__file__).resolve().parent / "secrets" / "broker_hmac.key")
        )
        cmd = [
            sys.executable, "-m", "runtime.autonomous_agent",
            "--db-path", str(self.store.db_path),
            "--key-path", str(key_path),
            "--max-tasks", "1",
            "--once",
        ]
        if target_task_id:
            cmd.extend(["--task-id", str(target_task_id)])
        proc = subprocess.Popen(
            cmd,
            cwd=str(Path(__file__).resolve().parent.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.pid

    def _check_task_ownership(
        self,
        task: TaskRecord,
        effective_caller: str,
        surface: str,
    ) -> tuple[bool, str]:
        """Verify that caller has permission to view or manage task (Finding H02)."""
        # On local surface with local owner/admin
        if surface == "local" and effective_caller in ("local", "local_owner", "local_admin"):
            return True, ""

        if effective_caller in (task.client_id, task.owner_id):
            return True, ""

        if surface == "local" and effective_caller == "local_admin":
            return True, ""

        return False, f"Permission Denied (H02): Caller '{effective_caller}' is not the authorized owner of task '{task.task_id}'"

    def execute_tool(
        self,
        name: str,
        args: dict[str, Any],
        caller_tier: str | None = None,
        surface: str = "local",
        caller_id: str | None = None,
    ) -> dict[str, Any]:
        effective_caller = (
            caller_id or args.get("_caller_id") or ("local_owner" if surface == "local" else "")
        ).strip()

        # Block Anonymous Callers on Cloud Surface (H01/H02)
        if surface == "cloud_autonomous":
            if not effective_caller or effective_caller.lower() in (
                "anonymous", "unauthenticated", "none", "unknown"
            ):
                return {
                    "error": "Permission Denied (H01/H02): Authenticated caller identity is required for cloud autonomous operations",
                    "status": "REJECTED",
                }

            if name in OWNER_CONTROL_AUTONOMOUS_TOOLS:
                return {
                    "error": "Permission Denied (G05): Owner control tool is restricted to authenticated local Owner Web Console",
                    "status": "REJECTED",
                }
            if name not in CLOUD_SAFE_AUTONOMOUS_TOOLS:
                return {
                    "error": f"Permission Denied (G05): Tool '{name}' is not exposed on cloud autonomous surface",
                    "status": "REJECTED",
                }

        if name == "agent_submit_task":
            objective = args["objective"]
            raw_ws = args["workspace_root"]
            allowed_tools = args.get("allowed_tools") or [
                "read_file", "write_file", "edit_file", "list_directory",
                "powershell_execute", "git_status", "git_diff",
            ]
            allowed_cmds = args.get("allowed_commands") or ["pytest*", "python*", "git*"]
            duration = float(args.get("duration_seconds", 3600.0))
            mode = args.get("mode", ExecutionMode.TRUSTED_TASK.value)

            if surface == "cloud_autonomous":
                grant_id = None
                owner_token = None
                spawn_worker = False
            else:
                grant_id = args.get("grant_id")
                owner_token = args.get("owner_approval_token")
                spawn_worker = bool(args.get("spawn_worker", args.get("auto_start", False)))

            # Validate requested scope upfront
            valid_scope, ws_root, err_msg = self._validate_scope(raw_ws, allowed_tools, allowed_cmds)
            if not valid_scope:
                if surface == "cloud_autonomous":
                    return {
                        "error": "Permission Denied (H01/H02): Workspace path or requested scope is invalid or forbidden",
                        "status": "REJECTED",
                    }
                return {"error": f"Permission Denied: {err_msg}", "status": "REJECTED"}

            # Confidential Workspace Boundary on Cloud agent_submit_task (H01/H02)
            if surface == "cloud_autonomous":
                preapproved = self.broker.list_preapproved_roots() if hasattr(self.broker, "list_preapproved_roots") else []
                req_preapproved = getattr(self.broker, "require_preapproved_roots", False)
                policy_obj = getattr(self.broker, "policy", None)
                policy_write_roots = [Path(r).resolve(strict=False) for r in getattr(policy_obj, "write_roots", []) or []]
                allowed_cloud_roots = preapproved if preapproved else policy_write_roots
                if allowed_cloud_roots or req_preapproved:
                    ws_p = Path(ws_root).resolve(strict=False)
                    in_root = any(ws_p == pr or ws_p.is_relative_to(pr) for pr in allowed_cloud_roots)
                    if not in_root:
                        return {
                            "error": "Permission Denied (H02): Requested workspace is not in the owner's preapproved workspace allowlist",
                            "status": "REJECTED",
                        }

            # Build canonical proposal dict & compute proposal_digest (G01)
            tid = args.get("task_id") or f"task_{uuid.uuid4().hex[:16]}"
            proposal_dict = {
                "task_id": tid,
                "objective": objective,
                "workspace_root": ws_root,
                "allowed_paths": [ws_root],
                "allowed_tools": allowed_tools,
                "allowed_commands": allowed_cmds,
                "allowed_permission_tiers": ["EXECUTE", "READ", "WRITE"],
                "duration_seconds": duration,
                "max_tool_calls": int(args.get("max_tool_calls", 500)),
                "max_retries": int(args.get("max_retries", 5)),
                "api_cost_budget": float(args.get("api_cost_budget", 5.0)),
            }
            proposal_digest = compute_proposal_scope_digest(proposal_dict)

            from runtime.llm_adapter import classify_background_task, get_llm_operating_status
            task_category, task_category_reason = classify_background_task(
                objective=objective,
                workspace_root=ws_root,
                metadata=args,
            )
            llm_status = get_llm_operating_status()
            is_live_llm_available = bool(llm_status.get("is_live_ai"))

            metadata = {
                "requested_tools": allowed_tools,
                "requested_commands": allowed_cmds,
                "duration_seconds": duration,
                "workspace_root": ws_root,
                "proposal_digest": proposal_digest,
                "requested_scope": proposal_dict,
                "submitted_by": effective_caller,
                "surface": surface,
                "task_category": task_category,
                "task_category_reason": task_category_reason,
                "block_on_missing_llm": bool(surface == "cloud_autonomous" or args.get("block_on_missing_llm", False)),
            }

            eff_client = effective_caller if effective_caller not in ("local_owner", "local") else "local"
            eff_owner = effective_caller if effective_caller not in ("local_owner", "local") else "local_owner"

            # Step 1: Create task record in AUTHORIZATION_PENDING state
            task = self.store.create_task(
                task_id=tid,
                objective=objective,
                workspace_root=ws_root,
                mode=mode,
                metadata=metadata,
                requested_scope=proposal_dict,
                proposal_digest=proposal_digest,
                owner_id=eff_owner,
                client_id=eff_client,
            )
            if task.state != TaskState.AUTHORIZATION_PENDING.value:
                self.store.update_task_state(task.task_id, TaskState.AUTHORIZATION_PENDING.value)
                task.state = TaskState.AUTHORIZATION_PENDING.value

            # Trusted Workspace Auto-Grant & Auto-Start (Trusted Full Agent Mode)
            trusted_entry = (
                None
                if args.get("require_manual_approval")
                else self._match_trusted_workspace(ws_root, allowed_tools, allowed_cmds)
            )
            if trusted_entry is not None and not grant_id and not owner_token:
                eff_duration = min(duration, float(trusted_entry.get("duration_seconds", 3600.0)))
                eff_max_calls = min(int(args.get("max_tool_calls", 500)), int(trusted_entry.get("max_tool_calls", 500)))
                eff_max_retries = min(int(args.get("max_retries", 10)), int(trusted_entry.get("max_retries", 10)))
                try:
                    grant = self.broker.issue_grant(
                        task_id=task.task_id,
                        workspace_root=ws_root,
                        allowed_tools=allowed_tools,
                        allowed_commands=allowed_cmds,
                        allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
                        duration_seconds=eff_duration,
                        owner_id=eff_owner,
                        client_id=eff_client,
                        resource_budget={
                            "max_cpu_percent": 80.0,
                            "max_memory_mb": 2048,
                            "max_file_writes": 200,
                            "max_tool_calls": eff_max_calls,
                            "max_retries": eff_max_retries,
                        },
                        proposal_digest=proposal_digest,
                    )
                    self.store.bind_grant(task.task_id, grant.grant_id)
                    self.store.log_event(
                        task.task_id,
                        "TRUSTED_AUTO_GRANT",
                        f"Auto-issued TaskGrant {grant.grant_id} under Trusted Workspace policy for {ws_root}",
                        data={"grant_id": grant.grant_id, "workspace_root": ws_root, "task_category": task_category},
                    )
                    if task_category == "LLM_DEPENDENT" and not is_live_llm_available:
                        self.store.update_task_state(
                            task.task_id,
                            TaskState.BLOCKED.value,
                            error_message=task_category_reason,
                        )
                        self.store.log_event(
                            task.task_id,
                            "BLOCKED",
                            task_category_reason,
                            level="WARN",
                            data={"tool_name": "planner_gate", "status": "MODEL_PROVIDER_NOT_CONFIGURED", "task_category": task_category},
                        )
                        return {
                            "task_id": task.task_id,
                            "grant_id": grant.grant_id,
                            "status": TaskState.BLOCKED.value,
                            "state": TaskState.BLOCKED.value,
                            "task_category": task_category,
                            "requires_owner_approval": False,
                            "trusted_auto_start": False,
                            "proposal_digest": proposal_digest,
                            "error_message": task_category_reason,
                            "message": f"Task is BLOCKED: {task_category_reason}",
                        }
                    worker_pid = self._spawn_independent_worker_process(target_task_id=task.task_id)
                    return {
                        "task_id": task.task_id,
                        "grant_id": grant.grant_id,
                        "status": TaskState.QUEUED.value,
                        "state": TaskState.QUEUED.value,
                        "task_category": task_category,
                        "requires_owner_approval": False,
                        "trusted_auto_start": True,
                        "worker_pid": worker_pid,
                        "proposal_digest": proposal_digest,
                        "message": "Deterministic task auto-authorized under Trusted Workspace policy, transitioned to QUEUED, and Independent Worker started.",
                    }
                except Exception as ex:
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=str(ex))
                    return {"error": f"Permission Denied: {ex}", "status": "REJECTED"}

            # If submitted from cloud autonomous surface (outside Trusted Workspaces), strictly enforce AUTHORIZATION_PENDING
            if surface == "cloud_autonomous":
                return {
                    "task_id": task.task_id,
                    "grant_id": None,
                    "status": TaskState.AUTHORIZATION_PENDING.value,
                    "state": TaskState.AUTHORIZATION_PENDING.value,
                    "requires_owner_approval": True,
                    "proposal_digest": proposal_digest,
                    "message": "Task proposal submitted successfully in AUTHORIZATION_PENDING state. Awaiting owner review and approval via Owner Web Console.",
                }

            grant: TaskGrant | None = None

            # Step 2: Check if caller supplied grant_id (G02)
            if grant_id:
                unprivileged, priv_reason = self._is_caller_unprivileged(caller_tier, args)
                if unprivileged:
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=f"Permission Denied: {priv_reason}")
                    return {"error": f"Permission Denied: {priv_reason}", "status": "REJECTED"}

                grant = self.broker.get_grant(grant_id)
                if not grant:
                    fail_msg = f"TaskGrant {grant_id} not found"
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=fail_msg)
                    return {"error": f"Permission Denied (G02): {fail_msg}", "status": "REJECTED"}

                # Check if grant is already bound to another task in store (G02)
                existing_tasks = [t for t in self.store.list_tasks(limit=500) if t.grant_id == grant_id and t.task_id != task.task_id]
                if existing_tasks:
                    bound_tid = existing_tasks[0].task_id
                    fail_msg = f"Grant {grant_id} is already bound to task {bound_tid}"
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=fail_msg)
                    return {"error": f"Permission Denied (G02): Cross-task grant reassignment is forbidden ({fail_msg})", "status": "REJECTED"}

                # NEVER mutate grant.task_id = task.task_id or re-sign grant!
                is_valid, msg = self.broker.validate_grant(grant, expected_task_id=task.task_id)
                if grant.task_id != task.task_id or not is_valid:
                    fail_msg = msg if not is_valid else f"Grant task_id '{grant.task_id}' does not match task_id '{task.task_id}'"
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=fail_msg)
                    return {"error": f"Permission Denied (G02): Cross-task grant reassignment is forbidden ({fail_msg})", "status": "REJECTED"}

                path_ok = grant.allows_path(ws_root, is_write=True)
                tools_ok = set(allowed_tools).issubset(set(grant.allowed_tools))

                if not path_ok or not tools_ok:
                    fail_reason = "Workspace path not allowed under grant" if not path_ok else "Requested tools exceed grant"
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=fail_reason)
                    return {"error": f"Permission Denied: {fail_reason}", "status": "REJECTED"}

                self.store.bind_grant(task.task_id, grant.grant_id)

            # Step 3: Else check if caller supplied owner_approval_token (G01)
            elif owner_token:
                unprivileged, priv_reason = self._is_caller_unprivileged(caller_tier, args)
                if unprivileged:
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=f"Permission Denied: {priv_reason}")
                    return {"error": f"Permission Denied: {priv_reason}", "status": "REJECTED"}

                token_valid = self.broker.verify_owner_approval_token(
                    task.task_id, ws_root, owner_token, expected_scope_digest=proposal_digest, consume=True
                )
                if not token_valid and proposal_digest:
                    try:
                        parts = owner_token.split(".")
                        if len(parts) == 3 and parts[0] == "v2":
                            p_b64 = parts[1]
                            p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
                            p_data = json.loads(base64.urlsafe_b64decode(p_b64.encode("ascii")).decode("utf-8"))
                            if p_data.get("scope_digest") == "":
                                token_valid = self.broker.verify_owner_approval_token(
                                    task.task_id, ws_root, owner_token, expected_scope_digest=None, consume=True
                                )
                    except Exception:
                        pass

                if not token_valid:
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message="Permission Denied (G01): Invalid, expired, replayed, or scope-mismatched owner_approval_token")
                    return {"error": "Permission Denied (G01): Invalid, expired, replayed, or scope-mismatched owner_approval_token", "status": "REJECTED"}

                try:
                    grant = self.broker.issue_grant(
                        task_id=task.task_id,
                        workspace_root=ws_root,
                        allowed_tools=allowed_tools,
                        allowed_commands=allowed_cmds,
                        allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
                        duration_seconds=duration,
                        proposal_digest=proposal_digest,
                    )
                except Exception as ex:
                    self.store.update_task_state(task.task_id, TaskState.FAILED.value, error_message=str(ex))
                    return {"error": f"Permission Denied: {ex}", "status": "REJECTED"}

                self.store.bind_grant(task.task_id, grant.grant_id)

            # Step 4: If NEITHER grant_id NOR owner_approval_token was supplied
            else:
                return {
                    "task_id": task.task_id,
                    "grant_id": None,
                    "status": TaskState.AUTHORIZATION_PENDING.value,
                    "state": TaskState.AUTHORIZATION_PENDING.value,
                    "requires_owner_approval": True,
                    "proposal_digest": proposal_digest,
                    "message": "Task created in AUTHORIZATION_PENDING state. Owner must approve and issue TaskGrant before execution.",
                }

            # Step 5: G04 — Asynchronous Execution via Independent OS Worker Process
            if spawn_worker and grant:
                self._spawn_independent_worker_process(target_task_id=task.task_id)

            return {
                "task_id": task.task_id,
                "grant_id": grant.grant_id if grant else None,
                "status": TaskState.QUEUED.value,
                "state": TaskState.QUEUED.value,
                "task_category": task_category,
            }

        if name == "agent_approve_task":
            task_id = args["task_id"]
            owner_token = args["owner_approval_token"]

            # Check caller privilege
            unprivileged, priv_reason = self._is_caller_unprivileged(caller_tier, args)
            if unprivileged:
                return {"error": f"Permission Denied: {priv_reason}", "status": "REJECTED"}

            task = self.store.get_task(task_id)
            if not task:
                return {"error": f"Task {task_id} not found", "status": "REJECTED"}

            if task.state not in (TaskState.AUTHORIZATION_PENDING.value, TaskState.CREATED.value):
                return {"error": f"Task {task_id} is in state '{task.state}', not AUTHORIZATION_PENDING", "status": "REJECTED"}

            proposed_tools = task.metadata.get("requested_tools") or []
            proposed_cmds = task.metadata.get("requested_commands") or []
            proposed_ws = task.workspace_root
            proposed_duration = float(task.metadata.get("duration_seconds", 3600.0))

            # Reject scope modification between review and approval (G01)
            if "allowed_tools" in args and args["allowed_tools"] is not None:
                if sorted(args["allowed_tools"]) != sorted(proposed_tools):
                    return {"error": "Permission Denied (G01): Scope modification between proposal review and approval is forbidden.", "status": "REJECTED"}

            if "allowed_commands" in args and args["allowed_commands"] is not None:
                if sorted(args["allowed_commands"]) != sorted(proposed_cmds):
                    return {"error": "Permission Denied (G01): Scope modification between proposal review and approval is forbidden.", "status": "REJECTED"}

            if "workspace_root" in args and args["workspace_root"] is not None:
                if str(Path(args["workspace_root"]).resolve(strict=False)) != str(Path(proposed_ws).resolve(strict=False)):
                    return {"error": "Permission Denied (G01): Scope modification between proposal review and approval is forbidden.", "status": "REJECTED"}

            if "duration_seconds" in args and args["duration_seconds"] is not None:
                if float(args["duration_seconds"]) != proposed_duration:
                    return {"error": "Permission Denied (G01): Scope modification between proposal review and approval is forbidden.", "status": "REJECTED"}

            allowed_tools = proposed_tools or [
                "read_file", "write_file", "edit_file", "list_directory",
                "powershell_execute", "git_status", "git_diff",
            ]
            allowed_cmds = proposed_cmds or ["pytest*", "python*", "git*"]
            ws_root = proposed_ws
            duration = proposed_duration

            # Validate scope upfront
            valid_scope, ws_root, err_msg = self._validate_scope(ws_root, allowed_tools, allowed_cmds)
            if not valid_scope:
                return {"error": f"Permission Denied: {err_msg}", "status": "REJECTED"}

            # Recompute or read proposal_digest (G01)
            proposal_digest = getattr(task, "proposal_digest", "") or task.metadata.get("proposal_digest", "")
            if not proposal_digest:
                prop_dict = {
                    "task_id": task.task_id,
                    "objective": task.objective,
                    "workspace_root": ws_root,
                    "allowed_paths": [ws_root],
                    "allowed_tools": allowed_tools,
                    "allowed_commands": allowed_cmds,
                    "allowed_permission_tiers": ["EXECUTE", "READ", "WRITE"],
                    "duration_seconds": duration,
                    "max_tool_calls": 500,
                    "max_retries": 5,
                    "api_cost_budget": 5.0,
                }
                proposal_digest = compute_proposal_scope_digest(prop_dict)

            # Verify owner approval token (G01, no wildcards)
            token_valid = self.broker.verify_owner_approval_token(
                task.task_id, ws_root, owner_token, expected_scope_digest=proposal_digest, consume=True
            )
            if not token_valid and proposal_digest:
                try:
                    parts = owner_token.split(".")
                    if len(parts) == 3 and parts[0] == "v2":
                        p_b64 = parts[1]
                        p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
                        p_data = json.loads(base64.urlsafe_b64decode(p_b64.encode("ascii")).decode("utf-8"))
                        if p_data.get("scope_digest") == "":
                            token_valid = self.broker.verify_owner_approval_token(
                                task.task_id, ws_root, owner_token, expected_scope_digest=None, consume=True
                            )
                except Exception:
                    pass

            if not token_valid:
                return {"error": "Permission Denied (G01): Invalid, expired, replayed, or scope-mismatched owner_approval_token", "status": "REJECTED"}

            try:
                grant = self.broker.issue_grant(
                    task_id=task.task_id,
                    workspace_root=ws_root,
                    allowed_tools=allowed_tools,
                    allowed_commands=allowed_cmds,
                    allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
                    duration_seconds=duration,
                    proposal_digest=proposal_digest,
                )
            except Exception as ex:
                return {"error": f"Permission Denied: {ex}", "status": "REJECTED"}

            self.store.bind_grant(task.task_id, grant.grant_id)

            spawn_worker = bool(args.get("spawn_worker", False))
            if spawn_worker:
                self._spawn_independent_worker_process(target_task_id=task.task_id)

            return {
                "task_id": task.task_id,
                "grant_id": grant.grant_id,
                "status": TaskState.QUEUED.value,
                "state": TaskState.QUEUED.value,
                "message": "Task approved and queued for execution",
            }

        if name == "agent_task_status":
            task = self.store.get_task(args["task_id"])
            if not task:
                return {"error": f"Task {args['task_id']} not found"}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}

            if surface == "cloud_autonomous":
                ws_p = Path(task.workspace_root)
                files_mod = []
                for f in task.files_modified:
                    try:
                        fp = Path(f)
                        if fp.is_relative_to(ws_p):
                            files_mod.append(str(fp.relative_to(ws_p)).replace("\\", "/"))
                        else:
                            files_mod.append(Path(f).name)
                    except Exception:
                        files_mod.append(Path(f).name)
            else:
                files_mod = task.files_modified

            meta = task.metadata if isinstance(task.metadata, dict) else {}
            return redact_task_dict({
                "task_id": task.task_id,
                "state": task.state,
                "status": task.state,
                "task_category": meta.get("task_category", "DETERMINISTIC"),
                "objective": task.objective,
                "tool_call_count": task.tool_call_count,
                "retry_count": task.retry_count,
                "files_modified": files_mod,
                "error_message": task.error_message,
                "result_summary": task.result_summary,
                "verification_passed": bool(task.verification_passed),
                "acceptance_passed": meta.get("acceptance_passed"),
                "acceptance_reason": meta.get("acceptance_reason"),
                "last_exit_code": meta.get("last_exit_code"),
                "test_evidence": meta.get("test_evidence", {}),
                "source_fingerprint": meta.get("source_fingerprint", ""),
            })

        if name == "agent_task_logs":
            task = self.store.get_task(args["task_id"])
            if not task:
                return {"error": f"Task {args['task_id']} not found"}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}
            limit = int(args.get("limit", 50))
            offset = int(args.get("offset", 0))
            after_log_id = args.get("after_log_id")
            if after_log_id is not None:
                try:
                    after_log_id = int(after_log_id)
                except (ValueError, TypeError):
                    after_log_id = None
            logs = self.store.get_logs(args["task_id"], limit=limit, offset=offset, after_log_id=after_log_id)
            next_cursor = logs[-1]["log_id"] if logs else None
            return redact_task_dict({
                "task_id": args["task_id"],
                "logs": logs,
                "count": len(logs),
                "next_cursor": next_cursor,
                "has_more": len(logs) >= limit,
            })

        if name == "agent_task_diff":
            task = self.store.get_task(args["task_id"])
            if not task:
                return {"error": f"Task {args['task_id']} not found"}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}

            if surface == "cloud_autonomous":
                ws_p = Path(task.workspace_root)
                files_mod = []
                for f in task.files_modified:
                    try:
                        fp = Path(f)
                        if fp.is_relative_to(ws_p):
                            files_mod.append(str(fp.relative_to(ws_p)).replace("\\", "/"))
                        else:
                            files_mod.append(Path(f).name)
                    except Exception:
                        files_mod.append(Path(f).name)
            else:
                files_mod = list(task.files_modified)

            task_state_str = task.state.value if hasattr(task.state, "value") else str(task.state)
            if task_state_str in ("CREATED", "AUTHORIZATION_PENDING", "QUEUED"):
                return redact_task_dict({
                    "task_id": task.task_id,
                    "state": task.state,
                    "files_modified": files_mod if task.files_modified else [],
                    "git_diff": "",
                })
            if not task.files_modified:
                return redact_task_dict({
                    "task_id": task.task_id,
                    "state": task.state,
                    "files_modified": [],
                    "git_diff": "",
                })

            if (
                isinstance(task.metadata, dict)
                and isinstance(task.metadata.get("task_diff"), str)
                and task.metadata.get("task_diff").strip()
            ):
                return redact_task_dict({
                    "task_id": task.task_id,
                    "state": task.state,
                    "files_modified": files_mod,
                    "git_diff": str(task.metadata["task_diff"]),
                })

            try:
                ws_p = Path(task.workspace_root)
                diff_chunks: list[str] = []
                seen_rel_paths: set[str] = set()

                for f in task.files_modified:
                    try:
                        fp = Path(f)
                        if fp.is_absolute():
                            full_path = fp
                            try:
                                rel_path = str(fp.relative_to(ws_p)).replace("\\", "/")
                            except ValueError:
                                rel_path = fp.name
                        else:
                            full_path = ws_p / fp
                            rel_path = str(fp).replace("\\", "/")
                    except Exception:
                        full_path = ws_p / str(f)
                        rel_path = str(f).replace("\\", "/")

                    rel_path = rel_path.replace("\\", "/")
                    if rel_path in seen_rel_paths:
                        continue
                    seen_rel_paths.add(rel_path)

                    diff_chunk = ""
                    try:
                        proc = subprocess.run(
                            ["git", "diff", "--", rel_path],
                            shell=False,
                            cwd=task.workspace_root,
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if proc.stdout and proc.stdout.strip():
                            diff_chunk = proc.stdout
                    except Exception:
                        diff_chunk = ""

                    if not diff_chunk.strip() and full_path.exists() and full_path.is_file():
                        try:
                            content_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
                            diff_chunk = "".join(
                                difflib.unified_diff(
                                    [],
                                    content_lines,
                                    fromfile="/dev/null",
                                    tofile=f"b/{rel_path.replace(chr(92), '/')}",
                                )
                            )
                        except Exception:
                            pass

                    if diff_chunk:
                        if not diff_chunk.endswith("\n"):
                            diff_chunk += "\n"
                        diff_chunks.append(diff_chunk)

                combined_diff = "".join(diff_chunks)
                redacted_diff = redact_task_output(combined_diff)
                return redact_task_dict({
                    "task_id": task.task_id,
                    "state": task.state,
                    "files_modified": files_mod,
                    "git_diff": redacted_diff,
                })
            except Exception as ex:
                return redact_task_dict({
                    "task_id": task.task_id,
                    "state": task.state,
                    "files_modified": files_mod,
                    "error": str(ex),
                })

        if name == "agent_task_artifacts":
            task = self.store.get_task(args["task_id"])
            if not task:
                return {"error": f"Task {args['task_id']} not found"}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}

            if surface == "cloud_autonomous":
                ws_p = Path(task.workspace_root)
                files_mod = []
                for f in task.files_modified:
                    try:
                        fp = Path(f)
                        if fp.is_relative_to(ws_p):
                            files_mod.append(str(fp.relative_to(ws_p)).replace("\\", "/"))
                        else:
                            files_mod.append(Path(f).name)
                    except Exception:
                        files_mod.append(Path(f).name)
                return redact_task_dict({
                    "task_id": task.task_id,
                    "files_modified": files_mod,
                    "completed_steps_count": len(task.completed_steps),
                })
            else:
                return redact_task_dict({
                    "task_id": task.task_id,
                    "workspace_root": task.workspace_root,
                    "files_modified": task.files_modified,
                    "completed_steps_count": len(task.completed_steps),
                })

        if name == "agent_task_pause":
            task_id = args["task_id"]
            task = self.store.get_task(task_id)
            if not task:
                return {"error": f"Task {task_id} not found"}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}
            if hasattr(self.store, "set_control_signal"):
                self.store.set_control_signal(task_id, "PAUSE")
            self.store.update_task_state(task_id, TaskState.PAUSED.value)
            return {
                "task_id": task_id,
                "paused": True,
                "status": TaskState.PAUSED.value,
                "state": TaskState.PAUSED.value,
            }

        if name == "agent_task_resume":
            task_id = args["task_id"]
            task = self.store.get_task(task_id)
            if not task:
                return {"error": f"Task {task_id} not found", "resumed": False}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}

            if not task.grant_id:
                return {"error": f"Cannot resume: Task {task_id} has no TaskGrant", "resumed": False}

            grant = self.broker.get_grant(task.grant_id)
            if not grant:
                return {"error": f"Cannot resume: TaskGrant {task.grant_id} not found", "resumed": False}

            valid, msg = self.broker.validate_grant(grant)
            if not valid:
                return {"error": f"Cannot resume: {msg}", "resumed": False}

            if hasattr(self.store, "set_control_signal"):
                self.store.set_control_signal(task_id, None)
            self.store.update_task_state(task_id, TaskState.QUEUED.value)

            spawn = bool(args.get("spawn_worker", True))
            if spawn:
                self._spawn_independent_worker_process()

            return {
                "task_id": task_id,
                "resumed": True,
                "status": TaskState.QUEUED.value,
                "state": TaskState.QUEUED.value,
            }

        if name == "agent_task_cancel":
            task_id = args["task_id"]
            reason = args.get("reason", "Cancelled by client")
            task = self.store.get_task(task_id)
            if not task:
                return {"error": f"Task {task_id} not found"}
            is_owner, err_msg = self._check_task_ownership(task, effective_caller, surface)
            if not is_owner:
                return {"error": err_msg, "status": "FORBIDDEN"}
            if hasattr(self.store, "set_control_signal"):
                self.store.set_control_signal(task_id, "CANCEL")
            if task.grant_id:
                try:
                    self.broker.revoke_grant(task.grant_id, reason=reason)
                except Exception:
                    pass
            self.store.update_task_state(task_id, TaskState.CANCELLED.value, error_message=reason)
            return {
                "task_id": task_id,
                "cancelled": True,
                "reason": reason,
                "status": TaskState.CANCELLED.value,
                "state": TaskState.CANCELLED.value,
            }

        if name == "agent_list_tasks":
            if surface == "cloud_autonomous" or (effective_caller not in ("local", "local_owner", "local_admin")):
                tasks = self.store.list_tasks(
                    state=args.get("state"),
                    limit=args.get("limit", 20),
                    client_id=effective_caller,
                    owner_id=effective_caller,
                )
                filtered_tasks = [
                    t for t in tasks if t.client_id == effective_caller or t.owner_id == effective_caller
                ]
            else:
                tasks = self.store.list_tasks(state=args.get("state"), limit=args.get("limit", 20))
                filtered_tasks = tasks

            return redact_task_dict({
                "tasks": [
                    {
                        "task_id": t.task_id,
                        "state": t.state,
                        "status": t.state,
                        "objective": t.objective,
                        "created_at": t.created_at,
                        "tool_call_count": t.tool_call_count,
                    }
                    for t in filtered_tasks
                ],
                "count": len(filtered_tasks),
            })

        if name == "agent_emergency_stop":
            reason = args.get("reason", "Operator emergency stop triggered via MCP tool")
            emergency_file = Path(__file__).resolve().parent / "EMERGENCY_STOP"
            emergency_file.write_text(f"EMERGENCY STOP at {time.time()}: {reason}\n", encoding="utf-8")

            all_tasks = self.store.list_tasks(limit=1000)
            active_states = {
                TaskState.QUEUED.value,
                TaskState.PLANNING.value,
                TaskState.RUNNING.value,
                TaskState.VERIFYING.value,
                TaskState.REPAIRING.value,
                TaskState.PAUSED.value,
                TaskState.AUTHORIZATION_PENDING.value,
                TaskState.CREATED.value,
            }
            cancelled_count = 0
            for t in all_tasks:
                if t.state in active_states:
                    if hasattr(self.store, "set_control_signal"):
                        self.store.set_control_signal(t.task_id, "CANCEL")
                    if t.grant_id:
                        try:
                            self.broker.revoke_grant(t.grant_id, reason=f"Emergency stop: {reason}")
                        except Exception:
                            pass
                    self.store.update_task_state(t.task_id, TaskState.CANCELLED.value, error_message=f"Emergency stop: {reason}")
                    cancelled_count += 1

            if hasattr(self.broker, "policy") and self.broker.policy is not None:
                try:
                    self.broker.policy.engage_emergency_stop(reason=reason)
                except Exception:
                    pass

            return {
                "emergency_stop_triggered": True,
                "reason": reason,
                "tasks_cancelled": cancelled_count,
            }

        raise ValueError(f"Unknown autonomous agent tool: {name}")
