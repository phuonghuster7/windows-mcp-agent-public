"""Durable SQLite State Store & Checkpoint Manager for Autonomous Agent Runtime.

Provides transactional job claiming, step idempotency, audit trail persistence,
and checkpoint save/restore surviving process restarts and browser disconnects.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


def is_pid_alive(pid: int | None) -> bool:
    """Check if process with given PID is currently running."""
    if pid is None or pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == STILL_ACTIVE
                return False
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


class TaskState(str, Enum):
    CREATED = "CREATED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    QUEUED = "QUEUED"
    PLANNING = "PLANNING"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    REPAIRING = "REPAIRING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


class ExecutionMode(str, Enum):
    MANUAL = "MANUAL"
    TRUSTED_TASK = "TRUSTED_TASK"
    UNATTENDED_WORKER = "UNATTENDED_WORKER"


@dataclass
class TaskRecord:
    task_id: str
    objective: str
    workspace_root: str
    mode: str = ExecutionMode.TRUSTED_TASK.value
    state: str = TaskState.CREATED.value
    grant_id: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    retry_count: int = 0
    tool_call_count: int = 0
    current_plan: list[dict[str, Any]] = field(default_factory=list)
    completed_steps: list[dict[str, Any]] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    test_results: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    result_summary: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    worker_pid: int | None = None
    worker_heartbeat_at: float | None = None
    control_signal: str | None = None
    file_write_count: int = 0
    api_cost_usd: float = 0.0
    verification_passed: bool = False
    requested_scope: dict[str, Any] = field(default_factory=dict)
    proposal_digest: str = ""
    owner_id: str = "local_owner"
    client_id: str = "local"


@dataclass
class CheckpointRecord:
    checkpoint_id: str
    task_id: str
    step_index: int
    state: str
    plan_snapshot: list[dict[str, Any]]
    completed_steps: list[dict[str, Any]]
    files_modified: list[str]
    test_results: dict[str, Any]
    created_at: float = field(default_factory=time.time)


class TaskStore:
    """Thread-safe, transaction-isolated SQLite task storage."""

    def __init__(self, db_path: Path | str | None = None):
        if db_path is None:
            state_root = os.getenv("MCP_STATE_ROOT")
            db_path = (Path(state_root) / "tasks.db") if state_root else (Path(__file__).resolve().parent / "tasks.db")
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    state TEXT NOT NULL,
                    grant_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    tool_call_count INTEGER NOT NULL DEFAULT 0,
                    current_plan TEXT,
                    completed_steps TEXT,
                    files_modified TEXT,
                    test_results TEXT,
                    error_message TEXT,
                    result_summary TEXT,
                    metadata TEXT,
                    worker_pid INTEGER,
                    worker_heartbeat_at REAL,
                    control_signal TEXT,
                    file_write_count INTEGER NOT NULL DEFAULT 0,
                    api_cost_usd REAL NOT NULL DEFAULT 0.0,
                    verification_passed INTEGER NOT NULL DEFAULT 0,
                    requested_scope TEXT,
                    proposal_digest TEXT DEFAULT '',
                    owner_id TEXT NOT NULL DEFAULT 'local_owner',
                    client_id TEXT NOT NULL DEFAULT 'local'
                );

                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    plan_snapshot TEXT,
                    completed_steps TEXT,
                    files_modified TEXT,
                    test_results TEXT,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS execution_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    level TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data TEXT,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
                CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON checkpoints(task_id, step_index);
                CREATE INDEX IF NOT EXISTS idx_logs_task ON execution_logs(task_id, timestamp);
            """)

            # Backward compatibility migrations for existing databases
            alter_cols = [
                ("worker_pid", "INTEGER"),
                ("worker_heartbeat_at", "REAL"),
                ("control_signal", "TEXT"),
                ("file_write_count", "INTEGER NOT NULL DEFAULT 0"),
                ("api_cost_usd", "REAL NOT NULL DEFAULT 0.0"),
                ("verification_passed", "INTEGER NOT NULL DEFAULT 0"),
                ("requested_scope", "TEXT"),
                ("proposal_digest", "TEXT DEFAULT ''"),
                ("owner_id", "TEXT NOT NULL DEFAULT 'local_owner'"),
                ("client_id", "TEXT NOT NULL DEFAULT 'local'"),
            ]
            for col_name, col_def in alter_cols:
                try:
                    conn.execute(f"ALTER TABLE tasks ADD COLUMN {col_name} {col_def}")
                except sqlite3.OperationalError:
                    pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_client_owner ON tasks(client_id, owner_id)")

    def create_task(
        self,
        objective: str,
        workspace_root: str | Path,
        mode: str = ExecutionMode.TRUSTED_TASK.value,
        grant_id: str | None = None,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        requested_scope: dict[str, Any] | None = None,
        proposal_digest: str = "",
        owner_id: str = "local_owner",
        client_id: str = "local",
    ) -> TaskRecord:
        tid = task_id or f"task_{uuid.uuid4().hex[:16]}"
        now = time.time()
        ws_canonical = str(Path(workspace_root).resolve(strict=False))
        eff_metadata = metadata or {}
        eff_requested_scope = requested_scope or eff_metadata.get("requested_scope", {})

        if not proposal_digest:
            import hashlib
            digest_payload = {
                "objective": objective.strip(),
                "workspace_root": ws_canonical,
                "requested_scope": eff_requested_scope,
                "metadata": eff_metadata,
            }
            proposal_digest = hashlib.sha256(
                json.dumps(digest_payload, sort_keys=True).encode("utf-8")
            ).hexdigest()

        task = TaskRecord(
            task_id=tid,
            objective=objective,
            workspace_root=ws_canonical,
            mode=mode,
            state=TaskState.CREATED.value if grant_id else TaskState.AUTHORIZATION_PENDING.value,
            grant_id=grant_id,
            created_at=now,
            updated_at=now,
            metadata=eff_metadata,
            requested_scope=eff_requested_scope,
            proposal_digest=proposal_digest,
            owner_id=owner_id,
            client_id=client_id,
        )
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO tasks (
                    task_id, objective, workspace_root, mode, state, grant_id,
                    created_at, updated_at, started_at, completed_at, retry_count,
                    tool_call_count, current_plan, completed_steps, files_modified,
                    test_results, error_message, result_summary, metadata,
                    worker_pid, worker_heartbeat_at, control_signal, file_write_count,
                    api_cost_usd, verification_passed, requested_scope, proposal_digest,
                    owner_id, client_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.objective,
                    task.workspace_root,
                    task.mode,
                    task.state,
                    task.grant_id,
                    task.created_at,
                    task.updated_at,
                    task.started_at,
                    task.completed_at,
                    task.retry_count,
                    task.tool_call_count,
                    json.dumps(task.current_plan),
                    json.dumps(task.completed_steps),
                    json.dumps(task.files_modified),
                    json.dumps(task.test_results),
                    task.error_message,
                    task.result_summary,
                    json.dumps(task.metadata),
                    task.worker_pid,
                    task.worker_heartbeat_at,
                    task.control_signal,
                    task.file_write_count,
                    task.api_cost_usd,
                    1 if task.verification_passed else 0,
                    json.dumps(task.requested_scope),
                    task.proposal_digest,
                    task.owner_id,
                    task.client_id,
                ),
            )
        return task

    def get_task(self, task_id: str) -> TaskRecord | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_task(row)

    def list_tasks(
        self,
        state: str | None = None,
        limit: int = 50,
        owner_id: str | None = None,
        client_id: str | None = None,
    ) -> list[TaskRecord]:
        with self._get_connection() as conn:
            conditions: list[str] = []
            params: list[Any] = []
            if state:
                conditions.append("state = ?")
                params.append(state)

            if client_id and owner_id:
                conditions.append("(client_id = ? OR owner_id = ?)")
                params.extend([client_id, owner_id])
            elif client_id:
                conditions.append("(client_id = ? OR owner_id = ?)")
                params.extend([client_id, client_id])
            elif owner_id:
                conditions.append("(client_id = ? OR owner_id = ?)")
                params.extend([owner_id, owner_id])

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"SELECT * FROM tasks {where_clause} ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            cur = conn.execute(query, params)
            return [self._row_to_task(row) for row in cur.fetchall()]

    def set_control_signal(self, task_id: str, signal: str | None) -> bool:
        """Sets control_signal ('PAUSE', 'CANCEL', 'RESUME', or None) and updates state if applicable."""
        now = time.time()
        with self._get_connection() as conn:
            with conn:
                cur = conn.execute("SELECT state FROM tasks WHERE task_id = ?", (task_id,))
                row = cur.fetchone()
                if not row:
                    return False
                current_state = row["state"]
                new_state = current_state

                if signal == "PAUSE":
                    if current_state == TaskState.QUEUED.value:
                        new_state = TaskState.PAUSED.value
                elif signal == "CANCEL":
                    if current_state in (
                        TaskState.CREATED.value,
                        TaskState.AUTHORIZATION_PENDING.value,
                        TaskState.QUEUED.value,
                        TaskState.PAUSED.value,
                    ):
                        new_state = TaskState.CANCELLED.value
                elif signal == "RESUME":
                    if current_state == TaskState.PAUSED.value:
                        new_state = TaskState.QUEUED.value

                conn.execute(
                    "UPDATE tasks SET control_signal = ?, state = ?, updated_at = ? WHERE task_id = ?",
                    (signal, new_state, now, task_id),
                )
                return True

    def heartbeat(self, task_id: str, worker_pid: int | None = None) -> dict[str, Any] | None:
        """Updates worker_heartbeat_at = time.time() and worker_pid for task_id, returns state & signal."""
        now = time.time()
        with self._get_connection() as conn:
            with conn:
                conn.execute(
                    """
                    UPDATE tasks
                    SET worker_heartbeat_at = ?,
                        worker_pid = coalesce(?, worker_pid),
                        updated_at = ?
                    WHERE task_id = ?
                    """,
                    (now, worker_pid, now, task_id),
                )
            cur = conn.execute(
                "SELECT state, control_signal, grant_id FROM tasks WHERE task_id = ?",
                (task_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "state": row["state"],
                "control_signal": row["control_signal"],
                "grant_id": row["grant_id"],
            }

    def reconcile_orphaned_tasks(self, heartbeat_timeout: float = 30.0) -> list[str]:
        """Reconciles orphaned tasks whose worker died or stopped heartbeating."""
        recovered: list[str] = []
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT task_id, worker_pid, worker_heartbeat_at
                FROM tasks
                WHERE state IN ('PLANNING', 'RUNNING', 'VERIFYING', 'REPAIRING')
                """
            )
            active_tasks = cur.fetchall()
            for row in active_tasks:
                tid = row["task_id"]
                w_pid = row["worker_pid"]
                w_hb = row["worker_heartbeat_at"]

                is_orphaned = False
                if w_pid is None:
                    is_orphaned = True
                elif not is_pid_alive(w_pid):
                    is_orphaned = True
                elif w_hb is not None and (now - w_hb > heartbeat_timeout):
                    is_orphaned = True

                if is_orphaned:
                    with conn:
                        conn.execute(
                            """
                            UPDATE tasks
                            SET state = ?, worker_pid = NULL, control_signal = NULL, updated_at = ?
                            WHERE task_id = ?
                            """,
                            (TaskState.QUEUED.value, now, tid),
                        )
                    self.log_event(
                        tid,
                        "RECOVERY",
                        f"Reconciled orphaned task from terminated worker PID {w_pid}; re-queued for checkpoint resumption",
                        level="WARN",
                    )
                    recovered.append(tid)
        return recovered

    def claim_next_queued_task(
        self,
        worker_pid: int | None = None,
        max_concurrent_workers: int = 1,
        target_task_id: str | None = None,
    ) -> TaskRecord | None:
        """Atomically claim next queued task within concurrency limits after reconciling orphans."""
        self.reconcile_orphaned_tasks()
        eff_pid = worker_pid or os.getpid()
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                """
                SELECT COUNT(*) as active_cnt
                FROM tasks
                WHERE state IN ('PLANNING', 'RUNNING', 'VERIFYING', 'REPAIRING')
                """
            )
            active_cnt = cur.fetchone()["active_cnt"]
            if active_cnt >= max_concurrent_workers:
                conn.commit()
                return None

            row = None
            if target_task_id:
                cur = conn.execute(
                    """
                    SELECT task_id
                    FROM tasks
                    WHERE task_id = ? AND state = ? AND (control_signal IS NULL OR control_signal NOT IN ('PAUSE', 'CANCEL'))
                    LIMIT 1
                    """,
                    (target_task_id, TaskState.QUEUED.value),
                )
                row = cur.fetchone()

            if not row:
                cur = conn.execute(
                    """
                    SELECT task_id
                    FROM tasks
                    WHERE state = ? AND (control_signal IS NULL OR control_signal NOT IN ('PAUSE', 'CANCEL'))
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (TaskState.QUEUED.value,),
                )
                row = cur.fetchone()
            if not row:
                conn.commit()
                return None

            task_id = row["task_id"]
            conn.execute(
                """
                UPDATE tasks
                SET state = ?,
                    worker_pid = ?,
                    worker_heartbeat_at = ?,
                    started_at = coalesce(started_at, ?),
                    updated_at = ?
                WHERE task_id = ?
                """,
                (TaskState.PLANNING.value, eff_pid, now, now, now, task_id),
            )
            conn.commit()
            return self.get_task(task_id)

    def bind_grant(self, task_id: str, grant_id: str) -> bool:
        """Bind a TaskGrant to a task record and update its state to QUEUED with G02 cross-task protection."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # G02: Check if grant is already bound to another task in tasks table
                cur = conn.execute(
                    "SELECT task_id FROM tasks WHERE grant_id = ? AND task_id != ?",
                    (grant_id, task_id),
                )
                row = cur.fetchone()
                if row:
                    raise PermissionError(
                        f"Cross-task grant reuse denied (G02): Grant {grant_id} is already bound to task {row['task_id']}"
                    )

                # G02: Check if table task_grants exists in the same SQLite DB
                has_grants_tbl = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='task_grants'"
                ).fetchone()
                if has_grants_tbl:
                    g_cur = conn.execute(
                        "SELECT task_id, revoked FROM task_grants WHERE grant_id = ?",
                        (grant_id,),
                    )
                    g_row = g_cur.fetchone()
                    if g_row:
                        if g_row["task_id"] != task_id:
                            raise PermissionError(
                                f"Cross-task grant reuse denied (G02): Grant {grant_id} was issued for {g_row['task_id']}, not {task_id}"
                            )
                        if g_row["revoked"] == 1:
                            raise PermissionError(f"Cannot bind revoked grant {grant_id}")

                conn.execute(
                    "UPDATE tasks SET grant_id = ?, state = ?, updated_at = ? WHERE task_id = ?",
                    (grant_id, TaskState.QUEUED.value, now, task_id),
                )
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                raise

    def update_task_state(
        self,
        task_id: str,
        state: str,
        error_message: str | None = None,
        result_summary: str | None = None,
    ) -> bool:
        now = time.time()
        is_terminal = state in (
            TaskState.COMPLETED.value,
            TaskState.FAILED.value,
            TaskState.CANCELLED.value,
            TaskState.EXPIRED.value,
        )
        completed_at = now if is_terminal else None
        with self._get_connection() as conn:
            with conn:
                if completed_at:
                    conn.execute(
                        """
                        UPDATE tasks SET state = ?, updated_at = ?, completed_at = ?,
                        worker_pid = NULL,
                        error_message = coalesce(?, error_message), result_summary = coalesce(?, result_summary)
                        WHERE task_id = ?
                        """,
                        (state, now, completed_at, error_message, result_summary, task_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE tasks SET state = ?, updated_at = ?,
                        worker_pid = (CASE WHEN ? IN ('PAUSED', 'QUEUED') THEN NULL ELSE worker_pid END),
                        error_message = coalesce(?, error_message), result_summary = coalesce(?, result_summary)
                        WHERE task_id = ?
                        """,
                        (state, now, state, error_message, result_summary, task_id),
                    )
            return conn.total_changes > 0

    def update_task_progress(
        self,
        task_id: str,
        current_plan: list[dict[str, Any]] | None = None,
        completed_steps: list[dict[str, Any]] | None = None,
        files_modified: list[str] | None = None,
        test_results: dict[str, Any] | None = None,
        tool_call_delta: int = 0,
        retry_delta: int = 0,
        file_write_delta: int = 0,
        api_cost_usd: float | None = None,
        verification_passed: bool | None = None,
    ) -> bool:
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = cur.fetchone()
            if not row:
                return False

            keys = row.keys()
            plan_json = json.dumps(current_plan) if current_plan is not None else row["current_plan"]
            steps_json = json.dumps(completed_steps) if completed_steps is not None else row["completed_steps"]
            files_json = json.dumps(files_modified) if files_modified is not None else row["files_modified"]
            tests_json = json.dumps(test_results) if test_results is not None else row["test_results"]
            new_tool_count = row["tool_call_count"] + tool_call_delta
            new_retry_count = row["retry_count"] + retry_delta

            cur_write_count = row["file_write_count"] if ("file_write_count" in keys and row["file_write_count"] is not None) else 0
            new_write_count = cur_write_count + file_write_delta

            new_api_cost = api_cost_usd if api_cost_usd is not None else (row["api_cost_usd"] if ("api_cost_usd" in keys and row["api_cost_usd"] is not None) else 0.0)
            new_verification = (1 if verification_passed else 0) if verification_passed is not None else (row["verification_passed"] if ("verification_passed" in keys and row["verification_passed"] is not None) else 0)

            with conn:
                conn.execute(
                    """
                    UPDATE tasks SET updated_at = ?, current_plan = ?, completed_steps = ?,
                    files_modified = ?, test_results = ?, tool_call_count = ?, retry_count = ?,
                    file_write_count = ?, api_cost_usd = ?, verification_passed = ?
                    WHERE task_id = ?
                    """,
                    (
                        now,
                        plan_json,
                        steps_json,
                        files_json,
                        tests_json,
                        new_tool_count,
                        new_retry_count,
                        new_write_count,
                        new_api_cost,
                        new_verification,
                        task_id,
                    ),
                )
            return True

    def save_checkpoint(
        self,
        task_id: str,
        step_index: int,
        state: str,
        plan_snapshot: list[dict[str, Any]],
        completed_steps: list[dict[str, Any]],
        files_modified: list[str],
        test_results: dict[str, Any],
    ) -> CheckpointRecord:
        cid = f"chk_{uuid.uuid4().hex[:12]}"
        now = time.time()
        record = CheckpointRecord(
            checkpoint_id=cid,
            task_id=task_id,
            step_index=step_index,
            state=state,
            plan_snapshot=plan_snapshot,
            completed_steps=completed_steps,
            files_modified=files_modified,
            test_results=test_results,
            created_at=now,
        )
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints (
                    checkpoint_id, task_id, step_index, state, plan_snapshot,
                    completed_steps, files_modified, test_results, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.checkpoint_id,
                    record.task_id,
                    record.step_index,
                    record.state,
                    json.dumps(record.plan_snapshot),
                    json.dumps(record.completed_steps),
                    json.dumps(record.files_modified),
                    json.dumps(record.test_results),
                    record.created_at,
                ),
            )
        return record

    def get_latest_checkpoint(self, task_id: str) -> CheckpointRecord | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM checkpoints WHERE task_id = ? ORDER BY step_index DESC, created_at DESC LIMIT 1",
                (task_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return CheckpointRecord(
                checkpoint_id=row["checkpoint_id"],
                task_id=row["task_id"],
                step_index=row["step_index"],
                state=row["state"],
                plan_snapshot=json.loads(row["plan_snapshot"] or "[]"),
                completed_steps=json.loads(row["completed_steps"] or "[]"),
                files_modified=json.loads(row["files_modified"] or "[]"),
                test_results=json.loads(row["test_results"] or "{}"),
                created_at=row["created_at"],
            )

    def log_event(
        self,
        task_id: str,
        phase: str,
        message: str,
        level: str = "INFO",
        data: dict[str, Any] | None = None,
    ) -> None:
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO execution_logs (task_id, timestamp, level, phase, message, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task_id, now, level, phase, message, json.dumps(data or {})),
            )

    def update_task_metadata(self, task_id: str, metadata: dict[str, Any]) -> bool:
        now = time.time()
        meta_json = json.dumps(metadata)
        with self._get_connection() as conn:
            with conn:
                conn.execute(
                    "UPDATE tasks SET metadata = ?, updated_at = ? WHERE task_id = ?",
                    (meta_json, now, task_id),
                )
            return conn.total_changes > 0

    def get_logs(
        self,
        task_id: str,
        limit: int = 100,
        offset: int = 0,
        after_log_id: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            if after_log_id is not None:
                cur = conn.execute(
                    """
                    SELECT * FROM execution_logs
                    WHERE task_id = ? AND log_id > ?
                    ORDER BY log_id ASC LIMIT ?
                    """,
                    (task_id, after_log_id, limit),
                )
            elif offset > 0:
                cur = conn.execute(
                    """
                    SELECT * FROM execution_logs
                    WHERE task_id = ?
                    ORDER BY log_id ASC LIMIT ? OFFSET ?
                    """,
                    (task_id, limit, offset),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM execution_logs WHERE task_id = ? ORDER BY log_id ASC LIMIT ?",
                    (task_id, limit),
                )
            return [
                {
                    "log_id": row["log_id"],
                    "task_id": row["task_id"],
                    "timestamp": row["timestamp"],
                    "level": row["level"],
                    "phase": row["phase"],
                    "message": row["message"],
                    "data": json.loads(row["data"] or "{}"),
                }
                for row in cur.fetchall()
            ]

    def _row_to_task(self, row: sqlite3.Row) -> TaskRecord:
        keys = row.keys()
        return TaskRecord(
            task_id=row["task_id"],
            objective=row["objective"],
            workspace_root=row["workspace_root"],
            mode=row["mode"],
            state=row["state"],
            grant_id=row["grant_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            retry_count=row["retry_count"],
            tool_call_count=row["tool_call_count"],
            current_plan=json.loads(row["current_plan"] or "[]"),
            completed_steps=json.loads(row["completed_steps"] or "[]"),
            files_modified=json.loads(row["files_modified"] or "[]"),
            test_results=json.loads(row["test_results"] or "{}"),
            error_message=row["error_message"],
            result_summary=row["result_summary"],
            metadata=json.loads(row["metadata"] or "{}"),
            worker_pid=row["worker_pid"] if "worker_pid" in keys else None,
            worker_heartbeat_at=row["worker_heartbeat_at"] if "worker_heartbeat_at" in keys else None,
            control_signal=row["control_signal"] if "control_signal" in keys else None,
            file_write_count=row["file_write_count"] if ("file_write_count" in keys and row["file_write_count"] is not None) else 0,
            api_cost_usd=row["api_cost_usd"] if ("api_cost_usd" in keys and row["api_cost_usd"] is not None) else 0.0,
            verification_passed=bool(row["verification_passed"]) if ("verification_passed" in keys and row["verification_passed"] is not None) else False,
            requested_scope=json.loads(row["requested_scope"] or "{}") if ("requested_scope" in keys and row["requested_scope"]) else {},
            proposal_digest=row["proposal_digest"] if ("proposal_digest" in keys and row["proposal_digest"]) else "",
            owner_id=row["owner_id"] if ("owner_id" in keys and row["owner_id"]) else "local_owner",
            client_id=row["client_id"] if ("client_id" in keys and row["client_id"]) else "local",
        )
