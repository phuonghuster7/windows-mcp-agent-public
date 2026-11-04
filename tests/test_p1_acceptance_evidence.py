"""Unit tests verifying P1 Honest Acceptance Evidence, Step Identity, and Pagination."""
from __future__ import annotations

import gc
import json
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
_GW_DIR = str(Path(__file__).resolve().parent.parent / "mcp-gateway")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

import pytest

from policy import GatewayPolicy
from runtime.agent_mcp_tools import AgentMCPToolHandler
from runtime.autonomous_agent import AutonomousAgentController
from runtime.task_grant import TaskGrantBroker
from runtime.task_store import TaskState, TaskStore


def test_step_hash_distinguishes_different_steps_with_same_command():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        store = TaskStore(db_path=ws / "tasks.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy)
        ctrl = AutonomousAgentController("task_test_01", store, broker, policy=policy)

        step_initial = {
            "step_id": "step_1_test",
            "action": "run_tests",
            "tool": "powershell_execute",
            "args": {"command": "pytest -v", "cwd": str(ws)},
        }
        step_final = {
            "step_id": "step_5_verify_test",
            "action": "run_tests",
            "tool": "powershell_execute",
            "args": {"command": "pytest -v", "cwd": str(ws)},
        }

        hash_init = ctrl._compute_step_hash(step_initial, attempt=0)
        hash_final = ctrl._compute_step_hash(step_final, attempt=0)
        hash_retry = ctrl._compute_step_hash(step_final, attempt=1)

        # Hashes must differ because step_id or attempt differs
        assert hash_init != hash_final, "Different step_ids with same args must have different hashes"
        assert hash_final != hash_retry, "Different retry attempts must have different hashes"
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_verification_passed_requires_actual_tests_and_zero_errors():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        store = TaskStore(db_path=ws / "tasks.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy)

        # Case A: Exit 0 but collected 0 items (no tests ran) -> Deliverable gate must reject
        mock_output_zero = "============================= test session starts =============================\ncollected 0 items\n\n============================ no tests ran in 0.01s ============================\n"

        task_with_req = store.create_task(
            objective="Must pass at least 5 tests for feature quote_shipment",
            workspace_root=str(ws),
        )
        ctrl = AutonomousAgentController(task_with_req.task_id, store, broker, policy=policy)
        v_ok_req, reason_req = ctrl._verify_objective_deliverables(
            task=task_with_req,
            workspace_root=str(ws),
            baseline_files={},
            last_pytest_output=mock_output_zero,
        )
        assert not v_ok_req
        assert "no passing tests recorded" in reason_req or "Expected at least" in reason_req
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_log_pagination_with_cursor_and_offset():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        store = TaskStore(db_path=ws / "tasks.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy)
        task = store.create_task(objective="Pagination test", workspace_root=str(ws))

        # Log 15 events
        for i in range(1, 16):
            store.log_event(task.task_id, "ACT", f"Step event {i}", data={"index": i})

        handler = AgentMCPToolHandler(store, broker)

        # Page 1: limit 5
        res1 = handler.execute_tool("agent_task_logs", {"task_id": task.task_id, "limit": 5})
        assert res1["count"] == 5
        assert res1["has_more"] is True
        cursor1 = res1["next_cursor"]
        assert cursor1 is not None

        # Page 2: after cursor
        res2 = handler.execute_tool("agent_task_logs", {"task_id": task.task_id, "limit": 5, "after_log_id": cursor1})
        assert res2["count"] == 5
        assert res2["has_more"] is True
        cursor2 = res2["next_cursor"]
        assert cursor2 > cursor1

        # Page 3: offset
        res3 = handler.execute_tool("agent_task_logs", {"task_id": task.task_id, "limit": 5, "offset": 10})
        assert res3["count"] == 5
        assert res3["logs"][0]["data"]["index"] == 11
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_task_status_returns_acceptance_and_test_evidence():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        store = TaskStore(db_path=ws / "tasks.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy)
        task = store.create_task(objective="Evidence check", workspace_root=str(ws))

        meta = {
            "acceptance_passed": True,
            "acceptance_reason": "All 10 tests passed and deliverables present",
            "last_exit_code": 0,
            "test_evidence": {"passed_count": 10, "failed_count": 0, "exit_code": 0},
            "source_fingerprint": "abc123sha256",
        }
        store.update_task_metadata(task.task_id, meta)

        handler = AgentMCPToolHandler(store, broker)
        status_res = handler.execute_tool("agent_task_status", {"task_id": task.task_id})

        assert status_res["acceptance_passed"] is True
        assert status_res["acceptance_reason"] == "All 10 tests passed and deliverables present"
        assert status_res["last_exit_code"] == 0
        assert status_res["test_evidence"]["passed_count"] == 10
        assert status_res["source_fingerprint"] == "abc123sha256"
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_source_fingerprint_detects_non_python_source_modifications():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        store = TaskStore(db_path=ws / "tasks.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy)
        ctrl = AutonomousAgentController("task_test_fp", store, broker, policy=policy)

        (ws / "package.json").write_text('{"name": "test-pkg", "version": "1.0.0"}', encoding="utf-8")
        (ws / "index.ts").write_text('console.log("hello");', encoding="utf-8")

        fp1 = ctrl._compute_workspace_source_fingerprint(ws)
        assert fp1 is not None and len(fp1) == 64

        # Modify package.json
        (ws / "package.json").write_text('{"name": "test-pkg", "version": "1.0.1"}', encoding="utf-8")
        fp2 = ctrl._compute_workspace_source_fingerprint(ws)
        assert fp1 != fp2, "Fingerprint must change when non-python source/config file is modified"
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)


def test_run_structured_process_anti_cheat_checks():
    td = tempfile.mkdtemp()
    try:
        ws = Path(td)
        store = TaskStore(db_path=ws / "tasks.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker.key", policy=policy, db_path=ws / "tasks.db", preapproved_roots=[ws])
        grant = broker.issue_grant(
            task_id="task_cheat_01",
            workspace_root=ws,
            allowed_tools=["powershell_execute"],
            allowed_commands=["python*"],
            allowed_permission_tiers=["EXECUTE"],
        )
        ctrl = AutonomousAgentController("task_cheat_01", store, broker, policy=policy)

        # 1. Output prints "100 passed" but exits with code 1 (failure)
        fake_fail_script = ws / "fake_fail.py"
        fake_fail_script.write_text("import sys; print('=== 100 passed in 0.01s ==='); sys.exit(1)", encoding="utf-8")
        ok, res, msg = ctrl._run_structured_process([sys.executable, str(fake_fail_script)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ok is False
        assert ctrl._verification_passed is False, "Exit code 1 must NOT set _verification_passed to True even if 'passed' in output"

        # 2. Output contains 'collected 0 items' and exit code 0
        zero_items_script = ws / "zero_items.py"
        zero_items_script.write_text("import sys; print('collected 0 items\\n=== no tests ran in 0.01s ==='); sys.exit(0)", encoding="utf-8")
        ok, res, msg = ctrl._run_structured_process([sys.executable, str(zero_items_script)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ctrl._verification_passed is False, "'collected 0 items' must NOT set _verification_passed to True"

        # 3. Legitimate pytest run with passing test
        good_test = ws / "test_good.py"
        good_test.write_text("def test_ok(): assert 1 + 1 == 2", encoding="utf-8")
        ok, res, msg = ctrl._run_structured_process([sys.executable, "-m", "pytest", str(good_test)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ok is True
        assert ctrl._verification_passed is True, "Legitimate passing test must set _verification_passed to True"
        assert ctrl._last_test_evidence["passed_count"] >= 1

        # 4. Output prints fake unanchored "100 passed" with exit code 0 (V03)
        fake_unanchored = ws / "fake_unanchored.py"
        fake_unanchored.write_text("import sys; print('My program processed 100 passed items in queue'); sys.exit(0)", encoding="utf-8")
        ok, res, msg = ctrl._run_structured_process([sys.executable, str(fake_unanchored)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ctrl._verification_passed is False, "Unanchored fake output string with exit 0 must NOT set _verification_passed to True"

        # 5. Output prints EXACT anchored banner "=== 100 passed in 0.01s ===" with exit code 0 (R1 root-cause regression)
        fake_anchored_exit0 = ws / "fake_anchored_exit0.py"
        fake_anchored_exit0.write_text("import sys; print('=== 100 passed in 0.01s ==='); sys.exit(0)", encoding="utf-8")
        ok, res, msg = ctrl._run_structured_process([sys.executable, str(fake_anchored_exit0)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ctrl._verification_passed is False, "Script exit0 with anchored '=== 100 passed in 0.01s ===' without JUnit report must NOT set _verification_passed to True"

        # 6. Pytest quiet mode positive control (-q)
        ok, res, msg = ctrl._run_structured_process([sys.executable, "-m", "pytest", "-q", str(good_test)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ok is True
        assert ctrl._verification_passed is True, "Pytest in quiet mode (-q) must be accepted via genuine JUnit report"
        assert ctrl._last_test_evidence["passed_count"] >= 1
        assert ctrl._last_test_evidence["report_path"] is not None
        assert Path(ctrl._last_test_evidence["report_path"]).exists()

        # 7. Pytest with collection error / bad syntax must fail acceptance
        bad_syntax_test = ws / "test_bad_syntax.py"
        bad_syntax_test.write_text("def test_syntax_err( This is broken python syntax", encoding="utf-8")
        ok, res, msg = ctrl._run_structured_process([sys.executable, "-m", "pytest", str(bad_syntax_test)], cwd=str(ws), timeout=15.0, grant=grant, is_test=True)
        assert ok is False
        assert ctrl._verification_passed is False, "Collection/syntax error must NOT set _verification_passed to True"
    finally:
        gc.collect()
        shutil.rmtree(td, ignore_errors=True)

