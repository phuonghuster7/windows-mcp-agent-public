"""Test suite for Agent C: Verifier Barrier & Race Condition Hardening (Audit 28D9ED5).

Verifies:
1. Rejection of fake exit 0 pass banner without genuine JUnit XML evidence.
2. Rejection when workspace source files are modified during test execution.
3. Rejection when workspace source files are modified after passing verification without re-running tests.
4. Acceptance when test passes cleanly and source remains byte-for-byte consistent.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for p in (PROJECT_ROOT, PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pytest

from policy import GatewayPolicy
from runtime.autonomous_agent import AutonomousAgentController
from runtime.contracts import RuntimeStatePaths
from runtime.task_grant import TaskGrant, TaskGrantBroker
from runtime.task_store import TaskStore


def test_verifier_rejects_fake_exit0_pass_banner():
    """Verify fake exit 0 output ('=== 100 passed ===') without JUnit XML does not grant verification pass."""
    td = tempfile.mkdtemp(prefix="test_fake_banner_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        store = TaskStore(db_path=paths.tasks_db_path)
        policy = GatewayPolicy(profile="owner_full_control", emergency_stop_file=paths.emergency_stop_file)
        broker = TaskGrantBroker(policy=policy, db_path=paths.tasks_db_path)

        task = store.create_task(
            objective="Fake banner attack test: min_total_tests: 10",
            workspace_root=td,
            owner_id="local_owner",
        )
        executor = AutonomousAgentController(
            task_id=task.task_id,
            store=store,
            broker=broker,
            policy=policy,
            runtime_paths=paths,
        )

        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=td,
            allowed_tools=["powershell_execute", "python_execute"],
            allowed_commands=["python", "pytest"],
            allowed_permission_tiers=["WRITE", "EXECUTE"],
        )

        # Run a script that outputs fake pytest banner with exit code 0
        fake_script = Path(td) / "fake_test.py"
        fake_script.write_text("print('============================== 100 passed in 0.05s ==============================')", encoding="utf-8")

        ok, res, err = executor._run_structured_process(
            argv=["python", str(fake_script)],
            cwd=td,
            timeout=10,
            grant=grant,
            is_test=True,
        )

        assert ok is True
        # Verification MUST be False because no genuine JUnit XML was produced
        assert executor._verification_passed is False

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_verifier_barrier_detects_source_modification_during_test():
    """Verify that source files changed during test execution barrier invalidate acceptance."""
    td = tempfile.mkdtemp(prefix="test_race_barrier_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        store = TaskStore(db_path=paths.tasks_db_path)
        policy = GatewayPolicy(profile="owner_full_control", emergency_stop_file=paths.emergency_stop_file)
        broker = TaskGrantBroker(policy=policy, db_path=paths.tasks_db_path)

        task = store.create_task(
            objective="Race barrier test: min_total_tests: 1",
            workspace_root=td,
            owner_id="local_owner",
        )
        executor = AutonomousAgentController(
            task_id=task.task_id,
            store=store,
            broker=broker,
            policy=policy,
            runtime_paths=paths,
        )

        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=td,
            allowed_tools=["powershell_execute", "python_execute"],
            allowed_commands=["python", "pytest"],
            allowed_permission_tiers=["WRITE", "EXECUTE"],
        )

        canary_src = Path(td) / "module.py"
        canary_src.write_text("def add(a, b): return a + b\n", encoding="utf-8")

        # Test script that passes but concurrently modifies module.py during its run
        test_file = Path(td) / "test_module.py"
        test_file.write_text(
            "import time\n"
            "from pathlib import Path\n"
            "def test_during_run():\n"
            "    time.sleep(0.3)\n"
            "    Path('module.py').write_text('def add(a, b): return a * b\\n', encoding='utf-8')\n"
            "    assert True\n",
            encoding="utf-8",
        )

        ok, res, err = executor._run_structured_process(
            argv=["pytest", str(test_file)],
            cwd=td,
            timeout=15,
            grant=grant,
            is_test=True,
        )

        # Even though pytest returned 0 and generated XML, source fingerprint changed during run
        assert executor._verification_passed is False

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_deliverable_check_rejects_source_mutation_after_pass():
    """Verify that source modified after a passing verification run is caught before completion."""
    td = tempfile.mkdtemp(prefix="test_post_verify_")
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        store = TaskStore(db_path=paths.tasks_db_path)
        policy = GatewayPolicy(profile="owner_full_control", emergency_stop_file=paths.emergency_stop_file)
        broker = TaskGrantBroker(policy=policy, db_path=paths.tasks_db_path)

        task = store.create_task(
            objective="Post verify test: min_total_tests: 1, required_files_to_exist: [calc.py]",
            workspace_root=td,
            owner_id="local_owner",
        )
        executor = AutonomousAgentController(
            task_id=task.task_id,
            store=store,
            broker=broker,
            policy=policy,
            runtime_paths=paths,
        )

        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=td,
            allowed_tools=["powershell_execute", "python_execute"],
            allowed_commands=["python", "pytest"],
            allowed_permission_tiers=["WRITE", "EXECUTE"],
        )

        calc_file = Path(td) / "calc.py"
        calc_file.write_text("def mul(a, b): return a * b\n", encoding="utf-8")

        test_file = Path(td) / "test_calc.py"
        test_file.write_text("from calc import mul\ndef test_mul(): assert mul(2, 3) == 6\n", encoding="utf-8")

        # 1. Genuine clean test execution -> passes verification
        ok, res, err = executor._run_structured_process(
            argv=["pytest", str(test_file)],
            cwd=td,
            timeout=15,
            grant=grant,
            is_test=True,
        )
        assert ok is True
        assert executor._verification_passed is True

        # 2. Verify deliverables -> OK initially
        ok_init, msg_init = executor._verify_objective_deliverables(
            task,
            workspace_root=td,
            baseline_files={},
            last_pytest_output="1 passed in 0.1s",
        )
        assert ok_init is True

        # 3. Modify source file after passing verification run
        time.sleep(0.05)
        calc_file.write_text("def mul(a, b): return a + b # TAMPERED\n", encoding="utf-8")

        # 4. Objective check must detect source change and reject completion!
        ok_tampered, msg_tampered = executor._verify_objective_deliverables(
            task,
            workspace_root=td,
            baseline_files={},
            last_pytest_output="1 passed in 0.1s",
        )
        assert ok_tampered is False
        assert "Source code was modified after the last passing verification run" in msg_tampered

    finally:
        shutil.rmtree(td, ignore_errors=True)
