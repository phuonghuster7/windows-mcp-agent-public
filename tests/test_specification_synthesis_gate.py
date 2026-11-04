"""Unit and E2E tests for Specification-to-Code Synthesis & Objective Deliverable Gates."""
from __future__ import annotations

import difflib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
_GW_DIR = str(Path(__file__).resolve().parent.parent / "mcp-gateway")
if _GW_DIR not in sys.path:
    sys.path.insert(0, _GW_DIR)

from policy import GatewayPolicy
from runtime.autonomous_agent import AutonomousAgentController
from runtime.llm_adapter import (
    DeterministicRuleBasedAdapter,
    UnsupportedObjectiveError,
    extract_objective_requirements,
)
from runtime.task_grant import TaskGrantBroker
from runtime.task_store import TaskStore, TaskState
from tests.fixtures.shipment_fixture import (
    BenchmarkShipmentPricingAdapter,
    SHIPMENT_PRICING_SOURCE,
    TEST_SHIPMENT_PRICING_SOURCE,
)


BENCHMARK_OBJECTIVE = (
    "INDEPENDENT CHATGPT CLOUD CODING BENCHMARK — implement a NEW feature, not an AST fixture repair. "
    "In this trusted disposable benchmark workspace, CREATE shipment_pricing.py and test_shipment_pricing.py "
    "from scratch (both currently absent); do not modify the existing 4 .py files. "
    "Implement quote_shipment(weight_kg: float, distance_km: float, zone: str, fragile: bool=False) -> dict "
    "returning keys base_fee, distance_fee, surcharge, total, currency. Requirements: reject negative weight/distance "
    "and unknown zone with ValueError; base_fee 20000 VND + 6000 VND per started kg (ceil); distance_fee = 1500 VND "
    "per started km (ceil); zone surcharge fixed: urban=0, suburban=10000, rural=25000; fragile surcharge is "
    "exactly 10% of (base_fee + distance_fee + zone surcharge); total is sum of all fees; currency='VND'; "
    "monetary values ints (round half-up if necessary). Include at least 9 independent pytest tests: zero weight/zero "
    "distance; ceil boundary; three zones; fragile; invalid negative weight/distance; unknown zone; return types/keys. "
    "Run pytest -q across entire benchmark workspace, diagnose and repair until all existing 10 plus new >=9 tests pass. "
    "Inspect git diff, report files created and test count. IMPORTANT: no external APIs, no paid services, no GitHub push, "
    "no source changes outside this benchmark workspace. An existing green pytest run without creating the required files "
    "and implementing functionality is FAILURE, not completion."
)


def test_extract_objective_requirements_benchmark():
    ws_bench = str(Path(__file__).resolve().parent.parent / "benchmarks" / "codex_like_eval")
    reqs = extract_objective_requirements(BENCHMARK_OBJECTIVE, ws_bench)
    assert "shipment_pricing.py" in reqs["required_files_to_create"]
    assert "test_shipment_pricing.py" in reqs["required_files_to_create"]
    assert "quote_shipment" in reqs["required_functions"]
    assert reqs["forbid_modifying_existing_py"] is True
    assert reqs["min_new_tests"] == 9
    assert reqs["min_total_tests"] == 19
    assert reqs["is_new_feature_request"] is True


def test_extract_objective_requirements_defect_repair():
    repair_obj = "Establish defect baseline and repair all test failures in workspace"
    reqs = extract_objective_requirements(repair_obj)
    assert reqs["required_files_to_create"] == []
    assert reqs["required_functions"] == []
    assert reqs["forbid_modifying_existing_py"] is False
    assert reqs["min_new_tests"] == 0
    assert reqs["min_total_tests"] == 0
    assert reqs["is_new_feature_request"] is False


def test_deterministic_synthesize_feature():
    adapter = BenchmarkShipmentPricingAdapter()
    ws_bench = str(Path(__file__).resolve().parent.parent / "benchmarks" / "codex_like_eval")
    reqs = extract_objective_requirements(BENCHMARK_OBJECTIVE, ws_bench)
    synthesized = adapter._synthesize_feature_code_deterministic(BENCHMARK_OBJECTIVE, ws_bench, reqs)
    assert synthesized is not None
    assert len(synthesized) == 2
    paths = [s["path"] for s in synthesized]
    assert any("shipment_pricing.py" in p for p in paths)
    assert any("test_shipment_pricing.py" in p for p in paths)

    # Validate that synthesized tests execute and pass 100%
    with tempfile.TemporaryDirectory() as td:
        for item in synthesized:
            p = Path(td) / Path(item["path"]).name
            p.write_text(item["content"], encoding="utf-8")
        test_file = str(Path(td) / "test_shipment_pricing.py")
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-o", f"rootdir={td}", test_file],
            cwd=td,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert "11 passed" in proc.stdout


def test_autonomous_shipment_pricing_e2e_benchmark():
    bench_orig = Path(__file__).resolve().parent.parent / "benchmarks" / "codex_like_eval"
    td = tempfile.mkdtemp()
    try:
        ws = Path(td) / "ws"
        shutil.copytree(bench_orig, ws)
        for _fn in ("shipment_pricing.py", "test_shipment_pricing.py"):
            if (ws / _fn).exists():
                (ws / _fn).unlink()

        db_path = ws / "tasks_test.db"
        key_path = ws / "broker_test.key"
        store = TaskStore(db_path=db_path)
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=key_path, policy=policy, db_path=ws / "grants_test.db", preapproved_roots=[ws])

        task = store.create_task(objective=BENCHMARK_OBJECTIVE, workspace_root=str(ws))
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=str(ws),
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory", "git_status", "git_diff"],
            allowed_commands=["pytest*", "python*", "git*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)

        ctrl = AutonomousAgentController(
            task.task_id,
            store,
            broker,
            policy=policy,
            llm_adapter=BenchmarkShipmentPricingAdapter(),
        )
        final_task = ctrl.run()

        assert final_task.state == TaskState.COMPLETED.value
        assert final_task.error_message is None
        assert (ws / "shipment_pricing.py").exists()
        assert (ws / "test_shipment_pricing.py").exists()
        assert len(final_task.files_modified) >= 2

        # Check git-style unified diff in task.metadata["task_diff"]
        diff_str = final_task.metadata.get("task_diff", "")
        assert "--- /dev/null" in diff_str
        assert "+++ b/shipment_pricing.py" in diff_str
        assert "+++ b/test_shipment_pricing.py" in diff_str
        assert "quote_shipment" in diff_str

        # Confirm all 21 tests pass across the entire workspace (10 original + 11 new >= 19)
        proc = subprocess.run([sys.executable, "-m", "pytest", "-q", str(ws)], capture_output=True, text=True)
        assert proc.returncode == 0
        assert "21 passed" in proc.stdout
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_unsupported_objective_fail_closed():
    bench_orig = Path(__file__).resolve().parent.parent / "benchmarks" / "codex_like_eval"
    td = tempfile.mkdtemp()
    try:
        ws = Path(td) / "ws"
        shutil.copytree(bench_orig, ws)
        for _fn in ("shipment_pricing.py", "test_shipment_pricing.py"):
            if (ws / _fn).exists():
                (ws / _fn).unlink()

        store = TaskStore(db_path=ws / "tasks_test.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker_test.key", policy=policy, db_path=ws / "grants_test.db", preapproved_roots=[ws])

        unsupported_obj = "INDEPENDENT CHATGPT BENCHMARK — CREATE custom_algo.py from scratch with solve_tsp()."
        task = store.create_task(objective=unsupported_obj, workspace_root=str(ws))
        grant = broker.issue_grant(
            task_id=task.task_id,
            workspace_root=str(ws),
            allowed_tools=["read_file", "write_file", "powershell_execute", "list_directory"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        store.bind_grant(task.task_id, grant.grant_id)

        ctrl = AutonomousAgentController(
            task.task_id,
            store,
            broker,
            policy=policy,
        )
        final_task = ctrl.run()

        assert final_task.state == TaskState.FAILED.value
        assert "MODEL_PROVIDER_NOT_CONFIGURED" in (final_task.error_message or "") or "UNSUPPORTED_OBJECTIVE" in (final_task.error_message or "")

        # Check planner_gate trace event
        logs = store.get_logs(task.task_id)
        planner_gate_logs = [log for log in logs if "MODEL_PROVIDER_NOT_CONFIGURED" in str(log.get("data", {})) or "UNSUPPORTED_OBJECTIVE" in str(log.get("data", {}))]
        assert len(planner_gate_logs) >= 1
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_deliverable_verification_failures():
    bench_orig = Path(__file__).resolve().parent.parent / "benchmarks" / "codex_like_eval"
    td = tempfile.mkdtemp()
    try:
        ws = Path(td) / "ws"
        shutil.copytree(bench_orig, ws)
        for _fn in ("shipment_pricing.py", "test_shipment_pricing.py"):
            if (ws / _fn).exists():
                (ws / _fn).unlink()

        store = TaskStore(db_path=ws / "tasks_test.db")
        policy = GatewayPolicy(profile="full_agent")
        broker = TaskGrantBroker(key_path=ws / "broker_test.key", policy=policy)

        task = store.create_task(
            objective="CREATE shipment_pricing.py and test_shipment_pricing.py from scratch; Implement quote_shipment(weight_kg, distance_km, zone); do not modify existing 4 .py files; at least 5 new tests; all 15 tests pass.",
            workspace_root=str(ws),
        )
        ctrl = AutonomousAgentController(task.task_id, store, broker, policy=policy)
        baseline = {"order_pipeline.py": (ws / "order_pipeline.py").read_text()}

        # 1. Missing required file
        valid, reason = ctrl._verify_objective_deliverables(task, str(ws), baseline, "15 passed")
        assert not valid
        assert "does not exist" in reason

        # 2. File exists but not recorded in files_modified
        (ws / "shipment_pricing.py").write_text("def quote_shipment(): pass")
        (ws / "test_shipment_pricing.py").write_text("def test_one(): pass")
        ctrl._files_modified = []
        valid, reason = ctrl._verify_objective_deliverables(task, str(ws), baseline, "15 passed")
        assert not valid
        assert "was not modified or created" in reason

        # 3. Prohibited modification of existing file
        ctrl._files_modified = [str(ws / "shipment_pricing.py"), str(ws / "test_shipment_pricing.py")]
        (ws / "order_pipeline.py").write_text("# tampered")
        valid, reason = ctrl._verify_objective_deliverables(task, str(ws), baseline, "15 passed")
        assert not valid
        assert "modified despite prohibition" in reason

        # Restore order_pipeline.py
        (ws / "order_pipeline.py").write_text(baseline["order_pipeline.py"])

        # 4. Missing required function
        (ws / "shipment_pricing.py").write_text("def wrong_func(): pass")
        valid, reason = ctrl._verify_objective_deliverables(task, str(ws), baseline, "15 passed")
        assert not valid
        assert "Required function 'quote_shipment' not found" in reason

        # 5. Insufficient new tests (only 2 test functions when 5 required)
        (ws / "shipment_pricing.py").write_text("def quote_shipment(): pass")
        (ws / "test_shipment_pricing.py").write_text("def test_1(): pass\ndef test_2(): pass\n")
        baseline_with_tests = dict(baseline)
        baseline_with_tests["test_fulfillment_pipeline.py"] = (ws / "test_fulfillment_pipeline.py").read_text()
        valid, reason = ctrl._verify_objective_deliverables(task, str(ws), baseline_with_tests, "15 passed")
        assert not valid
        assert "Expected at least 5 new tests, found 2" in reason

        # 6. Insufficient passing tests (only 12 passed when 15 required)
        (ws / "test_shipment_pricing.py").write_text("def test_1(): pass\ndef test_2(): pass\ndef test_3(): pass\ndef test_4(): pass\ndef test_5(): pass\n")
        valid, reason = ctrl._verify_objective_deliverables(task, str(ws), baseline_with_tests, "12 passed")
        assert not valid
        assert "Expected at least 15 passing tests, but only 12 passed" in reason
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_diagnose_and_repair_shipment_pricing():
    adapter = BenchmarkShipmentPricingAdapter()
    with tempfile.TemporaryDirectory() as td:
        ws_bench = str(Path(td))

        error_ctx = (
            'File "shipment_pricing.py", line 45, in quote_shipment\n'
            'AssertionError: assert 25000 == 26000\n'
            'FAILED test_shipment_pricing.py::test_ceil_boundary_weight'
        )
        repair = adapter.diagnose_and_repair(
            objective=BENCHMARK_OBJECTIVE,
            failed_step={"action": "run_tests", "args": {"command": "pytest"}},
            error_context=error_ctx,
            workspace_root=ws_bench,
        )
        assert repair is not None
        assert repair["tool"] == "write_file"
        assert "shipment_pricing.py" in repair["args"]["path"]
        assert "quote_shipment" in repair["args"]["content"]


def test_production_adapter_unsupported_when_no_provider():
    """Verify production DeterministicRuleBasedAdapter fails-closed when no LLM provider is configured."""
    adapter = DeterministicRuleBasedAdapter()
    with tempfile.TemporaryDirectory() as td:
        ws_bench = str(Path(td))
        reqs = extract_objective_requirements(BENCHMARK_OBJECTIVE, ws_bench)
        # In production without an LLM provider, synthesizing new feature files must return None
        synth = adapter._synthesize_feature_from_objective(BENCHMARK_OBJECTIVE, ws_bench, reqs)
        assert synth is None

        # And generate_plan must raise MODEL_PROVIDER_NOT_CONFIGURED
        with pytest.raises(UnsupportedObjectiveError) as exc_info:
            adapter.generate_plan(
                objective=BENCHMARK_OBJECTIVE,
                workspace_summary={"workspace_root": ws_bench, "files": []},
                allowed_tools=["read_file", "write_file", "powershell_execute"],
            )
        assert "MODEL_PROVIDER_NOT_CONFIGURED" in str(exc_info.value)
