"""Acceptance test suite for Agent B: Core Runtime, Environment Robustness & Isolation.

Remediates findings for ANTI 2.1 Pre-Publication Hardening & Zero-False-Pass:
1. Missing Home Environment Collection & Runtime:
   Stripped CI/sandboxed runners without USERPROFILE, HOME, HOMEDRIVE, HOMEPATH
   can import and instantiate SecurityPolicy, MCPGatewayServer, RuntimeStatePaths,
   ProductionWriteGuard, and collect pytest test suite without RuntimeError.
2. Unicode & Space-Containing Paths:
   SecurityPolicy, RuntimeStatePaths, TaskStore, TaskGrantBroker, and FileCodeOperations
   work cleanly on Windows paths containing spaces and UTF-8 Unicode (e.g. 'Thư mục Kiểm thử 2026').
3. Fail-Closed Missing Security Config:
   When nonexistent or corrupted policy path is explicitly passed or invalid profile requested,
   SecurityPolicy fails closed (FileNotFoundError / ValueError) without granting permissions.
4. Zero Fallback to Production State in Test Mode:
   ProductionWriteGuard blocks direct writes, os.replace, sqlite3.connect, and subprocess writes
   to PROJECT_ROOT / "runtime" and PROJECT_ROOT / "config" while never unlinking production files.
5. Process Tree Nonce + Barrier + Unicode Output Verification:
   execute_powershell_tree handles Unicode stdout/stderr (Tiếng Việt UTF-8) and cleanly
   terminates 3-tier process tree with survivors == [] and parent excluded from descendants.
6. Safe expanduser boundary cases.
"""
from __future__ import annotations

import gc
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict

import psutil
import pytest

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for p in (PROJECT_ROOT, PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent", PROJECT_ROOT / "runtime"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from runtime.contracts import RuntimeStatePaths, ProductionWriteGuard
from runtime.task_grant import TaskGrantBroker
from runtime.process_runner import (
    execute_powershell_tree,
    is_process_alive_with_create_time,
)
from task_store import TaskStore
from policy import SecurityPolicy, SessionManager, PermissionTier, _safe_expanduser
from gateway_server import MCPGatewayServer
from file_code_ops import FileCodeOperations
from exec_jobs import ExecutionJobManager
from agent import DesktopAgent


# ---------------------------------------------------------------------------
# Test 1: Missing Home Environment Collection & Runtime
# ---------------------------------------------------------------------------

def test_01_missing_home_environment_runtime_and_instantiation(monkeypatch, tmp_path):
    """Verify runtime classes instantiate without error when home env vars are stripped."""
    for var in ("USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH"):
        monkeypatch.delenv(var, raising=False)

    # 1. _safe_expanduser fallback
    expanded_root = _safe_expanduser("~")
    assert expanded_root.is_absolute()
    expanded_sub = _safe_expanduser("~/sandbox_dir")
    assert expanded_sub.is_absolute()
    assert expanded_sub.name == "sandbox_dir"

    # 2. SessionManager with ~ in allowed_paths
    sm = SessionManager()
    session = sm.create_session(allowed_paths=["~/workspace", tmp_path])
    assert session.session_id.startswith("sess_")
    assert session.allowed_paths is not None
    assert len(session.allowed_paths) >= 2

    # 3. SecurityPolicy._resolve_roots with ~
    roots = SecurityPolicy._resolve_roots(["~/safe_root", str(tmp_path)])
    assert len(roots) >= 2
    assert all(r.is_absolute() for r in roots)

    # 4. SecurityPolicy instantiation and validate_path
    audit_file = tmp_path / "stripped_env_audit.jsonl"
    pol = SecurityPolicy(audit_log_path=audit_file, profile="read_only")
    assert pol.profile == "read_only"
    assert pol.enabled_tiers == {PermissionTier.READ}

    # 5. RuntimeStatePaths isolated creation
    isolated_dir = tmp_path / "isolated_runtime"
    paths = RuntimeStatePaths.create_isolated(isolated_dir)
    assert paths.is_isolated is True
    assert paths.base_dir.exists()
    assert paths.tasks_db_path.parent.exists()
    store = TaskStore(db_path=paths.tasks_db_path)
    store.create_task("Isolated Init Task", isolated_dir, task_id="t_iso_init")
    assert paths.tasks_db_path.exists()

    # 6. ProductionWriteGuard instantiation
    guard = ProductionWriteGuard(protected_roots=[tmp_path / "mock_prod"])
    assert guard.run_id is not None

    # 7. MCPGatewayServer instantiation
    server = MCPGatewayServer(policy=pol, runtime_paths=paths)
    assert server.policy is pol

    # 8. Scripts safe home helpers run without RuntimeError
    import scripts.diagnose_autonomous_cloud as diag
    assert diag._safe_home().is_absolute()

    import scripts.verify_direct_coding_e2e as v_direct
    assert v_direct._safe_home().is_absolute()

    import scripts.verify_codex_materialization as v_codex
    assert v_codex._safe_home().is_absolute()


def test_02_missing_home_environment_subprocess_pytest_collection():
    """Verify pytest can collect the test suite in a stripped subprocess environment."""
    env = os.environ.copy()
    for var in ("USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH"):
        env.pop(var, None)

    # Ensure python paths are preserved
    env["PYTHONPATH"] = os.pathsep.join([
        str(PROJECT_ROOT),
        str(PROJECT_ROOT / "mcp-gateway"),
        str(PROJECT_ROOT / "backend"),
        str(PROJECT_ROOT / "desktop-agent"),
        str(PROJECT_ROOT / "runtime"),
    ])

    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "tests/test_environment_robustness.py",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    assert res.returncode == 0, f"pytest --collect-only failed: {res.stderr}\nstdout: {res.stdout}"
    assert "Could not determine home directory" not in res.stderr
    assert "Could not determine home directory" not in res.stdout


# ---------------------------------------------------------------------------
# Test 2: Unicode & Space-Containing Paths
# ---------------------------------------------------------------------------

def test_03_unicode_and_space_containing_paths_handling(tmp_path):
    """Verify SecurityPolicy, RuntimeStatePaths, TaskStore, and TaskGrantBroker on paths with spaces and Unicode."""
    unicode_dir = tmp_path / "Thư mục Kiểm thử 2026" / "Tài nguyên Hệ thống"
    unicode_dir.mkdir(parents=True, exist_ok=True)
    unicode_file = unicode_dir / "tệp_dữ_liệu_bảo_mật.txt"
    unicode_content = "Nội dung kiểm thử bảo mật tiếng Việt UTF-8: 100% chính xác!"
    unicode_file.write_text(unicode_content, encoding="utf-8")

    # 1. RuntimeStatePaths in Unicode & space directory
    paths = RuntimeStatePaths.create_isolated(unicode_dir / "runtime_trạng_thái")
    assert paths.base_dir.exists()
    assert paths.tasks_db_path.parent.exists()
    assert "Thư mục Kiểm thử 2026" in str(paths.base_dir)

    # 2. TaskStore with Unicode task title, description, and cwd
    store = TaskStore(db_path=paths.tasks_db_path)
    task_id = "task_tieng_viet_001"
    created = store.create_task(
        "Tác vụ phân tích hệ thống tự động",
        unicode_dir,
        task_id=task_id,
    )
    assert created.task_id == task_id
    assert created.objective == "Tác vụ phân tích hệ thống tự động"
    assert created.workspace_root == str(unicode_dir)
    assert paths.tasks_db_path.exists()

    fetched = store.get_task(task_id)
    assert fetched is not None
    assert fetched.objective == "Tác vụ phân tích hệ thống tự động"

    # 3. TaskGrantBroker with Unicode paths and grants
    broker = TaskGrantBroker(
        db_path=paths.tasks_db_path,
        key_path=unicode_dir / "khóa_bảo_mật.key",
    )
    grant = broker.issue_grant(
        task_id=task_id,
        workspace_root=unicode_dir,
        allowed_tools=["write_file", "read_file"],
        allowed_commands=[],
        allowed_permission_tiers=["READ", "WRITE"],
        duration_seconds=300.0,
    )
    assert grant.grant_id.startswith("grant_")
    assert grant.task_id == task_id
    valid, reason = broker.validate_grant(grant.grant_id, expected_task_id=task_id)
    assert valid is True

    # 4. SecurityPolicy validate_path and FileCodeOperations on Unicode path
    pol = SecurityPolicy(
        profile="full_agent",
        allowed_read_roots=[unicode_dir],
        allowed_write_roots=[unicode_dir],
        audit_log_path=unicode_dir / "kiểm_toán.jsonl",
    )
    validated = pol.validate_path(unicode_file, tier=PermissionTier.READ)
    assert validated.resolve() == unicode_file.resolve()

    file_ops = FileCodeOperations(policy=pol)
    read_data = file_ops.read_file(str(unicode_file))
    assert read_data["content"] == unicode_content


# ---------------------------------------------------------------------------
# Test 3: Fail-Closed Missing Security Config
# ---------------------------------------------------------------------------

def test_04_fail_closed_missing_or_corrupted_security_config(tmp_path):
    """Verify SecurityPolicy fails closed when policy file is nonexistent, corrupted, or profile is invalid."""
    # A. Explicit nonexistent policy file must raise FileNotFoundError
    nonexistent = tmp_path / "nonexistent_sec_policy.json"
    with pytest.raises(FileNotFoundError) as exc_fnf:
        SecurityPolicy(policy_path=nonexistent)
    assert "Explicit policy file does not exist" in str(exc_fnf.value)

    # B. Explicit corrupted JSON policy file must raise ValueError
    corrupted = tmp_path / "corrupted_policy.json"
    corrupted.write_text('{"profiles": { MALFORMED JSON...', encoding="utf-8")
    with pytest.raises(ValueError) as exc_val:
        SecurityPolicy(policy_path=corrupted)
    assert "Corrupted or invalid policy configuration file" in str(exc_val.value)

    # C. Invalid profile name must raise ValueError rather than granting permissions
    with pytest.raises(ValueError) as exc_prof:
        SecurityPolicy(profile="unrestricted_superadmin_p0")
    assert "Unknown or invalid security profile" in str(exc_prof.value)

    # D. Profile fallback verification: read_only has only READ tier enabled
    ro_pol = SecurityPolicy(profile="read_only")
    assert ro_pol.enabled_tiers == {PermissionTier.READ}
    with pytest.raises(PermissionError) as exc_deny:
        ro_pol.authorize_tool("write_file", {"path": str(tmp_path / "x.txt"), "content": "blocked"})
    assert "not enabled in profile" in str(exc_deny.value)


# ---------------------------------------------------------------------------
# Test 4: Zero Fallback to Production State in Test Mode
# ---------------------------------------------------------------------------

def test_05_zero_fallback_to_production_state_in_test_mode(tmp_path, guard_production_state):
    """Verify ProductionWriteGuard intercepts all writes, renames, unlinks, and subprocess writes to prod roots."""
    prod_runtime = PROJECT_ROOT / "runtime"
    prod_config = PROJECT_ROOT / "config"

    # Capture initial states
    canary_file = prod_runtime / "canary_never_create.tmp"
    prod_policy_path = prod_config / "policy.json"
    initial_policy_mtime = prod_policy_path.stat().st_mtime if prod_policy_path.exists() else None

    # Test 1: Direct write attempt to runtime root must be blocked by active guard
    with pytest.raises(PermissionError) as exc_w:
        canary_file.write_text("POLLUTION_DATA", encoding="utf-8")
    assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_w.value)
    assert not canary_file.exists()

    # Test 2: os.replace into production root must be blocked
    temp_src = tmp_path / "source_file.tmp"
    temp_src.write_text("SOURCE_DATA", encoding="utf-8")
    with pytest.raises(PermissionError) as exc_rep:
        os.replace(temp_src, prod_config / "malicious_overwrite.tmp")
    assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_rep.value)
    assert not (prod_config / "malicious_overwrite.tmp").exists()

    # Test 3: SQLite write connection to production DB must be blocked
    prod_db = prod_runtime / "tasks.db"
    with pytest.raises(PermissionError) as exc_db:
        sqlite3.connect(prod_db)
    assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_db.value)

    # Test 4: Unlink attempt on existing production config must be blocked
    if prod_policy_path.exists():
        with pytest.raises(PermissionError) as exc_unl:
            prod_policy_path.unlink()
        assert "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc_unl.value)
        assert prod_policy_path.exists()

    # Clear intercepted events on the test harness fixture so conftest teardown doesn't flag deliberate test assertions
    guard_production_state.blocked_events.clear()

    # Test 5: Subprocess write protection via an isolated mock canary guard
    mock_prod = tmp_path / "mock_prod_dir"
    mock_prod.mkdir()
    sub_canary = mock_prod / "subproc_target.txt"
    sub_guard = ProductionWriteGuard(protected_roots=[mock_prod], run_id="test_subproc_guard")
    sub_env = sub_guard.get_subprocess_env()
    sub_code = (
        f"from pathlib import Path; "
        f"Path(r'{sub_canary}').write_text('SUBPROC_POLLUTION', encoding='utf-8')"
    )
    res_sub = subprocess.run(
        [sys.executable, "-c", sub_code],
        env=sub_env,
        capture_output=True,
        text=True,
    )
    assert res_sub.returncode != 0
    assert "PRODUCTION_STATE_WRITE_BLOCKED" in res_sub.stderr
    assert not sub_canary.exists(), "Canary file must NEVER be created on disk"

    # Verify production files remain unchanged
    if initial_policy_mtime is not None:
        assert prod_policy_path.stat().st_mtime == initial_policy_mtime


# ---------------------------------------------------------------------------
# Test 5: Process Tree Nonce + Barrier + Unicode Output Verification
# ---------------------------------------------------------------------------

UNICODE_SPAWNER_SCRIPT = """import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import psutil

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser()
    parser.add_argument("--level", required=True, choices=["parent", "child", "grandchild"])
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--dir", required=True)
    parser.add_argument("--sleep", type=float, default=60.0)
    args = parser.parse_args()

    td = Path(args.dir)
    my_pid = os.getpid()
    p = psutil.Process(my_pid)
    my_ct = p.create_time()

    info = {
        "level": args.level,
        "pid": my_pid,
        "create_time": my_ct,
        "exe": sys.executable,
        "nonce": args.nonce,
        "ready": True,
    }

    barrier_file = td / f"barrier_{args.level}.json"
    temp_file = td / f"tmp_{barrier_file.name}"
    temp_file.write_text(json.dumps(info), encoding="utf-8")
    temp_file.replace(barrier_file)

    # Emit Unicode UTF-8 strings
    print(f"[{args.level}] Xin chào từ Tiến trình MCP Tiếng Việt UTF-8 (PID {my_pid})", flush=True)
    sys.stderr.write(f"[{args.level}] Kênh thông báo lỗi UTF-8: Hoạt động bình thường (PID {my_pid})\\n")
    sys.stderr.flush()

    sub_env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if args.level == "parent":
        subprocess.Popen([sys.executable, __file__, "--level", "child", "--nonce", args.nonce, "--dir", args.dir, "--sleep", str(args.sleep)], env=sub_env)
        time.sleep(args.sleep)
    elif args.level == "child":
        subprocess.Popen([sys.executable, __file__, "--level", "grandchild", "--nonce", args.nonce, "--dir", args.dir, "--sleep", str(args.sleep)], env=sub_env)
        time.sleep(args.sleep)
    elif args.level == "grandchild":
        time.sleep(args.sleep)

if __name__ == "__main__":
    main()
"""


def _wait_for_barrier_files(td: Path, nonce: str, timeout: float = 12.0) -> Dict[str, Dict[str, Any]]:
    start_t = time.monotonic()
    result: Dict[str, Dict[str, Any]] = {}
    levels = ("parent", "child", "grandchild")

    while time.monotonic() - start_t < timeout:
        all_ready = True
        for lvl in levels:
            bf = td / f"barrier_{lvl}.json"
            if not bf.exists():
                all_ready = False
                break
            try:
                data = json.loads(bf.read_text(encoding="utf-8"))
                if data.get("nonce") != nonce or not data.get("ready"):
                    all_ready = False
                    break
                pid = data["pid"]
                ct = data["create_time"]
                if not is_process_alive_with_create_time(pid, ct):
                    all_ready = False
                    break
                result[lvl] = data
            except Exception:
                all_ready = False
                break

        if all_ready and len(result) == 3:
            return result
        time.sleep(0.05)

    return result


def test_06_process_tree_nonce_barrier_and_unicode_output(tmp_path):
    """Verify execute_powershell_tree handles Unicode UTF-8 streams and terminates 3-tier tree cleanly."""
    spawner_dir = tmp_path / "process_tree_test"
    spawner_dir.mkdir(parents=True, exist_ok=True)
    spawner_script = spawner_dir / "unicode_spawner.py"
    spawner_script.write_text(UNICODE_SPAWNER_SCRIPT, encoding="utf-8")

    nonce = f"tree_nonce_{int(time.time() * 1000)}"
    cmd = (
        f'& "{sys.executable}" "{spawner_script.as_posix()}" '
        f'--level parent --nonce "{nonce}" --dir "{spawner_dir.as_posix()}" --sleep 60'
    )

    barriers: Dict[str, Dict[str, Any]] = {}
    stop_triggered = threading.Event()

    def poll_barrier_and_stop():
        nonlocal barriers
        barriers = _wait_for_barrier_files(spawner_dir, nonce, timeout=12.0)
        if len(barriers) == 3:
            stop_triggered.set()

    t = threading.Thread(target=poll_barrier_and_stop, daemon=True)
    t.start()

    res = execute_powershell_tree(
        cmd,
        cwd=spawner_dir,
        timeout_seconds=20.0,
        cleanup_timeout_seconds=5.0,
        stop_check_fn=stop_triggered.is_set,
    )
    t.join(timeout=2.0)

    # 1. Nonce + Barrier Verification
    assert len(barriers) == 3, f"Expected 3 barriers (parent, child, grandchild); got {list(barriers.keys())}"
    for lvl in ("parent", "child", "grandchild"):
        assert barriers[lvl]["nonce"] == nonce
        assert barriers[lvl]["ready"] is True

    # 2. Cleanup and survivor verification
    assert res.interrupted_by_emergency_stop is True or res.timed_out is True
    assert res.cleanup_status in ("CLEAN", "NOT_NEEDED")
    assert res.cleanup_verified is True
    assert len(res.survivors) == 0, f"Expected survivors == [], got: {res.survivors}"

    # 3. Runner parent process is tracked separately; descendants must not include runner parent PID
    runner_parent_pid = res.parent_pid
    discovered_pids = [d["pid"] for d in res.children_discovered]
    assert runner_parent_pid not in discovered_pids, "Runner parent PID must not be in discovered descendants"
    assert res.parent_terminated is True

    # 4. Confirm all 3 processes are dead
    for lvl in ("parent", "child", "grandchild"):
        info = barriers[lvl]
        pid, ct = info["pid"], info["create_time"]
        assert not is_process_alive_with_create_time(pid, ct), f"Process {lvl} (PID {pid}) survived cleanup!"

    # 5. Unicode output verification (Tiếng Việt UTF-8 in stdout / stderr)
    assert "Xin chào từ Tiến trình MCP Tiếng Việt UTF-8" in res.stdout
    assert "Kênh thông báo lỗi UTF-8" in res.stderr


# ---------------------------------------------------------------------------
# Test 6: Safe expanduser edge cases
# ---------------------------------------------------------------------------

def test_07_safe_expanduser_edge_cases(monkeypatch, tmp_path):
    """Verify _safe_expanduser handles edge cases across stripped and normal environments."""
    # Test normal environment
    assert _safe_expanduser("").as_posix() == "."
    assert _safe_expanduser("relative/subpath").as_posix() == "relative/subpath"

    # Test stripped environment
    for var in ("USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH"):
        monkeypatch.delenv(var, raising=False)

    p_tilde = _safe_expanduser("~")
    assert p_tilde.is_absolute()

    p_slash = _safe_expanduser("~/my_app/config")
    assert p_slash.is_absolute()
    assert p_slash.parts[-2:] == ("my_app", "config")

    p_backslash = _safe_expanduser("~\\my_app\\config")
    assert p_backslash.is_absolute()
    assert p_backslash.parts[-2:] == ("my_app", "config")


# ---------------------------------------------------------------------------
# Test 7: Adversarial Negative Tests for State Isolation & Robustness
# ---------------------------------------------------------------------------

def test_08_adversarial_tampered_guard_detection(tmp_path):
    """Adversarial Negative Test: Proves that disabling or mutating the WriteGuard is immediately caught.

    When guard is active: write to protected canary raises PermissionError.
    When guard is maliciously neutered (e.g. protected_roots cleared): canary write succeeds,
    and the adversarial verifier immediately detects the isolation failure.
    """
    mock_prod = tmp_path / "adversarial_mock_prod"
    mock_prod.mkdir()
    target_canary = mock_prod / "canary_payload.txt"

    def check_isolation_enforcement(guard_instance: ProductionWriteGuard, canary: Path) -> bool:
        """Returns True if the guard actively blocked the write, False if write slipped through."""
        try:
            canary.write_text("TAMPERED_STATE", encoding="utf-8")
            return False  # VULNERABILITY: Write was permitted!
        except PermissionError as exc:
            return "PRODUCTION_STATE_WRITE_BLOCKED" in str(exc)

    # 1. Normal/Secure Guard: Must successfully block write
    intact_guard = ProductionWriteGuard(protected_roots=[mock_prod], run_id="adv_intact")
    with intact_guard:
        is_protected = check_isolation_enforcement(intact_guard, target_canary)
        assert is_protected is True, "Intact guard must block writes to protected root"
        assert not target_canary.exists()

    # 2. Adversarial Mutation: Neuter the guard by emptying its protected_roots
    tampered_guard = ProductionWriteGuard(protected_roots=[mock_prod], run_id="adv_tampered")
    with tampered_guard:
        # Malicious mutation simulating accidental or hostile guard de-scoping
        tampered_guard.protected_roots = []
        is_protected = check_isolation_enforcement(tampered_guard, target_canary)
        # The verification framework must immediately flag that the tampered guard failed to protect!
        assert is_protected is False, "Verification harness must detect that tampered guard permitted writes"
        assert target_canary.exists()

    # Clean up canary
    target_canary.unlink(missing_ok=True)


def test_09_adversarial_mutated_policy_and_missing_env_fallback_detection(monkeypatch, tmp_path):
    """Adversarial Negative Test: Proves detection when policy fail-closed or path isolation is mutated.

    1. Profile mutation: Verifies that removing fail-closed validation on invalid profiles
       is caught by the test assertion.
    2. Missing environment path leakage: Verifies that _safe_expanduser NEVER falls back to
       PROJECT_ROOT when HOME/USERPROFILE are unset, and catches an adversarial fallback mutation.
    """
    # 1. Policy profile adversarial verification
    def verify_profile_fail_closed(policy_cls, profile_name: str) -> bool:
        try:
            policy_cls(profile=profile_name)
            return False  # VULNERABILITY: Permitted unknown profile without failing closed!
        except ValueError as exc:
            return "Unknown or invalid security profile" in str(exc)

    # Real SecurityPolicy correctly fails closed
    assert verify_profile_fail_closed(SecurityPolicy, "unrestricted_hacker_profile_p0") is True

    # Mutated/vulnerable policy subclass that ignores unknown profiles
    class VulnerablePolicyBypass(SecurityPolicy):
        def __init__(self, *args, **kwargs):
            # Bypass fail-closed profile check
            self.profile = kwargs.get("profile", "read_only")
            self.enabled_tiers = {PermissionTier.READ}
            self.config = {}
            self.read_roots = (tmp_path,)
            self.write_roots = (tmp_path,)
            self.exec_roots = (tmp_path,)
            self.strict_v021_read_tools_only = False
            self.unrestricted_workspace_access = False

    # Harness must detect that the bypass is vulnerable
    assert verify_profile_fail_closed(VulnerablePolicyBypass, "unrestricted_hacker_profile_p0") is False

    # 2. Environment fallback adversarial verification
    for var in ("USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH"):
        monkeypatch.delenv(var, raising=False)

    # Real safe expanduser in stripped env falls back to tempdir, NOT repository root
    resolved_safe = _safe_expanduser("~/isolated_sandbox")
    assert not resolved_safe.is_relative_to(PROJECT_ROOT), (
        f"Security breach: Missing env fallback leaked into PROJECT_ROOT: {resolved_safe}"
    )
    assert resolved_safe.is_relative_to(Path(tempfile.gettempdir()))

    # Adversarial defective resolver that mistakenly falls back to repo root
    def defective_insecure_expanduser(p: str | Path) -> Path:
        s = str(p)
        if s.startswith("~/") or s.startswith("~\\"):
            return PROJECT_ROOT / s[2:]
        return Path(p)

    def verify_resolver_confinement(resolver_fn, test_path: str) -> bool:
        res = resolver_fn(test_path)
        return not res.is_relative_to(PROJECT_ROOT)

    assert verify_resolver_confinement(_safe_expanduser, "~/secret_store") is True
    assert verify_resolver_confinement(defective_insecure_expanduser, "~/secret_store") is False


def test_10_adversarial_task_grant_signature_tampering_detection(tmp_path):
    """Adversarial Negative Test: Cryptographic token mutation is detected immediately by broker."""
    paths = RuntimeStatePaths.create_isolated(tmp_path / "adv_grant_rt")
    broker = TaskGrantBroker(
        db_path=paths.tasks_db_path,
        key_path=tmp_path / "adv_broker.key",
    )

    grant = broker.issue_grant(
        task_id="task_adv_001",
        workspace_root=tmp_path,
        allowed_tools=["read_file", "write_file"],
        allowed_commands=[],
        allowed_permission_tiers=["READ", "WRITE"],
        duration_seconds=300.0,
    )

    # 1. Intact token passes verification
    valid, _ = broker.validate_grant(grant.grant_id, expected_task_id="task_adv_001")
    assert valid is True

    # 2. Adversarial tampering: Cross-task token reuse attempt
    valid_cross, reason_cross = broker.validate_grant(grant.grant_id, expected_task_id="task_adv_VICTIM_999")
    assert valid_cross is False
    assert "cross-task" in reason_cross.lower() or "mismatch" in reason_cross.lower() or "not bound" in reason_cross.lower()

    # 3. Adversarial tampering: Nonexistent or forged grant ID
    valid_fake, reason_fake = broker.validate_grant("grant_FORGED_SIGNATURE_99999999")
    assert valid_fake is False

