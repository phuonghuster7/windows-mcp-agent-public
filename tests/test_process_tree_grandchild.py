"""Test suite for Agent C: Multi-tier Process Tree Termination & Grandchild Cleanup (Audit 28D9ED5).

Remediates Finding C1:
1. Deterministic Nonce + Barrier verification across Parent -> Child -> Grandchild.
   Fails immediately if any of the 3 process levels fails to spawn or is not alive.
2. Verified termination on Emergency Stop, Timeout, and Task Cancellation.
3. Orphan descendant discovery and cleanup when Parent exits early.
4. Dual-stream bounded memory (64KB) reading with simultaneous stdout/stderr and UTF-8 Unicode.
5. Normal completion and exact exit code reporting.
"""
from __future__ import annotations

import json
import os
import shutil
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
for p in (PROJECT_ROOT, PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from runtime.contracts import RuntimeStatePaths
from runtime.process_runner import (
    execute_powershell_tree,
    is_process_alive_with_create_time,
)


SPAWNER_SCRIPT_CONTENT = """import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import psutil

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", required=True, choices=["parent", "child", "grandchild", "parent_early_exit"])
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

    base_level = "parent" if "parent" in args.level else args.level
    barrier_file = td / f"barrier_{base_level}.json"
    temp_file = td / f"tmp_{barrier_file.name}"
    temp_file.write_text(json.dumps(info), encoding="utf-8")
    temp_file.replace(barrier_file)

    if args.level == "parent":
        subprocess.Popen([sys.executable, __file__, "--level", "child", "--nonce", args.nonce, "--dir", args.dir, "--sleep", str(args.sleep)])
        time.sleep(args.sleep)
    elif args.level == "parent_early_exit":
        # Spawn child, sleep briefly to let child & grandchild spawn and record barrier, then parent exits
        subprocess.Popen([sys.executable, __file__, "--level", "child", "--nonce", args.nonce, "--dir", args.dir, "--sleep", str(args.sleep)])
        time.sleep(1.8)
        sys.exit(0)
    elif args.level == "child":
        subprocess.Popen([sys.executable, __file__, "--level", "grandchild", "--nonce", args.nonce, "--dir", args.dir, "--sleep", str(args.sleep)])
        time.sleep(args.sleep)
    elif args.level == "grandchild":
        time.sleep(args.sleep)

if __name__ == "__main__":
    main()
"""


def _create_spawner_script(target_dir: Path) -> Path:
    script_path = target_dir / "tree_spawner.py"
    script_path.write_text(SPAWNER_SCRIPT_CONTENT, encoding="utf-8")
    return script_path


def _wait_for_3tier_barrier(
    td: Path,
    expected_nonce: str,
    timeout_seconds: float = 12.0,
) -> Dict[str, Dict[str, Any]]:
    """Poll for all 3 barrier files (parent, child, grandchild) to appear,
    validate nonces, and confirm all 3 PIDs are alive with matching create_time.
    Fails fast if any level is missing.
    """
    start_t = time.monotonic()
    levels = ("parent", "child", "grandchild")
    result: Dict[str, Dict[str, Any]] = {}

    while time.monotonic() - start_t < timeout_seconds:
        all_ready = True
        for lvl in levels:
            bf = td / f"barrier_{lvl}.json"
            if not bf.exists():
                all_ready = False
                break
            try:
                data = json.loads(bf.read_text(encoding="utf-8"))
                if data.get("nonce") != expected_nonce or not data.get("ready"):
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

    missing = [lvl for lvl in levels if lvl not in result]
    pytest.fail(f"Barrier failed: not all 3 levels spawned and alive within {timeout_seconds}s. Missing/unready: {missing}")


def test_01_emergency_stop_kills_verified_parent_child_grandchild():
    """Trigger emergency stop after barrier confirms 3 tiers alive.
    Verifies all descendants + parent are killed, no survivors.
    """
    td = Path(tempfile.mkdtemp(prefix="test_c1_stop_"))
    try:
        paths = RuntimeStatePaths.create_isolated(td)
        spawner = _create_spawner_script(td)
        nonce = f"stop_{int(time.time())}"

        cmd = f'& "{sys.executable}" "{spawner.as_posix()}" --level parent --nonce "{nonce}" --dir "{td.as_posix()}" --sleep 60'

        barriers: Dict[str, Dict[str, Any]] = {}

        def trigger_stop_when_ready():
            nonlocal barriers
            barriers = _wait_for_3tier_barrier(td, nonce, timeout_seconds=10.0)
            paths.trigger_emergency_stop("TEST_C1_EMERGENCY_STOP")

        t = threading.Thread(target=trigger_stop_when_ready, daemon=True)
        t.start()

        res = execute_powershell_tree(
            cmd,
            cwd=td,
            timeout_seconds=20.0,
            stop_check_fn=paths.is_emergency_stop_active,
        )
        paths.clear_emergency_stop()
        t.join(timeout=2.0)

        assert len(barriers) == 3, "All 3 tiers must have been alive and verified before stop"
        assert res.interrupted_by_emergency_stop is True
        assert res.parent_terminated is True
        assert res.cleanup_status == "CLEAN"
        assert res.cleanup_verified is True
        assert res.descendants_expected >= 2
        assert res.descendants_terminated >= 2
        assert len(res.survivors) == 0

        # Independent verification that all 3 tiers are dead
        for lvl, info in barriers.items():
            pid, ct = info["pid"], info["create_time"]
            assert not is_process_alive_with_create_time(pid, ct), f"Process {lvl} (PID {pid}) survived emergency stop!"

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_02_timeout_kills_verified_parent_child_grandchild():
    """Trigger timeout after barrier confirms 3 tiers alive.
    Verifies all tiers killed, no survivors.
    """
    td = Path(tempfile.mkdtemp(prefix="test_c1_timeout_"))
    try:
        spawner = _create_spawner_script(td)
        nonce = f"timeout_{int(time.time())}"

        cmd = f'& "{sys.executable}" "{spawner.as_posix()}" --level parent --nonce "{nonce}" --dir "{td.as_posix()}" --sleep 60'

        barriers: Dict[str, Dict[str, Any]] = {}

        def wait_barrier_in_bg():
            nonlocal barriers
            barriers = _wait_for_3tier_barrier(td, nonce, timeout_seconds=10.0)

        t = threading.Thread(target=wait_barrier_in_bg, daemon=True)
        t.start()

        # 3.0s timeout gives barrier time to form (~1.5s) and triggers timeout
        res = execute_powershell_tree(
            cmd,
            cwd=td,
            timeout_seconds=3.0,
        )
        t.join(timeout=2.0)

        assert len(barriers) == 3, "Barrier must have been formed and verified before timeout"
        assert res.timed_out is True
        assert res.parent_terminated is True
        assert res.cleanup_status == "CLEAN"
        assert res.cleanup_verified is True
        assert res.descendants_expected >= 2
        assert res.descendants_terminated >= 2
        assert len(res.survivors) == 0

        for lvl, info in barriers.items():
            pid, ct = info["pid"], info["create_time"]
            assert not is_process_alive_with_create_time(pid, ct), f"Process {lvl} (PID {pid}) survived timeout!"

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_03_cancel_revoke_kills_verified_parent_child_grandchild():
    """Trigger task cancellation after barrier confirms 3 tiers alive.
    Verifies cancel flag triggers full tree cleanup.
    """
    td = Path(tempfile.mkdtemp(prefix="test_c1_cancel_"))
    try:
        spawner = _create_spawner_script(td)
        nonce = f"cancel_{int(time.time())}"

        cmd = f'& "{sys.executable}" "{spawner.as_posix()}" --level parent --nonce "{nonce}" --dir "{td.as_posix()}" --sleep 60'

        is_cancelled = False
        barriers: Dict[str, Dict[str, Any]] = {}

        def trigger_cancel_when_ready():
            nonlocal is_cancelled, barriers
            barriers = _wait_for_3tier_barrier(td, nonce, timeout_seconds=10.0)
            is_cancelled = True

        t = threading.Thread(target=trigger_cancel_when_ready, daemon=True)
        t.start()

        res = execute_powershell_tree(
            cmd,
            cwd=td,
            timeout_seconds=20.0,
            cancel_check_fn=lambda: is_cancelled,
        )
        t.join(timeout=2.0)

        assert len(barriers) == 3, "Barrier must have been formed and verified before cancel"
        assert res.cancelled is True
        assert res.parent_terminated is True
        assert res.cleanup_status == "CLEAN"
        assert res.cleanup_verified is True
        assert res.descendants_expected >= 2
        assert res.descendants_terminated >= 2
        assert len(res.survivors) == 0

        for lvl, info in barriers.items():
            pid, ct = info["pid"], info["create_time"]
            assert not is_process_alive_with_create_time(pid, ct), f"Process {lvl} (PID {pid}) survived task cancellation!"

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_04_parent_early_exit_orphan_grandchild_cleanup():
    """Parent spawns Child -> Grandchild and exits immediately.
    Child and Grandchild remain running in background.
    Runner must detect alive orphan descendants and forcefully terminate them.
    """
    td = Path(tempfile.mkdtemp(prefix="test_c1_orphan_"))
    try:
        spawner = _create_spawner_script(td)
        nonce = f"orphan_{int(time.time())}"

        cmd = f'& "{sys.executable}" "{spawner.as_posix()}" --level parent_early_exit --nonce "{nonce}" --dir "{td.as_posix()}" --sleep 60'

        barriers: Dict[str, Dict[str, Any]] = {}

        def wait_barrier_in_bg():
            nonlocal barriers
            barriers = _wait_for_3tier_barrier(td, nonce, timeout_seconds=10.0)

        t = threading.Thread(target=wait_barrier_in_bg, daemon=True)
        t.start()

        res = execute_powershell_tree(
            cmd,
            cwd=td,
            timeout_seconds=15.0,
        )
        t.join(timeout=2.0)

        assert len(barriers) == 3, "Barrier must have been formed and verified while orphan processes alive"
        assert res.cleanup_status == "CLEAN"
        assert res.cleanup_verified is True
        assert res.descendants_expected >= 2
        assert res.descendants_terminated >= 2
        assert len(res.survivors) == 0

        # Child and Grandchild must both be confirmed dead
        for lvl in ("child", "grandchild"):
            info = barriers[lvl]
            pid, ct = info["pid"], info["create_time"]
            assert not is_process_alive_with_create_time(pid, ct), f"Orphan process {lvl} (PID {pid}) survived early-exit parent!"

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_05_simultaneous_bounded_stdout_stderr_and_unicode():
    """Simultaneous emission of >100KB to both stdout and stderr with Vietnamese Unicode text.
    Verifies dual 64KB cap, no deadlock, proper truncation flags, and UTF-8 integrity.
    """
    td = Path(tempfile.mkdtemp(prefix="test_c1_bounded_"))
    try:
        stream_script = td / "large_streams.py"
        stream_code = """import sys
vietnamese_phrase = "Dự án Quản lý Tiến trình Tự động hóa Windows MCP Agent - Kiểm thử Giới hạn Kép!\\n"
# Emit ~120KB to stdout and ~120KB to stderr simultaneously
chunk = (vietnamese_phrase * 10).encode("utf-8")
for _ in range(120):
    sys.stdout.buffer.write(chunk)
    sys.stderr.buffer.write(chunk)
sys.stdout.buffer.flush()
sys.stderr.buffer.flush()
"""
        stream_script.write_text(stream_code, encoding="utf-8")

        cmd = f'& "{sys.executable}" "{stream_script.as_posix()}"'

        res = execute_powershell_tree(
            cmd,
            cwd=td,
            timeout_seconds=10.0,
            max_output_bytes=65536,
        )

        assert res.exit_code == 0
        assert res.stdout_truncated is True
        assert res.stderr_truncated is True
        assert res.truncated is True

        # Byte lengths of decoded output within reasonable bound of 64KB limit
        out_bytes_len = len(res.stdout.encode("utf-8"))
        err_bytes_len = len(res.stderr.encode("utf-8"))
        assert out_bytes_len <= 65536 + 100
        assert err_bytes_len <= 65536 + 100

        # Unicode integrity preserved
        assert "Dự án Quản lý Tiến trình" in res.stdout
        assert "Dự án Quản lý Tiến trình" in res.stderr

    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_06_normal_success_and_nonzero_exit_codes():
    """Verify normal command execution handles exit codes cleanly."""
    td = Path(tempfile.mkdtemp(prefix="test_c1_normal_"))
    try:
        # 1. Normal success
        res_ok = execute_powershell_tree("Write-Output 'HELLO_NORMAL'", cwd=td)
        assert res_ok.exit_code == 0
        assert "HELLO_NORMAL" in res_ok.stdout
        assert res_ok.parent_terminated is True
        assert res_ok.cleanup_status == "NOT_NEEDED"
        assert res_ok.cleanup_verified is True
        assert res_ok.descendants_terminated == 0
        assert len(res_ok.survivors) == 0

        # 2. Nonzero exit code (42) via PowerShell exit
        res_err = execute_powershell_tree("exit 42", cwd=td)
        assert res_err.exit_code == 42
        assert res_err.cleanup_status == "NOT_NEEDED"

        # 3. Nonzero exit code forwarded from Python
        res_err_py = execute_powershell_tree(
            f'& "{sys.executable}" -c "import sys; sys.exit(42)"; exit $LASTEXITCODE',
            cwd=td,
        )
        assert res_err_py.exit_code == 42
        assert res_err_py.cleanup_status == "NOT_NEEDED"

    finally:
        shutil.rmtree(td, ignore_errors=True)
