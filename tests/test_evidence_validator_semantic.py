"""Comprehensive Semantic Validator Test Suite (Audit 28D9ED5 / Gate G06).

Tests Cover:
1. Auditor reproduction: two fake SHAs, invalid XML, meaningless log -> FAIL with exact errors.
2. source_commit vs tested_commit mismatch, and expected HEAD mismatch -> FAIL.
3. False working_tree_clean claim when working tree is dirty -> FAIL.
4. JUnit XML with failures, errors, 0 tests, or all skipped -> FAIL.
5. Count mismatch between raw log and JUnit XML -> FAIL.
6. ZIP package inventory mismatch: modified file hash or undeclared file -> FAIL.
7. Forbidden secret/database file leaked inside ZIP archive -> FAIL.
8. False Gate PASS or PUBLIC PACKAGED RELEASE claim in report without evidence -> FAIL.
9. Positive end-to-end: real pytest execution, real JUnit XML, real raw log, real ZIP inventory -> PASS.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.validate_evidence_manifest import (
    compute_sha256,
    compute_tree_fingerprint_from_entries,
    validate_manifest,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def make_clean_zip(zip_path: Path, files: dict[str, bytes]) -> tuple[int, str, list[dict]]:
    manifest_entries = []
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in files.items():
            zf.writestr(rel_path, content)
            c_sha = hashlib.sha256(content).hexdigest().upper()
            manifest_entries.append(
                {
                    "relative_path": rel_path.replace("\\", "/"),
                    "size_bytes": len(content),
                    "sha256": c_sha,
                }
            )
    zip_bytes = zip_path.read_bytes()
    zip_size = len(zip_bytes)
    zip_sha = hashlib.sha256(zip_bytes).hexdigest().upper()
    return zip_size, zip_sha, manifest_entries


def create_base_manifest(
    tmp_path: Path,
    source_commit: str = "a" * 40,
    tested_commit: str = "a" * 40,
    files_in_zip: dict[str, bytes] | None = None,
    log_content: str = "",
    junit_content: str = "",
    extra_fields: dict | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    if files_in_zip is None:
        files_in_zip = {"app.py": b"print('production safe code')\n"}

    zip_file = tmp_path / "package.zip"
    zip_size, zip_sha, manifest_files = make_clean_zip(zip_file, files_in_zip)
    tree_fp = compute_tree_fingerprint_from_entries(manifest_files)
    run_id = f"testrun-fixture-{hashlib.sha256(tree_fp.encode()).hexdigest()[:8]}"

    if log_content and "test session starts" in log_content and run_id not in log_content:
        log_content = f"RUN_ID: {run_id}\n" + log_content

    log_file = tmp_path / "regression_full_run.log"
    log_file.write_text(log_content, encoding="utf-8")

    junit_file = tmp_path / "regression_junit.xml"
    junit_file.write_text(junit_content, encoding="utf-8")

    log_sha = compute_sha256(log_file) if log_file.exists() else ""
    junit_sha = compute_sha256(junit_file) if junit_file.exists() else ""

    manifest_data = {
        "schema_version": "1.0.0",
        "version": "v1.0.0-rc2",
        "package_name": "package.zip",
        "zip_path": str(zip_file),
        "zip_size_bytes": zip_size,
        "zip_sha256": zip_sha,
        "tree_fingerprint": tree_fp,
        "run_id": run_id,
        "secret_scan_passed": True,
        "secret_violations": 0,
        "included_files_count": len(manifest_files),
        "files": manifest_files,
        "build_id": "build-test-semantic",
        "repository": str(tmp_path),
        "branch": "main",
        "source_commit": source_commit,
        "tested_commit": tested_commit,
        "raw_evidence_log": str(log_file),
        "raw_evidence_junit": str(junit_file),
        "test_run_attestation": {
            "run_id": run_id,
            "source_sha": source_commit,
            "tree_fingerprint": tree_fp,
            "tree_mutated_during_test": False,
            "pytest_command": "pytest tests/ -v --junitxml=runtime/evidence/regression_junit.xml",
            "started_at": "2026-10-30T10:00:00Z",
            "completed_at": "2026-10-30T10:00:05Z",
            "duration_seconds": 5.0,
            "exit_code": 0,
            "junit_path": str(junit_file),
            "junit_sha256": junit_sha,
            "log_path": str(log_file),
            "log_sha256": log_sha,
            "environment": {
                "python_version": sys.version,
                "platform": sys.platform,
                "executable": sys.executable,
                "requirements_sha256": "DUMMYREQSHA256",
            },
        },
    }
    if extra_fields:
        manifest_data.update(extra_fields)

    m_path = tmp_path / "release-manifest.json"
    m_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    return m_path


def test_01_auditor_repro_two_fake_shas_invalid_xml_meaningless_log_fails(tmp_path: Path):
    """Auditor Reproduction: two fake SHAs + 'NOT VALID XML' + 'meaningless log' + valid ZIP -> MUST FAIL."""
    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit="1111111111111111111111111111111111111111",
        tested_commit="2222222222222222222222222222222222222222",
        log_content="meaningless log",
        junit_content="NOT VALID XML",
    )

    ok, errors = validate_manifest(manifest_path, check_git=False)

    assert ok is False
    assert any("source_commit != tested_commit" in e for e in errors)
    assert any("Invalid JUnit XML" in e for e in errors)
    assert any("Raw log missing valid pytest execution markers and summary" in e for e in errors)


def test_02_source_vs_tested_commit_mismatch_and_head_mismatch_fails(tmp_path: Path):
    """Commit mismatch between source/tested and mismatch against expected commit SHA."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 2 items\n\n"
        "test_a.py .. [100%]\n"
        "============================== 2 passed in 0.12s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        '  <testcase classname="test_a" name="test_2" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 1. source_commit != tested_commit
    m_path1 = create_base_manifest(
        tmp_path=tmp_path / "case1",
        source_commit="a" * 40,
        tested_commit="b" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
    )
    ok1, errors1 = validate_manifest(m_path1, check_git=False)
    assert ok1 is False
    assert any("source_commit != tested_commit" in e for e in errors1)

    # 2. Both equal, but mismatch against expected_commit
    m_path2 = create_base_manifest(
        tmp_path=tmp_path / "case2",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
    )
    expected_head = "c" * 40
    ok2, errors2 = validate_manifest(m_path2, expected_commit=expected_head, check_git=False)
    assert ok2 is False
    assert any("Commit mismatch with expected HEAD" in e for e in errors2)


def test_03_dirty_tree_false_clean_claim_fails(tmp_path: Path):
    """Manifest declares working_tree_clean=True, but git status reports dirty files -> FAIL."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit="e" * 40,
        tested_commit="e" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"working_tree_clean": True},
    )

    # Mock git status returning dirty files outside allowed list
    mock_status_res = MagicMock()
    mock_status_res.returncode = 0
    mock_status_res.stdout = " M backend/core.py\n?? untracked_script.py\n"

    mock_rev_parse_res = MagicMock()
    mock_rev_parse_res.returncode = 0
    mock_rev_parse_res.stdout = "e" * 40 + "\n"

    def mock_subprocess_run(cmd, **kwargs):
        if cmd[1] == "status":
            return mock_status_res
        if cmd[1] == "rev-parse":
            return mock_rev_parse_res
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        ok, errors = validate_manifest(manifest_path, check_git=True)

    assert ok is False
    assert any("Dirty working tree contradicts manifest clean claim" in e for e in errors)
    assert any("backend/core.py" in e for e in errors)


def test_04_junit_with_failures_or_zero_tests_fails(tmp_path: Path):
    """Valid XML structure but semantic test failures, errors, zero tests, or all skipped -> FAIL."""
    valid_log_dummy = (
        "============================= test session starts =============================\n"
        "collected 2 items\n\n"
        "============================== 1 passed, 1 failed in 0.10s ====================\n"
    )

    # 4a: JUnit with failures
    junit_with_failure = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="2" failures="1" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_ok" time="0.01" />\n'
        '  <testcase classname="test_a" name="test_fail" time="0.02">\n'
        '    <failure message="assertion error">AssertionError</failure>\n'
        "  </testcase>\n"
        "</testsuite></testsuites>"
    )
    m_path_fail = create_base_manifest(
        tmp_path=tmp_path / "case_fail",
        source_commit="f" * 40,
        tested_commit="f" * 40,
        log_content=valid_log_dummy,
        junit_content=junit_with_failure,
    )
    ok_fail, errors_fail = validate_manifest(m_path_fail, check_git=False)
    assert ok_fail is False
    assert any("JUnit contains failures or errors" in e for e in errors_fail)

    # 4b: JUnit with 0 tests
    junit_zero = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="0" failures="0" errors="0" skipped="0">\n'
        "</testsuite></testsuites>"
    )
    m_path_zero = create_base_manifest(
        tmp_path=tmp_path / "case_zero",
        source_commit="f" * 40,
        tested_commit="f" * 40,
        log_content="test session starts\n=========== 0 passed in 0.01s ===========",
        junit_content=junit_zero,
    )
    ok_zero, errors_zero = validate_manifest(m_path_zero, check_git=False)
    assert ok_zero is False
    assert any("Zero tests in JUnit" in e for e in errors_zero)

    # 4c: JUnit with all tests skipped
    junit_all_skipped = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="1">\n'
        '  <testcase classname="test_a" name="test_skipped" time="0.001">\n'
        '    <skipped message="skip reason">skipped</skipped>\n'
        "  </testcase>\n"
        "</testsuite></testsuites>"
    )
    m_path_skip = create_base_manifest(
        tmp_path=tmp_path / "case_skip",
        source_commit="f" * 40,
        tested_commit="f" * 40,
        log_content="test session starts\n=========== 1 skipped in 0.01s ===========",
        junit_content=junit_all_skipped,
    )
    ok_skip, errors_skip = validate_manifest(m_path_skip, check_git=False)
    assert ok_skip is False
    assert any("All tests were skipped" in e for e in errors_skip)


def test_05_log_junit_count_mismatch_fails(tmp_path: Path):
    """JUnit reports 10 tests passed, but raw log reports 8 passed -> FAIL."""
    testcases_xml = "".join(
        f'<testcase classname="pkg.test" name="test_{i}" time="0.01" />\n' for i in range(10)
    )
    junit_10 = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="10" failures="0" errors="0" skipped="0">\n'
        f"{testcases_xml}"
        "</testsuite></testsuites>"
    )
    log_8 = (
        "============================= test session starts =============================\n"
        "collected 10 items\n\n"
        "pkg/test.py ........ [100%]\n"
        "============================== 8 passed in 1.45s ==============================\n"
    )

    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=log_8,
        junit_content=junit_10,
    )

    ok, errors = validate_manifest(manifest_path, check_git=False)
    assert ok is False
    assert any("Count mismatch between raw log and JUnit XML" in e for e in errors)


def test_06_zip_inventory_hash_mismatch_or_extra_file_fails(tmp_path: Path):
    """Tampered file content in ZIP, or extra unmanifested file in ZIP -> FAIL."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 6a: File hash mismatch (manifest recorded original hash, zip contains modified content)
    case_a_dir = tmp_path / "case_a"
    case_a_dir.mkdir(parents=True, exist_ok=True)
    manifest_path_a = create_base_manifest(
        tmp_path=case_a_dir,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        files_in_zip={"backend/app.py": b"AUTHENTIC_ORIGINAL_CODE"},
        log_content=valid_log,
        junit_content=valid_junit,
    )
    # Tamper with the zip archive directly
    zip_p_a = case_a_dir / "package.zip"
    with zipfile.ZipFile(zip_p_a, "w") as zf:
        zf.writestr("backend/app.py", b"TAMPERED_BACKDOOR_CODE")
    # Update zip-level hash in manifest to bypass outer check, isolating file-level hash check
    m_data_a = json.loads(manifest_path_a.read_text(encoding="utf-8"))
    m_data_a["zip_size_bytes"] = zip_p_a.stat().st_size
    m_data_a["zip_sha256"] = compute_sha256(zip_p_a)
    manifest_path_a.write_text(json.dumps(m_data_a, indent=2), encoding="utf-8")

    ok_a, errors_a = validate_manifest(manifest_path_a, check_git=False)
    assert ok_a is False
    assert any("SHA-256 mismatch" in e for e in errors_a)

    # 6b: Undeclared extra file inside ZIP
    case_b_dir = tmp_path / "case_b"
    case_b_dir.mkdir(parents=True, exist_ok=True)
    manifest_path_b = create_base_manifest(
        tmp_path=case_b_dir,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        files_in_zip={"backend/app.py": b"AUTHENTIC_CODE"},
        log_content=valid_log,
        junit_content=valid_junit,
    )
    zip_p_b = case_b_dir / "package.zip"
    with zipfile.ZipFile(zip_p_b, "w") as zf:
        zf.writestr("backend/app.py", b"AUTHENTIC_CODE")
        zf.writestr("rogue_payload.py", b"print('surprise')")
    m_data_b = json.loads(manifest_path_b.read_text(encoding="utf-8"))
    m_data_b["zip_size_bytes"] = zip_p_b.stat().st_size
    m_data_b["zip_sha256"] = compute_sha256(zip_p_b)
    manifest_path_b.write_text(json.dumps(m_data_b, indent=2), encoding="utf-8")

    ok_b, errors_b = validate_manifest(manifest_path_b, check_git=False)
    assert ok_b is False
    assert any("Inventory mismatch between manifest and ZIP archive" in e for e in errors_b)
    assert any("rogue_payload.py" in e for e in errors_b)


def test_07_secret_or_db_leaked_in_zip_fails(tmp_path: Path):
    """Forbidden secret extensions (.key, .pem, .db) or secret directories leaked inside ZIP -> FAIL."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        files_in_zip={
            "app.py": b"safe code",
            "runtime/secrets/master.key": b"SUPER_SECRET_KEY_MATERIAL",
            "runtime/tasks.db": b"SQLITE_FORMAT_3_DB_CONTENT",
        },
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"secret_scan_passed": True, "secret_violations": 0},
    )

    ok, errors = validate_manifest(manifest_path, check_git=False)
    assert ok is False
    assert any("Forbidden secret or state file leaked inside ZIP archive" in e for e in errors)
    assert any("master.key" in e or "tasks.db" in e for e in errors)


def test_08_false_gate_pass_in_report_fails(tmp_path: Path):
    """Report declares 'VERDICT: GO FOR PUBLIC PACKAGED RELEASE' without required g6_clean_vm_evidence -> FAIL."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    report_file = tmp_path / "TEST_RELEASE_REPORT.md"
    report_file.write_text(
        "# RELEASE VERIFICATION REPORT\n\n"
        "| **G6** | Clean Bare VM | PASS |\n\n"
        "VERDICT: GO FOR PUBLIC PACKAGED RELEASE\n",
        encoding="utf-8",
    )

    # Manifest lacks g6_clean_vm_evidence
    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
    )

    ok, errors = validate_manifest(manifest_path, check_git=False, report_path=report_file)
    assert ok is False
    assert any("False PASS claim in report without required layer evidence" in e for e in errors)


def test_09_positive_real_pytest_mini_run_passes(tmp_path: Path):
    """Positive test: executes real pytest command, produces real JUnit XML & log, packages clean ZIP -> PASS."""
    # 1. Create a real mini test file
    test_file = tmp_path / "test_mini.py"
    test_file.write_text(
        "def test_addition():\n"
        "    assert 1 + 1 == 2\n\n"
        "def test_string():\n"
        "    assert 'hello'.upper() == 'HELLO'\n",
        encoding="utf-8",
    )

    junit_file = tmp_path / "real_junit.xml"
    log_file = tmp_path / "real_pytest.log"

    # 2. Run real pytest process generating real XML and real log
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(test_file),
        f"--junitxml={junit_file}",
        "-o",
        "junit_family=xunit2",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    log_file.write_text(proc.stdout, encoding="utf-8")

    assert junit_file.exists()
    assert log_file.exists()

    # 3. Create real zip package with tested file
    zip_file = tmp_path / "real_release.zip"
    zip_size, zip_sha, file_entries = make_clean_zip(
        zip_file,
        {"test_mini.py": test_file.read_bytes()},
    )

    # 4. Create manifest referencing all genuine outputs
    commit_sha = "d" * 40
    tree_fp = compute_tree_fingerprint_from_entries(file_entries)
    run_id = f"testrun-real-{commit_sha[:8]}"
    log_file.write_text(f"RUN_ID: {run_id}\n" + log_file.read_text(encoding="utf-8"), encoding="utf-8")
    log_sha = compute_sha256(log_file)
    junit_sha = compute_sha256(junit_file)
    manifest_data = {
        "schema_version": "1.0.0",
        "version": "v1.0.0",
        "package_name": "real_release.zip",
        "zip_path": str(zip_file),
        "zip_size_bytes": zip_size,
        "zip_sha256": zip_sha,
        "tree_fingerprint": tree_fp,
        "run_id": run_id,
        "secret_scan_passed": True,
        "secret_violations": 0,
        "included_files_count": len(file_entries),
        "files": file_entries,
        "build_id": "build-real-test",
        "repository": str(tmp_path),
        "branch": "main",
        "source_commit": commit_sha,
        "tested_commit": commit_sha,
        "raw_evidence_log": str(log_file),
        "raw_evidence_junit": str(junit_file),
        "working_tree_clean": False,
        "junit_summary": {
            "tests": 2,
            "passed": 2,
            "skipped": 0,
            "failures": 0,
            "errors": 0,
        },
        "test_run_attestation": {
            "run_id": run_id,
            "source_sha": commit_sha,
            "tree_fingerprint": tree_fp,
            "tree_mutated_during_test": False,
            "pytest_command": "pytest test_mini.py -v",
            "started_at": "2026-10-30T10:00:00Z",
            "completed_at": "2026-10-30T10:00:05Z",
            "duration_seconds": 5.0,
            "exit_code": 0,
            "junit_path": str(junit_file),
            "junit_sha256": junit_sha,
            "log_path": str(log_file),
            "log_sha256": log_sha,
            "environment": {
                "python_version": sys.version,
                "platform": sys.platform,
                "executable": sys.executable,
                "requirements_sha256": "DUMMY",
            },
        },
    }
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # 5. Validate manifest with matching expected commit
    ok, errors = validate_manifest(
        manifest_path=manifest_path,
        expected_commit=commit_sha,
        check_git=False,
    )

    assert errors == []
    assert ok is True


def test_10_l3_evidence_cannot_substitute_for_l4_chatgpt_web_fails(tmp_path: Path):
    """Section 9: Manifest or report claiming G5 / L4 PASS must fail if L3 evidence is used or L4 missing."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 10a. Manifest claims g5_status="PASS" but no l4_live_chatgpt_web_evidence
    m_path_missing = create_base_manifest(
        tmp_path=tmp_path / "case_l4_missing",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"g5_status": "PASS"},
    )
    ok_missing, errors_missing = validate_manifest(m_path_missing, check_git=False)
    assert ok_missing is False
    assert any("False PASS claim: L3 evidence cannot substitute for L4 ChatGPT Web acceptance" in e for e in errors_missing)

    # 10b. Manifest claims g5_status="PASS" but l4_live_chatgpt_web_evidence has layer="L3_REAL_SOCKET"
    m_path_l3 = create_base_manifest(
        tmp_path=tmp_path / "case_l3_substitute",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g5_status": "PASS",
            "l4_live_chatgpt_web_evidence": {
                "layer": "L3_REAL_SOCKET",
                "port": 8769,
            },
        },
    )
    ok_l3, errors_l3 = validate_manifest(m_path_l3, check_git=False)
    assert ok_l3 is False
    assert any("False PASS claim: L3 evidence cannot substitute for L4 ChatGPT Web acceptance" in e for e in errors_l3)

    # 10c. Report claims G5 PASS and manifest lacks valid L4 evidence -> FAIL
    rep_file = tmp_path / "case_rep_l4" / "REPORT.md"
    rep_file.parent.mkdir(parents=True, exist_ok=True)
    rep_file.write_text(
        "| **G5** | L4 ChatGPT Web | PASS |\n",
        encoding="utf-8",
    )
    m_path_rep = create_base_manifest(
        tmp_path=tmp_path / "case_rep_l4",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
    )
    ok_rep, errors_rep = validate_manifest(m_path_rep, check_git=False, report_path=rep_file)
    assert ok_rep is False
    assert any("False PASS claim: L3 evidence cannot substitute for L4 ChatGPT Web acceptance" in e for e in errors_rep)

    # 10d-1. Incomplete L4 evidence (only layer and click flag, missing nonce/audit/windows effect) -> FAIL
    m_path_incomplete = create_base_manifest(
        tmp_path=tmp_path / "case_l4_incomplete",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g5_status": "PASS",
            "l4_live_chatgpt_web_evidence": {
                "layer": "L4_LIVE_CHATGPT_WEB",
                "live_browser_click_verified": True,
            },
        },
    )
    ok_inc, errors_inc = validate_manifest(m_path_incomplete, check_git=False)
    assert ok_inc is False
    assert any("missing valid request_nonce" in e for e in errors_inc)

    # 10d-2. Complete, genuinely attested L4 evidence with real files on disk -> PASS
    case_dir = tmp_path / "case_l4_valid"
    case_dir.mkdir(parents=True, exist_ok=True)
    nonce = "NONCE_TEST_1234567890_XYZ"
    audit_file = case_dir / "audit.jsonl"
    audit_ev_id = "evt_l4_accept_123"
    audit_file.write_bytes(f'{{"event_id": "{audit_ev_id}", "nonce": "{nonce}", "tool": "powershell_execute"}}\n'.encode("utf-8"))

    effect_file = case_dir / "observed_effect.txt"
    effect_content = f"Effect verification completed with nonce {nonce}\n"
    effect_file.write_bytes(effect_content.encode("utf-8"))
    effect_sha = compute_sha256(effect_file)

    commit_sha = "a" * 40
    build_id = "build-test-semantic"

    m_path_valid = create_base_manifest(
        tmp_path=case_dir,
        source_commit=commit_sha,
        tested_commit=commit_sha,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "build_id": build_id,
            "g5_status": "PASS",
            "l4_live_chatgpt_web_evidence": {
                "layer": "L4_LIVE_CHATGPT_WEB",
                "live_browser_click_verified": True,
                "request_nonce": nonce,
                "cloud_request_id": "req-cloud-9999",
                "connector_tunnel_id": "tunnel_active_production_123",
                "auth_principal": {
                    "subject": "owner@domain.test",
                    "client_id": "client_app_123",
                },
                "deployed_build_id": build_id,
                "deployed_commit_sha": commit_sha,
                "audit_log_path": str(audit_file),
                "audit_event_id": audit_ev_id,
                "observed_windows_effect": {
                    "effect_path": str(effect_file),
                    "expected_sha256": effect_sha,
                },
            },
        },
    )
    ok_valid, errors_valid = validate_manifest(m_path_valid, check_git=False)
    assert ok_valid is True, f"Expected L4 validation PASS, got errors: {errors_valid}"
    assert errors_valid == []


def test_11_soak_under_1800s_cannot_be_marked_pass_fails(tmp_path: Path):
    """Section 9: Manifest or report claiming G4/Soak PASS with duration < 1800s must FAIL."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 11a. G4 claimed PASS but soak_evidence missing
    m_path_missing = create_base_manifest(
        tmp_path=tmp_path / "case_soak_missing",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"g4_status": "PASS"},
    )
    ok_missing, errors_missing = validate_manifest(m_path_missing, check_git=False)
    assert ok_missing is False
    assert any("False PASS claim: Soak duration under 1800s (30 minutes) cannot be marked PASS/CLOSED" in e for e in errors_missing)

    # 11b. G4 claimed PASS with soak duration = 300s (< 1800s)
    m_path_short = create_base_manifest(
        tmp_path=tmp_path / "case_soak_short",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g4_status": "PASS",
            "soak_evidence": {
                "duration_seconds": 300,
                "operations_count": 100,
            },
        },
    )
    ok_short, errors_short = validate_manifest(m_path_short, check_git=False)
    assert ok_short is False
    assert any("False PASS claim: Soak duration under 1800s (30 minutes) cannot be marked PASS/CLOSED" in e for e in errors_short)

    # 11c. G4 claimed in report with duration = 1200s (< 1800s)
    rep_file = tmp_path / "case_rep_soak" / "REPORT.md"
    rep_file.parent.mkdir(parents=True, exist_ok=True)
    rep_file.write_text(
        "| **G4** | 30-minute soak | CLOSED |\n",
        encoding="utf-8",
    )
    m_path_rep = create_base_manifest(
        tmp_path=tmp_path / "case_rep_soak",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "soak_evidence": {
                "duration_seconds": 1200,
            },
        },
    )
    ok_rep, errors_rep = validate_manifest(m_path_rep, check_git=False, report_path=rep_file)
    assert ok_rep is False
    assert any("False PASS claim: Soak duration under 1800s (30 minutes) cannot be marked PASS/CLOSED" in e for e in errors_rep)

    # 11d. Valid 1800s soak evidence -> PASS
    m_path_valid = create_base_manifest(
        tmp_path=tmp_path / "case_soak_valid",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g4_status": "PASS",
            "soak_evidence": {
                "duration_seconds": 1800,
                "operations_count": 500,
            },
        },
    )
    ok_valid, errors_valid = validate_manifest(m_path_valid, check_git=False)
    assert ok_valid is True
    assert errors_valid == []


def test_12_fake_vm_cannot_be_marked_g6_clean_vm_pass_fails(tmp_path: Path):
    """Section 9: Manifest or report claiming G6 / Clean Windows VM / Public Packaged Release requires isolated VM."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 12a. G6 claimed PASS but g6_clean_vm_evidence missing
    m_path_missing = create_base_manifest(
        tmp_path=tmp_path / "case_vm_missing",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"g6_status": "PASS"},
    )
    ok_missing, errors_missing = validate_manifest(m_path_missing, check_git=False)
    assert ok_missing is False
    assert any("is_isolated_clean_vm" in e for e in errors_missing)

    # 12b. G6 claimed PASS but is_isolated_clean_vm=False
    m_path_fake = create_base_manifest(
        tmp_path=tmp_path / "case_vm_fake",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g6_status": "PASS",
            "g6_clean_vm_evidence": {
                "is_isolated_clean_vm": False,
                "hostname": "local-dev-box",
            },
        },
    )
    ok_fake, errors_fake = validate_manifest(m_path_fake, check_git=False)
    assert ok_fake is False
    assert any("is_isolated_clean_vm" in e for e in errors_fake)

    # 12c. Valid clean VM evidence -> PASS
    m_path_valid = create_base_manifest(
        tmp_path=tmp_path / "case_vm_valid",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g6_status": "PASS",
            "g6_clean_vm_evidence": {
                "is_isolated_clean_vm": True,
                "hypervisor": "hyper-v",
                "snapshot_restored": True,
            },
        },
    )
    ok_valid, errors_valid = validate_manifest(m_path_valid, check_git=False)
    assert ok_valid is True
    assert errors_valid == []


def test_13_unconfigured_provider_cannot_be_marked_g2_autonomous_ai_pass_fails(tmp_path: Path):
    """Section 9: Manifest or report claiming G2 / Autonomous AI PASS requires configured provider evidence."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 13a. G2 claimed PASS but g2_provider_evidence missing
    m_path_missing = create_base_manifest(
        tmp_path=tmp_path / "case_g2_missing",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"g2_status": "PASS"},
    )
    ok_missing, errors_missing = validate_manifest(m_path_missing, check_git=False)
    assert ok_missing is False
    assert any("provider_configured" in e for e in errors_missing)

    # 13b. G2 claimed PASS but provider_configured=False
    m_path_unconf = create_base_manifest(
        tmp_path=tmp_path / "case_g2_unconf",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g2_status": "PASS",
            "g2_provider_evidence": {
                "provider_configured": False,
                "status": "MODEL_PROVIDER_NOT_CONFIGURED",
            },
        },
    )
    ok_unconf, errors_unconf = validate_manifest(m_path_unconf, check_git=False)
    assert ok_unconf is False
    assert any("provider_configured" in e for e in errors_unconf)

    # 13c. Valid configured provider -> PASS
    m_path_valid = create_base_manifest(
        tmp_path=tmp_path / "case_g2_valid",
        source_commit="a" * 40,
        tested_commit="a" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={
            "g2_status": "PASS",
            "g2_provider_evidence": {
                "provider_configured": True,
                "provider": "openai",
                "model": "gpt-4o",
            },
        },
    )
    ok_valid, errors_valid = validate_manifest(m_path_valid, check_git=False)
    assert ok_valid is True
    assert errors_valid == []


def test_14_defect01_repro_stale_report_sha_test_count_and_file_count_rejected(tmp_path: Path):
    """DEFECT-01: Stale report claiming outdated commit SHA, test counts, or packaged file count must be rejected."""
    # Manifest generated for current source freeze
    current_commit = "8fee870de28ac51e25af245bb4d51694404f6f49"
    total_tests = 363
    passed_tests = 362
    skipped_tests = 1
    file_count = 260

    testcases_xml = "".join(
        f'<testcase classname="test_pkg" name="test_{i}" time="0.001" />\n'
        for i in range(passed_tests)
    ) + '<testcase classname="test_pkg" name="test_skip" time="0.001"><skipped message="skip"/></testcase>\n'

    junit_xml = (
        f'<?xml version="1.0" encoding="utf-8"?>\n'
        f'<testsuites><testsuite name="pytest" tests="{total_tests}" failures="0" errors="0" skipped="{skipped_tests}">\n'
        f'{testcases_xml}'
        f'</testsuite></testsuites>'
    )
    raw_log = (
        "============================= test session starts =============================\n"
        f"collected {total_tests} items\n\n"
        f"======================== {passed_tests} passed, {skipped_tests} skipped in 12.34s ========================\n"
    )

    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit=current_commit,
        tested_commit=current_commit,
        log_content=raw_log,
        junit_content=junit_xml,
        extra_fields={
            "included_files_count": file_count,
            "junit_summary": {
                "tests": total_tests,
                "passed": passed_tests,
                "skipped": skipped_tests,
                "failures": 0,
                "errors": 0,
            },
        },
    )

    # Stale report with DEFECT-01 discrepancies:
    # 1. Stale commit SHA: f9004fd5d9d36c98224befaefed8fdc7eb02c750 vs current 8fee870de28ac51e25af245bb4d51694404f6f49
    # 2. Stale test count: 350 test items (349 passed) vs current 363 (362 passed)
    # 3. Stale file count: 254 files packaged vs current 260
    stale_report = tmp_path / "STALE_RELEASE_REPORT.md"
    stale_report.write_text(
        "# Windows MCP Agent Release Report\n\n"
        "**Commit**: f9004fd5d9d36c98224befaefed8fdc7eb02c750\n"
        "- Full tracked file inventory verified (254 files in release manifest)\n"
        "- Total Unit & Integration Tests: 350 test items (349 passed, 1 skipped, 0 failed, 0 errors)\n",
        encoding="utf-8",
    )

    ok, errors = validate_manifest(
        manifest_path=manifest_path,
        check_git=False,
        report_path=stale_report,
    )

    assert ok is False
    assert any("report claims 254 packaged files, but manifest has 260" in e for e in errors), f"Missing file count mismatch: {errors}"
    assert any("report claims test count 350, but JUnit XML/manifest has tests=363" in e for e in errors), f"Missing total test count mismatch: {errors}"
    assert any("report claims commit 'f9004fd5d9d36c98224befaefed8fdc7eb02c750', but manifest has '8fee870de28ac51e25af245bb4d51694404f6f49'" in e for e in errors), f"Missing commit mismatch: {errors}"


def test_15_defect04_repro_machine_config_or_canary_in_zip_rejected(tmp_path: Path):
    """DEFECT-04: ZIP archives containing host-specific config files, canary secrets, or developer paths must be rejected."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 15a: ZIP contains host-specific config/policy.json (not .example.json)
    case_a_dir = tmp_path / "case_config_leak"
    case_a_dir.mkdir(parents=True, exist_ok=True)
    m_path_a = create_base_manifest(
        tmp_path=case_a_dir,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        files_in_zip={
            "backend/app.py": b"print('ok')",
            "config/policy.json": b'{"profiles": {"full_agent": true}}',
        },
        log_content=valid_log,
        junit_content=valid_junit,
    )
    ok_a, errors_a = validate_manifest(m_path_a, check_git=False)
    assert ok_a is False
    assert any("Forbidden host-specific config file leaked inside ZIP archive: 'config/policy.json'" in e for e in errors_a)

    # 15b: ZIP contains CANARY_SECRET_TOKEN_999
    case_b_dir = tmp_path / "case_canary_secret"
    case_b_dir.mkdir(parents=True, exist_ok=True)
    m_path_b = create_base_manifest(
        tmp_path=case_b_dir,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        files_in_zip={
            "backend/app.py": b"SECRET_TOKEN = 'CANARY_SECRET_TOKEN_999'",
        },
        log_content=valid_log,
        junit_content=valid_junit,
    )
    ok_b, errors_b = validate_manifest(m_path_b, check_git=False)
    assert ok_b is False
    assert any("Forbidden host path or canary secret leaked inside ZIP archive" in e for e in errors_b)

    # 15c: ZIP config file contains developer machine path C:\Users\ExampleUser
    case_c_dir = tmp_path / "case_dev_path"
    case_c_dir.mkdir(parents=True, exist_ok=True)
    m_path_c = create_base_manifest(
        tmp_path=case_c_dir,
        source_commit="a" * 40,
        tested_commit="a" * 40,
        files_in_zip={
            "config/policy.example.json": b'{"root": "C:\\\\Users\\\\Admin\\\\Desktop"}',
        },
        log_content=valid_log,
        junit_content=valid_junit,
    )
    ok_c, errors_c = validate_manifest(m_path_c, check_git=False)
    assert ok_c is False
    assert any("Forbidden host path or canary secret leaked inside ZIP archive: 'config/policy.example.json'" in e for e in errors_c)


def test_16_strict_clean_working_tree_fails_on_any_dirty_file(tmp_path: Path):
    """Section 9: Strict Clean Working Tree - any modified or untracked file fails when working_tree_clean=True."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    manifest_path = create_base_manifest(
        tmp_path=tmp_path,
        source_commit="e" * 40,
        tested_commit="e" * 40,
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"working_tree_clean": True},
    )

    # Test that even a dirty file in dist/ fails when working_tree_clean=True
    mock_status_res = MagicMock()
    mock_status_res.returncode = 0
    mock_status_res.stdout = " M dist/release-manifest.json\n"

    mock_rev_parse_res = MagicMock()
    mock_rev_parse_res.returncode = 0
    mock_rev_parse_res.stdout = "e" * 40 + "\n"

    def mock_subprocess_run(cmd, **kwargs):
        if cmd[1] == "status":
            return mock_status_res
        if cmd[1] == "rev-parse":
            return mock_rev_parse_res
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        ok, errors = validate_manifest(manifest_path, check_git=True)

    assert ok is False
    assert any("Dirty working tree contradicts manifest clean claim" in e for e in errors)
    assert any("dist/release-manifest.json" in e for e in errors)


def test_17_task102_stale_tree_fingerprint_tampered_junit_or_unattested_run_rejected(tmp_path: Path):
    """TASK-102: Provenance correctness - stale tree fingerprint, tampered JUnit, or unattested run rejected."""
    valid_log = (
        "============================= test session starts =============================\n"
        "collected 1 item\n\ntest_a.py . [100%]\n"
        "============================== 1 passed in 0.05s ==============================\n"
    )
    valid_junit = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">\n'
        '  <testcase classname="test_a" name="test_1" time="0.01" />\n'
        "</testsuite></testsuites>"
    )

    # 17a. Stale tree fingerprint: source modified after test run
    m_path_stale_fp = create_base_manifest(
        tmp_path=tmp_path / "case_17a_stale_fp",
        log_content=valid_log,
        junit_content=valid_junit,
    )
    data_17a = json.loads(m_path_stale_fp.read_text(encoding="utf-8"))
    data_17a["test_run_attestation"]["tree_fingerprint"] = "0000000000000000000000000000000000000000000000000000000000000000"
    m_path_stale_fp.write_text(json.dumps(data_17a, indent=2), encoding="utf-8")
    ok_17a, errors_17a = validate_manifest(m_path_stale_fp, check_git=False)
    assert ok_17a is False
    assert any("Stale test-run attestation: tree_fingerprint mismatch" in e for e in errors_17a)

    # 17b. Tampered JUnit XML or raw log after test run (hash mismatch)
    m_path_tampered = create_base_manifest(
        tmp_path=tmp_path / "case_17b_tampered",
        log_content=valid_log,
        junit_content=valid_junit,
    )
    # Modify JUnit file on disk without updating attestation hash
    j_file = tmp_path / "case_17b_tampered" / "regression_junit.xml"
    j_file.write_text(valid_junit + "\n<!-- Tampered content -->", encoding="utf-8")
    ok_17b, errors_17b = validate_manifest(m_path_tampered, check_git=False)
    assert ok_17b is False
    assert any("Test-run attestation junit_sha256 mismatch" in e for e in errors_17b)

    # 17c. Exit code != 0 or missing attestation
    m_path_fail_exit = create_base_manifest(
        tmp_path=tmp_path / "case_17c_exit_code",
        log_content=valid_log,
        junit_content=valid_junit,
    )
    data_17c = json.loads(m_path_fail_exit.read_text(encoding="utf-8"))
    data_17c["test_run_attestation"]["exit_code"] = 1
    m_path_fail_exit.write_text(json.dumps(data_17c, indent=2), encoding="utf-8")
    ok_17c, errors_17c = validate_manifest(m_path_fail_exit, check_git=False)
    assert ok_17c is False
    assert any("Test-run attestation failed: exit_code != 0" in e for e in errors_17c)

    m_path_no_att = create_base_manifest(
        tmp_path=tmp_path / "case_17c_no_att",
        log_content=valid_log,
        junit_content=valid_junit,
        extra_fields={"test_run_attestation": None},
    )
    ok_no_att, errors_no_att = validate_manifest(m_path_no_att, check_git=False)
    assert ok_no_att is False
    assert any("Manifest missing valid 'test_run_attestation' dictionary" in e for e in errors_no_att)

    # 17d. Build-ReleasePackage.ps1 with stale attestation generates UNATTESTED_OR_STALE_TEST_RUN
    # and validate_manifest immediately rejects it
    dist_dir = tmp_path / "case_17d_dist"
    stale_att_file = tmp_path / "case_17d_stale_att.json"
    stale_att_file.write_text(json.dumps({
        "run_id": "testrun-stale-commit",
        "source_sha": "0000000000000000000000000000000000000000",
        "tree_fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
        "tree_mutated_during_test": False,
        "pytest_command": "pytest",
        "started_at": "2026-10-30T10:00:00Z",
        "completed_at": "2026-10-30T10:00:05Z",
        "duration_seconds": 5.0,
        "exit_code": 0,
        "junit_path": "runtime/evidence/regression_junit.xml",
        "junit_sha256": "DUMMY",
        "log_path": "runtime/evidence/regression_full_run.log",
        "log_sha256": "DUMMY",
        "environment": {"python_version": sys.version, "platform": sys.platform, "executable": sys.executable, "requirements_sha256": ""},
    }), encoding="utf-8")

    ps_script = PROJECT_ROOT / "scripts" / "Build-ReleasePackage.ps1"
    res = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script), "-OutputDir", str(dist_dir), "-AttestationPath", str(stale_att_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"Build script failed: {res.stdout}\n{res.stderr}"

    pkg_manifest = dist_dir / "release-manifest.json"
    assert pkg_manifest.exists()
    pkg_data = json.loads(pkg_manifest.read_text(encoding="utf-8"))
    assert pkg_data.get("tested_commit") == "UNATTESTED_OR_STALE_TEST_RUN"
    assert pkg_data.get("test_run_attestation") is None

    ok_17d, errors_17d = validate_manifest(pkg_manifest, check_git=False)
    assert ok_17d is False
    assert any("must be a 40-character git commit SHA" in e for e in errors_17d)

