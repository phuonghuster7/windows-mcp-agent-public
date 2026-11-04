"""Stage S6 (P6) Automated Verification Suite:
Portable Installer, Updater, Repair, ChatGPT Account Migration (Scenario A & B),
Uninstaller, and Zero-Secret Release Package Verification.

All mutating lifecycle tests run strictly against a disposable staging directory
so live production services (3080, 8765, 8766, windows-mcp-isolated, codex-chatgpt-web)
are never interrupted.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

import pytest

PROJECT_ROOT = Path(r"D:\ExampleProjects\Windows-MCP-Agent")
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
DIST_DIR = PROJECT_ROOT / "dist"


def _run_ps1(script_name: str, *args: str) -> subprocess.CompletedProcess[str]:
    script_path = SCRIPTS_DIR / script_name
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        *args,
    ]
    return subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def test_01_repository_release_and_governance_files_present() -> None:
    """Verify all required Sprint 3 release & governance files exist and contain expected sections."""
    required_files = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "SECURITY.md",
        PROJECT_ROOT / "CHANGELOG.md",
        PROJECT_ROOT / "LICENSE",
        PROJECT_ROOT / ".github" / "workflows" / "ci-security.yml",
        PROJECT_ROOT / "docs" / "GITHUB_RELEASE_PLAN.md",
        PROJECT_ROOT / "docs" / "ACCOUNT_MIGRATION_GUIDE.md",
    ]
    for fpath in required_files:
        assert fpath.exists(), f"Missing required release file: {fpath}"
        assert fpath.stat().st_size > 200, f"Release file unexpectedly small: {fpath}"

    changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for ver in ("v0.1.4", "v0.2.0", "v0.2.1", "v0.3.0", "v1.0.0-rc1"):
        assert ver in changelog, f"CHANGELOG.md missing version entry {ver}"


def test_02_install_dryrun_on_primary_root_is_non_destructive() -> None:
    """Verify Install-WindowsMcpAgent.ps1 -DryRun passes all checks without mutating credentials."""
    res = _run_ps1("Install-WindowsMcpAgent.ps1", "-DryRun")
    assert res.returncode == 0, f"Install -DryRun failed:\nSTDOUT:{res.stdout}\nSTDERR:{res.stderr}"

    report_path = PROJECT_ROOT / "runtime" / "logs" / "install-report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["overall_status"] == "PASS"
    assert report["dry_run"] is True
    assert report["prerequisites"]["python_311_plus"] is True
    assert report["prerequisites"]["all_packages_present"] is True
    assert report["source_integrity"]["integrity_passed"] is True
    assert report["credentials"]["raw_secrets_printed"] is False
    assert report["coexistence_guard"]["untouched"] is True


def test_03_scenario_b_disposable_clean_install_and_idempotent_rerun() -> None:
    """Simulate Scenario B clean install into a disposable TargetRoot and verify idempotency."""
    staging_root = Path(tempfile.mkdtemp(prefix="wmcp_s6_stage_"))
    try:
        # First run: fresh install into disposable staging root
        res1 = _run_ps1(
            "Install-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
            "-SkipTaskRegistration",
            "-SkipStackStart",
        )
        assert res1.returncode == 0, f"Clean install failed:\n{res1.stdout}\n{res1.stderr}"

        for rel_dir in (
            "backend",
            "mcp-gateway",
            "desktop-agent",
            "runtime/logs",
            "runtime/secrets",
            "runtime/evidence",
            "backups",
            "config",
            "scripts",
            "docs",
            "tests",
        ):
            assert (staging_root / rel_dir).is_dir(), f"Missing directory: {rel_dir}"

        dpapi_blob = staging_root / "runtime" / "secrets" / "gateway_bearer_token.dpapi"
        assert dpapi_blob.exists(), "DPAPI gateway token blob was not created"
        hash_first = _sha256_file(dpapi_blob)

        report1 = json.loads(
            (staging_root / "runtime" / "logs" / "install-report.json").read_text(encoding="utf-8")
        )
        assert report1["overall_status"] == "PASS"
        assert report1["idempotent_rerun"] is False
        assert report1["credentials"]["gateway_token_sealed"] is True

        # Second run: idempotent re-run must preserve existing DPAPI credential without overwriting
        res2 = _run_ps1(
            "Install-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
            "-SkipTaskRegistration",
            "-SkipStackStart",
        )
        assert res2.returncode == 0, f"Idempotent rerun failed:\n{res2.stdout}\n{res2.stderr}"
        hash_second = _sha256_file(dpapi_blob)
        assert hash_first == hash_second, "Idempotent rerun overwrote existing DPAPI token!"

        report2 = json.loads(
            (staging_root / "runtime" / "logs" / "install-report.json").read_text(encoding="utf-8")
        )
        assert report2["overall_status"] == "PASS"
        assert report2["idempotent_rerun"] is True
        assert report2["credentials"]["existing_credential_preserved"] is True
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def test_04_scenario_a_account_migration_simulation_and_codex_guard() -> None:
    """Verify Connect-ChatGPTAccount.ps1 in -Simulated mode backs up config, labels SIMULATED,
    never alters live windows-mcp-isolated.yaml, and blocks touching codex-chatgpt-web.
    """
    staging_root = Path(tempfile.mkdtemp(prefix="wmcp_s6_mig_"))
    try:
        (staging_root / "runtime" / "logs").mkdir(parents=True, exist_ok=True)
        (staging_root / "backups").mkdir(parents=True, exist_ok=True)

        live_yaml = Path(r"C:\Users\ExampleUser\AppData\Roaming\tunnel-client\windows-mcp-isolated.yaml")
        hash_before = _sha256_file(live_yaml) if live_yaml.exists() else None

        res = _run_ps1(
            "Connect-ChatGPTAccount.ps1",
            "-TargetRoot",
            str(staging_root),
            "-Scenario",
            "ScenarioA",
            "-NewProfileName",
            "windows-mcp-isolated",
            "-NewTunnelId",
            "tunnel_simulated_acct_switch_20261023",
            "-McpTargetUrl",
            "http://127.0.0.1:8765/mcp",
            "-Simulated",
        )
        assert res.returncode == 0, f"Connect-ChatGPTAccount failed:\n{res.stdout}\n{res.stderr}"
        assert "[SIMULATED]" in res.stdout

        if hash_before is not None:
            assert _sha256_file(live_yaml) == hash_before, "Live tunnel profile was modified during simulation!"

        report_path = staging_root / "runtime" / "logs" / "account-migration-report.json"
        assert report_path.exists()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["overall_status"] == "PASS"
        assert report["execution_mode"] == "SIMULATED"
        assert report["simulated"] is True
        assert report["live_profile_unchanged"] is True
        assert report["yaml_template_valid"] is True
        assert report["backup_created"] is True
        assert Path(report["backup_dir"]).is_dir()
        assert (Path(report["backup_dir"]) / "migration_manifest.json").exists()

        # Verify Coexistence Guard: attempting to target codex-chatgpt-web must fail immediately
        res_forbidden = _run_ps1(
            "Connect-ChatGPTAccount.ps1",
            "-TargetRoot",
            str(staging_root),
            "-NewProfileName",
            "codex-chatgpt-web",
            "-Simulated",
        )
        assert res_forbidden.returncode != 0, "Connect-ChatGPTAccount must reject codex-chatgpt-web!"
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def test_05_repair_update_rollback_and_uninstall_lifecycle() -> None:
    """Verify Repair, Update (including automatic rollback on failure), and Fail-Safe Uninstall
    in a disposable staging directory.
    """
    staging_root = Path(tempfile.mkdtemp(prefix="wmcp_s6_lifecycle_"))
    try:
        # 1. Install clean staging instance
        res_inst = _run_ps1(
            "Install-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
            "-SkipTaskRegistration",
            "-SkipStackStart",
        )
        assert res_inst.returncode == 0

        # 2. Repair: plant stale watchdog.lock (dead PID 999999) and EMERGENCY_STOP
        stale_lock = staging_root / "runtime" / "watchdog.lock"
        emerg_flag = staging_root / "runtime" / "EMERGENCY_STOP"
        stale_lock.write_text("999999\n", encoding="utf-8")
        emerg_flag.write_text("STOP\n", encoding="utf-8")

        res_rep = _run_ps1(
            "Repair-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
            "-ClearEmergencyStop",
            "-SkipWatchdogHeal",
            "-SkipDiagnostics",
        )
        assert res_rep.returncode == 0, f"Repair failed:\n{res_rep.stdout}\n{res_rep.stderr}"
        assert not stale_lock.exists(), "Stale lockfile was not cleared by Repair script"
        assert not emerg_flag.exists(), "EMERGENCY_STOP was not cleared by Repair script"

        rep_report = json.loads(
            (staging_root / "runtime" / "logs" / "repair-report.json").read_text(encoding="utf-8")
        )
        assert rep_report["overall_status"] == "PASS"
        assert rep_report["lockfile_check"]["action"] == "STALE_LOCK_CLEARED"
        assert rep_report["emergency_stop"]["action"] == "CLEARED_EMERGENCY_STOP"
        assert rep_report["policy_validation"]["valid"] is True

        # 3. Update (normal pass) + Update with -SimulateFailure (automatic rollback verification)
        res_upd = _run_ps1(
            "Update-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
        )
        assert res_upd.returncode == 0, f"Update failed:\n{res_upd.stdout}\n{res_upd.stderr}"
        upd_report = json.loads(
            (staging_root / "runtime" / "logs" / "update-report.json").read_text(encoding="utf-8")
        )
        assert upd_report["overall_status"] == "PASS"
        assert upd_report["secrets_preserved"] is True

        res_rb = _run_ps1(
            "Update-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
            "-SimulateFailure",
        )
        assert res_rb.returncode == 0, f"Update rollback drill failed:\n{res_rb.stdout}\n{res_rb.stderr}"
        rb_report = json.loads(
            (staging_root / "runtime" / "logs" / "update-report.json").read_text(encoding="utf-8")
        )
        assert rb_report["rolled_back"] is True
        assert rb_report["rollback_verified"] is True
        assert rb_report["secrets_preserved"] is True

        # 4. Uninstall fail-safe check (must fail without -DryRun or -ConfirmUninstall)
        res_uninst_fail = _run_ps1(
            "Uninstall-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
        )
        assert res_uninst_fail.returncode != 0
        assert "FAIL-SAFE ABORT" in res_uninst_fail.stdout

        # 5. Uninstall with -ConfirmUninstall preserves backups and secrets by default
        res_uninst_ok = _run_ps1(
            "Uninstall-WindowsMcpAgent.ps1",
            "-TargetRoot",
            str(staging_root),
            "-ConfirmUninstall",
        )
        assert res_uninst_ok.returncode == 0, f"Uninstall failed:\n{res_uninst_ok.stdout}\n{res_uninst_ok.stderr}"
        assert not (staging_root / "backend").exists()
        assert (staging_root / "backups").is_dir(), "Backups should be preserved by default"
        assert (staging_root / "runtime" / "secrets").is_dir(), "Secrets should be preserved by default"
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def test_06_build_release_package_and_verify_zero_secrets(tmp_path: Path) -> None:
    """Execute Build-ReleasePackage.ps1 into disposable directory and verify zero secrets."""
    out_dir = tmp_path / "dist_out"
    res = _run_ps1("Build-ReleasePackage.ps1", "-OutputDir", str(out_dir))
    assert res.returncode == 0, f"Build-ReleasePackage failed:\n{res.stdout}\n{res.stderr}"

    manifest_path = out_dir / "release-manifest.json"
    shasums_path = out_dir / "SHA256SUMS.txt"

    assert manifest_path.exists()
    assert shasums_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    zip_path = Path(manifest.get("zip_path") or (out_dir / f"{manifest.get('package_name', 'windows-mcp-agent-v1.0.0-rc2')}.zip"))
    assert zip_path.exists()

    assert manifest["secret_scan_passed"] is True
    assert manifest["secret_violations"] == 0
    assert manifest["zip_sha256"] == _sha256_file(zip_path)

    forbidden_suffixes = (".dpapi", ".key", ".pem", ".pfx", ".p12", ".kdbx", ".log")
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        assert len(names) >= 40
        for name in names:
            lower_name = name.lower()
            assert not lower_name.endswith(forbidden_suffixes), f"Forbidden file in release zip: {name}"
            assert "/.env" not in lower_name, f".env file in release zip: {name}"
            assert "runtime/secrets/windows-mcp-isolated" not in lower_name


def test_07_negative_packaging_canary_secret_and_host_path_rejected(tmp_path: Path) -> None:
    """DEFECT-04 Negative packaging test: Build-ReleasePackage.ps1 must fail and refuse to build if canary secrets or developer paths are present."""
    fixture_root = tmp_path / "project_fixture"
    out_dir = tmp_path / "dist_out"
    fixture_root.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Populate minimal fixture files: root files, backend, config example, scripts
    (fixture_root / "LICENSE").write_text("MIT", encoding="utf-8")
    (fixture_root / "README.md").write_text("# Test Project", encoding="utf-8")

    backend_dir = fixture_root / "backend"
    backend_dir.mkdir(parents=True, exist_ok=True)
    # Inject canary secret into backend python file
    (backend_dir / "app.py").write_text(
        "SECRET_VAL = 'CANARY_SECRET_TOKEN_999999'\nHOST_PATH = 'CANARY_HOST_PATH_C:\\\\Users\\\\Admin\\\\SecretDir'\n",
        encoding="utf-8",
    )

    cfg_dir = fixture_root / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "policy.example.json").write_text('{"profiles": {}}', encoding="utf-8")

    scripts_dir = fixture_root / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SCRIPTS_DIR / "Build-ReleasePackage.ps1", scripts_dir / "Build-ReleasePackage.ps1")

    # Run Build-ReleasePackage.ps1 pointing to fixture_root
    res = _run_ps1("Build-ReleasePackage.ps1", "-ProjectRoot", str(fixture_root), "-OutputDir", str(out_dir))
    assert res.returncode != 0, f"Build-ReleasePackage should have failed but succeeded:\n{res.stdout}\n{res.stderr}"
    assert "SECRET SCAN FAILED" in res.stdout or "SECRET SCAN FAILED" in res.stderr
    assert "Canary secret or host path detected" in res.stdout or "Canary secret or host path detected" in res.stderr

    # Ensure no zip or manifest was produced
    assert not (out_dir / "release-manifest.json").exists()
    assert len(list(out_dir.glob("*.zip"))) == 0
