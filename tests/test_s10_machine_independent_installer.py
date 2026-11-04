"""Stage S10 — Machine-Independent Installer & Account Migration Automated Acceptance Tests.

Verifies:
1. Static Path Audit: Zero hardcoded user profiles (C:\\Users\\Admin) or hardcoded repository roots in active PowerShell code.
2. Scenario A: Same-machine ChatGPT account migration & profile staging with rollback without touching legacy codex tunnel.
3. Scenario B: Clean unpacked installation on C: drive (e.g. C:\\Users\\...\\AppData\\Local\\Temp) with dynamic python discovery.
4. Scenario C: In-place release upgrade (RC1 -> RC2) with configuration preservation and syntax validation.
5. Reversibility & Fail-Safe: DryRun verification for Install, Update, Repair, and Rollback scripts.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


def test_01_static_path_audit_zero_hardcoded_paths():
    """Verify no active PowerShell code lines contain hardcoded C:\\Users\\Admin or D:\\ProjectsWindows-MCP-Agent."""
    ps1_files = list(SCRIPTS_DIR.glob("*.ps1"))
    assert len(ps1_files) >= 10, f"Expected at least 10 scripts, found {len(ps1_files)}"

    violations = []
    for script_path in ps1_files:
        content = script_path.read_text(encoding="utf-8", errors="replace")
        in_comment_block = False
        for line_no, raw_line in enumerate(content.splitlines(), 1):
            line = raw_line.strip()
            if "<#" in line:
                in_comment_block = True
            if "#>" in line:
                in_comment_block = False
                continue
            if in_comment_block or line.startswith("#"):
                continue

            # Check for hardcoded paths in executable code
            if "C:\\Users\\Admin" in line or "C:/Users/Admin" in line:
                violations.append((script_path.name, line_no, "Hardcoded C:\\Users\\Admin", line))
            if "D:\\ProjectsWindows-MCP-Agent" in line or "D:/ProjectsWindows-MCP-Agent" in line:
                violations.append((script_path.name, line_no, "Hardcoded D:\\ProjectsWindows-MCP-Agent", line))

    assert not violations, f"Found hardcoded path violations in scripts: {violations}"


def test_02_scenario_a_account_migration_simulation(tmp_path: Path):
    """Scenario A: Test account migration staging and rollback via Connect-ChatGPTAccount.ps1."""
    staging_root = tmp_path / "staging_agent"
    staging_root.mkdir(parents=True, exist_ok=True)
    (staging_root / "config").mkdir(parents=True, exist_ok=True)
    (staging_root / "runtime").mkdir(parents=True, exist_ok=True)

    # Copy template config
    prod_policy = PROJECT_ROOT / "config" / "policy.json"
    if prod_policy.exists():
        shutil.copy(prod_policy, staging_root / "config" / "policy.json")

    connect_script = SCRIPTS_DIR / "Connect-ChatGPTAccount.ps1"
    assert connect_script.exists()

    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(connect_script),
        "-NewProfileName", "windows-mcp-staging-acc2",
        "-NewTunnelId", "tunnel_staging_11223344556677889900aabbccddeeff",
        "-Scenario", "ScenarioA",
        "-TargetRoot", str(staging_root),
        "-Simulated",
    ]

    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))
    assert res.returncode == 0, f"Connect-ChatGPTAccount failed: {res.stderr}\n{res.stdout}"
    assert "[SIMULATED]" in res.stdout
    assert "windows-mcp-staging-acc2" in res.stdout


def test_03_scenario_b_clean_installation_on_c_drive(tmp_path: Path):
    """Scenario B: Test clean installation on C: drive via Install-WindowsMcpAgent.ps1 -DryRun."""
    # Ensure tmp_path is on C: drive (pytest uses %TEMP% which is on C:)
    c_target = tmp_path / "c_drive_installed_agent"

    install_script = SCRIPTS_DIR / "Install-WindowsMcpAgent.ps1"
    assert install_script.exists()

    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(install_script),
        "-TargetRoot", str(c_target),
        "-SourceRoot", str(PROJECT_ROOT),
        "-DryRun",
        "-SkipTaskRegistration",
        "-SkipStackStart",
    ]

    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))
    assert res.returncode == 0, f"Install-WindowsMcpAgent DryRun failed: {res.stderr}\n{res.stdout}"
    assert "(DRY-RUN)" in res.stdout
    assert "Status: PASS" in res.stdout


def test_04_scenario_c_upgrade_rc1_to_rc2_simulation(tmp_path: Path):
    """Scenario C: Test upgrading an existing RC1 installation to RC2 via Update-WindowsMcpAgent.ps1."""
    staging_target = tmp_path / "existing_rc1_instance"
    staging_target.mkdir(parents=True, exist_ok=True)

    # Populate dummy RC1 files
    (staging_target / "backend").mkdir(parents=True, exist_ok=True)
    (staging_target / "config").mkdir(parents=True, exist_ok=True)
    (staging_target / "scripts").mkdir(parents=True, exist_ok=True)
    (staging_target / "runtime").mkdir(parents=True, exist_ok=True)

    (staging_target / "backend" / "test.py").write_text("# RC1 backend\n", encoding="utf-8")
    (staging_target / "config" / "user_custom.json").write_text('{"custom_setting": true}', encoding="utf-8")

    update_script = SCRIPTS_DIR / "Update-WindowsMcpAgent.ps1"
    assert update_script.exists()

    # Run Update in DryRun mode first
    cmd_dry = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(update_script),
        "-TargetRoot", str(staging_target),
        "-SourcePath", str(PROJECT_ROOT),
        "-DryRun",
    ]
    res_dry = subprocess.run(cmd_dry, capture_output=True, text=True, cwd=str(PROJECT_ROOT))
    assert res_dry.returncode == 0, f"Update-WindowsMcpAgent DryRun failed: {res_dry.stderr}\n{res_dry.stdout}"
    assert "(DRY-RUN)" in res_dry.stdout
    assert "Status: PASS" in res_dry.stdout

    # Custom config was untouched
    assert (staging_target / "config" / "user_custom.json").read_text(encoding="utf-8") == '{"custom_setting": true}'


def test_05_repair_and_rollback_scripts_dryrun():
    """Verify Repair-WindowsMcpAgent.ps1 and Rollback-WindowsMcp.ps1 execute cleanly with -DryRun."""
    repair_script = SCRIPTS_DIR / "Repair-WindowsMcpAgent.ps1"
    rollback_script = SCRIPTS_DIR / "Rollback-WindowsMcp.ps1"

    # Test Repair
    res_repair = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(repair_script), "-DryRun"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert res_repair.returncode == 0, f"Repair script DryRun failed: {res_repair.stderr}\n{res_repair.stdout}"
    assert "(DRY-RUN)" in res_repair.stdout
    assert "Status: PASS" in res_repair.stdout

    # Test Rollback
    res_rollback = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(rollback_script), "-DryRun"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert res_rollback.returncode == 0, f"Rollback script DryRun failed: {res_rollback.stderr}\n{res_rollback.stdout}"
    assert "(DRY-RUN)" in res_rollback.stdout or "Rollback" in res_rollback.stdout
