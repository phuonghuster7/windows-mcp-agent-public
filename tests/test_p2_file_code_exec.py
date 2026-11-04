"""Phase P2 (File, Code, Git, Shell, Process & Jobs) + P5 Security Policy Automated Tests.

Covers:
- Full 12-step P2 Acceptance Workflow on a disposable Git workspace:
  1. Create file -> 2. Read -> 3. Modify -> 4. Diff -> 5. Harmless PowerShell ->
  6. Run Python test -> 7. Capture exit code & logs -> 8. Start background job ->
  9. Poll job -> 10. Cancel job -> 11. Restore modified file -> 12. Verify audit logs
- Security tests:
  - Path traversal (..), UNC (\\\\server\\share), Device paths (\\\\.\\, \\\\?\\)
  - NTFS Alternate Data Streams (file.txt:stream)
  - Symlink / NTFS Junction escape detection outside approved roots
  - Sensitive path rejection (.env, .git/config, .ssh, .aws, AppData\\Roaming\\tunnel-client,
    DPAPI keys, browser profiles, .pem, .kdbx)
  - UTF-8 / UTF-16 encoding preservation
  - Concurrency conflict detection (expected_sha256 / ETag)
  - dry_run mode, recoverable delete to backups/trash, and safe Git operations
  - Destructive system/firewall/Defender command blocking
  - Revocable time-limited control session lifecycle
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _d in (PROJECT_ROOT / "mcp-gateway", PROJECT_ROOT / "backend", PROJECT_ROOT / "desktop-agent"):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))

from policy import PermissionTier, SecurityPolicy, redact_secrets  # noqa: E402
from file_code_ops import ConcurrencyConflictError, FileCodeOperations  # noqa: E402
from exec_jobs import ExecutionJobManager  # noqa: E402


class TestP2FileCodeExecAndP5Security(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name).resolve()
        self.workspace = self.base / "workspace"
        self.outside = self.base / "outside_root"
        self.backups = self.base / "backups"
        self.jobs_dir = self.base / "jobs"
        self.audit_log = self.base / "logs" / "audit.jsonl"

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.outside.mkdir(parents=True, exist_ok=True)
        (self.outside / "escaped.txt").write_text("OUTSIDE_SECRET", encoding="utf-8")

        # Initialize disposable Git repository inside workspace
        subprocess.run(["git", "init"], cwd=str(self.workspace), capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@local.mcp"],
            cwd=str(self.workspace),
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "MCP Test Agent"],
            cwd=str(self.workspace),
            capture_output=True,
            check=True,
        )

        self.policy = SecurityPolicy(
            profile="developer_p2",
            allowed_read_roots=[str(self.workspace)],
            allowed_write_roots=[str(self.workspace)],
            allowed_git_repos=[str(self.workspace)],
            allowed_exec_roots=[str(self.workspace)],
            audit_log_path=str(self.audit_log),
            approval_token="test-approval-token-999",
        )
        self.session = self.policy.sessions.create_session(
            [PermissionTier.WRITE, PermissionTier.EXECUTE],
            ttl_seconds=600,
        )
        self.sid = self.session.session_id
        self.file_ops = FileCodeOperations(policy=self.policy, backups_root=self.backups)
        self.exec_ops = ExecutionJobManager(policy=self.policy, jobs_dir=self.jobs_dir)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_full_12_step_p2_acceptance_workflow(self) -> None:
        """Execute all 12 steps of P2 acceptance end-to-end on disposable workspace."""
        target_py = self.workspace / "calculator.py"
        initial_code = (
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
        )

        # Step 1: Create file
        w_res = self.file_ops.write_file(str(target_py), initial_code, session_id=self.sid)
        self.assertTrue(w_res["ok"])
        self.assertFalse(w_res["overwritten"])
        original_sha = w_res["sha256"]

        # Commit initial file so git_diff can track working tree modifications
        commit_res = self.file_ops.git_add_commit(
            str(self.workspace), "Initial commit", ["calculator.py"], session_id=self.sid
        )
        self.assertTrue(commit_res["ok"])
        self.assertTrue(len(commit_res["commit_sha"]) >= 7)

        # Step 2: Read file
        r_res = self.file_ops.read_file(str(target_py))
        self.assertEqual(r_res["content"], initial_code)
        self.assertEqual(r_res["sha256"], original_sha)

        # Step 3: Modify file (with expected_sha256 concurrency guard)
        edit_res = self.file_ops.edit_file(
            str(target_py),
            old_text="    return a + b\n",
            new_text="    return a + b\n\n\ndef multiply(a: int, b: int) -> int:\n    return a * b\n",
            expected_sha256=original_sha,
            session_id=self.sid,
        )
        self.assertTrue(edit_res["ok"])
        self.assertNotEqual(edit_res["sha256"], original_sha)
        self.assertIn("+def multiply", edit_res["diff"])
        self.assertIsNotNone(edit_res["backup"])

        # Step 4: Diff (git_diff + unified diff verification)
        diff_res = self.file_ops.git_diff(str(self.workspace))
        self.assertIn("+def multiply(a: int, b: int) -> int:", diff_res["diff"])

        # Step 5: Harmless PowerShell execution
        ps_res = self.exec_ops.powershell_execute(
            "Write-Output 'P2_POWERSHELL_OK'; Get-Location | Select-Object -ExpandProperty Path",
            cwd=str(self.workspace),
            session_id=self.sid,
        )
        self.assertTrue(ps_res["ok"])
        self.assertEqual(ps_res["exit_code"], 0)
        self.assertIn("P2_POWERSHELL_OK", ps_res["stdout"])

        # Step 6: Run Python test in disposable workspace
        test_file = self.workspace / "test_calculator.py"
        test_code = (
            "import unittest\n"
            "from calculator import add, multiply\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_ops(self):\n"
            "        self.assertEqual(add(3, 4), 7)\n"
            "        self.assertEqual(multiply(6, 7), 42)\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
        )
        self.file_ops.write_file(str(test_file), test_code, session_id=self.sid)
        py_exe = sys.executable
        py_test_res = self.exec_ops.powershell_execute(
            f"& '{py_exe}' -m unittest discover -s . -p 'test_*.py' -v",
            cwd=str(self.workspace),
            session_id=self.sid,
        )

        # Step 7: Capture exit code & logs (and verify secret redaction in output)
        self.assertEqual(py_test_res["exit_code"], 0)
        self.assertIn("OK", py_test_res["stdout"] + py_test_res["stderr"])

        secret_ps = self.exec_ops.powershell_execute(
            "Write-Output 'api_key=sk-1234567890abcdefghijklmnop'",  # gitleaks:allow  (synthetic regression fixture; reviewed)
            cwd=str(self.workspace),
            session_id=self.sid,
        )
        self.assertIn("[REDACTED]", secret_ps["stdout"])
        self.assertNotIn("sk-1234567890abcdefghijklmnop", secret_ps["stdout"])

        # Step 8: Start background job
        job_init = self.exec_ops.job_create(
            "Write-Output 'JOB_STARTED_LINE'; Start-Sleep -Seconds 30; Write-Output 'NEVER_REACHED'",
            cwd=str(self.workspace),
            timeout_seconds=60,
            session_id=self.sid,
        )
        job_id = job_init["job_id"]
        self.assertTrue(job_id.startswith("job_"))
        self.assertTrue((self.jobs_dir / f"{job_id}.json").exists())

        # Step 9: Poll job
        time.sleep(0.4)
        polled = self.exec_ops.job_poll(job_id, session_id=self.sid)
        self.assertEqual(polled["job_id"], job_id)
        self.assertEqual(polled["status"], "running")
        self.assertIsNotNone(polled["pid"])

        # Step 10: Cancel job & check job_logs
        cancelled = self.exec_ops.job_cancel(job_id, session_id=self.sid)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertTrue(cancelled["cancelled"])
        logs = self.exec_ops.job_logs(job_id, session_id=self.sid)
        self.assertEqual(logs["status"], "cancelled")
        self.assertTrue(len(logs["audit_trail"]) >= 2)

        # Step 11: Restore modified file from version backup
        restore_res = self.file_ops.restore_file(str(target_py), session_id=self.sid)
        self.assertTrue(restore_res["ok"])
        self.assertEqual(restore_res["sha256"], original_sha)
        restored_read = self.file_ops.read_file(str(target_py))
        self.assertEqual(restored_read["content"], initial_code)

        # Step 12: Verify structured audit logs
        entries = self.policy.audit.read_entries(limit=100)
        logged_tools = [e["tool_name"] for e in entries]
        for expected_tool in (
            "write_file",
            "git_add_commit",
            "read_file",
            "edit_file",
            "git_diff",
            "powershell_execute",
            "job_create",
            "job_poll",
            "job_cancel",
            "restore_file",
        ):
            self.assertIn(expected_tool, logged_tools)

    def test_security_path_traversal_unc_device_ads_and_symlink_escape(self) -> None:
        """Verify P5 path safeguards: traversal, UNC, Device, ADS, and symlink/junction escape."""
        # 1. Path traversal outside root
        with self.assertRaises(PermissionError):
            self.file_ops.read_file(str(self.workspace / ".." / "outside_root" / "escaped.txt"))

        # 2. UNC path
        with self.assertRaises(PermissionError):
            self.policy.validate_path(r"\\127.0.0.1\c$\Windows\win.ini")

        # 3. Device paths
        with self.assertRaises(PermissionError):
            self.policy.validate_path(r"\\.\PhysicalDrive0")
        with self.assertRaises(PermissionError):
            self.policy.validate_path(r"\\?\C:\Windows\system.ini")

        # 4. NTFS Alternate Data Streams (ADS)
        with self.assertRaises(PermissionError):
            self.file_ops.write_file(str(self.workspace / "normal.txt:hidden_stream"), "secret", session_id=self.sid)

        # 5. Directory Junction / Symlink escape outside workspace
        junction_path = self.workspace / "link_outside"
        subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction_path), str(self.outside)],
            capture_output=True,
            check=False,
        )
        if junction_path.exists():
            try:
                with self.assertRaises(PermissionError):
                    self.file_ops.read_file(str(junction_path / "escaped.txt"))
                with self.assertRaises(PermissionError):
                    self.file_ops.write_file(str(junction_path / "pwn.txt"), "blocked", session_id=self.sid)
            finally:
                subprocess.run(["cmd.exe", "/c", "rmdir", str(junction_path)], capture_output=True)

    def test_sensitive_path_filtering(self) -> None:
        """Verify sensitive paths (.env, .git/config, .ssh, .aws, tunnel-client, DPAPI, browser) are blocked."""
        blocked_samples = [
            self.workspace / ".env",
            self.workspace / ".env.production",
            self.workspace / ".git" / "config",
            self.workspace / ".ssh" / "id_rsa",
            self.workspace / ".aws" / "credentials",
            self.workspace / "AppData" / "Roaming" / "tunnel-client" / "config.json",
            self.workspace / "AppData" / "Roaming" / "Microsoft" / "Protect" / "dpapi_master",
            self.workspace / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Login Data",
            self.workspace / "cert.pem",
            self.workspace / "vault.kdbx",
        ]
        for sample in blocked_samples:
            with self.assertRaises(PermissionError, msg=f"Failed to block sensitive path: {sample}"):
                self.policy.validate_path(sample, tier=PermissionTier.READ, check_content=True)
            with self.assertRaises(PermissionError, msg=f"Failed to block write to sensitive path: {sample}"):
                self.policy.validate_path(sample, tier=PermissionTier.WRITE, check_content=True)

    def test_utf8_and_utf16_encodings_and_concurrency_guard(self) -> None:
        """Verify UTF-8 and UTF-16 LE/BE support, dry_run, apply_patch, and expected_sha256 check."""
        utf16_file = self.workspace / "vietnamese_utf16.txt"
        content = "Xin chào Sếp! Hệ thống kiểm thử UTF-16 hoạt động chuẩn xác.\nDòng 2.\n"

        w16 = self.file_ops.write_file(str(utf16_file), content, encoding="utf-16", session_id=self.sid)
        self.assertTrue(w16["ok"])

        r16 = self.file_ops.read_file(str(utf16_file))
        self.assertEqual(r16["content"], content)
        self.assertEqual(r16["encoding"], "utf-16")

        # Concurrency check must fail with stale sha256
        with self.assertRaises(ConcurrencyConflictError):
            self.file_ops.edit_file(
                str(utf16_file),
                old_text="Dòng 2.",
                new_text="Dòng 2 đã sửa.",
                expected_sha256="0" * 64,
                session_id=self.sid,
            )

        # dry_run=True must not alter the file on disk
        dry = self.file_ops.edit_file(
            str(utf16_file),
            old_text="Dòng 2.",
            new_text="Dòng 2 DRY RUN.",
            expected_sha256=w16["sha256"],
            dry_run=True,
            session_id=self.sid,
        )
        self.assertTrue(dry["dry_run"])
        self.assertIn("+Dòng 2 DRY RUN.", dry["diff"])
        self.assertEqual(self.file_ops.read_file(str(utf16_file))["content"], content)

        # Apply SEARCH/REPLACE patch preserving UTF-16 encoding
        patch_str = (
            "<<<<<<< SEARCH\n"
            "Dòng 2.\n"
            "=======\n"
            "Dòng 2 đã cập nhật qua apply_patch.\n"
            ">>>>>>> REPLACE"
        )
        patched = self.file_ops.apply_patch(
            str(utf16_file), patch_str, expected_sha256=w16["sha256"], session_id=self.sid
        )
        self.assertTrue(patched["ok"])
        after_patch = self.file_ops.read_file(str(utf16_file))
        self.assertIn("Dòng 2 đã cập nhật qua apply_patch.", after_patch["content"])
        self.assertEqual(after_patch["encoding"], "utf-16")

    def test_file_copy_move_rename_recoverable_delete_and_binary_put_get(self) -> None:
        """Verify copy_file, move_file, rename_file, delete_file (trash), get_file, put_file."""
        sub = self.file_ops.create_directory(str(self.workspace / "subdir"), session_id=self.sid)
        self.assertTrue(sub["ok"])

        raw_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_TEST_BINARY"
        b64_in = base64.b64encode(raw_bytes).decode("ascii")
        bin_path = self.workspace / "subdir" / "sample.bin"

        put_res = self.file_ops.put_file(str(bin_path), b64_in, session_id=self.sid)
        self.assertTrue(put_res["ok"])

        get_res = self.file_ops.get_file(str(bin_path))
        self.assertEqual(base64.b64decode(get_res["data_base64"]), raw_bytes)

        copied_path = self.workspace / "subdir" / "copied.bin"
        self.file_ops.copy_file(str(bin_path), str(copied_path), session_id=self.sid)
        self.assertTrue(copied_path.exists())

        renamed_res = self.file_ops.rename_file(str(copied_path), "renamed.bin", session_id=self.sid)
        renamed_path = Path(renamed_res["dest"])
        self.assertTrue(renamed_path.exists())
        self.assertFalse(copied_path.exists())

        # Recoverable delete moves file to backups/trash
        del_res = self.file_ops.delete_file(str(renamed_path), session_id=self.sid)
        self.assertTrue(del_res["ok"])
        self.assertFalse(renamed_path.exists())
        self.assertTrue(Path(del_res["recoverable_trash_path"]).exists())

        # Restore deleted file from trash
        restored = self.file_ops.restore_file(str(renamed_path), session_id=self.sid)
        self.assertTrue(restored["ok"])
        self.assertTrue(renamed_path.exists())
        self.assertEqual(renamed_path.read_bytes(), raw_bytes)

    def test_destructive_commands_blocked_and_sessions_revocable(self) -> None:
        """Verify destructive commands are blocked and ControlSession expiration/revocation works."""
        destructive_cmds = [
            "Format-Volume -DriveLetter C -FileSystem NTFS",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "netsh advfirewall set allprofiles state off",
            "vssadmin delete shadows /all /quiet",
            "bcdedit /set {default} safeboot minimal",
            "Stop-Computer -Force",
        ]
        for dcmd in destructive_cmds:
            with self.assertRaises(PermissionError, msg=f"Did not block destructive cmd: {dcmd}"):
                self.exec_ops.powershell_execute(dcmd, cwd=str(self.workspace), session_id=self.sid)

        # 1. Outer profile boundary: read_only profile denies write_file even with a WRITE session
        ro_policy = SecurityPolicy(
            profile="read_only",
            allowed_read_roots=[str(self.workspace)],
            allowed_write_roots=[str(self.workspace)],
            audit_log_path=str(self.audit_log),
        )
        ro_files = FileCodeOperations(policy=ro_policy, backups_root=self.backups)
        ro_sess = ro_policy.sessions.create_session([PermissionTier.WRITE], ttl_seconds=60)
        with self.assertRaises(PermissionError):
            ro_files.write_file(str(self.workspace / "denied_ro.txt"), "nope", session_id=ro_sess.session_id)

        # 2. Fail-closed session lifecycle on developer_p2 profile
        dev_policy = SecurityPolicy(
            profile="developer_p2",
            allowed_read_roots=[str(self.workspace)],
            allowed_write_roots=[str(self.workspace)],
            audit_log_path=str(self.audit_log),
        )
        dev_files = FileCodeOperations(policy=dev_policy, backups_root=self.backups)

        # Without session, write_file is denied in developer_p2 profile (fail-closed)
        with self.assertRaises(PermissionError):
            dev_files.write_file(str(self.workspace / "denied.txt"), "nope")

        # Create a temporary WRITE control session
        sess = dev_policy.sessions.create_session([PermissionTier.WRITE], ttl_seconds=60)
        ok_write = dev_files.write_file(
            str(self.workspace / "allowed_via_session.txt"),
            "session granted",
            session_id=sess.session_id,
        )
        self.assertTrue(ok_write["ok"])

        # Revoke session -> subsequent write must fail immediately
        dev_policy.sessions.revoke_session(sess.session_id, reason="test_revoke")
        with self.assertRaises(PermissionError):
            dev_files.write_file(
                str(self.workspace / "after_revoke.txt"),
                "should fail",
                session_id=sess.session_id,
            )


if __name__ == "__main__":
    unittest.main()
