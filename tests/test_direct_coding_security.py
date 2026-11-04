"""Independent direct-coding security checks; runnable with stdlib unittest.

Only synthetic files under a temporary fixture are touched. The final test
documents that explicitly approved Python code runs with service-account access;
the coding API is not an OS filesystem or network sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from runtime.coding_tools import CODING_TOOL_NAMES, CodingToolHandler
from runtime.task_grant import _is_sensitive_path


class DirectCodingSecurity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="direct_coding_security_")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.control = self.base / "owner-policy.json"
        self.entry = {
            "workspace_root": str(self.root), "include_subdirectories": True,
            "allowed_tools": sorted(CODING_TOOL_NAMES),
            "allowed_commands": ["python*", "pytest*", "git*"],
            "allowed_callers": ["review-client"],
        }
        self.write_policy()
        self.stopped = False
        policy = SimpleNamespace(
            is_emergency_stop_active=lambda: self.stopped,
            is_sensitive_path_str=lambda *a, **k: False,
        )
        broker = SimpleNamespace(policy=policy, list_preapproved_roots=lambda: [self.root])
        self.handler = CodingToolHandler(
            None, broker, trusted_config_path=self.control,
            audit_path=self.base / "audit" / "coding.db",
        )

    def write_policy(self):
        self.control.write_text(json.dumps({
            "trusted_mode_enabled": True, "trusted_workspaces": [self.entry],
        }), encoding="utf-8")

    def call(self, name, args=None, **kw):
        arguments = {} if name == "agent_workspace_list" else {"workspace_root": str(self.root)}
        arguments.update(args or {})
        defaults = {"caller_id": "review-client", "caller_tier": "WRITE", "surface": "cloud_autonomous"}
        defaults.update(kw)
        return self.handler.execute_tool(name, arguments, **defaults)

    def deny(self, result):
        self.assertFalse(result.get("ok"), result)
        self.assertEqual(result.get("status"), "REJECTED", result)

    def write(self, path, content="synthetic", **kw):
        return self.call("agent_write_file", {
            "path": str(path), "content": content, "expected_sha256": "missing",
        }, **kw)

    def test_authenticated_trusted_writes_need_no_per_command_approval(self):
        first = self.write("one.py", "original\n")
        self.assertTrue(first.get("ok"), first)
        patched = self.call("agent_apply_patch", {
            "path": "one.py", "old_text": "original", "new_text": "revised",
            "expected_sha256": hashlib.sha256(b"original\n").hexdigest(),
        })
        self.assertTrue(patched.get("ok"), patched)
        self.assertEqual((self.root / "one.py").read_text(), "revised\n")
        self.assertTrue(self.write("two.py").get("ok"))
        self.assertNotIn("requires_owner_approval", first)

    def test_outside_root_traversal_ads_and_devices_denied(self):
        sentinel = self.outside / "sentinel.txt"
        sentinel.write_text("unchanged", encoding="utf-8")
        for path in (str(sentinel), "../outside/new.txt", "sub/../../outside/new.txt",
                     "safe.txt:stream", "NUL.txt", "ambiguous.txt.", "ambiguous.txt ",
                     r"\\server\share\file", r"\\?\C:\file"):
            with self.subTest(path=path):
                self.deny(self.write(path))
                self.deny(self.call("agent_read_file", {"path": path}))
        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertFalse((self.outside / "new.txt").exists())

    def test_missing_leaf_junction_escape_denied(self):
        link = self.root / "outside_link"
        try:
            os.symlink(self.outside, link, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                raise
            made = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(self.outside)],
                capture_output=True, check=False,
            )
            self.assertEqual(made.returncode, 0, "Could not create synthetic junction fixture")
        try:
            self.deny(self.write("outside_link/missing/deep.txt"))
            self.assertFalse((self.outside / "missing").exists())
        finally:
            if link.is_symlink():
                link.unlink()
            else:
                os.rmdir(link)

    def test_hardlink_alias_denied(self):
        sentinel = self.outside / "sentinel.txt"
        sentinel.write_text("unchanged", encoding="utf-8")
        os.link(sentinel, self.root / "alias.txt")
        self.deny(self.call("agent_read_file", {"path": "alias.txt"}))
        self.deny(self.write("alias.txt"))
        self.assertEqual(sentinel.read_text(), "unchanged")

    def test_secrets_tunnel_and_policy_writes_denied(self):
        paths = [".env", "nested/.env.local", ".aws/credentials", "nested/.ssh/id_custom",
                 "runtime/secrets/broker_hmac.key", "config/trusted_workspaces.json",
                 "config/policy.json", "config/tunnel-autonomous.json",
                 "config/tunnel-autonomous.yaml", "runtime/oauth_state.db",
                 "runtime/tasks.db", "runtime/EMERGENCY_STOP", ".git/config",
                 ".git/hooks/pre-commit", "nested/access_token.txt", "key.dpapi"]
        for path in paths:
            with self.subTest(path=path):
                self.deny(self.write(path))
                self.assertFalse((self.root / path).exists())
        self.deny(self.write(str(self.control)))

    def test_shared_grant_matcher_blocks_nested_credentials_and_controls(self):
        for path in ("nested/.aws/credentials", "nested/.ssh/custom", ".azure/config",
                     "secrets/.env.example", "config/trusted_workspaces.json",
                     "config/policy.json", "config/tunnel-autonomous.json",
                     "runtime/oauth_state.db", "runtime/EMERGENCY_STOP"):
            with self.subTest(path=path):
                self.assertTrue(_is_sensitive_path(self.root / path))
        self.assertFalse(_is_sensitive_path(self.root / ".env.example"))
        self.assertFalse(_is_sensitive_path(self.root / "src" / "main.py"))

    def test_identity_tiers_and_argument_smuggling_fail_closed(self):
        for identity in (None, "", "anonymous", "unauthenticated", "unknown", "other-client"):
            with self.subTest(identity=identity):
                self.deny(self.write("denied.txt", caller_id=identity))
        self.deny(self.write("denied.txt", caller_tier="READ"))
        self.deny(self.call("agent_read_file", {"path": "denied.txt", "_caller_id": "review-client"}))
        self.deny(self.call("agent_write_file", {"path": "denied.txt", "content": "x"}))
        self.assertFalse((self.root / "denied.txt").exists())

    def test_untrusted_workspace_and_disabled_trust_fail_closed(self):
        self.deny(self.call("agent_read_file", {"workspace_root": str(self.outside), "path": "x"}))
        self.control.write_text('{"trusted_mode_enabled":false,"trusted_workspaces":[]}', encoding="utf-8")
        self.deny(self.write("disabled.txt"))

    def test_admin_arbitrary_code_and_network_git_denied(self):
        for argv in (["powershell", "-Command", "Get-Process"], ["cmd", "/c", "echo x"],
                     ["python", "-c", "print(1)"], ["python", "unapproved.py"],
                     ["git", "push"], ["git", "fetch"], ["git", "config", "x", "y"],
                     ["pytest", "-p", "arbitrary_plugin"], ["python", "-m", "pip", "install", "x"]):
            with self.subTest(argv=argv):
                self.deny(self.call("agent_run_command", {"argv": argv}))

    def test_emergency_stop_denies_read_write_and_execution(self):
        self.stopped = True
        self.deny(self.call("agent_workspace_list"))
        self.deny(self.write("halted.txt"))
        self.deny(self.call("agent_run_tests"))
        self.assertFalse((self.root / "halted.txt").exists())

    def test_stale_hash_denies_without_clobber(self):
        target = self.root / "existing.txt"
        target.write_text("newer", encoding="utf-8")
        self.deny(self.write("existing.txt", "overwrite"))
        self.assertEqual(target.read_text(), "newer")

    def test_readonly_git_does_not_execute_repository_clean_filter(self):
        git = shutil.which("git")
        self.assertTrue(git, "Git is required for the repository filter security check")
        marker = self.outside / "unexpected_git_filter.txt"
        script = self.root / "filter_probe.py"
        script.write_text(
            "from pathlib import Path\nimport sys\nPath(" + repr(str(marker)) +
            ").write_text('synthetic filter ran')\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        def invoke(*argv):
            result = subprocess.run([git, *argv], cwd=self.root, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, "Synthetic Git fixture setup failed")
        invoke("init", "--quiet")
        invoke("config", "filter.securityprobe.clean", '"' + sys.executable + '" "' + str(script) + '"')
        (self.root / ".gitattributes").write_text("*.txt filter=securityprobe\n", encoding="utf-8")
        (self.root / "ordinary.txt").write_text("before\n", encoding="utf-8")
        invoke("add", "ordinary.txt", ".gitattributes")
        marker.unlink(missing_ok=True)
        (self.root / "ordinary.txt").write_text("after\n", encoding="utf-8")
        result = self.call("agent_git_diff")
        self.assertFalse(marker.exists(), "Read-only Git diff executed repository-defined clean filter")
        if result.get("ok"):
            self.assertEqual(result.get("returncode"), 0, result)

    def test_explicitly_approved_script_is_trusted_execution_not_os_sandbox(self):
        # Deliberate synthetic probe: this documents an architectural boundary,
        # rather than pretending child code is confined by cwd or argv filters.
        target = self.outside / "owner_trust_probe.txt"
        script = self.root / "approved_probe.py"
        script.write_text("from pathlib import Path\nPath(" + repr(str(target)) + ").write_text('synthetic probe')\n", encoding="utf-8")
        self.entry["allowed_argv"] = [["python", "approved_probe.py"]]
        self.write_policy()
        result = self.call("agent_run_command", {"argv": ["python", "approved_probe.py"], "timeout_seconds": 15})
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("returncode"), 0, result)
        self.assertEqual(target.read_text(), "synthetic probe")


if __name__ == "__main__":
    unittest.main()
