"""Stdlib-compatible direct coding security and behavior tests.

Run with python -m unittest discover -s tests -p test_coding_tools.py -v.
The same tests are collected by pytest in a normal service environment.
"""
import concurrent.futures
import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runtime.coding_tools import CodingToolHandler, CODING_TOOL_DEFINITIONS, MAX_OUTPUT_BYTES


class CodingToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="coding-tools-")
        self.base = Path(self.tmp.name)
        self.root = self.base / "project"
        self.root.mkdir()
        self.config = self.base / "trusted.json"
        self.entry = {"workspace_root": str(self.root), "include_subdirectories": True,
                      "allowed_tools": ["list_directory", "read_file", "write_file", "edit_file", "powershell_execute", "git_status", "git_diff"],
                      "allowed_commands": ["python*", "pytest*", "git*"]}
        self.save_policy()
        self.broker = SimpleNamespace(policy=None, list_preapproved_roots=lambda: [self.root])
        self.handler = CodingToolHandler(None, self.broker, trusted_config_path=self.config,
                                         audit_path=self.base / "audit" / "coding.db")

    def tearDown(self):
        self.tmp.cleanup()

    def save_policy(self):
        self.config.write_text(json.dumps({"trusted_mode_enabled": True, "trusted_workspaces": [self.entry]}), encoding="utf-8")

    def call(self, tool, **args):
        return self.handler.execute_tool(tool, {"workspace_root": str(self.root), **args}, caller_tier="WRITE", caller_id="authenticated-owner")

    def create(self, path="hello.py", content="value = 1\n"):
        result = self.call("agent_write_file", path=path, content=content, expected_sha256="missing")
        self.assertTrue(result["ok"], result)
        return result

    def script(self, content):
        self.create("approved.py", content)
        self.entry["allowed_argv"] = [["python", "approved.py"]]
        self.save_policy()
        return self.call("agent_run_command", argv=["python", "approved.py"], timeout_seconds=2)

    def test_definitions_are_strict(self):
        self.assertEqual(len(CODING_TOOL_DEFINITIONS), 8)
        for _, schema in CODING_TOOL_DEFINITIONS.values():
            self.assertFalse(schema["additionalProperties"])

    def test_authenticated_identity_never_from_arguments(self):
        result = self.handler.execute_tool("agent_workspace_list", {}, caller_tier="WRITE")
        self.assertFalse(result["ok"])
        result = self.handler.execute_tool("agent_workspace_list", {"_caller_id": "owner"}, caller_tier="WRITE", caller_id="owner")
        self.assertFalse(result["ok"])

    def test_read_caller_cannot_write(self):
        result = self.handler.execute_tool("agent_write_file", {"workspace_root": str(self.root), "path": "x.py", "content": "x", "expected_sha256": "missing"}, caller_tier="READ", caller_id="owner")
        self.assertFalse(result["ok"])
        self.assertFalse((self.root / "x.py").exists())

    def test_trusted_policy_and_broker_both_required(self):
        self.broker.list_preapproved_roots = lambda: []
        self.assertFalse(self.call("agent_read_file", path="x.py")["ok"])
        self.broker.list_preapproved_roots = lambda: [self.root]
        self.entry["allowed_tools"] = []
        self.save_policy()
        self.assertFalse(self.call("agent_write_file", path="x.py", content="x", expected_sha256="missing")["ok"])

    def test_caller_scope(self):
        self.entry["allowed_callers"] = ["someone-else"]
        self.save_policy()
        self.assertFalse(self.call("agent_read_file", path="x.py")["ok"])

    def test_atomic_write_read_range_patch_backup(self):
        first = self.create(content="one\ntwo\nthree\n")
        read = self.call("agent_read_file", path="hello.py", start_line=2, end_line=2)
        self.assertEqual(read["content"], "two\n")
        self.assertEqual(read["sha256"], first["sha256"])
        result = self.call("agent_apply_patch", path="hello.py", old_text="two\n", new_text="changed\n", expected_sha256=first["sha256"])
        self.assertTrue(result["ok"], result)
        self.assertEqual((self.handler.backup_dir / result["backup_id"]).read_text(), "one\ntwo\nthree\n")
        self.assertEqual(result["modified_paths"], [str(self.root / "hello.py")])
        self.assertEqual((self.root / "hello.py").read_text(), "one\nchanged\nthree\n")

    def test_stale_hash_and_ambiguous_patch_do_not_modify(self):
        first = self.create(content="same same\n")
        self.assertFalse(self.call("agent_write_file", path="hello.py", content="new", expected_sha256="0" * 64)["ok"])
        self.assertFalse(self.call("agent_apply_patch", path="hello.py", old_text="same", new_text="new", expected_sha256=first["sha256"])["ok"])
        self.assertEqual((self.root / "hello.py").read_text(), "same same\n")

    def test_two_handlers_stale_write_only_one_wins(self):
        initial = self.create()
        other = CodingToolHandler(None, self.broker, trusted_config_path=self.config, audit_path=self.handler.audit_path)
        def write(handler, content):
            return handler.execute_tool("agent_write_file", {"workspace_root": str(self.root), "path": "hello.py", "content": content, "expected_sha256": initial["sha256"]}, caller_tier="WRITE", caller_id="owner")
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda pair: write(*pair), [(self.handler, "first"), (other, "second")]))
        self.assertEqual(sum(result["ok"] for result in results), 1, results)

    def test_unsafe_paths_and_credentials_denied(self):
        for path in ("../escape.py", "nested/.aws/credentials", "nested/.ssh/id_rsa", ".git/config", ".env", "token.json", "NUL.txt", "file.py:stream", "ambiguous. ", "\\\\server\\share\\file"):
            with self.subTest(path=path):
                result = self.call("agent_write_file", path=path, content="x", expected_sha256="missing")
                self.assertFalse(result["ok"], result)

    def test_hardlinks_denied(self):
        outside = self.base / "outside.py"
        outside.write_text("original")
        os.link(outside, self.root / "hardlink.py")
        self.assertFalse(self.call("agent_read_file", path="hardlink.py")["ok"])
        self.assertFalse(self.call("agent_write_file", path="hardlink.py", content="new", expected_sha256=hashlib.sha256(b"original").hexdigest())["ok"])
        self.assertEqual(outside.read_text(), "original")

    def test_symlink_escape_missing_leaf(self):
        outside = self.base / "outside"
        outside.mkdir()
        try:
            (self.root / "link").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation privilege unavailable")
        self.assertFalse(self.call("agent_write_file", path="link/missing.py", content="x", expected_sha256="missing")["ok"])

    def test_listing_bounds_recursion_and_sensitive_filter(self):
        self.create("a.py")
        self.create("nested/b.py")
        (self.root / ".env").write_text("hidden")
        result = self.call("agent_workspace_list", path=".", recursive=True)
        self.assertTrue(result["ok"], result)
        self.assertIn(str(Path("nested/b.py")), [item["path"] for item in result["entries"]])
        self.assertNotIn(".env", [item["path"] for item in result["entries"]])
        self.assertTrue(self.call("agent_workspace_list", max_entries=1)["truncated"])

    def test_schema_rejects_coercion_unknown_fields(self):
        for args in ({"argv": "python -m pytest"}, {"argv": ["python", "-m", "pytest"], "timeout_seconds": True}, {"argv": ["python"], "env": {"TOKEN": "x"}}, {"argv": ["python"], "timeout_seconds": 121}):
            self.assertFalse(self.call("agent_run_command", **args)["ok"])

    def test_arbitrary_commands_and_injections_denied(self):
        for argv in (["python", "-c", "print(1)"], ["python", "-mpytest"], ["python", "outside.py"], ["git", "push"], ["git", "-c", "core.fsmonitor=evil", "status"], ["powershell", "-Command", "whoami"], ["python", "-m", "pytest", "-p", "evil"], ["python", "-m", "pytest", "../outside"], ["python", "-m", "pytest", "x;whoami"]):
            with self.subTest(argv=argv):
                self.assertFalse(self.call("agent_run_command", argv=argv)["ok"])

    def test_default_cwd_dot_and_real_compile(self):
        self.create("source.py", "value = 1\n")
        result = self.call("agent_run_command", argv=["python", "-m", "compileall", "-q", "source.py"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["returncode"], 0, result)

    def test_test_runner_argv_is_structured(self):
        with patch.object(self.handler, "_run", return_value={"returncode": 0, "stdout": "passed", "stderr": ""}) as run:
            result = self.call("agent_run_tests")
        self.assertTrue(result["ok"], result)
        self.assertEqual(run.call_args.args[0], [sys.executable, "-I", "-m", "pytest"])

    def test_real_output_capped_and_redacted(self):
        result = self.script("print('api_key=supersecret')\nprint('x' * 100000)\n")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["returncode"], 0, result)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["stdout"].encode()), MAX_OUTPUT_BYTES + 50)
        self.assertNotIn("supersecret", result["stdout"])

    def test_real_timeout(self):
        result = self.script("import time\ntime.sleep(30)\n")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["timed_out"], result)

    def test_emergency_stop_during_process(self):
        self.broker.policy = SimpleNamespace(is_emergency_stop_active=lambda: False,
                                            is_sensitive_path_str=lambda *a, **k: False)
        state = {"stop": False}
        self.broker.policy.is_emergency_stop_active = lambda: state["stop"]
        timer = __import__("threading").Timer(0.3, lambda: state.update(stop=True))
        timer.start()
        result = self.script("import time\ntime.sleep(30)\n")
        timer.join()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["emergency_stopped"], result)

    def test_audit_is_durable_without_content(self):
        self.create(content="unlogged source text")
        with contextlib.closing(sqlite3.connect(self.handler.audit_path)) as conn:
            events = [json.loads(row[0]) for row in conn.execute("SELECT record FROM coding_audit")]
        self.assertTrue(any(event["decision"] == "WRITE_COMMITTED" for event in events))
        self.assertNotIn("unlogged source text", json.dumps(events))

    def test_audit_failure_denies_write(self):
        with patch.object(self.handler, "_audit", side_effect=OSError("disk full")):
            result = self.call("agent_write_file", path="x.py", content="x", expected_sha256="missing")
        self.assertFalse(result["ok"])
        self.assertFalse((self.root / "x.py").exists())

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_real_git_status_diff_excludes_secrets(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "normal.py").write_text("before\n")
        (self.root / ".env").write_text("unredactedcredential\n")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        (self.root / "normal.py").write_text("after\n")
        (self.root / ".env").write_text("unredactedcredential_new\n")
        status = self.call("agent_git_status")
        self.assertTrue(status["ok"], status)
        self.assertIn("normal.py", status["stdout"])
        diff = self.call("agent_git_diff")
        self.assertTrue(diff["ok"], diff)
        self.assertIn("+after", diff["stdout"])
        self.assertNotIn("unredactedcredential", diff["stdout"])

    def test_b1_read_file_wire_contract_and_negative_empty_rejection(self):
        from gateway_server import (
            serialize_autonomous_read_file_result,
            simulate_chatgpt_mcp_client_parse,
        )
        # 1. Reproduce legacy bug: top-level scalar 'content' key normalizes to {} in ChatGPT MCP client
        legacy_wire = json.dumps({
            "ok": True,
            "content": "NONEMPTY_PAYLOAD\n",
            "sha256": "abc123",
            "bytes": 17,
            "start_line": 1,
            "end_line": 1,
            "total_lines": 1,
        })
        legacy_parsed = simulate_chatgpt_mcp_client_parse({
            "content": [{"type": "text", "text": legacy_wire}],
            "isError": False,
        })
        self.assertEqual(legacy_parsed, {})

        # 2. Negative test proving '{}' / empty client-visible text is rejected when file is nonempty
        with self.assertRaises(ValueError) as ctx:
            serialize_autonomous_read_file_result({
                "ok": True,
                "file_text": "",
                "text": "",
                "content": "",
                "sha256": "abc123",
                "bytes": 56,
                "start_line": 1,
                "end_line": 2,
                "total_lines": 2,
            })
        self.assertIn("B1 Contract Violation", str(ctx.exception))

        # 3. End-to-end write -> readback via wire serializer -> client-visible verification
        seed = self.create(path="b1_verify.txt", content="line_alpha\nline_beta\n")
        read_res = self.call("agent_read_file", path="b1_verify.txt")
        self.assertTrue(read_res["ok"], read_res)
        self.assertEqual(read_res["file_text"], "line_alpha\nline_beta\n")
        self.assertEqual(read_res["text"], "line_alpha\nline_beta\n")
        self.assertEqual(read_res["sha256"], hashlib.sha256(b"line_alpha\nline_beta\n").hexdigest())

        wire_str = serialize_autonomous_read_file_result(read_res)
        wire_obj = json.loads(wire_str)
        self.assertNotIn("content", wire_obj)
        self.assertEqual(wire_obj["file_text"], "line_alpha\nline_beta\n")
        self.assertEqual(wire_obj["text"], "line_alpha\nline_beta\n")

        client_visible = simulate_chatgpt_mcp_client_parse({
            "content": [{"type": "text", "text": wire_str}],
            "isError": False,
        })
        self.assertNotEqual(client_visible, {})
        self.assertEqual(client_visible["file_text"], "line_alpha\nline_beta\n")
        self.assertEqual(client_visible["sha256"], read_res["sha256"])


if __name__ == "__main__":
    unittest.main()
