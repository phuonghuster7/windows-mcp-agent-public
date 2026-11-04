"""Unit tests for runtime.watchdog safety, secret redaction, backoff, and tunnel command matching."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from runtime.watchdog import (
    ProcessInfo,
    RestartTracker,
    SingleInstanceLock,
    WatchdogSupervisor,
    build_bridge_env,
    find_duplicate_service_pids,
    is_autonomous_mcp_tunnel_cmd,
    is_isolated_mcp_tunnel_cmd,
    is_legacy_codex_tunnel_cmd,
    load_backend_auth_token,
    redact_secrets,
    setup_logger,
)


class TestWatchdogRuntime(unittest.TestCase):
    def test_secret_redaction_strips_bearer_and_api_keys(self) -> None:
        raw = (
            "Authorization: Bearer sk-proj-AbCdEf1234567890xyz "
            "api_key: 'secret_value_12345678' token=my_super_secret_token_99"
        )
        cleaned = redact_secrets(raw)
        self.assertNotIn("sk-proj-AbCdEf1234567890xyz", cleaned)
        self.assertNotIn("secret_value_12345678", cleaned)
        self.assertNotIn("my_super_secret_token_99", cleaned)
        self.assertIn("[REDACTED]", cleaned)

    def test_tunnel_profile_command_discrimination(self) -> None:
        isolated_cmd = (
            r'"C:\Users\ExampleUser\.codex-chatgpt-web\bin\tunnel-client.exe" '
            r"run --profile windows-mcp-isolated"
        )
        autonomous_cmd = (
            r'"C:\Users\ExampleUser\.codex-chatgpt-web\bin\tunnel-client.exe" '
            r"run --profile windows-mcp-autonomous"
        )
        autonomous_yaml_cmd = (
            r"tunnel-client.exe run config/tunnel-autonomous.yaml"
        )
        legacy_cmd = (
            r"C:\Users\ExampleUser\.codex-chatgpt-web\bin\tunnel-client.exe "
            r"run --profile-dir C:\Users\ExampleUser\.codex-chatgpt-web\tunnel\profiles "
            r'--profile codex-chatgpt-web --log.file ""'
        )
        self.assertTrue(is_isolated_mcp_tunnel_cmd(isolated_cmd))
        self.assertFalse(is_isolated_mcp_tunnel_cmd(autonomous_cmd))
        self.assertFalse(is_isolated_mcp_tunnel_cmd(autonomous_yaml_cmd))
        self.assertFalse(is_isolated_mcp_tunnel_cmd(legacy_cmd))

        self.assertTrue(is_autonomous_mcp_tunnel_cmd(autonomous_cmd))
        self.assertTrue(is_autonomous_mcp_tunnel_cmd(autonomous_yaml_cmd))
        self.assertFalse(is_autonomous_mcp_tunnel_cmd(isolated_cmd))
        self.assertFalse(is_autonomous_mcp_tunnel_cmd(legacy_cmd))

        self.assertTrue(is_legacy_codex_tunnel_cmd(legacy_cmd))
        self.assertFalse(is_legacy_codex_tunnel_cmd(isolated_cmd))
        self.assertFalse(is_legacy_codex_tunnel_cmd(autonomous_cmd))

    def test_restart_tracker_backoff_and_circuit_breaker(self) -> None:
        tracker = RestartTracker(
            "tunnel",
            base_backoff_sec=2.0,
            max_backoff_sec=30.0,
            window_sec=600.0,
            max_restarts_in_window=3,
            cooldown_sec=120.0,
        )
        t0 = 1000.0
        can_run, reason = tracker.can_attempt_restart(now=t0)
        self.assertTrue(can_run)
        self.assertEqual(reason, "ok")

        # 1st failed restart -> 2s backoff
        tracker.record_restart_attempt(False, "timeout 1", now=t0)
        can_run_early, reason_early = tracker.can_attempt_restart(now=t0 + 1.0)
        self.assertFalse(can_run_early)
        self.assertIn("backoff_waiting", reason_early)

        # After 2s backoff -> allowed
        can_run_after, _ = tracker.can_attempt_restart(now=t0 + 2.5)
        self.assertTrue(can_run_after)

        # 2nd and 3rd failed restarts within window -> trips circuit breaker OPEN
        tracker.record_restart_attempt(False, "timeout 2", now=t0 + 3.0)
        tracker.record_restart_attempt(False, "timeout 3", now=t0 + 8.0)
        self.assertEqual(tracker.circuit_state, "OPEN")

        can_run_open, reason_open = tracker.can_attempt_restart(now=t0 + 20.0)
        self.assertFalse(can_run_open)
        self.assertIn("circuit_breaker_open", reason_open)

        # After cooldown -> transitions to HALF_OPEN and allows a probe restart
        can_run_half, _ = tracker.can_attempt_restart(now=t0 + 8.0 + 121.0)
        self.assertTrue(can_run_half)
        self.assertEqual(tracker.circuit_state, "HALF_OPEN")

        # Healthy recovery resets circuit breaker to CLOSED
        tracker.record_healthy()
        self.assertEqual(tracker.circuit_state, "CLOSED")
        self.assertEqual(tracker.consecutive_failures, 0)

    def test_single_instance_lock_prevents_duplicates(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp_lock = Path(td) / "test_watchdog.lock"
            mutex_name = r"Local\WindowsMcpAgentWatchdogUnitTest"
            lock1 = SingleInstanceLock(lock_path=tmp_lock, mutex_name=mutex_name)
            lock2 = SingleInstanceLock(lock_path=tmp_lock, mutex_name=mutex_name)
            try:
                self.assertTrue(lock1.acquire("test1"))
                self.assertFalse(lock2.acquire("test2"))
            finally:
                lock1.release()
                lock2.release()

    def test_backend_env_token_loading_and_redaction(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text(
                "MCP_AUTH_MODE=bearer\nMCP_AUTH_TOKEN=unit_test_secret_token_987654\n",
                encoding="utf-8",
            )
            tok = load_backend_auth_token(env_path=env_file)
            self.assertEqual(tok, "unit_test_secret_token_987654")
            child_env = build_bridge_env(base_env={}, env_path=env_file)
            self.assertEqual(child_env.get("COMPUTER_API_TOKEN"), "unit_test_secret_token_987654")
            # Registered secret must be redacted even when bare
            self.assertNotIn(
                "unit_test_secret_token_987654",
                redact_secrets("leaked: unit_test_secret_token_987654"),
            )

    def test_duplicate_orphan_detection_preserves_venv_tree_and_legacy_tunnel(self) -> None:
        procs = [
            # Venv launcher + child python for bridge (1 logical instance: tree rooted at 100)
            ProcessInfo(100, 1, "python.exe", r"C:\venv\python.exe", "python.exe server\\bridge.py --http-local"),
            ProcessInfo(101, 100, "python.exe", r"C:\Python312\python.exe", "python.exe server\\bridge.py --http-local"),
            # Duplicate orphan bridge (tree rooted at 200)
            ProcessInfo(200, 1, "python.exe", r"C:\Python312\python.exe", "python.exe server\\bridge.py --http-local"),
            # Primary isolated tunnel (PID 300) + orphan duplicate (PID 301)
            ProcessInfo(300, 1, "tunnel-client.exe", r"C:\bin\tunnel-client.exe", "tunnel-client.exe run --profile windows-mcp-isolated"),
            ProcessInfo(301, 1, "tunnel-client.exe", r"C:\bin\tunnel-client.exe", "tunnel-client.exe run --profile windows-mcp-isolated"),
            # Primary autonomous tunnel (PID 400) + orphan duplicate (PID 401)
            ProcessInfo(400, 1, "tunnel-client.exe", r"C:\bin\tunnel-client.exe", "tunnel-client.exe run --profile windows-mcp-autonomous"),
            ProcessInfo(401, 1, "tunnel-client.exe", r"C:\bin\tunnel-client.exe", "tunnel-client.exe run --profile windows-mcp-autonomous"),
            # Legacy Codex tunnel (PID 999 - MUST NEVER BE FLAGGED)
            ProcessInfo(999, 1, "tunnel-client.exe", r"C:\bin\tunnel-client.exe", "tunnel-client.exe run --profile codex-chatgpt-web"),
        ]
        dup_bridge = find_duplicate_service_pids(procs, "mcp_bridge", active_pid=101)
        self.assertEqual(dup_bridge, [200])

        dup_tunnel = find_duplicate_service_pids(procs, "tunnel", active_pid=300)
        self.assertEqual(dup_tunnel, [301])
        self.assertNotIn(999, dup_tunnel)

        dup_auton = find_duplicate_service_pids(procs, "autonomous_tunnel", active_pid=400)
        self.assertEqual(dup_auton, [401])
        self.assertNotIn(999, dup_auton)

    def test_sleep_resume_and_network_outage_handling(self) -> None:
        sup = WatchdogSupervisor(setup_logger(), mode="test", load_previous=False, resume_grace_sec=30.0)
        # Normal 15s tick -> no jump
        self.assertFalse(sup.detect_sleep_resume(15.0, now_epoch=1000.0))
        self.assertFalse(sup.detect_sleep_resume(15.0, now_epoch=1015.0))
        self.assertFalse(sup.is_in_resume_grace_period(now_epoch=1015.0))

        # 120s sleep jump (> 3 * 15s) -> triggers grace period
        self.assertTrue(sup.detect_sleep_resume(15.0, now_epoch=1135.0))
        self.assertTrue(sup.is_in_resume_grace_period(now_epoch=1145.0))
        self.assertFalse(sup.is_in_resume_grace_period(now_epoch=1170.0))

        # Network transitions
        sup.handle_network_transition(True)
        sup.handle_network_transition(False)
        events = [e["event"] for e in sup.recent_events]
        self.assertIn("NETWORK_OUTAGE_DETECTED", events)
        sup.handle_network_transition(True)
        events = [e["event"] for e in sup.recent_events]
        self.assertIn("NETWORK_RESTORED", events)


if __name__ == "__main__":
    unittest.main()
