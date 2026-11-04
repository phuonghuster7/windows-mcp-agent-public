"""Test suite for Sprint 5.1 LLM Adapter upgrades (Agent C)."""
import json
import os
import sys
import tempfile
import urllib.request
from io import BytesIO
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from runtime.llm_adapter import (
    DeterministicRuleBasedAdapter,
    LLMProviderAdapter,
    LiveAINotConfiguredError,
    MockProviderAdapter,
    ModelBudgetExceededError,
    ModelProviderNotConfiguredError,
    OpenAIProviderAdapter,
    OperatingProfile,
    get_llm_adapter,
    get_llm_operating_status,
    validate_plan_schema,
    validate_repair_schema,
)


def test_provider_metadata_and_error_classes():
    assert ModelProviderNotConfiguredError.error_code == "MODEL_PROVIDER_NOT_CONFIGURED"
    assert ModelBudgetExceededError.error_code == "BUDGET_EXHAUSTED"
    assert LiveAINotConfiguredError.error_code == "LIVE_AI_NOT_CONFIGURED"
    assert LiveAINotConfiguredError.error_code == "MODEL_PROVIDER_NOT_CONFIGURED"
    assert issubclass(LiveAINotConfiguredError, ModelProviderNotConfiguredError)

    det = DeterministicRuleBasedAdapter()
    assert det.operating_profile == OperatingProfile.OFFLINE_TEST_MODE
    assert det.provider_name == "deterministic_offline"
    assert det.is_live_ai is False
    assert det.estimated_cost == 0.0
    assert det.api_calls_count == 0

    mock = MockProviderAdapter()
    assert mock.operating_profile == OperatingProfile.OFFLINE_TEST_MODE
    assert mock.provider_name == "mock"
    assert mock.is_live_ai is False
    assert mock.estimated_cost == 0.0

    live = OpenAIProviderAdapter(api_key="sk-test-fake")
    assert live.operating_profile == OperatingProfile.LIVE_AI_MODE
    assert live.provider_name == "openai_live"
    assert live.is_live_ai is True
    assert live.estimated_cost == 0.0
    assert live.api_calls_count == 0


def test_validate_plan_schema():
    with tempfile.TemporaryDirectory() as td:
        ws = str(Path(td).resolve())

        # Valid plan
        plan = [
            {
                "step_id": "step_1",
                "tool": "read_file",
                "args": {"path": f"{ws}/foo.py"},
                "description": "Read foo",
            }
        ]
        res = validate_plan_schema(plan, allowed_tools=["read_file"], workspace_root=ws)
        assert res == plan

        # Non-empty list requirement
        with pytest.raises(ValueError, match="non-empty list"):
            validate_plan_schema([], workspace_root=ws)
        with pytest.raises(ValueError, match="non-empty list"):
            validate_plan_schema("not a list", workspace_root=ws)

        # Missing required keys
        with pytest.raises(ValueError, match="missing required field"):
            validate_plan_schema([{"step_id": "s1"}], workspace_root=ws)

        # Unauthorized tool rejection
        with pytest.raises(ValueError, match="Unauthorized tool"):
            validate_plan_schema(plan, allowed_tools=["write_file"], workspace_root=ws)

        # Shell injection rejection
        inj_plan = [
            {
                "step_id": "step_inj",
                "tool": "powershell_execute",
                "args": {"command": "pytest -v; rm -rf /"},
                "description": "Injection test",
            }
        ]
        with pytest.raises(ValueError, match="Shell injection"):
            validate_plan_schema(inj_plan, allowed_tools=["powershell_execute"], workspace_root=ws)

        # Path traversal rejection
        trav_plan = [
            {
                "step_id": "step_trav",
                "tool": "read_file",
                "args": {"path": f"{ws}/../../escaped.py"},
                "description": "Traversal test",
            }
        ]
        with pytest.raises(ValueError, match="Path traversal"):
            validate_plan_schema(trav_plan, allowed_tools=["read_file"], workspace_root=ws)

        # Sensitive file rejection
        sens_plan = [
            {
                "step_id": "step_sens",
                "tool": "read_file",
                "args": {"path": f"{ws}/.env"},
                "description": "Sensitive test",
            }
        ]
        with pytest.raises(ValueError, match="sensitive file"):
            validate_plan_schema(sens_plan, allowed_tools=["read_file"], workspace_root=ws)


def test_validate_repair_schema():
    with tempfile.TemporaryDirectory() as td:
        ws = str(Path(td).resolve())

        # Valid repair
        rep = {
            "tool": "write_file",
            "args": {"path": "module.py", "content": "x = 1"},
            "reason": "Fix bug",
        }
        res = validate_repair_schema(rep, allowed_tools=["write_file"], workspace_root=ws)
        assert res is not None
        assert res["args"]["path"] == str(Path(ws) / "module.py")

        # abort_repair or can_continue=False returns None
        assert validate_repair_schema(None) is None
        assert validate_repair_schema({"tool": "abort_repair", "args": {}, "reason": "abort"}) is None
        assert validate_repair_schema({**rep, "can_continue": False}) is None

        # Invalid tool
        with pytest.raises(ValueError, match="Unsupported repair tool"):
            validate_repair_schema({**rep, "tool": "powershell_execute"}, workspace_root=ws)

        # Unauthorized tool
        with pytest.raises(ValueError, match="not in allowed_tools"):
            validate_repair_schema(rep, allowed_tools=["read_file"], workspace_root=ws)

        # Sensitive file
        with pytest.raises(ValueError, match="sensitive file"):
            validate_repair_schema(
                {"tool": "write_file", "args": {"path": ".env", "content": "x"}, "reason": "r"},
                workspace_root=ws,
            )

        # Path traversal
        with pytest.raises(ValueError, match="Path traversal"):
            validate_repair_schema(
                {"tool": "write_file", "args": {"path": "../outside.py", "content": "x"}, "reason": "r"},
                workspace_root=ws,
            )


def test_deterministic_adapter_heuristics_and_loop_prevention():
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td).resolve()
        adapter = DeterministicRuleBasedAdapter()

        # 1. SyntaxError
        bad_syntax = ws / "broken.py"
        bad_syntax.write_text("def foo(\n    return 42\n", encoding="utf-8")
        err_syntax = f'File "{bad_syntax}", line 1\n    def foo(\nSyntaxError: was never closed'
        rep = adapter.diagnose_and_repair("fix syntax", {}, err_syntax, str(ws))
        assert rep is not None
        assert "def foo():" in rep["args"]["content"]

        # 2. Repeated identical error detection returns None to cut off infinite loops
        rep2 = adapter.diagnose_and_repair("fix syntax", {}, err_syntax, str(ws))
        assert rep2 is None

        # 3. Arithmetic defect (# BUG: return a - b)
        adapter2 = DeterministicRuleBasedAdapter()
        calc_py = ws / "calc.py"
        calc_py.write_text("def add(a, b):\n    # BUG: broken add\n    return a - b\n", encoding="utf-8")
        err_calc = 'FAILED test_calc.py::test_add - AssertionError: assert -1 == 5'
        rep_calc = adapter2.diagnose_and_repair("fix add", {}, err_calc, str(ws))
        assert rep_calc is not None
        assert "return a + b" in rep_calc["args"]["content"]

        # 4. ZeroDivisionError
        adapter3 = DeterministicRuleBasedAdapter()
        div_py = ws / "div.py"
        div_py.write_text("def div(x):\n    return x / 0\n", encoding="utf-8")
        err_div = "ZeroDivisionError: division by zero"
        rep_div = adapter3.diagnose_and_repair("fix div", {}, err_div, str(ws))
        assert rep_div is not None
        assert "/ 1" in rep_div["args"]["content"]

        # 5. General AssertionError inspection
        adapter4 = DeterministicRuleBasedAdapter()
        bool_py = ws / "checker.py"
        bool_py.write_text("def is_valid():\n    return False\n", encoding="utf-8")
        err_bool = "assert is_valid() == True\nAssertionError: assert False == True"
        rep_bool = adapter4.diagnose_and_repair("fix checker", {}, err_bool, str(ws))
        assert rep_bool is not None
        assert "return True" in rep_bool["args"]["content"]


def test_openai_adapter_missing_key_and_budget_exceeded():
    # Missing key raises ModelProviderNotConfiguredError
    adapter_no_key = OpenAIProviderAdapter(api_key="")
    with pytest.raises(ModelProviderNotConfiguredError, match="MODEL_PROVIDER_NOT_CONFIGURED"):
        adapter_no_key.generate_plan("goal", {}, ["read_file"])

    with pytest.raises(ModelProviderNotConfiguredError, match="MODEL_PROVIDER_NOT_CONFIGURED"):
        adapter_no_key.diagnose_and_repair("goal", {}, "err", "C:/")

    # Budget exceeded raises ModelBudgetExceededError
    adapter_budget = OpenAIProviderAdapter(api_key="sk-test", max_budget=0.001)
    adapter_budget.estimated_cost = 0.002
    with pytest.raises(ModelBudgetExceededError, match="BUDGET_EXHAUSTED"):
        adapter_budget._call_chat_completion([{"role": "user", "content": "hi"}])


def test_openai_adapter_mock_http_generate_plan(monkeypatch):
    adapter = OpenAIProviderAdapter(api_key="sk-test-live", max_budget=5.0)

    class MockResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            payload = {
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "plan": [
                                {
                                    "step_id": "step_1",
                                    "tool": "read_file",
                                    "args": {"path": "main.py"},
                                    "description": "Read main",
                                }
                            ]
                        })
                    }
                }],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            }
            return json.dumps(payload).encode("utf-8")

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=30.0: MockResponse())

    plan = adapter.generate_plan("Test goal", {"workspace_root": "C:/tmp"}, ["read_file"])
    assert len(plan) == 1
    assert plan[0]["step_id"] == "step_1"
    assert adapter.api_calls_count == 1
    assert adapter.estimated_cost > 0.0


def test_openai_adapter_mock_http_multiturn_diagnose_and_repair(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td).resolve()
        helper_py = ws / "helper.py"
        helper_py.write_text("def helper(): return 0\n", encoding="utf-8")

        adapter = OpenAIProviderAdapter(api_key="sk-test-live", max_budget=5.0)

        # Multi-turn mock:
        # Turn 1: requests context on helper.py
        # Turn 2: returns repair
        call_count = 0

        class MultiTurnMockResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    content = {
                        "action": "request_context",
                        "files": ["helper.py"],
                        "reason": "Need to inspect helper.py to find root cause",
                    }
                else:
                    content = {
                        "action": "repair",
                        "can_continue": True,
                        "diagnosis": "helper returned 0 instead of 42",
                        "tool": "write_file",
                        "args": {"path": "helper.py", "content": "def helper(): return 42\n"},
                        "reason": "Fixed helper constant",
                    }
                payload = {
                    "choices": [{"message": {"content": json.dumps(content)}}],
                    "usage": {"prompt_tokens": 200, "completion_tokens": 80},
                }
                return json.dumps(payload).encode("utf-8")

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=30.0: MultiTurnMockResponse())

        repair = adapter.diagnose_and_repair(
            objective="Fix helper defect",
            failed_step={"step_id": "test_step", "tool": "powershell_execute"},
            error_context=f'File "{helper_py}", line 1, in test_helper\nAssertionError: assert 0 == 42',
            workspace_root=str(ws),
        )

        assert repair is not None
        assert repair["tool"] == "write_file"
        assert "return 42" in repair["args"]["content"]
        assert repair["args"]["path"] == str(helper_py)
        assert adapter.api_calls_count == 2
        assert adapter.estimated_cost > 0.0


def test_openai_adapter_mock_http_abort(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td).resolve()
        adapter = OpenAIProviderAdapter(api_key="sk-test-live", max_budget=5.0)

        class AbortMockResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                content = {
                    "action": "abort",
                    "can_continue": False,
                    "reason": "Defect is unfixable or external",
                }
                payload = {
                    "choices": [{"message": {"content": json.dumps(content)}}],
                    "usage": {"prompt_tokens": 150, "completion_tokens": 40},
                }
                return json.dumps(payload).encode("utf-8")

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=30.0: AbortMockResponse())

        repair = adapter.diagnose_and_repair(
            objective="Fix external service",
            failed_step={},
            error_context="External service unreachable",
            workspace_root=str(ws),
        )
        assert repair is None
        assert adapter.api_calls_count == 1


def test_get_llm_adapter_factory():
    # 1. Default -> Deterministic
    a1 = get_llm_adapter()
    assert isinstance(a1, DeterministicRuleBasedAdapter)
    assert a1.provider_name == "deterministic_offline"

    # 2. prefer_live=False -> Deterministic
    a2 = get_llm_adapter(prefer_live=False)
    assert isinstance(a2, DeterministicRuleBasedAdapter)

    # 3. require_live=True without key -> raises ModelProviderNotConfiguredError
    with pytest.raises(ModelProviderNotConfiguredError, match="MODEL_PROVIDER_NOT_CONFIGURED"):
        get_llm_adapter(require_live=True, api_key="")

    # 4. require_live=True with invalid/unit_test key -> raises ModelProviderNotConfiguredError
    with pytest.raises(ModelProviderNotConfiguredError, match="MODEL_PROVIDER_NOT_CONFIGURED"):
        get_llm_adapter(require_live=True, api_key="sk-unit_test_fake")

    # 5. require_live=True with valid key -> OpenAIProviderAdapter
    a3 = get_llm_adapter(require_live=True, api_key="sk-real-live-token-12345")
    assert isinstance(a3, OpenAIProviderAdapter)
    assert a3.provider_name == "openai_live"
    assert a3.api_key == "sk-real-live-token-12345"

    # 6. prefer_live=True with valid key -> OpenAIProviderAdapter
    a4 = get_llm_adapter(prefer_live=True, api_key="sk-valid-token-67890")
    assert isinstance(a4, OpenAIProviderAdapter)
    assert a4.provider_name == "openai_live"

    # 7. prefer_live=True without valid key -> fallback to Deterministic
    a5 = get_llm_adapter(prefer_live=True, api_key="")
    assert isinstance(a5, DeterministicRuleBasedAdapter)


def test_operating_profiles_and_telemetry():
    assert OperatingProfile.OFFLINE_TEST_MODE == "OFFLINE_TEST_MODE"
    assert OperatingProfile.LIVE_AI_MODE == "LIVE_AI_MODE"

    # Deterministic telemetry
    det = DeterministicRuleBasedAdapter()
    tel_det = det.get_telemetry()
    assert tel_det == {
        "operating_profile": "OFFLINE_TEST_MODE",
        "provider_name": "deterministic_offline",
        "is_live_ai": False,
        "api_calls_count": 0,
        "estimated_cost_usd": 0.0,
    }

    # Mock telemetry
    mock = MockProviderAdapter()
    tel_mock = mock.get_telemetry()
    assert tel_mock == {
        "operating_profile": "OFFLINE_TEST_MODE",
        "provider_name": "mock",
        "is_live_ai": False,
        "api_calls_count": 0,
        "estimated_cost_usd": 0.0,
    }

    # Live telemetry
    live = OpenAIProviderAdapter(api_key="sk-real-live-token-12345")
    assert live.operating_profile == "LIVE_AI_MODE"
    assert live.provider_name == "openai_live"
    assert live.is_live_ai is True
    live._update_cost(1000, 200)
    tel_live = live.get_telemetry()
    assert tel_live["operating_profile"] == "LIVE_AI_MODE"
    assert tel_live["provider_name"] == "openai_live"
    assert tel_live["is_live_ai"] is True
    assert tel_live["api_calls_count"] == 1
    assert tel_live["estimated_cost_usd"] > 0.0


def test_live_ai_not_configured_error_properties():
    assert issubclass(LiveAINotConfiguredError, ModelProviderNotConfiguredError)
    assert LiveAINotConfiguredError.error_code == "LIVE_AI_NOT_CONFIGURED"
    assert LiveAINotConfiguredError.error_code == "MODEL_PROVIDER_NOT_CONFIGURED"

    err_default = LiveAINotConfiguredError()
    assert "LIVE_AI_NOT_CONFIGURED" in str(err_default)
    assert "MODEL_PROVIDER_NOT_CONFIGURED" in str(err_default)

    err_custom = LiveAINotConfiguredError("LIVE_AI_NOT_CONFIGURED (MODEL_PROVIDER_NOT_CONFIGURED): custom detail")
    assert "LIVE_AI_NOT_CONFIGURED" in str(err_custom)
    assert "MODEL_PROVIDER_NOT_CONFIGURED" in str(err_custom)


def test_get_llm_operating_status(monkeypatch):
    # 1. Unset key
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    st1 = get_llm_operating_status(api_key=None)
    assert st1 == {
        "status": "LIVE_AI_NOT_CONFIGURED",
        "operating_profile": "OFFLINE_TEST_MODE",
        "provider": "deterministic_offline",
        "is_live_ai": False,
        "reason": "OPENAI_API_KEY not configured by owner",
    }

    # 2. Empty or unit test placeholder key
    st2 = get_llm_operating_status(api_key="sk-unit_test_fake")
    assert st2["status"] == "LIVE_AI_NOT_CONFIGURED"
    assert st2["operating_profile"] == "OFFLINE_TEST_MODE"
    assert st2["is_live_ai"] is False

    # 3. Valid key via argument
    st3 = get_llm_operating_status(api_key="sk-real-live-token-12345")
    assert st3 == {
        "status": "LIVE_AI_CONFIGURED",
        "operating_profile": "LIVE_AI_MODE",
        "provider": "openai_live",
        "is_live_ai": True,
    }

    # 4. Valid key via environment variable
    monkeypatch.setenv("OPENAI_API_KEY", "sk-valid-token-67890")
    st4 = get_llm_operating_status()
    assert st4 == {
        "status": "LIVE_AI_CONFIGURED",
        "operating_profile": "LIVE_AI_MODE",
        "provider": "openai_live",
        "is_live_ai": True,
    }


def test_get_llm_adapter_operating_profiles(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    # 1. Explicit OFFLINE_TEST_MODE returns DeterministicRuleBasedAdapter even if key provided
    a_off = get_llm_adapter(profile=OperatingProfile.OFFLINE_TEST_MODE, api_key="sk-real-live-token-12345")
    assert isinstance(a_off, DeterministicRuleBasedAdapter)
    assert a_off.operating_profile == "OFFLINE_TEST_MODE"

    # 2. Explicit LIVE_AI_MODE with no key raises LiveAINotConfiguredError
    with pytest.raises(LiveAINotConfiguredError, match="LIVE_AI_NOT_CONFIGURED"):
        get_llm_adapter(profile=OperatingProfile.LIVE_AI_MODE, api_key="")

    # 3. Explicit LIVE_AI_MODE with placeholder key raises LiveAINotConfiguredError
    with pytest.raises(LiveAINotConfiguredError, match="LIVE_AI_NOT_CONFIGURED"):
        get_llm_adapter(profile=OperatingProfile.LIVE_AI_MODE, api_key="sk-unit_test_fake")

    # 4. Explicit LIVE_AI_MODE with valid key returns OpenAIProviderAdapter
    a_live = get_llm_adapter(profile=OperatingProfile.LIVE_AI_MODE, api_key="sk-real-live-token-12345")
    assert isinstance(a_live, OpenAIProviderAdapter)
    assert a_live.operating_profile == "LIVE_AI_MODE"
    assert a_live.is_live_ai is True

    # 5. Invalid profile raises ValueError
    with pytest.raises(ValueError, match="Unknown operating profile"):
        get_llm_adapter(profile="UNKNOWN_MODE")


def test_openai_adapter_unmocked_placeholder_raises_live_ai_not_configured():
    adapter = OpenAIProviderAdapter(api_key="sk-unit_test_fake")

    with pytest.raises(LiveAINotConfiguredError, match="LIVE_AI_NOT_CONFIGURED"):
        adapter.generate_plan("Test plan", {"workspace_root": "C:/tmp"}, ["read_file"])

    with pytest.raises(LiveAINotConfiguredError, match="LIVE_AI_NOT_CONFIGURED"):
        adapter.diagnose_and_repair("Test goal", {}, "error", "C:/tmp")
