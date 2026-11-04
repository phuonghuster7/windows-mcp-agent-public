import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from runtime.contracts import RuntimeStatePaths, ProductionWriteGuard


@pytest.fixture(autouse=True)
def guard_production_state(request, tmp_path_factory):
    """Active isolation guard ensuring test execution never alters production runtime/ or config/ state."""
    prod_stop_file = PROJECT_ROOT / "runtime" / "EMERGENCY_STOP"
    had_stop_file = prod_stop_file.exists()
    orig_content = prod_stop_file.read_text(encoding="utf-8") if had_stop_file else None

    # Isolate default MCP_STATE_ROOT via env var for each test
    iso_dir = tmp_path_factory.mktemp("test_state")
    (iso_dir / "runtime").mkdir(parents=True, exist_ok=True)
    (iso_dir / "runtime" / "logs").mkdir(parents=True, exist_ok=True)
    (iso_dir / "config").mkdir(parents=True, exist_ok=True)

    old_state_root = os.environ.get("MCP_STATE_ROOT")
    os.environ["MCP_STATE_ROOT"] = str(iso_dir)

    # Write-boundary guard protecting real production paths
    guard = ProductionWriteGuard(
        protected_roots=[PROJECT_ROOT / "runtime", PROJECT_ROOT / "config"],
        allowed_subpaths=[
            PROJECT_ROOT / "runtime" / "evidence",
            PROJECT_ROOT / "runtime" / "__pycache__",
            PROJECT_ROOT / "config" / "__pycache__",
        ],
        run_id=f"conftest_{request.node.name}",
    )
    guard.activate()
    try:
        yield guard
    finally:
        guard.deactivate()

        # Restore environment variable
        if old_state_root is not None:
            os.environ["MCP_STATE_ROOT"] = old_state_root
        else:
            os.environ.pop("MCP_STATE_ROOT", None)

        # Post-test verification: Production state must be identical to pre-test state
        now_has_stop_file = prod_stop_file.exists()
        if had_stop_file:
            assert now_has_stop_file, "TEST POLLUTION DETECTED: Production EMERGENCY_STOP was unlinked by test!"
            now_content = prod_stop_file.read_text(encoding="utf-8")
            assert now_content == orig_content, "TEST POLLUTION DETECTED: Production EMERGENCY_STOP content was mutated by test!"
        else:
            if now_has_stop_file:
                # Do NOT unlink production file on detection per Audit 28D9ED5 item 4
                pytest.fail("TEST POLLUTION DETECTED: Test created EMERGENCY_STOP in production runtime directory!")

        if guard.blocked_events:
            pytest.fail(
                f"TEST POLLUTION DETECTED: Intercepted {len(guard.blocked_events)} write attempts to production state: {guard.blocked_events}"
            )


@pytest.fixture
def isolated_runtime_paths(tmp_path):
    """Provide isolated runtime paths rooted in disposable tmp_path."""
    return RuntimeStatePaths.create_isolated(tmp_path)
