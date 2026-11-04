"""Run Attested Regression Test Suite (TASK-102 / ANTI 4.0).

Executes pytest under strict provenance recording:
1. Records pre-test source commit (git rev-parse HEAD) and tree fingerprint.
2. Generates unique run_id.
3. Streams pytest execution to raw log with provenance header.
4. Verifies post-test source commit and tree fingerprint (detects mutations).
5. Computes SHA-256 hashes of JUnit XML and raw execution log.
6. Writes comprehensive test_run_attestation.json for packaging and manifest validation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def compute_tree_fingerprint_from_entries(entries: list[dict[str, Any]]) -> str:
    """Computes a deterministic SHA-256 fingerprint from packaged files inventory.

    Each entry is formatted as:
      f"{normalized_rel_path}:{sha256.upper()}\\n"
    Sorted ascending by normalized_rel_path.
    """
    normalized: list[tuple[str, str]] = []
    for entry in entries:
        rel = entry.get("relative_path", "").replace("\\", "/").lstrip("/")
        sha = str(entry.get("sha256", "")).strip().upper()
        if rel and sha:
            normalized.append((rel, sha))
    normalized.sort(key=lambda x: x[0])
    lines = "".join(f"{r}:{s}\n" for r, s in normalized)
    return hashlib.sha256(lines.encode("utf-8")).hexdigest().upper()


def enumerate_candidate_files(project_root: Path) -> list[str]:
    """Enumerates the exact set of release candidate files scanned by Build-ReleasePackage.ps1."""
    candidates: set[str] = set()

    # Root files (.md, LICENSE, .gitignore, .gitattributes)
    for item in project_root.iterdir():
        if item.is_file():
            if item.name in ("LICENSE", ".gitignore", ".gitattributes") or item.suffix.lower() == ".md":
                candidates.add(str(item.relative_to(project_root)).replace("\\", "/"))

    # .github/workflows/*.yml
    wf_dir = project_root / ".github" / "workflows"
    if wf_dir.is_dir():
        for item in wf_dir.glob("*.yml"):
            if item.is_file():
                candidates.add(str(item.relative_to(project_root)).replace("\\", "/"))

    # Code, Config, Scripts, Docs, Tests
    module_specs = [
        ("backend", [".py"], False),
        ("mcp-gateway", [".py", ".json"], False),
        ("desktop-agent", [".py"], False),
        ("config", [".json", ".yaml"], True),  # ExampleOnly
        ("scripts", [".ps1", ".py"], False),
        ("docs", [".md"], False),
        ("tests", [".py"], False),
    ]
    for dir_name, exts, example_only in module_specs:
        d = project_root / dir_name
        if d.is_dir():
            for item in d.iterdir():
                if item.is_file() and item.suffix.lower() in exts:
                    if example_only:
                        if item.name.endswith(".example.json") or item.name.endswith(".example.yaml"):
                            candidates.add(str(item.relative_to(project_root)).replace("\\", "/"))
                    else:
                        candidates.add(str(item.relative_to(project_root)).replace("\\", "/"))

    # Runtime code only (never logs, secrets, lockfiles, SQLite dbs, or jobs)
    rt_dir = project_root / "runtime"
    if rt_dir.is_dir():
        for item in rt_dir.glob("*.py"):
            if item.is_file():
                candidates.add(str(item.relative_to(project_root)).replace("\\", "/"))

    return sorted(candidates)


def compute_current_tree_fingerprint(project_root: Path) -> str:
    rel_files = enumerate_candidate_files(project_root)
    entries: list[dict[str, Any]] = []
    for rel in rel_files:
        full_path = project_root / rel
        if full_path.is_file():
            sha = compute_sha256(full_path)
            entries.append({"relative_path": rel, "sha256": sha})
    return compute_tree_fingerprint_from_entries(entries)


def get_git_head_commit(project_root: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "0" * 40


def run_attested_regression(
    project_root: Path = PROJECT_ROOT,
    pytest_args: list[str] | None = None,
    junit_path: Path | None = None,
    log_path: Path | None = None,
    attestation_path: Path | None = None,
) -> int:
    evidence_dir = project_root / "runtime" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if junit_path is None:
        junit_path = evidence_dir / "regression_junit.xml"
    if log_path is None:
        log_path = evidence_dir / "regression_full_run.log"
    if attestation_path is None:
        attestation_path = evidence_dir / "test_run_attestation.json"

    # Default pytest args
    if pytest_args is None:
        pytest_args = [
            "tests/",
            "-v",
            f"--junitxml={junit_path}",
            "-o",
            "junit_family=xunit2",
        ]
    else:
        # Ensure junitxml is included if not specified in custom args
        if not any(a.startswith("--junitxml") for a in pytest_args):
            pytest_args = list(pytest_args) + [f"--junitxml={junit_path}", "-o", "junit_family=xunit2"]

    pre_source_sha = get_git_head_commit(project_root)
    pre_tree_fingerprint = compute_current_tree_fingerprint(project_root)

    run_id = f"testrun-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    started_at_dt = datetime.now(timezone.utc)
    started_at_iso = started_at_dt.isoformat()

    pytest_cmd = [sys.executable, "-m", "pytest"] + pytest_args
    pytest_cmd_str = " ".join(pytest_cmd)

    header = (
        "=== TEST RUN PROVENANCE HEADER ===\n"
        f"RUN_ID: {run_id}\n"
        f"SOURCE_SHA: {pre_source_sha}\n"
        f"TREE_FINGERPRINT: {pre_tree_fingerprint}\n"
        f"PYTEST_CMD: {pytest_cmd_str}\n"
        f"STARTED_AT: {started_at_iso}\n"
        "==================================\n\n"
    )

    print(f"[*] Starting attested regression run: {run_id}")
    print(f"[*] Command: {pytest_cmd_str}")

    # Run pytest capturing stdout/stderr
    proc = subprocess.run(
        pytest_cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        check=False,
    )

    completed_at_dt = datetime.now(timezone.utc)
    completed_at_iso = completed_at_dt.isoformat()
    duration_seconds = round((completed_at_dt - started_at_dt).total_seconds(), 3)
    exit_code = proc.returncode

    # Write log file with header + stdout + stderr
    full_log_text = header + proc.stdout
    if proc.stderr:
        full_log_text += "\n=== STDERR ===\n" + proc.stderr
    log_path.write_text(full_log_text, encoding="utf-8")

    # Post-check tree mutation
    post_source_sha = get_git_head_commit(project_root)
    post_tree_fingerprint = compute_current_tree_fingerprint(project_root)
    tree_mutated = (post_source_sha.lower() != pre_source_sha.lower()) or (
        post_tree_fingerprint.upper() != pre_tree_fingerprint.upper()
    )

    junit_sha256 = compute_sha256(junit_path) if junit_path.exists() else ""
    log_sha256 = compute_sha256(log_path) if log_path.exists() else ""

    req_file = project_root / "requirements.txt"
    req_sha256 = compute_sha256(req_file) if req_file.exists() else ""

    try:
        rel_junit = str(junit_path.relative_to(project_root)).replace("\\", "/")
    except ValueError:
        rel_junit = str(junit_path)
    try:
        rel_log = str(log_path.relative_to(project_root)).replace("\\", "/")
    except ValueError:
        rel_log = str(log_path)

    attestation = {
        "run_id": run_id,
        "source_sha": pre_source_sha,
        "tree_fingerprint": pre_tree_fingerprint,
        "tree_mutated_during_test": tree_mutated,
        "pytest_command": pytest_cmd_str,
        "started_at": started_at_iso,
        "completed_at": completed_at_iso,
        "duration_seconds": duration_seconds,
        "exit_code": exit_code,
        "junit_path": rel_junit,
        "junit_sha256": junit_sha256,
        "log_path": rel_log,
        "log_sha256": log_sha256,
        "environment": {
            "python_version": sys.version,
            "platform": sys.platform,
            "executable": sys.executable,
            "requirements_sha256": req_sha256,
        },
    }

    attestation_path.write_text(json.dumps(attestation, indent=2), encoding="utf-8")
    print(f"[+] Test run attestation written to: {attestation_path}")
    print(f"[+] Exit code: {exit_code}, Duration: {duration_seconds}s, Mutated: {tree_mutated}")

    if tree_mutated:
        print("[-] WARNING: Working tree or git commit mutated during test run!")
        return 1 if exit_code == 0 else exit_code

    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Run attested pytest regression suite.")
    parser.add_argument(
        "--junit-path",
        default=None,
        help="Path to output JUnit XML (default: runtime/evidence/regression_junit.xml)",
    )
    parser.add_argument(
        "--log-path",
        default=None,
        help="Path to output execution log (default: runtime/evidence/regression_full_run.log)",
    )
    parser.add_argument(
        "--attestation-path",
        default=None,
        help="Path to output attestation JSON (default: runtime/evidence/test_run_attestation.json)",
    )
    parser.add_argument(
        "pytest_args",
        nargs="*",
        default=None,
        help="Arguments to forward to pytest (default: tests/ -v ...)",
    )
    args = parser.parse_args()

    junit_p = Path(args.junit_path).resolve() if args.junit_path else None
    log_p = Path(args.log_path).resolve() if args.log_path else None
    att_p = Path(args.attestation_path).resolve() if args.attestation_path else None
    fwd_args = args.pytest_args if args.pytest_args else None

    return run_attested_regression(
        project_root=PROJECT_ROOT,
        pytest_args=fwd_args,
        junit_path=junit_p,
        log_path=log_p,
        attestation_path=att_p,
    )


if __name__ == "__main__":
    sys.exit(main())
