"""Codex Web GPT Runtime Materialization & Integrity Verifier.

Audits runtime bundle files against manifest.json, verifies SHA-256 hashes,
validates launcher executables, and checks desktop runtime health.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _safe_home() -> Path:
    try:
        return Path.home()
    except RuntimeError:
        fallback = os.getenv("USERPROFILE") or os.getenv("HOME") or tempfile.gettempdir()
        return Path(fallback)


def compute_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file in 64KB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_runtime_bundle(runtime_dir: Path | None = None) -> dict:
    """Verify all files against manifest.json."""
    if runtime_dir is None:
        env_val = os.getenv("CODEX_RUNTIME_DIR")
        if env_val:
            runtime_dir = Path(env_val)
        else:
            candidates = [
                _safe_home() / "Desktop" / "Repo Codex Native2" / "codex-chatgpt-web" / "resources" / "runtime",
                Path(r"C:\Users\ExampleUser\Desktop\Repo Codex Native2\codex-chatgpt-web\resources\runtime"),
            ]
            for c in candidates:
                if c.exists():
                    runtime_dir = c
                    break

    if not runtime_dir or not runtime_dir.exists():
        return {
            "status": "SKIPPED",
            "reason": f"Codex runtime directory not found at candidate locations: {runtime_dir}",
            "verified_at": time.time(),
        }

    manifest_path = runtime_dir / "manifest.json"
    if not manifest_path.exists():
        return {
            "status": "FAILED",
            "reason": f"manifest.json missing at {manifest_path}",
            "verified_at": time.time(),
        }

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bundle_id = manifest.get("bundleId")
    files_list = manifest.get("files", [])

    total_files = len(files_list)
    matched = 0
    missing = []
    mismatched = []

    for entry in files_list:
        rel_path = entry.get("path")
        if not rel_path:
            continue
        fp = runtime_dir / rel_path
        if not fp.exists():
            missing.append(rel_path)
            continue

        expected_size = entry.get("size")
        actual_size = fp.stat().st_size
        if expected_size is not None and actual_size != expected_size:
            mismatched.append({
                "path": rel_path,
                "error": f"Size mismatch: expected {expected_size}, got {actual_size}",
            })
            continue

        expected_sha = entry.get("sha256")
        if expected_sha:
            actual_sha = compute_sha256(fp)
            if actual_sha.lower() != expected_sha.lower():
                mismatched.append({
                    "path": rel_path,
                    "error": f"SHA256 mismatch: expected {expected_sha}, got {actual_sha}",
                })
                continue

        matched += 1

    # Verify launcher & bun.exe
    bun_exe = runtime_dir / "runtime" / "bun.exe"
    bun_ok = False
    bun_ver = ""
    if bun_exe.exists():
        try:
            res = subprocess.run([str(bun_exe), "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                bun_ok = True
                bun_ver = res.stdout.strip()
        except Exception as ex:
            bun_ver = f"Error: {ex}"

    status = "PASS" if (len(missing) == 0 and len(mismatched) == 0 and bun_ok) else "FAILED"

    return {
        "status": status,
        "runtime_dir": str(runtime_dir),
        "bundle_id": bundle_id,
        "total_manifest_files": total_files,
        "matched_files": matched,
        "missing_count": len(missing),
        "mismatched_count": len(mismatched),
        "missing_samples": missing[:5],
        "mismatched_samples": mismatched[:5],
        "bun_executable_functional": bun_ok,
        "bun_version": bun_ver,
        "verified_at": time.time(),
    }


if __name__ == "__main__":
    result = verify_runtime_bundle()
    print(json.dumps(result, indent=2))
    if result["status"] == "FAILED":
        sys.exit(1)
