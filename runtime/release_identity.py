"""Single Source of Truth for Release Identity (Audit / Release Identity Model)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_CACHED_RELEASE_IDENTITY: dict[str, Any] | None = None


def get_release_identity() -> dict[str, Any]:
    global _CACHED_RELEASE_IDENTITY
    if _CACHED_RELEASE_IDENTITY is not None:
        return dict(_CACHED_RELEASE_IDENTITY)

    manifest_paths = [
        PROJECT_ROOT / "dist" / "release-manifest.json",
        PROJECT_ROOT / "runtime" / "evidence" / "release-evidence-manifest.json",
    ]
    manifest_data: dict[str, Any] = {}
    for mp in manifest_paths:
        if mp.exists():
            try:
                data = json.loads(mp.read_text(encoding="utf-8"))
                if data.get("version"):
                    manifest_data = data
                    break
            except Exception:
                pass

    rel_version = str(manifest_data.get("version") or "v1.0.0-rc3")
    source_commit = str(manifest_data.get("source_commit") or "")
    build_id = str(manifest_data.get("build_id") or "")
    zip_sha256 = str(manifest_data.get("zip_sha256") or "")

    if not source_commit or source_commit in ("unknown", "HEAD"):
        try:
            import subprocess
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                source_commit = proc.stdout.strip()
        except Exception:
            source_commit = "unknown"

    _CACHED_RELEASE_IDENTITY = {
        "release_version": rel_version,
        "source_commit": source_commit,
        "build_id": build_id or "local_build",
        "zip_sha256": zip_sha256 or "unknown",
    }
    return dict(_CACHED_RELEASE_IDENTITY)
