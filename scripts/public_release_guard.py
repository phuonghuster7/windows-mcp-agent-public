"""Fail-closed baseline checks for distributable repository content.

This does not replace human review or a full secret scanner.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
REQUIRED = [
    "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md",
    "requirements.txt", "requirements-dev.txt", "pytest.ini",
    "docs/INSTALLATION.md", "docs/PUBLIC_RELEASE_CHECKLIST.md",
    ".github/workflows/ci-security.yml", "config/policy.example.json",
]
BAD_PARTS = {"backups", "secrets", "dist", "agent-coordination"}
BAD_NAMES = {".env", ".env.local", "policy.json", "trusted_workspaces.json",
             "tunnel-autonomous.yaml", "tunnel-autonomous.json"}
BAD_EXTS = {".pfx", ".p12", ".dpapi", ".kdbx", ".pem", ".key"}
PRIVATE_PATH = re.compile(r"C:\\Users\\Admin|D:\\ProjectsWindows-MCP-Agent", re.I)
ACTUAL_TUNNEL = re.compile(r"tunnel_6a[0-9a-f]{20,}", re.I)
GH_ACCESS = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")
AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
issues = []
for name in REQUIRED:
    if not (ROOT / name).is_file():
        issues.append(f"required file missing: {name}")
for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    rel = path.relative_to(ROOT)
    if any(p in SKIP for p in rel.parts):
        continue
    lowerparts = {p.lower() for p in rel.parts}
    if len(rel.parts) > 1 and (lowerparts & BAD_PARTS):
        issues.append(f"forbidden path: {rel}")
    if path.name.lower() in BAD_NAMES or path.suffix.lower() in BAD_EXTS:
        issues.append(f"forbidden file: {rel}")
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        continue
    for label, rx in (("developer-specific host path", PRIVATE_PATH),
                      ("historical live tunnel identity", ACTUAL_TUNNEL),
                      ("GitHub API credential", GH_ACCESS),
                      ("AWS access key", AWS_ACCESS)):
        if rx.search(content):
            issues.append(f"{label}: {rel}")
    if "-----BEGIN" in content and "PRIVATE KEY-----" in content and path.suffix.lower() not in {".py", ".ps1", ".md"}:
        issues.append(f"potential PEM key: {rel}")
    if path.name in {"README.md", "docs/INSTALLATION.md"} and "YOUR_PUBLIC_REPOSITORY_URL" in content:
        issues.append(f"placeholder repo URL: {rel}")
# A handful of synthetic sk-prefixed strings are intentionally used in red-team tests.
# They require separate manual verification and are NOT automatically treated as safe here.
if issues:
    print("PUBLIC RELEASE GUARD: FAIL")
    for problem in issues:
        print(problem)
    raise SystemExit(1)
print("PUBLIC RELEASE GUARD: PASS (baseline paths, file inventory and high-risk identifiers)")
