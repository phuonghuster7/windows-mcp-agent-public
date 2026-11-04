"""Evidence and Release Manifest Validator (Audit 28D9ED5 / Gate G06).

Validates:
1. dist/release-manifest.json structure, required fields, and SHA-256 hash integrity.
2. Exact Git commit SHA linkage (source_commit and tested_commit).
3. Existence and semantic validity of raw regression evidence files (log and JUnit XML).
4. Raw log semantic execution markers and cross-check against JUnit XML counts.
5. ZIP package integrity, forbidden secret/state leak scan, and 100% inventory SHA-256 matching.
6. Optional Verification Report gate claim consistency against required evidence.
7. Fails with non-zero exit code on missing files, stale commit, hash mismatch, or false PASS claims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent

FORBIDDEN_EXTENSIONS = {
    ".dpapi",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".kdbx",
    ".db",
    ".sqlite",
    ".sqlite3",
}

FORBIDDEN_DIR_PREFIXES = (
    "runtime/secrets/",
    "runtime/logs/",
    "backups/",
)

ALLOWED_DIRTY_PREFIXES: tuple[str, ...] = ()


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def compute_tree_fingerprint_from_entries(entries: list[dict]) -> str:
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


def _validate_l4_evidence(
    data: dict,
    manifest_dir: Path,
    source_commit: str,
    errors: list[str],
) -> None:
    l4_ev = data.get("l4_live_chatgpt_web_evidence")
    if not l4_ev or not isinstance(l4_ev, dict) or l4_ev.get("layer") != "L4_LIVE_CHATGPT_WEB":
        errors.append("False PASS claim: L3 evidence cannot substitute for L4 ChatGPT Web acceptance")
        return

    nonce = str(l4_ev.get("request_nonce", "")).strip()
    if len(nonce) < 12:
        errors.append(f"L4 evidence missing valid request_nonce (must be string >= 12 chars, got: '{nonce}')")

    cloud_req_id = str(l4_ev.get("cloud_request_id", "")).strip()
    if not cloud_req_id:
        errors.append("L4 evidence missing cloud_request_id")

    tunnel_id = str(l4_ev.get("connector_tunnel_id", "")).strip()
    if not tunnel_id or "<" in tunnel_id or "placeholder" in tunnel_id.lower():
        errors.append(f"L4 evidence missing real connector_tunnel_id (got: '{tunnel_id}')")

    auth_p = l4_ev.get("auth_principal")
    if not isinstance(auth_p, dict) or not auth_p.get("subject") or not auth_p.get("client_id"):
        errors.append("L4 evidence missing auth_principal with valid 'subject' and 'client_id'")

    manifest_build_id = str(data.get("build_id", "")).strip()
    dep_build_id = str(l4_ev.get("deployed_build_id", "")).strip()
    if not dep_build_id or (manifest_build_id and dep_build_id != manifest_build_id):
        errors.append(f"L4 evidence deployed_build_id mismatch with manifest build_id ('{dep_build_id}' vs '{manifest_build_id}')")

    dep_sha = str(l4_ev.get("deployed_commit_sha", "")).strip().lower()
    if not dep_sha or dep_sha != source_commit.lower():
        errors.append(f"L4 evidence deployed_commit_sha mismatch with source_commit ('{dep_sha}' vs '{source_commit.lower()}')")

    audit_ev_id = str(l4_ev.get("audit_event_id", "")).strip()
    raw_audit_path = l4_ev.get("audit_log_path", "")
    if not raw_audit_path or not audit_ev_id:
        errors.append("L4 evidence missing audit_log_path or audit_event_id")
    else:
        audit_path = resolve_candidate_path(manifest_dir, raw_audit_path)
        if not audit_path.exists():
            errors.append(f"L4 evidence audit log file not found: {audit_path}")
        else:
            audit_text = audit_path.read_text(encoding="utf-8", errors="ignore")
            if audit_ev_id not in audit_text:
                errors.append(f"L4 evidence audit log does not contain audit_event_id '{audit_ev_id}'")
            if nonce and nonce not in audit_text:
                errors.append(f"L4 evidence audit log does not contain request_nonce '{nonce}'")

    owe = l4_ev.get("observed_windows_effect")
    if not isinstance(owe, dict):
        errors.append("L4 evidence missing observed_windows_effect dictionary")
    else:
        raw_effect_path = owe.get("effect_path", "")
        if not raw_effect_path:
            errors.append("L4 evidence observed_windows_effect missing effect_path")
        else:
            effect_path = resolve_candidate_path(manifest_dir, raw_effect_path)
            if not effect_path.exists():
                errors.append(f"L4 evidence observed_windows_effect file not found: {effect_path}")
            else:
                effect_text = effect_path.read_text(encoding="utf-8", errors="ignore")
                if nonce and nonce not in effect_text:
                    errors.append(f"L4 evidence observed_windows_effect file does not contain request_nonce '{nonce}'")
                exp_sha = str(owe.get("expected_sha256", "")).strip().upper()
                if exp_sha:
                    act_sha = compute_sha256(effect_path).upper()
                    if act_sha != exp_sha:
                        errors.append(f"L4 evidence observed_windows_effect SHA-256 mismatch: actual={act_sha}, expected={exp_sha}")


def resolve_candidate_path(manifest_dir: Path, rel_or_abs: str | Path) -> Path:
    p = Path(rel_or_abs)
    if p.is_absolute():
        return p
    cand_manifest = manifest_dir / p
    if cand_manifest.exists():
        return cand_manifest
    cand_proj = PROJECT_ROOT / p
    if cand_proj.exists():
        return cand_proj
    return cand_manifest


def _is_claim_active(val: object) -> bool:
    if isinstance(val, bool):
        return val is True
    if isinstance(val, str):
        v = val.strip().upper()
        return v in ("PASS", "CLOSED", "GO", "TRUE", "VERIFIED")
    return False


def _has_manifest_gate_claim(data: dict, gate_names: list[str]) -> bool:
    for g in gate_names:
        g_clean = g.strip().lower().replace(" ", "_").replace("-", "_")
        for suffix in ("", "_status", "_verdict", "_state", "_claim"):
            k = f"{g_clean}{suffix}"
            if k in data and _is_claim_active(data[k]):
                return True
        for container in ("gates", "claims"):
            if container in data and isinstance(data[container], dict):
                c = data[container]
                for key_variant in (g, g.upper(), g.lower(), g_clean):
                    if key_variant in c and _is_claim_active(c[key_variant]):
                        return True
    return False


def _report_claims_g5_l4(text: str) -> bool:
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) >= 3:
            gate_col, scope_col, status_col = cells[0], cells[1], cells[2]
            row_str = f"{gate_col} {scope_col}".upper()
            status_upper = status_col.upper()
            if ("G5" in row_str or "L4" in row_str or "CHATGPT WEB" in row_str) and any(
                w in status_upper for w in ("PASS", "CLOSED", "GO")
            ):
                if "UNVERIFIED" in status_upper and "L4" in status_upper:
                    continue
                if "(L3" in status_upper and "UNVERIFIED" in status_upper:
                    continue
                return True
    if re.search(r"(?:VERDICT:\s*)?(?:PASS|CLOSED|GO)\s+(?:FOR\s+)?L4(?:\s+CHATGPT\s+WEB)?\b", text, re.IGNORECASE):
        return True
    return False


def _report_claims_g4_soak(text: str) -> bool:
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) >= 3:
            gate_col, scope_col, status_col = cells[0], cells[1], cells[2]
            row_str = f"{gate_col} {scope_col}".upper()
            status_upper = status_col.upper()
            if ("G4" in row_str or "SOAK" in row_str) and any(
                w in status_upper for w in ("PASS", "CLOSED", "GO")
            ):
                if "PARTIAL" in status_upper or "UNVERIFIED" in status_upper or "BLOCKED" in status_upper:
                    continue
                return True
    if re.search(r"(?:30-minute\s+soak|G4\s+Soak).*?\|\s*(?:\*\*)?(?:PASS|CLOSED|GO)\b", text, re.IGNORECASE):
        return True
    return False


def _report_claims_g6_clean_vm(text: str) -> bool:
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) >= 3:
            gate_col, scope_col, status_col = cells[0], cells[1], cells[2]
            row_str = f"{gate_col} {scope_col}".upper()
            status_upper = status_col.upper()
            if ("G6" in row_str or ("CLEAN" in row_str and "VM" in row_str)) and any(
                w in status_upper for w in ("PASS", "CLOSED", "GO")
            ):
                if "UNVERIFIED" in status_upper or "BLOCKED" in status_upper:
                    continue
                return True
    if re.search(r"(?<!NO-)(?<!NO\s)(?:GO|PASS|CLOSED)\s+(?:FOR\s+)?PUBLIC\s+PACKAGED\s+RELEASE\b", text, re.IGNORECASE):
        return True
    if re.search(r"VERDICT:\s*(?<!NO-)(?<!NO\s)(?:GO|PASS|CLOSED)\s+(?:FOR\s+)?PUBLIC\s+PACKAGED\s+RELEASE\b", text, re.IGNORECASE):
        return True
    return False


def _report_claims_g2_provider(text: str) -> bool:
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) >= 3:
            gate_col, scope_col, status_col = cells[0], cells[1], cells[2]
            row_str = f"{gate_col} {scope_col}".upper()
            status_upper = status_col.upper()
            if ("G2" in row_str or "AUTONOMOUS AI" in row_str or "GENERALIZED WORKER" in row_str) and any(
                w in status_upper for w in ("PASS", "CLOSED", "GO")
            ):
                if "BLOCKED" in status_upper or "UNVERIFIED" in status_upper or "EXPERIMENTAL" in status_upper:
                    continue
                return True
    if re.search(r"\|\s*\*\*G2\*\*.*?\|\s*(?:PASS|GO)\b", text, re.IGNORECASE):
        if not re.search(r"\|\s*\*\*G2\*\*.*?\|\s*(?:BLOCKED|UNVERIFIED|EXPERIMENTAL)", text, re.IGNORECASE):
            return True
    return False


def _validate_report_provenance_consistency(
    rep_text: str,
    report_name: str,
    data: dict,
    total_xml_tests: int,
    actual_passed: int,
    actual_skipped: int,
) -> list[str]:
    rep_errors: list[str] = []

    # 1. Packaged File Count
    p_files1 = re.findall(
        r"(?:Included\s+Files(?:\s+Count)?|Packaged\s+Files(?:\s+Count)?|included_files_count|Files\s+in\s+ZIP|tổng\s+số\s+file\s+đóng\s+gói)[^\n\d]{1,40}\b(\d{2,4})\b",
        rep_text,
        re.IGNORECASE,
    )
    p_files2 = re.findall(
        r"\b(\d{2,4})\s+(?:clean\s+)?(?:tracked\s+|release\s+|packaged\s+)?files\s+(?:packaged|in\s+ZIP|in\s+archive|in\s+release\s+manifest|trong\s+gói)",
        rep_text,
        re.IGNORECASE,
    )
    declared_files = int(data.get("included_files_count", 0))
    checked_file_counts = set(int(x) for x in (p_files1 + p_files2))
    for fc in checked_file_counts:
        if fc != declared_files:
            rep_errors.append(
                f"Report provenance mismatch in {report_name}: report claims {fc} packaged files, but manifest has {declared_files}"
            )

    # 2. JUnit Total/Passed Test Count
    p_passed = re.findall(r"\b(\d{3,4})\s+passed\b", rep_text, re.IGNORECASE)
    p_total1 = re.findall(
        r"(?:Total\s+Tests|Regression\s+Suite|junit_summary\.tests|Tổng\s+số\s+test)[^\n\d]{1,40}\b(\d{3,4})\b",
        rep_text,
        re.IGNORECASE,
    )
    p_total2 = re.findall(r"\b(\d{3,4})\s+test\s+items\b", rep_text, re.IGNORECASE)

    checked_totals = set(int(x) for x in (p_total1 + p_total2))
    for tc in checked_totals:
        if total_xml_tests > 0 and tc != total_xml_tests:
            rep_errors.append(
                f"Report provenance mismatch in {report_name}: report claims test count {tc}, but JUnit XML/manifest has tests={total_xml_tests}, passed={actual_passed}"
            )

    checked_passed = set(int(x) for x in p_passed)
    for pc in checked_passed:
        if actual_passed > 0 and pc != actual_passed:
            rep_errors.append(
                f"Report provenance mismatch in {report_name}: report claims test count {pc} passed, but JUnit XML/manifest has tests={total_xml_tests}, passed={actual_passed}"
            )

    # 3. Source/Tested Commit SHA
    manifest_source_commit = str(data.get("source_commit", "")).strip().lower()
    for line in rep_text.splitlines():
        trimmed = line.strip()
        lower_line = trimmed.lower()
        if any(w in lower_line for w in ("source commit", "tested commit", "source freeze commit", "head commit", "frozen commit", "**commit**")):
            if any(w in lower_line for w in ("baseline", "audit baseline", "previous", "historical", "prior commit")):
                continue
            sha_m = re.search(r"\b([0-9a-f]{40})\b", trimmed, re.IGNORECASE)
            if not sha_m:
                sha_m = re.search(r"\b([0-9a-f]{7,8})\b", trimmed, re.IGNORECASE)
            if sha_m:
                found_sha = sha_m.group(1).lower()
                if not manifest_source_commit.startswith(found_sha):
                    rep_errors.append(
                        f"Report provenance mismatch in {report_name}: report claims commit '{found_sha}', but manifest has '{manifest_source_commit}'"
                    )

    return rep_errors


def validate_manifest(
    manifest_path: Path | str,
    expected_commit: str | None = None,
    check_git: bool = True,
    report_path: Path | str | list[Path | str] | None = None,
    check_default_reports: bool = False,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    manifest_file = Path(manifest_path).resolve()
    manifest_dir = manifest_file.parent

    if not manifest_file.exists():
        return False, [f"Manifest file not found: {manifest_file}"]

    try:
        data = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as e:
        return False, [f"Failed to parse manifest JSON: {e}"]

    # 1. Required top-level keys
    required_keys = [
        "schema_version",
        "version",
        "package_name",
        "zip_path",
        "zip_size_bytes",
        "zip_sha256",
        "secret_scan_passed",
        "secret_violations",
        "included_files_count",
        "files",
        "build_id",
        "repository",
        "branch",
        "source_commit",
        "tested_commit",
        "raw_evidence_log",
        "raw_evidence_junit",
    ]
    for k in required_keys:
        if k not in data:
            errors.append(f"Missing required key in manifest: '{k}'")

    if errors:
        return False, errors

    # 2. Commit & Provenance Verification
    sha_regex = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
    source_commit = str(data.get("source_commit", "")).strip()
    tested_commit = str(data.get("tested_commit", "")).strip()

    for c_field, c_val in (("source_commit", source_commit), ("tested_commit", tested_commit)):
        if not sha_regex.match(c_val):
            errors.append(f"Field '{c_field}' must be a 40-character git commit SHA, got: '{c_val}'")

    if sha_regex.match(source_commit) and sha_regex.match(tested_commit):
        if source_commit.lower() != tested_commit.lower():
            errors.append(f"source_commit != tested_commit: '{source_commit}' vs '{tested_commit}'")

    if expected_commit is not None:
        exp = str(expected_commit).strip().lower()
        if source_commit.lower() != exp or tested_commit.lower() != exp:
            errors.append(
                f"Commit mismatch with expected HEAD: source='{source_commit}', tested='{tested_commit}', expected='{exp}'"
            )
    elif check_git:
        try:
            repo_to_check = PROJECT_ROOT
            if data.get("repository") and Path(str(data["repository"])).exists():
                repo_to_check = Path(str(data["repository"]))
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(repo_to_check),
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                actual_head = res.stdout.strip().lower()
                if source_commit.lower() != actual_head or tested_commit.lower() != actual_head:
                    errors.append(
                        f"Commit mismatch with git HEAD: source='{source_commit}', tested='{tested_commit}', HEAD='{actual_head}'"
                    )
        except Exception:
            pass

    # Working tree clean claim check
    if data.get("working_tree_clean") is True and check_git:
        try:
            repo_to_check = PROJECT_ROOT
            if data.get("repository") and Path(str(data["repository"])).exists():
                repo_to_check = Path(str(data["repository"]))
            res = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(repo_to_check),
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if res.returncode == 0:
                dirty_files = []
                for line in res.stdout.splitlines():
                    trimmed = line.strip()
                    if not trimmed:
                        continue
                    parts = trimmed.split(maxsplit=1)
                    if len(parts) == 2:
                        raw_path = parts[1].strip().strip('"').replace("\\", "/")
                        if not any(
                            raw_path == p or raw_path.startswith(p)
                            for p in ALLOWED_DIRTY_PREFIXES
                        ):
                            dirty_files.append(raw_path)
                if dirty_files:
                    errors.append(
                        f"Dirty working tree contradicts manifest clean claim: {len(dirty_files)} modified/untracked file(s) found ({', '.join(dirty_files[:5])})"
                    )
        except Exception:
            pass

    # 3. Zip Package Verification & Inventory Semantic Check
    zip_path = resolve_candidate_path(manifest_dir, data["zip_path"])
    if not zip_path.exists():
        errors.append(f"Release zip package does not exist: {zip_path}")
    else:
        actual_size = zip_path.stat().st_size
        if actual_size != data["zip_size_bytes"]:
            errors.append(f"Zip size mismatch: manifest={data['zip_size_bytes']}, actual={actual_size}")
        actual_hash = compute_sha256(zip_path)
        if actual_hash.upper() != data["zip_sha256"].upper():
            errors.append(f"Zip SHA256 mismatch: manifest={data['zip_sha256']}, actual={actual_hash}")

        # Deep ZIP inspection
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                all_zip_entries: dict[str, zipfile.ZipInfo] = {}
                for zinfo in zf.infolist():
                    if zinfo.is_dir():
                        continue
                    clean_name = zinfo.filename.replace("\\", "/").lstrip("/")
                    all_zip_entries[clean_name] = zinfo

                    # Secret / state leak scanning
                    b_name = Path(clean_name).name
                    ext = Path(clean_name).suffix.lower()
                    if b_name.startswith(".env") and b_name != ".env.example":
                        errors.append(f"Forbidden secret or state file leaked inside ZIP archive: '{clean_name}'")
                    elif ext in FORBIDDEN_EXTENSIONS:
                        errors.append(f"Forbidden secret or state file leaked inside ZIP archive: '{clean_name}'")
                    elif any(clean_name.startswith(pfx) for pfx in FORBIDDEN_DIR_PREFIXES):
                        if not clean_name.endswith(".gitkeep"):
                            errors.append(f"Forbidden secret or state file leaked inside ZIP archive: '{clean_name}'")
                    elif clean_name.startswith("config/") and not clean_name.endswith(".example.json") and not clean_name.endswith(".example.yaml"):
                        errors.append(f"Forbidden host-specific config file leaked inside ZIP archive: '{clean_name}'")

                    # DEFECT-04: Scan content for canary secrets and host paths
                    try:
                        entry_bytes = zf.read(zinfo)
                        lower_bytes = entry_bytes.lower()
                        canary_exempt = clean_name in {
                            "scripts/Build-ReleasePackage.ps1",
                            "scripts/validate_evidence_manifest.py",
                            "tests/test_evidence_validator_semantic.py",
                            "tests/test_s6_installer_and_migration.py",
                        }
                        if not canary_exempt and (
                            b"canary_secret_" in lower_bytes or b"canary_host_path_" in lower_bytes
                        ):
                            errors.append(f"Forbidden host path or canary secret leaked inside ZIP archive: '{clean_name}'")
                        elif clean_name.startswith("config/"):
                            if (
                                b"c:\\users\\admin" in lower_bytes
                                or b"c:\\\\users\\\\admin" in lower_bytes
                                or b"c:/users/admin" in lower_bytes
                                or b"d:\\projectswindows-mcp-agent" in lower_bytes
                                or b"d:\\\\projectswindows-mcp-agent" in lower_bytes
                                or b"d:/projectswindows-mcp-agent" in lower_bytes
                            ):
                                errors.append(f"Forbidden host path or canary secret leaked inside ZIP archive: '{clean_name}'")
                    except Exception as e:
                        errors.append(f"Could not read entry '{clean_name}' inside ZIP archive: {e}")

                # Match against manifest files
                manifest_files_map = {
                    f["relative_path"].replace("\\", "/").lstrip("/"): f
                    for f in data.get("files", [])
                }

                # Non-gitkeep zip entries
                actual_content_entries = {
                    k: v for k, v in all_zip_entries.items() if not k.endswith(".gitkeep")
                }

                # Check declared vs actual
                for rel_path, entry in manifest_files_map.items():
                    if rel_path not in actual_content_entries:
                        errors.append(
                            f"Inventory mismatch between manifest and ZIP archive: declared file '{rel_path}' missing from ZIP"
                        )
                    else:
                        content_bytes = zf.read(actual_content_entries[rel_path])
                        c_size = len(content_bytes)
                        c_sha = hashlib.sha256(content_bytes).hexdigest().upper()
                        if c_size != entry.get("size_bytes"):
                            errors.append(
                                f"Inventory mismatch between manifest and ZIP archive: '{rel_path}' size mismatch (manifest={entry.get('size_bytes')}, actual={c_size})"
                            )
                        if c_sha != str(entry.get("sha256", "")).upper():
                            errors.append(
                                f"Inventory mismatch between manifest and ZIP archive: '{rel_path}' SHA-256 mismatch (manifest={entry.get('sha256')}, actual={c_sha})"
                            )

                for clean_name in actual_content_entries:
                    if clean_name not in manifest_files_map:
                        errors.append(
                            f"Inventory mismatch between manifest and ZIP archive: undeclared file '{clean_name}' found in ZIP"
                        )
        except zipfile.BadZipFile as e:
            errors.append(f"Invalid ZIP archive file: {e}")

    # 4. Secret Scan & File Count Top-Level Verification
    if not data.get("secret_scan_passed", False) or data.get("secret_violations", 1) != 0:
        errors.append(f"Secret scan validation failed: violations={data.get('secret_violations')}")

    files_list = data.get("files", [])
    if len(files_list) != data.get("included_files_count", 0):
        errors.append(f"File count mismatch: declared={data.get('included_files_count')}, actual={len(files_list)}")

    # 5. Raw Evidence JUnit XML Semantic Parsing
    junit_path = resolve_candidate_path(manifest_dir, data.get("raw_evidence_junit", ""))
    xml_parsed_ok = False
    total_xml_tests = 0
    total_xml_failures = 0
    total_xml_errors = 0
    total_xml_skipped = 0

    if not junit_path.exists():
        errors.append(f"Evidence file missing on disk: {junit_path} (raw_evidence_junit)")
    elif junit_path.stat().st_size == 0:
        errors.append(f"Evidence file is empty on disk: {junit_path} (raw_evidence_junit)")
    else:
        try:
            tree = ET.parse(junit_path)
            root = tree.getroot()
            testcases = root.findall(".//testcase")
            if len(testcases) > 0:
                total_xml_tests = len(testcases)
                total_xml_failures = len(root.findall(".//testcase/failure"))
                total_xml_errors = len(root.findall(".//testcase/error"))
                total_xml_skipped = len(root.findall(".//testcase/skipped"))
            else:
                suites = root.findall(".//testsuite")
                if not suites and root.tag == "testsuite":
                    suites = [root]
                total_xml_tests = sum(int(s.attrib.get("tests", 0)) for s in suites)
                total_xml_failures = sum(int(s.attrib.get("failures", 0)) for s in suites)
                total_xml_errors = sum(int(s.attrib.get("errors", 0)) for s in suites)
                total_xml_skipped = sum(int(s.attrib.get("skipped", 0)) for s in suites)

            xml_parsed_ok = True

            if total_xml_tests <= 0:
                errors.append(f"Zero tests in JUnit: found {total_xml_tests} tests in {junit_path}")
            if total_xml_failures > 0 or total_xml_errors > 0:
                errors.append(
                    f"JUnit contains failures or errors: failures={total_xml_failures}, errors={total_xml_errors}"
                )
            if total_xml_tests > 0 and total_xml_skipped >= total_xml_tests:
                errors.append(f"All tests were skipped: skipped={total_xml_skipped}, total={total_xml_tests}")

            # Manifest junit_summary matching
            if "junit_summary" in data and isinstance(data["junit_summary"], dict):
                js = data["junit_summary"]
                exp_tests = js.get("tests")
                exp_passed = js.get("passed")
                exp_skipped = js.get("skipped")
                exp_failures = js.get("failures", 0)
                exp_errors = js.get("errors", 0)
                actual_passed = total_xml_tests - total_xml_failures - total_xml_errors - total_xml_skipped
                if (
                    exp_tests != total_xml_tests
                    or exp_failures != total_xml_failures
                    or exp_errors != total_xml_errors
                    or exp_skipped != total_xml_skipped
                    or (exp_passed is not None and exp_passed != actual_passed)
                ):
                    errors.append(
                        f"junit_summary count mismatch between manifest and JUnit XML: manifest={js}, actual={{'tests': {total_xml_tests}, 'passed': {actual_passed}, 'skipped': {total_xml_skipped}, 'failures': {total_xml_failures}, 'errors': {total_xml_errors}}}"
                    )
        except Exception as e:
            errors.append(f"Invalid JUnit XML: {e}")

    # 6. Raw Evidence Log Semantic Parsing & Cross-Check
    log_text: str | None = None
    log_path = resolve_candidate_path(manifest_dir, data.get("raw_evidence_log", ""))
    if not log_path.exists():
        errors.append(f"Evidence file missing on disk: {log_path} (raw_evidence_log)")
    elif log_path.stat().st_size == 0:
        errors.append(f"Evidence file is empty on disk: {log_path} (raw_evidence_log)")
    else:
        raw_bytes = log_path.read_bytes()
        log_text = None
        for enc in ("utf-8", "utf-16le", "utf-16", "cp1252", "latin-1"):
            try:
                log_text = raw_bytes.decode(enc)
                break
            except Exception:
                continue

        if log_text is None:
            errors.append(f"Could not decode raw evidence log file: {log_path}")
        else:
            has_start = bool(
                re.search(r"test session starts|collected\s+\d+\s+items?", log_text, re.IGNORECASE)
            )
            summary_match = re.search(r"=+\s*(.*?in\s+[\d\.]+s.*?)=+", log_text, re.IGNORECASE)

            if not has_start or not summary_match:
                errors.append("Raw log missing valid pytest execution markers and summary")
            else:
                summary_content = summary_match.group(1).strip()
                # Check for explicit failure markers in summary
                fail_match = re.search(r"\b(\d+)\s+failed\b", summary_content, re.IGNORECASE)
                err_match = re.search(r"\b(\d+)\s+error(?:s)?\b", summary_content, re.IGNORECASE)
                if fail_match or err_match:
                    errors.append(f"Pytest raw log reports failed or error tests: '{summary_content}'")

                passed_match = re.search(r"\b(\d+)\s+passed\b", summary_content, re.IGNORECASE)
                log_passed = int(passed_match.group(1)) if passed_match else 0
                skipped_match = re.search(r"\b(\d+)\s+skipped\b", summary_content, re.IGNORECASE)
                log_skipped = int(skipped_match.group(1)) if skipped_match else 0

                if xml_parsed_ok:
                    expected_xml_passed = (
                        total_xml_tests - total_xml_failures - total_xml_errors - total_xml_skipped
                    )
                    if log_passed != expected_xml_passed or log_skipped != total_xml_skipped:
                        errors.append(
                            f"Count mismatch between raw log and JUnit XML: log has passed={log_passed}, skipped={log_skipped} vs xml passed={expected_xml_passed}, skipped={total_xml_skipped}"
                        )

            if "run_id" in data and data["run_id"]:
                expected_run_id = str(data["run_id"]).strip()
                if expected_run_id and ("run_id" in log_text.lower() or "run-" in log_text.lower()):
                    if expected_run_id.lower() not in log_text.lower():
                        errors.append(
                            f"run_id mismatch: manifest declared '{expected_run_id}' not found in raw execution log"
                        )

    # 7. Test-Run Attestation & Tree Fingerprint Verification (TASK-102)
    expected_tree_fp = compute_tree_fingerprint_from_entries(data.get("files", []))
    if "tree_fingerprint" in data and data["tree_fingerprint"]:
        if str(data["tree_fingerprint"]).strip().upper() != expected_tree_fp.upper():
            errors.append("Manifest tree_fingerprint mismatch with packaged file inventory")

    att = data.get("test_run_attestation")
    if not att or not isinstance(att, dict):
        errors.append("Manifest missing valid 'test_run_attestation' dictionary")
    else:
        if att.get("exit_code") != 0:
            errors.append(f"Test-run attestation failed: exit_code != 0 (got {att.get('exit_code')})")
        if att.get("tree_mutated_during_test") is True:
            errors.append("Test-run attestation failed: tree_mutated_during_test is True")
        att_source = str(att.get("source_sha", "")).strip().lower()
        if not att_source or att_source != source_commit.lower() or att_source != tested_commit.lower():
            errors.append("Test-run attestation source_sha mismatch")
        att_tree_fp = str(att.get("tree_fingerprint", "")).strip().upper()
        if att_tree_fp != expected_tree_fp.upper():
            errors.append("Stale test-run attestation: tree_fingerprint mismatch (source modified after test run)")
        if junit_path.exists():
            act_junit_sha = compute_sha256(junit_path)
            if str(att.get("junit_sha256", "")).strip().upper() != act_junit_sha.upper():
                errors.append("Test-run attestation junit_sha256 mismatch (JUnit XML modified or replaced after test run)")
        else:
            errors.append(f"Test-run attestation JUnit XML file not found: {junit_path}")

        if log_path.exists():
            act_log_sha = compute_sha256(log_path)
            if str(att.get("log_sha256", "")).strip().upper() != act_log_sha.upper():
                errors.append("Test-run attestation log_sha256 mismatch (raw log modified or replaced after test run)")
        else:
            errors.append(f"Test-run attestation raw log file not found: {log_path}")

        att_run_id = str(att.get("run_id", "")).strip()
        manifest_run_id = str(data.get("run_id", "")).strip()
        if not att_run_id:
            errors.append("Test-run attestation run_id is missing or empty")
        elif manifest_run_id and att_run_id != manifest_run_id:
            errors.append(f"run_id mismatch between attestation ('{att_run_id}') and manifest ('{manifest_run_id}')")
        if log_text is not None and att_run_id:
            if att_run_id.lower() not in log_text.lower():
                errors.append(f"Test-run attestation run_id '{att_run_id}' not found in raw execution log")

        for req_f in ("pytest_command", "started_at", "completed_at", "environment"):
            if not att.get(req_f):
                errors.append(f"Test-run attestation missing required field: '{req_f}'")

    # 8. Verification Report Consistency & Provenance Checks
    l4_validated = False
    target_reports: list[tuple[str, Path]] = []
    if report_path:
        if isinstance(report_path, (list, tuple)):
            for rp in report_path:
                target_reports.append((str(rp), resolve_candidate_path(manifest_dir, rp)))
        else:
            target_reports.append((str(report_path), resolve_candidate_path(manifest_dir, report_path)))
    elif "report_path" in data and data["report_path"]:
        target_reports.append((str(data["report_path"]), resolve_candidate_path(manifest_dir, data["report_path"])))

    if check_default_reports:
        for def_rep in ("docs/RELEASE_VERIFICATION_REPORT.md", "docs/RELEASE_GO_NO_GO.md", "docs/ANTI_3_0_FINAL_ACCEPTANCE.md"):
            cand = resolve_candidate_path(manifest_dir, def_rep)
            if cand.exists() and not any(r[1].resolve() == cand.resolve() for r in target_reports):
                target_reports.append((def_rep, cand))

    actual_passed = (
        (total_xml_tests - total_xml_failures - total_xml_errors - total_xml_skipped)
        if xml_parsed_ok
        else (data.get("junit_summary", {}).get("passed", 0) if isinstance(data.get("junit_summary"), dict) else 0)
    )
    if not xml_parsed_ok and isinstance(data.get("junit_summary"), dict):
        total_xml_tests = data["junit_summary"].get("tests", 0)
        total_xml_skipped = data["junit_summary"].get("skipped", 0)

    for rep_display_name, rep_file in target_reports:
        if not rep_file.exists():
            errors.append(f"Verification report file not found: {rep_file}")
            continue

        rep_text = rep_file.read_text(encoding="utf-8", errors="ignore")

        # DEFECT-01: Validate Report Provenance Consistency (Packaged files, JUnit tests/passed, Commit SHA)
        provenance_errs = _validate_report_provenance_consistency(
            rep_text=rep_text,
            report_name=rep_file.name,
            data=data,
            total_xml_tests=total_xml_tests,
            actual_passed=actual_passed,
            actual_skipped=total_xml_skipped,
        )
        errors.extend(provenance_errs)

        # Gate consistency checks
        g5_claimed = _has_manifest_gate_claim(data, ["g5", "l4", "l4_chatgpt_web", "chatgpt_web_l4"]) or _report_claims_g5_l4(rep_text)
        if g5_claimed and not l4_validated:
            _validate_l4_evidence(data, manifest_dir, source_commit, errors)
            l4_validated = True

        g4_claimed = _has_manifest_gate_claim(data, ["g4", "soak", "30_minute_soak", "soak_test"]) or _report_claims_g4_soak(rep_text)
        if g4_claimed:
            soak_ev = data.get("soak_evidence")
            if not soak_ev or not isinstance(soak_ev, dict) or soak_ev.get("duration_seconds", 0) < 1800:
                errors.append("False PASS claim: Soak duration under 1800s (30 minutes) cannot be marked PASS/CLOSED")

        g6_claimed = _has_manifest_gate_claim(data, ["g6", "clean_vm", "clean_windows_vm", "public_packaged_release"]) or _report_claims_g6_clean_vm(rep_text)
        if g6_claimed:
            vm_ev = data.get("g6_clean_vm_evidence")
            if not vm_ev or not isinstance(vm_ev, dict) or vm_ev.get("is_isolated_clean_vm") is not True:
                errors.append(
                    "False PASS claim in report without required layer evidence: G6 or Clean Windows VM or PUBLIC PACKAGED RELEASE claimed without 'g6_clean_vm_evidence' with 'is_isolated_clean_vm'=True"
                )

        g2_claimed = _has_manifest_gate_claim(data, ["g2", "autonomous_ai", "generalized_worker"]) or _report_claims_g2_provider(rep_text)
        if g2_claimed:
            g2_ev = data.get("g2_provider_evidence")
            if not g2_ev or not isinstance(g2_ev, dict) or g2_ev.get("provider_configured") is not True:
                errors.append(
                    "False PASS claim in report without required layer evidence: G2 or Autonomous AI claimed without 'g2_provider_evidence' with 'provider_configured'=True"
                )

    if not target_reports:
        # Check manifest-only claims
        if _has_manifest_gate_claim(data, ["g5", "l4", "l4_chatgpt_web", "chatgpt_web_l4"]) and not l4_validated:
            _validate_l4_evidence(data, manifest_dir, source_commit, errors)
            l4_validated = True
        if _has_manifest_gate_claim(data, ["g4", "soak", "30_minute_soak", "soak_test"]):
            soak_ev = data.get("soak_evidence")
            if not soak_ev or not isinstance(soak_ev, dict) or soak_ev.get("duration_seconds", 0) < 1800:
                errors.append("False PASS claim: Soak duration under 1800s (30 minutes) cannot be marked PASS/CLOSED")
        if _has_manifest_gate_claim(data, ["g6", "clean_vm", "clean_windows_vm", "public_packaged_release"]):
            vm_ev = data.get("g6_clean_vm_evidence")
            if not vm_ev or not isinstance(vm_ev, dict) or vm_ev.get("is_isolated_clean_vm") is not True:
                errors.append(
                    "False PASS claim in report without required layer evidence: G6 or Clean Windows VM or PUBLIC PACKAGED RELEASE claimed without 'g6_clean_vm_evidence' with 'is_isolated_clean_vm'=True"
                )
        if _has_manifest_gate_claim(data, ["g2", "autonomous_ai", "generalized_worker"]):
            g2_ev = data.get("g2_provider_evidence")
            if not g2_ev or not isinstance(g2_ev, dict) or g2_ev.get("provider_configured") is not True:
                errors.append(
                    "False PASS claim in report without required layer evidence: G2 or Autonomous AI claimed without 'g2_provider_evidence' with 'provider_configured'=True"
                )

    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate release manifest and evidence linkage.")
    parser.add_argument(
        "--manifest",
        default=str(PROJECT_ROOT / "dist" / "release-manifest.json"),
        help="Path to release manifest JSON",
    )
    parser.add_argument(
        "--expected-commit",
        default=None,
        help="Expected git commit SHA (default: git rev-parse HEAD)",
    )
    parser.add_argument(
        "--no-check-git",
        action="store_true",
        help="Skip git HEAD and working tree verification",
    )
    parser.add_argument(
        "--report",
        nargs="*",
        default=None,
        help="Path(s) to verification report markdown file(s) to check gate consistency",
    )
    parser.add_argument(
        "--check-default-reports",
        action="store_true",
        help="Automatically check default reports in docs/ (RELEASE_VERIFICATION_REPORT.md, RELEASE_GO_NO_GO.md, ANTI_3_0_FINAL_ACCEPTANCE.md)",
    )
    args = parser.parse_args()

    m_path = Path(args.manifest).resolve()
    print(f"[*] Validating release manifest: {m_path}")
    reports_arg = args.report
    if reports_arg and len(reports_arg) == 1:
        reports_arg = reports_arg[0]

    ok, errors = validate_manifest(
        manifest_path=m_path,
        expected_commit=args.expected_commit,
        check_git=not args.no_check_git,
        report_path=reports_arg,
        check_default_reports=args.check_default_reports,
    )
    if ok:
        print("[+] Manifest validation PASSED: all provenance, hashes, and evidence files verified.")
        return 0
    else:
        print(f"[-] Manifest validation FAILED with {len(errors)} error(s):")
        for err in errors:
            print(f"    - {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
