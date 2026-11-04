# Public GitHub release checklist — mandatory gates

**Public-source prerelease:** eligible only after a clean snapshot, zero-leak Git scan, focused Windows CI PASS and public access verification. **Stable production release:** NO-GO until clean-machine install, full regression and live E2E independently pass.

## 1. Source and history

- Preserve the current private repo as an internal reference and backup.
- Never change visibility of the original private repository while its historic Git objects retain tunnel configs, release ZIPs or other infrastructure identifiers.
- Build a new repository from a single reviewed source snapshot with no original .git directory or history. Avoid accidental fetch/push of any old refs, tags or backups.
- Include only vetted source, scripts, tests, requirements, CI, MIT LICENSE, README, SECURITY, CONTRIBUTING and generic example configs.
- Exclude actual local configs, .env, token/key stores, OAuth DB, audit logs, Windows user paths, tunnels, release zips and private operational reports.

## 2. Security review

- Secret-scan **all source and the entire public Git history**, including binary archives and Git LFS.
- Manually review every hit involving tunnel identifiers, client IDs, host paths, authorization or private endpoint identifiers.
- Confirm no active credential ever entered the snapshot; rotate any credential that was exposed in historical material before publication.
- Verify non-owner denial, owner scope/revocation, path escapes, secrets masking, emergency stop and backup semantics.

## 3. Release and reproducibility

- Verify package includes requirements.txt, requirements-dev.txt, LICENSE, README, SECURITY, installer scripts, portable example configs and tests.
- Build on a clean Windows runner and perform fresh-machine install, upgrade, uninstall and rollback.
- Run regression, static lint and secret-scanning CI; do not count skipped headless GUI/cloud tests as passing live E2E.
- Publish accurate release notes, semantic version tag, checksums and binaries as GitHub Release assets instead of Git-tracked zips.

## 4. GitHub publication

Local GitHub CLI currently requires interactive authorization. After audit PASS only, the owner can run:

    gh auth login --hostname github.com --web
    gh auth status

Create or select a **new empty** GitHub repository for the scrubbed source snapshot. Push only the new single-commit public branch, verify GitHub Actions, license, README and security policy render correctly, then publish an RC3 prerelease with SHA-256 sums. Set branch protection, secret scanning and private vulnerability reporting; verify public anonymous clone and install instructions.

**Never** push the original 42-commit private history or change private repo visibility until a documented independent security review approves that specific alternative.

## 5. Final decision

For **public-source prerelease**, verify an independently created clean Git history, no live secrets, GitHub Actions security/Windows baseline PASS, owner authorization, and anonymous public access; label the release experimental. For **production stable GO**, additionally require a clean Windows installation, complete isolated regression, non-owner denial, live connector/GUI E2E, rollback and independent review. Missing production evidence remains **PRODUCTION NO-GO**, not a forced PASS.
