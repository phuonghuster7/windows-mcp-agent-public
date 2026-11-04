# Windows MCP Agent — Release Candidate

Windows-local Model Context Protocol (MCP) tooling for an authorized ChatGPT client: file operations, coding, Git inspection, desktop interaction, autonomous tasks, OAuth owner authorization and audit.

**Status:** v1.0.0-rc3 source candidate (2026-11-04). Experimental, security-sensitive software; not independently certified for public deployment.

**Language:** English / Tiếng Việt. Recommended: Windows 10/11 (x64), Python 3.12+, Git and PowerShell 5.1+.

## Components

| Local endpoint | Purpose |
| --- | --- |
| 127.0.0.1:3080 | Core backend |
| 127.0.0.1:8765 | Read-only MCP bridge |
| 127.0.0.1:8766 | Policy-gated staging gateway |
| 127.0.0.1:8767 | Local owner console |
| 127.0.0.1:8768 | Authenticated cloud/owner adapter |

All services should remain bound to localhost. Cloud access requires your own authorized tunnel and OAuth configuration; this repository never ships usable tunnel credentials. Available tools vary by connector configuration.

## One-line Windows bootstrap (local MCP only)

**Paste one PowerShell line** (Git must be installed; missing Python 3.12 is installed via winget where available):

```powershell
git clone https://github.com/phuonghuster7/windows-mcp-agent-public.git winowner-mcp; if ($LASTEXITCODE -eq 0) { powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\winowner-mcp\scripts\Bootstrap-WindowsMcp.ps1" }
```

Bootstrapping creates an isolated Python environment, installs dependencies, configures loopback-only read-only operation and a protected local token, starts the standalone adapter, and checks `/health` plus anonymous MCP denial. Port 8768 must be free; existing services are never terminated.

**LOCAL_INSTALL_PASS is not remote connector authorization.** ChatGPT, Claude or another MCP client must still be paired using the owner's OAuth identity and a separate authenticated tunnel. `OWNER_GLOBAL_FILESYSTEM` is not enabled by installation. See [Connect ChatGPT](docs/CONNECT_CHATGPT.md).

## Getting started / Manual installation

Use a clean disposable Windows checkout rather than a live production directory.

    git clone https://github.com/phuonghuster7/windows-mcp-agent-public windows-mcp-agent
    cd windows-mcp-agent
    py -3.12 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsMcpAgent.ps1 -DryRun

Read [Installation](docs/INSTALLATION.md) before enabling any network connection. The installer dry-run verifies prerequisites; it does not establish ChatGPT connectivity.

## Authorization

- Install with least-privileged/read_only profile by default.
- Write, execution and desktop actions require a trusted session and authorization.
- OWNER_GLOBAL_FILESYSTEM is an explicit opt-in available only to an authenticated owner; it obeys Windows account permissions and is not a bypass of NTFS or UAC.
- Do not enable owner-global access on shared/untrusted clients, publish local service endpoints or disable authorization, audit, backup and emergency stop.
- Arbitrary execution has the full rights of the running Windows account; this is **not a sandbox**.

## Tests

Run tests in an isolated disposable checkout, not on a live installed agent:

    .\.venv\Scripts\python.exe -m pytest --collect-only -q
    .\.venv\Scripts\python.exe -m pytest -q tests/test_red_team_security.py tests/test_mcp_gateway.py

## Documents

- [Installation and owner setup](docs/INSTALLATION.md)
- [Connect ChatGPT (authorized owner setup)](docs/CONNECT_CHATGPT.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Public publication checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Security](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) — MIT

**Tiếng Việt:** Đây là agent cục bộ để ChatGPT thao tác Windows khi được chủ máy xác thực. Không mở quyền toàn ổ đĩa mặc định, không đưa khóa/tunnel của máy thật vào GitHub và không chạy public endpoint thiếu OAuth.