# Installation — WinOwner MCP (v1.0.0-rc3 candidate)

## Prerequisites

Use Windows 10/11 x64, PowerShell 5.1+ (or PowerShell 7), Python 3.12+, Git, and a dedicated user session. Review the security policy first. Do not expose the local MCP/console endpoints publicly.

## Clean checkout

Run in a fresh directory or disposable VM:

    git clone https://github.com/phuonghuster7/winowner-mcp.git winowner-mcp
    cd winowner-mcp
    py -3.12 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

## One-line local setup

Prerequisite: Git on Windows. Paste into PowerShell:

```powershell
git clone https://github.com/phuonghuster7/winowner-mcp.git winowner-mcp; if ($LASTEXITCODE -eq 0) { powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\winowner-mcp\scripts\Bootstrap-WindowsMcp.ps1" }
```

The bootstrap automatically creates the Python 3.12 virtual environment, installs dependencies, configures local read-only operation, creates a user-restricted local bearer [REDACTED], registers a least-privilege Task Scheduler job that runs the standalone adapter at owner logon, then tests /health and HTTP 401 without authentication. It fails closed when an unknown process uses the port or the task name is occupied; no firewall is opened. It can install Python 3.12 with winget where supported. Git itself cannot install or OAuth-pair an agent.

Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Bootstrap-WindowsMcp.ps1 -DryRun` for a non-mutating check. Run with `-Remove` to stop the verified local adapter and unregister the auto-start task. Existing secrets and policies remain on disk for owner-controlled cleanup. Auto-start has been verified across separate command sessions, but a full Windows reboot remains a separate acceptance check.

**LOCAL_INSTALL_PASS does NOT mean the ChatGPT connector is connected.** The operator must complete owner OAuth and private tunnel pairing using docs/CONNECT_CHATGPT.md. Owner full filesystem privileges are never provisioned automatically.

## Verify installer before modifying your workstation

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsMcpAgent.ps1 -DryRun

Review the output and explicitly decide which local services, scheduled tasks and ports should be installed before running the non-dry-run script. Test installation in a clean VM first; this candidate has not yet passed a fresh-machine public install gate.

## Configure your own identity and scope

Start with example files under config/. Never copy the developer's actual policy.json, trusted_workspaces.json or tunnel-autonomous runtime files. Every machine and ChatGPT account needs its own OAuth owner onboarding, locally bound endpoints, tunnel setup and access scope. Keep read_only as the initial profile. Do not enable OWNER_GLOBAL_FILESYSTEM until identity, scope, audit, grants and revocation have been tested.

## Verify runtime

Check local service health, OAuth state and the watchdog without exposing secrets. For example, a configured adapter may listen on 127.0.0.1:8768; a healthy local port is not evidence that the cloud connector is authenticated. Validate the native agent_system_status and a harmless read-only file operation from the intended ChatGPT client.

## Tests and troubleshooting

Run collection and a focused non-mutating subset on a **disposable** checkout:

    .\.venv\Scripts\python.exe -m pytest --collect-only -q
    .\.venv\Scripts\python.exe -m pytest -q tests/test_mcp_gateway.py tests/test_owner_full_control.py tests/test_oauth_dynamic_owner.py tests/test_direct_coding_security.py

No shared OAuth secret or owner delegation is supplied in this repository. For a failed connector, check owner OAuth, tunnel runtime, port binding and logs locally; redact credentials before sharing any diagnostic output.
