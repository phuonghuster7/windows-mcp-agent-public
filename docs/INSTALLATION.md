# Installation — Windows MCP Agent (v1.0.0-rc3 candidate)

## Prerequisites

Use Windows 10/11 x64, PowerShell 5.1+ (or PowerShell 7), Python 3.12+, Git, and a dedicated user session. Review the security policy first. Do not expose the local MCP/console endpoints publicly.

## Clean checkout

Run in a fresh directory or disposable VM:

    git clone https://github.com/phuonghuster7/windows-mcp-agent-public windows-mcp-agent
    cd windows-mcp-agent
    py -3.12 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

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
    .\.venv\Scripts\python.exe -m pytest -q tests/test_red_team_security.py tests/test_mcp_gateway.py

No shared OAuth secret or owner delegation is supplied in this repository. For a failed connector, check owner OAuth, tunnel runtime, port binding and logs locally; redact credentials before sharing any diagnostic output.
