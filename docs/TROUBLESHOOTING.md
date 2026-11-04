# Troubleshooting

## Check the basics

```powershell
python --version
Test-NetConnection 127.0.0.1 -Port 8768
python .\runtime\watchdog.py --status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-WindowsMcpStack.ps1
```

The port check measures **local listening only**. A working ChatGPT connector also requires a healthy authenticated tunnel, correct owner identity, valid OAuth token and a compatible MCP endpoint.

## Connection issues

- **429 on SSE probe:** Check the local tunnel-client, restart backoff and any request quota; retry with normal operational procedures, not with unsafe anonymous fallback.
- **Tunnel unseen:** Verify the exact running tunnel-client profile, watchdog task and OS network connectivity.
- **Owner false / unauthorized:** Inspect registered client identity, OAuth scope, delegation and expiry. Do not copy another user's tokens.
- **Outside workspace rejected:** Review the workspace policy. Global owner filesystem is optional and must not be granted to non-owners.

## File, test and CI issues

- **SHA-256 mismatch:** Reread the file and recompute its hash; do not force-overwrite concurrent changes.
- **GitHub Actions fails:** Read the job logs, reproduce on a clean Windows checkout and fix the root cause. Headless runners cannot stand in for a physical desktop or a live cloud connector.
- **Installer fails:** Run the installer with `-DryRun` and check available ports, Python dependencies and local permissions; do not terminate other services blindly.
- **Emergency stop active:** Diagnose why it was set and review the audit before manually clearing it.

## Safe recovery

Use the local emergency stop if unauthorized actions are suspected, disconnect the tunnel, revoke affected grants and rotate keys before restoring from a verified backup. Do not post raw diagnostic logs or OAuth information on public issues.
