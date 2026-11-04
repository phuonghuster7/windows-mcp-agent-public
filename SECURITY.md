# Security policy

## Supported status

The active source candidate is **v1.0.0-rc3**. This release candidate is not a public security certification; no promise is made to maintain older internal versions.

## Private vulnerability disclosure

Do not disclose attack details, credentials or identifiable logs in public GitHub issues. Prefer the repository's **Security → Report a vulnerability** private reporting channel if enabled; otherwise establish a private channel with the repository maintainer through GitHub before sending details.

## Critical boundaries

- Bind MCP/backend/console ports to **127.0.0.1** and expose them only through explicitly configured authenticated channels.
- Verify OAuth owner identity and operation-level scopes; a client name alone is not authorization.
- Default to read_only and use bounded capability grants, durable revocation and least privilege.
- **OWNER_GLOBAL_FILESYSTEM** is highly privileged, opt-in, owner-only, logged and revocable; it does not grant administrator rights or bypass NTFS/UAC.
- Keep source-control histories and release artifacts free of credentials, signed grants, machine-local tunnel config, personal paths and runtime state.
- Treat tool execution and third-party code as workstation code execution, not isolated execution.
- Use the existing emergency stop, immutable backups when appropriate, and durable audit records.

## Incident response

Disconnect cloud tunnel access, activate the local emergency stop, revoke affected OAuth grants, rotate any leaked credentials, inspect audit logs privately and restore a known-good configuration.

## Publication risk

Historical private Git commits once included host-specific tunnel config and binaries. Publishing the old private history without a complete scrub is unsafe even if the HEAD zip scanner passes. A new single-commit clean public snapshot is preferable to publishing any original history.