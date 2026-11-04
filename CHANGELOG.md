# Changelog

## Unreleased — WinOwner MCP branding

- Renamed the public repository to `phuonghuster7/winowner-mcp` and adopted **WinOwner MCP** as the public product name.
- Added English and Vietnamese README files, accurate compatibility/permission descriptions and architecture overview.
- Updated publication URLs and future source-package naming while retaining existing runtime entry points for backward compatibility.
- The existing v1.0.0-rc3 tag and release assets remain unchanged; PR #9 handles the separate P0 bootstrap/security work.

## v1.0.0-rc3 — public-source candidate (2026-11-04)

- OAuth-based verified owner authorization, durable delegation and rolling capability grants.
- Owner coding and filesystem operations, including opt-in OWNER_GLOBAL_FILESYSTEM with audit and SHA-256 verification.
- Local gateway, Windows desktop tooling, watchdog and authenticated cloud adapter.
- Separate private production configuration from portable example configurations.
- **Status:** public-source prerelease; not certified production-ready.
