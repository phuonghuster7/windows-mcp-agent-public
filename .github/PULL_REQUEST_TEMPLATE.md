## Summary

Describe the purpose of this change and its scope.

## Security considerations

- [ ] No API keys, OAuth tokens, private tunnel IDs, local runtime data, host-specific paths, or unredacted logs
- [ ] Default read-only behavior and owner/non-owner authorization boundaries remain intact
- [ ] Workspace isolation, durable revocation, audit, backup and emergency stop remain enforced
- [ ] Security-sensitive changes include negative/adversarial tests

## Validation

- [ ] Compile, Ruff and relevant pytest checks
- [ ] Public-source guard and Gitleaks scan
- [ ] Clean Windows setup implications considered
- [ ] Any required live E2E tests identified honestly (never forced PASS)

## Rollback

State how this can be reverted safely and whether user configs or on-disk state change.
