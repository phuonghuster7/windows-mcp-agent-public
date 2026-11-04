# Contributing

Contributions are welcome after public release approval.

1. Keep pull requests narrow; describe expected behavior and threat-model effects.
2. Use a disposable Windows checkout and Python 3.12+ for tests.
3. Do not commit credentials, OAuth grants, private tunnel configuration, runtime databases/logs, machine-specific paths or release archives.
4. Preserve the read-only default, verified owner access checks, path guards, emergency stop, audit and rollback.
5. Add regression tests and run relevant pytest/ruff on an isolated runner; never run state-mutating tests on the active agent installation.
6. Document deployment and rollback implications.

For vulnerabilities, follow SECURITY.md rather than opening a public issue. Licensing: MIT, see LICENSE.
