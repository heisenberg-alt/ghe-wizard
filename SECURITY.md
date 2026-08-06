# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately via a
[GitHub security advisory](https://github.com/heisenberg-alt/ghe-wizard/security/advisories/new).
We aim to acknowledge reports within 3 business days and to provide a remediation
timeline after triage.

## Scope and handling of secrets

ghe-wizard operates on privileged GitHub Enterprise credentials. Please keep the
following in mind:

- **Tokens are never persisted.** The CLI reads the token from the environment
  (`GHE_TOKEN` / `GITHUB_TOKEN`). The web dashboard accepts a token only in the
  request body and holds it in memory for the duration of a request; it is never
  written to disk or logs.
- **Assessment is read-only.** Only the `apply`/remediation paths perform writes,
  and only after explicit confirmation (or `--yes`).
- **Run the dashboard locally.** By default it binds to all interfaces on the
  chosen port; when exposing it beyond localhost, enable HTTP basic auth
  (`--basic-user` / `--basic-pass`) and terminate TLS at a reverse proxy.
- **Least privilege.** Use a token with only the scopes you need
  (`admin:enterprise`, `read:org`, `repo`). Prefer short-lived tokens.

## Supported versions

The latest released minor version receives security fixes.
