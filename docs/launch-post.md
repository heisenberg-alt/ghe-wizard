# Launch: ghe-wizard — a best-practices wizard for GitHub Enterprise Cloud

*Reading time: ~3 minutes*

## The problem

Buying GitHub Enterprise Cloud is the easy part. Setting it up **well** — the way
GitHub actually recommends in its onboarding docs — is where teams stall. The
guidance is spread across dozens of documentation pages: how many enterprise
owners you should have, when to create a new organization, which policies and
rulesets to enforce, how to wire up SSO/SCIM/2FA, when to prefer GitHub Apps over
PATs, how to allocate spend with cost centers, and much more.

Most enterprises discover the gaps months later — during an audit, an incident,
or a painful migration.

## The idea

**ghe-wizard** turns GitHub's official best-practice guidance into an automated
**assess → modify → implement** tool. Point it at your enterprise and it:

1. **Assesses** your current configuration against 28 checks across 9 domains and
   produces a 0–100 scorecard (read-only).
2. **Recommends** concrete fixes, each linked to the exact GitHub Docs page.
3. **Implements** the automatable ones — idempotently, with a dry-run preview and
   explicit confirmation.

It ships as a single Go binary that is both an **interactive CLI** and a
**web dashboard**.

## What it checks

- **Enterprise foundations** — limit enterprise owners, least-privilege custom roles
- **Organizations** — intentional creation, stale-org cleanup, least-privilege base permission
- **Teams** — manage access at scale, IdP sync, restrict membership control
- **Repositories** — org-owned collaboration, custom properties, creation controls
- **Policies** — branch rulesets, IP allow list, Copilot policy, read-only workflow token
- **Security** — enterprise SSO, SCIM, 2FA, audit-log streaming, secret scanning + push protection
- **Innersource, Automation, Billing** — internal repos, GitHub Apps over PATs, cost centers

## Design principles

- **Read-only by default.** Assessment never changes anything. Only remediation
  writes, and only after confirmation.
- **Idempotent, dry-runnable remediation.** Preview the exact changes first.
- **Honest results.** If the API can't determine something, it's flagged for
  manual review — never guessed.
- **Every finding cites the source.** Each rule links to the official docs.

## Try it in 10 seconds

No token, no setup:

```bash
go run github.com/ghe-wizard/ghe-wizard/cmd/ghe-wizard serve --demo
# open http://localhost:8080
```

Demo mode runs the *real* engine against a realistic synthetic enterprise, so you
can explore the scorecard and the one-click remediation flow immediately.

Against your real enterprise:

```bash
export GHE_TOKEN=ghp_xxx
export GHE_ENTERPRISE=your-slug
ghe-wizard assess            # scorecard
ghe-wizard serve             # dashboard
ghe-wizard apply --dry-run   # preview fixes
```

## Built for teams

- Single static binary; multi-arch container image on GHCR
- `--fail-on` to gate CI pipelines; JSON/Markdown/HTML reports
- Concurrent scanning with caching for large enterprises
- Security headers, optional basic auth, graceful shutdown
- MIT licensed and easy to extend — add a rule in one `init()` block

## Links

- Repo: https://github.com/heisenberg-alt/ghe-wizard
- Releases: https://github.com/heisenberg-alt/ghe-wizard/releases
- How to contribute a rule: [CONTRIBUTING.md](../CONTRIBUTING.md)

If this is useful, a ⭐ helps others find it.
