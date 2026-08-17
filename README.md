# ghe-wizard — GitHub Enterprise Best-Practices Wizard

[![CI](https://github.com/heisenberg-alt/ghe-wizard/actions/workflows/ci.yml/badge.svg)](https://github.com/heisenberg-alt/ghe-wizard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/heisenberg-alt/ghe-wizard?sort=semver)](https://github.com/heisenberg-alt/ghe-wizard/releases)

An automated **assess → modify → implement** tool for customers adopting **GitHub
Enterprise Cloud**. It scans an enterprise account against GitHub's recommended
best practices, produces a scorecard, and can remediate the fixable findings —
available as both an **interactive CLI wizard** and a **web dashboard**.

The rule catalog is distilled from GitHub's official
[Enterprise onboarding](https://docs.github.com/en/enterprise-cloud@latest/enterprise-onboarding)
and [Best practices for enterprises](https://docs.github.com/en/enterprise-cloud@latest/admin/concepts/enterprise-best-practices)
documentation.

<p align="center">
  <img src="docs/media/demo.gif" alt="ghe-wizard dashboard demo: assess, review findings, and preview one-click remediations" width="720">
</p>

> **Try it in 10 seconds — no GitHub token required:**
> ```bash
> go run ./cmd/ghe-wizard serve --demo   # then open http://localhost:8080
> ```
> Demo mode runs the real assessment engine against a realistic synthetic
> enterprise so you can explore the scorecard and remediation flow instantly.


## What it checks (45 rules, 10 domains)

| Domain | Examples |
|---|---|
| Enterprise foundations | limit enterprise owners, least-privilege custom roles |
| Organizations | intentional org creation, stale-org cleanup, least-privilege base permission, web commit sign-off, private-fork policy |
| Teams | team-based access (direct-collaborator detection), IdP group sync, empty/maintainer-less team hygiene |
| Repositories | org-owned collaboration, custom properties, repo-creation controls |
| Policies | branch rulesets, IP allow list, Copilot policies, hardened workflow token, allowed-actions policy |
| Security | enterprise SSO, SCIM, 2FA, audit-log streaming, secret scanning, Dependabot alerts, code security configurations |
| Identity | verified/approved domains, corporate email on personal accounts, outside collaborators, SSO linkage, offboarding & signup-trace cross-checks |
| Innersource | internal-visibility repos for discovery & reuse |
| Automation | GitHub Apps over PATs, automated provisioning |
| Billing | cost centers, spending limits |

Run `ghe-wizard list` for the full catalog. Rules marked `[remediable]` can be
applied automatically.

## Install / build

Download a prebuilt binary from the [Releases](https://github.com/heisenberg-alt/ghe-wizard/releases)
page (Linux/macOS/Windows, amd64/arm64), or build from source:

```bash
go build -o ghe-wizard ./cmd/ghe-wizard
```

### Docker

A container image is published to GitHub Container Registry:

```bash
docker run --rm -p 8080:8080 \
  -e GHE_ENTERPRISE=octo-enterprise \
  -e GHE_TOKEN=ghp_xxx \
  ghcr.io/heisenberg-alt/ghe-wizard:latest
# then open http://localhost:8080

# or run the CLI
docker run --rm -e GHE_ENTERPRISE=octo-enterprise -e GHE_TOKEN=ghp_xxx \
  ghcr.io/heisenberg-alt/ghe-wizard:latest assess
```

## Authentication

**Personal Access Token** — set a PAT with enterprise admin scopes and your
enterprise slug:

```bash
export GHE_TOKEN=ghp_xxx          # or GITHUB_TOKEN
export GHE_ENTERPRISE=octo-enterprise
```

**GitHub App (installation tokens)** — instead of a long-lived PAT, register a
GitHub App, install it for your enterprise's organizations, and point
ghe-wizard at the app credentials. Tokens are minted on demand (RS256 app JWT →
installation token) and refreshed automatically before expiry:

```bash
export GHE_APP_ID=123456
export GHE_APP_INSTALLATION_ID=7890123
export GHE_APP_PRIVATE_KEY_PATH=/path/to/app.private-key.pem
# or inline: export GHE_APP_PRIVATE_KEY="$(cat app.private-key.pem)"
export GHE_ENTERPRISE=octo-enterprise
```

Grant the app the permissions matching the checks you run (organization
administration/members read for org rules; write variants for remediation).
An explicit `GHE_TOKEN` always wins over app auth when both are set.

> Caveat: several enterprise-level endpoints (enterprise GraphQL owner data,
> some `/enterprises/*` REST APIs) do not accept installation tokens; affected
> rules degrade to error/manual. App auth is strongest for the organization
> domain rules today — a PAT remains the full-coverage path.

## GitHub Enterprise Server & data residency

Point ghe-wizard at a GHES installation or a data-residency enterprise
(`*.ghe.com`) with `--server` (or `GHE_SERVER`) — API endpoints are derived
automatically, and explicit `GHE_BASE_URL`/`GHE_GRAPHQL_URL` still win:

```bash
ghe-wizard assess --server github.example.internal   # GHES
ghe-wizard assess --server acme.ghe.com              # data residency
```

GHES installations are detected via `/meta`; rules that depend on cloud-only
features (EMU detection, the audit-log streaming API, Copilot policies, cost
centers) report **skipped** there and are excluded from the score.

## Usage

```bash
# Read-only assessment (Markdown scorecard)
ghe-wizard assess

# JSON or self-contained HTML report to a file
ghe-wizard assess --format json --out scorecard.json
ghe-wizard assess --format html --out scorecard.html

# Interactive wizard: walk failing rules and remediate with confirmation
ghe-wizard wizard

# Preview all remediations without changing anything
ghe-wizard apply --dry-run

# Apply specific fixes
ghe-wizard apply --rules ORG-04,SEC-03

# Remediate under governance: honor policy waivers/disabled rules and record
# the remediation log to history
ghe-wizard apply --policy policy.example.yaml --db ghe-wizard.db

# Web dashboard
ghe-wizard serve --addr :8080

# Try everything with no token (synthetic data)
ghe-wizard assess --demo
ghe-wizard serve --demo

# Print version / list the catalog
ghe-wizard version
ghe-wizard list
```

### Use in CI

`--fail-on` makes the assessment gate a pipeline. Combine with `--no-preflight`
when using a fine-grained token.

```bash
ghe-wizard assess --format json --out scorecard.json --fail-on fail
# exit code is non-zero if any check is failing
```

There is also an **official GitHub Action** that runs the assessment, gates PRs,
and posts a sticky scorecard comment — see [action/](action/).

### History & trends

Record every run to an embedded SQLite database to unlock score trends and drift
detection (newly failing / newly fixed rules). The dashboard shows a score-trend
sparkline, and a dynamic **score badge** is served at `/badge.svg`.

```bash
ghe-wizard assess --demo --db ghe-wizard.db     # record a run
ghe-wizard history --enterprise acme-corp --db ghe-wizard.db
ghe-wizard history --enterprise acme-corp --db ghe-wizard.db --remediations
ghe-wizard serve --db ghe-wizard.db             # dashboard trends + /badge.svg
```

### Identity governance: corporate email on personal accounts

Employees registering **personal** GitHub accounts with corporate email
(`@acme.com`) create recovery and shadow-IT risk. The identity rules
implement a detect → warn → prevent pipeline:

```yaml
# policy.yaml
identity:
  approved_domains: [acme.com]           # extends GitHub-verified domains
  forbid_corporate_email_on_members: true
  max_outside_collaborators: 0
  # roster_csv: hr-roster.csv            # offboarding cross-check (IDENT-09)
  # mail_trace_csv: github-signup-trace.csv   # complete rogue detection (IDENT-10)
```

```bash
# Detect: members with corporate email, rogue accounts (public signals +
# mail-gateway trace), departed employees still linked
ghe-wizard assess --policy policy.yaml

# Warn: generate the per-user notification campaign (CSV or Markdown)
ghe-wizard identity warn --policy policy.yaml --grace-days 14 --out campaign.csv

# Prevent: generate the Exchange Online transport rule that blocks completing
# GitHub signup with corporate email (plus the message-trace export query)
ghe-wizard identity transport-rule --domain acme.com \
  --allowlist oss-liaison@acme.com --out prevent-github-signup.ps1
```

Honest limits, stated in the output: the enterprise cannot delete an
employee's personal account (only the owner can); GitHub has no API to find
accounts by private registration email, so public-signal sweeps are partial
by design — the mail-gateway trace is the complete detector. Only EMU
eliminates personal accounts entirely (IDENT-06). Track campaign compliance
by re-running `assess --db`: drift shows warned findings turning fixed.

Removing outside collaborators (IDENT-04) is **destructive** and never runs
in bulk or from the dashboard:

```bash
ghe-wizard apply --rules IDENT-04 --allow-destructive --dry-run   # review first
```

### Config-as-code & waivers

Govern the assessment declaratively with a YAML policy — disable rules, override
severities, tune thresholds, and record compliance **waivers** (accepted risks
with an owner, reason and expiry). Waived findings are excluded from the score
and from `--fail-on` gating until they expire, and `apply`/`wizard`/the
dashboard skip them during remediation. See [policy.example.yaml](policy.example.yaml).

```bash
ghe-wizard assess --policy policy.example.yaml
ghe-wizard apply  --policy policy.example.yaml   # waived findings are not remediated
ghe-wizard serve  --policy policy.example.yaml --profile high-security
```

### Rule profiles & evidence export

Run a curated subset of checks with a **profile**, or export auditor-friendly
**evidence**:

```bash
ghe-wizard assess --profile high-security      # only critical/high rules
ghe-wizard assess --profile onboarding         # day-one onboarding checks
ghe-wizard assess --profile compliance         # security + policies domains
ghe-wizard assess --format csv --out evidence.csv
```

### ChatOps notifications (Slack / Teams / Discord / JSON)

Post the scorecard (and drift) to a Slack, Microsoft Teams or Discord incoming
webhook — auto-detected from the URL, or forced with `--notify-format`. The
`json` format posts a stable versioned document (`ghe-wizard/v1`) for custom
receivers. `--notify-only-alert` sends only on a score drop or a newly failing
check:

```bash
ghe-wizard assess --db ghe-wizard.db \
  --notify-webhook "$SLACK_WEBHOOK" --notify-only-alert

ghe-wizard assess --notify-webhook "$AUTOMATION_URL" --notify-format json
```

### AI assistance (optional, pluggable)

Point ghe-wizard at any OpenAI-compatible endpoint (OpenAI, Azure OpenAI, GitHub
Models, or a local server) for plain-English explanations, a prioritized
remediation plan, and natural-language questions. It is **off by default**, never
sends tokens/secrets, and no-ops when unconfigured.

```bash
export GHE_AI_ENDPOINT=https://api.openai.com/v1/chat/completions
export GHE_AI_MODEL=gpt-4o-mini
export GHE_AI_KEY=sk-...

ghe-wizard explain SEC-03            # explain a finding + blast radius
ghe-wizard ai-plan                   # staged remediation plan
ghe-wizard ask "which orgs lack 2FA and why does it matter?"
```

### Automations

Ready-to-copy example workflows live in [action/examples/](action/examples):
weekly **governance issue** upsert, PR **scorecard comment + gating**, and a
human-in-the-loop **remediation-plan PR** (`apply --dry-run`).

### Secure the dashboard

The dashboard streams live progress (SSE) as each check completes, sets strict
security headers, and supports optional HTTP basic auth. Keep it on localhost, or
put it behind a TLS-terminating proxy:

```bash
GHE_BASIC_PASS=s3cret ghe-wizard serve --basic-user admin
```

## Screenshots

| Scorecard | Findings & remediation |
|---|---|
| ![Scorecard](docs/media/frames/f02_scorecard_top.png) | ![Remediation](docs/media/frames/f06_remediation_modal.png) |

## Safety model

- `assess` is strictly read-only.
- `apply` defaults to prompting for confirmation; `--dry-run` describes changes only.
- Remediations are idempotent (they re-check current state before acting).
- Findings that cannot be determined from the API are reported as **manual review**
  rather than guessed.

## Configuration

Optional JSON config (`--config config.json`) tunes thresholds:

```json
{
  "base_url": "https://api.github.com",
  "graphql_url": "https://api.github.com/graphql",
  "max_orgs": 0,
  "thresholds": { "max_enterprise_owners": 5, "stale_org_days": 180 }
}
```

Environment variables (`GHE_ENTERPRISE`, `GHE_TOKEN`/`GITHUB_TOKEN`,
`GHE_BASE_URL`, `GHE_GRAPHQL_URL`) override file values.

## Project layout

```
cmd/ghe-wizard/      CLI entrypoint (assess | wizard | apply | report | serve | list)
internal/ghclient/   GitHub REST+GraphQL client (PAT auth, pagination, rate limits)
internal/rules/      Rule interface, registry, function-backed Base helper
internal/rules/catalog/  Best-practice rules, one file per domain
internal/engine/     Runs rules, aggregates scorecard, runs remediations
internal/report/     JSON / Markdown reporters
internal/web/        HTTP JSON API + embedded dashboard UI
internal/config/     Config + thresholds loading
```

## Extending the catalog

Add a rule by registering a `rules.Base` in an `init()` inside
`internal/rules/catalog/`. Provide `AssessFn` and, when automatable, a
`RemediateFn`. It is picked up automatically by the CLI and web server.

## Contributing

Contributions are welcome. CI (build, `go vet`, and race-enabled tests) runs on
every pull request via [GitHub Actions](.github/workflows/ci.yml). Please keep the
assessment path read-only and ensure remediations remain idempotent and dry-runnable.

## License

Released under the [MIT License](LICENSE).
