# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-08-11

Governance depth release: the teams domain becomes scored, code security
configurations arrive as the flagship automated remedy, IDENT-02 gains its
remediation, and the identity warning campaign can deliver via webhook and
SMTP. Catalog: 45 rules across 10 domains.

### Added
- **Teams governance (TEAM domain is now scored, catalog 45 rules):**
  TEAM-01 detects repositories granting access to direct collaborators
  instead of teams (bounded sampling, disclosed in the finding); TEAM-02
  checks IdP external-group availability for team sync; new TEAM-04 (empty
  teams) and TEAM-05 (teams without maintainers).
- **SEC-07 code security configurations (flagship remedy):** fails orgs with
  no default security configuration and can create a "ghe-wizard
  recommended" configuration (secret scanning + push protection, Dependabot
  alerts + security updates, dependency graph, private vulnerability
  reporting) and set it as default for all new repositories — GitHub's
  supported successor to the per-flag org settings.
- **ORG-06:** flags and remediates member forking of private repositories.
- **POL-05 hardened:** now also checks and disables the workflow token's
  ability to approve pull requests (same endpoint, one remediation).
- **POL-06 remediable (explicit-opt-in gated):** restricts allowed actions to
  GitHub-owned + verified creators + enterprise-local, preserving the
  enabled-organizations scope. Build-impacting, so it never runs in bulk —
  `apply --rules POL-06 --allow-destructive` only.
- **IDENT-02 is now scored and remediable:** reads the notification-
  restriction setting per org and can enable it (GraphQL field and mutation
  verified against GitHub's published schema).
- **Warning-campaign delivery:** `identity warn --webhook` posts a summary to
  Slack/Teams/Discord/JSON webhooks; `--email` sends per-user warnings via
  SMTP (`GHE_SMTP_HOST`, `GHE_SMTP_FROM`, optional `GHE_SMTP_USER/PASS`).
- Pre-implementation endpoint verification: all GraphQL fields and REST
  endpoints marked *(verify)* in the roadmap were checked against GitHub's
  published schema and REST docs before implementation.

## [1.3.0] - 2026-08-11

Governance release: a critical remediation fix, GitHub App authentication,
identity governance for corporate email on personal accounts, remediation
coverage expansion, GHES/data-residency support, and full policy parity
across CLI, dashboard and the GitHub Action.

### Fixed
- **Live remediation previously never reached GitHub.** Every remediation
  obtained its write client with a type assertion that always failed behind the
  engine's caching layer, so `apply`, `wizard` and the dashboard's Apply flow
  described changes without performing them (dry-run behavior was correct).
  Remediations now reach the write client through an explicit write-API seam,
  regression tests drive the full engine path, and a read-only client is now an
  explicit error instead of a silent skip. **After upgrading, `apply` makes
  real changes — review with `--dry-run` first.**
- CLI `apply` and `wizard` now actually persist remediation results to the
  history database via the new `--db` flag (previously only the dashboard
  recorded them, despite the 1.2.0 changelog entry).

### Added
- **Identity governance (new domain, 10 rules)** for the corporate-email-on-
  personal-accounts problem: verified/approved domains (IDENT-01), member
  corporate-email inventory with a configurable *forbid* posture (IDENT-07),
  rogue-account public-signal sweep with explicit partial-coverage labeling
  (IDENT-08), HR-roster offboarding cross-check (IDENT-09), mail-gateway
  signup-trace cross-check — the only complete rogue detector (IDENT-10),
  outside-collaborator thresholds with destructive-gated removal (IDENT-04),
  SSO-linkage hygiene (IDENT-05), notification-restriction guidance
  (IDENT-02), member identifiability (IDENT-03) and an EMU advisory
  (IDENT-06). Configured via the policy file's new `identity:` section.
- **`ghe-wizard identity warn`** — generates the per-user warning campaign
  (CSV/Markdown) across all affected populations with deadlines; compliance
  is tracked by re-scan drift. **`ghe-wizard identity transport-rule`** —
  generates the Exchange Online transport rule that prevents completing
  GitHub signup with corporate email, plus the message-trace export query.
- **Destructive-remediation gating:** rules that remove people/access/seats
  are excluded from bulk apply, the wizard and the dashboard; they run only
  with an explicit `--rules` selection plus `--allow-destructive`, and are
  marked `[DESTRUCTIVE]` in the confirmation prompt.
- `compliance` profile now includes the identity domain.
- **GitHub Enterprise Server & data residency:** `--server` (or `GHE_SERVER`)
  targets a GHES hostname or a `*.ghe.com` data-residency enterprise; API
  endpoints are derived automatically and explicit `GHE_BASE_URL`/
  `GHE_GRAPHQL_URL` still win. GHES installations are detected via `/meta`,
  and cloud-only rules (ENT-01 EMU, SEC-04 streaming API, POL-04 Copilot,
  BILL-01 cost centers) report **skipped** there, excluded from the score.
- **Notification backends:** Discord webhooks (auto-detected, 2000-char safe
  truncation) and a stable versioned JSON document (`ghe-wizard/v1`) for
  arbitrary receivers. `assess --notify-format auto|slack|teams|discord|json`;
  matching `notify-format` input on the GitHub Action.
- **New rule profiles:** `onboarding` (curated day-one checks from the
  enterprise onboarding guide) and `compliance` (security + policies domains).
  Profiles now support curated rule-ID sets in addition to domain/severity
  filters.
- **GitHub App authentication:** authenticate with a GitHub App installation
  instead of a PAT (`GHE_APP_ID`, `GHE_APP_INSTALLATION_ID`,
  `GHE_APP_PRIVATE_KEY[_PATH]`). The RS256 app JWT is hand-rolled with the
  standard library (still zero dependencies), installation tokens are cached
  and refreshed before expiry, and an explicit `GHE_TOKEN` always wins. Some
  enterprise-level endpoints reject installation tokens; affected rules
  degrade to error/manual (see README).
- **Auto-remediation expanded from 5 to 9 of 31 rules.** Newly remediable:
  POL-05 (enterprise default `GITHUB_TOKEN` permissions → read-only), REPO-03
  (disable member creation of *public* repositories — general repo creation is
  deliberately left untouched), and the new SEC-06 and ORG-05. SEC-05 now
  checks and enables secret scanning *and* push protection for new repos.
- **New rules:** SEC-06 (dependency graph + Dependabot alerts for new repos,
  remediable), POL-06 (warn when any public action is allowed enterprise-wide),
  ORG-05 (require web commit sign-off, remediable).
- **SEC-04 audit-log streaming and POL-05 workflow permissions are now read
  from the API** (`/enterprises/{e}/audit-log/streams`,
  `/enterprises/{e}/actions/permissions/workflow`) instead of always reporting
  manual — these can lower existing scores where misconfigured.
- **Policy & profile parity for remediation:** `apply` and `wizard` accept
  `--policy`, `--profile`, `--db` and `--demo`. Disabled rules never run,
  waived findings are skipped (explicitly requested waived rules are skipped
  with a warning), and thresholds apply consistently.
- **Dashboard parity:** `serve --policy` / `serve --profile`; waived findings
  get a status chip, stat tile and filter; `POST /api/export/csv` + a CSV
  evidence button next to the JSON export; `/api/health` reports the active
  policy and profile; the apply API skips waived/disabled rules and says so.
- **Stateful demo:** demo-mode remediations now visibly improve subsequent
  assessments within the same process, so the dashboard demo's apply →
  re-assess loop shows a real score change.
- **GitHub Action passthrough:** new optional inputs `policy`, `profile`,
  `notify-webhook` (passed via environment, never argv) and
  `notify-only-alert`.
- `history --remediations` lists recorded remediation logs; `assess
  --notify-webhook` falls back to the `GHE_NOTIFY_WEBHOOK` environment
  variable.

### Changed
- `apply` and `wizard` respect policy waivers and disabled rules — previously
  they would remediate findings your policy had accepted.

### Removed
- Staff-review dead-code sweep: `Engine.FailingRules` (superseded by
  `RemediableFailures`), the unused `notify.Notifier` type,
  `report.EvidenceJSON` (the CLI exports scorecard JSON and evidence CSV),
  `catalog.Load()`, the unused `web.Serve` wrapper, `rules.ByDomain`, and
  never-read struct fields (`Config.DryRun`, `Enterprise.TwoFactorReq`,
  `Organization.UpdatedAt`/`ReposURL`, `OrgSettings.AdvancedSecurityEnabled`,
  `Repository.Private`). Deduplicated the Slack/Discord text rendering and
  the GHES-detection logic.

## [1.2.0] - 2026-08-06

Continuous-governance release: living history, real-time UX, closed-loop
automation, and an optional AI layer — plus a staff-level code-quality and
performance pass.

### Added
- **Live assessment (SSE):** `/api/assess/stream` streams each rule result as it
  completes; the dashboard gauge and counters tick in real time (graceful
  fallback when streaming is unavailable).
- **History, trends & drift:** embedded pure-Go SQLite store records every run;
  dashboard score-trend sparkline; drift detection (newly failing / fixed /
  regressed); `assess --db`, `history` command, and a dynamic `/badge.svg`.
- **Config-as-code & waivers:** YAML policy to disable rules, override
  severities, tune thresholds, and record compliance waivers (owner/reason/
  expiry). Waived findings are excluded from the score and `--fail-on`.
  `assess --policy`, `policy.example.yaml`.
- **Rule profiles:** `assess --profile baseline|high-security|security-only`.
- **Compliance evidence export:** `assess --format csv`.
- **ChatOps notifications:** Slack & Microsoft Teams webhooks with score, grade,
  counts, top failures and drift; alert-only mode. `assess --notify-webhook`,
  `--notify-only-alert`.
- **AI assistance (optional, pluggable, privacy-preserving):** OpenAI-compatible
  `explain <RULE-ID>`, `ai-plan`, and `ask "…"` commands. Off by default; never
  transmits tokens/secrets. Configured via `GHE_AI_ENDPOINT/MODEL/KEY`.
- **Automations:** official GitHub Action (PR scorecard comment + gating) and
  example workflows for a scheduled governance issue and a human-in-the-loop
  auto-fix remediation-plan PR.
- **Version metadata:** `version` command and build info surfaced in the UI/health.
- Benchmarks for the assessment path to guard against performance regressions.

### Changed
- **Performance:** per-organization data is now fetched concurrently and cached,
  eliminating duplicate N+1 reads across rules. Repository scans are requested
  newest-push first and bounded by `max_repos_per_org` (default 500) to avoid
  unbounded pagination on very large organizations.
- Web dashboard hardened with graceful shutdown, strict security headers (CSP),
  request timeouts, and optional HTTP basic auth.
- Single source of truth for score→grade mapping via a shared `scoring` package
  (previously duplicated across reports and notifications).
- Toolchain moved to **Go 1.25** (required by the pure-Go SQLite driver); CI now
  builds golangci-lint v2 from source to match.

### Fixed
- Removed dead code: an unused accumulator in score aggregation and a stray
  no-op assignment in the assess handler.
- Remediation results are now persisted to history when a database is configured.
- Consistent line endings via `.gitattributes`; assessment output escaping and
  CSV quoting verified for untrusted content.

### Security
- Assessment remains strictly read-only; remediations stay idempotent,
  dry-runnable, and human-in-the-loop. Tokens are never persisted or logged.

## [1.1.0] - 2026-08-06

### Added
- Demo mode (`--demo`) running the real engine against synthetic data.
- Token scope preflight; `assess --fail-on` CI gating; self-contained HTML report.
- Dockerfile + GHCR image publishing; release binaries for linux/macOS/windows.
- Community & security files (SECURITY, CODE_OF_CONDUCT, CODEOWNERS), Dependabot,
  golangci-lint, Makefile.

### Changed
- Web server hardening (security headers, graceful shutdown, optional basic auth).

## [1.0.0] - 2026-08-06

### Added
- Initial release: 28 best-practice checks across 9 domains for GitHub Enterprise
  Cloud, as an interactive CLI and an embedded web dashboard. Read-only
  assessment with a 0–100 scorecard and idempotent, dry-runnable remediations.

[1.4.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.4.0
[1.3.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.3.0
[1.2.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.2.0
[1.1.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.1.0
[1.0.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.0.0
