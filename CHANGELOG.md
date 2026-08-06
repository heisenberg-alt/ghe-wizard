# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.2.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.2.0
[1.1.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.1.0
[1.0.0]: https://github.com/heisenberg-alt/ghe-wizard/releases/tag/v1.0.0
