# Contributing to ghe-wizard

Thanks for your interest in improving ghe-wizard! This document explains how to
build the project, the conventions it follows, and how to add new checks.

## Prerequisites

- Go **1.24+**
- (Optional) Docker, for building the container image

## Getting started

```bash
git clone https://github.com/heisenberg-alt/ghe-wizard
cd ghe-wizard

go build ./...          # build everything
go vet ./...            # static analysis
go test ./...           # unit tests (mock GitHub API)

go run ./cmd/ghe-wizard list      # list the rule catalog
go run ./cmd/ghe-wizard serve     # start the web dashboard on :8080
```

All of the above run in CI on every pull request.

## Project layout

```
cmd/ghe-wizard/          CLI entrypoint (assess | wizard | apply | report | serve | list)
internal/ghclient/       GitHub REST+GraphQL client (PAT auth, pagination, rate limits)
internal/rules/          Rule interface, registry, function-backed Base helper
internal/rules/catalog/  Best-practice rules, one file per domain
internal/engine/         Runs rules, aggregates the scorecard, runs remediations
internal/report/         JSON / Markdown reporters
internal/web/            HTTP JSON API + embedded dashboard UI (go:embed)
internal/config/         Config + thresholds loading
```

## Core principles

1. **Assessment is read-only.** The `Assess` path must never mutate the
   enterprise. Only `Remediate` may perform writes.
2. **Remediations are idempotent and dry-runnable.** Re-check current state
   before acting, and honor the `dryRun` flag by describing changes without
   applying them.
3. **Degrade gracefully.** If the API cannot determine a value, return
   `StatusManual` (human review) rather than guessing or failing the whole run.
4. **Cite the source.** Every rule links to the official GitHub Docs page that
   defines the best practice it enforces.

## Adding a new rule

Rules live in `internal/rules/catalog/`, grouped by domain. Register one in an
`init()` using the `rules.Base` helper:

```go
func init() {
    rules.Register(rules.Base{
        M: rules.Meta{
            ID: "SEC-06", Domain: rules.DomainSecurity, Severity: rules.SeverityHigh,
            Title:      "Short, imperative title",
            Rationale:  "Why this matters, in one or two sentences.",
            DocsURL:    docsBase + "/admin/...",
            Remediable: true, // set true only if you implement RemediateFn
        },
        AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
            m := rules.ByID("SEC-06").Meta()
            // ... read state via api, return rules.Pass/Fail/Warn/Manual/Errored
        },
        RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
            // ... describe changes; apply only when !dryRun
        },
    })
}
```

New rules are picked up automatically by both the CLI and the web server. Please
add a unit test in `internal/engine/engine_test.go` using the in-memory
`mockAPI` to cover the pass and fail paths.

## Rule ID convention

`<DOMAIN-PREFIX>-<NN>` — e.g. `ENT-`, `ORG-`, `TEAM-`, `REPO-`, `POL-`, `SEC-`,
`IS-`, `AUTO-`, `BILL-`.

## Commit & PR guidelines

- Keep changes focused; one logical change per PR.
- Ensure `go build`, `go vet`, and `go test` all pass locally.
- Fill out the pull request template checklist.
- For UI changes, include a screenshot.

## Security

Please report security vulnerabilities privately via a
[GitHub security advisory](https://github.com/heisenberg-alt/ghe-wizard/security/advisories/new)
rather than opening a public issue.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
