# GitHub Action examples

Copy these example workflows into `.github/workflows/` in the repository that
should run the automation, then set the required secrets. All three read
`GHE_TOKEN` and `GHE_ENTERPRISE` (a repo or org secret / variable).

## `governance.yml`

Runs the assessment on a schedule, manual dispatch, and pull requests. On PRs it
gates with `fail-on: fail` and posts a sticky scorecard comment; scheduled/manual
runs upload the scorecard as an artifact without failing. Uses the composite
action at `./action`.

## `scheduled-issue.yml`

Runs `ghe-wizard assess` weekly (and on manual dispatch), writes both JSON and
Markdown scorecards, and upserts one sticky GitHub Issue titled
**GHE governance scorecard**. The issue includes the current score, counts, top
failing findings with docs links, workflow-run link, and drift from the previous
tracked run. It creates the `governance` label if it is missing.

## `autofix-pr.yml`

Runs `ghe-wizard apply --dry-run` and opens/updates a single Pull Request that
records the proposed remediation plan (`ghe-remediation-plan.md`) for human
review. It **never applies** changes — ghe-wizard remediations are GitHub API
settings changes, so a human approves and runs `ghe-wizard apply` to enact them.
See [../AUTOFIX.md](../AUTOFIX.md) for the philosophy and security notes.

## Required secrets

- `GHE_TOKEN`: token that can read (and, for apply, change) the enterprise
  settings assessed by `ghe-wizard` — scopes `admin:enterprise`, `read:org`, `repo`.
- `GHE_ENTERPRISE`: GitHub Enterprise slug/account name.

## To adopt

1. Copy the chosen file from `action/examples/` into `.github/workflows/`.
2. Set the two secrets above in the destination repository or organization.
3. Adjust the cron schedule, image tag, or enterprise configuration in the
   workflow comments as needed.
