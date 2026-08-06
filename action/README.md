# GHE Best-Practices Assessment Action

Run [`ghe-wizard`](https://github.com/heisenberg-alt/ghe-wizard) in GitHub Actions using the published container image and produce a scorecard for GitHub Enterprise governance checks.

## Usage

```yaml
name: GHE Governance Assessment

on:
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'
  pull_request:

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: ghe
        uses: ./action
        with:
          enterprise: ${{ secrets.GHE_ENTERPRISE }}
          token: ${{ secrets.GHE_TOKEN }}
          fail-on: ${{ github.event_name == 'pull_request' && 'fail' || '' }}
          format: json
          output: scorecard.json
          comment-pr: 'true'
      - if: ${{ always() }}
        uses: actions/upload-artifact@v4
        with:
          name: ghe-wizard-scorecard
          path: scorecard.json
```

When published from this repository, replace `uses: ./action` with the released action reference.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `enterprise` | Yes |  | GitHub Enterprise slug or account name. |
| `token` | Yes |  | Token used by `ghe-wizard` for API access. Store it as `secrets.GHE_TOKEN`. |
| `fail-on` | No | `''` | Optional threshold: `fail`, `warn`, or empty. |
| `format` | No | `json` | Report format written to `output`: `json`, `md`, or `html`. |
| `output` | No | `scorecard.json` | Workspace-relative report path. |
| `comment-pr` | No | `true` | Upsert a sticky pull request comment when the workflow event is `pull_request`. |
| `version` | No | `latest` | Tag for `ghcr.io/heisenberg-alt/ghe-wizard`. |

## Outputs

| Output | Description |
| --- | --- |
| `score` | Numeric score from the JSON scorecard. |
| `grade` | Letter grade computed from score: A >= 90, B >= 75, C >= 60, D >= 40, else F. |
| `failing` | Number of failed checks. |
| `warnings` | Number of warning checks. |

## Pull request comment

When `comment-pr` is `true`, the action creates or updates one sticky PR comment containing `<!-- ghe-wizard -->`. It includes:

- Score and grade.
- Counts for pass, fail, warn, manual, error, and total.
- Up to 10 top failing findings with documentation links.

The hidden marker keeps the comment idempotent so repeated workflow runs update the same comment instead of spamming the PR.

## Token scopes

The assessment token should have the scopes required by the checks you enable:

- `admin:enterprise`
- `read:org`
- `repo`

PR comments use the workflow `GITHUB_TOKEN`; set workflow permissions for `issues: write` and `pull-requests: write`.
