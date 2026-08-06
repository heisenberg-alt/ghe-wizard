# Auto-remediation plan Pull Requests

`ghe-wizard apply --dry-run` can generate a proposed remediation log without changing anything. The example workflow in [`examples/autofix-pr.yml`](examples/autofix-pr.yml) turns that log into a Pull Request containing `ghe-remediation-plan.md`.

## Philosophy

Keep a human strictly in the loop. ghe-wizard remediations are GitHub API settings changes, not repository file edits. Examples include organization base permissions, enterprise or organization 2FA requirements, secret-scanning push protection, enterprise rulesets, and custom properties.

The PR pattern records the proposed settings plan for review and approval. It must never auto-apply governance changes from CI.

## How the workflow works

1. A maintainer runs the workflow manually, or the optional weekly schedule runs it.
2. The workflow runs `ghe-wizard apply --dry-run` in `ghcr.io/heisenberg-alt/ghe-wizard:latest`.
3. If no remediable drift is reported, it logs that the enterprise is already compliant and skips PR creation.
4. If changes are proposed, it writes `ghe-remediation-plan.md`, reuses the branch `ghe-wizard/remediation-plan`, and opens or updates a PR titled `chore: proposed GHE governance remediations`.
5. Reviewers approve or reject the plan. Applying the changes remains a separate human action.

## Required secrets and variables

- `secrets.GHE_TOKEN`: a least-privilege token with the enterprise and organization permissions required for the rules you intend to review and apply.
- `vars.GHE_ENTERPRISE` or `secrets.GHE_ENTERPRISE`: the enterprise slug/name. The manual workflow input can override this.

Use a dedicated token or GitHub App installation token where possible. Rotate it regularly, restrict its scope, and avoid logging command traces.

## Applying approved changes

After the PR is reviewed, an authorized operator applies the approved rules from a trusted machine:

```bash
export GHE_ENTERPRISE=octo-enterprise
export GHE_TOKEN=ghp_xxx

# Re-preview before changing settings.
docker run --rm -e GHE_ENTERPRISE -e GHE_TOKEN \
  ghcr.io/heisenberg-alt/ghe-wizard:latest apply --dry-run --rules ORG-04,SEC-03

# Apply only the approved rule IDs. ghe-wizard prompts for confirmation by default.
docker run --rm -e GHE_ENTERPRISE -e GHE_TOKEN \
  ghcr.io/heisenberg-alt/ghe-wizard:latest apply --rules ORG-04,SEC-03
```

Run `ghe-wizard assess --format md` afterward to verify the enterprise scorecard.

## Security considerations

- Do not run `ghe-wizard apply` automatically from this workflow.
- Keep `GHE_TOKEN` out of logs; do not enable `set -x`.
- Use the narrowest token permissions that can read and change the selected governance settings.
- Treat the generated PR as an approval artifact, not as proof that changes were applied.
- Re-run `apply --dry-run` immediately before applying because enterprise settings can drift after the PR is generated.
