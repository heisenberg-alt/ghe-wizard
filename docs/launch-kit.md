# Launch kit — social & community copy

Ready-to-post copy for sharing ghe-wizard. Replace the repo URL if you fork it.
Repo: https://github.com/heisenberg-alt/ghe-wizard

---

## Show HN

**Title:** Show HN: ghe-wizard – Assess and auto-fix GitHub Enterprise best practices

**Body:**
I kept seeing teams buy GitHub Enterprise Cloud and then struggle to set it up the
way GitHub actually recommends — the guidance is spread across dozens of docs
pages (enterprise owners, org strategy, rulesets, SSO/SCIM/2FA, GitHub Apps vs
PATs, cost centers, …).

ghe-wizard turns that guidance into an automated assess → recommend → remediate
tool. It scores your enterprise against 28 checks in 9 domains (read-only),
links every finding to the exact docs page, and can apply the fixable ones
idempotently with a dry-run preview. It's a single Go binary that's both a CLI
and a web dashboard.

You can try it with zero setup and no token via demo mode (runs the real engine
against synthetic data):

    go run ./cmd/ghe-wizard serve --demo

Repo (MIT): https://github.com/heisenberg-alt/ghe-wizard

Happy to answer questions about the rule catalog or the remediation model.

---

## Reddit (r/github, r/devops, r/sysadmin)

**Title:** I built an open-source tool that assesses and auto-fixes GitHub Enterprise best practices

Setting up GitHub Enterprise Cloud "the right way" means chasing guidance across
a lot of docs pages. ghe-wizard scores your enterprise against 28 best-practice
checks (owners, org strategy, rulesets, SSO/SCIM/2FA, secret scanning, cost
centers, and more), links each finding to the official docs, and can remediate
the automatable ones with a dry-run preview and confirmation.

- Read-only assessment → 0–100 scorecard
- CLI + web dashboard, single Go binary
- Demo mode (no token needed): `ghe-wizard serve --demo`
- MIT licensed, easy to add rules

Repo: https://github.com/heisenberg-alt/ghe-wizard — feedback welcome.

---

## LinkedIn

Just open-sourced **ghe-wizard** 🛡️

Buying GitHub Enterprise Cloud is easy. Configuring it the way GitHub actually
recommends — enterprise owners, org strategy, branch rulesets, SSO/SCIM/2FA,
secret scanning, GitHub Apps over PATs, cost centers — is where teams stall.

ghe-wizard automates GitHub's best-practice guidance end to end:
✅ Assess — 28 checks across 9 domains, 0–100 scorecard (read-only)
🧭 Recommend — every finding links to the exact GitHub docs page
🔧 Implement — idempotent one-click fixes with a dry-run preview

CLI + web dashboard, single Go binary, MIT licensed. Try it with zero setup via
demo mode (no token required).

👉 https://github.com/heisenberg-alt/ghe-wizard

#GitHub #DevOps #PlatformEngineering #DevSecOps #OpenSource

---

## X / Twitter (thread)

1/ Buying GitHub Enterprise is easy. Setting it up the way GitHub *recommends* is
not — the guidance is scattered across dozens of docs pages.

So I built ghe-wizard: assess → recommend → auto-fix, as a CLI + web dashboard. 🧵

2/ It scores your enterprise against 28 best-practice checks in 9 domains
(owners, orgs, teams, repos, policies, security, innersource, automation,
billing) and gives you a 0–100 scorecard. Assessment is 100% read-only.

3/ Every failing check links to the exact GitHub docs page and, when possible,
offers a one-click fix — idempotent, with a dry-run preview and confirmation
before anything changes.

4/ Try it in 10 seconds, no token needed (demo mode runs the real engine on
synthetic data):

    go run ./cmd/ghe-wizard serve --demo

5/ Single Go binary. MIT licensed. Multi-arch container on GHCR. Easy to extend —
add a rule in one init() block.

⭐ https://github.com/heisenberg-alt/ghe-wizard

---

## One-liner / elevator pitch

> ghe-wizard scores your GitHub Enterprise Cloud setup against GitHub's own
> best-practice guidance and fixes the gaps — read-only assessment, one-click
> remediation, CLI + web, MIT licensed.

## Suggested GitHub topics

github-enterprise · best-practices · governance · golang · cli · security ·
devops · compliance · enterprise-cloud · devsecproviders · scorecard
