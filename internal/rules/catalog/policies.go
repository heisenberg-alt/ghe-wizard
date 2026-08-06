package catalog

import (
	"context"
	"fmt"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// POL-01: Repository policies control create/delete/rename/transfer.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "POL-01", Domain: rules.DomainPolicies, Severity: rules.SeverityMedium,
			Title:     "Govern repository management actions",
			Rationale: "Enterprise repository policies control who can create, delete, rename, transfer or change the visibility of repositories.",
			DocsURL:   docsBase + "/admin/managing-accounts-and-repositories/managing-repositories-in-your-enterprise/governing-how-people-use-repositories-in-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("POL-01").Meta()
			return rules.Manual(m, "Confirm enterprise repository policies restrict deletion/transfer/visibility changes for production repositories.")
		},
	})

	// POL-02: Enterprise rulesets protect important branches.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "POL-02", Domain: rules.DomainPolicies, Severity: rules.SeverityHigh,
			Title:      "Protect important branches with enterprise rulesets",
			Rationale:  "Enterprise rulesets enforce protections (e.g. require pull requests with reviews) across all repositories.",
			DocsURL:    docsBase + "/enterprise-onboarding/govern-people-and-repositories/protect-branches",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("POL-02").Meta()
			rs, err := api.EnterpriseRulesets(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Manual(m, "Could not read enterprise rulesets: "+err.Error())
			}
			active := 0
			for _, r := range rs {
				if r.Enforcement == "active" {
					active++
				}
			}
			if active == 0 {
				return rules.Fail(m,
					"No active enterprise rulesets found.",
					"Create an active branch ruleset requiring pull requests with reviews on default branches.",
					nil)
			}
			return rules.Pass(m, fmt.Sprintf("%d active enterprise ruleset(s).", active), nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "POL-02", DryRun: dryRun}
			payload := map[string]any{
				"name":        "Require PR reviews on default branch",
				"target":      "branch",
				"enforcement": "active",
				"conditions": map[string]any{
					"ref_name": map[string]any{"include": []string{"~DEFAULT_BRANCH"}, "exclude": []string{}},
				},
				"rules": []map[string]any{
					{"type": "pull_request", "parameters": map[string]any{
						"required_approving_review_count":   1,
						"dismiss_stale_reviews_on_push":     true,
						"require_code_owner_review":         false,
						"require_last_push_approval":        false,
						"required_review_thread_resolution": false,
					}},
				},
			}
			res.Changes = append(res.Changes, "create active enterprise branch ruleset 'Require PR reviews on default branch' (1 approval)")
			if !dryRun {
				if client, ok := api.(*ghclient.Client); ok {
					if err := client.CreateEnterpriseRuleset(ctx, cfg.Enterprise, payload); err != nil {
						res.Errors = append(res.Errors, err.Error())
					} else {
						res.Applied = true
					}
				}
			}
			return res
		},
	})

	// POL-03: IP allow list configured (if required).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "POL-03", Domain: rules.DomainPolicies, Severity: rules.SeverityLow,
			Title:     "IP allow list configured (if required)",
			Rationale: "IP allow lists restrict where people can access your enterprise. Enable if your compliance requires it.",
			DocsURL:   docsBase + "/admin/configuration/hardening-security-for-your-enterprise/restricting-network-traffic-to-your-enterprise-with-an-ip-allow-list",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("POL-03").Meta()
			ent, err := api.Enterprise(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if ent.IPAllowListEnabled {
				return rules.Pass(m, "IP allow list is enabled.", nil)
			}
			return rules.Warn(m, "IP allow list is not enabled. Enable it if your compliance posture requires network restrictions.", nil)
		},
	})

	// POL-04: Copilot policies set intentionally.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "POL-04", Domain: rules.DomainPolicies, Severity: rules.SeverityLow,
			Title:     "Set Copilot policies intentionally",
			Rationale: "Govern which Copilot features and models people can use across the enterprise.",
			DocsURL:   docsBase + "/copilot/managing-copilot/managing-github-copilot-in-your-organization",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("POL-04").Meta()
			return rules.Manual(m, "Review Copilot policies (features, models, duplication detection) and confirm they match your governance requirements.")
		},
	})

	// POL-05: Default workflow permissions are read-only.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "POL-05", Domain: rules.DomainPolicies, Severity: rules.SeverityHigh,
			Title:     "Default GITHUB_TOKEN permissions are read-only",
			Rationale: "A permissive default workflow token ('read and write') broadens the blast radius of a compromised workflow.",
			DocsURL:   docsBase + "/admin/enforcing-policies/enforcing-policies-for-your-enterprise/enforcing-policies-for-github-actions-in-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("POL-05").Meta()
			ent, err := api.Enterprise(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			switch ent.DefaultWorkflowPermissions {
			case "read":
				return rules.Pass(m, "Default workflow permissions are read-only.", nil)
			case "write":
				return rules.Fail(m, "Default workflow permissions are read and write.",
					"Set the default GITHUB_TOKEN permissions to read-only at the enterprise level.", nil)
			default:
				return rules.Manual(m, "Default workflow permission level not exposed via API. Verify it is set to read-only in Actions policies.")
			}
		},
	})
}
