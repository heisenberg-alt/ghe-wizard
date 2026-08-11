package catalog

import (
	"context"
	"fmt"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// IS-01: Innersource practices enabled.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IS-01", Domain: rules.DomainInnersource, Severity: rules.SeverityLow,
			Title:     "Enable innersource collaboration",
			Rationale: "Innersource lets employees discover and reuse work, avoiding duplicated effort. Use internal visibility and discoverability.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/use-innersource",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IS-01").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			internal := 0
			for _, o := range orgs {
				repos, err := api.OrgRepos(ctx, o.Login, 0)
				if err != nil {
					continue
				}
				for _, r := range repos {
					if r.Visibility == "internal" {
						internal++
					}
				}
			}
			if internal == 0 {
				return rules.Warn(m, "No internal-visibility repositories found. Consider using internal repos to enable innersource discovery and reuse.", nil)
			}
			return rules.Pass(m, fmt.Sprintf("%d internal-visibility repositories support innersource.", internal), nil)
		},
	})

	// AUTO-01: Automate with GitHub Apps instead of PATs.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "AUTO-01", Domain: rules.DomainAutomation, Severity: rules.SeverityMedium,
			Title:     "Automate with GitHub Apps, not personal tokens",
			Rationale: "GitHub Apps provide scoped, auditable identities for automation, unlike broad personal access tokens.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-fundamentals/automations-in-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("AUTO-01").Meta()
			insts, err := api.EnterpriseInstallations(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Manual(m, "Could not list enterprise app installations: "+err.Error()+". Confirm automations use GitHub Apps.")
			}
			if len(insts) == 0 {
				return rules.Warn(m, "No GitHub Apps installed on the enterprise account. Prefer GitHub Apps over PATs for enterprise automation.", nil)
			}
			return rules.Pass(m, fmt.Sprintf("%d GitHub App(s) installed on the enterprise account.", len(insts)), nil)
		},
	})

	// AUTO-02: Provisioning/onboarding automated (manual review).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "AUTO-02", Domain: rules.DomainAutomation, Severity: rules.SeverityLow,
			Title:     "Automate onboarding and provisioning",
			Rationale: "Repeatable, automated provisioning reduces drift and manual error as the enterprise scales.",
			DocsURL:   docsBase + "/admin/managing-github-apps-for-your-enterprise/creating-github-apps-for-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("AUTO-02").Meta()
			return rules.Manual(m, "Confirm org/user provisioning and onboarding are automated and repeatable (IaC or scripts driven by GitHub Apps).")
		},
	})

	// BILL-01: Cost centers configured.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "BILL-01", Domain: rules.DomainBilling, Severity: rules.SeverityLow,
			Title:     "Allocate spend with cost centers",
			Rationale: "Cost centers allocate GitHub spending to business units independently of your org structure.",
			DocsURL:   docsBase + "/billing/concepts/enterprise-billing/billing-for-enterprises",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("BILL-01").Meta()
			if res, ok := skipOnGHES(m, cfg, "Enhanced billing with cost centers"); ok {
				return res
			}
			ccs, capb, err := api.CostCenters(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if !capb.Determined {
				return rules.Manual(m, capb.Reason)
			}
			if len(ccs) == 0 {
				return rules.Warn(m, "No cost centers configured. Consider cost centers to allocate spend to business units.", nil)
			}
			return rules.Pass(m, fmt.Sprintf("%d cost center(s) configured.", len(ccs)), nil)
		},
	})

	// BILL-02: Spending limits set (manual review).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "BILL-02", Domain: rules.DomainBilling, Severity: rules.SeverityLow,
			Title:     "Set spending limits",
			Rationale: "Spending limits guard against unexpected metered usage costs (Actions, Packages, Codespaces).",
			DocsURL:   docsBase + "/billing/managing-the-plan-for-your-github-account/managing-your-spending-limit",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("BILL-02").Meta()
			return rules.Manual(m, "Confirm spending limits are set intentionally for metered products (Actions, Packages, Codespaces).")
		},
	})
}
