package catalog

import (
	"context"
	"fmt"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// ENT-01: Enterprise type chosen intentionally (EMU vs standard).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ENT-01", Domain: rules.DomainEnterprise, Severity: rules.SeverityInfo,
			Title:     "Enterprise type chosen intentionally",
			Rationale: "Choose between a standard enterprise and Enterprise Managed Users (EMU) based on whether you need to fully control member accounts from your IdP.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-fundamentals/choose-an-enterprise-type",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ENT-01").Meta()
			if res, ok := skipOnGHES(m, cfg, "Enterprise Managed Users"); ok {
				return res
			}
			ent, err := api.Enterprise(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if capInfo, ok := ent.Capabilities["emu"]; ok && !capInfo.Determined {
				return rules.Manual(m, "Enterprise type (EMU vs standard) is not reliably exposed via the API. Confirm your choice is intentional and documented.")
			}
			return rules.Pass(m, "Enterprise type detected.", ent.EMU)
		},
	})

	// ENT-02: Limit the number of enterprise owners.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ENT-02", Domain: rules.DomainEnterprise, Severity: rules.SeverityHigh,
			Title:     "Limit the number of enterprise owners",
			Rationale: "Enterprise owners have unrestricted access. Keep their number small and delegate with custom roles to follow least privilege.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/organize-work",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ENT-02").Meta()
			owners, err := api.EnterpriseOwners(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			maxOwners := cfg.Thresholds.MaxEnterpriseOwners
			logins := make([]string, 0, len(owners))
			for _, o := range owners {
				logins = append(logins, o.Login)
			}
			if len(owners) > maxOwners {
				return rules.Fail(m,
					fmt.Sprintf("%d enterprise owners exceed the recommended maximum of %d.", len(owners), maxOwners),
					"Reduce enterprise owners to the minimum and delegate duties using custom enterprise roles (e.g. auditors, billing managers).",
					logins)
			}
			return rules.Pass(m, fmt.Sprintf("%d enterprise owners (<= %d).", len(owners), maxOwners), logins)
		},
	})

	// ENT-03: Use custom roles for least-privilege delegation.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ENT-03", Domain: rules.DomainEnterprise, Severity: rules.SeverityMedium,
			Title:     "Delegate with custom roles (least privilege)",
			Rationale: "Custom roles grant only the permissions a team needs (e.g. audit-log read) instead of broad predefined roles.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-fundamentals/roles-in-an-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ENT-03").Meta()
			return rules.Manual(m, "Custom enterprise roles are in preview and not fully exposed via the API. Confirm delegation uses custom roles instead of granting enterprise owner broadly.")
		},
	})
}
