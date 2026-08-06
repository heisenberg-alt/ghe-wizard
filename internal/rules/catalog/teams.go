package catalog

import (
	"context"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// TEAM-01: Use enterprise teams to manage access at scale.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "TEAM-01", Domain: rules.DomainTeams, Severity: rules.SeverityMedium,
			Title:     "Use teams to manage access at scale",
			Rationale: "Teams are the best way to control access, licensing and delegation across organizations.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-fundamentals/teams-in-an-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("TEAM-01").Meta()
			return rules.Manual(m, "Confirm access, licensing and org membership are managed through enterprise teams rather than individual grants.")
		},
	})

	// TEAM-02: Sync teams to IdP groups.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "TEAM-02", Domain: rules.DomainTeams, Severity: rules.SeverityMedium,
			Title:     "Sync teams to IdP groups",
			Rationale: "If you use an external IdP, sync team membership to IdP groups so a central administrator controls access.",
			DocsURL:   docsBase + "/admin/managing-accounts-and-repositories/managing-users-in-your-enterprise/create-enterprise-teams",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("TEAM-02").Meta()
			return rules.Manual(m, "Verify teams are synced to IdP groups where an identity provider is configured.")
		},
	})

	// TEAM-03: Restrict who can manage team membership.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "TEAM-03", Domain: rules.DomainTeams, Severity: rules.SeverityMedium,
			Title:     "Limit who can control team membership",
			Rationale: "When teams grant access at scale, controlling their membership is sensitive; limit that permission to a few people.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/organize-work",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("TEAM-03").Meta()
			return rules.Manual(m, "Confirm only a small, trusted group can change team membership (ideally via IdP).")
		},
	})
}
