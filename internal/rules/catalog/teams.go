package catalog

import (
	"context"
	"fmt"
	"sort"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// teamSampleRepos bounds the per-org repository sample for the
// direct-collaborator check, keeping API usage predictable on large orgs.
const teamSampleRepos = 10

func init() {
	// TEAM-01: Use teams (not direct collaborators) to manage access.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "TEAM-01", Domain: rules.DomainTeams, Severity: rules.SeverityMedium,
			Title:     "Use teams to manage access at scale",
			Rationale: "Direct per-repository collaborator grants bypass team-based governance and are invisible to IdP-driven offboarding.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-fundamentals/teams-in-an-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("TEAM-01").Meta()
			gov, ok := ghclient.Gov(api)
			if !ok {
				return rules.Manual(m, "Confirm access is managed through teams rather than individual grants.")
			}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var flagged []string
			sampled := 0
			for _, o := range orgs {
				repos, err := api.OrgRepos(ctx, o.Login, cfg.MaxReposPerOrg)
				if err != nil {
					continue
				}
				checked := 0
				for _, r := range repos {
					if r.Archived || checked >= teamSampleRepos {
						continue
					}
					checked++
					n, err := gov.RepoDirectCollaboratorCount(ctx, r.FullName)
					if err != nil {
						continue
					}
					sampled++
					if n > 0 {
						flagged = append(flagged, fmt.Sprintf("%s (%d direct)", r.FullName, n))
					}
				}
			}
			if sampled == 0 {
				return rules.Manual(m, "Direct-collaborator data unavailable; confirm access is managed through teams rather than individual grants.")
			}
			sort.Strings(flagged)
			if len(flagged) > 0 {
				return rules.Warn(m,
					fmt.Sprintf("%d of %d sampled repositories grant access to direct collaborators instead of teams (sample: %d most-recent repos per org).",
						len(flagged), sampled, teamSampleRepos), flagged)
			}
			return rules.Pass(m, fmt.Sprintf("No direct collaborators in %d sampled repositories.", sampled), nil)
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
			gov, ok := ghclient.Gov(api)
			if !ok {
				return rules.Manual(m, "Verify teams are synced to IdP groups where an identity provider is configured.")
			}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			total, determined := 0, 0
			reason := ""
			for _, o := range orgs {
				n, capb, err := gov.ExternalGroupCount(ctx, o.Login)
				if err != nil || !capb.Determined {
					if reason == "" && capb.Reason != "" {
						reason = capb.Reason
					}
					continue
				}
				determined++
				total += n
			}
			if determined == 0 {
				if reason == "" {
					reason = "external groups unavailable"
				}
				return rules.Manual(m, reason+". Verify teams are synced to IdP groups manually.")
			}
			if total == 0 {
				return rules.Warn(m, "No IdP groups are linked for team sync in any scanned organization.", nil)
			}
			return rules.Pass(m, fmt.Sprintf("%d IdP group(s) available for team sync across scanned organizations.", total), nil)
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

	// TEAM-04: No empty or unused teams.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "TEAM-04", Domain: rules.DomainTeams, Severity: rules.SeverityLow,
			Title:     "Clean up empty teams",
			Rationale: "Teams without members are governance debt: they suggest access paths that no longer map to real groups.",
			DocsURL:   docsBase + "/organizations/organizing-members-into-teams",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("TEAM-04").Meta()
			teams, res := collectTeams(ctx, api, cfg, m)
			if res != nil {
				return *res
			}
			var empty []string
			for org, list := range teams {
				for _, t := range list {
					if t.Members == 0 {
						empty = append(empty, org+"/"+t.Slug)
					}
				}
			}
			sort.Strings(empty)
			if len(empty) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d team(s) have no members.", len(empty)), empty)
			}
			return rules.Pass(m, "No empty teams in scanned organizations.", nil)
		},
	})

	// TEAM-05: Every team has a maintainer.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "TEAM-05", Domain: rules.DomainTeams, Severity: rules.SeverityMedium,
			Title:     "Every team has a maintainer",
			Rationale: "Teams without maintainers have no accountable owner for membership and access decisions.",
			DocsURL:   docsBase + "/organizations/organizing-members-into-teams/assigning-the-team-maintainer-role-to-a-team-member",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("TEAM-05").Meta()
			teams, res := collectTeams(ctx, api, cfg, m)
			if res != nil {
				return *res
			}
			var unowned []string
			for org, list := range teams {
				for _, t := range list {
					if t.Members > 0 && t.Maintainers == 0 {
						unowned = append(unowned, org+"/"+t.Slug)
					}
				}
			}
			sort.Strings(unowned)
			if len(unowned) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d team(s) have members but no maintainer.", len(unowned)), unowned)
			}
			return rules.Pass(m, "Every non-empty team has at least one maintainer.", nil)
		},
	})
}

// collectTeams gathers per-org team lists, returning a manual result when the
// data source is unavailable.
func collectTeams(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, m rules.Meta) (map[string][]ghclient.Team, *rules.Result) {
	gov, ok := ghclient.Gov(api)
	if !ok {
		r := rules.Manual(m, "Team data is unavailable with this client.")
		return nil, &r
	}
	orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
	if err != nil {
		r := rules.Errored(m, err.Error())
		return nil, &r
	}
	out := map[string][]ghclient.Team{}
	determined := 0
	for _, o := range orgs {
		teams, capb, err := gov.OrgTeams(ctx, o.Login)
		if err != nil || !capb.Determined {
			continue
		}
		determined++
		out[o.Login] = teams
	}
	if determined == 0 {
		r := rules.Manual(m, "Team data could not be read for any organization.")
		return nil, &r
	}
	return out, nil
}
