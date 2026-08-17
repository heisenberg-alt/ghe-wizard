package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// ORG-01: Organizations created intentionally (flag sprawl).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ORG-01", Domain: rules.DomainOrgs, Severity: rules.SeverityMedium,
			Title:     "Create organizations intentionally",
			Rationale: "Too many organizations hurt discoverability and @-mentions; too few hurt governance. Be intentional and start small.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/organize-work",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ORG-01").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			names := orgNames(orgs)
			if len(orgs) > 25 {
				return rules.Warn(m, fmt.Sprintf("%d organizations found. Review whether this reflects an intentional strategy (related work vs governance) and consolidate where possible.", len(orgs)), names)
			}
			return rules.Pass(m, fmt.Sprintf("%d organizations.", len(orgs)), names)
		},
	})

	// ORG-02: Each org maps to a clear model (manual/documentation).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ORG-02", Domain: rules.DomainOrgs, Severity: rules.SeverityLow,
			Title:     "Map each organization to a clear model",
			Rationale: "Each org should group either related work projects or similar governance requirements.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/organize-work",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ORG-02").Meta()
			return rules.Manual(m, "Document, for each organization, whether it groups related work or shared governance requirements.")
		},
	})

	// ORG-03: Flag stale/empty organizations for cleanup.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ORG-03", Domain: rules.DomainOrgs, Severity: rules.SeverityLow,
			Title:     "Clean up legacy or stale organizations",
			Rationale: "Regularly evaluate and clean up legacy organizations as part of your access and governance review.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/organize-work",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ORG-03").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			cutoff := time.Now().AddDate(0, 0, -cfg.Thresholds.StaleOrgDays)
			var stale []string
			for _, o := range orgs {
				repos, err := api.OrgRepos(ctx, o.Login, 0)
				if err != nil {
					continue
				}
				if len(repos) == 0 {
					stale = append(stale, o.Login+" (no repositories)")
					continue
				}
				newest := time.Time{}
				for _, r := range repos {
					if r.PushedAt.After(newest) {
						newest = r.PushedAt
					}
				}
				if !newest.IsZero() && newest.Before(cutoff) {
					stale = append(stale, fmt.Sprintf("%s (last activity %s)", o.Login, newest.Format("2006-01-02")))
				}
			}
			if len(stale) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) look stale or empty and may be candidates for cleanup.", len(stale)), stale)
			}
			return rules.Pass(m, "No obviously stale or empty organizations detected.", nil)
		},
	})

	// ORG-04: Base repository permission is not overly permissive.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ORG-04", Domain: rules.DomainOrgs, Severity: rules.SeverityHigh,
			Title:      "Base repository permission is least-privilege",
			Rationale:  "A permissive default (write/admin) grants all members broad access. Prefer 'none' or 'read' and grant access via teams.",
			DocsURL:    docsBase + "/organizations/managing-user-access-to-your-organizations-repositories/setting-base-permissions-for-an-organization",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ORG-04").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var bad []string
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if s.DefaultRepositoryPermission == "write" || s.DefaultRepositoryPermission == "admin" {
					bad = append(bad, fmt.Sprintf("%s=%s", o.Login, s.DefaultRepositoryPermission))
				}
			}
			if len(bad) > 0 {
				return rules.Fail(m,
					fmt.Sprintf("%d organization(s) use a permissive base permission.", len(bad)),
					"Set base permission to 'read' (or 'none') and grant repository access through teams.",
					bad)
			}
			return rules.Pass(m, "All scanned organizations use a least-privilege base permission.", nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "ORG-04", DryRun: dryRun}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				return res
			}
			client, ok := ghclient.Writer(api)
			if !dryRun && !ok {
				res.Errors = append(res.Errors, ghclient.ErrReadOnly)
			}
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if s.DefaultRepositoryPermission == "write" || s.DefaultRepositoryPermission == "admin" {
					change := fmt.Sprintf("set %s base permission %s -> read", o.Login, s.DefaultRepositoryPermission)
					res.Changes = append(res.Changes, change)
					if !dryRun && ok {
						if err := client.SetOrgDefaultRepositoryPermission(ctx, o.Login, "read"); err != nil {
							res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.Login, err))
						} else {
							res.Applied = true
						}
					}
				}
			}
			return res
		},
	})

	// ORG-05: Require sign-off on web-based commits.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ORG-05", Domain: rules.DomainOrgs, Severity: rules.SeverityLow,
			Title:      "Require contributors to sign off on web-based commits",
			Rationale:  "Web commit sign-off records explicit agreement to contribution terms for changes made through the web UI.",
			DocsURL:    docsBase + "/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ORG-05").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var without []string
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if !s.WebCommitSignoffRequired {
					without = append(without, o.Login)
				}
			}
			if len(without) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) do not require sign-off on web-based commits.", len(without)), without)
			}
			return rules.Pass(m, "Web commit sign-off is required in scanned organizations.", nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "ORG-05", DryRun: dryRun}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				return res
			}
			client, ok := ghclient.Writer(api)
			if !dryRun && !ok {
				res.Errors = append(res.Errors, ghclient.ErrReadOnly)
			}
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil || s.WebCommitSignoffRequired {
					continue
				}
				res.Changes = append(res.Changes, "require web commit sign-off in "+o.Login)
				if !dryRun && ok {
					if err := client.SetOrgWebCommitSignoff(ctx, o.Login, true); err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.Login, err))
					} else {
						res.Applied = true
					}
				}
			}
			return res
		},
	})

	// ORG-06: Members cannot fork private/internal repositories.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "ORG-06", Domain: rules.DomainOrgs, Severity: rules.SeverityMedium,
			Title:      "Disable forking of private repositories",
			Rationale:  "Private forks copy sensitive code outside the governed repository, surviving access revocation and complicating leak response.",
			DocsURL:    docsBase + "/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("ORG-06").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var open []string
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if s.MembersCanForkPrivateRepos {
					open = append(open, o.Login)
				}
			}
			if len(open) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) allow members to fork private repositories.", len(open)), open)
			}
			return rules.Pass(m, "Private-repository forking is disabled in scanned organizations.", nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "ORG-06", DryRun: dryRun}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				return res
			}
			client, ok := ghclient.Writer(api)
			if !dryRun && !ok {
				res.Errors = append(res.Errors, ghclient.ErrReadOnly)
			}
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil || !s.MembersCanForkPrivateRepos {
					continue
				}
				res.Changes = append(res.Changes, "disable private-repository forking in "+o.Login)
				if !dryRun && ok {
					if err := client.SetOrgMembersCanForkPrivate(ctx, o.Login, false); err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.Login, err))
					} else {
						res.Applied = true
					}
				}
			}
			return res
		},
	})
}

func orgNames(orgs []ghclient.Organization) []string {
	out := make([]string, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, o.Login)
	}
	return out
}
