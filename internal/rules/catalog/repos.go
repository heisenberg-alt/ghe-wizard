package catalog

import (
	"context"
	"fmt"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// REPO-01: Prefer org-owned repositories over user-owned.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "REPO-01", Domain: rules.DomainRepos, Severity: rules.SeverityMedium,
			Title:     "Collaborate in organization-owned repositories",
			Rationale: "Org-owned repos have richer security/admin features and remain accessible as membership changes.",
			DocsURL:   docsBase + "/admin/concepts/enterprise-best-practices/organize-work",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("REPO-01").Meta()
			return rules.Manual(m, "Encourage collaboration in organization-owned repositories and minimize work in user-owned repositories.")
		},
	})

	// REPO-02: Define enterprise custom properties for classification.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "REPO-02", Domain: rules.DomainRepos, Severity: rules.SeverityMedium,
			Title:      "Define custom properties for repository governance",
			Rationale:  "Enterprise custom properties give organizations a consistent way to classify repositories and target rulesets/policies.",
			DocsURL:    docsBase + "/admin/managing-accounts-and-repositories/managing-repositories-in-your-enterprise/managing-custom-properties-for-repositories-in-your-enterprise",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("REPO-02").Meta()
			props, err := api.EnterpriseCustomProperties(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Manual(m, "Could not read the enterprise custom property schema: "+err.Error())
			}
			if len(props) == 0 {
				return rules.Fail(m,
					"No enterprise custom properties are defined.",
					"Define at least a 'data-classification' custom property so repositories can be governed consistently.",
					nil)
			}
			names := make([]string, 0, len(props))
			for _, p := range props {
				names = append(names, p.Name)
			}
			return rules.Pass(m, fmt.Sprintf("%d enterprise custom property(ies) defined.", len(props)), names)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "REPO-02", DryRun: dryRun}
			res.Changes = append(res.Changes, "create custom property 'data-classification' (single_select: public, internal, confidential)")
			if !dryRun {
				if client, ok := ghclient.Writer(api); ok {
					if err := client.CreateEnterpriseCustomProperty(ctx, cfg.Enterprise, "data-classification", "single_select", false); err != nil {
						res.Errors = append(res.Errors, err.Error())
					} else {
						res.Applied = true
					}
				} else {
					res.Errors = append(res.Errors, ghclient.ErrReadOnly)
				}
			}
			return res
		},
	})

	// REPO-03: Members cannot create repos with overly broad defaults.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "REPO-03", Domain: rules.DomainRepos, Severity: rules.SeverityLow,
			Title:      "Review repository creation permissions",
			Rationale:  "Control who can create repositories — especially public ones — to keep repository sprawl and visibility in check.",
			DocsURL:    docsBase + "/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("REPO-03").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var open, public []string
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if s.MembersCanCreatePublicRepos {
					public = append(public, o.Login)
				} else if s.MembersCanCreateRepos {
					open = append(open, o.Login)
				}
			}
			if len(public) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) allow all members to create PUBLIC repositories.", len(public)), public)
			}
			if len(open) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) allow all members to create repositories.", len(open)), open)
			}
			return rules.Pass(m, "Repository creation is restricted in scanned organizations.", nil)
		},
		// The remediation deliberately covers only the safe subset: it turns
		// off member creation of PUBLIC repositories and leaves general repo
		// creation untouched (disabling that would disrupt normal workflows).
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "REPO-03", DryRun: dryRun}
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
				if err != nil || !s.MembersCanCreatePublicRepos {
					continue
				}
				res.Changes = append(res.Changes, "disable member creation of public repositories in "+o.Login)
				if !dryRun && ok {
					if err := client.SetOrgMembersCanCreatePublicRepos(ctx, o.Login, false); err != nil {
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
