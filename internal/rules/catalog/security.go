package catalog

import (
	"context"
	"fmt"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func init() {
	// SEC-01: SAML/OIDC SSO configured at the enterprise level.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEC-01", Domain: rules.DomainSecurity, Severity: rules.SeverityCritical,
			Title:     "Enterprise SSO (SAML/OIDC) configured",
			Rationale: "Centralized SSO at the enterprise level enforces authentication through your IdP and overrides org-level SSO.",
			DocsURL:   docsBase + "/admin/managing-iam/using-saml-for-enterprise-iam/configuring-saml-single-sign-on-for-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("SEC-01").Meta()
			ent, err := api.Enterprise(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if ent.SAMLEnabled {
				return rules.Pass(m, "Enterprise-level SAML SSO is configured.", nil)
			}
			return rules.Fail(m, "No enterprise-level SAML identity provider detected.",
				"Configure SAML or OIDC SSO at the enterprise level so authentication is centralized.", nil)
		},
	})

	// SEC-02: SCIM provisioning enabled.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEC-02", Domain: rules.DomainSecurity, Severity: rules.SeverityHigh,
			Title:     "SCIM provisioning enabled",
			Rationale: "SCIM automates provisioning and deprovisioning of users from your IdP, reducing orphaned access.",
			DocsURL:   docsBase + "/admin/managing-iam/provisioning-user-accounts-with-scim",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("SEC-02").Meta()
			return rules.Manual(m, "Confirm SCIM provisioning is enabled and healthy for your enterprise/IdP.")
		},
	})

	// SEC-03: 2FA required across organizations.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEC-03", Domain: rules.DomainSecurity, Severity: rules.SeverityHigh,
			Title:      "Require two-factor authentication",
			Rationale:  "Requiring 2FA protects accounts from credential compromise.",
			DocsURL:    docsBase + "/admin/enforcing-policies/enforcing-policies-for-security-settings-in-your-enterprise",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("SEC-03").Meta()
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
				if !s.TwoFactorRequired {
					without = append(without, o.Login)
				}
			}
			if len(without) > 0 {
				return rules.Fail(m, fmt.Sprintf("%d organization(s) do not require 2FA.", len(without)),
					"Require two-factor authentication (ideally enforce at the enterprise level).", without)
			}
			return rules.Pass(m, "All scanned organizations require 2FA.", nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "SEC-03", DryRun: dryRun}
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
				if err != nil || s.TwoFactorRequired {
					continue
				}
				res.Changes = append(res.Changes, "require 2FA for org "+o.Login)
				if !dryRun && ok {
					if err := client.SetOrgTwoFactorRequired(ctx, o.Login, true); err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.Login, err))
					} else {
						res.Applied = true
					}
				}
			}
			return res
		},
	})

	// SEC-04: Audit log streaming enabled.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEC-04", Domain: rules.DomainSecurity, Severity: rules.SeverityMedium,
			Title:     "Stream the enterprise audit log to a SIEM",
			Rationale: "Streaming the audit log to external storage supports compliance and long-term retention.",
			DocsURL:   docsBase + "/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("SEC-04").Meta()
			if res, ok := skipOnGHES(m, cfg, "The cloud audit-log streaming API"); ok {
				return res
			}
			enabled, capb, err := api.AuditLogStreamEnabled(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if !capb.Determined {
				return rules.Manual(m, capb.Reason)
			}
			if enabled {
				return rules.Pass(m, "Audit log streaming is enabled.", nil)
			}
			return rules.Fail(m, "Audit log streaming is not enabled.",
				"Configure audit log streaming to your SIEM or cloud storage.", nil)
		},
	})

	// SEC-05: Secret scanning + push protection enabled.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEC-05", Domain: rules.DomainSecurity, Severity: rules.SeverityHigh,
			Title:      "Enable secret scanning and push protection",
			Rationale:  "Secret scanning with push protection prevents credentials from being committed.",
			DocsURL:    docsBase + "/code-security/securing-your-organization",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("SEC-05").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var missing []string
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if !s.SecretScanningEnabled || !s.SecretScanningPushProtect {
					missing = append(missing, o.Login)
				}
			}
			if len(missing) > 0 {
				return rules.Fail(m, fmt.Sprintf("%d organization(s) do not enable secret scanning with push protection for new repos.", len(missing)),
					"Enable secret scanning and push protection for new repositories.", missing)
			}
			return rules.Pass(m, "Secret scanning and push protection are enabled for new repos in scanned organizations.", nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "SEC-05", DryRun: dryRun}
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
				if err != nil || (s.SecretScanningEnabled && s.SecretScanningPushProtect) {
					continue
				}
				res.Changes = append(res.Changes, "enable secret scanning + push protection for new repos in "+o.Login)
				if !dryRun && ok {
					if err := client.SetOrgSecretScanningDefaults(ctx, o.Login, true); err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.Login, err))
					} else {
						res.Applied = true
					}
				}
			}
			return res
		},
	})

	// SEC-06: Dependency graph + Dependabot alerts on by default.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEC-06", Domain: rules.DomainSecurity, Severity: rules.SeverityMedium,
			Title:      "Enable Dependabot alerts for new repositories",
			Rationale:  "The dependency graph with Dependabot alerts surfaces vulnerable dependencies automatically across every new repository.",
			DocsURL:    docsBase + "/code-security/dependabot/dependabot-alerts/about-dependabot-alerts",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("SEC-06").Meta()
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var missing []string
			for _, o := range orgs {
				s, err := api.OrgSettings(ctx, o.Login)
				if err != nil {
					continue
				}
				if !s.DependencyGraphEnabled || !s.DependabotAlertsEnabled {
					missing = append(missing, o.Login)
				}
			}
			if len(missing) > 0 {
				return rules.Fail(m, fmt.Sprintf("%d organization(s) do not enable the dependency graph with Dependabot alerts for new repos.", len(missing)),
					"Enable the dependency graph, Dependabot alerts and security updates for new repositories.", missing)
			}
			return rules.Pass(m, "Dependency graph and Dependabot alerts are enabled for new repos in scanned organizations.", nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "SEC-06", DryRun: dryRun}
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
				if err != nil || (s.DependencyGraphEnabled && s.DependabotAlertsEnabled) {
					continue
				}
				res.Changes = append(res.Changes,
					"enable dependency graph + Dependabot alerts/security updates for new repos in "+o.Login+" (security updates open PRs)")
				if !dryRun && ok {
					if err := client.SetOrgDependabotDefaults(ctx, o.Login); err != nil {
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
