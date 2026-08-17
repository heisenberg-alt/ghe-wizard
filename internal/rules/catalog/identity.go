package catalog

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// Identity domain: detect → warn → prevent for personal accounts registered
// with corporate email, plus outside-collaborator and SSO-linkage hygiene.
//
// Design notes:
//   - The corporate-domain set = GitHub-verified domains ∪ policy
//     identity.approved_domains. Rules that need it degrade to manual with
//     instructions when both are empty.
//   - GitHub exposes no way to find accounts by private registration email;
//     IDENT-08 sweeps PUBLIC signals only and says so, IDENT-10 closes the
//     gap with the company-owned mail-gateway trace.
//   - IDENT-04's remediation is DESTRUCTIVE (removes people) and only runs
//     via `apply --rules IDENT-04 --allow-destructive`.

const identityDocs = docsBase + "/admin/managing-iam"

// identityFor returns the identity read surface behind api, or a manual
// result when the client provides none.
func identityFor(api ghclient.GHAPI, m rules.Meta) (ghclient.IdentityAPI, *rules.Result) {
	id, ok := ghclient.Identity(api)
	if !ok {
		res := rules.Manual(m, "Identity data is unavailable with this client.")
		return nil, &res
	}
	return id, nil
}

// corporateDomains merges GitHub-verified domains with the policy's
// approved_domains (lowercased, deduped, sorted).
func corporateDomains(ctx context.Context, id ghclient.IdentityAPI, cfg *config.Config) []string {
	set := map[string]bool{}
	for _, d := range cfg.Identity.ApprovedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			set[d] = true
		}
	}
	doms, _, _ := id.EnterpriseVerifiedDomains(ctx, cfg.Enterprise)
	for _, d := range doms {
		if d.IsVerified {
			set[strings.ToLower(d.Domain)] = true
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// memberInventory merges the per-org member/verified-email lists into a
// deduped login → emails map. Orgs whose read was undetermined are counted.
func memberInventory(ctx context.Context, api ghclient.GHAPI, id ghclient.IdentityAPI, cfg *config.Config) (map[string][]string, int, error) {
	orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
	if err != nil {
		return nil, 0, err
	}
	inv := map[string][]string{}
	undetermined := 0
	for _, o := range orgs {
		members, capb, err := id.OrgMemberVerifiedEmails(ctx, o.Login)
		if err != nil || !capb.Determined {
			undetermined++
			continue
		}
		for _, m := range members {
			seen := map[string]bool{}
			for _, e := range inv[m.Login] {
				seen[e] = true
			}
			for _, e := range m.VerifiedEmails {
				e = strings.ToLower(e)
				if !seen[e] {
					inv[m.Login] = append(inv[m.Login], e)
					seen[e] = true
				}
			}
			if _, ok := inv[m.Login]; !ok {
				inv[m.Login] = nil
			}
		}
	}
	return inv, undetermined, nil
}

// readCSVColumn reads a CSV and returns lowercased non-empty first-column
// values, skipping a recognizable header row.
func readCSVColumn(path string) ([]string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-provided import file from the policy
	if err != nil {
		return nil, err
	}
	records, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	headers := map[string]bool{
		"email": true, "mail": true, "nameid": true, "name_id": true, "upn": true,
		"identity": true, "user": true, "login": true, "recipient": true, "recipientaddress": true,
	}
	var out []string
	for i, rec := range records {
		if len(rec) == 0 {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(rec[0]))
		if v == "" || (i == 0 && headers[v]) {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// readCSVEmails reads a CSV and returns every lowercased cell that looks like
// an email address, restricted to the given domains (mail-trace imports have
// arbitrary column layouts).
func readCSVEmails(path string, domains []string) ([]string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-provided import file from the policy
	if err != nil {
		return nil, err
	}
	records, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	set := map[string]bool{}
	for _, rec := range records {
		for _, cell := range rec {
			cell = strings.ToLower(strings.TrimSpace(cell))
			if !strings.Contains(cell, "@") {
				continue
			}
			for _, d := range domains {
				if strings.HasSuffix(cell, "@"+d) {
					set[cell] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	return out, nil
}

const noDomainsGuidance = "Verify your corporate domains on GitHub (Settings > Verified & approved domains) or set identity.approved_domains in the policy file."

func init() {
	// IDENT-01: Corporate domains verified and approved.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-01", Domain: rules.DomainIdentity, Severity: rules.SeverityMedium,
			Title:     "Verify and approve corporate domains",
			Rationale: "Verified domains prove ownership and unlock member-email visibility; approved domains enable notification restrictions.",
			DocsURL:   docsBase + "/admin/configuration/hardening-security-for-your-enterprise/verifying-or-approving-a-domain-for-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-01").Meta()
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			doms, capb, err := id.EnterpriseVerifiedDomains(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if !capb.Determined {
				return rules.Manual(m, capb.Reason)
			}
			var verified, approved []string
			for _, d := range doms {
				if d.IsVerified {
					verified = append(verified, d.Domain)
				}
				if d.IsApproved {
					approved = append(approved, d.Domain)
				}
			}
			switch {
			case len(verified) == 0 && len(approved) == 0:
				return rules.Fail(m, "No verified or approved domains are configured for the enterprise.",
					"Verify your corporate domains (DNS TXT record) so member emails become visible and restrictions can be enforced.", nil)
			case len(approved) == 0:
				return rules.Warn(m, fmt.Sprintf("%d domain(s) verified but none approved; approval is required for notification restrictions.", len(verified)), verified)
			default:
				return rules.Pass(m, fmt.Sprintf("%d verified, %d approved domain(s).", len(verified), len(approved)),
					map[string]any{"verified": verified, "approved": approved})
			}
		},
	})

	// IDENT-02: Restrict email notifications to approved domains.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-02", Domain: rules.DomainIdentity, Severity: rules.SeverityMedium,
			Title:      "Restrict email notifications to approved domains",
			Rationale:  "Without the restriction, repository notifications flow to any email on a member's personal account, leaking activity outside the company.",
			DocsURL:    docsBase + "/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/restricting-email-notifications-for-your-organization",
			Remediable: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-02").Meta()
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var disabled []string
			determined := 0
			for _, o := range orgs {
				on, capb, err := id.OrgNotificationRestriction(ctx, o.Login)
				if err != nil || !capb.Determined {
					continue
				}
				determined++
				if !on {
					disabled = append(disabled, o.Login)
				}
			}
			if determined == 0 {
				return rules.Manual(m, "Notification-restriction setting could not be read; confirm it is enabled in each organization (requires IDENT-01 approved domains).")
			}
			sort.Strings(disabled)
			if len(disabled) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) do not restrict email notifications to approved/verified domains.", len(disabled)), disabled)
			}
			return rules.Pass(m, fmt.Sprintf("Email notifications are domain-restricted in all %d scanned organizations.", determined), nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "IDENT-02", DryRun: dryRun}
			id, ok := ghclient.Identity(api)
			if !ok {
				res.Errors = append(res.Errors, "identity data unavailable with this client")
				return res
			}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				return res
			}
			client, wok := ghclient.Writer(api)
			if !dryRun && !wok {
				res.Errors = append(res.Errors, ghclient.ErrReadOnly)
			}
			for _, o := range orgs {
				on, capb, err := id.OrgNotificationRestriction(ctx, o.Login)
				if err != nil || !capb.Determined || on {
					continue
				}
				res.Changes = append(res.Changes,
					"restrict email notifications to approved/verified domains in "+o.Login+" (requires an approved domain — see IDENT-01)")
				if !dryRun && wok {
					if err := client.SetOrgNotificationRestriction(ctx, o.Login, true); err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.Login, err))
					} else {
						res.Applied = true
					}
				}
			}
			return res
		},
	})

	// IDENT-03: Members without a corporate-domain identity.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-03", Domain: rules.DomainIdentity, Severity: rules.SeverityMedium,
			Title:     "Members are identifiable by a corporate-domain email",
			Rationale: "Members with no corporate-domain email cannot be tied to an employee, complicating audits and offboarding.",
			DocsURL:   identityDocs,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-03").Meta()
			if cfg.Identity.ForbidCorporateEmailOnMembers {
				return rules.Result{Meta: m, Status: rules.StatusSkipped,
					Detail: "Identity posture forbids corporate email on member accounts (see IDENT-07); the identifiability check does not apply."}
			}
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			domains := corporateDomains(ctx, id, cfg)
			if len(domains) == 0 {
				return rules.Manual(m, noDomainsGuidance)
			}
			inv, undetermined, err := memberInventory(ctx, api, id, cfg)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if len(inv) == 0 && undetermined > 0 {
				return rules.Manual(m, "Member email data unavailable; verify a domain and re-run.")
			}
			var without []string
			for login, emails := range inv {
				if cfg.Identity.AllowsUser(login) {
					continue
				}
				if len(emails) == 0 {
					without = append(without, login)
				}
			}
			sort.Strings(without)
			if len(without) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d member(s) have no email on a corporate domain.", len(without)), without)
			}
			return rules.Pass(m, fmt.Sprintf("All %d scanned members carry a corporate-domain email.", len(inv)), nil)
		},
	})

	// IDENT-04: Outside collaborators within the policy threshold.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-04", Domain: rules.DomainIdentity, Severity: rules.SeverityMedium,
			Title:       "Outside collaborators are within the policy threshold",
			Rationale:   "Outside collaborators are personal accounts with repository access but no enterprise identity; keep their number deliberate and small.",
			DocsURL:     docsBase + "/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators",
			Remediable:  true,
			Destructive: true,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-04").Meta()
			if cfg.Identity.MaxOutsideCollaborators < 0 {
				return rules.Manual(m, "Set identity.max_outside_collaborators in the policy file to enforce a threshold (0 = none allowed).")
			}
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			over := map[string][]string{}
			total := 0
			for _, o := range orgs {
				users, err := id.OutsideCollaborators(ctx, o.Login)
				if err != nil {
					continue
				}
				var logins []string
				for _, u := range users {
					if !cfg.Identity.AllowsUser(u.Login) {
						logins = append(logins, u.Login)
					}
				}
				total += len(logins)
				if len(logins) > cfg.Identity.MaxOutsideCollaborators {
					sort.Strings(logins)
					over[o.Login] = logins
				}
			}
			if len(over) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d organization(s) exceed the outside-collaborator threshold of %d (%d collaborator(s) total).",
					len(over), cfg.Identity.MaxOutsideCollaborators, total), over)
			}
			return rules.Pass(m, fmt.Sprintf("Outside collaborators within threshold (%d total across scanned organizations).", total), nil)
		},
		RemediateFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
			res := rules.RemediationResult{RuleID: "IDENT-04", DryRun: dryRun}
			if cfg.Identity.MaxOutsideCollaborators != 0 {
				res.Errors = append(res.Errors,
					"removal only runs when identity.max_outside_collaborators is 0 (removing a subset is a human decision)")
				return res
			}
			id, ok := ghclient.Identity(api)
			if !ok {
				res.Errors = append(res.Errors, "identity data unavailable with this client")
				return res
			}
			orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				return res
			}
			client, wok := ghclient.Writer(api)
			if !dryRun && !wok {
				res.Errors = append(res.Errors, ghclient.ErrReadOnly)
			}
			for _, o := range orgs {
				users, err := id.OutsideCollaborators(ctx, o.Login)
				if err != nil {
					continue
				}
				for _, u := range users {
					if cfg.Identity.AllowsUser(u.Login) {
						continue
					}
					res.Changes = append(res.Changes,
						fmt.Sprintf("REMOVE outside collaborator %s from all repositories of %s", u.Login, o.Login))
					if !dryRun && wok {
						if err := client.RemoveOutsideCollaborator(ctx, o.Login, u.Login); err != nil {
							res.Errors = append(res.Errors, fmt.Sprintf("%s/%s: %v", o.Login, u.Login, err))
						} else {
							res.Applied = true
						}
					}
				}
			}
			return res
		},
	})

	// IDENT-05: Members linked to SSO.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-05", Domain: rules.DomainIdentity, Severity: rules.SeverityMedium,
			Title:     "All members are linked to an SSO identity",
			Rationale: "Members without a linked IdP identity keep access that offboarding cannot revoke centrally.",
			DocsURL:   docsBase + "/admin/managing-iam/using-saml-for-enterprise-iam/viewing-and-managing-a-user's-saml-access-to-your-enterprise",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-05").Meta()
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			ids, capb, err := id.SSOIdentities(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if !capb.Determined {
				return rules.Manual(m, capb.Reason)
			}
			linked := map[string]bool{}
			for _, i := range ids {
				if i.Login != "" {
					linked[strings.ToLower(i.Login)] = true
				}
			}
			inv, _, err := memberInventory(ctx, api, id, cfg)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			var unlinked []string
			for login := range inv {
				if cfg.Identity.AllowsUser(login) || linked[strings.ToLower(login)] {
					continue
				}
				unlinked = append(unlinked, login)
			}
			sort.Strings(unlinked)
			if len(unlinked) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d member(s) are not linked to an SSO identity.", len(unlinked)), unlinked)
			}
			return rules.Pass(m, fmt.Sprintf("All %d scanned members are SSO-linked.", len(inv)), nil)
		},
	})

	// IDENT-06: EMU advisory — the structural fix for personal accounts.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-06", Domain: rules.DomainIdentity, Severity: rules.SeverityInfo,
			Title:     "Consider Enterprise Managed Users to eliminate personal accounts",
			Rationale: "Only EMU guarantees that members are IdP-provisioned managed accounts; every other control mitigates rather than prevents personal-account exposure.",
			DocsURL:   docsBase + "/admin/managing-iam/understanding-iam-for-enterprises/about-enterprise-managed-users",
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-06").Meta()
			if res, ok := skipOnGHES(m, cfg, "Enterprise Managed Users"); ok {
				return res
			}
			return rules.Manual(m, "If personal-account exposure is unacceptable for your compliance posture, plan a migration to Enterprise Managed Users; the identity rules mitigate but cannot fully prevent it.")
		},
	})

	// IDENT-07: Corporate email on member accounts (the acme.com scenario).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-07", Domain: rules.DomainIdentity, Severity: rules.SeverityMedium,
			Title:     "Inventory corporate email on personal member accounts",
			Rationale: "Personal accounts registered with corporate email create account-recovery and data-governance risk when employees leave.",
			DocsURL:   identityDocs,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-07").Meta()
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			domains := corporateDomains(ctx, id, cfg)
			if len(domains) == 0 {
				return rules.Manual(m, noDomainsGuidance)
			}
			inv, undetermined, err := memberInventory(ctx, api, id, cfg)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if len(inv) == 0 && undetermined > 0 {
				return rules.Manual(m, "Member email data unavailable; verify a domain and re-run.")
			}
			carriers := map[string][]string{}
			for login, emails := range inv {
				if cfg.Identity.AllowsUser(login) || len(emails) == 0 {
					continue
				}
				carriers[login] = emails
			}
			if len(carriers) == 0 {
				return rules.Pass(m, "No member account carries a corporate-domain email.", nil)
			}
			if cfg.Identity.ForbidCorporateEmailOnMembers {
				return rules.Warn(m,
					fmt.Sprintf("%d member account(s) carry a corporate-domain email, which your policy forbids. Run 'ghe-wizard identity warn' to generate the notification campaign.", len(carriers)),
					carriers)
			}
			return rules.Manual(m,
				fmt.Sprintf("Inventory: %d member account(s) carry a corporate-domain email (allowed by current posture; set identity.forbid_corporate_email_on_members to enforce).", len(carriers)))
		},
	})

	// IDENT-08: Public signals of corporate email outside the enterprise.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-08", Domain: rules.DomainIdentity, Severity: rules.SeverityHigh,
			Title:     "No unsanctioned accounts show corporate email in public signals",
			Rationale: "Accounts outside the enterprise using corporate email are shadow IT: unmanaged, unauditable, and unrecoverable at offboarding.",
			DocsURL:   identityDocs,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-08").Meta()
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			domains := corporateDomains(ctx, id, cfg)
			if len(domains) == 0 {
				return rules.Manual(m, noDomainsGuidance)
			}
			inv, _, _ := memberInventory(ctx, api, id, cfg)
			member := map[string]bool{}
			for login := range inv {
				member[strings.ToLower(login)] = true
			}
			suspects := map[string]bool{}
			var notes []string
			for _, d := range domains {
				users, capb, _ := id.SearchUsersByEmailDomain(ctx, d)
				if !capb.Determined {
					notes = append(notes, capb.Reason)
				}
				authors, capb2, _ := id.SearchCommitAuthorsByDomain(ctx, d)
				if !capb2.Determined {
					notes = append(notes, capb2.Reason)
				}
				for _, l := range append(users, authors...) {
					ll := strings.ToLower(l)
					if !member[ll] && !cfg.Identity.AllowsUser(l) {
						suspects[l] = true
					}
				}
			}
			list := make([]string, 0, len(suspects))
			for l := range suspects {
				list = append(list, l)
			}
			sort.Strings(list)
			suffix := " Public-signal coverage is partial by design; import a mail-gateway trace (IDENT-10) for the complete picture."
			if len(notes) > 0 {
				suffix += " Notes: " + strings.Join(notes, "; ")
			}
			if len(list) > 0 {
				return rules.Warn(m, fmt.Sprintf("%d account(s) outside the enterprise show public signals of corporate email.%s", len(list), suffix), list)
			}
			return rules.Pass(m, "No public signals of corporate email outside the enterprise."+suffix, nil)
		},
	})

	// IDENT-09: Departed employees still linked (roster cross-check).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-09", Domain: rules.DomainIdentity, Severity: rules.SeverityHigh,
			Title:     "No departed employees retain a linked identity",
			Rationale: "SSO identities that are absent from the current employee roster indicate departed employees whose GitHub linkage was never cleaned up.",
			DocsURL:   identityDocs,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-09").Meta()
			if cfg.Identity.RosterCSV == "" {
				return rules.Manual(m, "Provide identity.roster_csv in the policy file (one current-employee email or IdP name-ID per line) to enable the offboarding cross-check.")
			}
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			roster, err := readCSVColumn(cfg.Identity.RosterCSV)
			if err != nil {
				return rules.Errored(m, "roster import: "+err.Error())
			}
			current := map[string]bool{}
			for _, r := range roster {
				current[r] = true
			}
			ids, capb, err := id.SSOIdentities(ctx, cfg.Enterprise)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if !capb.Determined {
				return rules.Manual(m, capb.Reason)
			}
			var departed []string
			for _, i := range ids {
				nameID := strings.ToLower(i.NameID)
				if nameID == "" || current[nameID] {
					continue
				}
				if i.Login != "" && cfg.Identity.AllowsUser(i.Login) {
					continue
				}
				label := nameID
				if i.Login != "" {
					label = i.Login + " (" + nameID + ")"
				}
				departed = append(departed, label)
			}
			sort.Strings(departed)
			if len(departed) > 0 {
				return rules.Fail(m,
					fmt.Sprintf("%d SSO identit(y/ies) are not in the employee roster — possible departed employees still linked.", len(departed)),
					"Remove the SSO linkage/enterprise access for departed employees, and do not recycle their mailboxes until GitHub linkage is cleared.",
					departed)
			}
			return rules.Pass(m, fmt.Sprintf("All %d SSO identities match the roster.", len(ids)), nil)
		},
	})

	// IDENT-10: Mail-gateway trace cross-check (the complete rogue detector).
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "IDENT-10", Domain: rules.DomainIdentity, Severity: rules.SeverityHigh,
			Title:     "No unsanctioned GitHub signups on corporate mailboxes",
			Rationale: "GitHub signup requires email verification, so the corporate mail gateway sees every registration — the only complete detector for accounts with private emails.",
			DocsURL:   identityDocs,
		},
		AssessFn: func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
			m := rules.ByID("IDENT-10").Meta()
			if cfg.Identity.MailTraceCSV == "" {
				return rules.Manual(m, "Provide identity.mail_trace_csv (a mail-gateway message-trace export of GitHub signup mail recipients). Generate the matching prevention rule with 'ghe-wizard identity transport-rule'.")
			}
			id, manual := identityFor(api, m)
			if manual != nil {
				return *manual
			}
			domains := corporateDomains(ctx, id, cfg)
			if len(domains) == 0 {
				return rules.Manual(m, noDomainsGuidance)
			}
			traced, err := readCSVEmails(cfg.Identity.MailTraceCSV, domains)
			if err != nil {
				return rules.Errored(m, "mail-trace import: "+err.Error())
			}
			inv, undetermined, err := memberInventory(ctx, api, id, cfg)
			if err != nil {
				return rules.Errored(m, err.Error())
			}
			if len(inv) == 0 && undetermined > 0 {
				return rules.Manual(m, "Member email data unavailable to correlate the mail trace; verify a domain and re-run.")
			}
			known := map[string]bool{}
			for _, emails := range inv {
				for _, e := range emails {
					known[e] = true
				}
			}
			var unknown []string
			for _, addr := range traced {
				if !known[addr] {
					unknown = append(unknown, addr)
				}
			}
			if len(unknown) > 0 {
				return rules.Fail(m,
					fmt.Sprintf("%d corporate address(es) received GitHub signup mail but match no enterprise member — unsanctioned personal accounts.", len(unknown)),
					"Warn the mailbox owners to remove the corporate email or delete the account ('ghe-wizard identity warn'), and deploy the prevention transport rule.",
					unknown)
			}
			return rules.Pass(m, fmt.Sprintf("All %d traced signup addresses belong to known enterprise members.", len(traced)), nil)
		},
	})
}
