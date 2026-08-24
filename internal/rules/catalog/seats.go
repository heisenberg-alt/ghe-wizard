package catalog

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	"github.com/ghe-wizard/ghe-wizard/internal/usage"
)

// Seat-lifecycle FinOps rules (billing domain, so the finops profile covers
// them together with BILL-*). All remediations are DESTRUCTIVE — they cancel
// Copilot seats — and therefore run only via
// `apply --rules SEAT-0x --allow-destructive`.

// collectReclaim gathers every org's Copilot seats and computes the reclaim
// list, or returns a manual result when seat data is unavailable.
func collectReclaim(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, m rules.Meta) ([]usage.ReclaimRow, *rules.Result) {
	u, ok := ghclient.Usage(api)
	if !ok {
		r := rules.Manual(m, "Copilot seat data is unavailable with this client.")
		return nil, &r
	}
	orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
	if err != nil {
		r := rules.Errored(m, err.Error())
		return nil, &r
	}
	var seats []ghclient.CopilotSeat
	determined := 0
	for _, o := range orgs {
		s, capb, err := u.CopilotSeats(ctx, o.Login)
		if err != nil || !capb.Determined {
			continue
		}
		determined++
		seats = append(seats, s...)
	}
	if determined == 0 {
		r := rules.Manual(m, "Copilot seats could not be read for any organization (needs Copilot billing access).")
		return nil, &r
	}
	rows, _ := usage.Reclaim(seats, time.Now(), cfg.Usage.NeverActivatedDays, cfg.Usage.DormantDays, cfg.Usage.KeepsUser)
	return rows, nil
}

// remediateReclaim revokes the seats behind the given reclaim rows, grouped
// per organization.
func remediateReclaim(ctx context.Context, api ghclient.GHAPI, ruleID string, rows []usage.ReclaimRow, dryRun bool) rules.RemediationResult {
	res := rules.RemediationResult{RuleID: ruleID, DryRun: dryRun}
	client, wok := ghclient.Writer(api)
	if !dryRun && !wok {
		res.Errors = append(res.Errors, ghclient.ErrReadOnly)
	}
	byOrg := map[string][]string{}
	for _, r := range rows {
		res.Changes = append(res.Changes,
			fmt.Sprintf("REVOKE Copilot seat: %s in %s (%s)", r.Login, r.RevokeOrg, r.Reason))
		byOrg[r.RevokeOrg] = append(byOrg[r.RevokeOrg], r.Login)
	}
	if dryRun || !wok {
		return res
	}
	orgs := make([]string, 0, len(byOrg))
	for org := range byOrg {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)
	for _, org := range orgs {
		if _, err := client.RevokeCopilotSeats(ctx, org, byOrg[org]); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", org, err))
		} else {
			res.Applied = true
		}
	}
	return res
}

func filterRows(rows []usage.ReclaimRow, priority int) []usage.ReclaimRow {
	var out []usage.ReclaimRow
	for _, r := range rows {
		if r.Priority == priority {
			out = append(out, r)
		}
	}
	return out
}

func rowLabels(rows []usage.ReclaimRow) []string {
	labels := make([]string, 0, len(rows))
	for _, r := range rows {
		labels = append(labels, r.RevokeOrg+"/"+r.Login)
	}
	sort.Strings(labels)
	return labels
}

func init() {
	// SEAT-01: seats never activated since assignment.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEAT-01", Domain: rules.DomainBilling, Severity: rules.SeverityMedium,
			Title:       "Reclaim never-activated Copilot seats",
			Rationale:   "Seats assigned long ago that were never used are pure spend with no adoption; reclaim them and reassign on demand.",
			DocsURL:     docsBase + "/copilot/managing-copilot/managing-copilot-for-your-enterprise/managing-access-to-copilot-in-your-enterprise",
			Remediable:  true,
			Destructive: true,
		},
		AssessFn: seatAssess("SEAT-01", 1, func(n, threshold int) string {
			return fmt.Sprintf("%d seat(s) were assigned more than %d day(s) ago and never activated.", n, threshold)
		}, func(cfg *config.Config) int { return cfg.Usage.NeverActivatedDays }),
		RemediateFn: seatRemediate("SEAT-01", 1),
	})

	// SEAT-02: dormant seats.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEAT-02", Domain: rules.DomainBilling, Severity: rules.SeverityLow,
			Title:       "Reclaim dormant Copilot seats",
			Rationale:   "Seats idle beyond the policy window keep billing without delivering value; reclaim and reassign when the user returns.",
			DocsURL:     docsBase + "/copilot/managing-copilot/managing-copilot-for-your-enterprise/managing-access-to-copilot-in-your-enterprise",
			Remediable:  true,
			Destructive: true,
		},
		AssessFn: seatAssess("SEAT-02", 3, func(n, threshold int) string {
			return fmt.Sprintf("%d seat(s) have been dormant for %d+ day(s).", n, threshold)
		}, func(cfg *config.Config) int { return cfg.Usage.DormantDays }),
		RemediateFn: seatRemediate("SEAT-02", 3),
	})

	// SEAT-03: duplicate seats across organizations.
	rules.Register(rules.Base{
		M: rules.Meta{
			ID: "SEAT-03", Domain: rules.DomainBilling, Severity: rules.SeverityMedium,
			Title:       "Deduplicate Copilot seats billed across organizations",
			Rationale:   "Users holding seats in multiple organizations are billed repeatedly; keep the most active seat and reclaim the rest.",
			DocsURL:     docsBase + "/copilot/managing-copilot/managing-copilot-for-your-enterprise/managing-access-to-copilot-in-your-enterprise",
			Remediable:  true,
			Destructive: true,
		},
		AssessFn: seatAssess("SEAT-03", 2, func(n, _ int) string {
			return fmt.Sprintf("%d duplicate seat(s) are billed across organizations.", n)
		}, nil),
		RemediateFn: seatRemediate("SEAT-03", 2),
	})
}

// seatAssess builds the assess function for one reclaim class (priority).
// thresholdOf returns the policy window; when it yields 0 the check is
// disabled and reported as manual.
func seatAssess(id string, priority int, describe func(n, threshold int) string, thresholdOf func(*config.Config) int) rules.AssessFunc {
	return func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) rules.Result {
		m := rules.ByID(id).Meta()
		threshold := 0
		if thresholdOf != nil {
			threshold = thresholdOf(cfg)
			if threshold <= 0 {
				return rules.Manual(m, "Check disabled: set the corresponding usage: window in the policy file (never_activated_days / dormant_days).")
			}
		}
		rows, manual := collectReclaim(ctx, api, cfg, m)
		if manual != nil {
			return *manual
		}
		mine := filterRows(rows, priority)
		if len(mine) == 0 {
			return rules.Pass(m, "No reclaimable seats in this class.", nil)
		}
		detail := describe(len(mine), threshold) +
			" Review with 'ghe-wizard usage'; reclaim via 'apply --rules " + id + " --allow-destructive'."
		return rules.Warn(m, detail, rowLabels(mine))
	}
}

// seatRemediate builds the destructive remediation for one reclaim class.
func seatRemediate(id string, priority int) rules.RemediateFunc {
	return func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) rules.RemediationResult {
		m := rules.ByID(id).Meta()
		rows, manual := collectReclaim(ctx, api, cfg, m)
		if manual != nil {
			res := rules.RemediationResult{RuleID: id, DryRun: dryRun}
			if !dryRun {
				if _, wok := ghclient.Writer(api); !wok {
					res.Errors = append(res.Errors, ghclient.ErrReadOnly)
				}
			}
			res.Errors = append(res.Errors, strings.TrimSuffix(manual.Detail, "."))
			return res
		}
		return remediateReclaim(ctx, api, id, filterRows(rows, priority), dryRun)
	}
}
