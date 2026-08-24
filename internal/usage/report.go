package usage

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
)

// Report is the full FinOps view rendered by the CLI and the /api/usage
// endpoint.
type Report struct {
	Enterprise  string           `json:"enterprise"`
	GeneratedAt time.Time        `json:"generated_at"`
	Days        int              `json:"metric_days"`
	Seats       SeatKPIs         `json:"seats"`
	Reclaim     []ReclaimRow     `json:"reclaim"`
	Spend       SpendKPIs        `json:"spend"`
	Models      []ModelEconomics `json:"models"`
	ROI         ROIResult        `json:"roi"`
	// Notes surfaces partial data (unavailable orgs/endpoints, unmapped
	// models) so the report never over-claims coverage.
	Notes []string `json:"notes,omitempty"`
}

// Collect gathers seats, metrics and billing through the assessment API and
// assembles the report using the config's usage/ROI settings.
func Collect(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) (*Report, error) {
	u, ok := ghclient.Usage(api)
	if !ok {
		return nil, fmt.Errorf("usage data is unavailable with this client")
	}
	r := &Report{Enterprise: cfg.Enterprise, GeneratedAt: time.Now().UTC()}

	orgs, err := api.Organizations(ctx, cfg.Enterprise, cfg.MaxOrgs)
	if err != nil {
		return nil, err
	}
	var seats []ghclient.CopilotSeat
	for _, o := range orgs {
		s, capb, err := u.CopilotSeats(ctx, o.Login)
		if err != nil || !capb.Determined {
			reason := capb.Reason
			if reason == "" && err != nil {
				reason = err.Error()
			}
			r.Notes = append(r.Notes, "seats: "+reason)
			continue
		}
		seats = append(seats, s...)
	}
	r.Reclaim, r.Seats = Reclaim(seats, time.Now(), cfg.Usage.NeverActivatedDays, cfg.Usage.DormantDays, cfg.Usage.KeepsUser)

	days, capb, _ := u.CopilotMetricsDays(ctx, cfg.Enterprise)
	if !capb.Determined {
		r.Notes = append(r.Notes, "metrics: "+capb.Reason)
	}
	r.Days = len(days)
	billing, bcap, _ := u.EnterpriseBillingUsage(ctx, cfg.Enterprise)
	if !bcap.Determined {
		r.Notes = append(r.Notes, "billing: "+bcap.Reason)
	}
	r.Models, r.Spend = Economics(days, billing)
	for _, m := range r.Models {
		if m.Unmapped {
			r.Notes = append(r.Notes, "unmapped model in telemetry: "+m.Family+" (extend the crosswalk)")
		}
	}

	acceptances := 0
	for _, m := range r.Models {
		acceptances += m.Acceptances
	}
	r.ROI = ComputeROI(ROIAssumptions{
		HourlyRateUSD:             cfg.ROI.HourlyRateUSD,
		MinutesSavedPerAcceptance: cfg.ROI.MinutesSavedPerAcceptance,
	}, acceptances, r.Spend.CopilotUSD)
	sort.Strings(r.Notes)
	r.Notes = slices.Compact(r.Notes)
	return r, nil
}

// JSON renders the report as indented JSON.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// ReclaimCSV renders the reclaim list for spreadsheets/ticketing.
func (r *Report) ReclaimCSV() string {
	var b strings.Builder
	b.WriteString("priority,login,revoke_org,revoke_tier,kept_org,kept_tier,days_since_activity,reason\n")
	for _, row := range r.Reclaim {
		days := fmt.Sprintf("%d", row.DaysSinceActivity)
		if row.DaysSinceActivity < 0 {
			days = "never"
		}
		fmt.Fprintf(&b, "%d,%s,%s,%s,%s,%s,%s,%q\n",
			row.Priority, row.Login, row.RevokeOrg, row.RevokeTier, row.KeptOrg, row.KeptTier, days, row.Reason)
	}
	return b.String()
}

// Markdown renders the full report.
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Copilot usage, spend & ROI — %s\n\n", r.Enterprise)
	fmt.Fprintf(&b, "- **Generated:** %s\n- **Metric window:** %d day(s)\n\n", r.GeneratedAt.Format("2006-01-02 15:04 UTC"), r.Days)

	b.WriteString("## Seats\n\n")
	fmt.Fprintf(&b, "| Licensed | Never activated | Dormant | Duplicate seats |\n|---:|---:|---:|---:|\n| %d | %d | %d | %d |\n\n",
		r.Seats.Licensed, r.Seats.NeverActivated, r.Seats.Dormant, r.Seats.Duplicates)

	if len(r.Reclaim) > 0 {
		b.WriteString("### Reclaim list\n\n| P | Login | Revoke | Kept | Last activity | Reason |\n|---|---|---|---|---|---|\n")
		for _, row := range r.Reclaim {
			days := fmt.Sprintf("%dd ago", row.DaysSinceActivity)
			if row.DaysSinceActivity < 0 {
				days = "never"
			}
			kept := "—"
			if row.KeptOrg != "" {
				kept = row.KeptOrg + " (" + row.KeptTier + ")"
			}
			fmt.Fprintf(&b, "| %d | %s | %s (%s) | %s | %s | %s |\n",
				row.Priority, row.Login, row.RevokeOrg, row.RevokeTier, kept, days, row.Reason)
		}
		b.WriteString("\nApply with: `ghe-wizard apply --rules SEAT-01,SEAT-02,SEAT-03 --allow-destructive --dry-run`\n\n")
	}

	b.WriteString("## Spend\n\n")
	fmt.Fprintf(&b, "| Total | Copilot | Premium requests | Premium share | Auto-routed activity | Cost/acceptance |\n|---:|---:|---:|---:|---:|---:|\n")
	cpa := "n/a"
	if r.Spend.CostPerAcceptanceUSD >= 0 {
		cpa = fmt.Sprintf("$%.3f", r.Spend.CostPerAcceptanceUSD)
	}
	fmt.Fprintf(&b, "| $%.2f | $%.2f | $%.2f | %.1f%% | %.1f%% | %s |\n\n",
		r.Spend.TotalUSD, r.Spend.CopilotUSD, r.Spend.PremiumRequestUSD,
		r.Spend.PremiumSharePct, r.Spend.AutoRoutedActivityPct, cpa)

	if len(r.Models) > 0 {
		b.WriteString("## Model economics\n\n| Family | Vendor | Tier | Acceptances | Activity share | Cost | Cost share | Cost/acceptance |\n|---|---|---|---:|---:|---:|---:|---:|\n")
		for _, m := range r.Models {
			name := m.Family
			if m.Unmapped {
				name += " (unmapped)"
			}
			mcpa := "—"
			if m.CostPerAcceptance >= 0 {
				mcpa = fmt.Sprintf("$%.4f", m.CostPerAcceptance)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %.1f%% | $%.2f | %.1f%% | %s |\n",
				name, m.Vendor, m.Tier, m.Acceptances, m.ActivitySharePct, m.CostUSD, m.CostSharePct, mcpa)
		}
		b.WriteString("\n")
	}

	b.WriteString("## ROI (explicit assumptions)\n\n")
	fmt.Fprintf(&b, "Assumptions: **$%.0f/hour**, **%.1f minutes saved per acceptance** (set `roi:` in the policy file).\n\n",
		r.ROI.Assumptions.HourlyRateUSD, r.ROI.Assumptions.MinutesSavedPerAcceptance)
	payback := "n/a (no measured spend)"
	if r.ROI.Payback >= 0 {
		payback = fmt.Sprintf("%.1fx", r.ROI.Payback)
	}
	fmt.Fprintf(&b, "| Acceptances | Hours saved | Value | Spend | Payback |\n|---:|---:|---:|---:|---:|\n| %d | %.1f | $%.2f | $%.2f | %s |\n\n",
		r.ROI.Acceptances, r.ROI.HoursSaved, r.ROI.ValueUSD, r.ROI.SpendUSD, payback)

	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			b.WriteString("- " + n + "\n")
		}
	}
	return b.String()
}
