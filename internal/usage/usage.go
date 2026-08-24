// Package usage turns raw Copilot seat, metrics and billing data into FinOps
// views: seat-reclaim lists, model economics and an explicit-assumptions ROI
// model.
package usage

import (
	"sort"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
)

// ModelClass positions a raw telemetry/billing model ID in the pricing space.
type ModelClass struct {
	Vendor     string
	Family     string
	Tier       string // included | balanced | frontier
	AutoRouted bool
}

// crosswalk maps model-ID substrings to classes, first match wins. Keeping it
// declarative makes new models a table-only change; unmapped IDs are surfaced
// by Classify, never silently dropped.
var crosswalk = []struct {
	match string
	class ModelClass
}{
	{"auto", ModelClass{Vendor: "GitHub", Family: "Auto-routed", Tier: "balanced", AutoRouted: true}},
	{"claude-haiku", ModelClass{Vendor: "Anthropic", Family: "Claude Haiku", Tier: "included"}},
	{"claude-sonnet", ModelClass{Vendor: "Anthropic", Family: "Claude Sonnet", Tier: "balanced"}},
	{"claude-opus", ModelClass{Vendor: "Anthropic", Family: "Claude Opus", Tier: "frontier"}},
	{"claude", ModelClass{Vendor: "Anthropic", Family: "Claude", Tier: "balanced"}},
	{"gpt-5-codex", ModelClass{Vendor: "OpenAI", Family: "GPT Codex", Tier: "frontier"}},
	{"gpt-5-mini", ModelClass{Vendor: "OpenAI", Family: "GPT mini", Tier: "included"}},
	{"gpt-5", ModelClass{Vendor: "OpenAI", Family: "GPT-5", Tier: "frontier"}},
	{"gpt-4", ModelClass{Vendor: "OpenAI", Family: "GPT-4.x", Tier: "included"}},
	{"o3", ModelClass{Vendor: "OpenAI", Family: "o-series", Tier: "balanced"}},
	{"o4", ModelClass{Vendor: "OpenAI", Family: "o-series", Tier: "balanced"}},
	{"gemini", ModelClass{Vendor: "Google", Family: "Gemini", Tier: "balanced"}},
}

// Classify returns the model's class; ok=false marks an unmapped model.
func Classify(modelID string) (ModelClass, bool) {
	id := strings.ToLower(modelID)
	for _, c := range crosswalk {
		if strings.Contains(id, c.match) {
			return c.class, true
		}
	}
	return ModelClass{Vendor: "unknown", Family: modelID, Tier: "unknown"}, false
}

// --- Seats: idle, duplicate & reclaim ---------------------------------------

// SeatKPIs summarizes the licensed pool.
type SeatKPIs struct {
	Licensed       int `json:"licensed"`
	NeverActivated int `json:"never_activated"`
	Dormant        int `json:"dormant"`
	Duplicates     int `json:"duplicate_seats"`
}

// ReclaimRow is one actionable seat-reclaim proposal.
type ReclaimRow struct {
	Login             string `json:"login"`
	RevokeOrg         string `json:"revoke_org"`
	RevokeTier        string `json:"revoke_tier"`
	KeptOrg           string `json:"kept_org,omitempty"`
	KeptTier          string `json:"kept_tier,omitempty"`
	DaysSinceActivity int    `json:"days_since_activity"` // -1 = never active
	Reason            string `json:"reason"`
	Priority          int    `json:"priority"` // 1 never-activated, 2 duplicate, 3 dormant
}

// Reclaim computes the seat KPIs and the reclaim list. keep exempts logins
// from reclaim proposals (they still count in the KPIs). Each seat yields at
// most one row, classified by the highest-priority reason that applies.
func Reclaim(seats []ghclient.CopilotSeat, now time.Time, neverDays, dormantDays int, keep func(string) bool) ([]ReclaimRow, SeatKPIs) {
	kpi := SeatKPIs{Licensed: len(seats)}
	byLogin := map[string][]ghclient.CopilotSeat{}
	for _, s := range seats {
		byLogin[s.Login] = append(byLogin[s.Login], s)
	}
	// For duplicate holders, keep the seat with the most recent activity
	// (ties: enterprise tier wins, then org name for determinism).
	keptSeat := map[string]ghclient.CopilotSeat{}
	for login, list := range byLogin {
		best := list[0]
		for _, s := range list[1:] {
			switch {
			case s.LastActivityAt.After(best.LastActivityAt):
				best = s
			case s.LastActivityAt.Equal(best.LastActivityAt) && s.PlanType == "enterprise" && best.PlanType != "enterprise":
				best = s
			case s.LastActivityAt.Equal(best.LastActivityAt) && s.PlanType == best.PlanType && s.Org < best.Org:
				best = s
			}
		}
		keptSeat[login] = best
		kpi.Duplicates += len(list) - 1
	}
	var rows []ReclaimRow
	for _, s := range seats {
		never := s.LastActivityAt.IsZero()
		days := -1
		if !never {
			days = int(now.Sub(s.LastActivityAt).Hours() / 24)
		}
		dormant := !never && dormantDays > 0 && days >= dormantDays
		if never {
			kpi.NeverActivated++
		}
		if dormant {
			kpi.Dormant++
		}
		kept := keptSeat[s.Login]
		duplicate := kept.Org != s.Org || kept.PlanType != s.PlanType || !kept.CreatedAt.Equal(s.CreatedAt)
		if keep != nil && keep(s.Login) {
			continue
		}
		row := ReclaimRow{Login: s.Login, RevokeOrg: s.Org, RevokeTier: s.PlanType, DaysSinceActivity: days}
		switch {
		case never && neverDays > 0 && now.Sub(s.CreatedAt).Hours() >= float64(neverDays)*24:
			row.Reason, row.Priority = "never activated since assignment", 1
		case duplicate:
			row.Reason, row.Priority = "duplicate seat across organizations", 2
			row.KeptOrg, row.KeptTier = kept.Org, kept.PlanType
		case dormant:
			row.Reason, row.Priority = "dormant", 3
		default:
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority < rows[j].Priority
		}
		if rows[i].Login != rows[j].Login {
			return rows[i].Login < rows[j].Login
		}
		return rows[i].RevokeOrg < rows[j].RevokeOrg
	})
	return rows, kpi
}

// --- Model economics ----------------------------------------------------------

// ModelEconomics aggregates activity and attributed spend per model family.
type ModelEconomics struct {
	Family            string  `json:"family"`
	Vendor            string  `json:"vendor"`
	Tier              string  `json:"tier"`
	AutoRouted        bool    `json:"auto_routed"`
	Unmapped          bool    `json:"unmapped,omitempty"`
	Suggestions       int     `json:"suggestions"`
	Acceptances       int     `json:"acceptances"`
	LinesAccepted     int     `json:"lines_accepted"`
	ActivitySharePct  float64 `json:"activity_share_pct"`
	CostUSD           float64 `json:"cost_usd"`
	CostSharePct      float64 `json:"cost_share_pct"`
	CostPerAcceptance float64 `json:"cost_per_acceptance_usd"` // -1 when unknown
}

// SpendKPIs summarizes billing usage. Model-attributed spend comes from
// premium-request line items; auto-routed activity has no separate bill, so
// its share is activity-based.
type SpendKPIs struct {
	TotalUSD              float64 `json:"total_usd"`
	CopilotUSD            float64 `json:"copilot_usd"`
	PremiumRequestUSD     float64 `json:"premium_request_usd"`
	PremiumSharePct       float64 `json:"premium_cost_share_pct"` // of Copilot spend
	AutoRoutedActivityPct float64 `json:"auto_routed_activity_share_pct"`
	CostPerAcceptanceUSD  float64 `json:"copilot_cost_per_acceptance_usd"` // -1 unknown
}

// Economics joins Copilot metrics with billing via the model crosswalk.
func Economics(days []ghclient.MetricsDay, billing []ghclient.BillingUsageItem) ([]ModelEconomics, SpendKPIs) {
	agg := map[string]*ModelEconomics{}
	get := func(class ModelClass, unmapped bool) *ModelEconomics {
		m := agg[class.Family]
		if m == nil {
			m = &ModelEconomics{Family: class.Family, Vendor: class.Vendor, Tier: class.Tier,
				AutoRouted: class.AutoRouted, Unmapped: unmapped, CostPerAcceptance: -1}
			agg[class.Family] = m
		}
		return m
	}
	totalAcceptances, autoAcceptances := 0, 0
	for _, d := range days {
		for _, mu := range d.Models {
			class, ok := Classify(mu.ID)
			m := get(class, !ok)
			m.Suggestions += mu.Suggestions
			m.Acceptances += mu.Acceptances
			m.LinesAccepted += mu.LinesAccepted
			totalAcceptances += mu.Acceptances
			if class.AutoRouted {
				autoAcceptances += mu.Acceptances
			}
		}
	}
	var kpi SpendKPIs
	modelCost := 0.0
	for _, b := range billing {
		kpi.TotalUSD += b.NetAmountUSD
		if b.Product == "copilot" {
			kpi.CopilotUSD += b.NetAmountUSD
		}
		if b.Model == "" {
			continue
		}
		kpi.PremiumRequestUSD += b.NetAmountUSD
		class, ok := Classify(b.Model)
		m := get(class, !ok)
		m.CostUSD += b.NetAmountUSD
		modelCost += b.NetAmountUSD
	}
	out := make([]ModelEconomics, 0, len(agg))
	for _, m := range agg {
		if totalAcceptances > 0 {
			m.ActivitySharePct = 100 * float64(m.Acceptances) / float64(totalAcceptances)
		}
		if modelCost > 0 {
			m.CostSharePct = 100 * m.CostUSD / modelCost
		}
		if m.Acceptances > 0 && m.CostUSD > 0 {
			m.CostPerAcceptance = m.CostUSD / float64(m.Acceptances)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CostUSD != out[j].CostUSD {
			return out[i].CostUSD > out[j].CostUSD
		}
		return out[i].Acceptances > out[j].Acceptances
	})
	if kpi.CopilotUSD > 0 {
		kpi.PremiumSharePct = 100 * kpi.PremiumRequestUSD / kpi.CopilotUSD
	}
	if totalAcceptances > 0 {
		kpi.AutoRoutedActivityPct = 100 * float64(autoAcceptances) / float64(totalAcceptances)
		if kpi.CopilotUSD > 0 {
			kpi.CostPerAcceptanceUSD = kpi.CopilotUSD / float64(totalAcceptances)
		} else {
			kpi.CostPerAcceptanceUSD = -1
		}
	} else {
		kpi.CostPerAcceptanceUSD = -1
	}
	return out, kpi
}

// --- ROI ------------------------------------------------------------------------

// ROIAssumptions are the explicit inputs to the agentic-SDLC ROI model. They
// are always carried alongside the result — no black-box ROI.
type ROIAssumptions struct {
	HourlyRateUSD             float64 `json:"hourly_rate_usd"`
	MinutesSavedPerAcceptance float64 `json:"minutes_saved_per_acceptance"`
}

// ROIResult is the computed value model.
type ROIResult struct {
	Assumptions ROIAssumptions `json:"assumptions"`
	Acceptances int            `json:"acceptances"`
	HoursSaved  float64        `json:"hours_saved"`
	ValueUSD    float64        `json:"value_usd"`
	SpendUSD    float64        `json:"spend_usd"`
	Payback     float64        `json:"payback_multiple"` // value / spend; -1 unknown
}

// ComputeROI applies the assumptions to measured acceptances and spend.
func ComputeROI(a ROIAssumptions, acceptances int, spendUSD float64) ROIResult {
	r := ROIResult{Assumptions: a, Acceptances: acceptances, SpendUSD: spendUSD, Payback: -1}
	r.HoursSaved = float64(acceptances) * a.MinutesSavedPerAcceptance / 60
	r.ValueUSD = r.HoursSaved * a.HourlyRateUSD
	if spendUSD > 0 {
		r.Payback = r.ValueUSD / spendUSD
	}
	return r
}
