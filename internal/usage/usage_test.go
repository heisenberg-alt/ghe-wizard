package usage

import (
	"math"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 0.01 }

func TestClassify(t *testing.T) {
	cases := []struct {
		id       string
		wantOK   bool
		vendor   string
		family   string
		tier     string
		autoRoll bool
	}{
		{"auto", true, "GitHub", "Auto-routed", "balanced", true},
		{"claude-sonnet-4.5", true, "Anthropic", "Claude Sonnet", "balanced", false},
		{"claude-opus-4.1", true, "Anthropic", "Claude Opus", "frontier", false},
		{"gpt-4.1", true, "OpenAI", "GPT-4.x", "included", false},
		{"gpt-5-codex", true, "OpenAI", "GPT Codex", "frontier", false},
		{"GPT-5", true, "OpenAI", "GPT-5", "frontier", false}, // case-insensitive
		{"gemini-2.5-pro", true, "Google", "Gemini", "balanced", false},
		{"experimental-x1", false, "unknown", "experimental-x1", "unknown", false},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got, ok := Classify(c.id)
			if ok != c.wantOK {
				t.Fatalf("Classify(%q) ok=%v, want %v", c.id, ok, c.wantOK)
			}
			if got.Vendor != c.vendor || got.Family != c.family || got.Tier != c.tier {
				t.Errorf("Classify(%q) = %+v, want vendor=%s family=%s tier=%s", c.id, got, c.vendor, c.family, c.tier)
			}
			if got.AutoRouted != c.autoRoll {
				t.Errorf("Classify(%q) AutoRouted=%v, want %v", c.id, got.AutoRouted, c.autoRoll)
			}
		})
	}
}

func TestReclaim(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	d := func(days int) time.Time { return now.AddDate(0, 0, -days) }
	seats := []ghclient.CopilotSeat{
		// never activated, assigned 40d ago (> neverDays=30) → priority 1
		{Org: "o1", Login: "never-dev", PlanType: "business", CreatedAt: d(40)},
		// dormant: last activity 90d ago (>= dormantDays=60) → priority 3
		{Org: "o1", Login: "dormant-dev", PlanType: "business", CreatedAt: d(200), LastActivityAt: d(90)},
		// duplicate holder across orgs; keep the most-recently-active (o2)
		{Org: "o1", Login: "dup", PlanType: "enterprise", CreatedAt: d(100), LastActivityAt: d(10)},
		{Org: "o2", Login: "dup", PlanType: "business", CreatedAt: d(50), LastActivityAt: d(5)},
		// active → never proposed
		{Org: "o1", Login: "active-dev", PlanType: "business", CreatedAt: d(100), LastActivityAt: d(2)},
		// never activated but exempted by keep(); still counted in KPIs
		{Org: "o1", Login: "vip", PlanType: "enterprise", CreatedAt: d(40)},
	}
	keep := func(login string) bool { return login == "vip" }

	rows, kpi := Reclaim(seats, now, 30, 60, keep)

	if kpi.Licensed != 6 {
		t.Errorf("Licensed = %d, want 6", kpi.Licensed)
	}
	if kpi.NeverActivated != 2 { // never-dev + vip (kept still counts)
		t.Errorf("NeverActivated = %d, want 2", kpi.NeverActivated)
	}
	if kpi.Dormant != 1 {
		t.Errorf("Dormant = %d, want 1", kpi.Dormant)
	}
	if kpi.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", kpi.Duplicates)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3: %+v", len(rows), rows)
	}
	// Sorted by priority: never(1), duplicate(2), dormant(3).
	if rows[0].Login != "never-dev" || rows[0].Priority != 1 {
		t.Errorf("row0 = %+v, want never-dev priority 1", rows[0])
	}
	if rows[1].Login != "dup" || rows[1].Priority != 2 || rows[1].RevokeOrg != "o1" || rows[1].KeptOrg != "o2" {
		t.Errorf("row1 = %+v, want dup revoke o1 kept o2 priority 2", rows[1])
	}
	if rows[2].Login != "dormant-dev" || rows[2].Priority != 3 {
		t.Errorf("row2 = %+v, want dormant-dev priority 3", rows[2])
	}
	if rows[0].DaysSinceActivity != -1 {
		t.Errorf("never-activated DaysSinceActivity = %d, want -1", rows[0].DaysSinceActivity)
	}
	// vip must never appear as a reclaim proposal.
	for _, r := range rows {
		if r.Login == "vip" {
			t.Errorf("kept user vip appeared in reclaim rows")
		}
	}
}

func TestReclaimDisabledWindows(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	seats := []ghclient.CopilotSeat{
		{Org: "o1", Login: "never-dev", PlanType: "business", CreatedAt: now.AddDate(0, 0, -40)},
		{Org: "o1", Login: "old-dev", PlanType: "business", CreatedAt: now.AddDate(0, 0, -200), LastActivityAt: now.AddDate(0, 0, -90)},
	}
	// neverDays=0 and dormantDays=0 disable those classes entirely.
	rows, kpi := Reclaim(seats, now, 0, 0, nil)
	if len(rows) != 0 {
		t.Errorf("rows = %d, want 0 when windows disabled: %+v", len(rows), rows)
	}
	// KPIs still reflect the raw state (never counts regardless of window).
	if kpi.NeverActivated != 1 {
		t.Errorf("NeverActivated = %d, want 1", kpi.NeverActivated)
	}
	if kpi.Dormant != 0 { // dormant requires dormantDays > 0
		t.Errorf("Dormant = %d, want 0", kpi.Dormant)
	}
}

func TestEconomics(t *testing.T) {
	days := []ghclient.MetricsDay{{
		Date: "2026-08-16",
		Models: []ghclient.ModelUsage{
			{ID: "gpt-4.1", Acceptances: 100, Suggestions: 400, LinesAccepted: 500},
			{ID: "claude-sonnet-4.5", Acceptances: 200, Suggestions: 500, LinesAccepted: 900},
			{ID: "auto", Acceptances: 50, Suggestions: 100},
			{ID: "experimental-x1", Acceptances: 10, Suggestions: 20},
		},
	}}
	billing := []ghclient.BillingUsageItem{
		{Product: "copilot", Model: "", NetAmountUSD: 100},                 // seat spend, no model
		{Product: "copilot", Model: "claude-sonnet-4.5", NetAmountUSD: 60}, // premium
		{Product: "copilot", Model: "gpt-4.1", NetAmountUSD: 40},           // premium
		{Product: "actions", Model: "", NetAmountUSD: 20},                  // non-copilot
	}

	models, kpi := Economics(days, billing)

	if !approx(kpi.TotalUSD, 220) {
		t.Errorf("TotalUSD = %.2f, want 220", kpi.TotalUSD)
	}
	if !approx(kpi.CopilotUSD, 200) {
		t.Errorf("CopilotUSD = %.2f, want 200", kpi.CopilotUSD)
	}
	if !approx(kpi.PremiumRequestUSD, 100) {
		t.Errorf("PremiumRequestUSD = %.2f, want 100", kpi.PremiumRequestUSD)
	}
	if !approx(kpi.PremiumSharePct, 50) {
		t.Errorf("PremiumSharePct = %.2f, want 50", kpi.PremiumSharePct)
	}
	// 360 total acceptances, 200 Copilot spend → ~0.5556/acceptance.
	if !approx(kpi.CostPerAcceptanceUSD, 200.0/360.0) {
		t.Errorf("CostPerAcceptanceUSD = %.4f, want %.4f", kpi.CostPerAcceptanceUSD, 200.0/360.0)
	}
	if !approx(kpi.AutoRoutedActivityPct, 100*50.0/360.0) {
		t.Errorf("AutoRoutedActivityPct = %.2f, want %.2f", kpi.AutoRoutedActivityPct, 100*50.0/360.0)
	}

	byFamily := map[string]ModelEconomics{}
	for _, m := range models {
		byFamily[m.Family] = m
	}
	claude := byFamily["Claude Sonnet"]
	if !approx(claude.CostUSD, 60) || !approx(claude.CostPerAcceptance, 0.3) {
		t.Errorf("Claude Sonnet = %+v, want cost 60 cpa 0.3", claude)
	}
	gpt := byFamily["GPT-4.x"]
	if !approx(gpt.CostUSD, 40) || !approx(gpt.CostPerAcceptance, 0.4) {
		t.Errorf("GPT-4.x = %+v, want cost 40 cpa 0.4", gpt)
	}
	// Auto-routed has activity but no attributed model spend.
	auto := byFamily["Auto-routed"]
	if !auto.AutoRouted || auto.CostPerAcceptance != -1 {
		t.Errorf("Auto-routed = %+v, want AutoRouted true cpa -1", auto)
	}
	// Unmapped model is surfaced, not dropped.
	exp, ok := byFamily["experimental-x1"]
	if !ok || !exp.Unmapped {
		t.Errorf("experimental-x1 should be surfaced as unmapped, got %+v (present=%v)", exp, ok)
	}
	// Highest spend sorts first.
	if models[0].Family != "Claude Sonnet" {
		t.Errorf("models[0] = %s, want Claude Sonnet (highest cost)", models[0].Family)
	}
}

func TestEconomicsNoData(t *testing.T) {
	models, kpi := Economics(nil, nil)
	if len(models) != 0 {
		t.Errorf("models = %d, want 0", len(models))
	}
	if kpi.CostPerAcceptanceUSD != -1 {
		t.Errorf("CostPerAcceptanceUSD = %.2f, want -1 (unknown)", kpi.CostPerAcceptanceUSD)
	}
}

func TestComputeROI(t *testing.T) {
	a := ROIAssumptions{HourlyRateUSD: 90, MinutesSavedPerAcceptance: 2}
	r := ComputeROI(a, 300, 100)
	if !approx(r.HoursSaved, 10) {
		t.Errorf("HoursSaved = %.2f, want 10", r.HoursSaved)
	}
	if !approx(r.ValueUSD, 900) {
		t.Errorf("ValueUSD = %.2f, want 900", r.ValueUSD)
	}
	if !approx(r.Payback, 9) {
		t.Errorf("Payback = %.2f, want 9", r.Payback)
	}
	if r.Assumptions != a {
		t.Errorf("assumptions not carried through: %+v", r.Assumptions)
	}
	// No measured spend → payback unknown, not divide-by-zero.
	if z := ComputeROI(a, 300, 0); z.Payback != -1 {
		t.Errorf("Payback with zero spend = %.2f, want -1", z.Payback)
	}
}
