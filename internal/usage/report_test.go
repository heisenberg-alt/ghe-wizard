package usage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
)

func demoCfg() *config.Config {
	return &config.Config{
		Enterprise: "acme-corp",
		Usage:      config.UsageConfig{NeverActivatedDays: 30, DormantDays: 60},
		ROI:        config.ROIConfig{HourlyRateUSD: 90, MinutesSavedPerAcceptance: 2},
	}
}

// TestCollectDemo runs the full report pipeline through the caching wrapper,
// exactly as the CLI and /api/usage do.
func TestCollectDemo(t *testing.T) {
	api := ghclient.NewCached(ghclient.NewDemoAPI(), 4)
	rep, err := Collect(context.Background(), api, demoCfg())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Seats.Licensed != 8 {
		t.Errorf("Licensed = %d, want 8", rep.Seats.Licensed)
	}
	if rep.Days != 7 {
		t.Errorf("Days = %d, want 7", rep.Days)
	}
	byPriority := map[int]int{}
	for _, row := range rep.Reclaim {
		byPriority[row.Priority]++
		if row.Login == "bob" && row.RevokeOrg != "acme-platform" {
			t.Errorf("duplicate bob: revoke %s, want acme-platform (least recently active)", row.RevokeOrg)
		}
	}
	if byPriority[1] == 0 || byPriority[2] == 0 || byPriority[3] == 0 {
		t.Errorf("reclaim classes = %v, want all three priorities present", byPriority)
	}
	if rep.ROI.Assumptions.HourlyRateUSD != 90 || rep.ROI.Assumptions.MinutesSavedPerAcceptance != 2 {
		t.Errorf("ROI assumptions not carried: %+v", rep.ROI.Assumptions)
	}
	if rep.ROI.Acceptances == 0 || rep.ROI.Payback <= 0 {
		t.Errorf("ROI = %+v, want measured acceptances and a positive payback", rep.ROI)
	}
	found := false
	for _, n := range rep.Notes {
		if strings.Contains(n, "experimental-x1") {
			found = true
		}
	}
	if !found {
		t.Errorf("Notes = %v, want the unmapped model surfaced", rep.Notes)
	}
}

func TestCollectHonorsKeepUsers(t *testing.T) {
	cfg := demoCfg()
	cfg.Usage.KeepUsers = []string{"never-activated-dev"}
	rep, err := Collect(context.Background(), ghclient.NewDemoAPI(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rep.Reclaim {
		if row.Login == "never-activated-dev" {
			t.Errorf("kept user proposed for reclaim: %+v", row)
		}
	}
	// The KPI still counts the kept never-activated seat.
	if rep.Seats.NeverActivated == 0 {
		t.Error("NeverActivated KPI should still count kept users")
	}
}

func TestCollectWithoutUsageSurface(t *testing.T) {
	if _, err := Collect(context.Background(), bareAPI{}, demoCfg()); err == nil {
		t.Fatal("expected an error for a client without the usage read surface")
	}
}

// bareAPI implements GHAPI (via embedding, all methods panic if called) but
// not UsageAPI and not Unwrap, so Collect must refuse it up front.
type bareAPI struct{ ghclient.GHAPI }

func TestReportRendering(t *testing.T) {
	rep, err := Collect(context.Background(), ghclient.NewDemoAPI(), demoCfg())
	if err != nil {
		t.Fatal(err)
	}
	md := rep.Markdown()
	for _, want := range []string{"## Seats", "## Spend", "## Model economics", "## ROI (explicit assumptions)", "--allow-destructive"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown missing %q", want)
		}
	}
	csv := rep.ReclaimCSV()
	if !strings.HasPrefix(csv, "priority,login,revoke_org,revoke_tier,kept_org,kept_tier,days_since_activity,reason\n") {
		t.Errorf("ReclaimCSV header wrong: %q", strings.SplitN(csv, "\n", 2)[0])
	}
	if len(strings.Split(strings.TrimSpace(csv), "\n")) != len(rep.Reclaim)+1 {
		t.Errorf("ReclaimCSV rows = %d lines, want %d reclaim rows + header", len(strings.Split(strings.TrimSpace(csv), "\n")), len(rep.Reclaim))
	}
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("JSON round-trip: %v", err)
	}
	if back.Seats != rep.Seats {
		t.Errorf("JSON round-trip seats = %+v, want %+v", back.Seats, rep.Seats)
	}
}
