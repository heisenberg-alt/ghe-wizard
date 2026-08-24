package catalog_test

import (
	"context"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// usageFake adds the UsageAPI read surface on top of fakeAPI (which already
// covers GHAPI + WriteAPI, including RevokeCopilotSeats). Embedding means the
// SEAT rules see a client that both reads seats and can revoke them through
// the Cached wrapper.
type usageFake struct {
	*fakeAPI
	seatsByOrg map[string][]ghclient.CopilotSeat
}

func (u *usageFake) CopilotSeats(ctx context.Context, org string) ([]ghclient.CopilotSeat, ghclient.Capability, error) {
	return u.seatsByOrg[org], ghclient.Capability{Determined: true}, nil
}
func (u *usageFake) CopilotMetricsDays(ctx context.Context, slug string) ([]ghclient.MetricsDay, ghclient.Capability, error) {
	return nil, ghclient.Capability{Determined: false, Reason: "n/a"}, nil
}
func (u *usageFake) EnterpriseBillingUsage(ctx context.Context, slug string) ([]ghclient.BillingUsageItem, ghclient.Capability, error) {
	return nil, ghclient.Capability{Determined: false, Reason: "n/a"}, nil
}

// seatFake builds two orgs whose seats exercise all three reclaim classes:
// a never-activated seat, a dormant seat, and a login duplicated across orgs.
func seatFake() *usageFake {
	now := time.Now()
	d := func(days int) time.Time { return now.AddDate(0, 0, -days) }
	base := &fakeAPI{orgs: []ghclient.Organization{{Login: "o1", ID: 1}, {Login: "o2", ID: 2}}}
	return &usageFake{
		fakeAPI: base,
		seatsByOrg: map[string][]ghclient.CopilotSeat{
			"o1": {
				{Org: "o1", Login: "never-dev", PlanType: "business", CreatedAt: d(40)},
				{Org: "o1", Login: "dormant-dev", PlanType: "business", CreatedAt: d(200), LastActivityAt: d(90)},
				{Org: "o1", Login: "dup", PlanType: "enterprise", CreatedAt: d(100), LastActivityAt: d(10)},
				{Org: "o1", Login: "active-dev", PlanType: "business", CreatedAt: d(100), LastActivityAt: d(2)},
			},
			"o2": {
				{Org: "o2", Login: "dup", PlanType: "business", CreatedAt: d(50), LastActivityAt: d(5)},
			},
		},
	}
}

func seatCfg() *config.Config {
	return &config.Config{
		Enterprise: "acme", Token: "x",
		Thresholds: config.DefaultThresholds(),
		Usage:      config.UsageConfig{NeverActivatedDays: 30, DormantDays: 60},
	}
}

// TestSeatRulesAreDestructive locks in the gating contract: SEAT remediations
// cancel seats and must be flagged destructive so bulk apply/wizard/dashboard
// exclude them.
func TestSeatRulesAreDestructive(t *testing.T) {
	for _, id := range []string{"SEAT-01", "SEAT-02", "SEAT-03"} {
		rl := rules.ByID(id)
		if rl == nil {
			t.Fatalf("%s not registered", id)
		}
		m := rl.Meta()
		if !m.Destructive {
			t.Errorf("%s must be Destructive", id)
		}
		if !m.Remediable {
			t.Errorf("%s must be Remediable", id)
		}
		if m.Domain != rules.DomainBilling {
			t.Errorf("%s domain = %s, want billing", id, m.Domain)
		}
	}
}

func TestSeatAssess(t *testing.T) {
	cases := []struct {
		id        string
		wantLabel string
	}{
		{"SEAT-01", "o1/never-dev"},
		{"SEAT-02", "o1/dormant-dev"},
		{"SEAT-03", "o1/dup"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			eng := engine.New(seatFake(), seatCfg())
			sc := eng.Assess(context.Background(), []rules.Rule{rules.ByID(tc.id)})
			if len(sc.Results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(sc.Results))
			}
			res := sc.Results[0]
			if res.Status != rules.StatusWarn {
				t.Fatalf("%s status = %s, want warn (%s)", tc.id, res.Status, res.Detail)
			}
			labels, ok := res.Evidence.([]string)
			if !ok {
				t.Fatalf("%s evidence = %T, want []string", tc.id, res.Evidence)
			}
			found := false
			for _, e := range labels {
				if e == tc.wantLabel {
					found = true
				}
			}
			if !found {
				t.Errorf("%s evidence = %v, want to contain %q", tc.id, labels, tc.wantLabel)
			}
		})
	}
}

func TestSeatRemediateDryRun(t *testing.T) {
	api := seatFake()
	eng := engine.New(api, seatCfg())
	rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID("SEAT-01")}, true)
	if len(rr) != 1 || len(rr[0].Changes) == 0 {
		t.Fatalf("dry-run should describe changes, got %+v", rr)
	}
	if rr[0].Applied {
		t.Error("dry-run must not apply")
	}
	if api.hasCall("RevokeCopilotSeats") {
		t.Errorf("dry-run must not revoke; calls: %v", api.calls)
	}
}

func TestSeatRemediateLiveRevokes(t *testing.T) {
	api := seatFake()
	eng := engine.New(api, seatCfg())
	rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID("SEAT-03")}, false)
	if len(rr) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rr))
	}
	if len(rr[0].Errors) > 0 {
		t.Fatalf("unexpected errors: %v", rr[0].Errors)
	}
	if !rr[0].Applied {
		t.Fatalf("expected applied; changes=%v", rr[0].Changes)
	}
	// The duplicate 'dup' keeps its most-active seat (o2) and is revoked from o1.
	if !api.hasCall("RevokeCopilotSeats o1 dup") {
		t.Errorf("expected revoke of dup in o1, got %v", api.calls)
	}
}

// TestSeatReadOnlyClientIsManual asserts that a client without the UsageAPI
// read surface degrades to a manual result rather than failing.
func TestSeatReadOnlyClientIsManual(t *testing.T) {
	eng := engine.New(failingFake(), seatCfg()) // fakeAPI has no CopilotSeats
	sc := eng.Assess(context.Background(), []rules.Rule{rules.ByID("SEAT-01")})
	if sc.Results[0].Status != rules.StatusManual {
		t.Fatalf("status = %s, want manual when seat data unavailable", sc.Results[0].Status)
	}
}
