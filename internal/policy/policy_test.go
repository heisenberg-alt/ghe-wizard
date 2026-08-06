package policy

import (
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func sc(results ...rules.Result) *engine.Scorecard {
	s := &engine.Scorecard{Enterprise: "acme", GeneratedAt: time.Now(), Results: results}
	engine.Recompute(s)
	return s
}

func r(id string, st rules.Status) rules.Result {
	return rules.Result{Meta: rules.Meta{ID: id, Domain: rules.DomainSecurity, Severity: rules.SeverityHigh}, Status: st}
}

func TestFilterRules_Disabled(t *testing.T) {
	mk := func(id string) rules.Rule {
		return rules.Base{M: rules.Meta{ID: id, Domain: rules.DomainSecurity}}
	}
	all := []rules.Rule{mk("SEC-01"), mk("SEC-02"), mk("SEC-03")}
	p := &Policy{DisabledRules: []string{"SEC-02"}}
	p.index()
	got := p.FilterRules(all)
	if len(got) != 2 {
		t.Fatalf("expected 2 rules after filtering, got %d", len(got))
	}
	for _, r := range got {
		if r.Meta().ID == "SEC-02" {
			t.Fatal("SEC-02 should have been filtered out")
		}
	}
}

func TestApply_Waiver(t *testing.T) {
	p := &Policy{Waivers: []Waiver{{Rule: "SEC-03", Reason: "accepted", Owner: "sec", Expires: "2999-01-01"}}}
	p.index()
	s := sc(r("SEC-01", rules.StatusPass), r("SEC-03", rules.StatusFail))
	before := s.Summary.Score
	n := p.Apply(s)
	if n != 1 {
		t.Fatalf("expected 1 waiver applied, got %d", n)
	}
	// SEC-03 should now be waived and excluded from score -> score improves.
	var found bool
	for _, res := range s.Results {
		if res.Meta.ID == "SEC-03" {
			found = res.Status == rules.StatusWaived
		}
	}
	if !found {
		t.Fatal("SEC-03 not marked waived")
	}
	if s.Summary.Score <= before {
		t.Fatalf("score should improve after waiver: before=%d after=%d", before, s.Summary.Score)
	}
}

func TestApply_ExpiredWaiverIgnored(t *testing.T) {
	p := &Policy{Waivers: []Waiver{{Rule: "SEC-03", Expires: "2000-01-01"}}}
	p.index()
	s := sc(r("SEC-03", rules.StatusFail))
	if n := p.Apply(s); n != 0 {
		t.Fatalf("expired waiver should not apply, got %d", n)
	}
}

func TestApply_SeverityOverride(t *testing.T) {
	p := &Policy{SeverityOverrides: map[string]string{"SEC-03": "low"}}
	p.index()
	s := sc(r("SEC-03", rules.StatusFail))
	p.Apply(s)
	if s.Results[0].Meta.Severity != rules.SeverityLow {
		t.Fatalf("severity override not applied: %s", s.Results[0].Meta.Severity)
	}
}

func TestWaiverExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if (Waiver{Expires: "2026-05-01"}).Expired(now) != true {
		t.Error("past date should be expired")
	}
	if (Waiver{Expires: "2027-01-01"}).Expired(now) != false {
		t.Error("future date should not be expired")
	}
	if (Waiver{}).Expired(now) != false {
		t.Error("empty expiry should never expire")
	}
}
