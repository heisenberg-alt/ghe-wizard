package store

import (
	"context"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func scorecard(results ...rules.Result) *engine.Scorecard {
	sc := &engine.Scorecard{Enterprise: "acme", GeneratedAt: time.Now().UTC(), Results: results}
	engine.Recompute(sc)
	return sc
}

func res(id string, st rules.Status) rules.Result {
	return rules.Result{Meta: rules.Meta{ID: id, Domain: rules.DomainSecurity, Severity: rules.SeverityHigh}, Status: st}
}

func TestSaveAndListRuns(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	sc := scorecard(res("SEC-01", rules.StatusPass), res("SEC-03", rules.StatusFail))
	run, err := st.SaveRun(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == 0 {
		t.Fatal("expected non-zero run id")
	}
	runs, err := st.Runs(ctx, "acme", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Fail != 1 || runs[0].Pass != 1 {
		t.Fatalf("unexpected runs: %+v", runs)
	}
}

func TestDrift(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	// Run 1: SEC-03 failing.
	sc1 := scorecard(res("SEC-01", rules.StatusPass), res("SEC-03", rules.StatusFail))
	if _, err := st.SaveRun(ctx, sc1); err != nil {
		t.Fatal(err)
	}

	// Run 2: SEC-03 fixed, SEC-01 regressed to fail.
	sc2 := scorecard(res("SEC-01", rules.StatusFail), res("SEC-03", rules.StatusPass))
	run2, err := st.SaveRun(ctx, sc2)
	if err != nil {
		t.Fatal(err)
	}
	drift, err := st.DriftAgainstPrevious(ctx, run2.ID, sc2)
	if err != nil {
		t.Fatal(err)
	}
	if drift == nil {
		t.Fatal("expected drift")
	}
	if !contains(drift.NewlyFixed, "SEC-03") {
		t.Errorf("SEC-03 should be newly fixed: %+v", drift)
	}
	if !contains(drift.NewlyFailing, "SEC-01") || !contains(drift.Regressed, "SEC-01") {
		t.Errorf("SEC-01 should be newly failing + regressed: %+v", drift)
	}
}

func TestDrift_NoPrevious(t *testing.T) {
	st, _ := Open(":memory:")
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	sc := scorecard(res("SEC-01", rules.StatusPass))
	run, _ := st.SaveRun(ctx, sc)
	drift, err := st.DriftAgainstPrevious(ctx, run.ID, sc)
	if err != nil {
		t.Fatal(err)
	}
	if drift != nil {
		t.Fatalf("expected nil drift for first run, got %+v", drift)
	}
}

func TestSaveAndReadRemediations(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	results := []rules.RemediationResult{
		{RuleID: "SEC-03", Applied: true, Changes: []string{"require 2FA for org a"}},
		{RuleID: "POL-02", DryRun: true, Changes: []string{"create ruleset"}, Errors: []string{"boom"}},
	}
	if err := st.SaveRemediations(ctx, "acme", results); err != nil {
		t.Fatal(err)
	}
	logs, err := st.Remediations(ctx, "acme", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 remediation logs, got %d", len(logs))
	}
	byRule := map[string]RemediationSummary{}
	for _, l := range logs {
		byRule[l.RuleID] = l
	}
	sec := byRule["SEC-03"]
	if !sec.Applied || sec.DryRun || len(sec.Changes) != 1 || sec.Changes[0] != "require 2FA for org a" {
		t.Fatalf("SEC-03 round-trip mismatch: %+v", sec)
	}
	pol := byRule["POL-02"]
	if pol.Applied || !pol.DryRun || len(pol.Errors) != 1 || pol.Errors[0] != "boom" {
		t.Fatalf("POL-02 round-trip mismatch: %+v", pol)
	}
	// Scoped by enterprise.
	other, err := st.Remediations(ctx, "other", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("expected no logs for other enterprise, got %d", len(other))
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
