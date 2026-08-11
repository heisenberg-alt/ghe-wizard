package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// demoOpts builds commonOpts for demo mode (no token, no preflight) with an
// optional policy file and profile name.
func demoOpts(policyPath, profileName string) *commonOpts {
	return &commonOpts{
		enterprise:  strPtr(""),
		server:      strPtr(""),
		cfgPath:     strPtr(""),
		policyPath:  strPtr(policyPath),
		profileName: strPtr(profileName),
		dbPath:      strPtr(""),
		demo:        boolPtr(true),
		noPreflight: boolPtr(false),
	}
}

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func findResult(sc *engine.Scorecard, id string) *rules.Result {
	for i := range sc.Results {
		if sc.Results[i].Meta.ID == id {
			return &sc.Results[i]
		}
	}
	return nil
}

func TestBuildAssessment_PolicyDisablesRule(t *testing.T) {
	pol := writePolicy(t, "disabled_rules:\n  - ORG-04\n")
	a, err := buildAssessment(demoOpts(pol, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.toRun) != len(rules.All())-1 {
		t.Fatalf("expected %d rules to run, got %d", len(rules.All())-1, len(a.toRun))
	}
	for _, r := range a.toRun {
		if r.Meta().ID == "ORG-04" {
			t.Fatal("ORG-04 is disabled by policy and must not run")
		}
	}
	sc := a.assessWithPolicy(context.Background())
	if findResult(sc, "ORG-04") != nil {
		t.Fatal("disabled rule must not appear in the scorecard")
	}
}

func TestAssessWithPolicy_WaiverExcludesFromRemediation(t *testing.T) {
	// ORG-04 fails in demo mode (permissive base permissions); waive it.
	pol := writePolicy(t, "waivers:\n  - rule: ORG-04\n    reason: accepted risk\n    owner: security\n")
	a, err := buildAssessment(demoOpts(pol, ""))
	if err != nil {
		t.Fatal(err)
	}
	sc := a.assessWithPolicy(context.Background())
	r := findResult(sc, "ORG-04")
	if r == nil || r.Status != rules.StatusWaived {
		t.Fatalf("ORG-04 expected waived, got %+v", r)
	}
	targets := engine.RemediableFailures(sc)
	if len(targets) == 0 {
		t.Fatal("demo data should still have other remediable failures")
	}
	for _, tr := range targets {
		if tr.Meta().ID == "ORG-04" {
			t.Fatal("waived rule must not be a remediation target")
		}
	}
}

func TestBuildAssessment_ProfileFilters(t *testing.T) {
	a, err := buildAssessment(demoOpts("", "security-only"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.toRun) == 0 {
		t.Fatal("expected security rules to run")
	}
	for _, r := range a.toRun {
		if r.Meta().Domain != rules.DomainSecurity {
			t.Fatalf("profile security-only leaked rule %s (%s)", r.Meta().ID, r.Meta().Domain)
		}
	}
}

func TestBuildAssessment_UnknownProfileErrors(t *testing.T) {
	if _, err := buildAssessment(demoOpts("", "no-such-profile")); err == nil {
		t.Fatal("expected an error for an unknown profile")
	}
}
