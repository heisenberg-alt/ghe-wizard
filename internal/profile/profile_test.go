package profile

import (
	"context"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

type stubRule struct {
	meta rules.Meta
}

func (s stubRule) Meta() rules.Meta {
	return s.meta
}

func (s stubRule) Assess(context.Context, ghclient.GHAPI, *config.Config) rules.Result {
	return rules.Result{Meta: s.meta}
}

func (s stubRule) Remediate(context.Context, ghclient.GHAPI, *config.Config, bool) rules.RemediationResult {
	return rules.RemediationResult{RuleID: s.meta.ID}
}

func TestBaselineReturnsAllRules(t *testing.T) {
	all := testRules()
	p, ok := Get("baseline")
	if !ok {
		t.Fatal("baseline profile not found")
	}

	got := p.Filter(all)
	if len(got) != len(all) {
		t.Fatalf("baseline returned %d rules, want %d", len(got), len(all))
	}
}

func TestHighSecurityExcludesMediumAndLowRules(t *testing.T) {
	p, ok := Get("high-security")
	if !ok {
		t.Fatal("high-security profile not found")
	}

	got := p.Filter(testRules())
	if len(got) != 2 {
		t.Fatalf("high-security returned %d rules, want 2", len(got))
	}
	for _, r := range got {
		switch sev := r.Meta().Severity; sev {
		case rules.SeverityCritical, rules.SeverityHigh:
		default:
			t.Fatalf("high-security included severity %q", sev)
		}
	}
}

func TestSecurityOnlyReturnsOnlySecurityDomainRules(t *testing.T) {
	p, ok := Get("security-only")
	if !ok {
		t.Fatal("security-only profile not found")
	}

	got := p.Filter(testRules())
	if len(got) != 2 {
		t.Fatalf("security-only returned %d rules, want 2", len(got))
	}
	for _, r := range got {
		if domain := r.Meta().Domain; domain != rules.DomainSecurity {
			t.Fatalf("security-only included domain %q", domain)
		}
	}
}

func testRules() []rules.Rule {
	return []rules.Rule{
		stubRule{meta: rules.Meta{ID: "SEC-001", Domain: rules.DomainSecurity, Severity: rules.SeverityCritical}},
		stubRule{meta: rules.Meta{ID: "ENT-001", Domain: rules.DomainEnterprise, Severity: rules.SeverityHigh}},
		stubRule{meta: rules.Meta{ID: "SEC-002", Domain: rules.DomainSecurity, Severity: rules.SeverityMedium}},
		stubRule{meta: rules.Meta{ID: "REP-001", Domain: rules.DomainRepos, Severity: rules.SeverityLow}},
	}
}
