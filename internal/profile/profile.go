// Package profile provides named, reusable rule selections for assessments.
package profile

import (
	"sort"

	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// Profile describes a named selection of rules.
//
// IDs is optional; when set, only the listed rule IDs are eligible (a curated
// set). Domains is optional; when empty, rules from every domain are eligible.
// MinSeverity is optional; when empty, rules of every severity are eligible.
// Keeping the profile data declarative makes adding future profiles a small
// registry-only change.
type Profile struct {
	Name        string
	Description string
	IDs         []string
	Domains     []rules.Domain
	MinSeverity rules.Severity
}

var registry = map[string]Profile{
	"baseline": {
		Name:        "baseline",
		Description: "All registered rules.",
	},
	"high-security": {
		Name:        "high-security",
		Description: "Only critical and high severity rules.",
		MinSeverity: rules.SeverityHigh,
	},
	"security-only": {
		Name:        "security-only",
		Description: "Only rules in the security domain.",
		Domains:     []rules.Domain{rules.DomainSecurity},
	},
	"onboarding": {
		Name:        "onboarding",
		Description: "Day-one checks from the enterprise onboarding guide.",
		IDs: []string{
			"ENT-01", "ENT-02", "ORG-01", "TEAM-01",
			"SEC-01", "SEC-02", "SEC-03", "POL-02", "REPO-02", "AUTO-01",
		},
	},
	"compliance": {
		Name:        "compliance",
		Description: "Security and policy rules for audit evidence.",
		Domains:     []rules.Domain{rules.DomainSecurity, rules.DomainPolicies},
	},
}

// Get returns a copy of a built-in profile by name.
func Get(name string) (*Profile, bool) {
	p, ok := registry[name]
	if !ok {
		return nil, false
	}
	p.IDs = append([]string(nil), p.IDs...)
	p.Domains = append([]rules.Domain(nil), p.Domains...)
	return &p, true
}

// Names returns all built-in profile names in deterministic order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Filter returns the subset of all rules that match the profile.
func (p *Profile) Filter(all []rules.Rule) []rules.Rule {
	if p == nil {
		return nil
	}
	out := make([]rules.Rule, 0, len(all))
	for _, r := range all {
		if r == nil {
			continue
		}
		if p.matches(r.Meta()) {
			out = append(out, r)
		}
	}
	return out
}

func (p *Profile) matches(m rules.Meta) bool {
	if len(p.IDs) > 0 && !containsID(p.IDs, m.ID) {
		return false
	}
	if len(p.Domains) > 0 && !containsDomain(p.Domains, m.Domain) {
		return false
	}
	if p.MinSeverity != "" && !severityAtLeast(m.Severity, p.MinSeverity) {
		return false
	}
	return true
}

func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func containsDomain(domains []rules.Domain, d rules.Domain) bool {
	for _, domain := range domains {
		if domain == d {
			return true
		}
	}
	return false
}

func severityAtLeast(actual, minimum rules.Severity) bool {
	actualRank, actualOK := severityRank(actual)
	minimumRank, minimumOK := severityRank(minimum)
	return actualOK && minimumOK && actualRank >= minimumRank
}

func severityRank(s rules.Severity) (int, bool) {
	switch s {
	case rules.SeverityCritical:
		return 5, true
	case rules.SeverityHigh:
		return 4, true
	case rules.SeverityMedium:
		return 3, true
	case rules.SeverityLow:
		return 2, true
	case rules.SeverityInfo:
		return 1, true
	default:
		return 0, false
	}
}
