// Package profile provides named, reusable rule selections for assessments.
package profile

import (
	"sort"

	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// Profile describes a named selection of rules.
//
// Domains is optional; when empty, rules from every domain are eligible.
// MinSeverity is optional; when empty, rules of every severity are eligible.
// Keeping the profile data declarative makes adding future profiles a small
// registry-only change.
type Profile struct {
	Name        string
	Description string
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
}

// Get returns a copy of a built-in profile by name.
func Get(name string) (*Profile, bool) {
	p, ok := registry[name]
	if !ok {
		return nil, false
	}
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
	if len(p.Domains) > 0 && !containsDomain(p.Domains, m.Domain) {
		return false
	}
	if p.MinSeverity != "" && !severityAtLeast(m.Severity, p.MinSeverity) {
		return false
	}
	return true
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
