// Package policy implements config-as-code for ghe-wizard: a declarative YAML
// file that can disable rules, override severities, tune thresholds, and record
// compliance waivers (accepted risks) with an owner, reason, and expiry.
package policy

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// Policy is the parsed config-as-code document.
type Policy struct {
	// DisabledRules are rule IDs that should not run at all.
	DisabledRules []string `yaml:"disabled_rules"`
	// SeverityOverrides maps a rule ID to a new severity.
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	// Thresholds tune assessment limits (0 = keep default).
	Thresholds struct {
		MaxEnterpriseOwners int `yaml:"max_enterprise_owners"`
		StaleOrgDays        int `yaml:"stale_org_days"`
	} `yaml:"thresholds"`
	// Waivers accept specific findings as known/accepted risks.
	Waivers []Waiver `yaml:"waivers"`

	disabled map[string]bool
	waiverBy map[string]Waiver
}

// Waiver records an accepted risk for a rule.
type Waiver struct {
	Rule    string `yaml:"rule"`
	Reason  string `yaml:"reason"`
	Owner   string `yaml:"owner"`
	Expires string `yaml:"expires"` // YYYY-MM-DD, optional
}

// Expired reports whether the waiver's expiry date has passed.
func (w Waiver) Expired(now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", w.Expires)
	if err != nil {
		return false // unpar.seable date -> treat as non-expiring, but see Validate
	}
	return now.After(t.Add(24 * time.Hour))
}

// Load reads and indexes a policy file. A blank path returns an empty policy.
func Load(path string) (*Policy, error) {
	p := &Policy{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy %q: %w", path, err)
		}
		if err := yaml.Unmarshal(b, p); err != nil {
			return nil, fmt.Errorf("parse policy %q: %w", path, err)
		}
	}
	p.index()
	return p, nil
}

func (p *Policy) index() {
	p.disabled = map[string]bool{}
	for _, id := range p.DisabledRules {
		p.disabled[id] = true
	}
	p.waiverBy = map[string]Waiver{}
	for _, w := range p.Waivers {
		if w.Rule != "" {
			p.waiverBy[w.Rule] = w
		}
	}
}

// FilterRules removes disabled rules from the set to run.
func (p *Policy) FilterRules(all []rules.Rule) []rules.Rule {
	if len(p.disabled) == 0 {
		return all
	}
	out := make([]rules.Rule, 0, len(all))
	for _, r := range all {
		if !p.disabled[r.Meta().ID] {
			out = append(out, r)
		}
	}
	return out
}

// ApplyThresholds copies any non-zero threshold overrides onto a target.
func (p *Policy) ApplyThresholds(maxOwners, staleDays *int) {
	if p.Thresholds.MaxEnterpriseOwners > 0 && maxOwners != nil {
		*maxOwners = p.Thresholds.MaxEnterpriseOwners
	}
	if p.Thresholds.StaleOrgDays > 0 && staleDays != nil {
		*staleDays = p.Thresholds.StaleOrgDays
	}
}

// Apply mutates a scorecard in place: applies severity overrides, converts
// waived failing/warning findings to StatusWaived (excluded from the score),
// and recomputes the summary. It returns the number of findings waived.
func (p *Policy) Apply(sc *engine.Scorecard) int {
	now := time.Now()
	waived := 0
	for i := range sc.Results {
		r := &sc.Results[i]
		if ov, ok := p.SeverityOverrides[r.Meta.ID]; ok && ov != "" {
			r.Meta.Severity = rules.Severity(ov)
		}
		if w, ok := p.waiverBy[r.Meta.ID]; ok && !w.Expired(now) {
			if r.Status == rules.StatusFail || r.Status == rules.StatusWarn {
				r.Status = rules.StatusWaived
				if w.Reason != "" {
					r.Detail = fmt.Sprintf("%s [waived: %s]", r.Detail, w.Reason)
				} else {
					r.Detail = r.Detail + " [waived]"
				}
				waived++
			}
		}
	}
	engine.Recompute(sc)
	return waived
}

// Validate returns human-readable warnings about the policy (e.g. expired
// waivers or unparseable dates) without failing.
func (p *Policy) Validate(known map[string]bool) []string {
	var warns []string
	now := time.Now()
	for _, w := range p.Waivers {
		if w.Rule == "" {
			warns = append(warns, "waiver with empty 'rule' ignored")
			continue
		}
		if known != nil && !known[w.Rule] {
			warns = append(warns, fmt.Sprintf("waiver references unknown rule %q", w.Rule))
		}
		if w.Expires != "" {
			if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
				warns = append(warns, fmt.Sprintf("waiver %q has invalid expires %q (use YYYY-MM-DD)", w.Rule, w.Expires))
			} else if w.Expired(now) {
				warns = append(warns, fmt.Sprintf("waiver %q expired on %s", w.Rule, w.Expires))
			}
		}
	}
	for id := range p.disabled {
		if known != nil && !known[id] {
			warns = append(warns, fmt.Sprintf("disabled_rules references unknown rule %q", id))
		}
	}
	return warns
}
