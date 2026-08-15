// Package rules defines the best-practice check interface and shared types
// consumed by the engine, catalog, reporters, CLI and web server.
package rules

import (
	"context"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
)

// Status is the outcome of assessing a rule.
type Status string

const (
	StatusPass    Status = "pass"    // best practice satisfied
	StatusFail    Status = "fail"    // best practice violated; remediation may apply
	StatusWarn    Status = "warn"    // partial / needs attention
	StatusManual  Status = "manual"  // cannot be determined via API; human review
	StatusError   Status = "error"   // assessment itself failed (auth, network)
	StatusSkipped Status = "skipped" // not applicable to this enterprise
	StatusWaived  Status = "waived"  // failing but accepted via a policy waiver
)

// Severity ranks the importance of a failing rule.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Domain groups related rules.
type Domain string

const (
	DomainEnterprise  Domain = "enterprise"
	DomainOrgs        Domain = "organizations"
	DomainTeams       Domain = "teams"
	DomainRepos       Domain = "repositories"
	DomainPolicies    Domain = "policies"
	DomainSecurity    Domain = "security"
	DomainIdentity    Domain = "identity"
	DomainInnersource Domain = "innersource"
	DomainAutomation  Domain = "automation"
	DomainBilling     Domain = "billing"
)

// Meta describes a rule.
type Meta struct {
	ID         string   `json:"id"`
	Domain     Domain   `json:"domain"`
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	Rationale  string   `json:"rationale"`
	DocsURL    string   `json:"docs_url"`
	Remediable bool     `json:"remediable"`
	// Destructive marks remediations that remove people, access or seats
	// rather than flipping settings. They are excluded from bulk apply and
	// from the dashboard, and run only with an explicit rule selection plus
	// --allow-destructive on the CLI.
	Destructive bool `json:"destructive,omitempty"`
}

// Result is the outcome of assessing a rule.
type Result struct {
	Meta     Meta   `json:"meta"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Evidence any    `json:"evidence,omitempty"`
	// Remediation summarises what apply-mode would change, when the rule fails.
	Remediation string `json:"remediation,omitempty"`
}

// RemediationResult reports the effect of running a rule's remediation.
type RemediationResult struct {
	RuleID  string   `json:"rule_id"`
	Applied bool     `json:"applied"`
	DryRun  bool     `json:"dry_run"`
	Changes []string `json:"changes"`
	Errors  []string `json:"errors,omitempty"`
}

// Rule is a single best-practice check with an optional remediation.
type Rule interface {
	Meta() Meta
	Assess(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) Result
	// Remediate applies (or, when dryRun, describes) the fix for a failing rule.
	Remediate(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) RemediationResult
}

// --- Registry -------------------------------------------------------------

var registry []Rule

// Register adds a rule to the global catalog. Called from catalog init().
func Register(r Rule) { registry = append(registry, r) }

// All returns every registered rule.
func All() []Rule {
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// ByID returns the rule with the given ID, or nil.
func ByID(id string) Rule {
	for _, r := range registry {
		if r.Meta().ID == id {
			return r
		}
	}
	return nil
}
