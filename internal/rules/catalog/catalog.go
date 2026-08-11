// Package catalog registers the GitHub Enterprise best-practice rules.
// Importing this package (for side effects) populates the rules registry.
package catalog

import (
	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

const docsBase = "https://docs.github.com/en/enterprise-cloud@latest"

// Load is a no-op that exists so callers can force-import this package to
// trigger the init() registrations in each catalog file.
func Load() {}

// skipOnGHES returns a skipped result (excluded from the score) when the
// target is a GitHub Enterprise Server installation and the rule depends on a
// cloud-only feature.
func skipOnGHES(m rules.Meta, cfg *config.Config, feature string) (rules.Result, bool) {
	if !cfg.TargetGHES {
		return rules.Result{}, false
	}
	return rules.Result{Meta: m, Status: rules.StatusSkipped,
		Detail: feature + " is not available on GitHub Enterprise Server; skipped."}, true
}
