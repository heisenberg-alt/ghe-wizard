// Package catalog registers the GitHub Enterprise best-practice rules.
// Importing this package (for side effects) populates the rules registry.
package catalog

const docsBase = "https://docs.github.com/en/enterprise-cloud@latest"

// Load is a no-op that exists so callers can force-import this package to
// trigger the init() registrations in each catalog file.
func Load() {}
