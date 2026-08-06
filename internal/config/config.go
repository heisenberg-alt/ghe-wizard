// Package config holds runtime configuration for the GHE best-practices wizard.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config controls how the wizard connects to GitHub and how strict the checks are.
type Config struct {
	// Enterprise is the enterprise account slug (e.g. "octo-enterprise").
	Enterprise string `json:"enterprise"`
	// Token is a GitHub PAT with enterprise admin scopes. Prefer env var over file.
	Token string `json:"-"`
	// BaseURL is the REST API base. Defaults to public GitHub cloud.
	BaseURL string `json:"base_url"`
	// GraphQLURL is the GraphQL endpoint.
	GraphQLURL string `json:"graphql_url"`

	// Thresholds tune assessment rules.
	Thresholds Thresholds `json:"thresholds"`

	// DryRun, when true, makes remediations describe changes without applying them.
	DryRun bool `json:"dry_run"`
	// MaxOrgs caps how many organizations are scanned (0 = no cap).
	MaxOrgs int `json:"max_orgs"`
	// Concurrency bounds parallel per-organization API calls (0 = default).
	Concurrency int `json:"concurrency"`
}

// Thresholds are tunable limits used by rules.
type Thresholds struct {
	MaxEnterpriseOwners int `json:"max_enterprise_owners"`
	StaleOrgDays        int `json:"stale_org_days"`
}

// DefaultThresholds returns GitHub-guidance-aligned defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxEnterpriseOwners: 5,
		StaleOrgDays:        180,
	}
}

// Load builds a Config from a file (optional), environment variables and defaults.
// Precedence: explicit env vars override file values.
func Load(path string) (*Config, error) {
	cfg := &Config{
		BaseURL:    "https://api.github.com",
		GraphQLURL: "https://api.github.com/graphql",
		Thresholds: DefaultThresholds(),
	}

	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
	}

	if v := os.Getenv("GHE_ENTERPRISE"); v != "" {
		cfg.Enterprise = v
	}
	if v := firstEnv("GHE_TOKEN", "GITHUB_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("GHE_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("GHE_GRAPHQL_URL"); v != "" {
		cfg.GraphQLURL = v
	}

	if cfg.Thresholds.MaxEnterpriseOwners == 0 {
		cfg.Thresholds.MaxEnterpriseOwners = DefaultThresholds().MaxEnterpriseOwners
	}
	if cfg.Thresholds.StaleOrgDays == 0 {
		cfg.Thresholds.StaleOrgDays = DefaultThresholds().StaleOrgDays
	}

	return cfg, nil
}

// Validate ensures the minimum required fields are present.
func (c *Config) Validate() error {
	var missing []string
	if strings.TrimSpace(c.Enterprise) == "" {
		missing = append(missing, "enterprise slug (set --enterprise or GHE_ENTERPRISE)")
	}
	if strings.TrimSpace(c.Token) == "" {
		missing = append(missing, "token (set GHE_TOKEN or GITHUB_TOKEN)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, "; "))
	}
	return nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
