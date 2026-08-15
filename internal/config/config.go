// Package config holds runtime configuration for the GHE best-practices wizard.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	// Server optionally targets a GitHub host other than github.com: a GHES
	// hostname (e.g. "github.example.com") or a data-residency enterprise
	// ("acme.ghe.com"). DeriveEndpoints translates it into API endpoints.
	Server string `json:"server"`
	// TargetGHES and ServerVersion are detected at runtime (never persisted):
	// cloud-only rules are skipped when TargetGHES is true.
	TargetGHES    bool   `json:"-"`
	ServerVersion string `json:"-"`

	// AppID, AppInstallationID and AppPrivateKeyPath configure GitHub App
	// installation-token authentication as an alternative to a PAT.
	AppID             int64  `json:"app_id"`
	AppInstallationID int64  `json:"app_installation_id"`
	AppPrivateKeyPath string `json:"app_private_key_path"`
	// AppPrivateKey is inline PEM key material (env GHE_APP_PRIVATE_KEY only,
	// never from the config file); it wins over AppPrivateKeyPath.
	AppPrivateKey string `json:"-"`

	// Thresholds tune assessment rules.
	Thresholds Thresholds `json:"thresholds"`

	// Identity governs the identity rules (IDENT-*). Usually populated from
	// the policy file's identity: section.
	Identity IdentityConfig `json:"identity"`

	// MaxOrgs caps how many organizations are scanned (0 = no cap).
	MaxOrgs int `json:"max_orgs"`
	// MaxReposPerOrg bounds the per-org repository scan (0 = default). Requested
	// newest-push first, so the bound still captures recent activity.
	MaxReposPerOrg int `json:"max_repos_per_org"`
	// Concurrency bounds parallel per-organization API calls (0 = default).
	Concurrency int `json:"concurrency"`
}

// Thresholds are tunable limits used by rules.
type Thresholds struct {
	MaxEnterpriseOwners int `json:"max_enterprise_owners"`
	StaleOrgDays        int `json:"stale_org_days"`
}

// IdentityConfig governs the identity rules (IDENT-*): corporate-domain
// policy, outside-collaborator thresholds, and the data imports used by the
// detect → warn → prevent pipeline.
type IdentityConfig struct {
	// ApprovedDomains lists corporate email domains (e.g. "acme.com"). They
	// extend the enterprise's GitHub-verified domains, which are always
	// treated as corporate.
	ApprovedDomains []string `json:"approved_domains"`
	// ForbidCorporateEmailOnMembers makes IDENT-07 warn when enterprise
	// members carry a corporate-domain email on their personal account
	// (default: inventory only).
	ForbidCorporateEmailOnMembers bool `json:"forbid_corporate_email_on_members"`
	// MaxOutsideCollaborators is the per-organization threshold for IDENT-04.
	// -1 disables enforcement; 0 means no outside collaborators allowed.
	MaxOutsideCollaborators int `json:"max_outside_collaborators"`
	// AllowUsers are logins never flagged or remediated by identity rules.
	AllowUsers []string `json:"allow_users"`
	// RosterCSV is a CSV of current-employee identities (one email or IdP
	// name-ID per line, header optional) for the IDENT-09 offboarding check.
	RosterCSV string `json:"roster_csv"`
	// MailTraceCSV is a mail-gateway message-trace export (recipient address
	// per line/column) of GitHub signup mail for the IDENT-10 check.
	MailTraceCSV string `json:"mail_trace_csv"`
}

// AllowsUser reports whether a login is exempted from identity findings.
func (ic *IdentityConfig) AllowsUser(login string) bool {
	for _, u := range ic.AllowUsers {
		if strings.EqualFold(u, login) {
			return true
		}
	}
	return false
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
		Identity:   IdentityConfig{MaxOutsideCollaborators: -1},
	}

	if path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- path is an operator-provided --config file, not attacker input
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
	if v := os.Getenv("GHE_SERVER"); v != "" {
		cfg.Server = v
	}
	if v := os.Getenv("GHE_APP_ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("GHE_APP_ID must be numeric: %w", err)
		}
		cfg.AppID = id
	}
	if v := os.Getenv("GHE_APP_INSTALLATION_ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("GHE_APP_INSTALLATION_ID must be numeric: %w", err)
		}
		cfg.AppInstallationID = id
	}
	if v := os.Getenv("GHE_APP_PRIVATE_KEY_PATH"); v != "" {
		cfg.AppPrivateKeyPath = v
	}
	if v := os.Getenv("GHE_APP_PRIVATE_KEY"); v != "" {
		cfg.AppPrivateKey = v
	}

	if cfg.Thresholds.MaxEnterpriseOwners == 0 {
		cfg.Thresholds.MaxEnterpriseOwners = DefaultThresholds().MaxEnterpriseOwners
	}
	if cfg.Thresholds.StaleOrgDays == 0 {
		cfg.Thresholds.StaleOrgDays = DefaultThresholds().StaleOrgDays
	}
	if cfg.MaxReposPerOrg == 0 {
		cfg.MaxReposPerOrg = DefaultMaxReposPerOrg
	}

	return cfg, nil
}

// DefaultMaxReposPerOrg bounds the per-org repository scan by default. Repos are
// fetched newest-push first, so this still captures recent activity while
// avoiding unbounded pagination on very large organizations.
const DefaultMaxReposPerOrg = 500

// DefaultBaseURL and DefaultGraphQLURL are the public GitHub cloud endpoints.
const (
	DefaultBaseURL    = "https://api.github.com"
	DefaultGraphQLURL = "https://api.github.com/graphql"
)

// DeriveEndpoints resolves BaseURL/GraphQLURL from Server when set:
// "github.com" keeps the cloud defaults, "*.ghe.com" targets a data-residency
// enterprise, and anything else is treated as a GitHub Enterprise Server
// hostname. Explicitly configured non-default endpoints always win.
func (c *Config) DeriveEndpoints() error {
	if strings.TrimSpace(c.Server) == "" {
		return nil
	}
	host := strings.TrimSpace(c.Server)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")
	if host == "" || strings.Contains(host, "/") {
		return fmt.Errorf("invalid server %q: expected a hostname such as github.example.com or acme.ghe.com", c.Server)
	}
	explicitBase := c.BaseURL != "" && c.BaseURL != DefaultBaseURL
	explicitGQL := c.GraphQLURL != "" && c.GraphQLURL != DefaultGraphQLURL
	switch {
	case host == "github.com":
		// Public cloud: keep the defaults.
	case strings.HasSuffix(host, ".ghe.com"):
		// Data residency: https://api.SUBDOMAIN.ghe.com
		if !explicitBase {
			c.BaseURL = "https://api." + host
		}
		if !explicitGQL {
			c.GraphQLURL = "https://api." + host + "/graphql"
		}
	default:
		// GitHub Enterprise Server.
		if !explicitBase {
			c.BaseURL = "https://" + host + "/api/v3"
		}
		if !explicitGQL {
			c.GraphQLURL = "https://" + host + "/api/graphql"
		}
	}
	return nil
}

// HasAppAuth reports whether a complete GitHub App credential triple is set.
func (c *Config) HasAppAuth() bool {
	return c.AppID != 0 && c.AppInstallationID != 0 &&
		(c.AppPrivateKey != "" || c.AppPrivateKeyPath != "")
}

// AppPrivateKeyPEM returns the App private key material: the inline value
// first, then the file at AppPrivateKeyPath.
func (c *Config) AppPrivateKeyPEM() ([]byte, error) {
	if c.AppPrivateKey != "" {
		return []byte(c.AppPrivateKey), nil
	}
	b, err := os.ReadFile(c.AppPrivateKeyPath) // #nosec G304 -- path is an operator-provided key file, not attacker input
	if err != nil {
		return nil, fmt.Errorf("read app private key %q: %w", c.AppPrivateKeyPath, err)
	}
	return b, nil
}

// Validate ensures the minimum required fields are present: an enterprise
// slug and either a token or a complete GitHub App credential triple.
func (c *Config) Validate() error {
	var missing []string
	if strings.TrimSpace(c.Enterprise) == "" {
		missing = append(missing, "enterprise slug (set --enterprise or GHE_ENTERPRISE)")
	}
	if strings.TrimSpace(c.Token) == "" && !c.HasAppAuth() {
		if c.AppID != 0 || c.AppInstallationID != 0 || c.AppPrivateKey != "" || c.AppPrivateKeyPath != "" {
			var app []string
			if c.AppID == 0 {
				app = append(app, "GHE_APP_ID")
			}
			if c.AppInstallationID == 0 {
				app = append(app, "GHE_APP_INSTALLATION_ID")
			}
			if c.AppPrivateKey == "" && c.AppPrivateKeyPath == "" {
				app = append(app, "GHE_APP_PRIVATE_KEY or GHE_APP_PRIVATE_KEY_PATH")
			}
			missing = append(missing, "incomplete GitHub App auth, missing: "+strings.Join(app, ", "))
		} else {
			missing = append(missing, "credentials (set GHE_TOKEN/GITHUB_TOKEN, or GitHub App auth via GHE_APP_ID + GHE_APP_INSTALLATION_ID + GHE_APP_PRIVATE_KEY[_PATH])")
		}
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
