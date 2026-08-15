// Package ghclient is a small GitHub API client (REST + GraphQL) for the
// enterprise best-practices wizard. It authenticates with a PAT or GitHub App
// installation tokens and exposes both low-level helpers and the higher-level
// GHAPI interface consumed by rules.
package ghclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
)

// GHAPI is the surface consumed by rules. A mock implementation is used in tests.
type GHAPI interface {
	Enterprise(ctx context.Context, slug string) (*Enterprise, error)
	EnterpriseOwners(ctx context.Context, slug string) ([]User, error)
	Organizations(ctx context.Context, slug string, limit int) ([]Organization, error)
	OrgSettings(ctx context.Context, org string) (*OrgSettings, error)
	OrgRepos(ctx context.Context, org string, limit int) ([]Repository, error)
	EnterpriseCustomProperties(ctx context.Context, slug string) ([]CustomProperty, error)
	EnterpriseRulesets(ctx context.Context, slug string) ([]Ruleset, error)
	AuditLogStreamEnabled(ctx context.Context, slug string) (bool, Capability, error)
	EnterpriseInstallations(ctx context.Context, slug string) ([]Installation, error)
	CostCenters(ctx context.Context, slug string) ([]CostCenter, Capability, error)
}

// Capability reports whether a value could be determined from the API.
type Capability struct {
	Determined bool
	Reason     string
}

// --- Domain types ---------------------------------------------------------

type Enterprise struct {
	Slug string
	Name string
	// SAML/OIDC configured at the enterprise level.
	SAMLEnabled bool
	// EMU indicates an Enterprise Managed Users enterprise (best-effort).
	EMU bool
	// DefaultWorkflowPermissions is "read" or "write" when known.
	DefaultWorkflowPermissions string
	// AllowedActions is the enterprise Actions policy ("all", "local_only",
	// "selected") when known.
	AllowedActions string
	// IPAllowListEnabled reflects the enterprise IP allow list policy.
	IPAllowListEnabled bool
	Capabilities       map[string]Capability
}

type User struct {
	Login string
	ID    int64
}

type Organization struct {
	Login     string
	ID        int64
	CreatedAt time.Time
}

type OrgSettings struct {
	Login                       string
	DefaultRepositoryPermission string // none|read|write|admin
	TwoFactorRequired           bool
	MembersCanCreateRepos       bool
	MembersCanCreatePublicRepos bool
	WebCommitSignoffRequired    bool
	SecretScanningEnabled       bool
	SecretScanningPushProtect   bool
	// Dependabot/dependency-graph defaults for new repositories.
	DependencyGraphEnabled    bool
	DependabotAlertsEnabled   bool
	DependabotSecurityUpdates bool
}

type Repository struct {
	Name          string
	FullName      string
	Visibility    string // public|private|internal
	Archived      bool
	PushedAt      time.Time
	DefaultBranch string
}

type CustomProperty struct {
	Name      string
	ValueType string
	Required  bool
}

type Ruleset struct {
	ID          int64
	Name        string
	Target      string // branch|tag|push
	Enforcement string // active|evaluate|disabled
	Rules       []string
}

type Installation struct {
	ID      int64
	AppID   int64
	AppSlug string
}

type CostCenter struct {
	ID   string
	Name string
}

// --- Client ---------------------------------------------------------------

// Client is an authenticated GitHub API client. Authentication is pluggable
// via TokenProvider: a static PAT or GitHub App installation tokens.
type Client struct {
	http       *http.Client
	baseURL    string
	graphqlURL string
	auth       TokenProvider
}

// New returns a PAT-authenticated Client. baseURL/graphqlURL default to
// public GitHub if empty.
func New(token, baseURL, graphqlURL string) *Client {
	return NewWithAuth(StaticToken(token), baseURL, graphqlURL)
}

// NewWithAuth returns a Client using the given token provider.
func NewWithAuth(auth TokenProvider, baseURL, graphqlURL string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	if graphqlURL == "" {
		graphqlURL = "https://api.github.com/graphql"
	}
	return &Client{
		http:       &http.Client{Timeout: 30 * time.Second},
		baseURL:    strings.TrimRight(baseURL, "/"),
		graphqlURL: graphqlURL,
		auth:       auth,
	}
}

// NewFromConfig builds a client from configuration. An explicit token wins
// (preserving the dashboard's per-request token override); otherwise GitHub
// App installation-token auth is used when configured.
func NewFromConfig(cfg *config.Config) (*Client, error) {
	if cfg.Token != "" || !cfg.HasAppAuth() {
		return New(cfg.Token, cfg.BaseURL, cfg.GraphQLURL), nil
	}
	pemKey, err := cfg.AppPrivateKeyPEM()
	if err != nil {
		return nil, err
	}
	auth, err := NewAppAuth(cfg.AppID, cfg.AppInstallationID, pemKey, cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	return NewWithAuth(auth, cfg.BaseURL, cfg.GraphQLURL), nil
}

// bearer returns the Authorization header value for a request, fetching (or
// refreshing) the token from the provider.
func (c *Client) bearer(ctx context.Context) (string, error) {
	tok, err := c.auth.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("obtain API token: %w", err)
	}
	return "Bearer " + tok, nil
}

// rest performs a REST request and decodes the JSON body into out (if non-nil).
// It returns the HTTP status code and any transport/decoding error.
func (c *Client) rest(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	url := path
	if !strings.HasPrefix(path, "http") {
		url = c.baseURL + path
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, err
	}
	bearer, err := c.bearer(ctx)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("GitHub API %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return resp.StatusCode, nil
}

// doWithRetry handles primary/secondary rate limits with a bounded backoff.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	const maxAttempts = 4
	for attempt := 1; ; attempt++ {
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}
		// Rate limited. Respect Retry-After or x-ratelimit-reset when present.
		wait := rateLimitWait(resp)
		_ = resp.Body.Close()
		if attempt >= maxAttempts || wait <= 0 || wait > 60*time.Second {
			// Re-issue once more without waiting is pointless; return the response.
			return c.http.Do(req)
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(wait):
		}
	}
}

func rateLimitWait(resp *http.Response) time.Duration {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	if resp.Header.Get("x-ratelimit-remaining") == "0" {
		if reset := resp.Header.Get("x-ratelimit-reset"); reset != "" {
			if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
				return time.Until(time.Unix(ts, 0))
			}
		}
	}
	return 0
}

// restPaginated follows Link rel="next" headers, appending each page into out slices
// via the accumulate callback.
func (c *Client) restPaginated(ctx context.Context, path string, accumulate func(page []byte) error) error {
	url := c.baseURL + path
	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		bearer, err := c.bearer(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := c.doWithRetry(req)
		if err != nil {
			return err
		}
		data, _ := io.ReadAll(resp.Body)
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("GitHub API GET %s: %d %s", url, resp.StatusCode, strings.TrimSpace(string(data)))
		}
		if err := accumulate(data); err != nil {
			return err
		}
		url = nextLink(link)
	}
	return nil
}

func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		segs := strings.Split(strings.TrimSpace(part), ";")
		if len(segs) < 2 {
			continue
		}
		if strings.Contains(segs[1], `rel="next"`) {
			return strings.Trim(strings.TrimSpace(segs[0]), "<>")
		}
	}
	return ""
}

// graphql executes a GraphQL query and decodes data into out.
func (c *Client) graphql(ctx context.Context, query string, vars map[string]any, out any) error {
	payload := map[string]any{"query": query, "variables": vars}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphqlURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	bearer, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GraphQL: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("GraphQL error: %s", env.Errors[0].Message)
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}
