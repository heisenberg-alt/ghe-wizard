package ghclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Preflight verifies the token authenticates and reports the granted OAuth
// scopes. It returns the authenticated login, the scopes present, and any
// recommended scopes that appear to be missing for enterprise administration.
func (c *Client) Preflight(ctx context.Context) (login string, scopes []string, missing []string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/user", nil)
	if err != nil {
		return "", nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.doWithRetry(req)
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return "", nil, nil, fmt.Errorf("token rejected (401): verify GHE_TOKEN is valid and not expired")
	}
	if resp.StatusCode >= 400 {
		return "", nil, nil, fmt.Errorf("preflight failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Fine-grained tokens do not populate X-OAuth-Scopes; treat empty as unknown.
	raw := resp.Header.Get("X-OAuth-Scopes")
	if raw != "" {
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				scopes = append(scopes, s)
			}
		}
	}

	// Best-effort login extraction without pulling in a full decoder path.
	if i := strings.Index(string(body), `"login":"`); i >= 0 {
		rest := string(body)[i+len(`"login":"`):]
		if j := strings.IndexByte(rest, '"'); j >= 0 {
			login = rest[:j]
		}
	}

	if len(scopes) > 0 {
		want := []string{"admin:enterprise", "read:org", "repo"}
		for _, w := range want {
			if !hasScope(scopes, w) {
				missing = append(missing, w)
			}
		}
	}
	return login, scopes, missing, nil
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
		// A broader scope implies a narrower read (e.g. repo implies repo:status).
		if want == "read:org" && s == "admin:org" {
			return true
		}
	}
	return false
}
