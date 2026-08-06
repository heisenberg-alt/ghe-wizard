package ghclient

import (
	"context"
	"encoding/json"
	"errors"
)

// errStopPagination is a sentinel to stop restPaginated early.
var errStopPagination = errors.New("stop pagination")

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// --- Remediation helpers (write operations used by rules) -----------------

// SetOrgDefaultRepositoryPermission updates the base permission for an org.
func (c *Client) SetOrgDefaultRepositoryPermission(ctx context.Context, org, perm string) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"default_repository_permission": perm,
	}, nil)
	return err
}

// SetOrgTwoFactorRequired enables the 2FA requirement for an org.
func (c *Client) SetOrgTwoFactorRequired(ctx context.Context, org string, required bool) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"two_factor_requirement_enabled": required,
	}, nil)
	return err
}

// SetOrgSecretScanningPushProtection toggles push protection defaults for new repos.
func (c *Client) SetOrgSecretScanningPushProtection(ctx context.Context, org string, enabled bool) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"secret_scanning_push_protection_enabled_for_new_repositories": enabled,
	}, nil)
	return err
}

// CreateEnterpriseCustomProperty creates or updates a custom property in the schema.
func (c *Client) CreateEnterpriseCustomProperty(ctx context.Context, slug, name, valueType string, required bool) error {
	_, err := c.rest(ctx, "PUT", "/enterprises/"+slug+"/properties/schema/"+name, map[string]any{
		"value_type": valueType,
		"required":   required,
	}, nil)
	return err
}

// CreateEnterpriseRuleset creates an enterprise ruleset from a raw payload.
func (c *Client) CreateEnterpriseRuleset(ctx context.Context, slug string, payload any) error {
	_, err := c.rest(ctx, "POST", "/enterprises/"+slug+"/rulesets", payload, nil)
	return err
}
