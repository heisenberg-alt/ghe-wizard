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

// WriteAPI is the write surface used by rule remediations. *Client implements
// it, and so do write-capable fakes (the stateful demo API, test doubles).
// Read wrappers such as *Cached expose the underlying writer via Unwrap.
type WriteAPI interface {
	SetOrgDefaultRepositoryPermission(ctx context.Context, org, perm string) error
	SetOrgTwoFactorRequired(ctx context.Context, org string, required bool) error
	SetOrgSecretScanningDefaults(ctx context.Context, org string, enabled bool) error
	SetOrgDependabotDefaults(ctx context.Context, org string) error
	SetOrgMembersCanCreatePublicRepos(ctx context.Context, org string, allowed bool) error
	SetOrgWebCommitSignoff(ctx context.Context, org string, required bool) error
	SetEnterpriseDefaultWorkflowPermissions(ctx context.Context, slug, perm string) error
	CreateEnterpriseCustomProperty(ctx context.Context, slug, name, valueType string, required bool) error
	CreateEnterpriseRuleset(ctx context.Context, slug string, payload any) error
	// RemoveOutsideCollaborator is DESTRUCTIVE: it removes the user from all
	// of the organization's repositories. Only destructive-gated rules may
	// call it.
	RemoveOutsideCollaborator(ctx context.Context, org, login string) error
}

// ErrReadOnly explains a remediation that could not run because the API has
// no write surface (for example a read-only mock).
const ErrReadOnly = "no write-capable API client (read-only mode); change not applied"

// Writer extracts the write surface from an assessment API, unwrapping any
// caching layers in between. It reports false when the API is read-only.
func Writer(api GHAPI) (WriteAPI, bool) {
	for api != nil {
		if w, ok := api.(WriteAPI); ok {
			return w, true
		}
		u, ok := api.(interface{ Unwrap() GHAPI })
		if !ok {
			return nil, false
		}
		api = u.Unwrap()
	}
	return nil, false
}

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

// SetOrgSecretScanningDefaults enables (or disables) secret scanning and push
// protection for new repositories in an org.
func (c *Client) SetOrgSecretScanningDefaults(ctx context.Context, org string, enabled bool) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"secret_scanning_enabled_for_new_repositories":                 enabled,
		"secret_scanning_push_protection_enabled_for_new_repositories": enabled,
	}, nil)
	return err
}

// SetOrgDependabotDefaults enables the dependency graph, Dependabot alerts and
// Dependabot security updates for new repositories in an org.
func (c *Client) SetOrgDependabotDefaults(ctx context.Context, org string) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"dependency_graph_enabled_for_new_repositories":            true,
		"dependabot_alerts_enabled_for_new_repositories":           true,
		"dependabot_security_updates_enabled_for_new_repositories": true,
	}, nil)
	return err
}

// SetOrgMembersCanCreatePublicRepos toggles whether members may create public
// repositories (the safe subset — general repo creation is left untouched).
func (c *Client) SetOrgMembersCanCreatePublicRepos(ctx context.Context, org string, allowed bool) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"members_can_create_public_repositories": allowed,
	}, nil)
	return err
}

// SetOrgWebCommitSignoff toggles required sign-off on web-based commits.
func (c *Client) SetOrgWebCommitSignoff(ctx context.Context, org string, required bool) error {
	_, err := c.rest(ctx, "PATCH", "/orgs/"+org, map[string]any{
		"web_commit_signoff_required": required,
	}, nil)
	return err
}

// SetEnterpriseDefaultWorkflowPermissions sets the enterprise-wide default
// GITHUB_TOKEN permission level ("read" or "write").
func (c *Client) SetEnterpriseDefaultWorkflowPermissions(ctx context.Context, slug, perm string) error {
	_, err := c.rest(ctx, "PUT", "/enterprises/"+slug+"/actions/permissions/workflow", map[string]any{
		"default_workflow_permissions": perm,
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

// RemoveOutsideCollaborator removes an outside collaborator from all of the
// organization's repositories. DESTRUCTIVE — callers must be gated.
func (c *Client) RemoveOutsideCollaborator(ctx context.Context, org, login string) error {
	_, err := c.rest(ctx, "DELETE", "/orgs/"+org+"/outside_collaborators/"+login, nil, nil)
	return err
}
