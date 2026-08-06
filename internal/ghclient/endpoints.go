package ghclient

import (
	"context"
	"fmt"
	"time"
)

// Enterprise fetches enterprise-level settings. Fields that cannot be determined
// from the API are recorded in Capabilities rather than failing the whole call.
func (c *Client) Enterprise(ctx context.Context, slug string) (*Enterprise, error) {
	ent := &Enterprise{Slug: slug, Capabilities: map[string]Capability{}}

	// Core info + owners + a few owner-info settings via GraphQL.
	var q struct {
		Enterprise struct {
			Name      string `json:"name"`
			Slug      string `json:"slug"`
			OwnerInfo struct {
				DefaultRepositoryPermissionSetting string `json:"defaultRepositoryPermissionSetting"`
				IPAllowListEnabledSetting          string `json:"ipAllowListEnabledSetting"`
				SamlIdentityProvider               *struct {
					SsoURL string `json:"ssoUrl"`
				} `json:"samlIdentityProvider"`
			} `json:"ownerInfo"`
		} `json:"enterprise"`
	}
	err := c.graphql(ctx, `
		query($slug:String!){
		  enterprise(slug:$slug){
		    name slug
		    ownerInfo{
		      defaultRepositoryPermissionSetting
		      ipAllowListEnabledSetting
		      samlIdentityProvider{ ssoUrl }
		    }
		  }
		}`, map[string]any{"slug": slug}, &q)
	if err != nil {
		ent.Capabilities["ownerInfo"] = Capability{false, err.Error()}
	} else {
		if q.Enterprise.Name != "" {
			ent.Name = q.Enterprise.Name
		}
		ent.SAMLEnabled = q.Enterprise.OwnerInfo.SamlIdentityProvider != nil
		ent.IPAllowListEnabled = q.Enterprise.OwnerInfo.IPAllowListEnabledSetting == "ENABLED"
		ent.DefaultWorkflowPermissions = ""
	}

	// EMU detection is best-effort: EMU logins carry an enterprise short-code suffix.
	ent.Capabilities["emu"] = Capability{false, "EMU type not exposed via API; confirm manually"}
	ent.Capabilities["twoFactor"] = Capability{false, "enterprise 2FA policy read via org settings"}

	return ent, nil
}

// EnterpriseOwners returns the enterprise administrators (owners).
func (c *Client) EnterpriseOwners(ctx context.Context, slug string) ([]User, error) {
	var owners []User
	var cursor *string
	for {
		var q struct {
			Enterprise struct {
				OwnerInfo struct {
					Admins struct {
						Nodes []struct {
							Login      string `json:"login"`
							DatabaseID int64  `json:"databaseId"`
						} `json:"nodes"`
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
					} `json:"admins"`
				} `json:"ownerInfo"`
			} `json:"enterprise"`
		}
		vars := map[string]any{"slug": slug, "cursor": cursor}
		err := c.graphql(ctx, `
			query($slug:String!,$cursor:String){
			  enterprise(slug:$slug){
			    ownerInfo{
			      admins(first:100, after:$cursor, role:OWNER){
			        nodes{ login databaseId }
			        pageInfo{ hasNextPage endCursor }
			      }
			    }
			  }
			}`, vars, &q)
		if err != nil {
			return nil, err
		}
		for _, n := range q.Enterprise.OwnerInfo.Admins.Nodes {
			owners = append(owners, User{Login: n.Login, ID: n.DatabaseID})
		}
		if !q.Enterprise.OwnerInfo.Admins.PageInfo.HasNextPage {
			break
		}
		ec := q.Enterprise.OwnerInfo.Admins.PageInfo.EndCursor
		cursor = &ec
	}
	return owners, nil
}

// Organizations lists organizations owned by the enterprise (capped by max, 0=all).
func (c *Client) Organizations(ctx context.Context, slug string, max int) ([]Organization, error) {
	var orgs []Organization
	var cursor *string
	for {
		var q struct {
			Enterprise struct {
				Organizations struct {
					Nodes []struct {
						Login      string    `json:"login"`
						DatabaseID int64     `json:"databaseId"`
						CreatedAt  time.Time `json:"createdAt"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"organizations"`
			} `json:"enterprise"`
		}
		vars := map[string]any{"slug": slug, "cursor": cursor}
		err := c.graphql(ctx, `
			query($slug:String!,$cursor:String){
			  enterprise(slug:$slug){
			    organizations(first:100, after:$cursor){
			      nodes{ login databaseId createdAt }
			      pageInfo{ hasNextPage endCursor }
			    }
			  }
			}`, vars, &q)
		if err != nil {
			return nil, err
		}
		for _, n := range q.Enterprise.Organizations.Nodes {
			orgs = append(orgs, Organization{Login: n.Login, ID: n.DatabaseID, CreatedAt: n.CreatedAt})
			if max > 0 && len(orgs) >= max {
				return orgs, nil
			}
		}
		if !q.Enterprise.Organizations.PageInfo.HasNextPage {
			break
		}
		ec := q.Enterprise.Organizations.PageInfo.EndCursor
		cursor = &ec
	}
	return orgs, nil
}

// OrgSettings reads org-level governance settings via REST.
func (c *Client) OrgSettings(ctx context.Context, org string) (*OrgSettings, error) {
	var raw struct {
		Login                                     string `json:"login"`
		DefaultRepositoryPermission               string `json:"default_repository_permission"`
		TwoFactorRequirementEnabled               bool   `json:"two_factor_requirement_enabled"`
		MembersCanCreateRepositories              bool   `json:"members_can_create_repositories"`
		AdvancedSecurityEnabledForNewRepositories bool   `json:"advanced_security_enabled_for_new_repositories"`
		SecretScanningEnabledForNewRepositories   bool   `json:"secret_scanning_enabled_for_new_repositories"`
		SecretScanningPushProtectionEnabledForNew bool   `json:"secret_scanning_push_protection_enabled_for_new_repositories"`
	}
	if _, err := c.rest(ctx, "GET", "/orgs/"+org, nil, &raw); err != nil {
		return nil, err
	}
	return &OrgSettings{
		Login:                       raw.Login,
		DefaultRepositoryPermission: raw.DefaultRepositoryPermission,
		TwoFactorRequired:           raw.TwoFactorRequirementEnabled,
		MembersCanCreateRepos:       raw.MembersCanCreateRepositories,
		AdvancedSecurityEnabled:     raw.AdvancedSecurityEnabledForNewRepositories,
		SecretScanningEnabled:       raw.SecretScanningEnabledForNewRepositories,
		SecretScanningPushProtect:   raw.SecretScanningPushProtectionEnabledForNew,
	}, nil
}

// OrgRepos lists repositories in an org via REST (capped by max, 0=all).
// Repositories are requested newest-push first so a bounded scan still yields
// the most-recently-active repos (used by staleness/innersource checks).
func (c *Client) OrgRepos(ctx context.Context, org string, max int) ([]Repository, error) {
	var repos []Repository
	err := c.restPaginated(ctx, "/orgs/"+org+"/repos?per_page=100&type=all&sort=pushed&direction=desc", func(page []byte) error {
		var batch []struct {
			Name          string    `json:"name"`
			FullName      string    `json:"full_name"`
			Private       bool      `json:"private"`
			Visibility    string    `json:"visibility"`
			Archived      bool      `json:"archived"`
			PushedAt      time.Time `json:"pushed_at"`
			DefaultBranch string    `json:"default_branch"`
		}
		if err := jsonUnmarshal(page, &batch); err != nil {
			return err
		}
		for _, r := range batch {
			repos = append(repos, Repository{
				Name: r.Name, FullName: r.FullName, Private: r.Private,
				Visibility: r.Visibility, Archived: r.Archived,
				PushedAt: r.PushedAt, DefaultBranch: r.DefaultBranch,
			})
			if max > 0 && len(repos) >= max {
				return errStopPagination
			}
		}
		return nil
	})
	if err != nil && err != errStopPagination {
		return repos, err
	}
	return repos, nil
}

// EnterpriseCustomProperties reads the enterprise custom property schema.
func (c *Client) EnterpriseCustomProperties(ctx context.Context, slug string) ([]CustomProperty, error) {
	var raw []struct {
		PropertyName string `json:"property_name"`
		ValueType    string `json:"value_type"`
		Required     bool   `json:"required"`
	}
	if _, err := c.rest(ctx, "GET", "/enterprises/"+slug+"/properties/schema", nil, &raw); err != nil {
		return nil, err
	}
	props := make([]CustomProperty, 0, len(raw))
	for _, p := range raw {
		props = append(props, CustomProperty{Name: p.PropertyName, ValueType: p.ValueType, Required: p.Required})
	}
	return props, nil
}

// EnterpriseRulesets lists enterprise-level rulesets (best-effort; may be empty).
func (c *Client) EnterpriseRulesets(ctx context.Context, slug string) ([]Ruleset, error) {
	var raw []struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Target      string `json:"target"`
		Enforcement string `json:"enforcement"`
	}
	if _, err := c.rest(ctx, "GET", "/enterprises/"+slug+"/rulesets", nil, &raw); err != nil {
		return nil, err
	}
	rs := make([]Ruleset, 0, len(raw))
	for _, r := range raw {
		rs = append(rs, Ruleset{ID: r.ID, Name: r.Name, Target: r.Target, Enforcement: r.Enforcement})
	}
	return rs, nil
}

// AuditLogStreamEnabled reports whether audit log streaming is configured.
// The stream configuration is not broadly exposed via REST, so this returns a
// Capability marking the result as undetermined for manual verification.
func (c *Client) AuditLogStreamEnabled(ctx context.Context, slug string) (bool, Capability, error) {
	return false, Capability{Determined: false, Reason: "audit log stream config not exposed via API; verify in Settings > Audit log > Log streaming"}, nil
}

// EnterpriseInstallations lists GitHub Apps installed on the enterprise account.
func (c *Client) EnterpriseInstallations(ctx context.Context, slug string) ([]Installation, error) {
	var raw struct {
		Installations []struct {
			ID      int64  `json:"id"`
			AppID   int64  `json:"app_id"`
			AppSlug string `json:"app_slug"`
		} `json:"installations"`
	}
	if _, err := c.rest(ctx, "GET", "/enterprises/"+slug+"/installations", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Installation, 0, len(raw.Installations))
	for _, i := range raw.Installations {
		out = append(out, Installation{ID: i.ID, AppID: i.AppID, AppSlug: i.AppSlug})
	}
	return out, nil
}

// CostCenters lists enterprise cost centers (enhanced billing). Returns a
// Capability when the endpoint is unavailable for the account.
func (c *Client) CostCenters(ctx context.Context, slug string) ([]CostCenter, Capability, error) {
	var raw struct {
		CostCenters []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"costCenters"`
	}
	status, err := c.rest(ctx, "GET", "/enterprises/"+slug+"/settings/billing/cost-centers", nil, &raw)
	if err != nil {
		return nil, Capability{Determined: false, Reason: fmt.Sprintf("cost centers unavailable (status %d): %v", status, err)}, nil
	}
	out := make([]CostCenter, 0, len(raw.CostCenters))
	for _, cc := range raw.CostCenters {
		out = append(out, CostCenter{ID: cc.ID, Name: cc.Name})
	}
	return out, Capability{Determined: true}, nil
}
