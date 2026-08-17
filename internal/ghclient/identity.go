package ghclient

import (
	"context"
	"fmt"
	"net/url"
)

// --- Identity governance read surface --------------------------------------

// VerifiedDomain is an enterprise domain in GitHub's verified/approved set.
type VerifiedDomain struct {
	Domain     string
	IsVerified bool
	IsApproved bool
}

// MemberIdentity pairs an organization member with the emails on their
// account that match the organization's verified domains. GitHub returns
// these even when the member keeps the email private, which makes this the
// supported way to inventory corporate-email usage.
type MemberIdentity struct {
	Login          string
	VerifiedEmails []string
}

// SSOIdentity links a GitHub login to its IdP identity (SAML NameID, which
// is usually the corporate email).
type SSOIdentity struct {
	Login  string
	NameID string
}

// IdentityAPI is the identity-governance read surface used by the IDENT-*
// rules. *Client and the demo API implement it; rules obtain it via
// Identity(api), which unwraps caching layers. Results are wrapped in a
// Capability because several of these views depend on tenant configuration
// (verified domains, SAML) or preview-stage APIs.
type IdentityAPI interface {
	EnterpriseVerifiedDomains(ctx context.Context, slug string) ([]VerifiedDomain, Capability, error)
	OrgMemberVerifiedEmails(ctx context.Context, org string) ([]MemberIdentity, Capability, error)
	SSOIdentities(ctx context.Context, slug string) ([]SSOIdentity, Capability, error)
	OutsideCollaborators(ctx context.Context, org string) ([]User, error)
	// OrgNotificationRestriction reports whether email notifications are
	// restricted to approved/verified domains for the organization.
	OrgNotificationRestriction(ctx context.Context, org string) (bool, Capability, error)
	// SearchUsersByEmailDomain and SearchCommitAuthorsByDomain sweep PUBLIC
	// signals only (profile emails, commit author emails). Coverage is
	// partial by design; GitHub exposes no way to find accounts by private
	// registration email.
	SearchUsersByEmailDomain(ctx context.Context, domain string) ([]string, Capability, error)
	SearchCommitAuthorsByDomain(ctx context.Context, domain string) ([]string, Capability, error)
}

// Identity extracts the identity read surface from an assessment API,
// unwrapping any caching layers in between. It reports false when the API
// does not provide identity data (e.g. plain test mocks).
func Identity(api GHAPI) (IdentityAPI, bool) {
	for api != nil {
		if id, ok := api.(IdentityAPI); ok {
			return id, true
		}
		u, ok := api.(interface{ Unwrap() GHAPI })
		if !ok {
			return nil, false
		}
		api = u.Unwrap()
	}
	return nil, false
}

// --- Client implementation --------------------------------------------------

// EnterpriseVerifiedDomains lists the enterprise's verified/approved domains.
func (c *Client) EnterpriseVerifiedDomains(ctx context.Context, slug string) ([]VerifiedDomain, Capability, error) {
	var q struct {
		Enterprise struct {
			OwnerInfo struct {
				Domains struct {
					Nodes []struct {
						Domain     string `json:"domain"`
						IsVerified bool   `json:"isVerified"`
						IsApproved bool   `json:"isApproved"`
					} `json:"nodes"`
				} `json:"domains"`
			} `json:"ownerInfo"`
		} `json:"enterprise"`
	}
	err := c.graphql(ctx, `
		query($slug:String!){
		  enterprise(slug:$slug){
		    ownerInfo{ domains(first:100){ nodes{ domain isVerified isApproved } } }
		  }
		}`, map[string]any{"slug": slug}, &q)
	if err != nil {
		return nil, Capability{Determined: false, Reason: "verified domains unavailable: " + err.Error()}, nil
	}
	out := make([]VerifiedDomain, 0, len(q.Enterprise.OwnerInfo.Domains.Nodes))
	for _, n := range q.Enterprise.OwnerInfo.Domains.Nodes {
		out = append(out, VerifiedDomain{Domain: n.Domain, IsVerified: n.IsVerified, IsApproved: n.IsApproved})
	}
	return out, Capability{Determined: true}, nil
}

// OrgMemberVerifiedEmails lists org members with their verified-domain emails.
func (c *Client) OrgMemberVerifiedEmails(ctx context.Context, org string) ([]MemberIdentity, Capability, error) {
	var members []MemberIdentity
	var cursor *string
	for {
		var q struct {
			Organization struct {
				MembersWithRole struct {
					Nodes []struct {
						Login                            string   `json:"login"`
						OrganizationVerifiedDomainEmails []string `json:"organizationVerifiedDomainEmails"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"membersWithRole"`
			} `json:"organization"`
		}
		err := c.graphql(ctx, `
			query($org:String!,$cursor:String){
			  organization(login:$org){
			    membersWithRole(first:100, after:$cursor){
			      nodes{ login organizationVerifiedDomainEmails(login:$org) }
			      pageInfo{ hasNextPage endCursor }
			    }
			  }
			}`, map[string]any{"org": org, "cursor": cursor}, &q)
		if err != nil {
			return nil, Capability{Determined: false, Reason: "member verified emails unavailable for " + org + ": " + err.Error()}, nil
		}
		for _, n := range q.Organization.MembersWithRole.Nodes {
			members = append(members, MemberIdentity{Login: n.Login, VerifiedEmails: n.OrganizationVerifiedDomainEmails})
		}
		if !q.Organization.MembersWithRole.PageInfo.HasNextPage {
			break
		}
		ec := q.Organization.MembersWithRole.PageInfo.EndCursor
		cursor = &ec
	}
	return members, Capability{Determined: true}, nil
}

// SSOIdentities lists the enterprise SAML identity ↔ login links.
func (c *Client) SSOIdentities(ctx context.Context, slug string) ([]SSOIdentity, Capability, error) {
	var ids []SSOIdentity
	var cursor *string
	for {
		var q struct {
			Enterprise struct {
				OwnerInfo struct {
					SamlIdentityProvider *struct {
						ExternalIdentities struct {
							Nodes []struct {
								User *struct {
									Login string `json:"login"`
								} `json:"user"`
								SamlIdentity *struct {
									NameID string `json:"nameId"`
								} `json:"samlIdentity"`
							} `json:"nodes"`
							PageInfo struct {
								HasNextPage bool   `json:"hasNextPage"`
								EndCursor   string `json:"endCursor"`
							} `json:"pageInfo"`
						} `json:"externalIdentities"`
					} `json:"samlIdentityProvider"`
				} `json:"ownerInfo"`
			} `json:"enterprise"`
		}
		err := c.graphql(ctx, `
			query($slug:String!,$cursor:String){
			  enterprise(slug:$slug){
			    ownerInfo{
			      samlIdentityProvider{
			        externalIdentities(first:100, after:$cursor){
			          nodes{ user{ login } samlIdentity{ nameId } }
			          pageInfo{ hasNextPage endCursor }
			        }
			      }
			    }
			  }
			}`, map[string]any{"slug": slug, "cursor": cursor}, &q)
		if err != nil {
			return nil, Capability{Determined: false, Reason: "SSO identities unavailable: " + err.Error()}, nil
		}
		idp := q.Enterprise.OwnerInfo.SamlIdentityProvider
		if idp == nil {
			return nil, Capability{Determined: false, Reason: "no SAML identity provider configured at the enterprise level"}, nil
		}
		for _, n := range idp.ExternalIdentities.Nodes {
			id := SSOIdentity{}
			if n.User != nil {
				id.Login = n.User.Login
			}
			if n.SamlIdentity != nil {
				id.NameID = n.SamlIdentity.NameID
			}
			if id.Login != "" || id.NameID != "" {
				ids = append(ids, id)
			}
		}
		if !idp.ExternalIdentities.PageInfo.HasNextPage {
			break
		}
		ec := idp.ExternalIdentities.PageInfo.EndCursor
		cursor = &ec
	}
	return ids, Capability{Determined: true}, nil
}

// OrgNotificationRestriction reads the organization's email-notification
// restriction setting (verified against the public GraphQL schema:
// Organization.notificationDeliveryRestrictionEnabledSetting).
func (c *Client) OrgNotificationRestriction(ctx context.Context, org string) (bool, Capability, error) {
	var q struct {
		Organization struct {
			Setting string `json:"notificationDeliveryRestrictionEnabledSetting"`
		} `json:"organization"`
	}
	err := c.graphql(ctx, `
		query($org:String!){
		  organization(login:$org){ notificationDeliveryRestrictionEnabledSetting }
		}`, map[string]any{"org": org}, &q)
	if err != nil {
		return false, Capability{Determined: false, Reason: "notification restriction unavailable for " + org + ": " + err.Error()}, nil
	}
	return q.Organization.Setting == "ENABLED", Capability{Determined: true}, nil
}

// OutsideCollaborators lists an org's outside collaborators.
func (c *Client) OutsideCollaborators(ctx context.Context, org string) ([]User, error) {
	var users []User
	err := c.restPaginated(ctx, "/orgs/"+org+"/outside_collaborators?per_page=100", func(page []byte) error {
		var batch []struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		}
		if err := jsonUnmarshal(page, &batch); err != nil {
			return err
		}
		for _, u := range batch {
			users = append(users, User{Login: u.Login, ID: u.ID})
		}
		return nil
	})
	return users, err
}

// searchPageSize bounds the public-signal sweeps: one page of 100 keeps well
// under the search API's tight rate limits while still surfacing plenty of
// signal; totals above the page are reported via the capability reason.
const searchPageSize = 100

// SearchUsersByEmailDomain finds users whose PUBLIC profile email is on the
// domain. Coverage is partial by design.
func (c *Client) SearchUsersByEmailDomain(ctx context.Context, domain string) ([]string, Capability, error) {
	var raw struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Login string `json:"login"`
		} `json:"items"`
	}
	q := url.QueryEscape(domain + " in:email")
	path := fmt.Sprintf("/search/users?q=%s&per_page=%d", q, searchPageSize)
	if _, err := c.rest(ctx, "GET", path, nil, &raw); err != nil {
		return nil, Capability{Determined: false, Reason: "user search unavailable: " + err.Error()}, nil
	}
	logins := make([]string, 0, len(raw.Items))
	for _, it := range raw.Items {
		logins = append(logins, it.Login)
	}
	capb := Capability{Determined: true}
	if raw.TotalCount > len(raw.Items) {
		capb.Reason = fmt.Sprintf("showing %d of %d matches", len(raw.Items), raw.TotalCount)
	}
	return logins, capb, nil
}

// SearchCommitAuthorsByDomain finds distinct users who authored PUBLIC
// commits with an email on the domain. Coverage is partial by design.
func (c *Client) SearchCommitAuthorsByDomain(ctx context.Context, domain string) ([]string, Capability, error) {
	var raw struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
		} `json:"items"`
	}
	q := url.QueryEscape("author-email:" + domain)
	path := fmt.Sprintf("/search/commits?q=%s&per_page=%d", q, searchPageSize)
	if _, err := c.rest(ctx, "GET", path, nil, &raw); err != nil {
		return nil, Capability{Determined: false, Reason: "commit search unavailable: " + err.Error()}, nil
	}
	seen := map[string]bool{}
	var logins []string
	for _, it := range raw.Items {
		if it.Author == nil || it.Author.Login == "" || seen[it.Author.Login] {
			continue
		}
		seen[it.Author.Login] = true
		logins = append(logins, it.Author.Login)
	}
	capb := Capability{Determined: true}
	if raw.TotalCount > len(raw.Items) {
		capb.Reason = fmt.Sprintf("showing first page of %d matches", raw.TotalCount)
	}
	return logins, capb, nil
}
