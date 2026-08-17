package ghclient

import (
	"context"
	"fmt"
)

// --- Organization-governance read surface (teams, security configs) ---------

// Team summarizes an organization team for governance checks.
type Team struct {
	Slug        string
	Name        string
	Members     int
	Maintainers int
	Repos       int
}

// GovAPI is the org-governance read surface used by the TEAM-* and SEC-07
// rules. *Client and the demo API implement it; rules obtain it via Gov(),
// which unwraps caching layers.
type GovAPI interface {
	OrgTeams(ctx context.Context, org string) ([]Team, Capability, error)
	// RepoDirectCollaboratorCount counts collaborators granted access
	// directly on the repository rather than through a team.
	RepoDirectCollaboratorCount(ctx context.Context, fullName string) (int, error)
	// ExternalGroupCount counts IdP groups available to the org for team
	// sync (external groups; EMU and team-sync tenants).
	ExternalGroupCount(ctx context.Context, org string) (int, Capability, error)
	// CodeSecurityDefaultConfigured reports whether the org has a code
	// security configuration set as default for new repositories.
	CodeSecurityDefaultConfigured(ctx context.Context, org string) (bool, Capability, error)
}

// Gov extracts the org-governance read surface from an assessment API,
// unwrapping any caching layers in between.
func Gov(api GHAPI) (GovAPI, bool) {
	for api != nil {
		if g, ok := api.(GovAPI); ok {
			return g, true
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

// OrgTeams lists org teams with member/maintainer/repository counts in a
// single GraphQL query per page (Team.members supports role: MAINTAINER;
// verified against the public schema).
func (c *Client) OrgTeams(ctx context.Context, org string) ([]Team, Capability, error) {
	var teams []Team
	var cursor *string
	for {
		var q struct {
			Organization struct {
				Teams struct {
					Nodes []struct {
						Slug    string `json:"slug"`
						Name    string `json:"name"`
						Members struct {
							TotalCount int `json:"totalCount"`
						} `json:"members"`
						Maintainers struct {
							TotalCount int `json:"totalCount"`
						} `json:"maintainers"`
						Repositories struct {
							TotalCount int `json:"totalCount"`
						} `json:"repositories"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"teams"`
			} `json:"organization"`
		}
		err := c.graphql(ctx, `
			query($org:String!,$cursor:String){
			  organization(login:$org){
			    teams(first:100, after:$cursor){
			      nodes{
			        slug name
			        members(first:1){ totalCount }
			        maintainers: members(first:1, role:MAINTAINER){ totalCount }
			        repositories(first:1){ totalCount }
			      }
			      pageInfo{ hasNextPage endCursor }
			    }
			  }
			}`, map[string]any{"org": org, "cursor": cursor}, &q)
		if err != nil {
			return nil, Capability{Determined: false, Reason: "teams unavailable for " + org + ": " + err.Error()}, nil
		}
		for _, n := range q.Organization.Teams.Nodes {
			teams = append(teams, Team{
				Slug: n.Slug, Name: n.Name,
				Members:     n.Members.TotalCount,
				Maintainers: n.Maintainers.TotalCount,
				Repos:       n.Repositories.TotalCount,
			})
		}
		if !q.Organization.Teams.PageInfo.HasNextPage {
			break
		}
		ec := q.Organization.Teams.PageInfo.EndCursor
		cursor = &ec
	}
	return teams, Capability{Determined: true}, nil
}

// RepoDirectCollaboratorCount counts directly-granted collaborators on a
// repository (first page of 100 is plenty as a governance signal).
func (c *Client) RepoDirectCollaboratorCount(ctx context.Context, fullName string) (int, error) {
	var collab []struct {
		Login string `json:"login"`
	}
	if _, err := c.rest(ctx, "GET", "/repos/"+fullName+"/collaborators?affiliation=direct&per_page=100", nil, &collab); err != nil {
		return 0, err
	}
	return len(collab), nil
}

// ExternalGroupCount counts IdP groups available for team sync.
func (c *Client) ExternalGroupCount(ctx context.Context, org string) (int, Capability, error) {
	var raw struct {
		Groups []struct {
			GroupID int64 `json:"group_id"`
		} `json:"groups"`
	}
	status, err := c.rest(ctx, "GET", "/orgs/"+org+"/external-groups", nil, &raw)
	if err != nil {
		return 0, Capability{Determined: false,
			Reason: fmt.Sprintf("external groups unavailable for %s (status %d); on classic SAML tenants verify team sync manually", org, status)}, nil
	}
	return len(raw.Groups), Capability{Determined: true}, nil
}

// CodeSecurityDefaultConfigured reports whether any code security
// configuration is the default for new repositories (endpoints verified
// against the REST docs: GET .../code-security/configurations/defaults).
func (c *Client) CodeSecurityDefaultConfigured(ctx context.Context, org string) (bool, Capability, error) {
	var raw []struct {
		DefaultForNewRepos string `json:"default_for_new_repos"`
		Configuration      *struct {
			ID int64 `json:"id"`
		} `json:"configuration"`
	}
	status, err := c.rest(ctx, "GET", "/orgs/"+org+"/code-security/configurations/defaults", nil, &raw)
	if err != nil {
		return false, Capability{Determined: false,
			Reason: fmt.Sprintf("code security configurations unavailable for %s (status %d)", org, status)}, nil
	}
	for _, d := range raw {
		if d.Configuration != nil && d.DefaultForNewRepos != "" && d.DefaultForNewRepos != "none" {
			return true, Capability{Determined: true}, nil
		}
	}
	return false, Capability{Determined: true}, nil
}
