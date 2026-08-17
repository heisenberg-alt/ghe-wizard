package ghclient

import (
	"context"
	"errors"
	"sync"
)

// Cached wraps a GHAPI so that identical reads during a single assessment are
// performed once and shared across all rules. It also prefetches per-org data
// concurrently, which greatly reduces wall-clock time on large enterprises.
type Cached struct {
	inner       GHAPI
	concurrency int

	mu   sync.Mutex
	ent  *cacheEntry[*Enterprise]
	own  *cacheEntry[[]User]
	orgs map[int]*cacheEntry[[]Organization]
	cp   *cacheEntry[[]CustomProperty]
	rs   *cacheEntry[[]Ruleset]
	inst *cacheEntry[[]Installation]

	set   map[string]*cacheEntry[*OrgSettings]
	repos map[string]*cacheEntry[[]Repository]

	// Identity reads (see IdentityAPI); memoized like the core reads.
	doms      *cacheEntry[domainsResult]
	sso       *cacheEntry[ssoResult]
	memberIDs map[string]*cacheEntry[membersResult]
	oc        map[string]*cacheEntry[[]User]
	notif     map[string]*cacheEntry[boolResult]

	// Org-governance reads (see GovAPI).
	teams     map[string]*cacheEntry[teamsResult]
	extGroups map[string]*cacheEntry[countResult]
	csDefault map[string]*cacheEntry[boolResult]
}

type cacheEntry[T any] struct {
	once sync.Once
	val  T
	err  error
}

// Unwrap exposes the wrapped API so remediations can reach the write surface
// (see Writer in helpers.go).
func (c *Cached) Unwrap() GHAPI { return c.inner }

// NewCached wraps an API with memoization. concurrency bounds parallel org
// prefetch (defaults to 8 when <= 0).
func NewCached(inner GHAPI, concurrency int) *Cached {
	if concurrency <= 0 {
		concurrency = 8
	}
	return &Cached{
		inner:       inner,
		concurrency: concurrency,
		orgs:        map[int]*cacheEntry[[]Organization]{},
		set:         map[string]*cacheEntry[*OrgSettings]{},
		repos:       map[string]*cacheEntry[[]Repository]{},
	}
}

func (c *Cached) Enterprise(ctx context.Context, slug string) (*Enterprise, error) {
	c.mu.Lock()
	if c.ent == nil {
		c.ent = &cacheEntry[*Enterprise]{}
	}
	e := c.ent
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.Enterprise(ctx, slug) })
	return e.val, e.err
}

func (c *Cached) EnterpriseOwners(ctx context.Context, slug string) ([]User, error) {
	c.mu.Lock()
	if c.own == nil {
		c.own = &cacheEntry[[]User]{}
	}
	e := c.own
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.EnterpriseOwners(ctx, slug) })
	return e.val, e.err
}

func (c *Cached) Organizations(ctx context.Context, slug string, limit int) ([]Organization, error) {
	c.mu.Lock()
	e := c.orgs[limit]
	if e == nil {
		e = &cacheEntry[[]Organization]{}
		c.orgs[limit] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.Organizations(ctx, slug, limit) })
	return e.val, e.err
}

func (c *Cached) OrgSettings(ctx context.Context, org string) (*OrgSettings, error) {
	c.mu.Lock()
	e := c.set[org]
	if e == nil {
		e = &cacheEntry[*OrgSettings]{}
		c.set[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.OrgSettings(ctx, org) })
	return e.val, e.err
}

func (c *Cached) OrgRepos(ctx context.Context, org string, limit int) ([]Repository, error) {
	key := org
	c.mu.Lock()
	e := c.repos[key]
	if e == nil {
		e = &cacheEntry[[]Repository]{}
		c.repos[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.OrgRepos(ctx, org, limit) })
	return e.val, e.err
}

func (c *Cached) EnterpriseCustomProperties(ctx context.Context, slug string) ([]CustomProperty, error) {
	c.mu.Lock()
	if c.cp == nil {
		c.cp = &cacheEntry[[]CustomProperty]{}
	}
	e := c.cp
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.EnterpriseCustomProperties(ctx, slug) })
	return e.val, e.err
}

func (c *Cached) EnterpriseRulesets(ctx context.Context, slug string) ([]Ruleset, error) {
	c.mu.Lock()
	if c.rs == nil {
		c.rs = &cacheEntry[[]Ruleset]{}
	}
	e := c.rs
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.EnterpriseRulesets(ctx, slug) })
	return e.val, e.err
}

func (c *Cached) AuditLogStreamEnabled(ctx context.Context, slug string) (bool, Capability, error) {
	// Not memoized: cheap and returns a Capability rather than heavy data.
	return c.inner.AuditLogStreamEnabled(ctx, slug)
}

func (c *Cached) EnterpriseInstallations(ctx context.Context, slug string) ([]Installation, error) {
	c.mu.Lock()
	if c.inst == nil {
		c.inst = &cacheEntry[[]Installation]{}
	}
	e := c.inst
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.EnterpriseInstallations(ctx, slug) })
	return e.val, e.err
}

func (c *Cached) CostCenters(ctx context.Context, slug string) ([]CostCenter, Capability, error) {
	return c.inner.CostCenters(ctx, slug)
}

// Prefetch warms the per-organization caches (settings + repositories) for the
// enterprise concurrently, so subsequent rule assessments hit memory. maxRepos
// bounds the per-org repository scan (0 = unbounded). Errors are ignored here;
// the individual rule reads will surface them.
func (c *Cached) Prefetch(ctx context.Context, slug string, maxOrgs, maxRepos int) {
	orgs, err := c.Organizations(ctx, slug, maxOrgs)
	if err != nil || len(orgs) == 0 {
		return
	}
	sem := make(chan struct{}, c.concurrency)
	var wg sync.WaitGroup
	for _, o := range orgs {
		wg.Add(1)
		sem <- struct{}{}
		go func(login string) {
			defer wg.Done()
			defer func() { <-sem }()
			_, _ = c.OrgSettings(ctx, login)
			_, _ = c.OrgRepos(ctx, login, maxRepos)
		}(o.Login)
	}
	wg.Wait()
}

// --- IdentityAPI: memoized identity reads -----------------------------------

// identityUnavailable is the capability reason when the wrapped API has no
// identity surface (e.g. plain test mocks).
const identityUnavailable = "identity data source unavailable with this client"

type domainsResult struct {
	v    []VerifiedDomain
	capb Capability
}

type membersResult struct {
	v    []MemberIdentity
	capb Capability
}

type ssoResult struct {
	v    []SSOIdentity
	capb Capability
}

// EnterpriseVerifiedDomains memoizes the inner identity read; several IDENT-*
// rules derive the corporate-domain set from it.
func (c *Cached) EnterpriseVerifiedDomains(ctx context.Context, slug string) ([]VerifiedDomain, Capability, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return nil, Capability{Determined: false, Reason: identityUnavailable}, nil
	}
	c.mu.Lock()
	if c.doms == nil {
		c.doms = &cacheEntry[domainsResult]{}
	}
	e := c.doms
	c.mu.Unlock()
	e.once.Do(func() {
		var r domainsResult
		r.v, r.capb, e.err = inner.EnterpriseVerifiedDomains(ctx, slug)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}

// OrgMemberVerifiedEmails memoizes per org — IDENT-03/05/07/08/10 all consume
// the member inventory.
func (c *Cached) OrgMemberVerifiedEmails(ctx context.Context, org string) ([]MemberIdentity, Capability, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return nil, Capability{Determined: false, Reason: identityUnavailable}, nil
	}
	c.mu.Lock()
	if c.memberIDs == nil {
		c.memberIDs = map[string]*cacheEntry[membersResult]{}
	}
	e := c.memberIDs[org]
	if e == nil {
		e = &cacheEntry[membersResult]{}
		c.memberIDs[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		var r membersResult
		r.v, r.capb, e.err = inner.OrgMemberVerifiedEmails(ctx, org)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}

// SSOIdentities memoizes the enterprise SSO identity list.
func (c *Cached) SSOIdentities(ctx context.Context, slug string) ([]SSOIdentity, Capability, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return nil, Capability{Determined: false, Reason: identityUnavailable}, nil
	}
	c.mu.Lock()
	if c.sso == nil {
		c.sso = &cacheEntry[ssoResult]{}
	}
	e := c.sso
	c.mu.Unlock()
	e.once.Do(func() {
		var r ssoResult
		r.v, r.capb, e.err = inner.SSOIdentities(ctx, slug)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}

// OutsideCollaborators memoizes per org.
func (c *Cached) OutsideCollaborators(ctx context.Context, org string) ([]User, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return nil, errors.New(identityUnavailable)
	}
	c.mu.Lock()
	if c.oc == nil {
		c.oc = map[string]*cacheEntry[[]User]{}
	}
	e := c.oc[org]
	if e == nil {
		e = &cacheEntry[[]User]{}
		c.oc[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = inner.OutsideCollaborators(ctx, org) })
	return e.val, e.err
}

type boolResult struct {
	v    bool
	capb Capability
}

// OrgNotificationRestriction memoizes per org.
func (c *Cached) OrgNotificationRestriction(ctx context.Context, org string) (bool, Capability, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return false, Capability{Determined: false, Reason: identityUnavailable}, nil
	}
	c.mu.Lock()
	if c.notif == nil {
		c.notif = map[string]*cacheEntry[boolResult]{}
	}
	e := c.notif[org]
	if e == nil {
		e = &cacheEntry[boolResult]{}
		c.notif[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		var r boolResult
		r.v, r.capb, e.err = inner.OrgNotificationRestriction(ctx, org)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}

// SearchUsersByEmailDomain passes through (one caller per assessment).
func (c *Cached) SearchUsersByEmailDomain(ctx context.Context, domain string) ([]string, Capability, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return nil, Capability{Determined: false, Reason: identityUnavailable}, nil
	}
	return inner.SearchUsersByEmailDomain(ctx, domain)
}

// SearchCommitAuthorsByDomain passes through (one caller per assessment).
func (c *Cached) SearchCommitAuthorsByDomain(ctx context.Context, domain string) ([]string, Capability, error) {
	inner, ok := Identity(c.inner)
	if !ok {
		return nil, Capability{Determined: false, Reason: identityUnavailable}, nil
	}
	return inner.SearchCommitAuthorsByDomain(ctx, domain)
}

// --- GovAPI: memoized org-governance reads ----------------------------------

const govUnavailable = "org governance data source unavailable with this client"

type teamsResult struct {
	v    []Team
	capb Capability
}

type countResult struct {
	v    int
	capb Capability
}

// OrgTeams memoizes per org.
func (c *Cached) OrgTeams(ctx context.Context, org string) ([]Team, Capability, error) {
	inner, ok := Gov(c.inner)
	if !ok {
		return nil, Capability{Determined: false, Reason: govUnavailable}, nil
	}
	c.mu.Lock()
	if c.teams == nil {
		c.teams = map[string]*cacheEntry[teamsResult]{}
	}
	e := c.teams[org]
	if e == nil {
		e = &cacheEntry[teamsResult]{}
		c.teams[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		var r teamsResult
		r.v, r.capb, e.err = inner.OrgTeams(ctx, org)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}

// RepoDirectCollaboratorCount passes through (rules sample a bounded set).
func (c *Cached) RepoDirectCollaboratorCount(ctx context.Context, fullName string) (int, error) {
	inner, ok := Gov(c.inner)
	if !ok {
		return 0, errors.New(govUnavailable)
	}
	return inner.RepoDirectCollaboratorCount(ctx, fullName)
}

// ExternalGroupCount memoizes per org.
func (c *Cached) ExternalGroupCount(ctx context.Context, org string) (int, Capability, error) {
	inner, ok := Gov(c.inner)
	if !ok {
		return 0, Capability{Determined: false, Reason: govUnavailable}, nil
	}
	c.mu.Lock()
	if c.extGroups == nil {
		c.extGroups = map[string]*cacheEntry[countResult]{}
	}
	e := c.extGroups[org]
	if e == nil {
		e = &cacheEntry[countResult]{}
		c.extGroups[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		var r countResult
		r.v, r.capb, e.err = inner.ExternalGroupCount(ctx, org)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}

// CodeSecurityDefaultConfigured memoizes per org.
func (c *Cached) CodeSecurityDefaultConfigured(ctx context.Context, org string) (bool, Capability, error) {
	inner, ok := Gov(c.inner)
	if !ok {
		return false, Capability{Determined: false, Reason: govUnavailable}, nil
	}
	c.mu.Lock()
	if c.csDefault == nil {
		c.csDefault = map[string]*cacheEntry[boolResult]{}
	}
	e := c.csDefault[org]
	if e == nil {
		e = &cacheEntry[boolResult]{}
		c.csDefault[org] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		var r boolResult
		r.v, r.capb, e.err = inner.CodeSecurityDefaultConfigured(ctx, org)
		e.val = r
	})
	return e.val.v, e.val.capb, e.err
}
