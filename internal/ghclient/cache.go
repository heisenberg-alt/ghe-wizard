package ghclient

import (
	"context"
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
}

type cacheEntry[T any] struct {
	once sync.Once
	val  T
	err  error
}

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

func (c *Cached) Organizations(ctx context.Context, slug string, max int) ([]Organization, error) {
	c.mu.Lock()
	e := c.orgs[max]
	if e == nil {
		e = &cacheEntry[[]Organization]{}
		c.orgs[max] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.Organizations(ctx, slug, max) })
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

func (c *Cached) OrgRepos(ctx context.Context, org string, max int) ([]Repository, error) {
	key := org
	c.mu.Lock()
	e := c.repos[key]
	if e == nil {
		e = &cacheEntry[[]Repository]{}
		c.repos[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.val, e.err = c.inner.OrgRepos(ctx, org, max) })
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
// enterprise concurrently, so subsequent rule assessments hit memory. Errors are
// ignored here; the individual rule reads will surface them.
func (c *Cached) Prefetch(ctx context.Context, slug string, maxOrgs int) {
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
			_, _ = c.OrgRepos(ctx, login, 0)
		}(o.Login)
	}
	wg.Wait()
}
