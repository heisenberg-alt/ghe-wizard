package ghclient

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// countingAPI counts underlying calls to verify caching behavior.
type countingAPI struct {
	orgCalls  int64
	setCalls  int64
	repoCalls int64
	entCalls  int64
}

func (c *countingAPI) Enterprise(ctx context.Context, slug string) (*Enterprise, error) {
	atomic.AddInt64(&c.entCalls, 1)
	return &Enterprise{Slug: slug, Capabilities: map[string]Capability{}}, nil
}
func (c *countingAPI) EnterpriseOwners(ctx context.Context, slug string) ([]User, error) {
	return nil, nil
}
func (c *countingAPI) Organizations(ctx context.Context, slug string, max int) ([]Organization, error) {
	atomic.AddInt64(&c.orgCalls, 1)
	return []Organization{{Login: "a"}, {Login: "b"}, {Login: "c"}}, nil
}
func (c *countingAPI) OrgSettings(ctx context.Context, org string) (*OrgSettings, error) {
	atomic.AddInt64(&c.setCalls, 1)
	return &OrgSettings{Login: org}, nil
}
func (c *countingAPI) OrgRepos(ctx context.Context, org string, max int) ([]Repository, error) {
	atomic.AddInt64(&c.repoCalls, 1)
	return nil, nil
}
func (c *countingAPI) EnterpriseCustomProperties(ctx context.Context, slug string) ([]CustomProperty, error) {
	return nil, nil
}
func (c *countingAPI) EnterpriseRulesets(ctx context.Context, slug string) ([]Ruleset, error) {
	return nil, nil
}
func (c *countingAPI) AuditLogStreamEnabled(ctx context.Context, slug string) (bool, Capability, error) {
	return false, Capability{}, nil
}
func (c *countingAPI) EnterpriseInstallations(ctx context.Context, slug string) ([]Installation, error) {
	return nil, nil
}
func (c *countingAPI) CostCenters(ctx context.Context, slug string) ([]CostCenter, Capability, error) {
	return nil, Capability{}, nil
}

func TestCached_MemoizesReads(t *testing.T) {
	inner := &countingAPI{}
	c := NewCached(inner, 4)
	ctx := context.Background()

	// Many concurrent calls should collapse to a single underlying call each.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Enterprise(ctx, "acme")
			_, _ = c.Organizations(ctx, "acme", 0)
			_, _ = c.OrgSettings(ctx, "a")
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&inner.entCalls); got != 1 {
		t.Errorf("Enterprise called %d times, want 1", got)
	}
	if got := atomic.LoadInt64(&inner.orgCalls); got != 1 {
		t.Errorf("Organizations called %d times, want 1", got)
	}
	if got := atomic.LoadInt64(&inner.setCalls); got != 1 {
		t.Errorf("OrgSettings(a) called %d times, want 1", got)
	}
}

func TestCached_Prefetch(t *testing.T) {
	inner := &countingAPI{}
	c := NewCached(inner, 4)
	ctx := context.Background()

	c.Prefetch(ctx, "acme", 0)

	// 3 orgs -> settings and repos fetched once each.
	if got := atomic.LoadInt64(&inner.setCalls); got != 3 {
		t.Errorf("OrgSettings called %d times, want 3", got)
	}
	if got := atomic.LoadInt64(&inner.repoCalls); got != 3 {
		t.Errorf("OrgRepos called %d times, want 3", got)
	}

	// Subsequent reads should be served from cache (no new calls).
	_, _ = c.OrgSettings(ctx, "a")
	_, _ = c.OrgRepos(ctx, "b", 0)
	if got := atomic.LoadInt64(&inner.setCalls); got != 3 {
		t.Errorf("OrgSettings re-fetched: %d, want 3", got)
	}
	if got := atomic.LoadInt64(&inner.repoCalls); got != 3 {
		t.Errorf("OrgRepos re-fetched: %d, want 3", got)
	}
}

func TestHasScope(t *testing.T) {
	if !hasScope([]string{"repo", "admin:org"}, "read:org") {
		t.Error("admin:org should imply read:org")
	}
	if hasScope([]string{"repo"}, "admin:enterprise") {
		t.Error("repo should not imply admin:enterprise")
	}
}

func TestNextLink(t *testing.T) {
	h := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`
	if got := nextLink(h); got != "https://api.github.com/x?page=2" {
		t.Errorf("nextLink = %q", got)
	}
	if got := nextLink(``); got != "" {
		t.Errorf("nextLink empty = %q", got)
	}
}
