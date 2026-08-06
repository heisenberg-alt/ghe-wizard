package engine

import (
	"context"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog"
)

// mockAPI implements ghclient.GHAPI with in-memory fixtures.
type mockAPI struct {
	owners      []ghclient.User
	orgs        []ghclient.Organization
	orgSettings map[string]*ghclient.OrgSettings
	orgRepos    map[string][]ghclient.Repository
	props       []ghclient.CustomProperty
	rulesets    []ghclient.Ruleset
	ent         *ghclient.Enterprise
}

func (m *mockAPI) Enterprise(ctx context.Context, slug string) (*ghclient.Enterprise, error) {
	if m.ent != nil {
		return m.ent, nil
	}
	return &ghclient.Enterprise{Slug: slug, Capabilities: map[string]ghclient.Capability{
		"emu": {Determined: false, Reason: "n/a"},
	}}, nil
}
func (m *mockAPI) EnterpriseOwners(ctx context.Context, slug string) ([]ghclient.User, error) {
	return m.owners, nil
}
func (m *mockAPI) Organizations(ctx context.Context, slug string, limit int) ([]ghclient.Organization, error) {
	return m.orgs, nil
}
func (m *mockAPI) OrgSettings(ctx context.Context, org string) (*ghclient.OrgSettings, error) {
	if s, ok := m.orgSettings[org]; ok {
		return s, nil
	}
	return &ghclient.OrgSettings{Login: org}, nil
}
func (m *mockAPI) OrgRepos(ctx context.Context, org string, limit int) ([]ghclient.Repository, error) {
	return m.orgRepos[org], nil
}
func (m *mockAPI) EnterpriseCustomProperties(ctx context.Context, slug string) ([]ghclient.CustomProperty, error) {
	return m.props, nil
}
func (m *mockAPI) EnterpriseRulesets(ctx context.Context, slug string) ([]ghclient.Ruleset, error) {
	return m.rulesets, nil
}
func (m *mockAPI) AuditLogStreamEnabled(ctx context.Context, slug string) (bool, ghclient.Capability, error) {
	return false, ghclient.Capability{Determined: false, Reason: "n/a"}, nil
}
func (m *mockAPI) EnterpriseInstallations(ctx context.Context, slug string) ([]ghclient.Installation, error) {
	return nil, nil
}
func (m *mockAPI) CostCenters(ctx context.Context, slug string) ([]ghclient.CostCenter, ghclient.Capability, error) {
	return nil, ghclient.Capability{Determined: false, Reason: "n/a"}, nil
}

func testCfg() *config.Config {
	return &config.Config{
		Enterprise: "acme",
		Token:      "x",
		Thresholds: config.DefaultThresholds(),
	}
}

func resultByID(sc *Scorecard, id string) *rules.Result {
	for i := range sc.Results {
		if sc.Results[i].Meta.ID == id {
			return &sc.Results[i]
		}
	}
	return nil
}

func TestAssess_OwnersThreshold(t *testing.T) {
	// 7 owners exceeds the default limit of 5 -> ENT-02 should fail.
	m := &mockAPI{orgSettings: map[string]*ghclient.OrgSettings{}}
	for i := 0; i < 7; i++ {
		m.owners = append(m.owners, ghclient.User{Login: "owner", ID: int64(i)})
	}
	sc := New(m, testCfg()).Assess(context.Background(), nil)
	r := resultByID(sc, "ENT-02")
	if r == nil || r.Status != rules.StatusFail {
		t.Fatalf("ENT-02 expected fail, got %+v", r)
	}
}

func TestAssess_BasePermissionFailAndRemediate(t *testing.T) {
	m := &mockAPI{
		orgs: []ghclient.Organization{{Login: "acme-app"}},
		orgSettings: map[string]*ghclient.OrgSettings{
			"acme-app": {Login: "acme-app", DefaultRepositoryPermission: "write"},
		},
	}
	eng := New(m, testCfg())
	sc := eng.Assess(context.Background(), nil)
	if r := resultByID(sc, "ORG-04"); r == nil || r.Status != rules.StatusFail {
		t.Fatalf("ORG-04 expected fail, got %+v", r)
	}
	// Dry-run remediation should describe the change without erroring.
	rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID("ORG-04")}, true)
	if len(rr) != 1 || len(rr[0].Changes) == 0 {
		t.Fatalf("ORG-04 remediation expected a described change, got %+v", rr)
	}
	if rr[0].Applied {
		t.Fatalf("dry-run should not apply changes")
	}
}

func TestAssess_2FAAcrossOrgs(t *testing.T) {
	m := &mockAPI{
		orgs: []ghclient.Organization{{Login: "a"}, {Login: "b"}},
		orgSettings: map[string]*ghclient.OrgSettings{
			"a": {Login: "a", TwoFactorRequired: true},
			"b": {Login: "b", TwoFactorRequired: false},
		},
	}
	sc := New(m, testCfg()).Assess(context.Background(), nil)
	if r := resultByID(sc, "SEC-03"); r == nil || r.Status != rules.StatusFail {
		t.Fatalf("SEC-03 expected fail (org b lacks 2FA), got %+v", r)
	}
}

func TestScore_IsComputed(t *testing.T) {
	m := &mockAPI{orgSettings: map[string]*ghclient.OrgSettings{}}
	sc := New(m, testCfg()).Assess(context.Background(), nil)
	if sc.Summary.Total == 0 {
		t.Fatal("expected some rules to run")
	}
	if sc.Summary.Score < 0 || sc.Summary.Score > 100 {
		t.Fatalf("score out of range: %d", sc.Summary.Score)
	}
}

func TestCatalog_AllRulesHaveMetadata(t *testing.T) {
	for _, r := range rules.All() {
		m := r.Meta()
		if m.ID == "" || m.Title == "" || m.DocsURL == "" || m.Domain == "" {
			t.Errorf("rule missing metadata: %+v", m)
		}
	}
}
