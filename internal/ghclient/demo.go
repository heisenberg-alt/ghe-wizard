package ghclient

import (
	"context"
	"time"
)

// DemoAPI is a built-in, credential-free data source that returns realistic
// synthetic data for evaluation and demos. It implements GHAPI, so the real
// assessment engine runs against it unchanged and produces a representative
// mix of pass/fail/warn/manual findings.
type DemoAPI struct{}

// NewDemoAPI returns a demo data source.
func NewDemoAPI() *DemoAPI { return &DemoAPI{} }

func (d *DemoAPI) Enterprise(ctx context.Context, slug string) (*Enterprise, error) {
	return &Enterprise{
		Slug:                       slug,
		Name:                       "Acme Corporation",
		SAMLEnabled:                true,
		IPAllowListEnabled:         false,
		DefaultWorkflowPermissions: "write",
		Capabilities: map[string]Capability{
			"emu": {Determined: false, Reason: "EMU type not exposed via API; confirm manually"},
		},
	}, nil
}

func (d *DemoAPI) EnterpriseOwners(ctx context.Context, slug string) ([]User, error) {
	// 7 owners -> exceeds the recommended maximum (ENT-02 fails).
	return []User{
		{Login: "alice", ID: 1}, {Login: "bob", ID: 2}, {Login: "carol", ID: 3},
		{Login: "dave", ID: 4}, {Login: "erin", ID: 5}, {Login: "frank", ID: 6},
		{Login: "grace", ID: 7},
	}, nil
}

func (d *DemoAPI) Organizations(ctx context.Context, slug string, limit int) ([]Organization, error) {
	now := time.Now()
	orgs := []Organization{
		{Login: "acme-payments", ID: 101, CreatedAt: now.AddDate(-3, 0, 0)},
		{Login: "acme-platform", ID: 102, CreatedAt: now.AddDate(-2, 0, 0)},
		{Login: "acme-web", ID: 103, CreatedAt: now.AddDate(-2, -6, 0)},
		{Login: "acme-labs", ID: 104, CreatedAt: now.AddDate(-4, 0, 0)},
		{Login: "acme-legacy", ID: 105, CreatedAt: now.AddDate(-6, 0, 0)},
	}
	if limit > 0 && len(orgs) > limit {
		return orgs[:limit], nil
	}
	return orgs, nil
}

func (d *DemoAPI) OrgSettings(ctx context.Context, org string) (*OrgSettings, error) {
	// A deliberate mix so security/permission rules produce varied results.
	settings := map[string]*OrgSettings{
		"acme-payments": {Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: true, MembersCanCreateRepos: false, SecretScanningPushProtect: true},
		"acme-platform": {Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: true, MembersCanCreateRepos: true, SecretScanningPushProtect: true},
		"acme-web":      {Login: org, DefaultRepositoryPermission: "write", TwoFactorRequired: false, MembersCanCreateRepos: true, SecretScanningPushProtect: false},
		"acme-labs":     {Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: false, MembersCanCreateRepos: true, SecretScanningPushProtect: false},
		"acme-legacy":   {Login: org, DefaultRepositoryPermission: "admin", TwoFactorRequired: false, MembersCanCreateRepos: true, SecretScanningPushProtect: false},
	}
	if s, ok := settings[org]; ok {
		return s, nil
	}
	return &OrgSettings{Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: true}, nil
}

func (d *DemoAPI) OrgRepos(ctx context.Context, org string, limit int) ([]Repository, error) {
	now := time.Now()
	switch org {
	case "acme-legacy":
		// Stale org (ORG-03 flags it).
		return []Repository{
			{Name: "old-service", FullName: org + "/old-service", Visibility: "private", PushedAt: now.AddDate(-1, -2, 0)},
		}, nil
	case "acme-labs":
		return []Repository{}, nil // empty org
	default:
		return []Repository{
			{Name: "api", FullName: org + "/api", Visibility: "internal", PushedAt: now.AddDate(0, 0, -2)},
			{Name: "web", FullName: org + "/web", Visibility: "private", PushedAt: now.AddDate(0, 0, -1)},
			{Name: "docs", FullName: org + "/docs", Visibility: "internal", PushedAt: now.AddDate(0, 0, -5)},
		}, nil
	}
}

func (d *DemoAPI) EnterpriseCustomProperties(ctx context.Context, slug string) ([]CustomProperty, error) {
	return []CustomProperty{
		{Name: "data-classification", ValueType: "single_select", Required: true},
	}, nil
}

func (d *DemoAPI) EnterpriseRulesets(ctx context.Context, slug string) ([]Ruleset, error) {
	// No active rulesets -> POL-02 fails (and is remediable in the demo).
	return []Ruleset{}, nil
}

func (d *DemoAPI) AuditLogStreamEnabled(ctx context.Context, slug string) (bool, Capability, error) {
	return true, Capability{Determined: true}, nil
}

func (d *DemoAPI) EnterpriseInstallations(ctx context.Context, slug string) ([]Installation, error) {
	return []Installation{
		{ID: 900, AppID: 12, AppSlug: "terraform-cloud"},
		{ID: 901, AppID: 34, AppSlug: "ghe-provisioner"},
	}, nil
}

func (d *DemoAPI) CostCenters(ctx context.Context, slug string) ([]CostCenter, Capability, error) {
	return []CostCenter{
		{ID: "cc-1", Name: "Engineering"},
		{ID: "cc-2", Name: "Data Platform"},
	}, Capability{Determined: true}, nil
}
