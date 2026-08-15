package catalog_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog"
)

// fakeAPI implements ghclient.GHAPI plus ghclient.WriteAPI, recording every
// write call so tests can assert remediations reach the write surface.
type fakeAPI struct {
	mu    sync.Mutex
	calls []string

	ent         *ghclient.Enterprise
	orgs        []ghclient.Organization
	orgSettings map[string]*ghclient.OrgSettings
	props       []ghclient.CustomProperty
	rulesets    []ghclient.Ruleset
}

func (f *fakeAPI) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

func (f *fakeAPI) hasCall(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeAPI) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeAPI) Enterprise(ctx context.Context, slug string) (*ghclient.Enterprise, error) {
	if f.ent != nil {
		return f.ent, nil
	}
	return &ghclient.Enterprise{Slug: slug, Capabilities: map[string]ghclient.Capability{}}, nil
}
func (f *fakeAPI) EnterpriseOwners(ctx context.Context, slug string) ([]ghclient.User, error) {
	return nil, nil
}
func (f *fakeAPI) Organizations(ctx context.Context, slug string, limit int) ([]ghclient.Organization, error) {
	return f.orgs, nil
}
func (f *fakeAPI) OrgSettings(ctx context.Context, org string) (*ghclient.OrgSettings, error) {
	if s, ok := f.orgSettings[org]; ok {
		return s, nil
	}
	return &ghclient.OrgSettings{Login: org}, nil
}
func (f *fakeAPI) OrgRepos(ctx context.Context, org string, limit int) ([]ghclient.Repository, error) {
	return nil, nil
}
func (f *fakeAPI) EnterpriseCustomProperties(ctx context.Context, slug string) ([]ghclient.CustomProperty, error) {
	return f.props, nil
}
func (f *fakeAPI) EnterpriseRulesets(ctx context.Context, slug string) ([]ghclient.Ruleset, error) {
	return f.rulesets, nil
}
func (f *fakeAPI) AuditLogStreamEnabled(ctx context.Context, slug string) (bool, ghclient.Capability, error) {
	return false, ghclient.Capability{Determined: false, Reason: "n/a"}, nil
}
func (f *fakeAPI) EnterpriseInstallations(ctx context.Context, slug string) ([]ghclient.Installation, error) {
	return nil, nil
}
func (f *fakeAPI) CostCenters(ctx context.Context, slug string) ([]ghclient.CostCenter, ghclient.Capability, error) {
	return nil, ghclient.Capability{Determined: false, Reason: "n/a"}, nil
}

// WriteAPI implementation: record and succeed.

func (f *fakeAPI) SetOrgDefaultRepositoryPermission(ctx context.Context, org, perm string) error {
	f.record("SetOrgDefaultRepositoryPermission %s %s", org, perm)
	return nil
}
func (f *fakeAPI) SetOrgTwoFactorRequired(ctx context.Context, org string, required bool) error {
	f.record("SetOrgTwoFactorRequired %s %v", org, required)
	return nil
}
func (f *fakeAPI) SetOrgSecretScanningDefaults(ctx context.Context, org string, enabled bool) error {
	f.record("SetOrgSecretScanningDefaults %s %v", org, enabled)
	return nil
}
func (f *fakeAPI) SetOrgDependabotDefaults(ctx context.Context, org string) error {
	f.record("SetOrgDependabotDefaults %s", org)
	return nil
}
func (f *fakeAPI) SetOrgMembersCanCreatePublicRepos(ctx context.Context, org string, allowed bool) error {
	f.record("SetOrgMembersCanCreatePublicRepos %s %v", org, allowed)
	return nil
}
func (f *fakeAPI) SetOrgWebCommitSignoff(ctx context.Context, org string, required bool) error {
	f.record("SetOrgWebCommitSignoff %s %v", org, required)
	return nil
}
func (f *fakeAPI) SetEnterpriseDefaultWorkflowPermissions(ctx context.Context, slug, perm string) error {
	f.record("SetEnterpriseDefaultWorkflowPermissions %s %s", slug, perm)
	return nil
}
func (f *fakeAPI) CreateEnterpriseCustomProperty(ctx context.Context, slug, name, valueType string, required bool) error {
	f.record("CreateEnterpriseCustomProperty %s %s %s", slug, name, valueType)
	return nil
}
func (f *fakeAPI) CreateEnterpriseRuleset(ctx context.Context, slug string, payload any) error {
	f.record("CreateEnterpriseRuleset %s", slug)
	return nil
}
func (f *fakeAPI) RemoveOutsideCollaborator(ctx context.Context, org, login string) error {
	f.record("RemoveOutsideCollaborator %s %s", org, login)
	return nil
}

// readOnlyAPI exposes only the read surface of a fakeAPI: embedding the GHAPI
// interface promotes just its methods, so no WriteAPI and no Unwrap exist.
type readOnlyAPI struct{ ghclient.GHAPI }

// failingFake returns fixtures where every remediable rule fails: permissive
// base permission, no 2FA, no secret scanning, no Dependabot defaults, public
// repo creation allowed, no web sign-off, writable workflow token, no custom
// properties and no active rulesets.
func failingFake() *fakeAPI {
	return &fakeAPI{
		ent: &ghclient.Enterprise{Slug: "acme", DefaultWorkflowPermissions: "write",
			Capabilities: map[string]ghclient.Capability{}},
		orgs: []ghclient.Organization{{Login: "acme-app", ID: 1}},
		orgSettings: map[string]*ghclient.OrgSettings{
			"acme-app": {Login: "acme-app", DefaultRepositoryPermission: "write",
				MembersCanCreateRepos: true, MembersCanCreatePublicRepos: true},
		},
	}
}

// compliantFake returns fixtures where every remediable rule passes.
func compliantFake() *fakeAPI {
	return &fakeAPI{
		ent: &ghclient.Enterprise{Slug: "acme", DefaultWorkflowPermissions: "read",
			Capabilities: map[string]ghclient.Capability{}},
		orgs: []ghclient.Organization{{Login: "acme-app", ID: 1}},
		orgSettings: map[string]*ghclient.OrgSettings{
			"acme-app": {
				Login:                       "acme-app",
				DefaultRepositoryPermission: "read",
				TwoFactorRequired:           true,
				SecretScanningEnabled:       true,
				SecretScanningPushProtect:   true,
				DependencyGraphEnabled:      true,
				DependabotAlertsEnabled:     true,
				WebCommitSignoffRequired:    true,
			},
		},
		props:    []ghclient.CustomProperty{{Name: "data-classification", ValueType: "single_select"}},
		rulesets: []ghclient.Ruleset{{ID: 1, Name: "protect", Target: "branch", Enforcement: "active"}},
	}
}

func testCfg() *config.Config {
	return &config.Config{Enterprise: "acme", Token: "x", Thresholds: config.DefaultThresholds()}
}

// remediableCases pairs each remediable rule with the write call it must make.
var remediableCases = []struct {
	id        string
	wantWrite string
}{
	{"ORG-04", "SetOrgDefaultRepositoryPermission acme-app read"},
	{"ORG-05", "SetOrgWebCommitSignoff acme-app true"},
	{"SEC-03", "SetOrgTwoFactorRequired acme-app true"},
	{"SEC-05", "SetOrgSecretScanningDefaults acme-app true"},
	{"SEC-06", "SetOrgDependabotDefaults acme-app"},
	{"REPO-02", "CreateEnterpriseCustomProperty acme data-classification"},
	{"REPO-03", "SetOrgMembersCanCreatePublicRepos acme-app false"},
	{"POL-02", "CreateEnterpriseRuleset acme"},
	{"POL-05", "SetEnterpriseDefaultWorkflowPermissions acme read"},
}

// TestRemediate_WritesThroughCachedWrapper is the regression test for the
// remediation no-op: engine.New wraps the API in *ghclient.Cached, and
// remediations must still reach the write surface through it.
func TestRemediate_WritesThroughCachedWrapper(t *testing.T) {
	for _, tc := range remediableCases {
		t.Run(tc.id, func(t *testing.T) {
			api := failingFake()
			eng := engine.New(api, testCfg())
			rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID(tc.id)}, false)
			if len(rr) != 1 {
				t.Fatalf("expected 1 remediation result, got %d", len(rr))
			}
			if len(rr[0].Errors) > 0 {
				t.Fatalf("unexpected errors: %v", rr[0].Errors)
			}
			if !rr[0].Applied {
				t.Fatalf("remediation not applied; changes=%v", rr[0].Changes)
			}
			if !api.hasCall(tc.wantWrite) {
				t.Fatalf("expected write call %q, got %v", tc.wantWrite, api.calls)
			}
		})
	}
}

func TestRemediate_DryRunDescribesWithoutWriting(t *testing.T) {
	for _, tc := range remediableCases {
		t.Run(tc.id, func(t *testing.T) {
			api := failingFake()
			eng := engine.New(api, testCfg())
			rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID(tc.id)}, true)
			if len(rr) != 1 || len(rr[0].Changes) == 0 {
				t.Fatalf("dry-run should describe changes, got %+v", rr)
			}
			if rr[0].Applied {
				t.Fatal("dry-run must not apply changes")
			}
			if n := api.callCount(); n != 0 {
				t.Fatalf("dry-run must not write; %d call(s) recorded: %v", n, api.calls)
			}
		})
	}
}

func TestRemediate_CompliantStateMakesNoChanges(t *testing.T) {
	// Remediations re-check state and skip compliant targets entirely.
	for _, id := range []string{"ORG-04", "ORG-05", "SEC-03", "SEC-05", "SEC-06", "REPO-03", "POL-05"} {
		t.Run(id, func(t *testing.T) {
			api := compliantFake()
			eng := engine.New(api, testCfg())
			rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID(id)}, false)
			if len(rr[0].Changes) != 0 {
				t.Fatalf("compliant state should produce no changes, got %v", rr[0].Changes)
			}
			if n := api.callCount(); n != 0 {
				t.Fatalf("compliant state must not write; got %v", api.calls)
			}
		})
	}
}

func TestRemediate_ReadOnlyAPIReportsExplicitError(t *testing.T) {
	for _, tc := range remediableCases {
		t.Run(tc.id, func(t *testing.T) {
			eng := engine.New(readOnlyAPI{failingFake()}, testCfg())
			rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID(tc.id)}, false)
			if rr[0].Applied {
				t.Fatal("read-only API must not report applied")
			}
			found := false
			for _, e := range rr[0].Errors {
				if strings.Contains(e, "read-only") {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected explicit read-only error, got %v", rr[0].Errors)
			}
		})
	}
}

// TestCloudOnlyRulesSkipOnGHES asserts that rules depending on cloud-only
// features report skipped (excluded from the score) against a GHES target.
func TestCloudOnlyRulesSkipOnGHES(t *testing.T) {
	cfg := testCfg()
	cfg.TargetGHES = true
	cfg.ServerVersion = "3.14.0"
	eng := engine.New(compliantFake(), cfg)
	sc := eng.Assess(context.Background(), nil)
	byID := map[string]rules.Status{}
	for _, r := range sc.Results {
		byID[r.Meta.ID] = r.Status
	}
	for _, id := range []string{"ENT-01", "SEC-04", "POL-04", "BILL-01"} {
		if byID[id] != rules.StatusSkipped {
			t.Errorf("%s = %s on GHES, want skipped", id, byID[id])
		}
	}
	if sc.Summary.Counts[string(rules.StatusSkipped)] < 4 {
		t.Fatalf("expected at least 4 skipped rules, got %v", sc.Summary.Counts)
	}
}
