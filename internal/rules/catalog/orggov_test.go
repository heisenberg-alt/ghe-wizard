package catalog_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func govFake() *fakeAPI {
	f := failingFake()
	f.orgRepos = map[string][]ghclient.Repository{
		"acme-app": {
			{Name: "api", FullName: "acme-app/api", Visibility: "internal"},
			{Name: "web", FullName: "acme-app/web", Visibility: "private"},
			{Name: "old", FullName: "acme-app/old", Visibility: "private", Archived: true},
		},
	}
	f.directCount = map[string]int{"acme-app/api": 2}
	f.teams = map[string][]ghclient.Team{
		"acme-app": {
			{Slug: "core", Name: "Core", Members: 5, Maintainers: 1, Repos: 2},
			{Slug: "ghost", Name: "Ghost", Members: 0, Maintainers: 0, Repos: 0},
			{Slug: "orphan", Name: "Orphan", Members: 3, Maintainers: 0, Repos: 1},
		},
	}
	return f
}

func govAssess(t *testing.T, api ghclient.GHAPI, id string) rules.Result {
	t.Helper()
	r := rules.ByID(id)
	if r == nil {
		t.Fatalf("rule %s not registered", id)
	}
	sc := engine.New(api, testCfg()).Assess(context.Background(), []rules.Rule{r})
	return sc.Results[0]
}

func TestTeam01_DirectCollaborators(t *testing.T) {
	f := govFake()
	res := govAssess(t, f, "TEAM-01")
	if res.Status != rules.StatusWarn {
		t.Fatalf("direct collaborators present; expected warn, got %s (%s)", res.Status, res.Detail)
	}
	list, _ := res.Evidence.([]string)
	if len(list) != 1 || !strings.Contains(list[0], "acme-app/api (2 direct)") {
		t.Fatalf("evidence should flag acme-app/api, got %#v", list)
	}
	if !strings.Contains(res.Detail, "sample") {
		t.Fatalf("detail must disclose sampling, got %q", res.Detail)
	}
	f.directCount = nil
	if res := govAssess(t, f, "TEAM-01"); res.Status != rules.StatusPass {
		t.Fatalf("no direct collaborators should pass, got %s", res.Status)
	}
}

func TestTeam02_ExternalGroups(t *testing.T) {
	f := govFake() // extGroups 0
	if res := govAssess(t, f, "TEAM-02"); res.Status != rules.StatusWarn {
		t.Fatalf("no IdP groups should warn, got %s", res.Status)
	}
	f.extGroups = 4
	if res := govAssess(t, f, "TEAM-02"); res.Status != rules.StatusPass {
		t.Fatalf("linked IdP groups should pass, got %s", res.Status)
	}
}

func TestTeam04And05_TeamHygiene(t *testing.T) {
	f := govFake()
	res := govAssess(t, f, "TEAM-04")
	if res.Status != rules.StatusWarn {
		t.Fatalf("empty team present; expected warn, got %s", res.Status)
	}
	if list, _ := res.Evidence.([]string); len(list) != 1 || list[0] != "acme-app/ghost" {
		t.Fatalf("TEAM-04 evidence should be [acme-app/ghost], got %#v", res.Evidence)
	}
	res = govAssess(t, f, "TEAM-05")
	if res.Status != rules.StatusWarn {
		t.Fatalf("maintainer-less team present; expected warn, got %s", res.Status)
	}
	if list, _ := res.Evidence.([]string); len(list) != 1 || list[0] != "acme-app/orphan" {
		t.Fatalf("TEAM-05 evidence should be [acme-app/orphan] (ghost is empty, core has a maintainer), got %#v", res.Evidence)
	}
}

func TestSec07_CodeSecurityDefault(t *testing.T) {
	f := govFake() // csDefault empty -> missing
	res := govAssess(t, f, "SEC-07")
	if res.Status != rules.StatusFail {
		t.Fatalf("missing default configuration should fail, got %s (%s)", res.Status, res.Detail)
	}
	f.csDefault = map[string]bool{"acme-app": true}
	if res := govAssess(t, f, "SEC-07"); res.Status != rules.StatusPass {
		t.Fatalf("configured default should pass, got %s", res.Status)
	}
}

func TestPol05_ApprovalOnlyFailure(t *testing.T) {
	f := govFake()
	f.ent = &ghclient.Enterprise{Slug: "acme", DefaultWorkflowPermissions: "read",
		CanApprovePRReviews: true, Capabilities: map[string]ghclient.Capability{}}
	res := govAssess(t, f, "POL-05")
	if res.Status != rules.StatusFail || !strings.Contains(res.Detail, "approve") {
		t.Fatalf("read-only + approval enabled should fail on approval, got %s (%s)", res.Status, res.Detail)
	}
	eng := engine.New(f, testCfg())
	rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID("POL-05")}, false)
	if !rr[0].Applied || !f.hasCall("HardenEnterpriseWorkflowPermissions acme") {
		t.Fatalf("remediation should harden workflow permissions, got %+v calls=%v", rr[0], f.calls)
	}
}

func TestPol06_GatedRestriction(t *testing.T) {
	f := govFake() // AllowedActions "all"
	if !rules.ByID("POL-06").Meta().Destructive {
		t.Fatal("POL-06 remediation must be gated (Destructive)")
	}
	eng := engine.New(f, testCfg())
	rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID("POL-06")}, true)
	if len(rr[0].Changes) != 1 || !strings.Contains(rr[0].Changes[0], "BUILD-IMPACTING") {
		t.Fatalf("dry-run must warn about build impact, got %+v", rr[0])
	}
	// Already restricted -> no changes.
	f.ent.AllowedActions = "selected"
	rr = eng.Remediate(context.Background(), []rules.Rule{rules.ByID("POL-06")}, false)
	if len(rr[0].Changes) != 0 {
		t.Fatalf("restricted policy should need no changes, got %+v", rr[0])
	}
}
