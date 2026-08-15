package catalog_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// identityFake layers the identity-governance read surface over fakeAPI.
// Keeping it separate means the base fakeAPI (and readOnlyAPI) stay
// identity-free, preserving the existing gating tests.
type identityFake struct {
	*fakeAPI
	domains       []ghclient.VerifiedDomain
	members       map[string][]ghclient.MemberIdentity
	sso           []ghclient.SSOIdentity
	outside       map[string][]ghclient.User
	searchUsers   []string
	searchCommits []string
}

func (f *identityFake) EnterpriseVerifiedDomains(ctx context.Context, slug string) ([]ghclient.VerifiedDomain, ghclient.Capability, error) {
	return f.domains, ghclient.Capability{Determined: true}, nil
}
func (f *identityFake) OrgMemberVerifiedEmails(ctx context.Context, org string) ([]ghclient.MemberIdentity, ghclient.Capability, error) {
	return f.members[org], ghclient.Capability{Determined: true}, nil
}
func (f *identityFake) SSOIdentities(ctx context.Context, slug string) ([]ghclient.SSOIdentity, ghclient.Capability, error) {
	return f.sso, ghclient.Capability{Determined: true}, nil
}
func (f *identityFake) OutsideCollaborators(ctx context.Context, org string) ([]ghclient.User, error) {
	return f.outside[org], nil
}
func (f *identityFake) SearchUsersByEmailDomain(ctx context.Context, domain string) ([]string, ghclient.Capability, error) {
	return f.searchUsers, ghclient.Capability{Determined: true}, nil
}
func (f *identityFake) SearchCommitAuthorsByDomain(ctx context.Context, domain string) ([]string, ghclient.Capability, error) {
	return f.searchCommits, ghclient.Capability{Determined: true}, nil
}

// newIdentityFake: alice carries corporate email and is SSO-linked; bob has
// no corporate email and no SSO link; contractor-x is an outside
// collaborator; rogue-1/rogue-2 appear only in public signals.
func newIdentityFake() *identityFake {
	return &identityFake{
		fakeAPI: &fakeAPI{
			orgs: []ghclient.Organization{{Login: "acme-app", ID: 1}},
			orgSettings: map[string]*ghclient.OrgSettings{
				"acme-app": {Login: "acme-app", DefaultRepositoryPermission: "read", TwoFactorRequired: true},
			},
		},
		domains: []ghclient.VerifiedDomain{{Domain: "acme.com", IsVerified: true, IsApproved: true}},
		members: map[string][]ghclient.MemberIdentity{
			"acme-app": {
				{Login: "alice", VerifiedEmails: []string{"alice@acme.com"}},
				{Login: "bob"},
			},
		},
		sso: []ghclient.SSOIdentity{
			{Login: "alice", NameID: "alice@acme.com"},
			{Login: "gone-dev", NameID: "gone-dev@acme.com"},
		},
		outside:       map[string][]ghclient.User{"acme-app": {{Login: "contractor-x", ID: 7}}},
		searchUsers:   []string{"rogue-1"},
		searchCommits: []string{"rogue-2", "alice"},
	}
}

func identityCfg() *config.Config {
	return &config.Config{
		Enterprise: "acme", Token: "x", Thresholds: config.DefaultThresholds(),
		Identity: config.IdentityConfig{
			ApprovedDomains:               []string{"acme.com"},
			ForbidCorporateEmailOnMembers: true,
			MaxOutsideCollaborators:       0,
		},
	}
}

func assessOne(t *testing.T, api ghclient.GHAPI, cfg *config.Config, id string) rules.Result {
	t.Helper()
	r := rules.ByID(id)
	if r == nil {
		t.Fatalf("rule %s not registered", id)
	}
	sc := engine.New(api, cfg).Assess(context.Background(), []rules.Rule{r})
	if len(sc.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(sc.Results))
	}
	return sc.Results[0]
}

func TestIdentity01_DomainStates(t *testing.T) {
	f := newIdentityFake()
	if res := assessOne(t, f, identityCfg(), "IDENT-01"); res.Status != rules.StatusPass {
		t.Fatalf("verified+approved should pass, got %s (%s)", res.Status, res.Detail)
	}
	f.domains = []ghclient.VerifiedDomain{{Domain: "acme.com", IsVerified: true}}
	if res := assessOne(t, f, identityCfg(), "IDENT-01"); res.Status != rules.StatusWarn {
		t.Fatalf("verified-only should warn, got %s", res.Status)
	}
	f.domains = nil
	if res := assessOne(t, f, identityCfg(), "IDENT-01"); res.Status != rules.StatusFail {
		t.Fatalf("no domains should fail, got %s", res.Status)
	}
}

func TestIdentity07_CorporateEmailPosture(t *testing.T) {
	f := newIdentityFake()
	cfg := identityCfg()
	res := assessOne(t, f, cfg, "IDENT-07")
	if res.Status != rules.StatusWarn {
		t.Fatalf("forbidden posture with carriers should warn, got %s (%s)", res.Status, res.Detail)
	}
	carriers, ok := res.Evidence.(map[string][]string)
	if !ok || len(carriers["alice"]) != 1 || carriers["alice"][0] != "alice@acme.com" {
		t.Fatalf("evidence should list alice's corporate email, got %#v", res.Evidence)
	}
	if _, listed := carriers["bob"]; listed {
		t.Fatal("bob has no corporate email and must not be listed")
	}

	cfg.Identity.ForbidCorporateEmailOnMembers = false
	if res := assessOne(t, f, cfg, "IDENT-07"); res.Status != rules.StatusManual {
		t.Fatalf("inventory posture should be manual, got %s", res.Status)
	}
	cfg.Identity.ForbidCorporateEmailOnMembers = true
	cfg.Identity.AllowUsers = []string{"alice"}
	if res := assessOne(t, f, cfg, "IDENT-07"); res.Status != rules.StatusPass {
		t.Fatalf("allowlisted carrier should pass, got %s", res.Status)
	}
}

func TestIdentity03_SkipsUnderForbidPosture(t *testing.T) {
	f := newIdentityFake()
	cfg := identityCfg()
	if res := assessOne(t, f, cfg, "IDENT-03"); res.Status != rules.StatusSkipped {
		t.Fatalf("IDENT-03 should skip when posture forbids corporate email, got %s", res.Status)
	}
	cfg.Identity.ForbidCorporateEmailOnMembers = false
	res := assessOne(t, f, cfg, "IDENT-03")
	if res.Status != rules.StatusWarn {
		t.Fatalf("bob lacks a corporate email; expected warn, got %s", res.Status)
	}
	if list, _ := res.Evidence.([]string); len(list) != 1 || list[0] != "bob" {
		t.Fatalf("evidence should be [bob], got %#v", res.Evidence)
	}
}

func TestIdentity05_UnlinkedMembers(t *testing.T) {
	res := assessOne(t, newIdentityFake(), identityCfg(), "IDENT-05")
	if res.Status != rules.StatusWarn {
		t.Fatalf("bob is not SSO-linked; expected warn, got %s (%s)", res.Status, res.Detail)
	}
	if list, _ := res.Evidence.([]string); len(list) != 1 || list[0] != "bob" {
		t.Fatalf("evidence should be [bob], got %#v", res.Evidence)
	}
}

func TestIdentity08_RogueSweepExcludesMembers(t *testing.T) {
	res := assessOne(t, newIdentityFake(), identityCfg(), "IDENT-08")
	if res.Status != rules.StatusWarn {
		t.Fatalf("rogue signals present; expected warn, got %s (%s)", res.Status, res.Detail)
	}
	list, _ := res.Evidence.([]string)
	if len(list) != 2 || list[0] != "rogue-1" || list[1] != "rogue-2" {
		t.Fatalf("suspects should be [rogue-1 rogue-2] (alice is a member), got %#v", list)
	}
	if !strings.Contains(res.Detail, "partial") {
		t.Fatalf("detail must state partial coverage, got %q", res.Detail)
	}
}

func TestIdentity04_OutsideCollaborators(t *testing.T) {
	f := newIdentityFake()
	cfg := identityCfg()
	res := assessOne(t, f, cfg, "IDENT-04")
	if res.Status != rules.StatusWarn {
		t.Fatalf("threshold 0 with contractor-x should warn, got %s (%s)", res.Status, res.Detail)
	}
	cfg.Identity.MaxOutsideCollaborators = -1
	if res := assessOne(t, f, cfg, "IDENT-04"); res.Status != rules.StatusManual {
		t.Fatalf("unset threshold should be manual, got %s", res.Status)
	}
}

func TestIdentity04_DestructiveRemediation(t *testing.T) {
	f := newIdentityFake()
	cfg := identityCfg()
	eng := engine.New(f, cfg)

	rr := eng.Remediate(context.Background(), []rules.Rule{rules.ByID("IDENT-04")}, true)
	if len(rr[0].Changes) != 1 || !strings.Contains(rr[0].Changes[0], "contractor-x") {
		t.Fatalf("dry-run should describe the removal, got %+v", rr[0])
	}
	if f.callCount() != 0 {
		t.Fatalf("dry-run must not write: %v", f.calls)
	}

	rr = eng.Remediate(context.Background(), []rules.Rule{rules.ByID("IDENT-04")}, false)
	if !rr[0].Applied || !f.hasCall("RemoveOutsideCollaborator acme-app contractor-x") {
		t.Fatalf("live remediation should remove contractor-x, got %+v calls=%v", rr[0], f.calls)
	}

	// Threshold above zero refuses to choose who to remove.
	cfg.Identity.MaxOutsideCollaborators = 2
	rr = eng.Remediate(context.Background(), []rules.Rule{rules.ByID("IDENT-04")}, false)
	if len(rr[0].Changes) != 0 || len(rr[0].Errors) == 0 {
		t.Fatalf("threshold > 0 must refuse, got %+v", rr[0])
	}
}

func TestDestructiveExcludedFromBulkTargets(t *testing.T) {
	f := newIdentityFake()
	sc := engine.New(f, identityCfg()).Assess(context.Background(), nil)
	for _, r := range engine.RemediableFailures(sc) {
		if r.Meta().Destructive {
			t.Fatalf("bulk targets must exclude destructive rule %s", r.Meta().ID)
		}
	}
	// The warning itself must still be present so operators see it.
	found := false
	for _, res := range sc.Results {
		if res.Meta.ID == "IDENT-04" && res.Status == rules.StatusWarn {
			found = true
		}
	}
	if !found {
		t.Fatal("IDENT-04 warning missing from the scorecard")
	}
}

func TestIdentity09_RosterCrossCheck(t *testing.T) {
	f := newIdentityFake()
	cfg := identityCfg()
	roster := filepath.Join(t.TempDir(), "roster.csv")
	if err := os.WriteFile(roster, []byte("email\nalice@acme.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Identity.RosterCSV = roster
	res := assessOne(t, f, cfg, "IDENT-09")
	if res.Status != rules.StatusFail {
		t.Fatalf("gone-dev is not in the roster; expected fail, got %s (%s)", res.Status, res.Detail)
	}
	list, _ := res.Evidence.([]string)
	if len(list) != 1 || !strings.Contains(list[0], "gone-dev") {
		t.Fatalf("evidence should identify gone-dev, got %#v", list)
	}
	cfg.Identity.RosterCSV = ""
	if res := assessOne(t, f, cfg, "IDENT-09"); res.Status != rules.StatusManual {
		t.Fatalf("no roster should be manual, got %s", res.Status)
	}
}

func TestIdentity10_MailTraceCrossCheck(t *testing.T) {
	f := newIdentityFake()
	cfg := identityCfg()
	trace := filepath.Join(t.TempDir(), "trace.csv")
	body := "Received,RecipientAddress,Subject\n" +
		"2026-08-01,alice@acme.com,Please verify your email address\n" +
		"2026-08-02,ghost@acme.com,Please verify your email address\n" +
		"2026-08-03,someone@other.org,Please verify your email address\n"
	if err := os.WriteFile(trace, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Identity.MailTraceCSV = trace
	res := assessOne(t, f, cfg, "IDENT-10")
	if res.Status != rules.StatusFail {
		t.Fatalf("ghost@acme.com matches no member; expected fail, got %s (%s)", res.Status, res.Detail)
	}
	list, _ := res.Evidence.([]string)
	if len(list) != 1 || list[0] != "ghost@acme.com" {
		t.Fatalf("evidence should be [ghost@acme.com] (alice is known, other.org filtered), got %#v", list)
	}
	cfg.Identity.MailTraceCSV = ""
	if res := assessOne(t, f, cfg, "IDENT-10"); res.Status != rules.StatusManual {
		t.Fatalf("no trace should be manual, got %s", res.Status)
	}
}
