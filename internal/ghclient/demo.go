package ghclient

import (
	"context"
	"sync"
	"time"
)

// DemoAPI is a built-in, credential-free data source that returns realistic
// synthetic data for evaluation and demos. It implements GHAPI, so the real
// assessment engine runs against it unchanged and produces a representative
// mix of pass/fail/warn/manual findings. It also implements WriteAPI with
// in-memory state, so demo-mode remediations visibly improve subsequent
// assessments within the same process (e.g. the dashboard's apply flow).
type DemoAPI struct {
	mu           sync.Mutex
	basePerm     map[string]string // org -> overridden default repository permission
	twoFA        map[string]bool   // org -> overridden 2FA requirement
	secretScan   map[string]bool   // org -> overridden secret-scanning + push-protection defaults
	dependabot   map[string]bool   // org -> overridden dependency-graph/Dependabot defaults
	publicRepo   map[string]bool   // org -> overridden members-can-create-public-repos
	signoff      map[string]bool   // org -> overridden web-commit-signoff requirement
	removedOC    map[string]bool   // "org/login" -> outside collaborator removed via remediation
	notifOn      map[string]bool   // org -> overridden notification restriction
	forkPriv     map[string]bool   // org -> overridden members-can-fork-private
	csDefault    map[string]bool   // org -> code security default configured via remediation
	workflowPerm string            // overridden enterprise default workflow permissions
	wfHardened   bool              // workflow permissions hardened via remediation
	allowedActs  string            // overridden enterprise allowed-actions policy
	props        []CustomProperty  // custom properties added via remediation
	rulesets     []Ruleset         // rulesets created via remediation
}

// NewDemoAPI returns a demo data source.
func NewDemoAPI() *DemoAPI {
	return &DemoAPI{
		basePerm:   map[string]string{},
		twoFA:      map[string]bool{},
		secretScan: map[string]bool{},
		dependabot: map[string]bool{},
		publicRepo: map[string]bool{},
		signoff:    map[string]bool{},
		removedOC:  map[string]bool{},
		notifOn:    map[string]bool{},
		forkPriv:   map[string]bool{},
		csDefault:  map[string]bool{},
	}
}

func (d *DemoAPI) Enterprise(ctx context.Context, slug string) (*Enterprise, error) {
	ent := &Enterprise{
		Slug:                       slug,
		Name:                       "Acme Corporation",
		SAMLEnabled:                true,
		IPAllowListEnabled:         false,
		DefaultWorkflowPermissions: "write",
		CanApprovePRReviews:        true,
		AllowedActions:             "all",
		EnabledOrganizations:       "all",
		Capabilities: map[string]Capability{
			"emu": {Determined: false, Reason: "EMU type not exposed via API; confirm manually"},
		},
	}
	d.mu.Lock()
	if d.workflowPerm != "" {
		ent.DefaultWorkflowPermissions = d.workflowPerm
	}
	if d.wfHardened {
		ent.CanApprovePRReviews = false
	}
	if d.allowedActs != "" {
		ent.AllowedActions = d.allowedActs
	}
	d.mu.Unlock()
	return ent, nil
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
		"acme-payments": {Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: true,
			SecretScanningEnabled: true, SecretScanningPushProtect: true,
			DependencyGraphEnabled: true, DependabotAlertsEnabled: true, DependabotSecurityUpdates: true,
			WebCommitSignoffRequired: true},
		"acme-platform": {Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: true,
			MembersCanCreateRepos: true,
			SecretScanningEnabled: true, SecretScanningPushProtect: true,
			DependencyGraphEnabled: true, DependabotAlertsEnabled: true},
		"acme-web": {Login: org, DefaultRepositoryPermission: "write",
			MembersCanCreateRepos: true, MembersCanCreatePublicRepos: true,
			MembersCanForkPrivateRepos: true},
		"acme-labs": {Login: org, DefaultRepositoryPermission: "read",
			MembersCanCreateRepos: true},
		"acme-legacy": {Login: org, DefaultRepositoryPermission: "admin",
			MembersCanCreateRepos: true, MembersCanCreatePublicRepos: true,
			MembersCanForkPrivateRepos: true},
	}
	if s, ok := settings[org]; ok {
		d.applyOverrides(s)
		return s, nil
	}
	s := &OrgSettings{Login: org, DefaultRepositoryPermission: "read", TwoFactorRequired: true,
		SecretScanningEnabled: true, SecretScanningPushProtect: true,
		DependencyGraphEnabled: true, DependabotAlertsEnabled: true,
		WebCommitSignoffRequired: true}
	d.applyOverrides(s)
	return s, nil
}

// applyOverrides layers any demo-remediation state onto freshly built settings.
func (d *DemoAPI) applyOverrides(s *OrgSettings) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.basePerm[s.Login]; ok {
		s.DefaultRepositoryPermission = p
	}
	if v, ok := d.twoFA[s.Login]; ok {
		s.TwoFactorRequired = v
	}
	if v, ok := d.secretScan[s.Login]; ok {
		s.SecretScanningEnabled = v
		s.SecretScanningPushProtect = v
	}
	if v, ok := d.dependabot[s.Login]; ok {
		s.DependencyGraphEnabled = v
		s.DependabotAlertsEnabled = v
		s.DependabotSecurityUpdates = v
	}
	if v, ok := d.publicRepo[s.Login]; ok {
		s.MembersCanCreatePublicRepos = v
	}
	if v, ok := d.signoff[s.Login]; ok {
		s.WebCommitSignoffRequired = v
	}
	if v, ok := d.forkPriv[s.Login]; ok {
		s.MembersCanForkPrivateRepos = v
	}
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
	base := []CustomProperty{
		{Name: "data-classification", ValueType: "single_select", Required: true},
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append(base, d.props...), nil
}

func (d *DemoAPI) EnterpriseRulesets(ctx context.Context, slug string) ([]Ruleset, error) {
	// No active rulesets by default -> POL-02 fails (and is remediable in the
	// demo); rulesets created via demo remediation appear here.
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Ruleset{}, d.rulesets...), nil
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

// --- WriteAPI: demo remediations mutate in-memory state --------------------

func (d *DemoAPI) SetOrgDefaultRepositoryPermission(ctx context.Context, org, perm string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.basePerm[org] = perm
	return nil
}

func (d *DemoAPI) SetOrgTwoFactorRequired(ctx context.Context, org string, required bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.twoFA[org] = required
	return nil
}

func (d *DemoAPI) SetOrgSecretScanningDefaults(ctx context.Context, org string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.secretScan[org] = enabled
	return nil
}

func (d *DemoAPI) SetOrgDependabotDefaults(ctx context.Context, org string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dependabot[org] = true
	return nil
}

func (d *DemoAPI) SetOrgMembersCanCreatePublicRepos(ctx context.Context, org string, allowed bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.publicRepo[org] = allowed
	return nil
}

func (d *DemoAPI) SetOrgWebCommitSignoff(ctx context.Context, org string, required bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signoff[org] = required
	return nil
}

func (d *DemoAPI) HardenEnterpriseWorkflowPermissions(ctx context.Context, slug string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.workflowPerm = "read"
	d.wfHardened = true
	return nil
}

func (d *DemoAPI) SetEnterpriseAllowedActionsSelected(ctx context.Context, slug, enabledOrganizations string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allowedActs = "selected"
	return nil
}

func (d *DemoAPI) SetOrgMembersCanForkPrivate(ctx context.Context, org string, allowed bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forkPriv[org] = allowed
	return nil
}

func (d *DemoAPI) CreateOrgSecurityDefault(ctx context.Context, org string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.csDefault[org] = true
	return nil
}

// --- GovAPI: synthetic org-governance data ----------------------------------

func (d *DemoAPI) OrgTeams(ctx context.Context, org string) ([]Team, Capability, error) {
	teams := map[string][]Team{
		"acme-platform": {
			{Slug: "platform-team", Name: "Platform Team", Members: 5, Maintainers: 2, Repos: 3},
			{Slug: "old-guild", Name: "Old Guild", Members: 0, Maintainers: 0, Repos: 0},
			{Slug: "docs-team", Name: "Docs Team", Members: 3, Maintainers: 0, Repos: 1},
		},
		"acme-payments": {
			{Slug: "payments-core", Name: "Payments Core", Members: 8, Maintainers: 2, Repos: 4},
		},
	}
	return teams[org], Capability{Determined: true}, nil
}

func (d *DemoAPI) RepoDirectCollaboratorCount(ctx context.Context, fullName string) (int, error) {
	direct := map[string]int{
		"acme-web/api":            2,
		"acme-legacy/old-service": 1,
	}
	return direct[fullName], nil
}

func (d *DemoAPI) ExternalGroupCount(ctx context.Context, org string) (int, Capability, error) {
	// No IdP groups linked anywhere -> TEAM-02 flags it.
	return 0, Capability{Determined: true}, nil
}

func (d *DemoAPI) CodeSecurityDefaultConfigured(ctx context.Context, org string) (bool, Capability, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.csDefault[org], Capability{Determined: true}, nil
}

func (d *DemoAPI) RemoveOutsideCollaborator(ctx context.Context, org, login string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removedOC[org+"/"+login] = true
	return nil
}

// --- IdentityAPI: synthetic identity-governance data ------------------------

func (d *DemoAPI) EnterpriseVerifiedDomains(ctx context.Context, slug string) ([]VerifiedDomain, Capability, error) {
	// Verified but not approved -> IDENT-01 flags the missing approval step.
	return []VerifiedDomain{
		{Domain: "acme-corp.com", IsVerified: true, IsApproved: false},
	}, Capability{Determined: true}, nil
}

func (d *DemoAPI) OrgMemberVerifiedEmails(ctx context.Context, org string) ([]MemberIdentity, Capability, error) {
	members := map[string][]MemberIdentity{
		"acme-payments": {
			{Login: "alice", VerifiedEmails: []string{"alice@acme-corp.com"}},
			{Login: "bob", VerifiedEmails: []string{"bob@acme-corp.com"}},
		},
		"acme-platform": {
			{Login: "carol"},
			{Login: "dave"},
		},
		"acme-web": {
			{Login: "erin", VerifiedEmails: []string{"erin@acme-corp.com"}},
			{Login: "frank"},
		},
		"acme-labs": {
			{Login: "grace"},
		},
		"acme-legacy": {
			// Duplicate membership across orgs, like real enterprises.
			{Login: "bob", VerifiedEmails: []string{"bob@acme-corp.com"}},
		},
	}
	return members[org], Capability{Determined: true}, nil
}

func (d *DemoAPI) SSOIdentities(ctx context.Context, slug string) ([]SSOIdentity, Capability, error) {
	// erin, frank and grace are not SSO-linked -> IDENT-05 flags them.
	return []SSOIdentity{
		{Login: "alice", NameID: "alice@acme-corp.com"},
		{Login: "bob", NameID: "bob@acme-corp.com"},
		{Login: "carol", NameID: "carol@acme-corp.com"},
		{Login: "dave", NameID: "dave@acme-corp.com"},
		{Login: "", NameID: "departed-dev@acme-corp.com"}, // identity without a linked account
	}, Capability{Determined: true}, nil
}

func (d *DemoAPI) OutsideCollaborators(ctx context.Context, org string) ([]User, error) {
	base := map[string][]User{
		"acme-web":    {{Login: "contractor-jane", ID: 9001}},
		"acme-legacy": {{Login: "old-vendor-bot", ID: 9002}},
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []User
	for _, u := range base[org] {
		if !d.removedOC[org+"/"+u.Login] {
			out = append(out, u)
		}
	}
	return out, nil
}

func (d *DemoAPI) OrgNotificationRestriction(ctx context.Context, org string) (bool, Capability, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.notifOn[org]; ok {
		return v, Capability{Determined: true}, nil
	}
	// Only the payments org restricts notifications by default.
	return org == "acme-payments", Capability{Determined: true}, nil
}

func (d *DemoAPI) SetOrgNotificationRestriction(ctx context.Context, org string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifOn[org] = enabled
	return nil
}

func (d *DemoAPI) SearchUsersByEmailDomain(ctx context.Context, domain string) ([]string, Capability, error) {
	if domain == "acme-corp.com" {
		return []string{"rogue-dev-1"}, Capability{Determined: true}, nil
	}
	return nil, Capability{Determined: true}, nil
}

func (d *DemoAPI) SearchCommitAuthorsByDomain(ctx context.Context, domain string) ([]string, Capability, error) {
	if domain == "acme-corp.com" {
		return []string{"rogue-dev-2", "alice"}, Capability{Determined: true}, nil
	}
	return nil, Capability{Determined: true}, nil
}

func (d *DemoAPI) CreateEnterpriseCustomProperty(ctx context.Context, slug, name, valueType string, required bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.props = append(d.props, CustomProperty{Name: name, ValueType: valueType, Required: required})
	return nil
}

func (d *DemoAPI) CreateEnterpriseRuleset(ctx context.Context, slug string, payload any) error {
	name := "demo-ruleset"
	if m, ok := payload.(map[string]any); ok {
		if n, ok := m["name"].(string); ok && n != "" {
			name = n
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rulesets = append(d.rulesets, Ruleset{
		ID: int64(9000 + len(d.rulesets)), Name: name, Target: "branch", Enforcement: "active",
	})
	return nil
}
