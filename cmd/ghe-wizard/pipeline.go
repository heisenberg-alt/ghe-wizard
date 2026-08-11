package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/policy"
	"github.com/ghe-wizard/ghe-wizard/internal/profile"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	"github.com/ghe-wizard/ghe-wizard/internal/store"
)

// commonOpts holds the flag values shared by assess, apply and wizard so all
// three commands honor the same config, policy, profile and history wiring.
type commonOpts struct {
	enterprise  *string
	server      *string
	cfgPath     *string
	policyPath  *string
	profileName *string
	dbPath      *string
	demo        *bool
	noPreflight *bool
}

// registerCommonFlags registers the shared assess/apply/wizard flags on fs.
func registerCommonFlags(fs *flag.FlagSet) *commonOpts {
	return &commonOpts{
		enterprise:  fs.String("enterprise", "", "enterprise slug"),
		server:      fs.String("server", "", "GitHub host: github.com (default), a GHES hostname, or a *.ghe.com data-residency domain (or env GHE_SERVER)"),
		cfgPath:     fs.String("config", "", "config file"),
		policyPath:  fs.String("policy", "", "config-as-code policy file (YAML): disabled rules, thresholds, waivers"),
		profileName: fs.String("profile", "", "rule profile to run: "+strings.Join(profile.Names(), "|")),
		dbPath:      fs.String("db", "", "record runs/remediations to a SQLite history database at this path"),
		demo:        fs.Bool("demo", false, "run against synthetic demo data (no token required)"),
		noPreflight: fs.Bool("no-preflight", false, "skip token scope preflight check"),
	}
}

// assessment bundles the engine, config, policy and filtered rule set that a
// command needs after policy + profile wiring.
type assessment struct {
	eng   *engine.Engine
	cfg   *config.Config
	pol   *policy.Policy
	toRun []rules.Rule
}

// buildAssessment wires config, policy, profile and engine the same way for
// every command, so apply and wizard honor the same filters as assess:
// disabled rules never run, profile selection applies, and waivers are
// respected via assessWithPolicy.
func buildAssessment(o *commonOpts) (*assessment, error) {
	eng, cfg, err := buildEngine(*o.enterprise, *o.server, *o.cfgPath, !*o.noPreflight && !*o.demo, *o.demo)
	if err != nil {
		return nil, err
	}
	pol, err := policy.Load(*o.policyPath)
	if err != nil {
		return nil, err
	}
	pol.ApplyThresholds(&cfg.Thresholds.MaxEnterpriseOwners, &cfg.Thresholds.StaleOrgDays)
	known := map[string]bool{}
	for _, r := range rules.All() {
		known[r.Meta().ID] = true
	}
	for _, w := range pol.Validate(known) {
		fmt.Fprintln(os.Stderr, "policy warning:", w)
	}
	toRun := pol.FilterRules(rules.All())
	if *o.profileName != "" {
		p, ok := profile.Get(*o.profileName)
		if !ok {
			return nil, fmt.Errorf("unknown profile %q (available: %s)", *o.profileName, strings.Join(profile.Names(), ", "))
		}
		toRun = p.Filter(toRun)
	}
	return &assessment{eng: eng, cfg: cfg, pol: pol, toRun: toRun}, nil
}

// assessWithPolicy runs the assessment over the filtered rule set and applies
// waivers and severity overrides from the policy.
func (a *assessment) assessWithPolicy(ctx context.Context) *engine.Scorecard {
	sc := a.eng.Assess(ctx, a.toRun)
	if waived := a.pol.Apply(sc); waived > 0 {
		fmt.Fprintf(os.Stderr, "applied %d waiver(s) from policy\n", waived)
	}
	return sc
}

// recordRemediations persists remediation results when a history DB is
// configured. Failures are reported as warnings, never fatal.
func recordRemediations(ctx context.Context, dbPath, enterprise string, results []rules.RemediationResult) {
	if dbPath == "" || len(results) == 0 {
		return
	}
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not open history db:", err)
		return
	}
	defer func() { _ = st.Close() }()
	if err := st.SaveRemediations(ctx, enterprise, results); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not record remediations:", err)
	}
}
