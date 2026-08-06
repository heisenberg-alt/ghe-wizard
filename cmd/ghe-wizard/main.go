// Command ghe-wizard assesses, guides and remediates GitHub Enterprise Cloud
// against GitHub's recommended best practices.
//
// Usage:
//
//	ghe-wizard assess   [--enterprise SLUG] [--format md|json] [--out FILE]
//	ghe-wizard wizard   [--enterprise SLUG] [--yes]
//	ghe-wizard apply    [--enterprise SLUG] [--rules ID,ID] [--dry-run] [--yes]
//	ghe-wizard report   [--enterprise SLUG] [--format md|json] [--out FILE]
//	ghe-wizard serve    [--addr :8080]
//	ghe-wizard list
//
// Auth: set GHE_TOKEN (or GITHUB_TOKEN) to a PAT with enterprise admin scopes,
// and GHE_ENTERPRISE (or --enterprise) to your enterprise slug.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ghe-wizard/ghe-wizard/internal/buildinfo"
	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/policy"
	"github.com/ghe-wizard/ghe-wizard/internal/report"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog" // register rules
	"github.com/ghe-wizard/ghe-wizard/internal/store"
	"github.com/ghe-wizard/ghe-wizard/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "assess":
		err = cmdAssess(args)
	case "wizard":
		err = cmdWizard(args)
	case "apply":
		err = cmdApply(args)
	case "report":
		err = cmdAssess(args) // report is assess with default md output
	case "serve":
		err = cmdServe(args)
	case "list":
		err = cmdList(args)
	case "history":
		err = cmdHistory(args)
	case "version", "--version", "-v":
		fmt.Println(buildinfo.Get().String())
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ghe-wizard — GitHub Enterprise best-practices assessment & setup wizard

Commands:
  assess    Read-only assessment; prints a scorecard (md or json)
  wizard    Interactive walk-through of findings and remediations
  apply     Apply remediations for failing rules (supports --dry-run)
  report    Alias for assess
  serve     Start the web dashboard
  list      List the best-practice rule catalog
  history   Show recorded assessment history (requires --db)
  version   Print version and build information

Global flags (or env GHE_ENTERPRISE / GHE_TOKEN):
  --enterprise SLUG   Enterprise account slug
  --config FILE       JSON config file

Run "ghe-wizard <command> -h" for command flags.
`)
}

// buildEngine wires config, client and engine, validating required inputs.
// When preflight is true, it verifies the token and warns about missing scopes.
// When demo is true, a synthetic data source is used and no token is required.
func buildEngine(fs *flag.FlagSet, enterprise, cfgPath string, preflight, demo bool) (*engine.Engine, *config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if enterprise != "" {
		cfg.Enterprise = enterprise
	}
	if demo {
		if cfg.Enterprise == "" {
			cfg.Enterprise = "acme-corp"
		}
		return engine.New(ghclient.NewDemoAPI(), cfg), cfg, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	client := ghclient.New(cfg.Token, cfg.BaseURL, cfg.GraphQLURL)
	if preflight {
		if login, _, missing, perr := client.Preflight(context.Background()); perr != nil {
			return nil, nil, fmt.Errorf("token preflight failed: %w", perr)
		} else {
			if login != "" {
				fmt.Fprintf(os.Stderr, "Authenticated as %s\n", login)
			}
			if len(missing) > 0 {
				fmt.Fprintf(os.Stderr, "warning: token may be missing scopes: %s\n", strings.Join(missing, ", "))
			}
		}
	}
	return engine.New(client, cfg), cfg, nil
}

func cmdAssess(args []string) error {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	policyPath := fs.String("policy", "", "config-as-code policy file (YAML): disabled rules, thresholds, waivers")
	dbPath := fs.String("db", "", "record this run to a SQLite history database at this path")
	format := fs.String("format", "md", "output format: md|json|html")
	out := fs.String("out", "", "write output to file instead of stdout")
	failOn := fs.String("fail-on", "", "exit non-zero if any finding has this status or worse: fail|warn")
	noPreflight := fs.Bool("no-preflight", false, "skip token scope preflight check")
	demo := fs.Bool("demo", false, "assess synthetic demo data (no token required)")
	fs.Parse(args)

	eng, cfg, err := buildEngine(fs, *enterprise, *cfgPath, !*noPreflight && !*demo, *demo)
	if err != nil {
		return err
	}

	// Config-as-code: load policy, apply thresholds, filter disabled rules.
	pol, err := policy.Load(*policyPath)
	if err != nil {
		return err
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

	ctx := context.Background()
	sc := eng.Assess(ctx, toRun)
	if waived := pol.Apply(sc); waived > 0 {
		fmt.Fprintf(os.Stderr, "applied %d waiver(s) from policy\n", waived)
	}

	// Persist run + report drift against the previous run.
	if *dbPath != "" {
		if err := recordRun(ctx, *dbPath, sc); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not record run:", err)
		}
	}

	var data string
	switch *format {
	case "json":
		b, err := report.JSON(sc)
		if err != nil {
			return err
		}
		data = string(b)
	case "html":
		data = report.HTML(sc)
	default:
		data = report.Markdown(sc)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(data), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (score %d/100)\n", *out, sc.Summary.Score)
	} else {
		fmt.Println(data)
	}

	// CI gating: exit non-zero when findings breach the threshold.
	if *failOn != "" {
		fails := sc.Summary.Counts["fail"]
		warns := sc.Summary.Counts["warn"]
		if (*failOn == "fail" && fails > 0) || (*failOn == "warn" && (fails > 0 || warns > 0)) {
			return fmt.Errorf("assessment gate failed: %d failing, %d warnings (--fail-on=%s)", fails, warns, *failOn)
		}
	}
	return nil
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	ruleList := fs.String("rules", "", "comma-separated rule IDs (default: all failing remediable rules)")
	dryRun := fs.Bool("dry-run", false, "describe changes without applying")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	fs.Parse(args)

	eng, cfg, err := buildEngine(fs, *enterprise, *cfgPath, !*dryRun, false)
	if err != nil {
		return err
	}
	ctx := context.Background()

	var targets []rules.Rule
	if *ruleList != "" {
		for _, id := range strings.Split(*ruleList, ",") {
			if r := rules.ByID(strings.TrimSpace(id)); r != nil {
				targets = append(targets, r)
			} else {
				return fmt.Errorf("unknown rule %q", id)
			}
		}
	} else {
		for _, r := range eng.FailingRules(ctx, nil) {
			if r.Meta().Remediable {
				targets = append(targets, r)
			}
		}
	}
	if len(targets) == 0 {
		fmt.Println("nothing to remediate — no failing remediable rules.")
		return nil
	}

	fmt.Println("The following rules will be remediated:")
	for _, r := range targets {
		fmt.Printf("  - %s %s\n", r.Meta().ID, r.Meta().Title)
	}
	if !*dryRun && !*yes {
		if !confirm(fmt.Sprintf("Apply changes to enterprise %q?", cfg.Enterprise)) {
			fmt.Println("aborted.")
			return nil
		}
	}
	results := eng.Remediate(ctx, targets, *dryRun)
	fmt.Println(report.RemediationLog(results))
	return nil
}

func cmdWizard(args []string) error {
	fs := flag.NewFlagSet("wizard", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	yes := fs.Bool("yes", false, "auto-confirm each remediation")
	dryRun := fs.Bool("dry-run", false, "describe changes without applying")
	fs.Parse(args)

	eng, cfg, err := buildEngine(fs, *enterprise, *cfgPath, !*dryRun, false)
	if err != nil {
		return err
	}
	ctx := context.Background()

	fmt.Printf("\n== GitHub Enterprise Best-Practices Wizard ==\nEnterprise: %s\n\n", cfg.Enterprise)
	fmt.Println("Assessing current state...")
	sc := eng.Assess(ctx, nil)
	fmt.Printf("Overall score: %d/100  (pass %d, fail %d, warn %d, manual %d)\n\n",
		sc.Summary.Score,
		sc.Summary.Counts[string(rules.StatusPass)],
		sc.Summary.Counts[string(rules.StatusFail)],
		sc.Summary.Counts[string(rules.StatusWarn)],
		sc.Summary.Counts[string(rules.StatusManual)])

	for _, res := range sc.Results {
		if res.Status != rules.StatusFail {
			continue
		}
		fmt.Printf("❌ [%s] %s\n   %s\n", res.Meta.ID, res.Meta.Title, res.Detail)
		if res.Remediation != "" {
			fmt.Printf("   Fix: %s\n", res.Remediation)
		}
		fmt.Printf("   Docs: %s\n", res.Meta.DocsURL)
		r := rules.ByID(res.Meta.ID)
		if r == nil || !r.Meta().Remediable {
			fmt.Println("   (manual change required)")
			fmt.Println()
			continue
		}
		if *yes || confirm("   Remediate this now?") {
			rr := eng.Remediate(ctx, []rules.Rule{r}, *dryRun)
			for _, one := range rr {
				for _, c := range one.Changes {
					fmt.Printf("     - %s\n", c)
				}
				for _, e := range one.Errors {
					fmt.Printf("     ! %s\n", e)
				}
			}
		}
		fmt.Println()
	}
	fmt.Println("Wizard complete. Re-run 'assess' to see your updated score.")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	addr := fs.String("addr", ":8080", "listen address")
	demo := fs.Bool("demo", false, "serve synthetic demo data (no token required)")
	dbPath := fs.String("db", "", "record runs to a SQLite history DB (enables trends & /badge.svg)")
	basicUser := fs.String("basic-user", "", "enable HTTP basic auth with this username")
	basicPass := fs.String("basic-pass", "", "HTTP basic auth password (or env GHE_BASIC_PASS)")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *enterprise != "" {
		cfg.Enterprise = *enterprise
	}
	pass := *basicPass
	if pass == "" {
		pass = os.Getenv("GHE_BASIC_PASS")
	}
	opts := web.Options{Addr: *addr, Demo: *demo, DBPath: *dbPath, BasicUser: *basicUser, BasicPass: pass}
	authMsg := ""
	if opts.BasicUser != "" && opts.BasicPass != "" {
		authMsg = " (basic auth enabled)"
	}
	if opts.Demo {
		authMsg += " [demo mode]"
	}
	fmt.Printf("ghe-wizard %s dashboard listening on http://localhost%s%s\n", buildinfo.Get().Version, *addr, authMsg)
	fmt.Println("Press Ctrl+C to stop.")
	return web.ServeWithOptions(opts, cfg)
}

func cmdList(args []string) error {
	all := rules.All()
	sort.Slice(all, func(i, j int) bool { return all[i].Meta().ID < all[j].Meta().ID })
	fmt.Printf("%-8s %-14s %-9s %s\n", "ID", "DOMAIN", "SEVERITY", "TITLE")
	for _, r := range all {
		m := r.Meta()
		rem := ""
		if m.Remediable {
			rem = " [remediable]"
		}
		fmt.Printf("%-8s %-14s %-9s %s%s\n", m.ID, m.Domain, m.Severity, m.Title, rem)
	}
	fmt.Printf("\n%d rules.\n", len(all))
	return nil
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

// recordRun persists a scorecard to the history DB and prints drift vs the
// previous run to stderr.
func recordRun(ctx context.Context, dbPath string, sc *engine.Scorecard) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	run, err := st.SaveRun(ctx, sc)
	if err != nil {
		return err
	}
	drift, err := st.DriftAgainstPrevious(ctx, run.ID, sc)
	if err != nil || drift == nil {
		return err
	}
	sign := "+"
	if drift.ScoreDelta < 0 {
		sign = ""
	}
	fmt.Fprintf(os.Stderr, "drift vs previous run: score %s%d", sign, drift.ScoreDelta)
	if len(drift.NewlyFailing) > 0 {
		fmt.Fprintf(os.Stderr, ", newly failing: %s", strings.Join(drift.NewlyFailing, ","))
	}
	if len(drift.NewlyFixed) > 0 {
		fmt.Fprintf(os.Stderr, ", newly fixed: %s", strings.Join(drift.NewlyFixed, ","))
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

// cmdHistory prints recent recorded runs for an enterprise.
func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	dbPath := fs.String("db", "ghe-wizard.db", "SQLite history database path")
	limit := fs.Int("limit", 20, "number of runs to show")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *enterprise != "" {
		cfg.Enterprise = *enterprise
	}
	if cfg.Enterprise == "" {
		return fmt.Errorf("enterprise slug required (set --enterprise or GHE_ENTERPRISE)")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	runs, err := st.Runs(context.Background(), cfg.Enterprise, *limit)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		fmt.Printf("no recorded runs for %q in %s\n", cfg.Enterprise, *dbPath)
		return nil
	}
	fmt.Printf("%-20s %-6s %-5s %-5s %-5s %-6s\n", "WHEN (UTC)", "SCORE", "FAIL", "WARN", "PASS", "MANUAL")
	for _, r := range runs {
		fmt.Printf("%-20s %-6d %-5d %-5d %-5d %-6d\n",
			r.CreatedAt.Format("2006-01-02 15:04"), r.Score, r.Fail, r.Warn, r.Pass, r.Manual)
	}
	return nil
}
