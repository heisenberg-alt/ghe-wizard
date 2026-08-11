// Command ghe-wizard assesses, guides and remediates GitHub Enterprise Cloud
// against GitHub's recommended best practices.
//
// Usage:
//
//	ghe-wizard assess   [--enterprise SLUG] [--policy FILE] [--profile NAME] [--db FILE] [--format md|json|html|csv] [--out FILE]
//	ghe-wizard wizard   [--enterprise SLUG] [--policy FILE] [--profile NAME] [--db FILE] [--yes]
//	ghe-wizard apply    [--enterprise SLUG] [--policy FILE] [--profile NAME] [--db FILE] [--rules ID,ID] [--dry-run] [--yes]
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

	"github.com/ghe-wizard/ghe-wizard/internal/ai"
	"github.com/ghe-wizard/ghe-wizard/internal/buildinfo"
	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/notify"
	"github.com/ghe-wizard/ghe-wizard/internal/profile"
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
	case "explain", "ai-plan", "ask":
		err = cmdAI(cmd, args)
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
  explain   AI: explain a finding (explain <RULE-ID>; needs GHE_AI_* env)
  ai-plan   AI: prioritized remediation plan (needs GHE_AI_* env)
  ask       AI: ask a question about the scorecard (needs GHE_AI_* env)
  version   Print version and build information

Global flags (or env GHE_ENTERPRISE / GHE_TOKEN):
  --enterprise SLUG   Enterprise account slug
  --config FILE       JSON config file

Run "ghe-wizard <command> -h" for command flags.
`)
}

// buildEngine wires config, client and engine, validating required inputs.
// When preflight is true, it verifies the credentials and warns about missing
// scopes. When demo is true, a synthetic data source is used and no token is
// required. A non-empty server selects GHES or a data-residency host.
func buildEngine(enterprise, server, cfgPath string, preflight, demo bool) (*engine.Engine, *config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if enterprise != "" {
		cfg.Enterprise = enterprise
	}
	if server != "" {
		cfg.Server = server
	}
	if err := cfg.DeriveEndpoints(); err != nil {
		return nil, nil, err
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
	client, err := ghclient.NewFromConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	// Detect GitHub Enterprise Server (best-effort) so cloud-only rules skip.
	if cfg.BaseURL != "" && cfg.BaseURL != config.DefaultBaseURL {
		if v, isGHES, merr := client.ServerMeta(context.Background()); merr == nil && isGHES {
			cfg.TargetGHES = true
			cfg.ServerVersion = v
			fmt.Fprintf(os.Stderr, "Target: GitHub Enterprise Server %s (cloud-only rules will be skipped)\n", v)
		}
	}
	if preflight {
		if cfg.Token == "" && cfg.HasAppAuth() {
			// Installation tokens are not users and carry no OAuth scopes; a
			// one-shot mint verifies the app credentials instead of /user.
			if err := client.PreflightAppAuth(context.Background()); err != nil {
				return nil, nil, fmt.Errorf("github app preflight failed: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Authenticated as GitHub App installation %d\n", cfg.AppInstallationID)
		} else {
			login, _, missing, perr := client.Preflight(context.Background())
			if perr != nil {
				return nil, nil, fmt.Errorf("token preflight failed: %w", perr)
			}
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
	o := registerCommonFlags(fs)
	format := fs.String("format", "md", "output format: md|json|html|csv")
	out := fs.String("out", "", "write output to file instead of stdout")
	failOn := fs.String("fail-on", "", "exit non-zero if any finding has this status or worse: fail|warn")
	notifyURL := fs.String("notify-webhook", os.Getenv("GHE_NOTIFY_WEBHOOK"),
		"Slack/Teams/Discord/JSON webhook URL to post the scorecard to (or env GHE_NOTIFY_WEBHOOK)")
	notifyFormat := fs.String("notify-format", "auto", "webhook payload format: auto|slack|teams|discord|json")
	notifyOnlyAlert := fs.Bool("notify-only-alert", false, "only send a notification on a score drop or new failure")
	_ = fs.Parse(args)

	a, err := buildAssessment(o)
	if err != nil {
		return err
	}

	ctx := context.Background()
	sc := a.assessWithPolicy(ctx)

	// Persist run + compute drift against the previous run.
	var drift *store.Drift
	if *o.dbPath != "" {
		drift, err = recordRun(ctx, *o.dbPath, sc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not record run:", err)
		}
	}

	// Optional ChatOps notification.
	if *notifyURL != "" {
		send := true
		if *notifyOnlyAlert {
			var reason string
			send, reason = notify.ShouldAlert(sc, drift, 0)
			if send {
				fmt.Fprintln(os.Stderr, "alert:", reason)
			}
		}
		if send {
			if nerr := notify.SendFormat(ctx, *notifyFormat, *notifyURL, sc, drift); nerr != nil {
				fmt.Fprintln(os.Stderr, "warning: notification failed:", nerr)
			}
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
	case "csv":
		data = report.EvidenceCSV(sc)
	default:
		data = report.Markdown(sc)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(data), 0o644); err != nil { // #nosec G306 -- report/scorecard output is non-sensitive; world-readable is intentional
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
	o := registerCommonFlags(fs)
	ruleList := fs.String("rules", "", "comma-separated rule IDs (default: all failing remediable rules)")
	dryRun := fs.Bool("dry-run", false, "describe changes without applying")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	_ = fs.Parse(args)

	a, err := buildAssessment(o)
	if err != nil {
		return err
	}
	ctx := context.Background()
	sc := a.assessWithPolicy(ctx)

	var targets []rules.Rule
	if *ruleList != "" {
		// Explicit IDs: honor policy — skip rules that were disabled, filtered
		// out by the profile, or waived, with a warning.
		statusByID := map[string]rules.Status{}
		for _, res := range sc.Results {
			statusByID[res.Meta.ID] = res.Status
		}
		for _, id := range strings.Split(*ruleList, ",") {
			id = strings.TrimSpace(id)
			r := rules.ByID(id)
			if r == nil {
				return fmt.Errorf("unknown rule %q", id)
			}
			st, ran := statusByID[id]
			switch {
			case !ran:
				fmt.Fprintf(os.Stderr, "warning: skipping %s: disabled by policy or excluded by profile\n", id)
			case st == rules.StatusWaived:
				fmt.Fprintf(os.Stderr, "warning: skipping %s: waived by policy\n", id)
			default:
				targets = append(targets, r)
			}
		}
	} else {
		targets = engine.RemediableFailures(sc)
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
		if !confirm(fmt.Sprintf("Apply changes to enterprise %q?", a.cfg.Enterprise)) {
			fmt.Println("aborted.")
			return nil
		}
	}
	results := a.eng.Remediate(ctx, targets, *dryRun)
	fmt.Println(report.RemediationLog(results))
	recordRemediations(ctx, *o.dbPath, a.cfg.Enterprise, results)
	return nil
}

func cmdWizard(args []string) error {
	fs := flag.NewFlagSet("wizard", flag.ExitOnError)
	o := registerCommonFlags(fs)
	yes := fs.Bool("yes", false, "auto-confirm each remediation")
	dryRun := fs.Bool("dry-run", false, "describe changes without applying")
	_ = fs.Parse(args)

	a, err := buildAssessment(o)
	if err != nil {
		return err
	}
	ctx := context.Background()

	fmt.Printf("\n== GitHub Enterprise Best-Practices Wizard ==\nEnterprise: %s\n\n", a.cfg.Enterprise)
	fmt.Println("Assessing current state...")
	sc := a.assessWithPolicy(ctx)
	fmt.Printf("Overall score: %d/100  (pass %d, fail %d, warn %d, manual %d)\n\n",
		sc.Summary.Score,
		sc.Summary.Counts[string(rules.StatusPass)],
		sc.Summary.Counts[string(rules.StatusFail)],
		sc.Summary.Counts[string(rules.StatusWarn)],
		sc.Summary.Counts[string(rules.StatusManual)])

	var recorded []rules.RemediationResult
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
			rr := a.eng.Remediate(ctx, []rules.Rule{r}, *dryRun)
			recorded = append(recorded, rr...)
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
	recordRemediations(ctx, *o.dbPath, a.cfg.Enterprise, recorded)
	fmt.Println("Wizard complete. Re-run 'assess' to see your updated score.")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	server := fs.String("server", "", "GitHub host: github.com (default), a GHES hostname, or a *.ghe.com data-residency domain")
	cfgPath := fs.String("config", "", "config file")
	addr := fs.String("addr", ":8080", "listen address")
	demo := fs.Bool("demo", false, "serve synthetic demo data (no token required)")
	dbPath := fs.String("db", "", "record runs to a SQLite history DB (enables trends & /badge.svg)")
	policyPath := fs.String("policy", "", "config-as-code policy file (YAML): disabled rules, thresholds, waivers")
	profileName := fs.String("profile", "", "rule profile to run: "+strings.Join(profile.Names(), "|"))
	basicUser := fs.String("basic-user", "", "enable HTTP basic auth with this username")
	basicPass := fs.String("basic-pass", "", "HTTP basic auth password (or env GHE_BASIC_PASS)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *enterprise != "" {
		cfg.Enterprise = *enterprise
	}
	if *server != "" {
		cfg.Server = *server
	}
	if err := cfg.DeriveEndpoints(); err != nil {
		return err
	}
	// Detect GitHub Enterprise Server once at startup (best-effort) so
	// per-request engines skip cloud-only rules.
	if !*demo && cfg.Token != "" && cfg.BaseURL != config.DefaultBaseURL {
		if client, cerr := ghclient.NewFromConfig(cfg); cerr == nil {
			if v, isGHES, merr := client.ServerMeta(context.Background()); merr == nil && isGHES {
				cfg.TargetGHES = true
				cfg.ServerVersion = v
				fmt.Fprintf(os.Stderr, "Target: GitHub Enterprise Server %s (cloud-only rules will be skipped)\n", v)
			}
		}
	}
	pass := *basicPass
	if pass == "" {
		pass = os.Getenv("GHE_BASIC_PASS")
	}
	opts := web.Options{Addr: *addr, Demo: *demo, DBPath: *dbPath,
		PolicyPath: *policyPath, ProfileName: *profileName,
		BasicUser: *basicUser, BasicPass: pass}
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

// cmdList prints the rule catalog. It returns an error to match the uniform
// command-handler signature used by the dispatcher, even though it cannot fail.
//
//nolint:unparam // uniform command-handler signature
func cmdList(_ []string) error {
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

// recordRun persists a scorecard to the history DB, prints drift vs the
// previous run to stderr, and returns the drift (nil for the first run).
func recordRun(ctx context.Context, dbPath string, sc *engine.Scorecard) (*store.Drift, error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()
	run, err := st.SaveRun(ctx, sc)
	if err != nil {
		return nil, err
	}
	drift, err := st.DriftAgainstPrevious(ctx, run.ID, sc)
	if err != nil || drift == nil {
		return drift, err
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
	return drift, nil
}

// cmdHistory prints recent recorded runs (or remediation logs) for an enterprise.
func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	dbPath := fs.String("db", "ghe-wizard.db", "SQLite history database path")
	limit := fs.Int("limit", 20, "number of entries to show")
	remediations := fs.Bool("remediations", false, "show recorded remediation logs instead of scan runs")
	_ = fs.Parse(args)

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
	defer func() { _ = st.Close() }()
	if *remediations {
		logs, err := st.Remediations(context.Background(), cfg.Enterprise, *limit)
		if err != nil {
			return err
		}
		if len(logs) == 0 {
			fmt.Printf("no recorded remediations for %q in %s\n", cfg.Enterprise, *dbPath)
			return nil
		}
		fmt.Printf("%-20s %-8s %-7s %-7s %s\n", "WHEN (UTC)", "RULE", "APPLIED", "DRY-RUN", "CHANGES")
		for _, l := range logs {
			fmt.Printf("%-20s %-8s %-7v %-7v %s\n",
				l.CreatedAt.Format("2006-01-02 15:04"), l.RuleID, l.Applied, l.DryRun, strings.Join(l.Changes, "; "))
		}
		return nil
	}
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

// aiClientFromEnv builds an AI client from GHE_AI_ENDPOINT/GHE_AI_MODEL/GHE_AI_KEY.
func aiClientFromEnv() *ai.Client {
	return ai.New(ai.Config{
		Endpoint: os.Getenv("GHE_AI_ENDPOINT"),
		Model:    os.Getenv("GHE_AI_MODEL"),
		APIKey:   os.Getenv("GHE_AI_KEY"),
	})
}

// cmdAI implements the optional AI-assisted commands: explain <RULE-ID>,
// ai-plan, and ask "<question>". They run an assessment and then call the
// configured OpenAI-compatible endpoint. AI is a no-op when unconfigured.
func cmdAI(sub string, args []string) error {
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	server := fs.String("server", "", "GitHub host: github.com (default), a GHES hostname, or a *.ghe.com data-residency domain")
	cfgPath := fs.String("config", "", "config file")
	demo := fs.Bool("demo", false, "assess synthetic demo data (no token required)")
	_ = fs.Parse(args)
	rest := fs.Args()

	client := aiClientFromEnv()
	if !client.Enabled() {
		return fmt.Errorf("AI not configured: set GHE_AI_ENDPOINT, GHE_AI_MODEL and GHE_AI_KEY")
	}

	eng, _, err := buildEngine(*enterprise, *server, *cfgPath, !*demo, *demo)
	if err != nil {
		return err
	}
	ctx := context.Background()
	sc := eng.Assess(ctx, nil)

	var out string
	switch sub {
	case "explain":
		if len(rest) == 0 {
			return fmt.Errorf("usage: ghe-wizard explain <RULE-ID>")
		}
		id := strings.ToUpper(rest[0])
		var found *rules.Result
		for i := range sc.Results {
			if sc.Results[i].Meta.ID == id {
				found = &sc.Results[i]
				break
			}
		}
		if found == nil {
			return fmt.Errorf("rule %q not found in assessment", id)
		}
		out, err = client.Explain(ctx, *found)
	case "ai-plan":
		out, err = client.PrioritizePlan(ctx, sc)
	case "ask":
		if len(rest) == 0 {
			return fmt.Errorf("usage: ghe-wizard ask \"<question>\"")
		}
		out, err = client.Query(ctx, sc, strings.Join(rest, " "))
	}
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
