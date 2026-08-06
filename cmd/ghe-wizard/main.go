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

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/report"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog" // register rules
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

Global flags (or env GHE_ENTERPRISE / GHE_TOKEN):
  --enterprise SLUG   Enterprise account slug
  --config FILE       JSON config file

Run "ghe-wizard <command> -h" for command flags.
`)
}

// buildEngine wires config, client and engine, validating required inputs.
func buildEngine(fs *flag.FlagSet, enterprise, cfgPath string) (*engine.Engine, *config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if enterprise != "" {
		cfg.Enterprise = enterprise
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	api := ghclient.New(cfg.Token, cfg.BaseURL, cfg.GraphQLURL)
	return engine.New(api, cfg), cfg, nil
}

func cmdAssess(args []string) error {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	enterprise := fs.String("enterprise", "", "enterprise slug")
	cfgPath := fs.String("config", "", "config file")
	format := fs.String("format", "md", "output format: md|json")
	out := fs.String("out", "", "write output to file instead of stdout")
	fs.Parse(args)

	eng, _, err := buildEngine(fs, *enterprise, *cfgPath)
	if err != nil {
		return err
	}
	sc := eng.Assess(context.Background(), nil)

	var data string
	if *format == "json" {
		b, err := report.JSON(sc)
		if err != nil {
			return err
		}
		data = string(b)
	} else {
		data = report.Markdown(sc)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(data), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (score %d/100)\n", *out, sc.Summary.Score)
		return nil
	}
	fmt.Println(data)
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

	eng, cfg, err := buildEngine(fs, *enterprise, *cfgPath)
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

	eng, cfg, err := buildEngine(fs, *enterprise, *cfgPath)
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
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *enterprise != "" {
		cfg.Enterprise = *enterprise
	}
	fmt.Printf("ghe-wizard dashboard listening on http://localhost%s\n", *addr)
	return web.Serve(*addr, cfg)
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
