// Package report renders scorecards and remediation logs to JSON, Markdown and HTML.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// JSON renders the scorecard as indented JSON.
func JSON(sc *engine.Scorecard) ([]byte, error) {
	return json.MarshalIndent(sc, "", "  ")
}

var statusIcon = map[rules.Status]string{
	rules.StatusPass:    "✅",
	rules.StatusFail:    "❌",
	rules.StatusWarn:    "⚠️",
	rules.StatusManual:  "📝",
	rules.StatusError:   "🔥",
	rules.StatusSkipped: "➖",
}

// Markdown renders a human-friendly scorecard.
func Markdown(sc *engine.Scorecard) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# GitHub Enterprise Best-Practices Scorecard\n\n")
	fmt.Fprintf(&b, "- **Enterprise:** `%s`\n", sc.Enterprise)
	fmt.Fprintf(&b, "- **Generated:** %s\n", sc.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "- **Score:** %d/100\n\n", sc.Summary.Score)

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Status | Count |\n|---|---|\n")
	for _, s := range []rules.Status{rules.StatusPass, rules.StatusFail, rules.StatusWarn, rules.StatusManual, rules.StatusError} {
		fmt.Fprintf(&b, "| %s %s | %d |\n", statusIcon[s], s, sc.Summary.Counts[string(s)])
	}
	b.WriteString("\n")

	// Group results by domain.
	byDomain := map[rules.Domain][]rules.Result{}
	var domains []rules.Domain
	for _, r := range sc.Results {
		if _, ok := byDomain[r.Meta.Domain]; !ok {
			domains = append(domains, r.Meta.Domain)
		}
		byDomain[r.Meta.Domain] = append(byDomain[r.Meta.Domain], r)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i] < domains[j] })

	for _, d := range domains {
		fmt.Fprintf(&b, "## %s\n\n", strings.Title(string(d)))
		fmt.Fprintf(&b, "| Rule | Status | Severity | Finding |\n|---|---|---|---|\n")
		for _, r := range byDomain[d] {
			detail := strings.ReplaceAll(r.Detail, "\n", " ")
			fmt.Fprintf(&b, "| [%s](%s) %s | %s %s | %s | %s |\n",
				r.Meta.ID, r.Meta.DocsURL, r.Meta.Title,
				statusIcon[r.Status], r.Status, r.Meta.Severity, detail)
		}
		b.WriteString("\n")
	}

	// Remediation guidance for failing rules.
	var fails []rules.Result
	for _, r := range sc.Results {
		if r.Status == rules.StatusFail && r.Remediation != "" {
			fails = append(fails, r)
		}
	}
	if len(fails) > 0 {
		fmt.Fprintf(&b, "## Recommended remediations\n\n")
		for _, r := range fails {
			fmt.Fprintf(&b, "- **%s %s** — %s\n", r.Meta.ID, r.Meta.Title, r.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// RemediationLog renders remediation results as Markdown.
func RemediationLog(results []rules.RemediationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Remediation log\n\n")
	for _, r := range results {
		mode := "APPLIED"
		if r.DryRun {
			mode = "DRY-RUN"
		}
		fmt.Fprintf(&b, "## %s (%s)\n\n", r.RuleID, mode)
		if len(r.Changes) == 0 {
			b.WriteString("- no changes\n\n")
			continue
		}
		for _, c := range r.Changes {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- ⚠️ error: %s\n", e)
		}
		b.WriteString("\n")
	}
	return b.String()
}
