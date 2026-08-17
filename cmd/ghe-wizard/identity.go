package main

import (
	"context"
	"flag"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/notify"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// cmdIdentity dispatches the identity-governance subcommands.
func cmdIdentity(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ghe-wizard identity <warn|transport-rule> [flags]")
	}
	switch args[0] {
	case "warn":
		return cmdIdentityWarn(args[1:])
	case "transport-rule":
		return cmdIdentityTransportRule(args[1:])
	default:
		return fmt.Errorf("unknown identity subcommand %q (use warn or transport-rule)", args[0])
	}
}

// warnTarget is one row of the warning campaign.
type warnTarget struct {
	Population string // member | rogue-public-signal | rogue-confirmed-signup | departed
	Identifier string // login or email address
	Emails     string // corporate emails involved, when known
	SourceRule string
	Action     string
	Deadline   string
}

// cmdIdentityWarn runs the identity rules and generates the notification
// campaign for every affected principal: enterprise members carrying
// corporate email, rogue accounts outside the enterprise, and departed
// employees still linked. Compliance is tracked by re-running the assessment
// (drift shows warned findings turning fixed).
func cmdIdentityWarn(args []string) error {
	fs := flag.NewFlagSet("identity warn", flag.ExitOnError)
	o := registerCommonFlags(fs)
	graceDays := fs.Int("grace-days", 14, "days until the stated deadline")
	format := fs.String("format", "csv", "output format: csv|md")
	out := fs.String("out", "", "write the campaign to a file instead of stdout")
	webhook := fs.String("webhook", "", "post a campaign summary to this chat webhook (Slack/Teams/Discord/JSON)")
	webhookFormat := fs.String("webhook-format", "auto", "webhook payload format: auto|slack|teams|discord|json")
	email := fs.Bool("email", false, "send per-user warning emails via SMTP (GHE_SMTP_HOST host:port, GHE_SMTP_FROM; optional GHE_SMTP_USER/GHE_SMTP_PASS)")
	_ = fs.Parse(args)

	a, err := buildAssessment(o)
	if err != nil {
		return err
	}
	// Only the identity rules are needed for the campaign.
	var idRules []rules.Rule
	for _, r := range a.toRun {
		if r.Meta().Domain == rules.DomainIdentity {
			idRules = append(idRules, r)
		}
	}
	if len(idRules) == 0 {
		return fmt.Errorf("no identity rules to run (check policy disabled_rules / profile)")
	}
	a.toRun = idRules
	ctx := context.Background()
	sc := a.assessWithPolicy(ctx)

	deadline := time.Now().AddDate(0, 0, *graceDays).Format("2006-01-02")
	targets := collectWarnTargets(sc, deadline)
	if len(targets) == 0 {
		fmt.Println("No warning targets found — no corporate-email findings in the identity rules.")
		fmt.Println("(Members are included only when identity.forbid_corporate_email_on_members is set;")
		fmt.Println(" rogue and departed detection need approved domains, and optionally roster/mail-trace imports.)")
		return nil
	}
	counts := map[string]int{}
	for _, t := range targets {
		counts[t.Population]++
	}
	summary := fmt.Sprintf("ghe-wizard identity campaign for %s: %d target(s) — members=%d, rogue-public=%d, rogue-confirmed=%d, departed=%d. Deadline %s.",
		sc.Enterprise, len(targets), counts["member"], counts["rogue-public-signal"], counts["rogue-confirmed-signup"], counts["departed"], deadline)

	var data string
	switch *format {
	case "md":
		data = warnMarkdown(sc.Enterprise, targets, deadline)
	case "csv":
		data = warnCSV(targets)
	default:
		return fmt.Errorf("unknown format %q (use csv or md)", *format)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(data), 0o600); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d target(s))\n", *out, len(targets))
	} else {
		fmt.Print(data)
	}

	if *webhook != "" {
		if nerr := notify.Message(ctx, *webhookFormat, *webhook, summary); nerr != nil {
			fmt.Fprintln(os.Stderr, "warning: webhook summary failed:", nerr)
		} else {
			fmt.Fprintln(os.Stderr, "webhook summary posted")
		}
	}
	if *email {
		sent, skipped, serr := sendCampaignEmails(targets)
		if serr != nil {
			fmt.Fprintln(os.Stderr, "warning: email campaign stopped:", serr)
		}
		fmt.Fprintf(os.Stderr, "emails: %d sent, %d skipped (no known corporate mailbox)\n", sent, skipped)
	}
	fmt.Fprintln(os.Stderr, summary)
	fmt.Fprintln(os.Stderr, "track compliance by re-running: ghe-wizard assess --db <file> (drift shows remediated findings)")
	return nil
}

// emailAddressFor returns the target's corporate mailbox when one is known
// and parses as a valid address (imported CSV values are untrusted).
func emailAddressFor(t warnTarget) string {
	candidate := ""
	if strings.Contains(t.Identifier, "@") && !strings.Contains(t.Identifier, " ") {
		candidate = t.Identifier
	} else if t.Emails != "" {
		candidate = strings.Fields(t.Emails)[0]
	}
	if candidate == "" {
		return ""
	}
	addr, err := mail.ParseAddress(candidate)
	if err != nil {
		return ""
	}
	return addr.Address
}

// sendCampaignEmails delivers one warning email per target with a known
// corporate mailbox, via plain SMTP (stdlib; STARTTLS when the server
// supports it). It stops on the first send error so a bad relay does not
// half-spam the company.
func sendCampaignEmails(targets []warnTarget) (sent, skipped int, err error) {
	host := os.Getenv("GHE_SMTP_HOST") // host:port
	from := os.Getenv("GHE_SMTP_FROM")
	if host == "" || from == "" {
		return 0, 0, fmt.Errorf("set GHE_SMTP_HOST (host:port) and GHE_SMTP_FROM to send email")
	}
	fromAddr, ferr := mail.ParseAddress(from)
	if ferr != nil {
		return 0, 0, fmt.Errorf("GHE_SMTP_FROM is not a valid address: %w", ferr)
	}
	var auth smtp.Auth
	if u := os.Getenv("GHE_SMTP_USER"); u != "" {
		hostname := host
		if i := strings.IndexByte(host, ':'); i > 0 {
			hostname = host[:i]
		}
		auth = smtp.PlainAuth("", u, os.Getenv("GHE_SMTP_PASS"), hostname)
	}
	for _, t := range targets {
		to := emailAddressFor(t)
		if to == "" {
			skipped++
			continue
		}
		// Addresses are validated via mail.ParseAddress above and every
		// header value is CR/LF-stripped in buildWarnEmail, so imported CSV
		// values cannot inject SMTP commands or headers.
		msg := buildWarnEmail(fromAddr.Address, to, t)
		if serr := smtp.SendMail(host, auth, fromAddr.Address, []string{to}, msg); serr != nil { // #nosec G707 -- to/from parsed with mail.ParseAddress; headers sanitized
			return sent, skipped, fmt.Errorf("send to %s: %w", to, serr)
		}
		sent++
	}
	return sent, skipped, nil
}

// headerSafe strips CR/LF so untrusted values cannot inject SMTP headers.
func headerSafe(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", " ")
}

// buildWarnEmail composes the per-user plain-text warning message.
func buildWarnEmail(from, to string, t warnTarget) []byte {
	subject := headerSafe("Action required: corporate email on a personal GitHub account (deadline " + t.Deadline + ")")
	body := fmt.Sprintf(
		"Hello,\r\n\r\nOur GitHub governance scan (%s) flagged: %s\r\n\r\nRequired action by %s:\r\n%s\r\n\r\nQuestions? Reply to this address.\r\n",
		headerSafe(t.SourceRule), headerSafe(t.Identifier), headerSafe(t.Deadline), headerSafe(t.Action))
	return []byte("From: " + headerSafe(from) + "\r\nTo: " + headerSafe(to) + "\r\nSubject: " + subject +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
}

// collectWarnTargets extracts per-principal campaign rows from the identity
// findings' evidence.
func collectWarnTargets(sc *engine.Scorecard, deadline string) []warnTarget {
	byID := map[string]*rules.Result{}
	for i := range sc.Results {
		byID[sc.Results[i].Meta.ID] = &sc.Results[i]
	}
	var targets []warnTarget

	// Population A: members carrying corporate email (only when the policy
	// forbids it — otherwise IDENT-07 reports an inventory, not a finding).
	if r := byID["IDENT-07"]; r != nil && r.Status == rules.StatusWarn {
		if carriers, ok := r.Evidence.(map[string][]string); ok {
			logins := make([]string, 0, len(carriers))
			for l := range carriers {
				logins = append(logins, l)
			}
			sort.Strings(logins)
			for _, login := range logins {
				targets = append(targets, warnTarget{
					Population: "member", Identifier: login,
					Emails:     strings.Join(carriers[login], " "),
					SourceRule: "IDENT-07", Deadline: deadline,
					Action: "Remove the corporate email(s) from your personal GitHub account (github.com/settings/emails) or replace them with a personal address, per company policy.",
				})
			}
		}
	}
	// Population B (partial): public signals outside the enterprise.
	if r := byID["IDENT-08"]; r != nil && r.Status == rules.StatusWarn {
		if list, ok := r.Evidence.([]string); ok {
			for _, login := range list {
				targets = append(targets, warnTarget{
					Population: "rogue-public-signal", Identifier: login,
					SourceRule: "IDENT-08", Deadline: deadline,
					Action: "This account is outside the enterprise but shows corporate-email usage in public activity. Remove the corporate email or delete the account.",
				})
			}
		}
	}
	// Population B (confirmed): mail-gateway trace.
	if r := byID["IDENT-10"]; r != nil && r.Status == rules.StatusFail {
		if list, ok := r.Evidence.([]string); ok {
			for _, addr := range list {
				targets = append(targets, warnTarget{
					Population: "rogue-confirmed-signup", Identifier: addr, Emails: addr,
					SourceRule: "IDENT-10", Deadline: deadline,
					Action: "This corporate mailbox received GitHub signup mail but matches no enterprise member. The owner must remove the corporate email or delete the account; IT should deploy the prevention transport rule.",
				})
			}
		}
	}
	// Population C: departed employees still linked.
	if r := byID["IDENT-09"]; r != nil && r.Status == rules.StatusFail {
		if list, ok := r.Evidence.([]string); ok {
			for _, label := range list {
				targets = append(targets, warnTarget{
					Population: "departed", Identifier: label,
					SourceRule: "IDENT-09", Deadline: deadline,
					Action: "Departed employee still linked: revoke enterprise/SSO access and hold mailbox recycling until the GitHub linkage is cleared.",
				})
			}
		}
	}
	return targets
}

func warnCSV(targets []warnTarget) string {
	var b strings.Builder
	b.WriteString("population,identifier,corporate_emails,source_rule,deadline,action\n")
	for _, t := range targets {
		fmt.Fprintf(&b, "%s,%s,%q,%s,%s,%q\n",
			t.Population, t.Identifier, t.Emails, t.SourceRule, t.Deadline, t.Action)
	}
	return b.String()
}

func warnMarkdown(enterprise string, targets []warnTarget, deadline string) string {
	var b strings.Builder
	b.WriteString("# Corporate-email warning campaign — " + enterprise + "\n\n")
	b.WriteString("Deadline: **" + deadline + "**\n\n")
	sections := []struct{ pop, title string }{
		{"member", "Enterprise members carrying corporate email"},
		{"rogue-public-signal", "Accounts outside the enterprise (public signals — partial coverage)"},
		{"rogue-confirmed-signup", "Confirmed signups on corporate mailboxes (mail-gateway trace)"},
		{"departed", "Departed employees still linked"},
	}
	for _, s := range sections {
		var rows []warnTarget
		for _, t := range targets {
			if t.Population == s.pop {
				rows = append(rows, t)
			}
		}
		if len(rows) == 0 {
			continue
		}
		b.WriteString("## " + s.title + "\n\n")
		b.WriteString("| Who | Corporate emails | Source | Required action |\n|---|---|---|---|\n")
		for _, t := range rows {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", t.Identifier, t.Emails, t.SourceRule, t.Action)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// cmdIdentityTransportRule generates the Exchange Online artifacts that
// PREVENT new GitHub signups with corporate email (signup cannot complete
// without the verification email) and DETECT past ones via message trace.
func cmdIdentityTransportRule(args []string) error {
	fs := flag.NewFlagSet("identity transport-rule", flag.ExitOnError)
	domain := fs.String("domain", "", "corporate email domain to protect (e.g. acme.com)")
	allowlist := fs.String("allowlist", "", "comma-separated mailboxes allowed to complete GitHub signup")
	out := fs.String("out", "", "write the PowerShell script to a file instead of stdout")
	_ = fs.Parse(args)
	if *domain == "" {
		return fmt.Errorf("--domain is required (e.g. --domain acme.com)")
	}
	var allowed []string
	for _, a := range strings.Split(*allowlist, ",") {
		if a = strings.TrimSpace(a); a != "" {
			allowed = append(allowed, a)
		}
	}
	sort.Strings(allowed)
	script := transportRuleScript(*domain, allowed)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(script), 0o600); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", *out)
		return nil
	}
	fmt.Print(script)
	return nil
}

func transportRuleScript(domain string, allowlist []string) string {
	var b strings.Builder
	b.WriteString(`# Generated by ghe-wizard — GitHub signup prevention & detection for @` + domain + `
#
# WHY THIS WORKS: GitHub cannot complete a personal-account signup without a
# verified email. Quarantining GitHub's verification mail to non-allowlisted
# corporate mailboxes makes registration with @` + domain + ` impossible,
# without blocking legitimate GitHub mail (notifications, invitations).
#
# Requires the ExchangeOnlineManagement module and an Exchange admin:
#   Connect-ExchangeOnline
#
# Review before running; adjust the allowlist to your sanctioned accounts.

# --- PREVENT: quarantine signup-verification mail ---------------------------
New-TransportRule -Name "ghe-wizard: block GitHub signup verification (@` + domain + `)" ` + "`" + `
  -FromAddressContainsWords "noreply@github.com" ` + "`" + `
  -SubjectContainsWords "verify your email address","Welcome to GitHub" ` + "`" + `
  -RecipientDomainIs "` + domain + `" ` + "`" + `
`)
	if len(allowlist) > 0 {
		b.WriteString(`  -ExceptIfSentTo "` + strings.Join(allowlist, `","`) + `" ` + "`" + "\n")
	}
	b.WriteString(`  -Quarantine $true ` + "`" + `
  -Comments "Prevents completing GitHub personal-account signup with corporate email. Generated by ghe-wizard."

# --- DETECT: export past signup mail for 'ghe-wizard' (IDENT-10 import) -----
# Last 10 days (Get-MessageTrace limit). For up to 90 days use
# Start-HistoricalSearch -ReportType MessageTrace instead.
Get-MessageTrace -SenderAddress "noreply@github.com" ` + "`" + `
  -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) |
  Where-Object { $_.Subject -like "*verify your email*" -or $_.Subject -like "*Welcome to GitHub*" } |
  Select-Object Received, RecipientAddress, Subject |
  Export-Csv github-signup-trace.csv -NoTypeInformation

# Then import it:
#   policy.yaml -> identity: { mail_trace_csv: github-signup-trace.csv }
#   ghe-wizard assess --policy policy.yaml       (IDENT-10 correlates it)
#   ghe-wizard identity warn --policy policy.yaml
`)
	return b.String()
}
