package main

import (
	"strings"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func identityScorecard() *engine.Scorecard {
	meta := func(id string) rules.Meta {
		return rules.Meta{ID: id, Domain: rules.DomainIdentity, Severity: rules.SeverityMedium, Title: id}
	}
	return &engine.Scorecard{
		Enterprise: "acme",
		Results: []rules.Result{
			{Meta: meta("IDENT-07"), Status: rules.StatusWarn,
				Evidence: map[string][]string{"alice": {"alice@acme.com"}, "bob": {"bob@acme.com", "b@acme.com"}}},
			{Meta: meta("IDENT-08"), Status: rules.StatusWarn, Evidence: []string{"rogue-1"}},
			{Meta: meta("IDENT-10"), Status: rules.StatusFail, Evidence: []string{"ghost@acme.com"}},
			{Meta: meta("IDENT-09"), Status: rules.StatusFail, Evidence: []string{"gone-dev (gone-dev@acme.com)"}},
			// Passing rules contribute nothing.
			{Meta: meta("IDENT-01"), Status: rules.StatusPass},
		},
	}
}

func TestCollectWarnTargets(t *testing.T) {
	targets := collectWarnTargets(identityScorecard(), "2026-09-01")
	if len(targets) != 5 {
		t.Fatalf("expected 5 targets (2 members, 1 public rogue, 1 confirmed, 1 departed), got %d: %+v", len(targets), targets)
	}
	byPop := map[string][]warnTarget{}
	for _, tg := range targets {
		byPop[tg.Population] = append(byPop[tg.Population], tg)
		if tg.Deadline != "2026-09-01" {
			t.Fatalf("deadline not propagated: %+v", tg)
		}
		if tg.Action == "" || tg.SourceRule == "" {
			t.Fatalf("incomplete target: %+v", tg)
		}
	}
	members := byPop["member"]
	if len(members) != 2 || members[0].Identifier != "alice" || members[1].Identifier != "bob" {
		t.Fatalf("member targets wrong (must be sorted): %+v", members)
	}
	if !strings.Contains(members[1].Emails, "bob@acme.com") {
		t.Fatalf("member emails missing: %+v", members[1])
	}
	if len(byPop["rogue-public-signal"]) != 1 || byPop["rogue-public-signal"][0].Identifier != "rogue-1" {
		t.Fatalf("rogue public target wrong: %+v", byPop["rogue-public-signal"])
	}
	if len(byPop["rogue-confirmed-signup"]) != 1 || byPop["rogue-confirmed-signup"][0].Identifier != "ghost@acme.com" {
		t.Fatalf("confirmed rogue target wrong: %+v", byPop["rogue-confirmed-signup"])
	}
	if len(byPop["departed"]) != 1 || !strings.Contains(byPop["departed"][0].Identifier, "gone-dev") {
		t.Fatalf("departed target wrong: %+v", byPop["departed"])
	}
}

func TestWarnOutputsRenderAllTargets(t *testing.T) {
	targets := collectWarnTargets(identityScorecard(), "2026-09-01")

	csvOut := warnCSV(targets)
	lines := strings.Split(strings.TrimSpace(csvOut), "\n")
	if len(lines) != len(targets)+1 {
		t.Fatalf("CSV should have header + %d rows, got %d", len(targets), len(lines))
	}
	if lines[0] != "population,identifier,corporate_emails,source_rule,deadline,action" {
		t.Fatalf("unexpected CSV header: %q", lines[0])
	}

	md := warnMarkdown("acme", targets, "2026-09-01")
	for _, want := range []string{"alice", "bob", "rogue-1", "ghost@acme.com", "gone-dev", "2026-09-01"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestTransportRuleScript(t *testing.T) {
	script := transportRuleScript("acme.com", []string{"oss-liaison@acme.com"})
	for _, want := range []string{
		"New-TransportRule",
		`-RecipientDomainIs "acme.com"`,
		`noreply@github.com`,
		`-ExceptIfSentTo "oss-liaison@acme.com"`,
		"-Quarantine $true",
		"Get-MessageTrace",
		"github-signup-trace.csv",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	// No allowlist -> no ExceptIfSentTo clause.
	if strings.Contains(transportRuleScript("acme.com", nil), "ExceptIfSentTo") {
		t.Fatal("empty allowlist must not emit ExceptIfSentTo")
	}
}
