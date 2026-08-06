package report

import (
	"strings"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func sampleScorecard() *engine.Scorecard {
	return &engine.Scorecard{
		Enterprise:  "acme",
		GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Results: []rules.Result{
			{
				Meta:   rules.Meta{ID: "SEC-01", Domain: rules.DomainSecurity, Severity: rules.SeverityCritical, Title: "SSO", DocsURL: "https://example.com"},
				Status: rules.StatusFail, Detail: "No SSO", Remediation: "Configure SSO",
			},
			{
				Meta:   rules.Meta{ID: "ORG-01", Domain: rules.DomainOrgs, Severity: rules.SeverityMedium, Title: "Orgs", DocsURL: "https://example.com"},
				Status: rules.StatusPass, Detail: "ok",
			},
		},
		Summary: engine.Summary{
			Total:  2,
			Counts: map[string]int{"fail": 1, "pass": 1},
			Score:  50,
		},
	}
}

func TestHTML_ContainsKeyContent(t *testing.T) {
	html := HTML(sampleScorecard())
	for _, want := range []string{"<!DOCTYPE html>", "acme", "SEC-01", "Configure SSO", "Grade", "</html>"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

func TestHTML_EscapesContent(t *testing.T) {
	sc := sampleScorecard()
	sc.Results[0].Detail = "<script>alert(1)</script>"
	html := HTML(sc)
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("HTML output did not escape untrusted detail text")
	}
}

func TestMarkdown_And_JSON(t *testing.T) {
	sc := sampleScorecard()
	md := Markdown(sc)
	if !strings.Contains(md, "SEC-01") || !strings.Contains(md, "Score") {
		t.Error("markdown missing expected content")
	}
	b, err := JSON(sc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\"enterprise\": \"acme\"") {
		t.Error("json missing enterprise field")
	}
}

func TestGrade(t *testing.T) {
	cases := map[int]string{95: "A", 80: "B", 65: "C", 45: "D", 10: "F"}
	for score, want := range cases {
		if got := grade(score).letter; got != want {
			t.Errorf("grade(%d) = %s, want %s", score, got, want)
		}
	}
}
