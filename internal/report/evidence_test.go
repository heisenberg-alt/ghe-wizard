package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func TestEvidenceCSVHeaderRowsAndEscaping(t *testing.T) {
	sc := evidenceScorecard()

	out := EvidenceCSV(sc)
	if !strings.Contains(out, `detail, with comma and ""quotes""`) {
		t.Fatalf("CSV output did not escape comma/quotes as expected:\n%s", out)
	}
	if !strings.Contains(out, "\"detail, with comma and \"\"quotes\"\"") {
		t.Fatalf("CSV output did not quote escaped field:\n%s", out)
	}
	if !strings.Contains(out, "\nsecond line\"") {
		t.Fatalf("CSV output did not preserve quoted newline:\n%s", out)
	}

	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(rows) != len(sc.Results)+1 {
		t.Fatalf("CSV returned %d rows, want %d", len(rows), len(sc.Results)+1)
	}

	wantHeader := []string{"rule_id", "domain", "severity", "status", "title", "detail", "docs_url"}
	for i, want := range wantHeader {
		if rows[0][i] != want {
			t.Fatalf("header[%d] = %q, want %q", i, rows[0][i], want)
		}
	}
	if rows[1][0] != "AAA-001" {
		t.Fatalf("results not sorted by rule_id: first rule = %q", rows[1][0])
	}
	if rows[1][5] != "detail, with comma and \"quotes\"\nsecond line" {
		t.Fatalf("escaped detail parsed as %q", rows[1][5])
	}
}

func evidenceScorecard() *engine.Scorecard {
	return &engine.Scorecard{
		Enterprise:  "octo-enterprise",
		GeneratedAt: time.Date(2026, 8, 6, 16, 0, 0, 0, time.UTC),
		Summary:     engine.Summary{Score: 87},
		Results: []rules.Result{
			{
				Meta: rules.Meta{
					ID:       "ZZZ-002",
					Domain:   rules.DomainRepos,
					Severity: rules.SeverityLow,
					Title:    "Repository setting",
					DocsURL:  "https://docs.example.com/repos",
				},
				Status: rules.StatusPass,
				Detail: "plain detail",
			},
			{
				Meta: rules.Meta{
					ID:       "AAA-001",
					Domain:   rules.DomainSecurity,
					Severity: rules.SeverityHigh,
					Title:    "Security evidence",
					DocsURL:  "https://docs.example.com/security",
				},
				Status: rules.StatusFail,
				Detail: "detail, with comma and \"quotes\"\nsecond line",
			},
		},
	}
}
