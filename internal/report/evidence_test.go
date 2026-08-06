package report

import (
	"encoding/csv"
	"encoding/json"
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

func TestEvidenceJSONWrapperAndFindings(t *testing.T) {
	sc := evidenceScorecard()

	out, err := EvidenceJSON(sc)
	if err != nil {
		t.Fatalf("EvidenceJSON returned error: %v", err)
	}

	var got struct {
		Enterprise  string    `json:"enterprise"`
		GeneratedAt time.Time `json:"generated_at"`
		Score       int       `json:"score"`
		Findings    []struct {
			RuleID   string `json:"rule_id"`
			Domain   string `json:"domain"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Title    string `json:"title"`
			Detail   string `json:"detail"`
			DocsURL  string `json:"docs_url"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	if got.Enterprise != sc.Enterprise {
		t.Fatalf("enterprise = %q, want %q", got.Enterprise, sc.Enterprise)
	}
	if !got.GeneratedAt.Equal(sc.GeneratedAt) {
		t.Fatalf("generated_at = %s, want %s", got.GeneratedAt, sc.GeneratedAt)
	}
	if got.Score != sc.Summary.Score {
		t.Fatalf("score = %d, want %d", got.Score, sc.Summary.Score)
	}
	if len(got.Findings) != len(sc.Results) {
		t.Fatalf("findings length = %d, want %d", len(got.Findings), len(sc.Results))
	}
	if got.Findings[0].RuleID != "AAA-001" {
		t.Fatalf("findings not sorted by rule_id: first rule = %q", got.Findings[0].RuleID)
	}
	if got.Findings[0].Detail != "detail, with comma and \"quotes\"\nsecond line" {
		t.Fatalf("finding detail = %q", got.Findings[0].Detail)
	}
	if got.Findings[0].Domain == "" || got.Findings[0].Severity == "" || got.Findings[0].Status == "" {
		t.Fatalf("finding omitted flattened fields: %+v", got.Findings[0])
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
