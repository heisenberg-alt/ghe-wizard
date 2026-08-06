package report

import (
	"encoding/csv"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

var evidenceHeader = []string{"rule_id", "domain", "severity", "status", "title", "detail", "docs_url"}

type evidenceDocument struct {
	Enterprise  string            `json:"enterprise"`
	GeneratedAt time.Time         `json:"generated_at"`
	Score       int               `json:"score"`
	Findings    []evidenceFinding `json:"findings"`
}

type evidenceFinding struct {
	RuleID   string `json:"rule_id"`
	Domain   string `json:"domain"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	DocsURL  string `json:"docs_url"`
}

// EvidenceCSV renders a deterministic, auditor-facing CSV evidence export.
func EvidenceCSV(sc *engine.Scorecard) string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write(evidenceHeader)
	for _, f := range evidenceFindings(sc) {
		_ = w.Write([]string{f.RuleID, f.Domain, f.Severity, f.Status, f.Title, f.Detail, f.DocsURL})
	}
	w.Flush()
	return b.String()
}

// EvidenceJSON renders a deterministic, compliance-friendly JSON evidence export.
func EvidenceJSON(sc *engine.Scorecard) ([]byte, error) {
	doc := evidenceDocument{
		Findings: evidenceFindings(sc),
	}
	if sc != nil {
		doc.Enterprise = sc.Enterprise
		doc.GeneratedAt = sc.GeneratedAt
		doc.Score = sc.Summary.Score
	}
	return json.MarshalIndent(doc, "", "  ")
}

func evidenceFindings(sc *engine.Scorecard) []evidenceFinding {
	results := sortedEvidenceResults(sc)
	findings := make([]evidenceFinding, 0, len(results))
	for _, r := range results {
		findings = append(findings, evidenceFinding{
			RuleID:   r.Meta.ID,
			Domain:   string(r.Meta.Domain),
			Severity: string(r.Meta.Severity),
			Status:   string(r.Status),
			Title:    r.Meta.Title,
			Detail:   r.Detail,
			DocsURL:  r.Meta.DocsURL,
		})
	}
	return findings
}

func sortedEvidenceResults(sc *engine.Scorecard) []rules.Result {
	if sc == nil {
		return nil
	}
	results := append([]rules.Result(nil), sc.Results...)
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Meta.ID < results[j].Meta.ID
	})
	return results
}
