package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// newTestServer builds a demo-mode server (no token required) and serves the
// full handler stack via httptest, without binding a real port.
func newTestServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	opts.Demo = true
	base := &config.Config{Thresholds: config.DefaultThresholds()}
	s, err := newServer(base, opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return ts
}

func writeWaiverPolicy(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	body := "waivers:\n  - rule: ORG-04\n    reason: accepted risk\n    owner: security\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func postJSON(t *testing.T, url string, payload any) *http.Response {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b)) // #nosec G107 -- httptest URL
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHealthReportsPolicyAndProfile(t *testing.T) {
	pol := writeWaiverPolicy(t)
	ts := newTestServer(t, Options{PolicyPath: pol, ProfileName: "high-security"})
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var h map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatal(err)
	}
	if h["policy"] != pol {
		t.Fatalf("health policy = %v, want %v", h["policy"], pol)
	}
	if h["profile"] != "high-security" {
		t.Fatalf("health profile = %v, want high-security", h["profile"])
	}
}

func TestNewServer_UnknownProfileFailsFast(t *testing.T) {
	_, err := newServer(&config.Config{}, Options{ProfileName: "no-such-profile"})
	if err == nil {
		t.Fatal("expected startup error for unknown profile")
	}
}

func TestAssessAppliesWaivers(t *testing.T) {
	ts := newTestServer(t, Options{PolicyPath: writeWaiverPolicy(t)})
	resp := postJSON(t, ts.URL+"/api/assess", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("assess status %d", resp.StatusCode)
	}
	var sc engine.Scorecard
	if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
		t.Fatal(err)
	}
	var found *rules.Result
	for i := range sc.Results {
		if sc.Results[i].Meta.ID == "ORG-04" {
			found = &sc.Results[i]
		}
	}
	if found == nil || found.Status != rules.StatusWaived {
		t.Fatalf("ORG-04 expected waived, got %+v", found)
	}
	if sc.Summary.Counts["waived"] == 0 {
		t.Fatal("summary should count waived findings")
	}
}

func TestApplySkipsWaivedRules(t *testing.T) {
	ts := newTestServer(t, Options{PolicyPath: writeWaiverPolicy(t)})
	resp := postJSON(t, ts.URL+"/api/apply", map[string]any{
		"dry_run": true,
		"rules":   []string{"ORG-04", "SEC-03"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apply status %d", resp.StatusCode)
	}
	var results []rules.RemediationResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	byRule := map[string]rules.RemediationResult{}
	for _, r := range results {
		byRule[r.RuleID] = r
	}
	waived, ok := byRule["ORG-04"]
	if !ok || len(waived.Errors) == 0 || !strings.Contains(waived.Errors[0], "waived") {
		t.Fatalf("ORG-04 should be skipped as waived, got %+v", waived)
	}
	sec, ok := byRule["SEC-03"]
	if !ok || len(sec.Changes) == 0 {
		t.Fatalf("SEC-03 dry-run should describe changes, got %+v", sec)
	}
	if sec.Applied {
		t.Fatal("dry-run must not apply")
	}
}

func TestExportCSV(t *testing.T) {
	ts := newTestServer(t, Options{})
	sc := engine.Scorecard{
		Enterprise: "acme",
		Results: []rules.Result{
			{Meta: rules.Meta{ID: "SEC-01", Domain: rules.DomainSecurity, Severity: rules.SeverityHigh,
				Title: "SSO", DocsURL: "https://example.com"}, Status: rules.StatusPass, Detail: "ok"},
		},
	}
	resp := postJSON(t, ts.URL+"/api/export/csv", sc)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "ghe-evidence-acme.csv") {
		t.Fatalf("content-disposition %q", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected header + 1 row, got %q", string(body))
	}
	if strings.TrimSpace(lines[0]) != "rule_id,domain,severity,status,title,detail,docs_url" {
		t.Fatalf("unexpected CSV header: %q", lines[0])
	}
	if !strings.Contains(lines[1], "SEC-01") {
		t.Fatalf("row missing rule: %q", lines[1])
	}
}

func TestBasicAuthGuardsAPI(t *testing.T) {
	ts := newTestServer(t, Options{BasicUser: "admin", BasicPass: "s3cret"})
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials, got %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
	req.SetBasicAuth("admin", "s3cret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with credentials, got %d", resp2.StatusCode)
	}
}

// TestDemoApplyImprovesNextAssessment exercises the stateful demo API through
// the full web flow: apply fixes, then re-assess and expect a better outcome.
func TestDemoApplyImprovesNextAssessment(t *testing.T) {
	ts := newTestServer(t, Options{})

	assess := func() *engine.Scorecard {
		resp := postJSON(t, ts.URL+"/api/assess", map[string]any{})
		defer resp.Body.Close()
		var sc engine.Scorecard
		if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
			t.Fatal(err)
		}
		return &sc
	}

	before := assess()
	resp := postJSON(t, ts.URL+"/api/apply", map[string]any{"dry_run": false})
	var results []rules.RemediationResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	applied := false
	for _, r := range results {
		if r.Applied {
			applied = true
		}
		if len(r.Errors) > 0 {
			t.Fatalf("demo apply reported errors: %+v", r)
		}
	}
	if !applied {
		t.Fatalf("demo apply should apply changes, got %+v", results)
	}
	after := assess()
	if after.Summary.Score <= before.Summary.Score {
		t.Fatalf("score should improve after demo apply: before=%d after=%d",
			before.Summary.Score, after.Summary.Score)
	}
}
