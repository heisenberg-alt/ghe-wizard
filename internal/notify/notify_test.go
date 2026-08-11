package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	"github.com/ghe-wizard/ghe-wizard/internal/store"
)

func TestSlackSendsTextPayload(t *testing.T) {
	sc := testScorecard()
	drift := &store.Drift{ScoreDelta: -4, NewlyFailing: []string{"SEC-2"}, NewlyFixed: []string{"POL-1"}}
	var payload map[string]string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJSONPost(t, r)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	if err := Slack(context.Background(), ts.URL, sc, drift); err != nil {
		t.Fatalf("Slack returned error: %v", err)
	}

	text := payload["text"]
	for _, want := range []string{
		"GitHub Enterprise assessment: octo-ent",
		"Score: *82* (B)",
		"fail=2 warn=1 manual=1 pass=3",
		"SEC-1",
		"Require SAML SSO",
		"Drift: score delta -4",
		"Newly failing: SEC-2",
		"Newly fixed: POL-1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Slack text missing %q:\n%s", want, text)
		}
	}
}

func TestTeamsSendsMessageCardPayload(t *testing.T) {
	sc := testScorecard()
	drift := &store.Drift{ScoreDelta: 7, NewlyFixed: []string{"SEC-1"}}
	var payload map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJSONPost(t, r)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := Teams(context.Background(), ts.URL, sc, drift); err != nil {
		t.Fatalf("Teams returned error: %v", err)
	}

	if payload["@type"] != "MessageCard" {
		t.Fatalf("expected MessageCard payload, got %#v", payload["@type"])
	}
	if payload["summary"] != "GitHub Enterprise assessment for octo-ent" {
		t.Fatalf("unexpected summary: %#v", payload["summary"])
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	text := string(body)
	for _, want := range []string{"octo-ent", "SEC-1", "Require SAML SSO", "Score delta", "+7", "Newly fixed: SEC-1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Teams payload missing %q:\n%s", want, text)
		}
	}
}

func TestSendAutoDetectsTeamsWebhook(t *testing.T) {
	sc := testScorecard()
	var payload map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webhook.office.com" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := Send(context.Background(), ts.URL+"/webhook.office.com", sc, nil); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if payload["@type"] != "MessageCard" {
		t.Fatalf("expected Teams MessageCard from auto-detection, got %#v", payload)
	}
}

func TestNon2xxReturnsErrorWithResponseSnippet(t *testing.T) {
	sc := testScorecard()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied by webhook", http.StatusForbidden)
	}))
	defer ts.Close()

	err := Slack(context.Background(), ts.URL, sc, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "403 Forbidden") || !strings.Contains(msg, "denied by webhook") {
		t.Fatalf("error missing status/snippet: %v", err)
	}
	if strings.Contains(msg, ts.URL) {
		t.Fatalf("error leaked webhook URL: %v", err)
	}
}

func TestShouldAlert(t *testing.T) {
	tests := []struct {
		name     string
		score    int
		drift    *store.Drift
		minScore int
		want     bool
		reason   string
	}{
		{
			name:   "score drop",
			score:  90,
			drift:  &store.Drift{ScoreDelta: -1},
			want:   true,
			reason: "score dropped",
		},
		{
			name:   "new failure",
			score:  90,
			drift:  &store.Drift{NewlyFailing: []string{"SEC-1"}},
			want:   true,
			reason: "newly failing",
		},
		{
			name:     "below threshold",
			score:    74,
			minScore: 75,
			want:     true,
			reason:   "below threshold",
		},
		{
			name:     "quiet",
			score:    90,
			drift:    &store.Drift{ScoreDelta: 3},
			minScore: 75,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := ShouldAlert(&engine.Scorecard{Summary: engine.Summary{Score: tt.score}}, tt.drift, tt.minScore)
			if got != tt.want {
				t.Fatalf("ShouldAlert() = %v, want %v (reason %q)", got, tt.want, reason)
			}
			if tt.reason != "" && !strings.Contains(reason, tt.reason) {
				t.Fatalf("reason %q missing %q", reason, tt.reason)
			}
			if !tt.want && reason != "" {
				t.Fatalf("quiet alert returned reason %q", reason)
			}
		})
	}
}

func TestDiscordSendsContentPayload(t *testing.T) {
	sc := testScorecard()
	drift := &store.Drift{ScoreDelta: -4, NewlyFailing: []string{"SEC-2"}}
	var payload map[string]string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJSONPost(t, r)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	if err := Discord(context.Background(), ts.URL, sc, drift); err != nil {
		t.Fatalf("Discord returned error: %v", err)
	}
	content := payload["content"]
	for _, want := range []string{
		"**GitHub Enterprise assessment: octo-ent**",
		"Score: **82** (B)",
		"SEC-1",
		"Drift: score delta -4",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("Discord content missing %q:\n%s", want, content)
		}
	}
	if len(content) > discordContentLimit {
		t.Fatalf("content exceeds Discord limit: %d", len(content))
	}
}

func TestGenericSendsVersionedDocument(t *testing.T) {
	sc := testScorecard()
	drift := &store.Drift{ScoreDelta: -4, NewlyFailing: []string{"SEC-2"}}
	var payload genericPayload

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJSONPost(t, r)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := Generic(context.Background(), ts.URL, sc, drift); err != nil {
		t.Fatalf("Generic returned error: %v", err)
	}
	if payload.Schema != "ghe-wizard/v1" {
		t.Fatalf("schema = %q", payload.Schema)
	}
	if payload.Enterprise != "octo-ent" || payload.Score != 82 || payload.Grade != "B" {
		t.Fatalf("summary fields wrong: %+v", payload)
	}
	if len(payload.TopFailing) != 2 || payload.TopFailing[0].ID != "SEC-1" || payload.TopFailing[0].Severity != "high" {
		t.Fatalf("top_failing wrong: %+v", payload.TopFailing)
	}
	if payload.Drift == nil || payload.Drift.ScoreDelta != -4 || len(payload.Drift.NewlyFailing) != 1 {
		t.Fatalf("drift wrong: %+v", payload.Drift)
	}
}

func TestSendFormatDispatch(t *testing.T) {
	sc := testScorecard()
	var raw map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = map[string]any{}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cases := []struct {
		format  string
		wantKey string
	}{
		{"slack", "text"},
		{"discord", "content"},
		{"json", "schema"},
		{"teams", "@type"},
		{"auto", "text"}, // plain URL auto-detects as Slack
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			if err := SendFormat(context.Background(), tc.format, ts.URL, sc, nil); err != nil {
				t.Fatal(err)
			}
			if _, ok := raw[tc.wantKey]; !ok {
				t.Fatalf("format %s: payload missing key %q: %v", tc.format, tc.wantKey, raw)
			}
		})
	}
	if err := SendFormat(context.Background(), "carrier-pigeon", ts.URL, sc, nil); err == nil {
		t.Fatal("unknown format should error")
	}
}

func TestSendAutoDetectsDiscordWebhook(t *testing.T) {
	sc := testScorecard()
	var payload map[string]string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	if err := Send(context.Background(), ts.URL+"/discord.com/api/webhooks/1/x", sc, nil); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if _, ok := payload["content"]; !ok {
		t.Fatalf("expected Discord content payload, got %v", payload)
	}
}

func TestTruncateIsRuneSafe(t *testing.T) {
	s := strings.Repeat("é", 1500) // 2 bytes per rune = 3000 bytes
	out := truncate(s, discordContentLimit)
	if len(out) > discordContentLimit {
		t.Fatalf("truncated length %d exceeds limit", len(out))
	}
	if !strings.HasSuffix(out, "…") {
		t.Fatal("expected ellipsis suffix")
	}
	for _, r := range out {
		if r == '\uFFFD' {
			t.Fatal("truncation split a rune")
		}
	}
}

func assertJSONPost(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", r.Method)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}

func testScorecard() *engine.Scorecard {
	return &engine.Scorecard{
		Enterprise:  "octo-ent",
		GeneratedAt: time.Date(2026, 8, 6, 16, 0, 0, 0, time.UTC),
		Summary: engine.Summary{
			Total: 7,
			Counts: map[string]int{
				string(rules.StatusFail):   2,
				string(rules.StatusWarn):   1,
				string(rules.StatusManual): 1,
				string(rules.StatusPass):   3,
			},
			Score: 82,
		},
		Results: []rules.Result{
			result("SEC-1", "Require SAML SSO", rules.StatusFail),
			result("POL-1", "Enforce repository policies", rules.StatusWarn),
			result("SEC-2", "Require 2FA", rules.StatusFail),
			result("AUTO-1", "Enable automation", rules.StatusPass),
		},
	}
}

func result(id, title string, status rules.Status) rules.Result {
	return rules.Result{
		Meta: rules.Meta{
			ID:       id,
			Domain:   rules.DomainSecurity,
			Severity: rules.SeverityHigh,
			Title:    title,
		},
		Status: status,
	}
}
