package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

func TestClientMethodsCallChatCompletions(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) (string, error)
	}{
		{
			name: "Explain",
			call: func(c *Client) (string, error) {
				return c.Explain(context.Background(), sampleResult())
			},
		},
		{
			name: "PrioritizePlan",
			call: func(c *Client) (string, error) {
				return c.PrioritizePlan(context.Background(), sampleScorecard())
			},
		},
		{
			name: "Query",
			call: func(c *Client) (string, error) {
				return c.Query(context.Background(), sampleScorecard(), "Which critical controls failed?")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Add(1)
				if r.Method != http.MethodPost {
					t.Fatalf("method = %s, want POST", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
					t.Fatalf("Authorization = %q, want bearer key", got)
				}
				if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
					t.Fatalf("Content-Type = %q, want JSON", got)
				}

				var req chatRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				if req.Model != "test-model" {
					t.Fatalf("model = %q, want test-model", req.Model)
				}
				if req.Temperature != temperature {
					t.Fatalf("temperature = %v, want %v", req.Temperature, temperature)
				}
				if len(req.Messages) != 2 {
					t.Fatalf("messages len = %d, want 2", len(req.Messages))
				}
				if req.Messages[0].Role != "system" || strings.TrimSpace(req.Messages[0].Content) == "" {
					t.Fatalf("system message malformed: %#v", req.Messages[0])
				}
				if req.Messages[1].Role != "user" || strings.TrimSpace(req.Messages[1].Content) == "" {
					t.Fatalf("user message malformed: %#v", req.Messages[1])
				}
				if strings.Contains(req.Messages[1].Content, "test-key") {
					t.Fatal("API key leaked into prompt")
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"mock assistant content"}}]}`))
			}))
			defer server.Close()

			client := New(Config{Endpoint: server.URL, APIKey: "test-key", Model: "test-model"})
			got, err := tt.call(client)
			if err != nil {
				t.Fatalf("call returned error: %v", err)
			}
			if got != "mock assistant content" {
				t.Fatalf("content = %q, want mocked assistant content", got)
			}
			if called.Load() != 1 {
				t.Fatalf("HTTP calls = %d, want 1", called.Load())
			}
		})
	}
}

func TestDisabledClientNoopsWithoutHTTP(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called.Add(1)
	}))
	defer server.Close()

	client := New(Config{Endpoint: "", APIKey: "test-key", Model: ""})
	if client.Enabled() {
		t.Fatal("Enabled() = true, want false")
	}

	calls := []func() (string, error){
		func() (string, error) { return client.Explain(context.Background(), sampleResult()) },
		func() (string, error) { return client.PrioritizePlan(context.Background(), sampleScorecard()) },
		func() (string, error) { return client.Query(context.Background(), sampleScorecard(), "Any failures?") },
	}
	for _, call := range calls {
		got, err := call()
		if err != nil {
			t.Fatalf("disabled call returned error: %v", err)
		}
		if got != DisabledMessage {
			t.Fatalf("disabled call = %q, want %q", got, DisabledMessage)
		}
	}
	if called.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", called.Load())
	}
}

func TestNon2xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	client := New(Config{Endpoint: server.URL, APIKey: "test-key", Model: "test-model"})
	got, err := client.Explain(context.Background(), sampleResult())
	if err == nil {
		t.Fatal("error = nil, want non-2xx error")
	}
	if got != "" {
		t.Fatalf("content = %q, want empty on error", got)
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "provider unavailable") {
		t.Fatalf("error = %q, want status and response snippet", err.Error())
	}
	if strings.Contains(err.Error(), "test-key") || strings.Contains(strings.ToLower(err.Error()), "authorization") {
		t.Fatalf("error leaked sensitive header material: %q", err.Error())
	}
}

func TestRedactionKeepsPromptsScopedToSafeFields(t *testing.T) {
	result := sampleResult()
	result.Detail = "token=ghp_123456789012345678901234567890123456 and SSO is disabled"
	result.Evidence = map[string]string{"secret": "should-not-appear"}
	result.Remediation = "do not include remediation"
	result.Meta.Rationale = "do not include rationale"
	result.Meta.Remediable = true

	redacted := redactResult(result)
	got, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted result: %v", err)
	}
	body := string(got)
	for _, forbidden := range []string{
		"ghp_123456789012345678901234567890123456",
		"should-not-appear",
		"do not include remediation",
		"do not include rationale",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("redacted prompt data contains %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("redacted prompt data = %s, want redaction marker", body)
	}
}

func sampleScorecard() *engine.Scorecard {
	return &engine.Scorecard{
		Enterprise:  "octo-enterprise",
		GeneratedAt: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
		Results: []rules.Result{
			sampleResult(),
			{
				Meta: rules.Meta{
					ID:       "repos-002",
					Domain:   rules.DomainRepos,
					Severity: rules.SeverityLow,
					Title:    "Archive inactive repositories",
					DocsURL:  "https://docs.github.com/",
				},
				Status: rules.StatusPass,
				Detail: "Inactive repositories are archived.",
			},
		},
		Summary: engine.Summary{Total: 2, Counts: map[string]int{"fail": 1, "pass": 1}, Score: 50},
	}
}

func sampleResult() rules.Result {
	return rules.Result{
		Meta: rules.Meta{
			ID:       "sec-001",
			Domain:   rules.DomainSecurity,
			Severity: rules.SeverityCritical,
			Title:    "Require SSO",
			DocsURL:  "https://docs.github.com/",
		},
		Status: rules.StatusFail,
		Detail: "SSO is not enforced for all organizations.",
	}
}
