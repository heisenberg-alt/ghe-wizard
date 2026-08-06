// Package ai provides optional, pluggable AI assistance for scorecard findings.
//
// It intentionally depends only on the standard library and accepts a full
// OpenAI-compatible chat-completions endpoint so callers can use OpenAI, Azure
// OpenAI, GitHub Models, or a local compatible server.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

const (
	defaultTimeout = 60 * time.Second
	temperature    = 0.2

	// DisabledMessage is returned by AI methods when the client is not configured.
	DisabledMessage = "AI disabled: configure an endpoint and model to enable optional assistance."
)

var (
	errEmptyEndpoint = errors.New("ai endpoint is empty")
	errEmptyModel    = errors.New("ai model is empty")

	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s,;"']+`),
		regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;"']+`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
	}
)

// Config controls the AI client.
type Config struct {
	// Endpoint is the full OpenAI-compatible chat-completions URL.
	Endpoint string
	// APIKey is sent only as an Authorization bearer token and is never prompted.
	APIKey string
	// Model is the provider-specific model deployment/name.
	Model string
}

// Client calls an OpenAI-compatible chat-completions API.
type Client struct {
	cfg  Config
	http *http.Client
}

// New returns a configured AI client. Empty Endpoint or Model leaves it disabled.
func New(cfg Config) *Client {
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	cfg.Model = strings.TrimSpace(cfg.Model)
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: defaultTimeout},
	}
}

// Enabled reports whether this client has the minimum configuration needed to call AI.
func (c *Client) Enabled() bool {
	return c != nil && c.cfg.Endpoint != "" && c.cfg.Model != ""
}

// Explain returns a plain-English explanation of a finding and its likely blast radius.
func (c *Client) Explain(ctx context.Context, r rules.Result) (string, error) {
	if !c.Enabled() {
		return DisabledMessage, nil
	}
	payload := redactResult(r)
	user := marshalPrompt(map[string]any{
		"task":    "Explain this GitHub Enterprise best-practice finding in plain English for a non-expert. Include likely blast radius and why it matters.",
		"finding": payload,
	})
	return c.chat(ctx, systemPrompt("explain findings"), user)
}

// PrioritizePlan returns a staged Markdown remediation plan for failing findings.
func (c *Client) PrioritizePlan(ctx context.Context, sc *engine.Scorecard) (string, error) {
	if !c.Enabled() {
		return DisabledMessage, nil
	}
	payload := redactScorecard(sc, true)
	user := marshalPrompt(map[string]any{
		"task":      "Create a staged Markdown remediation plan. Rank failing findings by risk and expected effort. Include quick wins, medium-term fixes, and executive-level sequencing.",
		"scorecard": payload,
	})
	return c.chat(ctx, systemPrompt("prioritize remediation"), user)
}

// Query answers a natural-language question using only the redacted scorecard data.
func (c *Client) Query(ctx context.Context, sc *engine.Scorecard, question string) (string, error) {
	if !c.Enabled() {
		return DisabledMessage, nil
	}
	payload := redactScorecard(sc, false)
	user := marshalPrompt(map[string]any{
		"task":      "Answer the question using only the scorecard data below. If the data does not support an answer, say that the scorecard does not contain enough information.",
		"question":  redactString(question),
		"scorecard": payload,
	})
	return c.chat(ctx, systemPrompt("answer scorecard questions"), user)
}

func systemPrompt(purpose string) string {
	return "You help GitHub Enterprise administrators " + purpose + ". Use only the provided redacted scorecard data. Do not invent facts, secrets, tokens, or external telemetry."
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

func (c *Client) chat(ctx context.Context, system, user string) (string, error) {
	if c.cfg.Endpoint == "" {
		return "", errEmptyEndpoint
	}
	if c.cfg.Model == "" {
		return "", errEmptyModel
	}

	body, err := json.Marshal(chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: redactString(system)},
			{Role: "user", Content: redactString(user)},
		},
		Temperature: temperature,
	})
	if err != nil {
		return "", fmt.Errorf("encode AI request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create AI request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.cfg.APIKey))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("call AI endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("AI endpoint returned %s: %s", resp.Status, shortSnippet(redactString(string(snippet))))
	}

	var decoded chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode AI response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return "", errors.New("AI response contained no choices")
	}
	content := strings.TrimSpace(decoded.Choices[0].Message.Content)
	if content == "" {
		return "", errors.New("AI response content was empty")
	}
	return content, nil
}

type redactedScorecard struct {
	Enterprise string           `json:"enterprise,omitempty"`
	Results    []redactedResult `json:"results"`
}

type redactedResult struct {
	Meta   redactedMeta `json:"meta"`
	Status string       `json:"status"`
	Detail string       `json:"detail"`
}

type redactedMeta struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	DocsURL  string `json:"docs_url,omitempty"`
}

func redactScorecard(sc *engine.Scorecard, failingOnly bool) redactedScorecard {
	if sc == nil {
		return redactedScorecard{}
	}
	out := redactedScorecard{
		Enterprise: redactString(sc.Enterprise),
		Results:    make([]redactedResult, 0, len(sc.Results)),
	}
	for _, r := range sc.Results {
		if failingOnly && r.Status != rules.StatusFail {
			continue
		}
		out.Results = append(out.Results, redactResult(r))
	}
	return out
}

func redactResult(r rules.Result) redactedResult {
	return redactedResult{
		Meta: redactedMeta{
			ID:       redactString(r.Meta.ID),
			Domain:   redactString(string(r.Meta.Domain)),
			Severity: redactString(string(r.Meta.Severity)),
			Title:    redactString(r.Meta.Title),
			DocsURL:  redactString(r.Meta.DocsURL),
		},
		Status: redactString(string(r.Status)),
		Detail: redactString(r.Detail),
	}
}

func redactString(s string) string {
	out := s
	for _, pattern := range secretPatterns {
		out = pattern.ReplaceAllStringFunc(out, func(match string) string {
			if strings.Contains(match, " ") || strings.Contains(match, ":") || strings.Contains(match, "=") {
				parts := regexp.MustCompile(`[:=]`).Split(match, 2)
				if len(parts) == 2 {
					return parts[0] + ": [REDACTED]"
				}
			}
			return "[REDACTED]"
		})
	}
	return out
}

func marshalPrompt(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "Unable to encode prompt data."
	}
	return string(b)
}

func shortSnippet(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
