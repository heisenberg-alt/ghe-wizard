// Package notify sends scorecard summaries to ChatOps webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	"github.com/ghe-wizard/ghe-wizard/internal/scoring"
	"github.com/ghe-wizard/ghe-wizard/internal/store"
)

const (
	httpTimeout          = 15 * time.Second
	maxFailingFindings   = 5
	responseSnippetLimit = 1024
	discordContentLimit  = 2000
)

// httpClient is shared across notifications to enable connection reuse.
var httpClient = &http.Client{Timeout: httpTimeout}

// Notifier sends a scorecard summary to a ChatOps webhook.
type Notifier func(ctx context.Context, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error

// Send auto-detects the webhook provider and sends a notification.
func Send(ctx context.Context, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error {
	switch {
	case isTeamsWebhook(webhookURL):
		return Teams(ctx, webhookURL, sc, drift)
	case isDiscordWebhook(webhookURL):
		return Discord(ctx, webhookURL, sc, drift)
	default:
		return Slack(ctx, webhookURL, sc, drift)
	}
}

// SendFormat dispatches by explicit format: auto (detect from the URL),
// slack, teams, discord, or json (the stable generic document).
func SendFormat(ctx context.Context, format, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "auto":
		return Send(ctx, webhookURL, sc, drift)
	case "slack":
		return Slack(ctx, webhookURL, sc, drift)
	case "teams":
		return Teams(ctx, webhookURL, sc, drift)
	case "discord":
		return Discord(ctx, webhookURL, sc, drift)
	case "json", "generic":
		return Generic(ctx, webhookURL, sc, drift)
	default:
		return fmt.Errorf("notify: unknown format %q (use auto|slack|teams|discord|json)", format)
	}
}

// Slack posts a Slack incoming-webhook payload summarizing the scorecard.
func Slack(ctx context.Context, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error {
	if err := validate(webhookURL, sc); err != nil {
		return err
	}
	payload := map[string]string{"text": slackText(sc, drift)}
	return postJSON(ctx, webhookURL, payload)
}

// Teams posts a Microsoft Teams MessageCard payload summarizing the scorecard.
func Teams(ctx context.Context, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error {
	if err := validate(webhookURL, sc); err != nil {
		return err
	}
	payload := teamsCard{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		Summary:    fmt.Sprintf("GitHub Enterprise assessment for %s", sc.Enterprise),
		ThemeColor: themeColor(sc.Summary.Score),
		Title:      fmt.Sprintf("GitHub Enterprise assessment: %s", sc.Enterprise),
		Sections: []teamsSection{{
			Facts: teamsFacts(sc, drift),
			Text:  teamsText(sc, drift),
		}},
	}
	return postJSON(ctx, webhookURL, payload)
}

// Discord posts a Discord webhook message summarizing the scorecard. Content
// is truncated to Discord's 2000-character message limit.
func Discord(ctx context.Context, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error {
	if err := validate(webhookURL, sc); err != nil {
		return err
	}
	payload := map[string]string{"content": truncate(discordText(sc, drift), discordContentLimit)}
	return postJSON(ctx, webhookURL, payload)
}

// Generic posts a stable, versioned JSON document for arbitrary receivers
// (schema "ghe-wizard/v1"): enterprise, score, grade, counts, top failing
// findings and drift.
func Generic(ctx context.Context, webhookURL string, sc *engine.Scorecard, drift *store.Drift) error {
	if err := validate(webhookURL, sc); err != nil {
		return err
	}
	payload := genericPayload{
		Schema:      "ghe-wizard/v1",
		Enterprise:  sc.Enterprise,
		GeneratedAt: sc.GeneratedAt,
		Score:       sc.Summary.Score,
		Grade:       Grade(sc.Summary.Score),
		Counts:      sc.Summary.Counts,
	}
	for _, f := range failingFindings(sc) {
		payload.TopFailing = append(payload.TopFailing, genericFinding(f))
	}
	if drift != nil {
		payload.Drift = &genericDrift{
			ScoreDelta:   drift.ScoreDelta,
			NewlyFailing: drift.NewlyFailing,
			NewlyFixed:   drift.NewlyFixed,
		}
	}
	return postJSON(ctx, webhookURL, payload)
}

// ShouldAlert reports whether a scorecard should trigger a ChatOps notification.
func ShouldAlert(sc *engine.Scorecard, drift *store.Drift, minScore int) (bool, string) {
	if drift != nil {
		if drift.ScoreDelta < 0 {
			return true, fmt.Sprintf("score dropped by %d point(s)", -drift.ScoreDelta)
		}
		if len(drift.NewlyFailing) > 0 {
			return true, "newly failing rule(s): " + strings.Join(drift.NewlyFailing, ", ")
		}
	}
	if sc != nil && sc.Summary.Score < minScore {
		return true, fmt.Sprintf("score %d is below threshold %d", sc.Summary.Score, minScore)
	}
	return false, ""
}

// Grade returns the A-F grade for a 0-100 score.
func Grade(score int) string { return scoring.Letter(score) }

type finding struct {
	ID       string
	Title    string
	Severity string
}

// genericPayload is the stable "ghe-wizard/v1" webhook document.
type genericPayload struct {
	Schema      string           `json:"schema"`
	Enterprise  string           `json:"enterprise"`
	GeneratedAt time.Time        `json:"generated_at"`
	Score       int              `json:"score"`
	Grade       string           `json:"grade"`
	Counts      map[string]int   `json:"counts"`
	TopFailing  []genericFinding `json:"top_failing"`
	Drift       *genericDrift    `json:"drift,omitempty"`
}

type genericFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

type genericDrift struct {
	ScoreDelta   int      `json:"score_delta"`
	NewlyFailing []string `json:"newly_failing,omitempty"`
	NewlyFixed   []string `json:"newly_fixed,omitempty"`
}

type teamsCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	Summary    string         `json:"summary"`
	ThemeColor string         `json:"themeColor,omitempty"`
	Title      string         `json:"title"`
	Sections   []teamsSection `json:"sections,omitempty"`
}

type teamsSection struct {
	Facts []teamsFact `json:"facts,omitempty"`
	Text  string      `json:"text,omitempty"`
}

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func validate(webhookURL string, sc *engine.Scorecard) error {
	if strings.TrimSpace(webhookURL) == "" {
		return errors.New("notify: webhook URL is required")
	}
	if sc == nil {
		return errors.New("notify: scorecard is required")
	}
	return nil
}

func isTeamsWebhook(webhookURL string) bool {
	u := strings.ToLower(webhookURL)
	return strings.Contains(u, "webhook.office.com") || strings.Contains(u, "office.com/webhookb2")
}

func isDiscordWebhook(webhookURL string) bool {
	u := strings.ToLower(webhookURL)
	return strings.Contains(u, "discord.com/api/webhooks") || strings.Contains(u, "discordapp.com/api/webhooks")
}

// truncate shortens s to at most limit bytes without splitting a UTF-8 rune,
// appending an ellipsis when cut.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func postJSON(ctx context.Context, webhookURL string, payload any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: encode payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, responseSnippetLimit))
		msg := strings.TrimSpace(string(snippet))
		if msg == "" {
			return fmt.Errorf("notify: webhook returned %s", resp.Status)
		}
		return fmt.Errorf("notify: webhook returned %s: %s", resp.Status, msg)
	}
	return nil
}

func slackText(sc *engine.Scorecard, drift *store.Drift) string {
	lines := []string{
		fmt.Sprintf("*GitHub Enterprise assessment: %s*", sc.Enterprise),
		fmt.Sprintf("Score: *%d* (%s)", sc.Summary.Score, Grade(sc.Summary.Score)),
		fmt.Sprintf("Counts: fail=%d warn=%d manual=%d pass=%d",
			count(sc, rules.StatusFail), count(sc, rules.StatusWarn),
			count(sc, rules.StatusManual), count(sc, rules.StatusPass)),
	}
	lines = append(lines, findingsLines("Top failing findings:", "•", sc)...)
	lines = append(lines, driftLines(drift)...)
	return strings.Join(lines, "\n")
}

func discordText(sc *engine.Scorecard, drift *store.Drift) string {
	lines := []string{
		fmt.Sprintf("**GitHub Enterprise assessment: %s**", sc.Enterprise),
		fmt.Sprintf("Score: **%d** (%s)", sc.Summary.Score, Grade(sc.Summary.Score)),
		fmt.Sprintf("Counts: fail=%d warn=%d manual=%d pass=%d",
			count(sc, rules.StatusFail), count(sc, rules.StatusWarn),
			count(sc, rules.StatusManual), count(sc, rules.StatusPass)),
	}
	lines = append(lines, findingsLines("Top failing findings:", "•", sc)...)
	lines = append(lines, driftLines(drift)...)
	return strings.Join(lines, "\n")
}

func teamsText(sc *engine.Scorecard, drift *store.Drift) string {
	lines := findingsLines("Top failing findings:", "-", sc)
	lines = append(lines, driftLines(drift)...)
	if len(lines) == 0 {
		return "No failing findings."
	}
	return strings.Join(lines, "\n\n")
}

func teamsFacts(sc *engine.Scorecard, drift *store.Drift) []teamsFact {
	facts := []teamsFact{
		{Name: "Enterprise", Value: sc.Enterprise},
		{Name: "Score", Value: fmt.Sprintf("%d", sc.Summary.Score)},
		{Name: "Grade", Value: Grade(sc.Summary.Score)},
		{Name: "Fail", Value: fmt.Sprintf("%d", count(sc, rules.StatusFail))},
		{Name: "Warn", Value: fmt.Sprintf("%d", count(sc, rules.StatusWarn))},
		{Name: "Manual", Value: fmt.Sprintf("%d", count(sc, rules.StatusManual))},
		{Name: "Pass", Value: fmt.Sprintf("%d", count(sc, rules.StatusPass))},
	}
	if drift != nil {
		facts = append(facts, teamsFact{Name: "Score delta", Value: fmt.Sprintf("%+d", drift.ScoreDelta)})
	}
	return facts
}

func findingsLines(header, bullet string, sc *engine.Scorecard) []string {
	findings := failingFindings(sc)
	if len(findings) == 0 {
		return nil
	}
	lines := []string{header}
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("%s %s — %s", bullet, f.ID, f.Title))
	}
	return lines
}

func driftLines(drift *store.Drift) []string {
	if drift == nil {
		return nil
	}
	lines := []string{fmt.Sprintf("Drift: score delta %+d", drift.ScoreDelta)}
	if len(drift.NewlyFailing) > 0 {
		lines = append(lines, "Newly failing: "+strings.Join(drift.NewlyFailing, ", "))
	}
	if len(drift.NewlyFixed) > 0 {
		lines = append(lines, "Newly fixed: "+strings.Join(drift.NewlyFixed, ", "))
	}
	return lines
}

func failingFindings(sc *engine.Scorecard) []finding {
	var out []finding
	for _, r := range sc.Results {
		if r.Status != rules.StatusFail {
			continue
		}
		out = append(out, finding{ID: r.Meta.ID, Title: r.Meta.Title, Severity: string(r.Meta.Severity)})
		if len(out) == maxFailingFindings {
			break
		}
	}
	return out
}

func count(sc *engine.Scorecard, status rules.Status) int {
	if sc.Summary.Counts == nil {
		return 0
	}
	return sc.Summary.Counts[string(status)]
}

func themeColor(score int) string {
	switch Grade(score) {
	case "A", "B":
		return "2EB886"
	case "C":
		return "F2C744"
	default:
		return "D93F0B"
	}
}
