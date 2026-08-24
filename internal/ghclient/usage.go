package ghclient

import (
	"context"
	"fmt"
	"time"
)

// --- Usage / FinOps read surface (Copilot seats, metrics, billing) ----------

// CopilotSeat is one assigned Copilot seat. A zero LastActivityAt means the
// seat was never used.
type CopilotSeat struct {
	Org            string
	Login          string
	PlanType       string // business|enterprise|unknown
	CreatedAt      time.Time
	LastActivityAt time.Time
}

// ModelUsage is one model's share of a day's Copilot activity.
type ModelUsage struct {
	ID            string // raw telemetry model identifier
	Suggestions   int
	Acceptances   int
	LinesAccepted int
}

// MetricsDay is one day of enterprise Copilot metrics, flattened per model
// across editors and languages.
type MetricsDay struct {
	Date   string // YYYY-MM-DD
	Models []ModelUsage
}

// BillingUsageItem is one product/SKU line from the enhanced billing usage
// report (AI credits / premium requests), reduced to the fields the FinOps
// views consume.
type BillingUsageItem struct {
	Product      string
	Model        string // when the line item carries a model name; else ""
	NetAmountUSD float64
}

// UsageAPI is the FinOps read surface used by the SEAT-* rules and the usage
// command. *Client and the demo API implement it; obtain it via Usage(),
// which unwraps caching layers. All views are capability-wrapped: when an
// endpoint is unavailable the result degrades to a reasoned Capability
// instead of an error.
type UsageAPI interface {
	CopilotSeats(ctx context.Context, org string) ([]CopilotSeat, Capability, error)
	CopilotMetricsDays(ctx context.Context, slug string) ([]MetricsDay, Capability, error)
	EnterpriseBillingUsage(ctx context.Context, slug string) ([]BillingUsageItem, Capability, error)
}

// Usage extracts the FinOps read surface from an assessment API.
func Usage(api GHAPI) (UsageAPI, bool) {
	for api != nil {
		if u, ok := api.(UsageAPI); ok {
			return u, true
		}
		w, ok := api.(interface{ Unwrap() GHAPI })
		if !ok {
			return nil, false
		}
		api = w.Unwrap()
	}
	return nil, false
}

// --- Client implementation --------------------------------------------------

// CopilotSeats lists an org's Copilot billing seats.
func (c *Client) CopilotSeats(ctx context.Context, org string) ([]CopilotSeat, Capability, error) {
	var seats []CopilotSeat
	page := 1
	for {
		var raw struct {
			TotalSeats int `json:"total_seats"`
			Seats      []struct {
				CreatedAt      time.Time  `json:"created_at"`
				LastActivityAt *time.Time `json:"last_activity_at"`
				PlanType       string     `json:"plan_type"`
				Assignee       struct {
					Login string `json:"login"`
				} `json:"assignee"`
			} `json:"seats"`
		}
		path := fmt.Sprintf("/orgs/%s/copilot/billing/seats?per_page=100&page=%d", org, page)
		if _, err := c.rest(ctx, "GET", path, nil, &raw); err != nil {
			return nil, Capability{Determined: false, Reason: "Copilot seats unavailable for " + org + ": " + err.Error()}, nil
		}
		for _, s := range raw.Seats {
			seat := CopilotSeat{Org: org, Login: s.Assignee.Login, PlanType: s.PlanType, CreatedAt: s.CreatedAt}
			if s.LastActivityAt != nil {
				seat.LastActivityAt = *s.LastActivityAt
			}
			seats = append(seats, seat)
		}
		if len(seats) >= raw.TotalSeats || len(raw.Seats) == 0 {
			break
		}
		page++
	}
	return seats, Capability{Determined: true}, nil
}

// CopilotMetricsDays fetches enterprise Copilot metrics and flattens the
// per-editor/per-language breakdown into per-model daily totals.
func (c *Client) CopilotMetricsDays(ctx context.Context, slug string) ([]MetricsDay, Capability, error) {
	type lang struct {
		TotalCodeSuggestions   int `json:"total_code_suggestions"`
		TotalCodeAcceptances   int `json:"total_code_acceptances"`
		TotalCodeLinesAccepted int `json:"total_code_lines_accepted"`
	}
	type model struct {
		Name      string `json:"name"`
		Languages []lang `json:"languages"`
	}
	type editor struct {
		Models []model `json:"models"`
	}
	var raw []struct {
		Date        string `json:"date"`
		Completions *struct {
			Editors []editor `json:"editors"`
		} `json:"copilot_ide_code_completions"`
		IDEChat *struct {
			Editors []editor `json:"editors"`
		} `json:"copilot_ide_chat"`
	}
	if _, err := c.rest(ctx, "GET", "/enterprises/"+slug+"/copilot/metrics", nil, &raw); err != nil {
		return nil, Capability{Determined: false, Reason: "Copilot metrics unavailable: " + err.Error()}, nil
	}
	var days []MetricsDay
	for _, d := range raw {
		day := MetricsDay{Date: d.Date}
		acc := map[string]*ModelUsage{}
		addEditors := func(editors []editor) {
			for _, e := range editors {
				for _, m := range e.Models {
					mu := acc[m.Name]
					if mu == nil {
						mu = &ModelUsage{ID: m.Name}
						acc[m.Name] = mu
					}
					for _, l := range m.Languages {
						mu.Suggestions += l.TotalCodeSuggestions
						mu.Acceptances += l.TotalCodeAcceptances
						mu.LinesAccepted += l.TotalCodeLinesAccepted
					}
				}
			}
		}
		if d.Completions != nil {
			addEditors(d.Completions.Editors)
		}
		if d.IDEChat != nil {
			addEditors(d.IDEChat.Editors)
		}
		for _, mu := range acc {
			day.Models = append(day.Models, *mu)
		}
		days = append(days, day)
	}
	return days, Capability{Determined: true}, nil
}

// EnterpriseBillingUsage fetches the enhanced-billing usage report (premium
// requests / AI credits). The response shape should be re-confirmed on a
// real tenant; parsing is defensive and unknown products simply pass through.
func (c *Client) EnterpriseBillingUsage(ctx context.Context, slug string) ([]BillingUsageItem, Capability, error) {
	var raw struct {
		UsageItems []struct {
			Product   string  `json:"product"`
			Model     string  `json:"model"`
			NetAmount float64 `json:"netAmount"`
		} `json:"usageItems"`
	}
	if _, err := c.rest(ctx, "GET", "/enterprises/"+slug+"/settings/billing/usage", nil, &raw); err != nil {
		return nil, Capability{Determined: false, Reason: "enhanced billing usage unavailable: " + err.Error()}, nil
	}
	items := make([]BillingUsageItem, 0, len(raw.UsageItems))
	for _, it := range raw.UsageItems {
		items = append(items, BillingUsageItem{Product: it.Product, Model: it.Model, NetAmountUSD: it.NetAmount})
	}
	return items, Capability{Determined: true}, nil
}

// RevokeCopilotSeats cancels Copilot seats for the given users. DESTRUCTIVE —
// destructive-gated rules only. Returns the number of seats cancelled.
func (c *Client) RevokeCopilotSeats(ctx context.Context, org string, logins []string) (int, error) {
	var out struct {
		SeatsCancelled int `json:"seats_cancelled"`
	}
	if _, err := c.rest(ctx, "DELETE", "/orgs/"+org+"/copilot/billing/selected_users", map[string]any{
		"selected_usernames": logins,
	}, &out); err != nil {
		return 0, err
	}
	return out.SeatsCancelled, nil
}
