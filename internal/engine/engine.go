// Package engine runs the rule catalog against an enterprise and aggregates
// the results into a scorecard.
package engine

import (
	"context"
	"sort"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
)

// Scorecard aggregates assessment results.
type Scorecard struct {
	Enterprise string          `json:"enterprise"`
	GeneratedAt time.Time      `json:"generated_at"`
	Results    []rules.Result  `json:"results"`
	Summary    Summary         `json:"summary"`
}

// Summary counts outcomes and computes a score.
type Summary struct {
	Total   int            `json:"total"`
	Counts  map[string]int `json:"counts"`  // by status
	ByDomain map[string]DomainScore `json:"by_domain"`
	Score   int            `json:"score"` // 0-100 over automatable rules
}

// DomainScore is a per-domain roll-up.
type DomainScore struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
}

// Engine runs rules.
type Engine struct {
	api ghclient.GHAPI
	cfg *config.Config
}

// New builds an Engine. If the API is not already a *ghclient.Cached, it is
// wrapped so identical reads across rules are memoized and org data is fetched
// concurrently.
func New(api ghclient.GHAPI, cfg *config.Config) *Engine {
	if _, ok := api.(*ghclient.Cached); !ok {
		api = ghclient.NewCached(api, cfg.Concurrency)
	}
	return &Engine{api: api, cfg: cfg}
}

// Assess runs the given rules (or all if none supplied) and returns a scorecard.
func (e *Engine) Assess(ctx context.Context, rs []rules.Rule) *Scorecard {
	if len(rs) == 0 {
		rs = rules.All()
	}
	// Warm per-org caches concurrently before running rules.
	if c, ok := e.api.(*ghclient.Cached); ok {
		c.Prefetch(ctx, e.cfg.Enterprise, e.cfg.MaxOrgs)
	}
	sc := &Scorecard{
		Enterprise:  e.cfg.Enterprise,
		GeneratedAt: time.Now().UTC(),
	}
	for _, r := range rs {
		res := r.Assess(ctx, e.api, e.cfg)
		sc.Results = append(sc.Results, res)
	}
	sort.SliceStable(sc.Results, func(i, j int) bool {
		return sc.Results[i].Meta.ID < sc.Results[j].Meta.ID
	})
	sc.Summary = summarize(sc.Results)
	return sc
}

// Remediate runs remediations for the supplied rules (typically the failing ones).
func (e *Engine) Remediate(ctx context.Context, rs []rules.Rule, dryRun bool) []rules.RemediationResult {
	var out []rules.RemediationResult
	for _, r := range rs {
		out = append(out, r.Remediate(ctx, e.api, e.cfg, dryRun))
	}
	return out
}

// FailingRules assesses and returns the rules whose status is fail or warn.
func (e *Engine) FailingRules(ctx context.Context, rs []rules.Rule) []rules.Rule {
	if len(rs) == 0 {
		rs = rules.All()
	}
	var failing []rules.Rule
	for _, r := range rs {
		res := r.Assess(ctx, e.api, e.cfg)
		if res.Status == rules.StatusFail || res.Status == rules.StatusWarn {
			failing = append(failing, r)
		}
	}
	return failing
}

func summarize(results []rules.Result) Summary {
	s := Summary{
		Counts:   map[string]int{},
		ByDomain: map[string]DomainScore{},
		Total:    len(results),
	}
	var scored, passed int
	for _, r := range results {
		s.Counts[string(r.Status)]++
		d := s.ByDomain[string(r.Meta.Domain)]
		switch r.Status {
		case rules.StatusPass:
			d.Pass++
			scored++
			passed++
		case rules.StatusFail:
			d.Fail++
			scored++
		case rules.StatusWarn:
			d.Warn++
			scored++
			passed++ // warnings count as half below
		}
		s.ByDomain[string(r.Meta.Domain)] = d
	}
	// Score: pass=1, warn=0.5, fail=0, over automatable (pass+warn+fail) rules.
	if scored > 0 {
		warnCount := s.Counts[string(rules.StatusWarn)]
		passCount := s.Counts[string(rules.StatusPass)]
		s.Score = int((float64(passCount) + 0.5*float64(warnCount)) / float64(scored) * 100)
	}
	return s
}
