// Package web serves the ghe-wizard dashboard: a small JSON API plus an
// embedded single-page UI for running assessments and remediations.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ghe-wizard/ghe-wizard/internal/buildinfo"
	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/engine"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	"github.com/ghe-wizard/ghe-wizard/internal/policy"
	"github.com/ghe-wizard/ghe-wizard/internal/profile"
	"github.com/ghe-wizard/ghe-wizard/internal/report"
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog" // register rules
	"github.com/ghe-wizard/ghe-wizard/internal/store"
)

//go:embed ui
var uiFS embed.FS

// Options configures the dashboard server.
type Options struct {
	Addr         string
	BasicUser    string // optional; when set with BasicPass, enables basic auth
	BasicPass    string
	Demo         bool   // serve synthetic data without requiring a token
	DBPath       string // optional: record runs and enable history/trends
	PolicyPath   string // optional: config-as-code policy (disabled rules, waivers)
	ProfileName  string // optional: rule profile to run (e.g. high-security)
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// newServer builds the dashboard server, loading the policy and profile up
// front so bad configuration fails at startup rather than per-request. The
// demo API is shared across requests so demo remediations visibly improve
// subsequent assessments.
func newServer(base *config.Config, opts Options) (*server, error) {
	s := &server{base: base, opts: opts, demoAPI: ghclient.NewDemoAPI()}
	pol, err := policy.Load(opts.PolicyPath)
	if err != nil {
		return nil, err
	}
	s.pol = pol
	if opts.ProfileName != "" {
		p, ok := profile.Get(opts.ProfileName)
		if !ok {
			return nil, fmt.Errorf("unknown profile %q (available: %s)", opts.ProfileName, strings.Join(profile.Names(), ", "))
		}
		s.prof = p
	}
	return s, nil
}

// handler builds the full route + middleware stack (also exercised by tests).
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fsSub()
	mux.Handle("/", cacheStatic(http.FileServer(http.FS(sub))))
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/assess", s.handleAssess)
	mux.HandleFunc("/api/assess/stream", s.handleAssessStream)
	mux.HandleFunc("/api/apply", s.handleApply)
	mux.HandleFunc("/api/export/csv", s.handleExportCSV)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/badge.svg", s.handleBadge)
	return securityHeaders(s.auth(mux))
}

// ServeWithOptions starts the dashboard with graceful shutdown, security
// headers, timeouts and optional HTTP basic auth.
func ServeWithOptions(opts Options, base *config.Config) error {
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 15 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 3 * time.Minute
	}
	s, err := newServer(base, opts)
	if err != nil {
		return err
	}
	if opts.DBPath != "" {
		st, err := store.Open(opts.DBPath)
		if err != nil {
			return fmt.Errorf("open history db: %w", err)
		}
		defer func() { _ = st.Close() }()
		s.store = st
	}

	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       opts.ReadTimeout,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

type server struct {
	base    *config.Config
	opts    Options
	store   *store.Store
	pol     *policy.Policy
	prof    *profile.Profile
	demoAPI *ghclient.DemoAPI
}

// request-scoped overrides supplied by the UI form.
type reqBody struct {
	Enterprise string   `json:"enterprise"`
	Token      string   `json:"token"`
	DryRun     bool     `json:"dry_run"`
	Rules      []string `json:"rules"`
}

func (s *server) cfgFor(b reqBody) *config.Config {
	c := *s.base // shallow copy
	if b.Enterprise != "" {
		c.Enterprise = b.Enterprise
	}
	if b.Token != "" {
		c.Token = b.Token
	}
	// Config-as-code thresholds apply to every request-scoped config.
	s.pol.ApplyThresholds(&c.Thresholds.MaxEnterpriseOwners, &c.Thresholds.StaleOrgDays)
	s.pol.ApplyIdentity(&c.Identity)
	return &c
}

func (s *server) engineFor(b reqBody) (*engine.Engine, error) {
	c := s.cfgFor(b)
	// Demo mode: run the real engine against synthetic data, no token required.
	// The demo API instance is shared across requests so demo remediations
	// visibly change subsequent assessments.
	if s.opts.Demo || strings.EqualFold(c.Enterprise, "demo") || strings.EqualFold(c.Token, "demo") {
		if c.Enterprise == "" {
			c.Enterprise = "acme-corp"
		}
		return engine.New(s.demoAPI, c), nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	api, err := ghclient.NewFromConfig(c)
	if err != nil {
		return nil, err
	}
	return engine.New(api, c), nil
}

// rulesToRun applies the server's policy (disabled rules) and profile filters.
func (s *server) rulesToRun() []rules.Rule {
	toRun := s.pol.FilterRules(rules.All())
	if s.prof != nil {
		toRun = s.prof.Filter(toRun)
	}
	return toRun
}

// runAssessment assesses the filtered rule set and applies policy waivers and
// severity overrides, mirroring the CLI pipeline.
func (s *server) runAssessment(ctx context.Context, eng *engine.Engine) *engine.Scorecard {
	sc := eng.Assess(ctx, s.rulesToRun())
	s.pol.Apply(sc)
	return sc
}

func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	all := rules.All()
	sort.Slice(all, func(i, j int) bool { return all[i].Meta().ID < all[j].Meta().ID })
	metas := make([]rules.Meta, 0, len(all))
	for _, rl := range all {
		metas = append(metas, rl.Meta())
	}
	writeJSON(w, http.StatusOK, metas)
}

// handleHealth reports version, rule count and the server-side default enterprise
// (never the token) so the UI can pre-fill and show readiness.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"version":            buildinfo.Get().Version,
		"commit":             buildinfo.Get().Commit,
		"rules":              len(rules.All()),
		"default_enterprise": s.base.Enterprise,
		"has_server_token":   s.base.Token != "",
		"demo":               s.opts.Demo,
		"history":            s.store != nil,
		"policy":             s.opts.PolicyPath,
		"profile":            s.opts.ProfileName,
	})
}

func (s *server) handleAssess(w http.ResponseWriter, r *http.Request) {
	var b reqBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	eng, err := s.engineFor(b)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sc := s.runAssessment(ctx, eng)
	// Record history when a store is configured (best-effort, non-fatal).
	if s.store != nil {
		_, _ = s.store.SaveRun(ctx, sc)
	}
	writeJSON(w, http.StatusOK, sc)
}

// handleAssessStream runs the assessment and streams each rule result as a
// Server-Sent Events (SSE) message, then a final "done" event with the full
// scorecard. The client POSTs the same body as /api/assess and reads the
// response as a stream.
func (s *server) handleAssessStream(w http.ResponseWriter, r *http.Request) {
	var b reqBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	eng, err := s.engineFor(b)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Streaming unsupported: fall back to a single JSON response.
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		sc := s.runAssessment(ctx, eng)
		if s.store != nil {
			_, _ = s.store.SaveRun(ctx, sc)
		}
		writeJSON(w, http.StatusOK, sc)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	send := func(event string, v any) {
		data, _ := json.Marshal(v)
		_, _ = w.Write([]byte("event: " + event + "\ndata: "))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	// Streamed per-rule events are pre-waiver; the final "done" scorecard
	// carries waived statuses and is the UI's source of truth.
	sc := eng.AssessStream(ctx, s.rulesToRun(), func(total, index int, res rules.Result) {
		send("result", map[string]any{"total": total, "index": index, "result": res})
	})
	s.pol.Apply(sc)
	if s.store != nil {
		_, _ = s.store.SaveRun(ctx, sc)
	}
	send("done", sc)
}

// handleHistory returns recent recorded runs for an enterprise.
func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	ent := r.URL.Query().Get("enterprise")
	if ent == "" {
		ent = s.base.Enterprise
	}
	if ent == "" && s.opts.Demo {
		ent = "acme-corp"
	}
	runs, err := s.store.Runs(r.Context(), ent, 50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

// handleBadge serves an SVG score badge for the latest recorded run.
func (s *server) handleBadge(w http.ResponseWriter, r *http.Request) {
	score := -1
	if s.store != nil {
		ent := r.URL.Query().Get("enterprise")
		if ent == "" {
			ent = s.base.Enterprise
		}
		if runs, err := s.store.Runs(r.Context(), ent, 1); err == nil && len(runs) > 0 {
			score = runs[0].Score
		}
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache")
	// The badge SVG is generated solely from an integer score (no user-controlled
	// markup) and served as image/svg+xml, so it is not an XSS vector.
	if score < 0 {
		_, _ = w.Write([]byte(report.Badge(0))) // #nosec G705 -- integer-derived SVG, no user input
		return
	}
	_, _ = w.Write([]byte(report.Badge(score))) // #nosec G705 -- integer-derived SVG, no user input
}

func (s *server) handleApply(w http.ResponseWriter, r *http.Request) {
	var b reqBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	eng, err := s.engineFor(b)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	// Assess first so remediation honors the policy: disabled rules never ran
	// and waived findings are excluded (or skipped with a note when explicit).
	sc := s.runAssessment(ctx, eng)
	var targets []rules.Rule
	var results []rules.RemediationResult
	if len(b.Rules) > 0 {
		statusByID := map[string]rules.Status{}
		for _, res := range sc.Results {
			statusByID[res.Meta.ID] = res.Status
		}
		for _, id := range b.Rules {
			rl := rules.ByID(id)
			if rl == nil {
				results = append(results, rules.RemediationResult{RuleID: id, DryRun: b.DryRun,
					Errors: []string{"unknown rule"}})
				continue
			}
			st, ran := statusByID[id]
			switch {
			case rl.Meta().Destructive:
				results = append(results, rules.RemediationResult{RuleID: id, DryRun: b.DryRun,
					Errors: []string{"skipped: destructive remediation is CLI-only (apply --rules " + id + " --allow-destructive)"}})
			case !ran:
				results = append(results, rules.RemediationResult{RuleID: id, DryRun: b.DryRun,
					Errors: []string{"skipped: disabled by policy or excluded by profile"}})
			case st == rules.StatusWaived:
				results = append(results, rules.RemediationResult{RuleID: id, DryRun: b.DryRun,
					Errors: []string{"skipped: waived by policy"}})
			default:
				targets = append(targets, rl)
			}
		}
	} else {
		targets = engine.RemediableFailures(sc)
	}
	results = append(results, eng.Remediate(ctx, targets, b.DryRun)...)
	// Record applied (non-dry-run) remediations to history when available.
	if s.store != nil && !b.DryRun {
		_ = s.store.SaveRemediations(ctx, s.enterpriseFor(b), results)
	}
	writeJSON(w, http.StatusOK, results)
}

// handleExportCSV renders a scorecard the client already holds as a CSV
// evidence download. No re-assessment happens here; report.EvidenceCSV is the
// single source of truth for the CSV format.
func (s *server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	var sc engine.Scorecard
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scorecard payload: " + err.Error()})
		return
	}
	name := sanitizeFilename(sc.Enterprise)
	if name == "" {
		name = "scorecard"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "ghe-evidence-"+name+".csv"))
	_, _ = w.Write([]byte(report.EvidenceCSV(&sc)))
}

// sanitizeFilename keeps a user-supplied name safe for a Content-Disposition
// filename: alphanumerics, dash, underscore and dot only.
func sanitizeFilename(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, name)
}

// enterpriseFor resolves the enterprise slug for a request (body override,
// server default, or the demo enterprise).
func (s *server) enterpriseFor(b reqBody) string {
	if b.Enterprise != "" {
		return b.Enterprise
	}
	if s.base.Enterprise != "" {
		return s.base.Enterprise
	}
	if s.opts.Demo {
		return "acme-corp"
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// securityHeaders sets a strict, self-contained set of response headers. The
// dashboard uses no third-party scripts, so a tight CSP is safe.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline' https://rsms.me; "+
				"font-src https://rsms.me; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// auth optionally enforces HTTP basic auth when credentials are configured.
func (s *server) auth(next http.Handler) http.Handler {
	if s.opts.BasicUser == "" || s.opts.BasicPass == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !subtleCompare(u, s.opts.BasicUser) || !subtleCompare(p, s.opts.BasicPass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="ghe-wizard"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func subtleCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// cacheStatic adds light caching headers for embedded static assets.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") || strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		next.ServeHTTP(w, r)
	})
}
