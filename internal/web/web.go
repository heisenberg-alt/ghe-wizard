// Package web serves the ghe-wizard dashboard: a small JSON API plus an
// embedded single-page UI for running assessments and remediations.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
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
	"github.com/ghe-wizard/ghe-wizard/internal/rules"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog" // register rules
)

//go:embed ui
var uiFS embed.FS

// Options configures the dashboard server.
type Options struct {
	Addr         string
	BasicUser    string // optional; when set with BasicPass, enables basic auth
	BasicPass    string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Serve starts the dashboard HTTP server on addr with sensible defaults.
func Serve(addr string, base *config.Config) error {
	return ServeWithOptions(Options{Addr: addr}, base)
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
	s := &server{base: base, opts: opts}
	mux := http.NewServeMux()

	sub, _ := fsSub()
	mux.Handle("/", cacheStatic(http.FileServer(http.FS(sub))))
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/assess", s.handleAssess)
	mux.HandleFunc("/api/apply", s.handleApply)
	mux.HandleFunc("/api/health", s.handleHealth)

	handler := securityHeaders(s.auth(mux))
	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           handler,
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
		if err != nil && err != http.ErrServerClosed {
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
	base *config.Config
	opts Options
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
	return &c
}

func (s *server) engineFor(b reqBody) (*engine.Engine, *config.Config, error) {
	c := s.cfgFor(b)
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	api := ghclient.New(c.Token, c.BaseURL, c.GraphQLURL)
	return engine.New(api, c), c, nil
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
	})
}

func (s *server) handleAssess(w http.ResponseWriter, r *http.Request) {
	var b reqBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	eng, _, err := s.engineFor(b)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sc := eng.Assess(ctx, nil)
	writeJSON(w, http.StatusOK, sc)
}

func (s *server) handleApply(w http.ResponseWriter, r *http.Request) {
	var b reqBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	eng, _, err := s.engineFor(b)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	var targets []rules.Rule
	if len(b.Rules) > 0 {
		for _, id := range b.Rules {
			if rl := rules.ByID(id); rl != nil {
				targets = append(targets, rl)
			}
		}
	} else {
		for _, rl := range eng.FailingRules(ctx, nil) {
			if rl.Meta().Remediable {
				targets = append(targets, rl)
			}
		}
	}
	results := eng.Remediate(ctx, targets, b.DryRun)
	writeJSON(w, http.StatusOK, results)
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
		if !ok || subtleCompare(u, s.opts.BasicUser) == false || subtleCompare(p, s.opts.BasicPass) == false {
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
