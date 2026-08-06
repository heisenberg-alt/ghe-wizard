package engine

import (
	"context"
	"testing"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
	_ "github.com/ghe-wizard/ghe-wizard/internal/rules/catalog"
)

// BenchmarkAssess measures the full assessment path (prefetch + all rules +
// summarize) against the in-memory demo data source, isolating CPU/allocation
// cost from network latency.
func BenchmarkAssess(b *testing.B) {
	cfg := &config.Config{Enterprise: "acme", Token: "x", Thresholds: config.DefaultThresholds(), MaxReposPerOrg: 500}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng := New(ghclient.NewDemoAPI(), cfg)
		_ = eng.Assess(context.Background(), nil)
	}
}

// BenchmarkSummarize isolates the summary aggregation hot path.
func BenchmarkSummarize(b *testing.B) {
	cfg := &config.Config{Enterprise: "acme", Token: "x", Thresholds: config.DefaultThresholds()}
	sc := New(ghclient.NewDemoAPI(), cfg).Assess(context.Background(), nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Recompute(sc)
	}
}
