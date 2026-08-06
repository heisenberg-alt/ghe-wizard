package rules

import (
	"context"

	"github.com/ghe-wizard/ghe-wizard/internal/config"
	"github.com/ghe-wizard/ghe-wizard/internal/ghclient"
)

// AssessFunc assesses a rule.
type AssessFunc func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) Result

// RemediateFunc remediates a rule.
type RemediateFunc func(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) RemediationResult

// Base is a function-backed Rule, letting catalog files declare rules concisely.
type Base struct {
	M           Meta
	AssessFn    AssessFunc
	RemediateFn RemediateFunc
}

func (b Base) Meta() Meta { return b.M }

func (b Base) Assess(ctx context.Context, api ghclient.GHAPI, cfg *config.Config) Result {
	if b.AssessFn == nil {
		return Result{Meta: b.M, Status: StatusManual, Detail: "no automated assessment; review manually"}
	}
	return b.AssessFn(ctx, api, cfg)
}

func (b Base) Remediate(ctx context.Context, api ghclient.GHAPI, cfg *config.Config, dryRun bool) RemediationResult {
	if b.RemediateFn == nil {
		return RemediationResult{RuleID: b.M.ID, Applied: false, DryRun: dryRun,
			Changes: []string{"no automated remediation available; follow the docs link"}}
	}
	return b.RemediateFn(ctx, api, cfg, dryRun)
}

// --- small constructors used across catalog files ---

// Pass builds a passing result.
func Pass(m Meta, detail string, ev any) Result {
	return Result{Meta: m, Status: StatusPass, Detail: detail, Evidence: ev}
}

// Fail builds a failing result with a remediation summary.
func Fail(m Meta, detail, remediation string, ev any) Result {
	return Result{Meta: m, Status: StatusFail, Detail: detail, Remediation: remediation, Evidence: ev}
}

// Warn builds a warning result.
func Warn(m Meta, detail string, ev any) Result {
	return Result{Meta: m, Status: StatusWarn, Detail: detail, Evidence: ev}
}

// Manual builds a manual-review result.
func Manual(m Meta, detail string) Result {
	return Result{Meta: m, Status: StatusManual, Detail: detail}
}

// Errored builds an error result.
func Errored(m Meta, detail string) Result {
	return Result{Meta: m, Status: StatusError, Detail: detail}
}
