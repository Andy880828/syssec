package checks

import (
	"context"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

const maxEvidence = 600

// Engine runs checks concurrently with per-check timeouts and panic isolation.
type Engine struct {
	Workers int
	Timeout time.Duration
}

// Run executes the checks and returns results sorted by priority.
func (e Engine) Run(ctx context.Context, env *sysenv.Env, cs []Check) []core.Result {
	workers := e.Workers
	if workers <= 0 {
		workers = min(runtime.NumCPU()*2, 16)
	}
	results := make([]core.Result, len(cs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = e.runOne(ctx, env, c)
		}()
	}
	wg.Wait()
	core.SortResults(results)
	return results
}

func (e Engine) runOne(ctx context.Context, env *sysenv.Env, c Check) core.Result {
	m := c.Meta()
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if c := env.Host.Container; c != "" && slices.Contains(m.Tags, core.TagHostOnly) {
		return result(m, Skip("host-level control; evaluate it on the %s host, not inside the container", c))
	}
	done := make(chan Outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- Errorf("check panicked: %v", r)
			}
		}()
		done <- c.Run(ctx, env)
	}()

	var o Outcome
	select {
	case o = <-done:
	case <-ctx.Done():
		o = Errorf("timed out after %s", timeout)
	}
	return result(m, o)
}

func result(m core.CheckMeta, o Outcome) core.Result {
	res := core.Result{
		ID:       m.ID,
		Title:    m.Title,
		Category: m.Category,
		Severity: m.Severity,
		Status:   o.Status,
		Evidence: truncate(o.Evidence, maxEvidence),
	}
	if o.Status == core.StatusFail || o.Status == core.StatusWarn {
		res.Remediation = m.Remediation
	}
	return res
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
