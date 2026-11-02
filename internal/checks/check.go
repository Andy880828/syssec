// Package checks is the extensible security-check engine: a Check
// interface, a registry, a concurrent runner, reusable declarative
// primitives (sysctl, sshd, file mode, registry, command) and a JSON rule
// loader so new rules can ship without recompiling.
package checks

import (
	"context"
	"fmt"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// Check is a single security control.
type Check interface {
	Meta() core.CheckMeta
	Run(ctx context.Context, env *sysenv.Env) Outcome
}

// Outcome is what a check observed.
type Outcome struct {
	Status     core.Status
	Evidence   string
	Unverified bool // error because of missing privileges; see Unverified
}

func outcome(s core.Status, format string, a ...any) Outcome {
	return Outcome{Status: s, Evidence: fmt.Sprintf(format, a...)}
}

func Pass(format string, a ...any) Outcome   { return outcome(core.StatusPass, format, a...) }
func Fail(format string, a ...any) Outcome   { return outcome(core.StatusFail, format, a...) }
func Warn(format string, a ...any) Outcome   { return outcome(core.StatusWarn, format, a...) }
func Skip(format string, a ...any) Outcome   { return outcome(core.StatusSkip, format, a...) }
func Errorf(format string, a ...any) Outcome { return outcome(core.StatusError, format, a...) }

// UnverifiedSuffix 是附在 Unverified 結果 evidence 後的人類提示。它由引擎在
// 截斷之後才加上，所以永遠完整；程式判斷請看 Result.Unverified，不要比對這段文字。
const UnverifiedSuffix = " (run as root for full coverage)"

// Unverified 是「權限不足、無法驗證」的唯一出口。它回報 error 而不是 skip：
// skip 不計分，曾讓讀不到的檢查默默消失、分數反而變高；error 計入分母不給分。
// skip 只留給真正不適用的情況（沒安裝、不在這個平台）。
func Unverified(format string, a ...any) Outcome {
	o := outcome(core.StatusError, format, a...)
	o.Unverified = true
	return o
}

// Func adapts a function into a Check.
type Func struct {
	M  core.CheckMeta
	Fn func(ctx context.Context, env *sysenv.Env) Outcome
}

func (f Func) Meta() core.CheckMeta                             { return f.M }
func (f Func) Run(ctx context.Context, env *sysenv.Env) Outcome { return f.Fn(ctx, env) }

// New builds a Check from metadata and a probe function.
func New(m core.CheckMeta, fn func(ctx context.Context, env *sysenv.Env) Outcome) Check {
	return Func{M: m, Fn: fn}
}

// Cached shares an expensive, typed probe between checks of one run.
func Cached[T any](env *sysenv.Env, key string, fn func() (T, error)) (T, error) {
	v, err := env.Memo(key, func() (any, error) { return fn() })
	if err != nil {
		var zero T
		return zero, err
	}
	return v.(T), nil
}
