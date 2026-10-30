package sysenv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// ErrCommandNotFound is returned when a probe binary is not installed.
var ErrCommandNotFound = errors.New("command not found")

// Runner executes OS-native probe commands (fdesetup, spctl, rpm, ...).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real processes with a timeout and a C locale so output
// parsing is stable.
type ExecRunner struct{ Timeout time.Duration }

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCommandNotFound, name)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.CombinedOutput()
}
