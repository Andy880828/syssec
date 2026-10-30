// Command syssec is an agent-native host security posture and
// vulnerability-intelligence CLI for Linux, macOS and Windows.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/Andy880828/syssec/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
