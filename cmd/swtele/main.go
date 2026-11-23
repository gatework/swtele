// Command swtele builds the runtime ledger of network devices and answers
// operations questions on it: where an endpoint attaches, which links
// lose light or grow errors, which stacks lack split protection.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	nboot "github.com/gatework/netops/bootstrap"

	"github.com/gatework/swtele/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	home, _ := os.UserHomeDir()
	code := cli.Run(ctx, os.Args[1:], cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Environ: nboot.Environ(os.Environ()), Home: home})
	stop()
	os.Exit(code)
}
