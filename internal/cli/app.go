// Package cli is the Chinese command line of swtele.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	nboot "github.com/gatework/netops/bootstrap"

	"github.com/gatework/swtele/internal/bootstrap"
	"github.com/gatework/swtele/internal/workflow"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1 // findings at or above --fail-on
	ExitError    = 2
)

// Version is the release of the command.
const Version = "0.1.0"

var errFindings = errors.New("cli: findings at or above the threshold")

// Env is the process environment of a run.
type Env struct {
	Stdout, Stderr io.Writer
	Environ        map[string]string
	Home           string
	Now            func() time.Time
}

type app struct {
	env    Env
	config string
	batch  string
	json   bool
	res    *bootstrap.Resources
	// refresh holds the --refresh settings of the analysis commands.
	refresh map[*cobra.Command]*refreshSpec
}

// Run executes args and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	a := &app{env: env}
	root := a.root() //nolint:contextcheck // cobra hands ctx to every command through cmd.Context()
	root.SetArgs(args)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errFindings):
		return ExitFindings
	default:
		fmt.Fprintln(env.Stderr, errText(err))
		return ExitError
	}
}

func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use: "swtele", Short: shortRoot, Long: longRoot, Version: Version,
		SilenceErrors: true, SilenceUsage: true,
	}
	root.PersistentFlags().StringVar(&a.config, "config", "", flagConfig)
	root.PersistentFlags().StringVar(&a.batch, "batch", "", flagBatch)
	root.PersistentFlags().BoolVar(&a.json, "json", false, flagJSON)
	rf := a.refreshable
	root.AddCommand(a.importCmd(), a.batchesCmd(),
		rf(a.devicesCmd(), dimsAll, nil), rf(a.deviceCmd(), dimsAll, nil),
		rf(a.portCmd(), dimsPorts, nil), rf(a.errorsCmd(), dimsErrors, nil), rf(a.opticsCmd(), dimsOptics, nil),
		rf(a.locateCmd(), dimsLocate, endpointDevices), rf(a.endpointsCmd(), dimsLocate, nil), rf(a.pathCmd(), dimsLocate, endpointDevices),
		rf(a.topologyCmd(), dimsTopology, neighbors), rf(a.discoverCmd(), dimsTopology, nil),
		rf(a.riskCmd(), dimsAll, nil), a.reportCmd(), a.historyCmd(), a.diffCmd(), a.trendCmd(), a.collectCmd(), a.watchCmd(),
		rf(a.capacityCmd(), dimsErrors, nil), a.assetsCmd(), a.rebuildCmd(),
		rf(a.findingsCmd("flap [选择器...]", "抖动", shortFlap, []string{"flap."}, "  swtele flap role=core"), dimsFlap, nil),
		rf(a.findingsCmd("health [选择器...]", "运行", shortHealth, []string{"health.", "stack.", "lag.", "routing.", "stp."}, "  swtele health --severity high"), dimsHealth, nil))
	localize(root)
	return root
}

// load wires the resources once per run.
func (a *app) load(ctx context.Context) (*bootstrap.Resources, error) {
	if a.res != nil {
		return a.res, nil
	}
	r, err := bootstrap.Load(ctx, nboot.Env{Environ: a.env.Environ, Home: a.env.Home}, a.config)
	if errors.Is(err, bootstrap.ErrNoDataDir) {
		return nil, errors.New("无法确定数据目录：请设置 HOME，或在配置文件中设置 data_dir")
	}
	if err != nil {
		return nil, err
	}
	r.App.Now = a.env.Now
	a.res = r
	return r, nil
}

func (a *app) view(ctx context.Context, withPrev bool) (*workflow.View, *bootstrap.Resources, error) {
	r, err := a.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	v, err := r.App.Open(ctx, a.batch, withPrev)
	if err != nil {
		return nil, nil, friendly(err)
	}
	return v, r, nil
}

// friendly translates the errors an operator can act on.
func friendly(err error) error {
	switch {
	case strings.Contains(err.Error(), "no ledger batch"):
		return errors.New("还没有台账批次，请先运行 swtele import <快照目录>")
	case errors.Is(err, workflow.ErrNoDevice):
		return fmt.Errorf("台账中找不到设备：%s", strings.TrimPrefix(err.Error(), "workflow: no such device: "))
	}
	return err
}

func parseSeverity(s string) (assess.Severity, error) {
	if s == "" {
		return assess.SeverityUnset, nil
	}
	sev, err := assess.ParseSeverity(s)
	if err != nil {
		return 0, fmt.Errorf("无效的级别 %q", s)
	}
	return sev, nil
}
