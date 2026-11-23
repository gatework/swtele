package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/event"
	"github.com/gatework/netops/job"
	"github.com/gatework/netops/store/runs"
	"github.com/gatework/netops/term"

	"github.com/gatework/swtele/internal/bootstrap"
	"github.com/gatework/swtele/internal/workflow"
)

// configs opens the backup directory of the flag, else of the
// configuration; ok is false when neither names one.
func (a *app) configs(r *bootstrap.Resources, flag string) (cfg workflow.Configs, ok bool, err error) {
	dir := cmp.Or(flag, r.ConfigsDir)
	if dir == "" {
		return nil, false, nil
	}
	c, err := bootstrap.Configs(dir)
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// collectOnce collects, imports and summarizes one run.
func (a *app) collectOnce(ctx context.Context, r *bootstrap.Resources, selectors []string, configs string) (workflow.CollectResult, workflow.ImportResult, error) {
	cfg, _, err := a.configs(r, configs)
	if err != nil {
		return workflow.CollectResult{}, workflow.ImportResult{}, err
	}
	cr, ir, err := r.App.Collect(ctx, selectors, cfg)
	if errors.Is(err, bootstrap.ErrNoCredentials) {
		return cr, ir, errors.New("缺少设备凭据：请在 ~/.gatework/.env 中设置 NC_DEVICE_USERNAME 与 NC_DEVICE_PASSWORD（或按平台的 NC_<平台>_USERNAME/PASSWORD），未连接任何设备")
	}
	if errors.Is(err, workflow.ErrNoCollector) {
		return cr, ir, errors.New("未配置在线采集：请在 ~/.gatework/swtele.yml 中设置 inventory（设备清单），并在 ~/.gatework/.env 中提供 NC_DEVICE_USERNAME/NC_DEVICE_PASSWORD")
	}
	return cr, ir, err
}

func (a *app) collectCmd() *cobra.Command {
	var configs string
	cmd := &cobra.Command{
		Use: "collect [选择器...]", Aliases: []string{"采集"}, Short: shortCollect,
		Example: "  swtele collect                 # 采集清单中全部 H3C 与 NX-OS 设备\n  swtele collect site=hq role=access",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			cr, ir, err := a.collectOnce(cmd.Context(), r, args, configs)
			if a.json {
				_ = term.WriteJSON(a.out(), map[string]any{"collect": cr, "import": ir})
			} else if cr.Devices > 0 {
				fmt.Fprintf(a.out(), "采集 %d 台，成功 %d 台，失败 %d 台\n", cr.Devices, cr.Collected, len(cr.Failed))
				for _, h := range cr.Failed {
					fmt.Fprintf(a.out(), "  失败：%s\n", h)
				}
				if ir.Manifest.Batch != "" {
					fmt.Fprintf(a.out(), "批次 %s：解析 %d 台，终端 %d 个，迁移 %d 个\n", ir.Manifest.Batch, ir.Decoded, ir.Endpoints, len(ir.Moves))
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&configs, "configs", "", flagConfigs)
	return cmd
}

func (a *app) watchCmd() *cobra.Command {
	var every string
	var once bool
	cmd := &cobra.Command{
		Use: "watch [选择器...]", Aliases: []string{"巡检"}, Short: shortWatch,
		Example: "  swtele watch --every @every 4h\n  swtele watch --every '0 */2 * * *' role=core",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			expr := every
			if expr == "" {
				expr = r.Config.Schedule
			}
			if expr == "" {
				expr = "@every 4h"
			}
			spec, err := job.ParseSpec(expr, time.Local)
			if err != nil {
				return fmt.Errorf("无效的计划 %q：%w", expr, err)
			}
			bus, err := a.bus(r)
			if err != nil {
				return err
			}
			hist, err := runs.Open(filepath.Join(r.Data, "runs"), 200)
			if err != nil {
				return err
			}
			j := job.Job{Name: "swtele.watch", Spec: spec, Timeout: 6 * time.Hour,
				Run: func(ctx context.Context) (string, error) { return a.watchRun(ctx, r, bus, args) }}
			s, err := job.NewScheduler([]job.Job{j}, job.Options{History: hist, Events: bus, Source: "swtele"})
			if err != nil {
				return err
			}
			if once {
				run := s.RunNow(cmd.Context(), j)
				fmt.Fprintf(a.out(), "%s：%s %v\n", run.Status, run.Summary, run.Codes)
				return nil
			}
			fmt.Fprintf(a.out(), "按计划 %s 定时采集与评估，Ctrl-C 结束\n", spec)
			return s.Run(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&every, "every", "", flagEvery)
	cmd.Flags().BoolVar(&once, "once", false, flagOnce)
	return cmd
}

// bus publishes events to the configured routes (events file, webhook).
func (a *app) bus(r *bootstrap.Resources) (*event.Bus, error) {
	return event.NewBus(r.Routes...)
}

// watchRun is one scheduled run: collect, import, assess, and publish the
// high findings and endpoint moves.
func (a *app) watchRun(ctx context.Context, r *bootstrap.Resources, bus *event.Bus, selectors []string) (string, error) {
	cr, ir, err := a.collectOnce(ctx, r, selectors, "")
	if err != nil {
		return "", err
	}
	v, err := r.App.Open(ctx, ir.Manifest.Batch, true)
	if err != nil {
		return "", err
	}
	res, err := v.Assess(ctx, r.Policy, nil)
	if err != nil {
		return "", err
	}
	now := a.env.Now()
	var events []event.Event
	high := 0
	for _, f := range filter(res, assess.SeverityHigh, "") {
		high++
		e, err := event.New(event.Event{Kind: event.KindComplianceViolation, Severity: f.Severity, At: now, Source: "swtele",
			Subject: f.Subject.String(), Summary: string(f.Rule) + "：" + f.Title, Fields: f.Fields})
		if err == nil {
			events = append(events, e)
		}
	}
	for _, m := range ir.Moves {
		e, err := event.New(event.Event{Kind: "endpoint.moved", Severity: assess.SeverityInfo, At: now, Source: "swtele",
			Subject: m.IP + " " + m.MAC, Summary: "终端迁移：" + m.From.Device + " " + m.From.Port + " → " + m.To.Device + " " + m.To.Port})
		if err == nil {
			events = append(events, e)
		}
	}
	if err := bus.Publish(ctx, events...); err != nil {
		return "", err
	}
	return fmt.Sprintf("采集 %d/%d 台，批次 %s，高危发现 %d，终端迁移 %d", cr.Collected, cr.Devices, ir.Manifest.Batch, high, len(ir.Moves)), nil
}
