package cli

import (
	"cmp"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/report"
	"github.com/gatework/netops/term"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/internal/bootstrap"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/topology"
)

func (a *app) importCmd() *cobra.Command {
	var configs string
	cmd := &cobra.Command{
		Use: "import <快照目录>", Aliases: []string{"导入"}, Short: shortImport, Args: cobra.ExactArgs(1),
		Example: "  swtele import ~/Documents/Snapshots/devices --configs ~/Documents/2026-10-14",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			src, err := bootstrap.Source(args[0])
			if err != nil {
				return err
			}
			cfg, _, err := a.configs(r, configs)
			if err != nil {
				return err
			}
			res, err := r.App.Import(cmd.Context(), src, cfg)
			if err != nil {
				return err
			}
			if a.json {
				return term.WriteJSON(a.out(), res)
			}
			fmt.Fprintf(a.out(), "批次 %s：解析 %d 台设备（其中 %d 台叠加了配置），暂不支持的平台 %d 台，失败 %d 台\n",
				res.Manifest.Batch, res.Decoded, res.Configured, len(res.Unsupported), len(res.Failed))
			for _, h := range res.Failed {
				fmt.Fprintf(a.out(), "  未解析：%s\n", h)
			}
			fmt.Fprintf(a.out(), "终端：%d 个定位到接入口，%d 个较上批次迁移\n", res.Endpoints, len(res.Moves))
			for n, m := range res.Moves {
				if n == 20 {
					fmt.Fprintf(a.out(), "  ……另有 %d 个\n", len(res.Moves)-20)
					break
				}
				fmt.Fprintf(a.out(), "  %s %s：%s %s → %s %s\n", m.IP, m.MAC, m.From.Device, m.From.Port, m.To.Device, m.To.Port)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configs, "configs", "", flagConfigs)
	return cmd
}

func (a *app) rebuildCmd() *cobra.Command {
	var configs string
	cmd := &cobra.Command{
		Use: "rebuild", Aliases: []string{"重建"}, Short: shortRebuild, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, r, err := a.view(cmd.Context(), false)
			if err != nil {
				return err
			}
			if v.Manifest.Source == "" {
				return fmt.Errorf("批次 %s 没有记录来源目录，无法重建", v.Manifest.Batch)
			}
			src, err := bootstrap.Source(v.Manifest.Source)
			if err != nil {
				return err
			}
			cfg, _, err := a.configs(r, configs)
			if err != nil {
				return err
			}
			res, err := r.App.Import(cmd.Context(), src, cfg)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.out(), "由 %s 的来源重建为批次 %s：解析 %d 台设备\n", v.Manifest.Batch, res.Manifest.Batch, res.Decoded)
			return nil
		},
	}
	cmd.Flags().StringVar(&configs, "configs", "", flagConfigs)
	return cmd
}

func (a *app) reportCmd() *cobra.Command {
	var format, sev string
	cmd := &cobra.Command{
		Use: "report [选择器...]", Aliases: []string{"报表"}, Short: shortReport,
		RunE: func(cmd *cobra.Command, args []string) error {
			floor, err := parseSeverity(cmp.Or(sev, "medium"))
			if err != nil {
				return err
			}
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			res, err := a.assessDevices(cmd, s)
			if err != nil {
				return err
			}
			doc := summary(s, res, floor)
			switch format {
			case "markdown", "md":
				return report.Markdown(a.out(), doc)
			case "json":
				return report.JSON(a.out(), doc)
			default:
				return report.Text(a.out(), doc)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", flagFormat)
	cmd.Flags().StringVar(&sev, "severity", "", flagSev)
	return cmd
}

func summary(s *session, res []workflow.DeviceAssessment, floor assess.Severity) report.Document {
	v := s.v
	var phys, up, optics, arp, macs int
	for _, d := range s.devs {
		for _, i := range d.Interfaces.All() {
			if i.Kind == swtele.KindPhysical {
				phys++
				if i.Up() {
					up++
				}
			}
			if i.Optics != nil && i.Optics.Present {
				optics++
			}
		}
		arp += len(d.L3.ARP)
		macs += len(d.L2.MACs)
	}
	stats := map[topology.State]int{}
	for _, r := range s.q.Links(s.devs) {
		stats[r.Link.State]++
	}
	fs := filter(res, floor, "")
	byRule := ruleSummary(fs)
	detail := &report.Table{Columns: []string{"级别", "设备", "对象", "问题", "说明"}}
	for _, x := range fs {
		detail.Add(severityText[x.Severity], x.Subject.Parts()[0].Key, subjectText(x.Subject, true), x.Title, x.Detail)
	}
	return report.Document{
		Title:     "网络运行态台账报告（批次 " + v.Ledger.Batch + "）",
		Generated: v.Ledger.At.In(s.clk.loc),
		Summary: []report.KV{
			{Key: "设备", Value: strconv.Itoa(len(s.devs))},
			{Key: "物理端口", Value: fmt.Sprintf("%d（up %d，利用率 %.0f%%）", phys, up, float64(up)*100/float64(max(phys, 1)))},
			{Key: "光模块", Value: strconv.Itoa(optics)},
			{Key: "互联链路", Value: fmt.Sprintf("双向 %d，单向 %d，共享网段 %d，非受管邻居 %d", stats[topology.Confirmed], stats[topology.OneWay], stats[topology.Shared], stats[topology.Unmanaged])},
			{Key: "ARP / MAC", Value: fmt.Sprintf("%d / %d", arp, macs)},
			{Key: "风险发现（" + severityText[floor] + "级及以上）", Value: strconv.Itoa(len(fs))},
			{Key: "数据", Value: s.dataNote()},
		},
		Sections: []report.Section{
			{Title: "按问题汇总", Table: byRule},
			{Title: "风险明细", Table: detail},
		},
	}
}
