package cli

import (
	"cmp"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/term"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/capacity"
	"github.com/gatework/swtele/check"
	"github.com/gatework/swtele/internal/bootstrap"
)

// printRisks prints the health score and the most severe findings of d.
func (a *app) printRisks(cmd *cobra.Command, d *swtele.Device) error {
	res, _, err := a.assess(cmd, d.Identity.Mgmt.String())
	if err != nil || len(res) == 0 {
		return err
	}
	as := res[0].Assessment
	fmt.Fprintf(a.out(), "健康分：%d（发现 %d 条）\n", check.Score(as), len(as.Findings))
	for n, f := range as.Findings {
		if n == 8 {
			fmt.Fprintf(a.out(), "  ……另有 %d 条，见 swtele risk --device %s\n", len(as.Findings)-8, d.Identity.Mgmt)
			break
		}
		fmt.Fprintf(a.out(), "  [%s] %s %s\n", f.Severity, f.Subject.String(), cmp.Or(f.Detail, f.Title))
	}
	return nil
}

// ruleCmd is a risk report restricted to a rule family.
func (a *app) ruleCmd(use, alias, short string, prefixes ...string) *cobra.Command {
	var dev, sev string
	var limit int
	cmd := &cobra.Command{
		Use: use + " [设备]", Aliases: []string{alias}, Short: short, Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			floor, err := parseSeverity(sev)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				dev = args[0]
			}
			res, _, err := a.assess(cmd, dev)
			if err != nil {
				return err
			}
			var fs []assess.Finding
			for _, p := range prefixes {
				fs = append(fs, filter(res, floor, p)...)
			}
			if a.json {
				return term.WriteJSON(a.out(), fs)
			}
			t := term.NewTable("级别", "规则", "对象", "说明")
			for _, f := range fs {
				t.Add(f.Severity.String(), string(f.Rule), f.Subject.String(), cmp.Or(f.Detail, f.Title))
			}
			omitted, err := t.Render(a.out(), limit)
			if omitted > 0 {
				fmt.Fprintf(a.out(), "……另有 %d 条未显示\n", omitted)
			}
			fmt.Fprintf(a.out(), "共 %d 条发现\n", len(fs))
			return err
		},
	}
	cmd.Flags().StringVar(&sev, "severity", "", flagSev)
	cmd.Flags().IntVar(&limit, "limit", 200, flagLimit)
	return cmd
}

func (a *app) capacityCmd() *cobra.Command {
	var days int
	var hot float64
	var detail bool
	cmd := &cobra.Command{
		Use: "capacity [设备]", Aliases: []string{"容量"}, Short: shortCapacity, Args: cobra.MaximumNArgs(1),
		Example: "  swtele capacity              # 全网端口使用与可回收端口\n  swtele capacity SW01 --detail",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := a.view(cmd.Context(), false)
			if err != nil {
				return err
			}
			devs := v.Ledger.Devices()
			if len(args) == 1 {
				d, err := v.Device(args[0])
				if err != nil {
					return friendly(err)
				}
				devs, detail = []*swtele.Device{d}, true
			}
			o := capacity.Options{IdleDays: days, HotPercent: hot}
			var all []capacity.Summary
			for _, d := range devs {
				all = append(all, capacity.Device(d, o))
			}
			if a.json {
				return term.WriteJSON(a.out(), all)
			}
			return a.printCapacity(all, cmp.Or(days, 30), detail)
		},
	}
	cmd.Flags().IntVar(&days, "idle-days", 30, flagIdleDays)
	cmd.Flags().Float64Var(&hot, "hot", 70, flagHot)
	cmd.Flags().BoolVar(&detail, "detail", false, flagDetail)
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

func (a *app) printCapacity(all []capacity.Summary, days int, detail bool) error {
	t := term.NewTable("设备", "物理口", "up", "down", "关闭", "闲置≥"+strconv.Itoa(days)+"天", "热点")
	var phys, up, idle int
	for _, s := range all {
		t.Add(s.Device, strconv.Itoa(s.Physical), strconv.Itoa(s.Up), strconv.Itoa(s.Down), strconv.Itoa(s.Disabled), strconv.Itoa(len(s.Idle)), strconv.Itoa(len(s.Hot)))
		phys, up, idle = phys+s.Physical, up+s.Up, idle+len(s.Idle)
	}
	if _, err := t.Render(a.out(), 0); err != nil {
		return err
	}
	fmt.Fprintf(a.out(), "合计：物理口 %d，up %d（%.0f%%），可回收闲置口 %d\n", phys, up, float64(up)*100/float64(max(phys, 1)), idle)
	if !detail {
		return nil
	}
	for _, s := range all {
		for _, i := range s.Idle {
			since := "从未 up"
			if !i.Never {
				since = term.Duration(i.Since) + " 前变为 down"
			}
			fmt.Fprintf(a.out(), "  闲置 %s %s：%s %s\n", s.Device, i.Port, since, term.Dash(i.Desc))
		}
		for _, h := range s.Hot {
			fmt.Fprintf(a.out(), "  热点 %s %s：%.1f%%（%s）%s\n", s.Device, h.Port, h.Percent, speed(swtele.Some(h.Speed)), term.Dash(h.Desc))
		}
	}
	return nil
}
