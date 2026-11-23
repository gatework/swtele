package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/capacity"
)

func (a *app) capacityCmd() *cobra.Command {
	var days, freeBelow int
	var hot float64
	var detail bool
	var o outFlags
	cmd := &cobra.Command{
		Use: "capacity [选择器...]", Aliases: []string{"容量"}, Short: shortCapacity,
		Example: "  swtele capacity                    # 每台设备的端口使用与可回收端口\n" +
			"  swtele capacity --free-below 4     # 空闲口不足、需要扩容的设备\n" +
			"  swtele capacity SW01 --detail      # 列出闲置口与热点口",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			opts := capacity.Options{IdleDays: days, HotPercent: hot}
			var all, rows []capacity.Summary
			for _, d := range s.devs {
				sum := capacity.Device(d, opts)
				all = append(all, sum)
				if freeBelow > 0 && sum.Down >= freeBelow {
					continue
				}
				rows = append(rows, sum)
			}
			if detail || len(s.devs) == 1 {
				return a.capacityDetail(&o, s, rows, days)
			}
			t := &report.Table{Columns: []string{"设备", "物理口", "up", "down", "管理关闭", "闲置≥" + strconv.Itoa(days) + "天", "热点", "利用率"}}
			var phys, up, idle int
			for _, c := range rows {
				t.Add(c.Device, strconv.Itoa(c.Physical), strconv.Itoa(c.Up), strconv.Itoa(c.Down), strconv.Itoa(c.Disabled),
					strconv.Itoa(len(c.Idle)), strconv.Itoa(len(c.Hot)), percent(float64(c.Up)*100/float64(max(c.Physical, 1))))
				phys, up, idle = phys+c.Physical, up+c.Up, idle+len(c.Idle)
			}
			return a.emit(&o, "端口容量", t, rows, matched(len(rows), len(all), "台设备"),
				fmt.Sprintf("合计：物理口 %d，up %d（%s），可回收闲置口 %d（管理关闭的端口不计入）", phys, up, percent(float64(up)*100/float64(max(phys, 1))), idle),
				s.dataNote())
		},
	}
	cmd.Flags().IntVar(&days, "idle-days", 30, flagIdleDays)
	cmd.Flags().Float64Var(&hot, "hot", 70, flagHot)
	cmd.Flags().IntVar(&freeBelow, "free-below", 0, flagFreeBelow)
	cmd.Flags().BoolVar(&detail, "detail", false, flagDetail)
	o.add(cmd, 300)
	return cmd
}

func (a *app) capacityDetail(o *outFlags, s *session, rows []capacity.Summary, days int) error {
	t := &report.Table{Columns: []string{"设备", "端口", "类别", "说明", "描述"}}
	for _, c := range rows {
		for _, i := range c.Idle {
			what := "从未 up"
			if !i.Never {
				what = since(i.Since) + "变为 down"
			}
			t.Add(c.Device, i.Port, "闲置", what, dash(i.Desc))
		}
		for _, h := range c.Hot {
			t.Add(c.Device, h.Port, "热点", fmt.Sprintf("利用率 %s（%s）", percent(h.Percent), speed(swtele.Some(h.Speed))), dash(h.Desc))
		}
	}
	return a.emit(o, "端口容量明细", t, rows, fmt.Sprintf("闲置：down 超过 %d 天或从未 up 的启用端口", days), s.dataNote())
}
