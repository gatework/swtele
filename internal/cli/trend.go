package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/metrics"
)

var metricText = map[metrics.Metric]string{
	metrics.CRC: "CRC", metrics.Errors: "输入错误", metrics.Discards: "出向丢弃", metrics.Util: "利用率%",
	metrics.Rx: "收光 dBm", metrics.CPU: "CPU%", metrics.Memory: "内存%", metrics.Temp: "温度℃",
}

func (a *app) trendCmd() *cobra.Command {
	var metric, port string
	var batches int
	var sustained bool
	var o outFlags
	cmd := &cobra.Command{
		Use: "trend [选择器...]", Aliases: []string{"趋势"}, Short: shortTrend,
		Example: "  swtele trend --metric crc                  # 近 10 个批次错包增长最多的端口\n" +
			"  swtele trend SW01 --port GE1/0/1 --metric crc   # 逐批次序列\n" +
			"  swtele trend --metric rx --sustained        # 收光持续下降的端口\n" +
			"  swtele trend role=core --metric cpu --batches 30",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := metrics.ParseMetric(metric)
			if err != nil {
				return fmt.Errorf("无效的指标 %q（可选 crc、errors、discards、util、rx、cpu、mem、temp）", metric)
			}
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			snaps, err := s.r.App.Snapshots(cmd.Context(), a.batch, batches)
			if err != nil {
				return friendly(err)
			}
			keep := map[string]bool{}
			for _, d := range s.devs {
				keep[d.Identity.Mgmt.String()] = true
			}
			var pick func(string) bool
			if port != "" {
				k := swtele.InterfaceKey(port)
				pick = func(p string) bool { return swtele.InterfaceKey(p) == k }
			}
			all := metrics.Trend(snaps, m, keep, pick)
			rows := slices.DeleteFunc(slices.Clone(all), func(x metrics.Series) bool {
				// A counter that never grew is no trend; neither is a
				// series that did not worsen every time, with --sustained.
				return m.Counter() && port == "" && x.Growth() == 0 || sustained && !x.Sustained()
			})
			span := fmt.Sprintf("%d 个批次（%s ～ %s）", len(snaps), s.clk.time(snaps[0].At), s.clk.time(snaps[len(snaps)-1].At))
			if len(rows) == 1 && !a.json {
				return a.emit(&o, "指标序列", seriesTable(s, rows[0]), rows, span+"，时间均为 "+s.clk.zone())
			}
			t := summaryTable(rows, m)
			notes := []string{matched(len(rows), len(all), "条序列") + "；" + span}
			if len(snaps) < 2 {
				notes = append(notes, "只有一个批次，无法计算变化")
			}
			return a.emit(&o, metricText[m]+"趋势", t, rows, append(notes, s.dataNote())...)
		},
	}
	cmd.Flags().StringVar(&metric, "metric", "crc", flagMetric)
	cmd.Flags().StringVar(&port, "port", "", flagPort)
	cmd.Flags().IntVar(&batches, "batches", 10, flagBatches)
	cmd.Flags().BoolVar(&sustained, "sustained", false, flagSustained)
	o.add(cmd, 50)
	return cmd
}

// summaryTable ranks series: counters by growth, gauges by change in the
// bad direction.
func summaryTable(rows []metrics.Series, m metrics.Metric) *report.Table {
	bad := func(x metrics.Series) float64 {
		switch {
		case m.Counter():
			return x.Growth()
		case m == metrics.Rx:
			return -x.Change()
		}
		return x.Change()
	}
	slices.SortStableFunc(rows, func(x, y metrics.Series) int { return cmp.Compare(bad(y), bad(x)) })
	cols := []string{"设备", "端口", "起始", "最新", "变化", "持续"}
	if m.Counter() {
		cols = []string{"设备", "端口", "起始", "最新", "累计增长", "每小时", "增长批次", "持续"}
	}
	t := &report.Table{Columns: cols}
	for _, x := range rows {
		first, last := x.Points[0], x.Points[len(x.Points)-1]
		mark := "-"
		if x.Sustained() {
			mark = "是"
		}
		if m.Counter() {
			var hours float64
			if h := last.At.Sub(first.At).Hours(); h > 0 {
				hours = x.Growth() / h
			}
			t.Add(x.Device, dash(x.Port), num(first.Value), num(last.Value), num(x.Growth()), strconv.FormatFloat(hours, 'f', 1, 64),
				fmt.Sprintf("%d/%d", x.Growing(), len(x.Points)-1), mark)
			continue
		}
		t.Add(x.Device, dash(x.Port), num(first.Value), num(last.Value), signed(x.Change()), mark)
	}
	return t
}

func seriesTable(s *session, x metrics.Series) *report.Table {
	t := &report.Table{Columns: []string{"批次", "时间", metricText[x.Metric], "增长", "每小时"}}
	for _, p := range x.Points {
		delta, rate := "-", "-"
		switch {
		case p.Reset:
			delta = "计数清零或重启"
		case x.Metric.Counter() && p.Delta > 0:
			delta, rate = num(p.Delta), strconv.FormatFloat(p.PerHour, 'f', 1, 64)
		}
		t.Add(p.Batch, s.clk.time(p.At), num(p.Value), delta, rate)
	}
	return t
}

func num(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

func signed(v float64) string {
	if v > 0 {
		return "+" + num(v)
	}
	return strings.TrimSpace(num(v))
}
