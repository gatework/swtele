package cli

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/check"
	"github.com/gatework/swtele/query"
	"github.com/gatework/swtele/topology"
)

type deviceFilters struct {
	platform, model, version, staleConfig           string
	cpuAbove, memAbove                              float64
	scoreBelow                                      int
	tempAlarm, fanPSU, irfNoMAD, irfSplit, singleUp bool
	incomplete                                      bool
}

func (f *deviceFilters) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.platform, "platform", "", flagPlatform)
	fl.StringVar(&f.model, "model", "", flagModel)
	fl.StringVar(&f.version, "version", "", flagVersionFilter)
	fl.StringVar(&f.staleConfig, "stale-config", "", flagStaleConfig)
	fl.Float64Var(&f.cpuAbove, "cpu-above", 0, flagCPUAbove)
	fl.Float64Var(&f.memAbove, "mem-above", 0, flagMemAbove)
	fl.IntVar(&f.scoreBelow, "score-below", 0, flagScoreBelow)
	fl.BoolVar(&f.tempAlarm, "temp-alarm", false, flagTempAlarm)
	fl.BoolVar(&f.fanPSU, "fan-psu-fault", false, flagFanPSU)
	fl.BoolVar(&f.irfNoMAD, "irf-no-mad", false, flagIRFNoMAD)
	fl.BoolVar(&f.irfSplit, "irf-split", false, flagIRFSplit)
	fl.BoolVar(&f.singleUp, "single-uplink", false, flagSingleUplink)
	fl.BoolVar(&f.incomplete, "incomplete", false, flagIncomplete)
}

func (f *deviceFilters) predicate() (query.Device, error) {
	var ps []query.Device
	add := func(on bool, p query.Device) {
		if on {
			ps = append(ps, p)
		}
	}
	add(f.platform != "", query.Platform(f.platform))
	add(f.model != "", query.Model(f.model))
	add(f.version != "", query.Version(f.version))
	add(f.cpuAbove > 0, query.CPUAbove(f.cpuAbove))
	add(f.memAbove > 0, query.MemAbove(f.memAbove))
	add(f.scoreBelow > 0, query.ScoreBelow(f.scoreBelow))
	add(f.tempAlarm, query.TempAlarm())
	add(f.fanPSU, query.FanPSUFault())
	add(f.irfNoMAD, query.IRFNoMAD())
	add(f.irfSplit, query.IRFSplit())
	add(f.singleUp, query.SingleUplink())
	add(f.incomplete, query.Incomplete())
	if f.staleConfig != "" {
		d, err := parseAge(f.staleConfig)
		if err != nil {
			return nil, err
		}
		ps = append(ps, query.StaleConfig(d))
	}
	return query.All(ps...), nil
}

func (a *app) devicesCmd() *cobra.Command {
	var f deviceFilters
	var o outFlags
	cmd := &cobra.Command{
		Use: "devices [选择器...]", Aliases: []string{"设备列表"}, Short: shortDevices,
		Example: "  swtele devices                        # 全网设备概况\n" +
			"  swtele devices --score-below 80       # 健康分低的设备\n" +
			"  swtele devices --irf-no-mad           # 多成员 IRF 未开 MAD\n" +
			"  swtele devices site=hq --cpu-above 70 --sort CPU% --desc-order",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, true)
			if err != nil {
				return err
			}
			pred, err := f.predicate()
			if err != nil {
				return err
			}
			scores, counts, err := a.scores(cmd, s)
			if err != nil {
				return err
			}
			all := s.q.DeviceRows(s.devs)
			for n := range all {
				all[n].Score, all[n].Findings = scores[all[n].Device], counts[all[n].Device]
			}
			rows := query.Filter(all, pred)
			t := &report.Table{Columns: []string{"设备", "地址", "平台", "型号", "版本", "CPU%", "内存%", "最高温度℃", "端口 up/物理", "健康分", "风险"}}
			for _, r := range rows {
				d := r.Device
				up, phys := 0, 0
				for _, i := range d.Interfaces.All() {
					if i.Kind == swtele.KindPhysical {
						phys++
						if i.Up() {
							up++
						}
					}
				}
				t.Add(d.Name(), d.Identity.Mgmt.String(), platformText(d.Identity.Platform), modelText(d), dash(d.System.Version),
					optPct(query.CPU(d)), optPct(query.Memory(d)), optNum(query.Temperature(d)),
					fmt.Sprintf("%d/%d", up, phys), strconv.Itoa(r.Score), strconv.Itoa(r.Findings))
			}
			return a.emit(&o, "设备列表", t, rows, matched(len(rows), len(all), "台设备"), s.dataNote())
		},
	}
	f.add(cmd)
	o.add(cmd, 200)
	return cmd
}

func optPct(v float64, ok bool) string {
	if !ok {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', 0, 64)
}

func optNum(v float64, ok bool) string {
	if !ok {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', 0, 64)
}

func modelText(d *swtele.Device) string {
	switch {
	case d.System.Model == "":
		return "-"
	case d.System.ModelFrom == "neighbor":
		return d.System.Model + "（邻居通告）"
	}
	return d.System.Model
}

// scores assesses the selected devices: health score and the number of
// findings at low severity or above.
func (a *app) scores(cmd *cobra.Command, s *session) (map[*swtele.Device]int, map[*swtele.Device]int, error) {
	res, err := a.assessDevices(cmd, s)
	if err != nil {
		return nil, nil, err
	}
	scores, counts := map[*swtele.Device]int{}, map[*swtele.Device]int{}
	for _, da := range res {
		scores[da.Device] = check.Score(da.Assessment)
		for _, f := range da.Assessment.Findings {
			if f.Severity >= assess.SeverityLow {
				counts[da.Device]++
			}
		}
	}
	return scores, counts, nil
}

func (a *app) deviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "device <选择器...>", Aliases: []string{"设备"}, Short: shortDevice, Args: cobra.MinimumNArgs(1),
		Example: "  swtele device SW01\n  swtele device 192.0.2.1",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, true)
			if err != nil {
				return err
			}
			if a.json {
				return a.emit(&outFlags{}, "", nil, s.devs)
			}
			if len(s.devs) > 5 {
				return fmt.Errorf("选择器匹配 %d 台设备；设备 360 一次最多显示 5 台，列表请用 swtele devices", len(s.devs))
			}
			for n, d := range s.devs {
				if n > 0 {
					fmt.Fprintln(a.out(), strings.Repeat("─", 60))
				}
				if err := a.printDevice(cmd, s, d); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return cmd
}

// printDevice is the device 360 view: identity, platform health, stack,
// ports, neighbors, routing, optics and risks.
func (a *app) printDevice(cmd *cobra.Command, s *session, d *swtele.Device) error {
	w, sys := a.out(), d.System
	fmt.Fprintf(w, "设备：%s（%s）\n", d.Name(), d.Identity.Mgmt)
	fmt.Fprintf(w, "  平台 %s，型号 %s，版本 %s", platformText(d.Identity.Platform), modelText(d), dash(sys.Version))
	if up, ok := sys.Uptime.Get(); ok {
		fmt.Fprintf(w, "，已运行 %d 天", int(up.Hours()/24))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  采集于 %s（%s），批次 %s；%s\n", s.clk.time(d.Observed), s.clk.zone(), s.v.Ledger.Batch, coverageLine(d))
	if c := d.Config; c != nil {
		fmt.Fprintf(w, "  配置备份于 %s\n", s.clk.time(c.At))
	}
	printPlatform(w, d)
	printStack(w, d)
	printPortSummary(w, s, d)
	printNeighbors(w, s, d)
	printPeers(w, d)
	return a.printRisks(cmd, s, d)
}

func coverageLine(d *swtele.Device) string {
	dims := d.Coverage.Dimensions()
	var bad []string
	for _, dim := range dims {
		if st := d.Coverage.Status(dim); st != evidence.StatusComplete {
			bad = append(bad, fmt.Sprintf("%s %s", dim, coverageText[st]))
		}
	}
	line := fmt.Sprintf("采集维度 %d/%d 项完整", len(dims)-len(bad), len(dims))
	if len(bad) > 0 {
		line += "（" + strings.Join(bad, "，") + "）"
	}
	return line
}

func printPlatform(w io.Writer, d *swtele.Device) {
	for _, c := range d.System.CPU {
		var parts []string
		if v, ok := c.Now.Get(); ok {
			parts = append(parts, fmt.Sprintf("当前 %.0f%%", v))
		}
		if v, ok := c.Min1.Get(); ok {
			parts = append(parts, fmt.Sprintf("1 分钟 %.0f%%", v))
		}
		if v, ok := c.Min5.Get(); ok {
			parts = append(parts, fmt.Sprintf("5 分钟 %.0f%%", v))
		}
		fmt.Fprintf(w, "  CPU %s：%s\n", unitText(c.Unit), strings.Join(parts, "，"))
	}
	for _, m := range d.System.Memory {
		if u, ok := m.UsedPercent(); ok {
			line := fmt.Sprintf("  内存 %s：已用 %.1f%%", unitText(m.Unit), u)
			if t, ok := m.Total.Get(); ok && t > 0 {
				line += fmt.Sprintf("（共 %d MB）", t>>20)
			}
			fmt.Fprintln(w, line)
		}
	}
	env := []string{}
	if t, ok := query.Temperature(d); ok {
		env = append(env, fmt.Sprintf("最高温度 %.0f℃", t))
	}
	bad := 0
	for _, c := range append(append([]swtele.Component{}, d.System.Fans...), d.System.PSUs...) {
		if ok, known := c.OK.Get(); known && !ok {
			bad++
		}
	}
	if n := len(d.System.Fans) + len(d.System.PSUs); n > 0 {
		env = append(env, fmt.Sprintf("风扇/电源 %d 个，异常 %d", n, bad))
	}
	if len(env) > 0 {
		fmt.Fprintf(w, "  环境：%s\n", strings.Join(env, "，"))
	}
}

func printStack(w io.Writer, d *swtele.Device) {
	st := d.Stack
	if st == nil || len(st.Members) == 0 {
		return
	}
	var members []string
	for _, m := range st.Members {
		mem := fmt.Sprintf("成员 %d %s", m.ID, memberRole(m.Role))
		if p, ok := m.Priority.Get(); ok && st.Kind == swtele.StackIRF {
			mem += fmt.Sprintf("（优先级 %d）", p)
		}
		members = append(members, mem)
	}
	line := fmt.Sprintf("  %s：%s", stackText[st.Kind], strings.Join(members, "，"))
	if st.Kind == swtele.StackIRF && len(st.Members) > 1 {
		switch {
		case st.MAD == nil:
		case !st.MAD.Enabled():
			line += "；未启用 MAD"
		default:
			line += fmt.Sprintf("；MAD %s %s", strings.ToUpper(strings.Join(st.MAD.Modes, "/")), dash(st.MAD.Status))
		}
	}
	fmt.Fprintln(w, line)
}

func printPortSummary(w io.Writer, s *session, d *swtele.Device) {
	var up, down, shut, optics, alarms int
	speeds := map[string]int{}
	for _, i := range d.Interfaces.All() {
		if i.Kind != swtele.KindPhysical {
			continue
		}
		switch {
		case i.Admin == swtele.StateDown:
			shut++
		case i.Up():
			up++
			speeds[speed(i.Speed)]++
		default:
			down++
		}
		if i.Optics != nil && i.Optics.Present {
			optics++
			if r := (query.OpticRow{Device: d, Port: i, Optic: i.Optics}); query.Abnormal(2, 3)(r) {
				alarms++
			}
		}
	}
	keys := make([]string, 0, len(speeds))
	for k := range speeds {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var dist []string
	for _, k := range keys {
		dist = append(dist, fmt.Sprintf("%s×%d", k, speeds[k]))
	}
	fmt.Fprintf(w, "  端口：物理口 %d（up %d，down %d，管理关闭 %d）", up+down+shut, up, down, shut)
	if len(dist) > 0 {
		fmt.Fprintf(w, "，up 口速率 %s", strings.Join(dist, " "))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  光模块 %d 个（up 口异常 %d），聚合组 %d，ARP %d，MAC %d\n", optics, alarms, len(d.Aggregates), len(d.L3.ARP), len(d.L2.MACs))
	rows := query.Filter(s.q.Ports([]*swtele.Device{d}), query.Errors())
	slices.SortFunc(rows, func(x, y query.PortRow) int { return cmp.Compare(query.ErrorRate(y.Port), query.ErrorRate(x.Port)) })
	for n, r := range rows {
		if n == 3 {
			fmt.Fprintf(w, "    ……共 %d 个端口有错包，见 swtele errors %s\n", len(rows), d.Identity.Mgmt)
			break
		}
		fmt.Fprintf(w, "    错包：%s CRC %s 输入错误 %s，错误率 %s\n", r.Port.Name, count(r.Port.Counters.CRC), count(r.Port.Counters.In.Errors), rateText(query.ErrorRate(r.Port)))
	}
}

func printNeighbors(w io.Writer, s *session, d *swtele.Device) {
	links := s.v.Graph.LinksOf(d)
	if len(links) == 0 {
		return
	}
	fmt.Fprintf(w, "  邻居：%d 条链路\n", len(links))
	for n, l := range links {
		if n == 12 {
			fmt.Fprintf(w, "    ……另有 %d 条，见 swtele topology %s\n", len(links)-12, d.Identity.Mgmt)
			break
		}
		state := linkText[l.State]
		if l.State == topology.Confirmed {
			state = ""
		}
		fmt.Fprintf(w, "    %-24s → %s %s\n", l.A.Port, peerText(l.B, true), state)
	}
}

func printPeers(w io.Writer, d *swtele.Device) {
	if len(d.L3.Peers) == 0 {
		return
	}
	down := 0
	for _, p := range d.L3.Peers {
		if !p.Established {
			down++
		}
	}
	fmt.Fprintf(w, "  路由邻居：%d 个（未建立 %d）\n", len(d.L3.Peers), down)
	for n, p := range d.L3.Peers {
		if n == 8 {
			fmt.Fprintf(w, "    ……另有 %d 个\n", len(d.L3.Peers)-8)
			break
		}
		up := ""
		if u, ok := p.Up.Get(); ok {
			up = "，已建立 " + strings.TrimSuffix(since(u), "前")
		}
		where := dash(p.VRF)
		if p.Family != "" {
			where += " " + p.Family
		}
		fmt.Fprintf(w, "    %s %s（%s）：%s%s\n", strings.ToUpper(string(p.Proto)), p.Address, where, p.State, up)
	}
}
