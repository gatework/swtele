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
	"github.com/gatework/swtele/query"
)

// portFilters are the scenario filters of the port and errors commands.
type portFilters struct {
	port, status, idle, flapping, speedBelow, mode, role, desc string
	vlan, macsAbove                                            int
	utilAbove, rateAbove                                       float64
	errors, growing, halfDuplex, noDesc, descMismatch, drift   bool
	kind                                                       string
}

func (f *portFilters) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.port, "port", "", flagPort)
	fl.StringVar(&f.status, "status", "", flagStatus)
	fl.StringVar(&f.idle, "idle", "", flagIdle)
	fl.StringVar(&f.flapping, "flapping", "", flagFlapping)
	fl.StringVar(&f.speedBelow, "speed-below", "", flagSpeedBelow)
	fl.StringVar(&f.mode, "mode", "", flagMode)
	fl.StringVar(&f.role, "role", "", flagRole)
	fl.StringVar(&f.desc, "desc", "", flagDesc)
	fl.IntVar(&f.vlan, "vlan", 0, flagVLAN)
	fl.IntVar(&f.macsAbove, "macs-above", 0, flagMACsAbove)
	fl.Float64Var(&f.utilAbove, "util-above", 0, flagUtilAbove)
	fl.Float64Var(&f.rateAbove, "rate-above", 0, flagRateAbove)
	fl.BoolVar(&f.errors, "errors", false, flagErrors)
	fl.BoolVar(&f.growing, "growing", false, flagGrowing)
	fl.BoolVar(&f.halfDuplex, "half-duplex", false, flagHalfDuplex)
	fl.BoolVar(&f.noDesc, "no-desc", false, flagNoDesc)
	fl.BoolVar(&f.descMismatch, "desc-mismatch", false, flagDescMismatch)
	fl.BoolVar(&f.drift, "drift", false, flagDrift)
	fl.StringVar(&f.kind, "kind", "", flagKind)
}

// predicate builds the conjunction of the given filters.
func (f *portFilters) predicate() (query.Port, error) {
	var ps []query.Port
	if f.port != "" {
		k := swtele.InterfaceKey(f.port)
		ps = append(ps, func(r query.PortRow) bool { return r.Port.Key() == k })
	}
	if f.status != "" {
		if !slices.Contains([]string{"up", "down", "admin-down", "err-disabled", "stp-down"}, f.status) {
			return nil, fmt.Errorf("无效的状态 %q（可选 up、down、admin-down、err-disabled、stp-down）", f.status)
		}
		ps = append(ps, query.Status(f.status))
	}
	if f.idle != "" {
		d, err := parseAge(f.idle)
		if err != nil {
			return nil, err
		}
		ps = append(ps, query.Idle(d))
	}
	if f.flapping != "" {
		d, err := parseAge(f.flapping)
		if err != nil {
			return nil, err
		}
		ps = append(ps, query.Flapping(d))
	}
	if f.speedBelow != "" {
		bps, err := parseSpeed(f.speedBelow)
		if err != nil {
			return nil, err
		}
		ps = append(ps, query.SpeedBelow(bps))
	}
	add := func(on bool, p query.Port) {
		if on {
			ps = append(ps, p)
		}
	}
	add(f.mode != "", query.Mode(f.mode))
	add(f.role != "", query.Role(f.role))
	add(f.desc != "", query.Desc(f.desc))
	add(f.vlan > 0, query.VLAN(f.vlan))
	add(f.macsAbove > 0, query.MACsAbove(f.macsAbove))
	add(f.utilAbove > 0, query.UtilAbove(f.utilAbove))
	add(f.rateAbove > 0, query.RateAbove(f.rateAbove))
	add(f.errors, query.Errors())
	add(f.growing, query.Growing())
	add(f.halfDuplex, query.HalfDuplex())
	add(f.noDesc, query.NoDesc())
	add(f.descMismatch, query.DescMismatch())
	add(f.drift, query.Drifted())
	add(f.kind != "", query.Kind(f.kind))
	return query.All(ps...), nil
}

func (a *app) portCmd() *cobra.Command {
	var f portFilters
	var o outFlags
	cmd := &cobra.Command{
		Use: "port [选择器...]", Aliases: []string{"端口"}, Short: shortPort,
		Example: "  swtele port SW01                       # 一台设备的端口台账\n" +
			"  swtele port SW01 --port GE1/0/1        # 单个端口详情\n" +
			"  swtele port role=access --idle 30d     # 可回收的闲置口\n" +
			"  swtele port --role edge --macs-above 5 # 疑似私接交换机的接入口\n" +
			"  swtele port --no-desc                  # up 但缺描述的端口",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, f.growing)
			if err != nil {
				return err
			}
			pred, err := f.predicate()
			if err != nil {
				return err
			}
			all := s.q.Ports(s.devs)
			rows := query.Filter(all, pred)
			if f.port != "" && len(rows) == 1 && !a.json {
				return a.printPort(cmd, s, rows[0])
			}
			t := &report.Table{Columns: []string{"设备", "端口", "状态", "速率", "模式", "VLAN", "描述", "聚合", "角色", "邻居", "终端", "CRC"}}
			for _, r := range rows {
				i := r.Port
				mode := "-"
				if i.Switching != nil {
					mode = dash(modeText[i.Switching.Mode])
				}
				t.Add(r.Device.Name(), i.Name, stateText(i), speed(i.Speed), mode, vlanText(i), dash(i.Desc), dash(i.Aggregate),
					dash(roleText[r.Role]), peerText(r.Peer, r.HasPeer), strconv.Itoa(r.MACs), count(i.Counters.CRC))
			}
			return a.emit(&o, "端口台账", t, rows, matched(len(rows), len(all), "个端口"), s.dataNote())
		},
	}
	f.add(cmd)
	o.add(cmd, 200)
	return cmd
}

// printPort is the detail view of one port.
func (a *app) printPort(cmd *cobra.Command, s *session, r query.PortRow) error {
	w, d, i := a.out(), r.Device, r.Port
	fmt.Fprintf(w, "%s %s：%s，速率 %s %s，MTU %s\n", d.Name(), i.Name, stateText(i), speed(i.Speed), dash(duplexText[i.Duplex]), dash(optInt(i.MTU)))
	fmt.Fprintf(w, "描述：%s\n", dash(i.Desc))
	fmt.Fprintf(w, "类型：%s，介质 %s，MAC %s，拓扑角色 %s", dash(kindText[i.Kind]), dash(i.Media), dash(i.MAC.String()), dash(roleText[r.Role]))
	if i.Aggregate != "" {
		fmt.Fprintf(w, "，属于聚合 %s", i.Aggregate)
	}
	fmt.Fprintln(w)
	if sw := i.Switching; sw != nil {
		fmt.Fprintf(w, "二层：%s，PVID %s，VLAN %s\n", dash(modeText[sw.Mode]), dash(optInt(sw.PVID)), vlanText(i))
	}
	for _, ad := range i.Addresses {
		fmt.Fprintf(w, "地址：%s %s\n", ad.Prefix, dash(i.VRF))
	}
	if c := r.Config; c != nil {
		cfg := fmt.Sprintf("配置意图：模式 %s", dash(modeText[c.Mode]))
		if c.Allowed != nil && !c.Allowed.IsEmpty() {
			cfg += "，VLAN " + c.Allowed.Compact()
		}
		if c.Aggregate != "" {
			cfg += "，聚合 " + c.Aggregate
		}
		if shut, ok := c.Shutdown.Get(); ok && shut {
			cfg += "，shutdown"
		}
		fmt.Fprintln(w, cfg)
		if diff := query.Drift(r); len(diff) > 0 {
			fmt.Fprintf(w, "  与运行态不一致：%s\n", strings.Join(driftText(diff), "、"))
		}
	}
	printCounters(a, r)
	switch {
	case i.Flap.Never:
		fmt.Fprintln(w, "抖动：从未 up/down")
	case i.Flap.Since.OK:
		fmt.Fprintf(w, "最近一次 up/down：%s\n", since(i.Flap.Since.V))
	}
	if x := i.Optics; x != nil && x.Present {
		printOptic(a, query.OpticRow{Device: d, Port: i, Optic: x})
	}
	fmt.Fprintf(w, "邻居：%s\n", peerText(r.Peer, r.HasPeer))
	printEndpoints(a, s, d, i)
	if err := a.printPortRisks(cmd, s, d, i); err != nil {
		return err
	}
	fmt.Fprintln(w, s.dataNote())
	return nil
}

func printCounters(a *app, r query.PortRow) {
	w, c := a.out(), r.Port.Counters
	fmt.Fprintf(w, "流量：入 %s 包 / 出 %s 包", count(c.In.Packets), count(c.Out.Packets))
	if rt := r.Port.Rates; rt.InBps.OK {
		fmt.Fprintf(w, "，%s平均 入 %.1f Mb/s 出 %.1f Mb/s", window(rt.Window), rt.InBps.V/1e6, rt.OutBps.Or(0)/1e6)
	}
	if u, ok := query.Utilization(r.Port); ok {
		fmt.Fprintf(w, "（利用率 %s）", percent(u))
	}
	fmt.Fprintln(w)
	line := fmt.Sprintf("错包：CRC %s，输入错误 %s，giants %s，runts %s，出向丢弃 %s", count(c.CRC), count(c.In.Errors), count(c.Giants), count(c.Runts), count(c.Out.Discards))
	if rate := query.ErrorRate(r.Port); rate > 0 {
		line += "，错误率 " + rateText(rate)
	}
	if g, ok := query.Growth(r); ok {
		line += fmt.Sprintf("，较上一批次增长 %d", g)
	}
	fmt.Fprintln(w, line)
}

func printEndpoints(a *app, s *session, d *swtele.Device, i *swtele.Interface) {
	w := a.out()
	macs := s.v.Ledger.EntriesOn(d, i.Name)
	if len(macs) == 0 {
		return
	}
	fmt.Fprintf(w, "口下终端：%d 个 MAC\n", len(macs))
	for n, e := range macs {
		if n == 10 {
			fmt.Fprintf(w, "  ……另有 %d 个，见 swtele endpoints %s --port %s\n", len(macs)-10, d.Identity.Mgmt, i.Name)
			break
		}
		var ips []string
		for _, r := range s.v.Ledger.ARPByMAC(e.MAC) {
			if ip := r.Entry.IP.String(); !slices.Contains(ips, ip) {
				ips = append(ips, ip)
			}
		}
		fmt.Fprintf(w, "  %s VLAN %d %s\n", e.MAC, e.VLAN, strings.Join(ips, "、"))
	}
}

var driftNames = map[string]string{"mode": "端口模式", "vlans": "允许 VLAN", "admin": "管理状态", "aggregate": "聚合归属"}

func driftText(kinds []string) []string {
	out := make([]string, len(kinds))
	for n, k := range kinds {
		out[n] = cmp.Or(driftNames[k], k)
	}
	return out
}

func optInt(o swtele.Opt[int]) string {
	if !o.OK {
		return ""
	}
	return strconv.Itoa(o.V)
}

// errorsCmd lists ports with inbound errors, worst rate first.
func (a *app) errorsCmd() *cobra.Command {
	var f portFilters
	var o outFlags
	cmd := &cobra.Command{
		Use: "errors [选择器...]", Aliases: []string{"错包"}, Short: shortErrors,
		Example: "  swtele errors                       # 全网有错包的端口，按错误率排序\n" +
			"  swtele errors --growing             # 较上一批次仍在增长\n" +
			"  swtele errors role=core --kind crc  # 核心设备的 CRC",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, true)
			if err != nil {
				return err
			}
			f.errors = f.kind == "" && !f.growing
			pred, err := f.predicate()
			if err != nil {
				return err
			}
			all := s.q.Ports(s.devs)
			rows := query.Filter(all, pred)
			// Up ports first: errors on a dead port are history; then the
			// growing ones, then the worst share of errored packets.
			slices.SortStableFunc(rows, func(x, y query.PortRow) int {
				gx, _ := query.Growth(x)
				gy, _ := query.Growth(y)
				return cmp.Or(cmp.Compare(boolRank(y.Port.Up()), boolRank(x.Port.Up())), cmp.Compare(gy, gx),
					cmp.Compare(query.ErrorRate(y.Port), query.ErrorRate(x.Port)))
			})
			t := &report.Table{Columns: []string{"设备", "端口", "状态", "CRC", "输入错误", "入包", "错误率", "较上批增长", "描述", "邻居"}}
			for _, r := range rows {
				i, grow := r.Port, "-"
				if g, ok := query.Growth(r); ok {
					grow = strconv.FormatUint(g, 10)
				}
				t.Add(r.Device.Name(), i.Name, stateText(i), count(i.Counters.CRC), count(i.Counters.In.Errors), count(i.Counters.In.Packets),
					rateText(query.ErrorRate(i)), grow, dash(i.Desc), peerText(r.Peer, r.HasPeer))
			}
			notes := []string{matched(len(rows), len(all), "个端口"), s.dataNote()}
			if s.v.Prev == nil {
				notes = append(notes, "提示：没有上一批次，无法判断错包是否仍在增长")
			}
			return a.emit(&o, "错包端口", t, rows, notes...)
		},
	}
	f.add(cmd)
	o.add(cmd, 100)
	return cmd
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}
