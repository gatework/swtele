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
	"github.com/gatework/netops/report"
	"github.com/gatework/netops/term"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/internal/bootstrap"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/topology"
)

func (a *app) out() io.Writer { return a.env.Stdout }

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

func (a *app) batchesCmd() *cobra.Command {
	return &cobra.Command{
		Use: "batches", Aliases: []string{"批次"}, Short: shortBatches, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			list, err := r.App.Ledgers.Batches()
			if err != nil {
				return err
			}
			if a.json {
				return term.WriteJSON(a.out(), list)
			}
			for _, b := range list {
				fmt.Fprintln(a.out(), b)
			}
			return nil
		},
	}
}

func speed(o swtele.Opt[uint64]) string {
	v, ok := o.Get()
	switch {
	case !ok || v == 0:
		return "-"
	case v >= 1e9 && v%1e9 == 0:
		return strconv.FormatUint(v/1e9, 10) + "G"
	case v >= 1e9:
		return strconv.FormatFloat(float64(v)/1e9, 'f', 1, 64) + "G"
	}
	return strconv.FormatUint(v/1e6, 10) + "M"
}

func state(i *swtele.Interface) string {
	switch {
	case i.Admin == swtele.StateDown:
		return "管理关闭"
	case i.Up():
		return "up"
	case i.DownCause != swtele.CauseNone:
		return "down(" + string(i.DownCause) + ")"
	}
	return term.Dash(string(i.Oper))
}

func (a *app) deviceCmd() *cobra.Command {
	return &cobra.Command{
		Use: "device <地址|名称>", Aliases: []string{"设备"}, Short: shortDevice, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := a.view(cmd.Context(), false)
			if err != nil {
				return err
			}
			d, err := v.Device(args[0])
			if err != nil {
				return friendly(err)
			}
			if a.json {
				return term.WriteJSON(a.out(), d)
			}
			if err := a.printDevice(v, d); err != nil {
				return err
			}
			return a.printRisks(cmd, d)
		},
	}
}

func (a *app) printDevice(v *workflow.View, d *swtele.Device) error {
	w := a.out()
	s := d.System
	fmt.Fprintf(w, "设备：%s（%s）平台 %s 型号 %s 版本 %s\n", d.Name(), d.Identity.Mgmt, term.Dash(d.Identity.Platform), term.Dash(s.Model), term.Dash(s.Version))
	fmt.Fprintf(w, "采集：%s，批次 %s\n", term.Time(d.Observed), v.Ledger.Batch)
	for _, c := range s.CPU {
		fmt.Fprintf(w, "CPU %s：5秒 %s%% 1分 %s%% 5分 %s%%\n", c.Unit, pct(c.Now), pct(c.Min1), pct(c.Min5))
	}
	for _, m := range s.Memory {
		u, _ := m.UsedPercent()
		fmt.Fprintf(w, "内存 %s：已用 %.1f%%（共 %d MB）\n", m.Unit, u, m.Total.Or(0)>>20)
	}
	if st := d.Stack; st != nil && len(st.Members) > 0 {
		fmt.Fprintf(w, "堆叠 %s：%d 个成员", st.Kind, len(st.Members))
		if st.MAD != nil {
			fmt.Fprintf(w, "，MAD %s %s", term.Dash(strings.Join(st.MAD.Modes, "/")), term.Dash(st.MAD.Status))
		}
		fmt.Fprintln(w)
		for _, m := range st.Members {
			fmt.Fprintf(w, "  成员 %d %s 优先级 %d\n", m.ID, m.Role, m.Priority.Or(0))
		}
	}
	var phys, up, optics int
	for _, i := range d.Interfaces.All() {
		if i.Kind != swtele.KindPhysical {
			continue
		}
		phys++
		if i.Up() {
			up++
		}
		if i.Optics != nil && i.Optics.Present {
			optics++
		}
	}
	fmt.Fprintf(w, "端口：物理口 %d（up %d），光模块 %d，聚合组 %d，邻居 %d，ARP %d，MAC %d，路由邻居 %d\n",
		phys, up, optics, len(d.Aggregates), len(d.Neighbors), len(d.L3.ARP), len(d.L2.MACs), len(d.L3.Peers))
	t := term.NewTable("维度", "状态")
	for _, dim := range d.Coverage.Dimensions() {
		t.Add(string(dim), string(d.Coverage.Status(dim)))
	}
	_, err := t.Render(w, 0)
	return err
}

func pct(o swtele.Opt[float64]) string {
	if !o.OK {
		return "-"
	}
	return strconv.FormatFloat(o.V, 'f', 0, 64)
}

func (a *app) portCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use: "port <设备> [端口]", Aliases: []string{"端口"}, Short: shortPort, Args: cobra.RangeArgs(1, 2),
		Example: "  swtele port SW01\n  swtele port 192.0.2.1 GE1/0/1",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := a.view(cmd.Context(), false)
			if err != nil {
				return err
			}
			d, err := v.Device(args[0])
			if err != nil {
				return friendly(err)
			}
			if len(args) == 2 {
				i := d.Interfaces.Get(args[1])
				if i == nil {
					return fmt.Errorf("设备 %s 没有端口 %s", d.Name(), args[1])
				}
				return a.printPort(v, d, i)
			}
			t := portTable(v, d)
			if a.json {
				return term.WriteJSON(a.out(), d.Interfaces.All())
			}
			omitted, err := t.Render(a.out(), limit)
			if omitted > 0 {
				fmt.Fprintf(a.out(), "……另有 %d 行未显示\n", omitted)
			}
			return err
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, flagLimit)
	return cmd
}

func portTable(v *workflow.View, d *swtele.Device) *term.Table {
	t := term.NewTable("端口", "状态", "速率", "模式", "PVID", "描述", "聚合", "收光dBm", "CRC", "邻居")
	for _, i := range d.Interfaces.All() {
		if i.Kind != swtele.KindPhysical && i.Kind != swtele.KindAggregate {
			continue
		}
		mode, pvid := "-", "-"
		if i.Switching != nil {
			mode = term.Dash(string(i.Switching.Mode))
			if p, ok := i.Switching.PVID.Get(); ok {
				pvid = strconv.Itoa(p)
			}
		}
		rx := "-"
		if i.Optics != nil && len(i.Optics.Lanes) > 0 {
			rx = reading(i.Optics.Lanes[0].RxPower)
		}
		t.Add(i.Name, state(i), speed(i.Speed), mode, pvid, term.Dash(i.Desc), term.Dash(i.Aggregate), rx, count(i.Counters.CRC), peerText(v, d, i.Name))
	}
	return t
}

func peerText(v *workflow.View, d *swtele.Device, port string) string {
	e, ok := v.Graph.Peer(d, port)
	if !ok {
		return "-"
	}
	name := cmp.Or(e.Name, "?")
	if e.Device != nil {
		name = e.Device.Name()
	}
	return name + " " + e.Port
}

func count(o swtele.Opt[uint64]) string {
	if !o.OK {
		return "-"
	}
	return strconv.FormatUint(o.V, 10)
}

func (a *app) printPort(v *workflow.View, d *swtele.Device, i *swtele.Interface) error {
	if a.json {
		return term.WriteJSON(a.out(), i)
	}
	w := a.out()
	fmt.Fprintf(w, "%s %s：%s，速率 %s %s，MTU %d，描述 %s\n", d.Name(), i.Name, state(i), speed(i.Speed), term.Dash(string(i.Duplex)), i.MTU.Or(0), term.Dash(i.Desc))
	fmt.Fprintf(w, "类型 %s，介质 %s，MAC %s，聚合 %s，拓扑角色 %s\n", i.Kind, term.Dash(i.Media), term.Dash(i.MAC.String()), term.Dash(i.Aggregate), v.Graph.Role(d, i.Name))
	if sw := i.Switching; sw != nil {
		allowed := "-"
		if sw.Allowed != nil {
			allowed = sw.Allowed.Compact()
		}
		fmt.Fprintf(w, "二层：%s，PVID %d，允许 VLAN %s\n", term.Dash(string(sw.Mode)), sw.PVID.Or(0), allowed)
	}
	for _, ad := range i.Addresses {
		fmt.Fprintf(w, "地址：%s\n", ad.Prefix)
	}
	c := i.Counters
	fmt.Fprintf(w, "入：包 %s 字节 %s 错误 %s 丢弃 %s；出：包 %s 字节 %s 错误 %s 丢弃 %s\n",
		count(c.In.Packets), count(c.In.Octets), count(c.In.Errors), count(c.In.Discards),
		count(c.Out.Packets), count(c.Out.Octets), count(c.Out.Errors), count(c.Out.Discards))
	fmt.Fprintf(w, "错包：CRC %s，runts %s，giants %s，复位 %s\n", count(c.CRC), count(c.Runts), count(c.Giants), count(c.Resets))
	if r := i.Rates; r.InBps.OK {
		fmt.Fprintf(w, "速率（%s 平均）：入 %.1f Mb/s，出 %.1f Mb/s\n", r.Window, r.InBps.V/1e6, r.OutBps.V/1e6)
	}
	switch {
	case i.Flap.Never:
		fmt.Fprintln(w, "抖动：从未 up/down")
	case i.Flap.Since.OK:
		fmt.Fprintf(w, "抖动：最近一次在 %s 前\n", term.Duration(i.Flap.Since.V))
	}
	if x := i.Optics; x != nil {
		fmt.Fprintf(w, "光模块：%s %s SN %s，温度 %s°C 电压 %sV\n", term.Dash(x.Inventory.Vendor), term.Dash(x.Inventory.Type), term.Dash(x.Inventory.Serial), reading(x.Temp), reading(x.Voltage))
		for _, l := range x.Lanes {
			lvl := "端口未 up，不评级"
			if i.Up() {
				lvl = term.Dash(string(l.RxPower.Level()))
			}
			fmt.Fprintf(w, "  通道 %d：收光 %s dBm（%s）发光 %s dBm 偏置 %s mA\n", l.Index, reading(l.RxPower), lvl, reading(l.TxPower), reading(l.Bias))
		}
	}
	if e, ok := v.Graph.Peer(d, i.Name); ok {
		name := e.Name
		if e.Device != nil {
			name = e.Device.Name()
		}
		fmt.Fprintf(w, "邻居：%s %s\n", term.Dash(name), term.Dash(e.Port))
	}
	macs := v.Ledger.EntriesOn(d, i.Name)
	fmt.Fprintf(w, "终端：%d 个 MAC\n", len(macs))
	for n, e := range macs {
		if n == 10 {
			fmt.Fprintf(w, "  ……另有 %d 个\n", len(macs)-10)
			break
		}
		ips := []string{}
		for _, r := range v.Ledger.ARPByMAC(e.MAC) {
			if !slices.Contains(ips, r.Entry.IP.String()) {
				ips = append(ips, r.Entry.IP.String())
			}
		}
		fmt.Fprintf(w, "  %s VLAN %d %s\n", e.MAC, e.VLAN, strings.Join(ips, ","))
	}
	return nil
}

func reading(r swtele.Reading) string {
	if !r.Value.OK {
		return "-"
	}
	return strconv.FormatFloat(r.Value.V, 'f', 2, 64)
}

func (a *app) locateCmd() *cobra.Command {
	var why bool
	cmd := &cobra.Command{
		Use: "locate <IP|MAC>...", Aliases: []string{"定位"}, Short: shortLocate, Args: cobra.MinimumNArgs(1),
		Example: "  swtele locate 192.0.2.10\n  swtele locate 7c7a-3c7b-31e2",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, r, err := a.view(cmd.Context(), false)
			if err != nil {
				return err
			}
			var all []locate.Location
			for _, q := range args {
				all = append(all, v.Locate(q, locate.Options{TrunkLimit: r.Config.TrunkLimit}))
			}
			if a.json {
				return term.WriteJSON(a.out(), all)
			}
			for _, l := range all {
				a.printLocation(l, why)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&why, "why", false, flagWhy)
	return cmd
}

var confidenceText = map[locate.Confidence]string{
	locate.Exact: "精确", locate.Shared: "共享接入口", locate.Ambiguous: "不唯一",
	locate.GatewayOnly: "仅网关可见", locate.Unknown: "未找到",
}

func (a *app) printLocation(l locate.Location, why bool) {
	w := a.out()
	fmt.Fprintf(w, "%s：IP %s MAC %s（%s）\n", l.Query, term.Dash(addr(l)), term.Dash(l.MAC.String()), confidenceText[l.Confidence])
	for _, g := range l.Gateways {
		fmt.Fprintf(w, "  网关：%s（%s）%s VLAN %d %s\n", g.Device, g.Mgmt, g.Interface, g.VLAN, g.VRF)
	}
	for _, p := range l.Access {
		fmt.Fprintf(w, "  接入：%s（%s）%s VLAN %d 描述 %s 速率 %s 学到 %d 个 MAC %s\n", p.Device, p.Mgmt, p.Interface, p.VLAN,
			term.Dash(p.Desc), speed(swtele.Some(p.Speed)), p.MACs, neighbor(p))
	}
	if why {
		for _, p := range l.Path {
			fmt.Fprintf(w, "  经过：%s %s（%s，%d 个 MAC）%s\n", p.Device, p.Interface, p.Role, p.MACs, neighbor(p))
		}
	}
	for _, n := range l.Notes {
		fmt.Fprintf(w, "  提示：%s\n", n)
	}
}

func addr(l locate.Location) string {
	if l.IP.IsValid() {
		return l.IP.String()
	}
	return ""
}

func neighbor(p locate.Port) string {
	if p.Neighbor == "" {
		return ""
	}
	return "→ " + p.Neighbor
}

func (a *app) topologyCmd() *cobra.Command {
	return &cobra.Command{
		Use: "topology [设备]", Aliases: []string{"拓扑"}, Short: shortTopology, Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := a.view(cmd.Context(), false)
			if err != nil {
				return err
			}
			links := v.Graph.Links
			if len(args) == 1 {
				d, err := v.Device(args[0])
				if err != nil {
					return friendly(err)
				}
				links = v.Graph.LinksOf(d)
			}
			type row struct{ A, APort, B, BPort, State string }
			var rows []row
			for _, l := range links {
				b := l.B.Name
				if l.B.Device != nil {
					b = l.B.Device.Name()
				}
				rows = append(rows, row{l.A.Device.Name(), l.A.Port, b, l.B.Port, string(l.State)})
			}
			if a.json {
				return term.WriteJSON(a.out(), rows)
			}
			t := term.NewTable("本端", "端口", "对端", "对端端口", "状态")
			stats := map[topology.State]int{}
			for i, r := range rows {
				t.Add(r.A, r.APort, term.Dash(r.B), term.Dash(r.BPort), r.State)
				stats[links[i].State]++
			}
			if _, err := t.Render(a.out(), 0); err != nil {
				return err
			}
			fmt.Fprintf(a.out(), "双向确认 %d，单向 %d，共享网段 %d，非受管邻居 %d\n", stats[topology.Confirmed], stats[topology.OneWay], stats[topology.Shared], stats[topology.Unmanaged])
			return nil
		},
	}
}

func (a *app) opticsCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use: "optics [设备]", Aliases: []string{"光模块"}, Short: shortOptics, Args: cobra.MaximumNArgs(1),
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
				devs = []*swtele.Device{d}
			}
			t := term.NewTable("设备", "端口", "状态", "厂商", "类型", "序列号", "温度", "收光", "发光", "级别")
			for _, d := range devs {
				for _, i := range d.Interfaces.All() {
					x := i.Optics
					if x == nil || !x.Present {
						continue
					}
					rx, tx, lvl := "-", "-", "-"
					if len(x.Lanes) > 0 {
						rx, tx = reading(x.Lanes[0].RxPower), reading(x.Lanes[0].TxPower)
						// Readings are graded only on up ports: a down port
						// neither sends nor receives light.
						lvl = "端口未 up"
						if i.Up() {
							lvl = term.Dash(string(x.Lanes[0].RxPower.Level()))
						}
					}
					t.Add(d.Name(), i.Name, state(i), term.Dash(x.Inventory.Vendor), term.Dash(x.Inventory.Type), term.Dash(x.Inventory.Serial), reading(x.Temp), rx, tx, lvl)
				}
			}
			omitted, err := t.Render(a.out(), limit)
			if omitted > 0 {
				fmt.Fprintf(a.out(), "……另有 %d 行未显示\n", omitted)
			}
			return err
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, flagLimit)
	return cmd
}

func (a *app) assess(cmd *cobra.Command, deviceQuery string) ([]workflow.DeviceAssessment, *workflow.View, error) {
	v, r, err := a.view(cmd.Context(), true)
	if err != nil {
		return nil, nil, err
	}
	var keep func(*swtele.Device) bool
	if deviceQuery != "" {
		d, err := v.Device(deviceQuery)
		if err != nil {
			return nil, nil, friendly(err)
		}
		keep = func(x *swtele.Device) bool { return x == d }
	}
	res, err := v.Assess(cmd.Context(), r.Policy, keep)
	return res, v, err
}

func filter(res []workflow.DeviceAssessment, floor assess.Severity, rule string) []assess.Finding {
	var out []assess.Finding
	for _, da := range res {
		for _, f := range da.Assessment.Findings {
			if f.Severity >= floor && strings.HasPrefix(string(f.Rule), rule) {
				out = append(out, f)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b assess.Finding) int { return cmp.Compare(b.Severity, a.Severity) })
	return out
}

func (a *app) riskCmd() *cobra.Command {
	var sev, rule, dev, failOn string
	var limit int
	cmd := &cobra.Command{
		Use: "risk", Aliases: []string{"风险"}, Short: shortRisk, Args: cobra.NoArgs,
		Example: "  swtele risk --severity high\n  swtele risk --rule optics. --device SW01",
		RunE: func(cmd *cobra.Command, _ []string) error {
			floor, err := parseSeverity(sev)
			if err != nil {
				return err
			}
			res, _, err := a.assess(cmd, dev)
			if err != nil {
				return err
			}
			fs := filter(res, floor, rule)
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
			if fail, _ := parseSeverity(failOn); failOn != "" && len(filter(res, fail, rule)) > 0 {
				return errFindings
			}
			return err
		},
	}
	cmd.Flags().StringVar(&sev, "severity", "", flagSev)
	cmd.Flags().StringVar(&rule, "rule", "", flagRule)
	cmd.Flags().StringVar(&dev, "device", "", flagDevice)
	cmd.Flags().StringVar(&failOn, "fail-on", "", flagSev)
	cmd.Flags().IntVar(&limit, "limit", 200, flagLimit)
	return cmd
}

func (a *app) reportCmd() *cobra.Command {
	var format, sev string
	cmd := &cobra.Command{
		Use: "report", Aliases: []string{"报表"}, Short: shortReport, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			floor, err := parseSeverity(cmp.Or(sev, "medium"))
			if err != nil {
				return err
			}
			res, v, err := a.assess(cmd, "")
			if err != nil {
				return err
			}
			doc := summary(v, res, floor)
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

func summary(v *workflow.View, res []workflow.DeviceAssessment, floor assess.Severity) report.Document {
	var phys, up, optics, arp, macs int
	for _, d := range v.Ledger.Devices() {
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
	for _, l := range v.Graph.Links {
		stats[l.State]++
	}
	fs := filter(res, floor, "")
	byRule := report.Table{Columns: []string{"规则", "数量"}}
	counts := map[assess.RuleID]int{}
	for _, f := range fs {
		counts[f.Rule]++
	}
	ids := make([]assess.RuleID, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b assess.RuleID) int { return cmp.Compare(counts[b], counts[a]) })
	for _, id := range ids {
		byRule.Add(string(id), strconv.Itoa(counts[id]))
	}
	return report.Document{
		Title:     "网络运行态台账报告（批次 " + v.Ledger.Batch + "）",
		Generated: v.Ledger.At,
		Summary: []report.KV{
			{Key: "设备", Value: strconv.Itoa(v.Ledger.Len())},
			{Key: "物理端口", Value: fmt.Sprintf("%d（up %d，利用率 %.0f%%）", phys, up, float64(up)*100/float64(max(phys, 1)))},
			{Key: "光模块", Value: strconv.Itoa(optics)},
			{Key: "互联链路", Value: fmt.Sprintf("双向 %d，单向 %d，共享网段 %d，非受管邻居 %d", stats[topology.Confirmed], stats[topology.OneWay], stats[topology.Shared], stats[topology.Unmanaged])},
			{Key: "ARP / MAC", Value: fmt.Sprintf("%d / %d", arp, macs)},
			{Key: "风险发现（≥" + floor.String() + "）", Value: strconv.Itoa(len(fs))},
		},
		Sections: []report.Section{
			{Title: "按规则统计", Table: &byRule},
			{Title: "风险明细", Findings: fs},
		},
	}
}
