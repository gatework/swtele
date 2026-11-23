package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/query"
	"github.com/gatework/swtele/topology"
)

var mismatchNames = map[string]string{"speed": "速率", "duplex": "双工", "mtu": "MTU", "pvid": "PVID", "vlans": "允许 VLAN"}

func (a *app) topologyCmd() *cobra.Command {
	var state, mismatch string
	var hops int
	var anyMismatch bool
	var o outFlags
	cmd := &cobra.Command{
		Use: "topology [选择器...]", Aliases: []string{"拓扑"}, Short: shortTopology,
		Example: "  swtele topology SW01 --hops 1           # 设备及一跳邻居\n" +
			"  swtele topology site=hq --format mermaid # 导出拓扑图\n" +
			"  swtele topology --state one-way          # 单向可见的链路\n" +
			"  swtele topology --mismatch vlans         # 两端允许 VLAN 不一致",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			devs := expand(s, hops)
			var ps []query.Link
			if state != "" {
				if !slices.Contains([]string{"one-way", "shared", "unmanaged", "confirmed"}, state) {
					return fmt.Errorf("无效的链路状态 %q（可选 confirmed、one-way、shared、unmanaged）", state)
				}
				ps = append(ps, query.LinkState(state))
			}
			if mismatch != "" || anyMismatch {
				ps = append(ps, query.Mismatch(mismatch))
			}
			all := s.q.Links(devs)
			rows := query.Filter(all, query.All(ps...))
			switch o.format {
			case "mermaid":
				fmt.Fprint(a.out(), mermaid(rows))
				return nil
			case "dot":
				fmt.Fprint(a.out(), dot(rows))
				return nil
			}
			t := &report.Table{Columns: []string{"本端", "端口", "对端", "对端端口", "状态", "速率", "不一致"}}
			stats := map[topology.State]int{}
			for _, r := range rows {
				stats[r.Link.State]++
				sp := "-"
				if r.Local != nil {
					sp = speed(r.Local.Speed)
				}
				var diff []string
				for _, m := range query.Mismatches(r) {
					diff = append(diff, mismatchNames[m])
				}
				t.Add(r.Link.A.Device.Name(), r.Link.A.Port, peerText(r.Link.B, true), "", linkText[r.Link.State], sp, dash(strings.Join(diff, "、")))
				t.Rows[len(t.Rows)-1][2], t.Rows[len(t.Rows)-1][3] = peerName(r.Link.B), dash(r.Link.B.Port)
			}
			return a.emit(&o, "拓扑", t, rows,
				fmt.Sprintf("%s：双向确认 %d，单向 %d，共享网段 %d，非受管邻居 %d", matched(len(rows), len(all), "条链路"),
					stats[topology.Confirmed], stats[topology.OneWay], stats[topology.Shared], stats[topology.Unmanaged]), s.dataNote())
		},
	}
	cmd.Flags().IntVar(&hops, "hops", 0, flagHops)
	cmd.Flags().StringVar(&state, "state", "", flagLinkState)
	cmd.Flags().StringVar(&mismatch, "mismatch", "", flagMismatch)
	cmd.Flags().BoolVar(&anyMismatch, "any-mismatch", false, flagAnyMismatch)
	o.add(cmd, 300)
	return cmd
}

func peerName(e topology.End) string {
	if e.Device != nil {
		return e.Device.Name()
	}
	return dash(e.Name)
}

// expand adds the managed neighbors within hops of the selection.
func expand(s *session, hops int) []*swtele.Device {
	in := map[*swtele.Device]bool{}
	out := append([]*swtele.Device(nil), s.devs...)
	for _, d := range out {
		in[d] = true
	}
	frontier := s.devs
	for range hops {
		var next []*swtele.Device
		for _, d := range frontier {
			for _, l := range s.v.Graph.LinksOf(d) {
				if l.B.Device != nil && !in[l.B.Device] && l.State != topology.Shared {
					in[l.B.Device] = true
					next = append(next, l.B.Device)
				}
			}
		}
		out = append(out, next...)
		frontier = next
	}
	return out
}

func nodeID(name string) string {
	return "n_" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, name)
}

func mermaid(rows []query.LinkRow) string {
	var b strings.Builder
	b.WriteString("graph LR\n")
	for _, r := range rows {
		a, z := r.Link.A.Device.Name(), peerName(r.Link.B)
		style := "---"
		if r.Link.State != topology.Confirmed {
			style = "-.-"
		}
		fmt.Fprintf(&b, "  %s[\"%s\"] %s|%s ↔ %s| %s[\"%s\"]\n", nodeID(a), a, style, r.Link.A.Port, r.Link.B.Port, nodeID(z), z)
	}
	return b.String()
}

func dot(rows []query.LinkRow) string {
	var b strings.Builder
	b.WriteString("graph swtele {\n  node [shape=box];\n")
	for _, r := range rows {
		style := "solid"
		if r.Link.State != topology.Confirmed {
			style = "dashed"
		}
		fmt.Fprintf(&b, "  %q -- %q [label=%q, style=%s];\n", r.Link.A.Device.Name(), peerName(r.Link.B), r.Link.A.Port+" - "+r.Link.B.Port, style)
	}
	b.WriteString("}\n")
	return b.String()
}

func (a *app) discoverCmd() *cobra.Command {
	var o outFlags
	cmd := &cobra.Command{
		Use: "discover [选择器...]", Aliases: []string{"发现"}, Short: shortDiscover,
		Example: "  swtele discover                       # LLDP/CDP 看到但不在台账中的网络设备\n" +
			"  swtele discover --format yaml >> ~/.gatework/swtele/inventory.yml",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			in := map[*swtele.Device]bool{}
			for _, d := range s.devs {
				in[d] = true
			}
			var rows []topology.Candidate
			for _, c := range s.v.Graph.Discover(s.v.Ledger) {
				if slices.ContainsFunc(c.SeenBy, func(e topology.End) bool { return in[e.Device] }) {
					rows = append(rows, c)
				}
			}
			if o.format == "yaml" {
				fmt.Fprint(a.out(), inventoryYAML(rows))
				return nil
			}
			t := &report.Table{Columns: []string{"名称", "管理地址", "推断平台", "型号", "见于", "端口数"}}
			for _, c := range rows {
				mgmt := "-"
				if c.Mgmt.IsValid() {
					mgmt = c.Mgmt.String()
				}
				first := c.SeenBy[0]
				t.Add(c.Name, mgmt, dash(c.Platform), dash(c.Model), first.Device.Name()+" "+first.Port, fmt.Sprint(len(c.SeenBy)))
			}
			return a.emit(&o, "待纳管设备", t, rows, fmt.Sprintf("共 %d 台；--format yaml 输出清单片段（无管理地址的以注释列出）", len(rows)), s.dataNote())
		},
	}
	o.add(cmd, 300)
	return cmd
}

// inventoryYAML renders candidates as netops inventory entries; those
// without a management address are listed as comments to fill in.
func inventoryYAML(cs []topology.Candidate) string {
	var b strings.Builder
	b.WriteString("# swtele discover：LLDP/CDP 发现、尚未纳管的设备，核对后并入 devices:\n")
	for _, c := range cs {
		platform := cmp.Or(c.Platform, "unknown")
		if !c.Mgmt.IsValid() {
			fmt.Fprintf(&b, "  # - {name: %q, platform: %s}  # 邻居未通告管理地址\n", c.Name, platform)
			continue
		}
		fmt.Fprintf(&b, "  - {id: %s, name: %q, mgmt: %s, platform: %s}\n", c.Mgmt, c.Name, c.Mgmt, platform)
	}
	return b.String()
}
