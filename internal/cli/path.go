package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/path"
	"github.com/gatework/swtele/query"
)

var pathStatusText = map[path.Status]string{path.Found: "已找到", path.Partial: "不完整", path.Unlocated: "端点未定位"}

func (a *app) pathCmd() *cobra.Command {
	var o outFlags
	cmd := &cobra.Command{
		Use: "path <源 IP|MAC> <目的 IP|MAC>", Aliases: []string{"路径"}, Short: shortPath, Args: cobra.ExactArgs(2),
		Example: "  swtele path 192.0.2.10 192.0.2.20\n  swtele path 192.0.2.10 198.51.100.7 --format json",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, nil, true)
			if err != nil {
				return err
			}
			r := s.v.Trace(args[0], args[1], locate.Options{TrunkLimit: s.r.Config.TrunkLimit})
			risks, err := a.pathRisks(cmd, s, r)
			if err != nil {
				return err
			}
			t := &report.Table{Columns: []string{"跳", "设备", "入端口", "出端口", "VLAN", "速率", "错包增长", "收光", "风险"}}
			for n, h := range r.Hops {
				name := h.Name
				if h.Routed {
					name += "（三层网关）"
				}
				vlan := "-"
				if h.VLAN > 0 {
					vlan = fmt.Sprint(h.VLAN)
				}
				t.Add(fmt.Sprint(n+1), name, portState(h.Device, h.In), portState(h.Device, h.Out), vlan,
					hopSpeed(h), hopGrowth(s, h), hopOptics(h), dash(strings.Join(risks[n], "；")))
			}
			notes := []string{fmt.Sprintf("%s → %s：%s，%d 跳", endText(r.From), endText(r.To), pathStatusText[r.Status], len(r.Hops))}
			if r.Reason != "" {
				notes = append(notes, "原因："+r.Reason)
			}
			for _, h := range r.Hops {
				if h.Unchecked {
					notes = append(notes, "部分链路缺少 VLAN 数据，按可转发处理")
					break
				}
			}
			for _, h := range r.Hops {
				if h.Routed {
					notes = append(notes, "跨 VLAN 只标出网关，不推断网关之间的路由")
					break
				}
			}
			notes = append(notes, s.dataNote())
			return a.emit(&o, "转发路径", t, r, notes...)
		},
	}
	o.add(cmd, 0)
	return cmd
}

func endText(l locate.Location) string {
	if len(l.Access) > 0 {
		return fmt.Sprintf("%s（%s %s）", l.Query, l.Access[0].Device, l.Access[0].Interface)
	}
	return l.Query
}

// portState renders a hop port with its aggregate and state.
func portState(d *swtele.Device, port string) string {
	if port == "" {
		return "-"
	}
	i := d.Interfaces.Get(port)
	if i == nil {
		return port
	}
	out := port
	if i.Aggregate != "" {
		out += "（" + i.Aggregate + "）"
	}
	if !i.Up() {
		out += " " + stateText(i)
	}
	return out
}

func hopPorts(h path.Hop) []*swtele.Interface {
	var out []*swtele.Interface
	for _, p := range []string{h.In, h.Out} {
		if i := h.Device.Interfaces.Get(p); p != "" && i != nil && (i.Kind == swtele.KindPhysical || i.Kind == swtele.KindAggregate) {
			out = append(out, i)
		}
	}
	return out
}

func hopSpeed(h path.Hop) string {
	var parts []string
	for _, i := range hopPorts(h) {
		parts = append(parts, speed(i.Speed))
	}
	return dash(strings.Join(parts, "/"))
}

func hopGrowth(s *session, h path.Hop) string {
	var parts []string
	for _, r := range s.q.Ports([]*swtele.Device{h.Device}) {
		for _, i := range hopPorts(h) {
			if r.Port != i {
				continue
			}
			if g, ok := query.Growth(r); ok && g > 0 {
				parts = append(parts, fmt.Sprintf("%s +%d", i.Name, g))
			}
		}
	}
	return dash(strings.Join(parts, "，"))
}

func hopOptics(h path.Hop) string {
	var parts []string
	for _, i := range hopPorts(h) {
		if i.Optics == nil || !i.Optics.Present {
			continue
		}
		if l := opticLevel(query.OpticRow{Device: h.Device, Port: i, Optic: i.Optics}); l != "正常" {
			parts = append(parts, i.Name+" "+l)
		}
	}
	return dash(strings.Join(parts, "，"))
}

// pathRisks returns, per hop, the findings about the device as a whole or
// about the hop's ports.
func (a *app) pathRisks(cmd *cobra.Command, s *session, r path.Result) ([][]string, error) {
	out := make([][]string, len(r.Hops))
	if len(r.Hops) == 0 {
		return out, nil
	}
	var devs []*swtele.Device
	for _, h := range r.Hops {
		devs = append(devs, h.Device)
	}
	res, err := a.assessDevices(cmd, &session{v: s.v, r: s.r, devs: devs})
	if err != nil {
		return nil, err
	}
	for n, h := range r.Hops {
		keys := map[string]bool{}
		for _, i := range hopPorts(h) {
			keys[i.Key()] = true
		}
		for _, da := range res {
			if da.Device != h.Device {
				continue
			}
			for _, f := range da.Assessment.Findings {
				// Findings on the hop's ports; of the device-wide ones only
				// the high ones bear on forwarding.
				parts := f.Subject.Parts()
				onPort := len(parts) > 1 && parts[1].Kind == "interface" && keys[swtele.InterfaceKey(parts[1].Key)]
				if onPort && f.Severity >= assess.SeverityMedium || len(parts) == 1 && f.Severity >= assess.SeverityHigh {
					out[n] = append(out[n], f.Title)
				}
			}
		}
	}
	return out, nil
}
