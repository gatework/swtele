package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/locate"
)

func (a *app) locateCmd() *cobra.Command {
	var why, exactOnly bool
	var o outFlags
	cmd := &cobra.Command{
		Use: "locate <IP|MAC>...", Aliases: []string{"定位"}, Short: shortLocate, Args: cobra.MinimumNArgs(1),
		Example: "  swtele locate 192.0.2.10\n  swtele locate 192.0.2.10 192.0.2.11 --format csv\n  swtele locate 7c7a-3c7b-31e2 --why",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, nil, false)
			if err != nil {
				return err
			}
			var all []locate.Location
			for _, q := range args {
				l := s.v.Locate(q, locate.Options{TrunkLimit: s.r.Config.TrunkLimit})
				if exactOnly && l.Confidence != locate.Exact {
					continue
				}
				all = append(all, l)
			}
			if len(all) == 1 && o.format == "table" && !a.json {
				a.printLocation(s, all[0], why)
				return nil
			}
			t := &report.Table{Columns: []string{"查询", "IP", "MAC", "结论", "接入设备", "接入端口", "VLAN", "端口描述", "网关"}}
			for _, l := range all {
				dev, port, vlan, desc := "-", "-", "-", "-"
				if len(l.Access) > 0 {
					p := l.Access[0]
					dev, port, vlan, desc = p.Device, p.Interface, strconv.Itoa(p.VLAN), dash(p.Desc)
				}
				var gws []string
				for _, g := range l.Gateways {
					gws = append(gws, g.Device)
				}
				t.Add(l.Query, ipText(l), dash(l.MAC.String()), confidenceText[l.Confidence], dev, port, vlan, desc, dash(strings.Join(gws, "、")))
			}
			return a.emit(&o, "终端定位", t, all, s.dataNote())
		},
	}
	cmd.Flags().BoolVar(&why, "why", false, flagWhy)
	cmd.Flags().BoolVar(&exactOnly, "exact-only", false, flagExactOnly)
	o.add(cmd, 0)
	return cmd
}

func ipText(l locate.Location) string {
	if l.IP.IsValid() {
		return l.IP.String()
	}
	return "-"
}

func (a *app) printLocation(s *session, l locate.Location, why bool) {
	w := a.out()
	fmt.Fprintf(w, "%s：IP %s，MAC %s", l.Query, ipText(l), dash(l.MAC.String()))
	if v := s.r.OUI[l.OUI]; v != "" {
		fmt.Fprintf(w, "（%s）", v)
	} else if l.OUI != "" {
		fmt.Fprintf(w, "（OUI %s）", l.OUI)
	}
	fmt.Fprintf(w, "，结论：%s\n", confidenceText[l.Confidence])
	if l.Confidence == locate.Device {
		fmt.Fprintf(w, "  该地址属于网络设备 %s 的 %s\n", l.Device, dash(l.Interface))
	}
	for _, p := range l.Access {
		if l.Confidence == locate.Device {
			fmt.Fprintf(w, "  上联：%s（%s）%s\n", p.Device, p.Mgmt, p.Interface)
			continue
		}
		line := fmt.Sprintf("  接入：%s（%s）%s", p.Device, p.Mgmt, p.Interface)
		if p.VLAN > 0 {
			line += fmt.Sprintf("，VLAN %d", p.VLAN)
		}
		if p.Speed > 0 {
			line += "，速率 " + speed(swtele.Some(p.Speed))
		}
		if p.Desc != "" {
			line += "，描述 " + p.Desc
		}
		if p.MACs > 1 {
			line += fmt.Sprintf("，该口学到 %d 个 MAC", p.MACs)
		}
		if p.Neighbor != "" {
			line += "，对端 " + p.Neighbor
		}
		fmt.Fprintln(w, line)
	}
	printGateways(w, l, why)
	printPath(w, l, why)
	for _, n := range l.Notes {
		fmt.Fprintf(w, "  提示：%s\n", n)
	}
	fmt.Fprintln(w, s.dataNote())
}

func printGateways(w io.Writer, l locate.Location, why bool) {
	for _, g := range l.Gateways {
		line := fmt.Sprintf("  网关：%s（%s）%s", g.Device, g.Mgmt, g.Interface)
		if g.VLAN > 0 {
			line += fmt.Sprintf("，VLAN %d", g.VLAN)
		}
		if g.VRF != "" {
			line += "，VRF " + g.VRF
		}
		fmt.Fprintln(w, line)
	}
	if len(l.Gateways) == 0 && len(l.Seen) > 0 {
		fmt.Fprintln(w, "  网关：不在台账中（只有同网段交换机的 ARP 表见到该地址）")
	}
	if n := len(l.Seen); n > 0 {
		if why {
			for _, g := range l.Seen {
				fmt.Fprintf(w, "  ARP 见于：%s（%s）%s\n", g.Device, g.Mgmt, g.Interface)
			}
		} else {
			fmt.Fprintf(w, "  另有 %d 台设备的 ARP 表见到该地址（--why 展开）\n", n)
		}
	}
}

func printPath(w io.Writer, l locate.Location, why bool) {
	if why {
		for n, p := range l.Path {
			if n == 15 {
				fmt.Fprintf(w, "  ……另有 %d 个经过口\n", len(l.Path)-15)
				break
			}
			fmt.Fprintf(w, "  经过：%s %s（%s，%d 个 MAC）→ %s\n", p.Device, p.Interface, roleName(p.Role), p.MACs, dash(p.Neighbor))
		}
	} else if len(l.Path) > 0 {
		fmt.Fprintf(w, "  沿途 %d 个互联口学到该 MAC（--why 展开）\n", len(l.Path))
	}
}

func roleName(role string) string {
	for k, v := range roleText {
		if string(k) == role {
			return v
		}
	}
	return role
}
