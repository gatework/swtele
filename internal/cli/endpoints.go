package cli

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/query"
)

type endpointFilters struct {
	vlan, movesAbove            int
	subnet, oui, desc           string
	newSince, movedSince        string
	behindUnmanaged, ipConflict bool
}

func (f *endpointFilters) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.IntVar(&f.vlan, "vlan", 0, flagEPVLAN)
	fl.StringVar(&f.subnet, "subnet", "", flagSubnet)
	fl.StringVar(&f.oui, "oui", "", flagOUI)
	fl.StringVar(&f.desc, "desc", "", flagEPDesc)
	fl.BoolVar(&f.behindUnmanaged, "behind-unmanaged", false, flagBehindUnmanaged)
	fl.StringVar(&f.newSince, "new-since", "", flagNewSince)
	fl.StringVar(&f.movedSince, "moved-since", "", flagMovedSince)
	fl.IntVar(&f.movesAbove, "moves-above", 0, flagMovesAbove)
	fl.BoolVar(&f.ipConflict, "ip-conflict", false, flagIPConflict)
}

func (f *endpointFilters) predicate(now time.Time) (query.Endpoint, error) {
	var ps []query.Endpoint
	if f.vlan > 0 {
		ps = append(ps, query.OnVLAN(f.vlan))
	}
	if f.subnet != "" {
		p, err := netip.ParsePrefix(f.subnet)
		if err != nil {
			return nil, fmt.Errorf("无效的网段 %q（形如 192.0.2.0/24）", f.subnet)
		}
		ps = append(ps, query.InSubnet(p.Masked()))
	}
	if f.oui != "" {
		ps = append(ps, query.OUIPrefix(f.oui))
	}
	if f.desc != "" {
		ps = append(ps, query.PortDesc(f.desc))
	}
	if f.behindUnmanaged {
		ps = append(ps, query.BehindUnmanaged())
	}
	if f.ipConflict {
		ps = append(ps, query.IPConflict())
	}
	if f.movesAbove > 0 {
		ps = append(ps, query.MovesAbove(f.movesAbove))
	}
	for _, x := range []struct {
		text string
		mk   func(time.Duration, time.Time) query.Endpoint
	}{{f.newSince, query.NewSince}, {f.movedSince, query.MovedSince}} {
		if x.text == "" {
			continue
		}
		d, err := parseAge(x.text)
		if err != nil {
			return nil, err
		}
		ps = append(ps, x.mk(d, now))
	}
	return query.All(ps...), nil
}

func (a *app) endpointsCmd() *cobra.Command {
	var f endpointFilters
	var o outFlags
	cmd := &cobra.Command{
		Use: "endpoints [选择器...]", Aliases: []string{"终端"}, Short: shortEndpoints,
		Example: "  swtele endpoints SW01                   # 某台接入交换机下的终端\n" +
			"  swtele endpoints --vlan 130 --format csv\n" +
			"  swtele endpoints --behind-unmanaged      # 接在 AP、桌面交换机之后的终端\n" +
			"  swtele endpoints --new-since 1d          # 一天内首次出现的终端\n" +
			"  swtele endpoints --ip-conflict           # 同一 IP 有多个 MAC",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			pred, err := f.predicate(s.v.Ledger.At)
			if err != nil {
				return err
			}
			hist, err := s.r.App.History.All(cmd.Context())
			if err != nil {
				return err
			}
			in := map[string]bool{}
			for _, d := range s.devs {
				in[d.Identity.Mgmt.String()] = true
			}
			var seen []locate.Sighting
			for _, x := range s.v.Sightings(locate.Options{TrunkLimit: s.r.Config.TrunkLimit}) {
				if in[x.Mgmt] {
					seen = append(seen, x)
				}
			}
			all := s.q.Endpoints(seen, hist, s.r.OUI)
			rows := query.Filter(all, pred)
			t := &report.Table{Columns: []string{"IP", "MAC", "厂商", "VLAN", "接入设备", "端口", "端口描述", "结论", "首次出现", "迁移"}}
			for _, r := range rows {
				vendor := r.Vendor
				if vendor == "" {
					vendor = r.MAC.OUI()
				}
				first, moves := "-", "-"
				if r.Record != nil {
					first = s.clk.time(r.Record.First)
					if n := len(r.Record.Moves); n > 0 {
						moves = strconv.Itoa(n)
					}
				}
				t.Add(r.IP.String(), r.MAC.String(), vendor, vlanNum(r.VLAN), r.Sighting.Device, r.Sighting.Port, portDesc(r.Port),
					confidenceText[r.Confidence], first, moves)
			}
			notes := []string{matched(len(rows), len(all), "个终端")}
			if s.r.OUI == nil {
				notes = append(notes, "未配置 oui_file，厂商列显示 OUI 前缀")
			}
			return a.emit(&o, "终端清单", t, rows, append(notes, s.dataNote())...)
		},
	}
	f.add(cmd)
	o.add(cmd, 300)
	return cmd
}

func vlanNum(v int) string {
	if v <= 0 {
		return "-"
	}
	return strconv.Itoa(v)
}

func portDesc(i *swtele.Interface) string {
	if i == nil {
		return "-"
	}
	return dash(i.Desc)
}
