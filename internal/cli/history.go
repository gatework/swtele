package cli

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/term"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/internal/workflow"
)

func (a *app) historyCmd() *cobra.Command {
	return &cobra.Command{
		Use: "history <IP|MAC>", Aliases: []string{"轨迹"}, Short: shortHistory, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			ip, mac := "", ""
			if a, err := netip.ParseAddr(args[0]); err == nil {
				ip = a.String()
			} else if m, err := swtele.ParseMAC(args[0]); err == nil {
				mac = m.String()
			} else {
				return fmt.Errorf("无法识别的 IP 或 MAC 地址：%s", args[0])
			}
			recs, err := r.App.History.Find(cmd.Context(), ip, mac)
			if err != nil {
				return err
			}
			if a.json {
				return term.WriteJSON(a.out(), recs)
			}
			if len(recs) == 0 {
				fmt.Fprintln(a.out(), "没有该终端的接入记录")
				return nil
			}
			t := term.NewTable("IP", "MAC", "设备", "端口", "VLAN", "自", "首次出现", "最近出现")
			for _, rec := range recs {
				t.Add(rec.IP, rec.MAC, rec.Place.Device, rec.Place.Port, fmt.Sprint(rec.Place.VLAN), term.Time(rec.Place.Since), term.Time(rec.First), term.Time(rec.Last))
				for _, m := range rec.Moves {
					t.Add("", "  曾在", m.Device, m.Port, fmt.Sprint(m.VLAN), term.Time(m.Since), "", "")
				}
			}
			_, err = t.Render(a.out(), 0)
			return err
		},
	}
}

var kindText = map[string]string{
	"device_added": "新增设备", "device_removed": "设备消失", "port_state": "端口状态", "port_speed": "端口速率",
	"port_description": "端口描述", "optics": "光模块", "neighbor": "邻居", "routing_peer": "路由邻居",
	"stack": "堆叠", "aggregate": "聚合成员", "vlan": "VLAN", "version": "软件版本",
}

func (a *app) diffCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use: "diff [旧批次] [新批次]", Aliases: []string{"变化"}, Short: shortDiff, Args: cobra.MaximumNArgs(2),
		Example: "  swtele diff                 # 最新批次与上一批次\n  swtele diff 2026-11-01_08-00-00 2026-11-23_08-00-00",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			from, to := "", ""
			if len(args) > 0 {
				from = args[0]
			}
			if len(args) > 1 {
				to = args[1]
			}
			changes, fromB, toB, err := r.App.Changes(cmd.Context(), from, to)
			if errors.Is(err, workflow.ErrNoPrevious) {
				return fmt.Errorf("批次 %s 之前没有可比较的批次", toB)
			}
			if err != nil {
				return friendly(err)
			}
			if a.json {
				return term.WriteJSON(a.out(), changes)
			}
			t := term.NewTable("设备", "类别", "变化", "对象", "之前", "之后")
			for _, c := range changes {
				t.Add(c.Device, kindText[string(c.Kind)], string(c.Op), term.Dash(c.Key), term.Dash(c.Before), term.Dash(c.After))
			}
			fmt.Fprintf(a.out(), "%s → %s：%d 处变化\n", fromB, toB, len(changes))
			omitted, err := t.Render(a.out(), limit)
			if omitted > 0 {
				fmt.Fprintf(a.out(), "……另有 %d 行未显示\n", omitted)
			}
			return err
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 200, flagLimit)
	return cmd
}
