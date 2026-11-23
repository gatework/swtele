package cli

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/delta"
	"github.com/gatework/swtele/internal/workflow"
)

func (a *app) historyCmd() *cobra.Command {
	var o outFlags
	cmd := &cobra.Command{
		Use: "history <IP|MAC>", Aliases: []string{"轨迹"}, Short: shortHistory, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			clk := clock{loc: r.Location}
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
			if len(recs) == 0 && !a.json {
				fmt.Fprintln(a.out(), "没有该终端的接入记录")
				return nil
			}
			t := &report.Table{Columns: []string{"IP", "MAC", "接入设备", "端口", "VLAN", "接入自", "首次出现", "最近出现"}}
			for _, rec := range recs {
				t.Add(rec.IP, rec.MAC, rec.Place.Device, rec.Place.Port, strconv.Itoa(rec.Place.VLAN), clk.time(rec.Place.Since), clk.time(rec.First), clk.time(rec.Last))
				for _, m := range rec.Moves {
					t.Add("", "  此前", m.Device, m.Port, strconv.Itoa(m.VLAN), clk.time(m.Since), "", "")
				}
			}
			return a.emit(&o, "终端轨迹", t, recs, "时间均为 "+clk.zone())
		},
	}
	o.add(cmd, 0)
	return cmd
}

var changeText = map[delta.Kind]string{
	delta.DeviceAdded: "新增设备", delta.DeviceRemoved: "设备消失", delta.PortState: "端口状态", delta.PortSpeed: "端口速率",
	delta.PortDesc: "端口描述", delta.OpticsSwapped: "光模块", delta.Neighbor: "邻居", delta.Peer: "路由邻居",
	delta.StackRole: "堆叠", delta.Aggregate: "聚合成员", delta.VLAN: "VLAN", delta.Version: "软件版本",
}

var opText = map[string]string{"added": "新增", "removed": "删除", "changed": "变化"}

func (a *app) diffCmd() *cobra.Command {
	var kinds []string
	var o outFlags
	cmd := &cobra.Command{
		Use: "diff [旧批次] [新批次]", Aliases: []string{"变化"}, Short: shortDiff, Args: cobra.MaximumNArgs(2),
		Example: "  swtele diff                 # 最新批次与上一批次\n  swtele diff --kind port_state --kind neighbor",
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
			if len(kinds) > 0 {
				changes = slices.DeleteFunc(changes, func(c delta.Change) bool { return !slices.Contains(kinds, string(c.Kind)) })
			}
			if len(changes) == 0 && !a.json {
				fmt.Fprintf(a.out(), "%s → %s：无变化\n", fromB, toB)
				return nil
			}
			byKind := map[delta.Kind]int{}
			t := &report.Table{Columns: []string{"设备", "类别", "变化", "对象", "之前", "之后"}}
			for _, c := range changes {
				byKind[c.Kind]++
				t.Add(c.Device, changeText[c.Kind], opText[string(c.Op)], dash(c.Key), dash(c.Before), dash(c.After))
			}
			var sum []string
			for _, k := range slices.SortedFunc(maps.Keys(byKind), func(x, y delta.Kind) int { return cmp.Compare(byKind[y], byKind[x]) }) {
				sum = append(sum, fmt.Sprintf("%s %d", changeText[k], byKind[k]))
			}
			return a.emit(&o, "批次变化", t, changes, fmt.Sprintf("%s → %s：共 %d 处变化（%s）", fromB, toB, len(changes), strings.Join(sum, "，")))
		},
	}
	cmd.Flags().StringSliceVar(&kinds, "kind", nil, flagChangeKind)
	o.add(cmd, 300)
	return cmd
}

func (a *app) batchesCmd() *cobra.Command {
	var o outFlags
	cmd := &cobra.Command{
		Use: "batches", Aliases: []string{"批次"}, Short: shortBatches, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.load(cmd.Context())
			if err != nil {
				return err
			}
			clk := clock{loc: r.Location}
			list, err := r.App.Ledgers.Batches()
			if err != nil {
				return err
			}
			latest, _ := r.App.Ledgers.Latest(cmd.Context())
			t := &report.Table{Columns: []string{"批次", "时间", "设备", "来源", "最新"}}
			var data []any
			for _, b := range slices.Backward(list) {
				m, err := r.App.Ledgers.Manifest(cmd.Context(), b)
				if err != nil {
					continue
				}
				src := dash(m.Source)
				if m.Parent != "" {
					src = "刷新自 " + m.Parent
				}
				mark := ""
				if b == latest {
					mark = "是"
				}
				t.Add(b, clk.time(m.At), strconv.Itoa(len(m.Devices)), src, mark)
				data = append(data, m)
			}
			return a.emit(&o, "台账批次", t, data, "时间均为 "+clk.zone())
		},
	}
	o.add(cmd, 0)
	return cmd
}
