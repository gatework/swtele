package cli

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/query"
)

func (a *app) assetsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "assets", Aliases: []string{"资产"}, Short: shortAssets,
		Example: "  swtele assets optics                  # 光模块按厂商、料号、类型统计\n" +
			"  swtele assets software site=hq        # 软件版本分布（配置 lifecycle 后含合规）\n" +
			"  swtele assets hardware --format csv   # 型号分布",
	}
	cmd.AddCommand(a.assetOpticsCmd(), a.assetSoftwareCmd(), a.assetHardwareCmd())
	return cmd
}

// tally counts rows by a composite key, most frequent first.
type tally[T any] struct {
	keys  map[string][]string
	rows  map[string][]T
	order []string
}

func newTally[T any]() *tally[T] {
	return &tally[T]{keys: map[string][]string{}, rows: map[string][]T{}}
}

func (t *tally[T]) add(row T, key ...string) {
	k := strings.Join(key, "\x00")
	if _, ok := t.keys[k]; !ok {
		t.keys[k] = key
		t.order = append(t.order, k)
	}
	t.rows[k] = append(t.rows[k], row)
}

func (t *tally[T]) sorted() []string {
	return slices.SortedStableFunc(slices.Values(t.order), func(x, y string) int {
		return cmp.Or(cmp.Compare(len(t.rows[y]), len(t.rows[x])), strings.Compare(x, y))
	})
}

func (a *app) assetOpticsCmd() *cobra.Command {
	var o outFlags
	cmd := &cobra.Command{
		Use: "optics [选择器...]", Short: shortAssetOptics,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			rows := s.q.Optics(s.devs)
			tl := newTally[query.OpticRow]()
			for _, r := range rows {
				inv := r.Optic.Inventory
				tl.add(r, dash(strings.TrimSpace(inv.Vendor)), dash(cmp.Or(inv.PartNumber, inv.ProductID)), dash(inv.Type), speed(r.Port.Speed))
			}
			t := &report.Table{Columns: []string{"厂商", "料号", "类型", "端口速率", "数量", "端口 up", "非原厂", "无诊断", "设备数"}}
			var nonOrig, noDOM int
			for _, k := range tl.sorted() {
				key, rs := tl.keys[k], tl.rows[k]
				up, no, nd := 0, 0, 0
				devs := map[*swtele.Device]bool{}
				for _, r := range rs {
					devs[r.Device] = true
					if r.Port.Up() {
						up++
					}
					if query.NonOriginal()(r) {
						no++
					}
					if query.NoDOM()(r) {
						nd++
					}
				}
				nonOrig, noDOM = nonOrig+no, noDOM+nd
				t.Add(key[0], key[1], key[2], key[3], strconv.Itoa(len(rs)), strconv.Itoa(up), strconv.Itoa(no), strconv.Itoa(nd), strconv.Itoa(len(devs)))
			}
			return a.emit(&o, "光模块资产", t, rows,
				fmt.Sprintf("共 %d 个模块、%d 种规格；非原厂 %d，无诊断 %d", len(rows), len(tl.order), nonOrig, noDOM), s.dataNote())
		},
	}
	o.add(cmd, 200)
	return cmd
}

func (a *app) assetSoftwareCmd() *cobra.Command {
	var o outFlags
	var nonCompliant bool
	cmd := &cobra.Command{
		Use: "software [选择器...]", Short: shortAssetSoftware,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			verdicts := map[*swtele.Device]string{}
			if lp := s.r.Lifecycle; lp != nil {
				for d, v := range s.v.Lifecycle(*lp, s.devs) {
					verdicts[d] = lifecycleText[v.Status]
					if v.Compliant() {
						verdicts[d] = "合规"
					}
				}
			} else if nonCompliant {
				return fmt.Errorf("未配置 lifecycle 策略文件，无法判定版本合规")
			}
			tl := newTally[*swtele.Device]()
			for _, d := range s.devs {
				if nonCompliant && verdicts[d] == "合规" {
					continue
				}
				tl.add(d, platformText(d.Identity.Platform), dash(d.System.Version), dash(verdicts[d]))
			}
			t := &report.Table{Columns: []string{"平台", "版本", "合规", "设备数", "型号", "示例设备"}}
			for _, k := range tl.sorted() {
				key, ds := tl.keys[k], tl.rows[k]
				t.Add(key[0], key[1], key[2], strconv.Itoa(len(ds)), models(ds), examples(ds))
			}
			n := 0
			for _, ds := range tl.rows {
				n += len(ds)
			}
			notes := []string{fmt.Sprintf("%s，%d 个版本", matched(n, len(s.devs), "台设备"), len(tl.order))}
			if s.r.Lifecycle == nil {
				notes = append(notes, "未配置 lifecycle 策略文件，合规列为空")
			}
			return a.emit(&o, "软件版本", t, tl.rows, append(notes, s.dataNote())...)
		},
	}
	cmd.Flags().BoolVar(&nonCompliant, "non-compliant", false, flagNonCompliant)
	o.add(cmd, 200)
	return cmd
}

func (a *app) assetHardwareCmd() *cobra.Command {
	var o outFlags
	cmd := &cobra.Command{
		Use: "hardware [选择器...]", Short: shortAssetHardware,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, false)
			if err != nil {
				return err
			}
			tl := newTally[*swtele.Device]()
			for _, d := range s.devs {
				tl.add(d, platformText(d.Identity.Platform), modelText(d))
			}
			t := &report.Table{Columns: []string{"平台", "型号", "设备数", "版本数", "示例设备"}}
			for _, k := range tl.sorted() {
				key, ds := tl.keys[k], tl.rows[k]
				vers := map[string]bool{}
				for _, d := range ds {
					vers[d.System.Version] = true
				}
				t.Add(key[0], key[1], strconv.Itoa(len(ds)), strconv.Itoa(len(vers)), examples(ds))
			}
			return a.emit(&o, "硬件型号", t, tl.rows, fmt.Sprintf("共 %d 台设备、%d 种型号", len(s.devs), len(tl.order)), s.dataNote())
		},
	}
	o.add(cmd, 200)
	return cmd
}

func models(ds []*swtele.Device) string {
	set := map[string]bool{}
	for _, d := range ds {
		if d.System.Model != "" {
			set[d.System.Model] = true
		}
	}
	list := slices.Sorted(maps.Keys(set))
	if len(list) > 3 {
		return strings.Join(list[:3], "、") + fmt.Sprintf(" 等 %d 种", len(list))
	}
	return dash(strings.Join(list, "、"))
}

func examples(ds []*swtele.Device) string {
	var names []string
	for n, d := range ds {
		if n == 2 {
			names = append(names, "…")
			break
		}
		names = append(names, d.Name())
	}
	return strings.Join(names, "、")
}
