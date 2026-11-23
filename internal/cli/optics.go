package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/query"
)

type opticFilters struct {
	abnormal, dark, noDOM, idle, nonOriginal, swapped bool
	level, vendor, kind, speed, port                  string
	margin, spread, marginBelow                       float64
}

func (f *opticFilters) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.port, "port", "", flagPort)
	fl.BoolVar(&f.abnormal, "abnormal", false, flagAbnormal)
	fl.BoolVar(&f.dark, "dark", false, flagDark)
	fl.BoolVar(&f.noDOM, "no-dom", false, flagNoDOM)
	fl.BoolVar(&f.idle, "idle-module", false, flagIdleModule)
	fl.BoolVar(&f.nonOriginal, "non-original", false, flagNonOriginal)
	fl.BoolVar(&f.swapped, "swapped", false, flagSwapped)
	fl.StringVar(&f.level, "level", "", flagLevel)
	fl.StringVar(&f.vendor, "vendor", "", flagVendor)
	fl.StringVar(&f.kind, "type", "", flagModuleType)
	fl.StringVar(&f.speed, "speed", "", flagSpeed)
	fl.Float64Var(&f.marginBelow, "margin-below", 0, flagMarginBelow)
	fl.Float64Var(&f.margin, "abnormal-margin", 2, flagAbnormalMargin)
	fl.Float64Var(&f.spread, "abnormal-spread", 3, flagAbnormalSpread)
}

func (f *opticFilters) predicate() (query.Optic, error) {
	var ps []query.Optic
	add := func(on bool, p query.Optic) {
		if on {
			ps = append(ps, p)
		}
	}
	if f.port != "" {
		k := swtele.InterfaceKey(f.port)
		ps = append(ps, func(r query.OpticRow) bool { return r.Port.Key() == k })
	}
	add(f.abnormal, query.Abnormal(f.margin, f.spread))
	add(f.dark, query.Dark())
	add(f.noDOM, query.NoDOM())
	add(f.idle, query.IdleModule())
	add(f.nonOriginal, query.NonOriginal())
	add(f.swapped, query.Swapped())
	add(f.vendor != "", query.Vendor(f.vendor))
	add(f.kind != "", query.Type(f.kind))
	add(f.marginBelow > 0, query.MarginBelow(f.marginBelow))
	switch f.level {
	case "":
	case "alarm":
		ps = append(ps, query.Level(swtele.LevelAlarm))
	case "warn", "warning":
		ps = append(ps, query.Level(swtele.LevelWarn))
	default:
		return nil, fmt.Errorf("无效的级别 %q（可选 warn、alarm）", f.level)
	}
	if f.speed != "" {
		bps, err := parseSpeed(f.speed)
		if err != nil {
			return nil, err
		}
		ps = append(ps, query.Speed(bps))
	}
	return query.All(ps...), nil
}

// opticLevel renders the grade of a module: only up ports with
// diagnostics are graded.
func opticLevel(r query.OpticRow) string {
	switch {
	case !r.Port.Up():
		return "端口未 up，不评级"
	case !query.Graded(r):
		return "无诊断"
	}
	issues := query.Issues(r, 2, 3)
	if len(issues) == 0 {
		return "正常"
	}
	var parts []string
	for _, i := range issues {
		if t := issueText(i); !slices.Contains(parts, t) {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "、")
}

var issueNames = map[string]string{"temperature": "温度", "voltage": "电压", "bias": "偏置", "tx": "发光", "rx": "收光"}

func issueText(i query.Issue) string {
	switch i.What {
	case "dark":
		return "无光"
	case "margin":
		return "收光余量不足"
	case "spread":
		return "通道收光不均"
	}
	dir := "偏低"
	if i.High {
		dir = "偏高"
	}
	return issueNames[i.What] + dir + levelText[i.Level]
}

func (a *app) opticsCmd() *cobra.Command {
	var f opticFilters
	var o outFlags
	cmd := &cobra.Command{
		Use: "optics [选择器...]", Aliases: []string{"光模块"}, Short: shortOptics,
		Example: "  swtele optics --abnormal              # 端口 up 的异常光模块\n" +
			"  swtele optics role=core --margin-below 2 --sort 余量dB\n" +
			"  swtele optics --idle-module           # 插在 down 口上、可回收的模块\n" +
			"  swtele optics --non-original          # 非原厂模块",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.session(cmd, args, f.swapped)
			if err != nil {
				return err
			}
			pred, err := f.predicate()
			if err != nil {
				return err
			}
			all := s.q.Optics(s.devs)
			rows := query.Filter(all, pred)
			t := &report.Table{Columns: []string{"设备", "端口", "端口状态", "厂商", "类型", "序列号", "温度℃", "收光dBm", "发光dBm", "余量dB", "评估"}}
			for _, r := range rows {
				x, rx, tx, margin := r.Optic, "-", "-", "-"
				if query.Graded(r) {
					rx, tx = reading(x.Lanes[0].RxPower), reading(x.Lanes[0].TxPower)
					if m, ok := query.RxMargin(r); ok {
						margin = strconv.FormatFloat(m, 'f', 2, 64)
					}
				}
				temp := "-"
				if r.Port.Up() {
					temp = reading(x.Temp)
				}
				t.Add(r.Device.Name(), r.Port.Name, stateText(r.Port), dash(x.Inventory.Vendor), dash(x.Inventory.Type), dash(x.Inventory.Serial),
					temp, rx, tx, margin, opticLevel(r))
			}
			return a.emit(&o, "光模块", t, rows, opticSummary(all, rows), s.dataNote())
		},
	}
	f.add(cmd)
	o.add(cmd, 200)
	return cmd
}

func opticSummary(all, rows []query.OpticRow) string {
	var up, abnormal, dark, noDOM, idle int
	for _, r := range all {
		switch {
		case !r.Port.Up():
			idle++
		case !query.Graded(r):
			up++
			noDOM++
		default:
			up++
			if query.Abnormal(2, 3)(r) {
				abnormal++
			}
			if query.Dark()(r) {
				dark++
			}
		}
	}
	return fmt.Sprintf("%s；在位 %d，端口 up %d（异常 %d，其中无光 %d；无诊断 %d），插在未用端口上 %d",
		matched(len(rows), len(all), "个模块"), len(all), up, abnormal, dark, noDOM, idle)
}

// printOptic is the optics section of a port view.
func printOptic(a *app, r query.OpticRow) {
	w, x := a.out(), r.Optic
	fmt.Fprintf(w, "光模块：%s %s %s SN %s，级别 %s\n", dash(x.Inventory.Vendor), dash(x.Inventory.Type), dash(x.Inventory.PartNumber), dash(x.Inventory.Serial), opticLevel(r))
	if !query.Graded(r) {
		return
	}
	fmt.Fprintf(w, "  温度 %s℃，电压 %sV\n", reading(x.Temp), reading(x.Voltage))
	for _, l := range x.Lanes {
		fmt.Fprintf(w, "  通道 %d：收光 %s dBm（%s）发光 %s dBm 偏置 %s mA\n", l.Index, reading(l.RxPower), dash(levelText[l.RxPower.Level()]), reading(l.TxPower), reading(l.Bias))
	}
	if m, ok := query.RxMargin(r); ok {
		fmt.Fprintf(w, "  收光余量：%.2f dB\n", m)
	}
}
