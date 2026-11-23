package cli

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/lifecycle"
	"github.com/gatework/netops/report"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/check"
	"github.com/gatework/swtele/internal/workflow"
)

// assessDevices runs the risk catalog over the selected devices.
func (a *app) assessDevices(cmd *cobra.Command, s *session) ([]workflow.DeviceAssessment, error) {
	in := map[*swtele.Device]bool{}
	for _, d := range s.devs {
		in[d] = true
	}
	res, err := s.v.Assess(cmd.Context(), s.r.Policy, func(d *swtele.Device) bool { return in[d] })
	if err != nil {
		return nil, fmt.Errorf("风险评估失败：%w", err)
	}
	if s.r.Lifecycle != nil {
		verdicts := s.v.Lifecycle(*s.r.Lifecycle, s.devs)
		for n := range res {
			if v, ok := verdicts[res[n].Device]; ok && !v.Compliant() {
				res[n].Assessment.Findings = append(res[n].Assessment.Findings, lifecycleFinding(v))
			}
		}
	}
	return res, nil
}

var lifecycleText = map[lifecycle.Status]string{
	lifecycle.StatusBlocked: "运行禁用版本", lifecycle.StatusEndOfSupport: "软件已停止支持",
	lifecycle.StatusBelowMinimum: "版本低于最低要求", lifecycle.StatusEndOfSupportSoon: "软件即将停止支持",
	lifecycle.StatusNotTarget: "版本不是标准版本", lifecycle.StatusEndOfSale: "已停售",
	lifecycle.StatusUnknown: "版本未知", lifecycle.StatusUnmanaged: "无适用的版本规则", lifecycle.StatusCompliant: "合规",
}

// lifecycleFinding renders a verdict as a finding about the device.
func lifecycleFinding(v lifecycle.Verdict) assess.Finding {
	f := v.Finding()
	f.Subject = assess.NewSubject("device", v.Device.Name)
	f.Title = lifecycleText[v.Status]
	f.Detail = fmt.Sprintf("当前 %s", dash(v.Version))
	if v.Target != "" {
		f.Detail += "，标准版本 " + v.Target
	}
	if v.Rule != "" {
		f.Detail += "（规则 " + v.Rule + "）"
	}
	return f
}

// filter returns the findings at or above floor whose rule starts with
// rule, most severe first.
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

func findingKey(f assess.Finding) string { return string(f.Rule) + "|" + f.Subject.String() }

// riskFilters select findings.
type riskFilters struct {
	severity, category string
	rules, exclude     []string
	detail, newOnly    bool
	resolved           bool
}

func (f *riskFilters) add(cmd *cobra.Command, fixedRules bool) {
	fl := cmd.Flags()
	fl.StringVar(&f.severity, "severity", "medium", flagSev)
	fl.StringVar(&f.category, "category", "", flagCategory)
	if !fixedRules {
		fl.StringSliceVar(&f.rules, "rule", nil, flagRule)
	}
	fl.StringSliceVar(&f.exclude, "exclude", nil, flagExclude)
	fl.BoolVar(&f.detail, "detail", fixedRules, flagRiskDetail)
	fl.BoolVar(&f.newOnly, "new", false, flagNew)
	fl.BoolVar(&f.resolved, "resolved", false, flagResolved)
}

// select applies the filters; with --new or --resolved it compares with
// the findings of the previous batch.
func (a *app) selectFindings(cmd *cobra.Command, s *session, f *riskFilters) ([]assess.Finding, error) {
	floor, err := parseSeverity(f.severity)
	if err != nil {
		return nil, err
	}
	keep := func(x assess.Finding) bool {
		if x.Severity < floor || f.category != "" && string(x.Category) != f.category {
			return false
		}
		if len(f.rules) > 0 && !slices.ContainsFunc(f.rules, func(p string) bool { return strings.HasPrefix(string(x.Rule), p) }) {
			return false
		}
		return !slices.ContainsFunc(f.exclude, func(p string) bool { return strings.HasPrefix(string(x.Rule), p) })
	}
	res, err := a.assessDevices(cmd, s)
	if err != nil {
		return nil, err
	}
	cur := slices.DeleteFunc(filter(res, assess.SeverityInfo, ""), func(x assess.Finding) bool { return !keep(x) })
	if !f.newOnly && !f.resolved {
		return cur, nil
	}
	if s.v.Prev == nil {
		return nil, fmt.Errorf("批次 %s 之前没有批次，无法比较新增或消失的发现", s.v.Ledger.Batch)
	}
	prevRes, err := s.v.AssessPrevious(cmd.Context(), s.r.Policy, s.devs)
	if err != nil {
		return nil, err
	}
	prev := slices.DeleteFunc(filter(prevRes, assess.SeverityInfo, ""), func(x assess.Finding) bool { return !keep(x) })
	was := map[string]bool{}
	for _, x := range prev {
		was[findingKey(x)] = true
	}
	now := map[string]bool{}
	for _, x := range cur {
		now[findingKey(x)] = true
	}
	if f.resolved {
		return slices.DeleteFunc(prev, func(x assess.Finding) bool { return now[findingKey(x)] }), nil
	}
	return slices.DeleteFunc(cur, func(x assess.Finding) bool { return was[findingKey(x)] }), nil
}

func (a *app) riskCmd() *cobra.Command {
	return a.findingsCmd("risk [选择器...]", "风险", shortRisk, nil,
		"  swtele risk                           # 按规则汇总中级以上风险\n"+
			"  swtele risk --detail --severity high  # 高危明细\n"+
			"  swtele risk role=core --new           # 较上一批次新增的风险\n"+
			"  swtele risk --rule optics. --rule counters.")
}

// findingsCmd is a findings report; fixed restricts it to rule families.
func (a *app) findingsCmd(use, alias, short string, fixed []string, example string) *cobra.Command {
	var f riskFilters
	var o outFlags
	cmd := &cobra.Command{
		Use: use, Aliases: []string{alias}, Short: short, Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(fixed) > 0 {
				f.rules = fixed
			}
			s, err := a.session(cmd, args, true)
			if err != nil {
				return err
			}
			fs, err := a.selectFindings(cmd, s, &f)
			if err != nil {
				return err
			}
			if f.detail {
				t := &report.Table{Columns: []string{"级别", "设备", "对象", "问题", "说明", "规则"}}
				for _, x := range fs {
					dev := x.Subject.Parts()[0].Key
					t.Add(severityText[x.Severity], dev, subjectText(x.Subject, true), x.Title, x.Detail, string(x.Rule))
				}
				return a.emit(&o, "风险明细", t, fs, fmt.Sprintf("共 %d 条发现", len(fs)), s.dataNote())
			}
			return a.emit(&o, "风险汇总", ruleSummary(fs), fs,
				fmt.Sprintf("共 %d 条发现；--detail 查看明细，--rule 规则前缀 限定范围", len(fs)), s.dataNote())
		},
	}
	f.add(cmd, len(fixed) > 0)
	o.add(cmd, 200)
	return cmd
}

// ruleSummary groups findings by rule: title, worst severity, count and
// devices concerned.
func ruleSummary(fs []assess.Finding) *report.Table {
	type key struct {
		rule assess.RuleID
		sev  assess.Severity
	}
	type agg struct {
		title   string
		n       int
		devices map[string]bool
	}
	by := map[key]*agg{}
	for _, x := range fs {
		k := key{x.Rule, x.Severity}
		g := by[k]
		if g == nil {
			g = &agg{title: x.Title, devices: map[string]bool{}}
			by[k] = g
		}
		g.n++
		g.devices[x.Subject.Parts()[0].Key] = true
	}
	keys := slices.SortedFunc(maps.Keys(by), func(x, y key) int {
		return cmp.Or(cmp.Compare(y.sev, x.sev), cmp.Compare(by[y].n, by[x].n), strings.Compare(string(x.rule), string(y.rule)))
	})
	t := &report.Table{Columns: []string{"级别", "问题", "数量", "涉及设备", "规则"}}
	for _, k := range keys {
		g := by[k]
		t.Add(severityText[k.sev], g.title, strconv.Itoa(g.n), strconv.Itoa(len(g.devices)), string(k.rule))
	}
	return t
}

// printRisks prints the health score and the findings of d in the
// device view; hints (info) are left out.
func (a *app) printRisks(cmd *cobra.Command, s *session, d *swtele.Device) error {
	res, err := a.assessDevices(cmd, &session{v: s.v, r: s.r, devs: []*swtele.Device{d}})
	if err != nil || len(res) == 0 {
		return err
	}
	as := res[0].Assessment
	fs := slices.DeleteFunc(slices.Clone(as.Findings), func(f assess.Finding) bool { return f.Severity < assess.SeverityLow })
	fmt.Fprintf(a.out(), "  健康分：%d，风险 %d 条\n", check.Score(as), len(fs))
	for n, f := range fs {
		if n == 8 {
			fmt.Fprintf(a.out(), "    ……另有 %d 条，见 swtele risk %s --detail\n", len(fs)-8, d.Identity.Mgmt)
			break
		}
		fmt.Fprintf(a.out(), "    [%s] %s：%s\n", severityText[f.Severity], subjectText(f.Subject, true), cmp.Or(f.Detail, f.Title))
	}
	return nil
}

// printPortRisks prints the findings about one port.
func (a *app) printPortRisks(cmd *cobra.Command, s *session, d *swtele.Device, i *swtele.Interface) error {
	res, err := a.assessDevices(cmd, &session{v: s.v, r: s.r, devs: []*swtele.Device{d}})
	if err != nil || len(res) == 0 {
		return err
	}
	k := i.Key()
	for _, f := range res[0].Assessment.Findings {
		for _, p := range f.Subject.Parts() {
			if p.Kind == "interface" && swtele.InterfaceKey(p.Key) == k && f.Severity >= assess.SeverityLow {
				fmt.Fprintf(a.out(), "风险：[%s] %s\n", severityText[f.Severity], cmp.Or(f.Detail, f.Title))
			}
		}
	}
	return nil
}
