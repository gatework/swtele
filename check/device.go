package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/gatework/netops/assess"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

func flapRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "flap.recent", Title: "端口近期发生过 up/down", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimFlap, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Integer("hours", 24), assess.Bool("edge", false)},
		}, recentFlap),
		assess.Check(assess.Meta{
			ID: "flap.logged", Title: "日志中端口反复 up/down", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimLogs),
			Params:   []assess.Param{assess.Integer("count", 3)},
		}, loggedFlap),
		assess.Check(assess.Meta{
			ID: "flap.resets", Title: "端口复位次数增长", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimCounters),
		}, resetGrowth),
	}
}

func recentFlap(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	window := time.Duration(in.Params.Integer("hours")) * time.Hour
	edge := in.Params.Bool("edge")
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		if i.Kind != swtele.KindPhysical || i.Flap.Never {
			continue
		}
		// Access ports go up and down with the endpoints behind them; only
		// links between network devices are checked unless edge is set.
		if r := t.Graph.Role(t.Device, i.Name); !edge && r != topology.RoleInfra && r != topology.RoleStack {
			continue
		}
		if since, ok := i.Flap.Since.Get(); ok && since < window {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "端口近期抖动",
				fmt.Sprintf("最近一次 up/down 发生在 %s 前，当前状态 %s", since.Round(time.Minute), i.Oper), field("since", since.Round(time.Second))))
		}
	}
	return out
}

func loggedFlap(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	limit := in.Params.Integer("count")
	counts := map[string]int{}
	for _, e := range t.Device.Logs {
		if e.Interface == "" {
			continue
		}
		if m := strings.ToUpper(e.Mnemonic); strings.Contains(m, "UPDOWN") || strings.Contains(m, "LINK_DOWN") || strings.Contains(m, "IF_DOWN") {
			counts[swtele.CleanName(e.Interface)]++
		}
	}
	var out []assess.Finding
	for port, n := range counts {
		if n >= limit {
			out = append(out, finding(t, portSubject(t.Device, port), "日志中端口反复 up/down",
				fmt.Sprintf("最近日志中出现 %d 次端口状态变化", n), field("events", n)))
		}
	}
	return out
}

func resetGrowth(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		p := prevInterface(t, i.Name)
		if p == nil {
			continue
		}
		if d, ok := delta(i.Counters.Resets, p.Counters.Resets); ok && d > 0 {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "端口复位",
				fmt.Sprintf("%s 内复位 %d 次", t.Elapsed().Round(time.Minute), d), field("resets", d)))
		}
	}
	return out
}

func healthRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "health.cpu", Title: "CPU 利用率过高", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimCPU), Params: []assess.Param{assess.Number("percent", 80)},
		}, cpu),
		assess.Check(assess.Meta{
			ID: "health.memory", Title: "内存利用率过高", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimMemory), Params: []assess.Param{assess.Number("percent", 85)},
		}, memory),
		assess.Check(assess.Meta{
			ID: "health.temperature", Title: "设备温度越限", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimEnvironment),
		}, temperature),
		assess.Check(assess.Meta{
			ID: "health.fan_power", Title: "风扇或电源异常", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimEnvironment),
		}, fanPower),
	}
}

func cpu(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	limit := in.Params.Number("percent")
	var out []assess.Finding
	for _, c := range t.Device.System.CPU {
		v, ok := c.Min5.Get()
		if !ok {
			v, ok = c.Now.Get()
		}
		if ok && v >= limit {
			out = append(out, finding(t, deviceSubject(t.Device).Child("cpu", c.Unit.String()), "CPU 利用率过高",
				fmt.Sprintf("%.0f%%", v), field("percent", v)))
		}
	}
	return out
}

func memory(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	limit := in.Params.Number("percent")
	var out []assess.Finding
	for _, m := range t.Device.System.Memory {
		if v, ok := m.UsedPercent(); ok && v >= limit {
			out = append(out, finding(t, deviceSubject(t.Device).Child("memory", m.Unit.String()), "内存利用率过高",
				fmt.Sprintf("%.1f%%", v), field("percent", round(v))))
		}
	}
	return out
}

func temperature(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, s := range t.Device.System.Sensors {
		v, ok := s.Value.Get()
		if !ok {
			continue
		}
		limit, sev := s.Warning, assess.SeverityMedium
		if s.Alarm.OK && v >= s.Alarm.V {
			limit, sev = s.Alarm, assess.SeverityHigh
		}
		if limit.OK && v >= limit.V {
			f := finding(t, deviceSubject(t.Device).Child("sensor", s.Unit.String()+" "+s.Name), "温度越限",
				fmt.Sprintf("%s %.0f°C，阈值 %.0f°C", s.Name, v, limit.V), field("celsius", v))
			f.Severity = sev
			out = append(out, f)
		}
	}
	return out
}

func fanPower(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for kind, list := range map[string][]swtele.Component{"fan": t.Device.System.Fans, "psu": t.Device.System.PSUs} {
		for _, c := range list {
			if ok, known := c.OK.Get(); known && !ok {
				out = append(out, finding(t, deviceSubject(t.Device).Child(kind, c.ID), "部件状态异常", c.ID+"："+c.Status))
			}
		}
	}
	return out
}

func stackRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "stack.mad_disabled", Title: "多成员 IRF 未启用 MAD", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
			Requires: dims(swtele.DimStack, swtele.DimMAD),
		}, madDisabled),
		assess.Check(assess.Meta{
			ID: "stack.mad_status", Title: "MAD 状态异常", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimMAD),
		}, madStatus),
		assess.Check(assess.Meta{
			ID: "stack.link", Title: "IRF 物理链路异常或无冗余", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimStack),
		}, stackLinks),
		assess.Check(assess.Meta{
			ID: "stack.member_lost", Title: "IRF 成员减少", Severity: assess.SeverityCritical, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimStack),
		}, memberLost),
	}
}

func members(d *swtele.Device) int {
	if d == nil || d.Stack == nil {
		return 0
	}
	return len(d.Stack.Members)
}

func madDisabled(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if members(t.Device) < 2 || t.Device.Stack.MAD.Enabled() {
		return nil
	}
	f := finding(t, deviceSubject(t.Device), "IRF 未启用 MAD", fmt.Sprintf("%d 个成员，IRF 链路断开后会出现双主", members(t.Device)))
	f.Remediation = &assess.Remediation{Summary: "配置 BFD MAD 或 LACP MAD", Commands: []string{"interface Vlan-interface<N>", " mad bfd enable", " mad ip address <ip> <mask> member <id>"}}
	return []assess.Finding{f}
}

func madStatus(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if t.Device.Stack == nil || t.Device.Stack.MAD == nil {
		return nil
	}
	m := t.Device.Stack.MAD
	var out []assess.Finding
	if m.Recovering {
		out = append(out, finding(t, deviceSubject(t.Device), "IRF 处于多主恢复状态", "Multi-active recovery"))
	}
	if m.Status != "" && !strings.EqualFold(m.Status, "Normal") {
		out = append(out, finding(t, deviceSubject(t.Device), "MAD 状态异常", m.Status))
	}
	for _, mm := range m.Members {
		if mm.Status != "" && !strings.EqualFold(mm.Status, "Normal") {
			out = append(out, finding(t, deviceSubject(t.Device).Child("member", fmt.Sprint(mm.Member)), "成员 MAD 状态异常", mm.Status))
		}
	}
	return out
}

func stackLinks(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if members(t.Device) < 2 {
		return nil
	}
	var out []assess.Finding
	up := map[[2]int]int{}
	for _, l := range t.Device.Stack.Links {
		if l.State == swtele.StateUp {
			up[[2]int{l.Member, l.Port}]++
			continue
		}
		out = append(out, finding(t, portSubject(t.Device, l.Interface), "IRF 物理链路 down", fmt.Sprintf("成员 %d IRF-Port%d", l.Member, l.Port)))
	}
	for k, n := range up {
		if n == 1 {
			f := finding(t, deviceSubject(t.Device).Child("irf-port", fmt.Sprintf("%d/%d", k[0], k[1])), "IRF 端口仅一条物理链路",
				fmt.Sprintf("成员 %d IRF-Port%d 只绑定 1 条 up 链路，单点故障将导致分裂", k[0], k[1]))
			f.Severity = assess.SeverityMedium
			out = append(out, f)
		}
	}
	return out
}

func memberLost(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if now, was := members(t.Device), members(t.Prev); was > now {
		return []assess.Finding{finding(t, deviceSubject(t.Device), "IRF 成员减少", fmt.Sprintf("上次 %d 个成员，本次 %d 个", was, now))}
	}
	return nil
}
