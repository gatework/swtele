package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/gatework/netops/assess"

	"github.com/gatework/swtele"
)

func configRules() []rule {
	req := dims(swtele.DimConfig, swtele.DimInterfaces)
	return []rule{
		assess.Check(assess.Meta{ID: "config.stale", Title: "配置备份过旧", Severity: assess.SeverityInfo, Category: assess.CategoryEvidence,
			Requires: dims(swtele.DimConfig), Params: []assess.Param{assess.Integer("days", 30)}}, configStale),
		assess.Check(assess.Meta{ID: "config.port_mode", Title: "端口模式与配置不一致", Severity: assess.SeverityMedium, Category: assess.CategoryDrift, Requires: req}, portMode),
		assess.Check(assess.Meta{ID: "config.allowed_vlans", Title: "允许 VLAN 与配置不一致", Severity: assess.SeverityMedium, Category: assess.CategoryDrift, Requires: req}, allowedVLANs),
		assess.Check(assess.Meta{ID: "config.admin_state", Title: "端口管理状态与配置不一致", Severity: assess.SeverityMedium, Category: assess.CategoryDrift, Requires: req}, adminState),
		assess.Check(assess.Meta{ID: "config.aggregate", Title: "聚合归属与配置不一致", Severity: assess.SeverityMedium, Category: assess.CategoryDrift,
			Requires: dims(swtele.DimConfig, swtele.DimInterfaces, swtele.DimAggregates)}, aggregateDrift),
		assess.Check(assess.Meta{ID: "stp.edge_unguarded", Title: "边缘端口未开启 BPDU 保护", Severity: assess.SeverityMedium, Category: assess.CategoryConfiguration, Requires: req}, edgeUnguarded),
		assess.Check(assess.Meta{ID: "stp.disabled", Title: "交换机未启用生成树", Severity: assess.SeverityHigh, Category: assess.CategoryConfiguration,
			Requires: dims(swtele.DimConfig)}, stpDisabled),
	}
}

// portPair is an interface with its configuration.
type portPair struct {
	i *swtele.Interface
	p *swtele.PortConfig
}

// configured returns the physical and aggregate interfaces that have a
// configuration.
func configured(t *Target) []portPair {
	var out []portPair
	for _, i := range t.Device.Interfaces.All() {
		if i.Kind != swtele.KindPhysical && i.Kind != swtele.KindAggregate {
			continue
		}
		if p := t.Device.Config.Port(i.Name); p != nil {
			out = append(out, portPair{i, p})
		}
	}
	return out
}

func each(t *Target, f func(i *swtele.Interface, p *swtele.PortConfig) *assess.Finding) []assess.Finding {
	var out []assess.Finding
	for _, pp := range configured(t) {
		if fd := f(pp.i, pp.p); fd != nil {
			out = append(out, *fd)
		}
	}
	return out
}

func configStale(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	c := t.Device.Config
	age := t.Device.Observed.Sub(c.At)
	if c.At.IsZero() || age < time.Duration(in.Params.Integer("days"))*24*time.Hour {
		return nil
	}
	return []assess.Finding{finding(t, deviceSubject(t.Device), "配置备份过旧",
		fmt.Sprintf("配置备份于 %s，比运行态早 %d 天，漂移结论可能受配置变更影响", c.At.Format("2006-01-02"), int(age.Hours()/24)))}
}

func portMode(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	return each(t, func(i *swtele.Interface, p *swtele.PortConfig) *assess.Finding {
		if i.Switching == nil || i.Switching.Mode == swtele.ModeUnknown || p.Mode == swtele.ModeUnknown || p.Mode == swtele.ModeRouted || i.Aggregate != "" {
			return nil
		}
		if i.Switching.Mode == p.Mode {
			return nil
		}
		f := finding(t, portSubject(t.Device, i.Name), "端口模式与配置不一致", fmt.Sprintf("运行态 %s，配置 %s", i.Switching.Mode, p.Mode))
		f.Expected, f.Actual = string(p.Mode), string(i.Switching.Mode)
		return &f
	})
}

func allowedVLANs(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	return each(t, func(i *swtele.Interface, p *swtele.PortConfig) *assess.Finding {
		if i.Switching == nil || i.Switching.Allowed == nil || p.Allowed == nil || p.Mode != swtele.ModeTrunk || i.Switching.Mode != swtele.ModeTrunk || i.Aggregate != "" {
			return nil
		}
		if i.Switching.Allowed.Equal(p.Allowed) {
			return nil
		}
		f := finding(t, portSubject(t.Device, i.Name), "允许 VLAN 与配置不一致",
			fmt.Sprintf("运行态 %s，配置 %s", i.Switching.Allowed.Compact(), p.Allowed.Compact()))
		f.Expected, f.Actual = p.Allowed.Compact(), i.Switching.Allowed.Compact()
		return &f
	})
}

func adminState(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	return each(t, func(i *swtele.Interface, p *swtele.PortConfig) *assess.Finding {
		shut, known := p.Shutdown.Get()
		if !known || i.Admin == swtele.StateUnknown || i.Kind != swtele.KindPhysical {
			return nil
		}
		if (i.Admin == swtele.StateDown) == shut {
			return nil
		}
		want := "启用"
		if shut {
			want = "shutdown"
		}
		f := finding(t, portSubject(t.Device, i.Name), "端口管理状态与配置不一致", fmt.Sprintf("配置为 %s，运行态管理状态 %s", want, i.Admin))
		return &f
	})
}

func aggregateDrift(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	return each(t, func(i *swtele.Interface, p *swtele.PortConfig) *assess.Finding {
		if i.Kind != swtele.KindPhysical || swtele.InterfaceKey(i.Aggregate) == swtele.InterfaceKey(p.Aggregate) {
			return nil
		}
		f := finding(t, portSubject(t.Device, i.Name), "聚合归属与配置不一致",
			fmt.Sprintf("配置属于 %s，运行态属于 %s", orDash(p.Aggregate), orDash(i.Aggregate)))
		return &f
	})
}

// edgeUnguarded reports, once per device, the edge ports that neither a
// global nor a port BPDU protection covers.
func edgeUnguarded(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if t.Device.Config.BPDUProtection.Or(false) {
		return nil
	}
	var ports []string
	for _, pp := range configured(t) {
		if pp.p.Edge.Or(false) && !pp.p.BPDUProtection.Or(false) {
			ports = append(ports, pp.i.Name)
		}
	}
	if len(ports) == 0 {
		return nil
	}
	f := finding(t, deviceSubject(t.Device), "边缘端口未开启 BPDU 保护",
		fmt.Sprintf("%d 个边缘端口未受 BPDU 保护（如 %s），接入非法交换机时可能引发环路或根桥抢占", len(ports), strings.Join(ports[:min(3, len(ports))], "、")),
		field("ports", len(ports)))
	f.Remediation = &assess.Remediation{Summary: "全局开启 BPDU 保护", Commands: []string{"stp bpdu-protection", "spanning-tree port type edge bpduguard default"}}
	return []assess.Finding{f}
}

func stpDisabled(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if en, ok := t.Device.Config.STPEnabled.Get(); !ok || en {
		return nil
	}
	return []assess.Finding{finding(t, deviceSubject(t.Device), "未启用生成树", "配置 undo stp global enable，二层环路无保护")}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
