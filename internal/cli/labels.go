package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/topology"
)

// Chinese labels of model enums. JSON output keeps the English values.

var causeText = map[swtele.DownCause]string{
	swtele.CauseNotConnected: "未连接", swtele.CauseAdmin: "管理关闭", swtele.CauseSTP: "STP 阻塞",
	swtele.CauseAggregate: "聚合口 down", swtele.CauseErrDisabled: "错误关闭", swtele.CauseNoXcvr: "无模块",
	swtele.CauseSuspended: "聚合挂起", swtele.CauseOther: "down",
}

// stateText renders the state of an interface.
func stateText(i *swtele.Interface) string {
	switch {
	case i.Admin == swtele.StateDown:
		return "管理关闭"
	case i.Up():
		return "up"
	case i.DownCause != swtele.CauseNone:
		return "down（" + causeText[i.DownCause] + "）"
	case i.Oper == swtele.StateDown:
		return "down"
	}
	return "-"
}

var kindText = map[swtele.Kind]string{
	swtele.KindPhysical: "物理口", swtele.KindAggregate: "聚合口", swtele.KindSVI: "VLAN 接口", swtele.KindLoopback: "环回口",
	swtele.KindTunnel: "隧道", swtele.KindMgmt: "管理口", swtele.KindNull: "空接口", swtele.KindVirtual: "虚接口",
}

var roleText = map[topology.Role]string{
	topology.RoleEdge: "接入", topology.RoleInfra: "互联", topology.RoleStack: "堆叠/对等", topology.RoleUnused: "未用",
}

var linkText = map[topology.State]string{
	topology.Confirmed: "双向确认", topology.OneWay: "单向", topology.Shared: "共享网段", topology.Unmanaged: "非受管邻居",
}

var duplexText = map[swtele.Duplex]string{swtele.DuplexFull: "全双工", swtele.DuplexHalf: "半双工", swtele.DuplexAuto: "自协商"}

var modeText = map[swtele.PortMode]string{
	swtele.ModeAccess: "access", swtele.ModeTrunk: "trunk", swtele.ModeHybrid: "hybrid", swtele.ModeRouted: "三层",
}

var severityText = map[assess.Severity]string{
	assess.SeverityCritical: "严重", assess.SeverityHigh: "高", assess.SeverityMedium: "中", assess.SeverityLow: "低", assess.SeverityInfo: "提示",
}

var coverageText = map[evidence.Status]string{
	evidence.StatusComplete: "完整", evidence.StatusPartial: "部分", evidence.StatusFailed: "失败",
	evidence.StatusNotRequested: "未采集", evidence.StatusUnsupported: "不支持",
}

var levelText = map[swtele.Level]string{swtele.LevelNormal: "正常", swtele.LevelWarn: "预警", swtele.LevelAlarm: "告警"}

var confidenceText = map[locate.Confidence]string{
	locate.Exact: "精确", locate.Shared: "共享接入口", locate.Ambiguous: "不唯一",
	locate.GatewayOnly: "仅网关可见", locate.Unknown: "未找到", locate.Device: "网络设备地址",
}

var roleNames = map[string]string{
	"master": "主", "standby": "备", "slave": "备", "backup": "备", "loading": "加载中",
	"active": "主用", "passive": "备用",
}

// memberRole renders an IRF or HA role.
func memberRole(r string) string {
	if t, ok := roleNames[strings.ToLower(r)]; ok {
		return t
	}
	return r
}

var stackText = map[swtele.StackKind]string{swtele.StackIRF: "IRF 堆叠", swtele.StackVPC: "vPC", swtele.StackHA: "HA 双机"}

// clock renders times in the operators' zone.
type clock struct{ loc *time.Location }

func (c clock) time(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(c.loc).Format("2006-01-02 15:04")
}

// zone names the display zone, for headers.
func (c clock) zone() string { return c.loc.String() }

// since renders an age: "393 天前", "3 小时前".
func since(d time.Duration) string {
	switch {
	case d <= 0:
		return "刚刚"
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d 天前", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%d 小时前", int(d/time.Hour))
	case d >= time.Minute:
		return fmt.Sprintf("%d 分钟前", int(d/time.Minute))
	}
	return "刚刚"
}

// window renders an averaging window: "5 分钟", "30 秒".
func window(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	}
	return fmt.Sprintf("%d 秒", int(d/time.Second))
}

var partText = map[string]string{
	"interface": "端口", "cpu": "CPU", "memory": "内存", "sensor": "传感器", "fan": "风扇", "psu": "电源",
	"member": "成员", "irf-port": "IRF 端口", "bgp": "BGP 邻居", "ospf": "OSPF 邻居",
}

// subjectText renders a finding subject as "SW01 端口 GE1/0/1"; the
// device name is left out when inDevice is set.
func subjectText(s assess.Subject, inDevice bool) string {
	var parts []string
	for _, p := range s.Parts() {
		switch {
		case p.Kind == "device":
			if !inDevice {
				parts = append(parts, p.Key)
			}
		case partText[p.Kind] != "":
			parts = append(parts, partText[p.Kind]+" "+p.Key)
		default:
			parts = append(parts, p.Kind+" "+p.Key)
		}
	}
	if len(parts) == 0 {
		return "本设备"
	}
	return strings.Join(parts, " ")
}

// unitText renders a CPU or board location.
func unitText(u swtele.Unit) string {
	switch {
	case u.Chassis > 0 && u.CPU > 0:
		return fmt.Sprintf("框 %d 槽位 %d CPU %d", u.Chassis, u.Slot, u.CPU)
	case u.Chassis > 0:
		return fmt.Sprintf("框 %d 槽位 %d", u.Chassis, u.Slot)
	case u.CPU > 0:
		return fmt.Sprintf("槽位 %d CPU %d", u.Slot, u.CPU)
	}
	return fmt.Sprintf("槽位 %d", u.Slot)
}

var platformNames = map[string]string{
	"comware": "H3C Comware", "h3c": "H3C Comware", "h3c_wireless": "H3C 无线控制器",
	"nxos": "Cisco NX-OS", "cisco_nxos": "Cisco NX-OS", "ios": "Cisco IOS", "cisco_ios": "Cisco IOS",
	"hillstone": "Hillstone StoneOS", "alteon": "Radware Alteon", "radware": "Radware Alteon",
	"panos": "PAN-OS", "palo_alto": "PAN-OS",
}

func platformText(p string) string {
	if t, ok := platformNames[p]; ok {
		return t
	}
	return dash(p)
}
