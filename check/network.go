package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

func lagRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "lag.member_unselected", Title: "聚合成员未选中", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimAggregates, swtele.DimInterfaces),
		}, unselected),
		assess.Check(assess.Meta{
			ID: "lag.lacp_state", Title: "LACP 协商状态异常", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimAggregates),
		}, lacpState),
		assess.Check(assess.Meta{
			ID: "lag.single_member", Title: "聚合组仅一个成员（无冗余）", Severity: assess.SeverityLow, Category: assess.CategoryConfiguration,
			Requires: dims(swtele.DimAggregates),
		}, singleMember),
		assess.Check(assess.Meta{
			ID: "lag.same_member", Title: "聚合成员都在同一 IRF 成员上", Severity: assess.SeverityLow, Category: assess.CategoryConfiguration,
			Requires: dims(swtele.DimAggregates, swtele.DimStack),
		}, sameMember),
		assess.Check(assess.Meta{
			ID: "stp.down_port", Title: "端口被 STP 保护关闭", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimSTP),
		}, stpDown),
	}
}

func unselected(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, a := range t.Device.Aggregates {
		for _, m := range a.Members {
			i := t.Device.Interfaces.Get(m.Port)
			if m.Selected || i == nil || !i.Up() {
				continue
			}
			out = append(out, finding(t, portSubject(t.Device, m.Port), "聚合成员 up 但未选中",
				fmt.Sprintf("%s 成员状态 %s", a.Name, m.Status), field("aggregate", a.Name)))
		}
	}
	return out
}

func lacpState(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, a := range t.Device.Aggregates {
		if a.Mode != swtele.AggLACP {
			continue
		}
		for _, m := range a.Members {
			if m.Flags == "" || m.Selected && m.Flags.Healthy() && (m.PartnerFlags == "" || m.PartnerFlags.Healthy()) {
				continue
			}
			if i := t.Device.Interfaces.Get(m.Port); i == nil || !i.Up() {
				continue
			}
			out = append(out, finding(t, portSubject(t.Device, m.Port), "LACP 状态不完整",
				fmt.Sprintf("%s 本端 {%s} 对端 {%s}", a.Name, m.Flags, m.PartnerFlags), field("aggregate", a.Name)))
		}
	}
	return out
}

func singleMember(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, a := range t.Device.Aggregates {
		if len(a.Members) == 1 {
			out = append(out, finding(t, portSubject(t.Device, a.Name), "聚合组仅一个成员", a.Members[0].Port))
		}
	}
	return out
}

var memberOf = func(port string) string {
	// Comware "GigabitEthernet2/0/1" belongs to IRF member 2.
	i := strings.IndexFunc(port, func(r rune) bool { return r >= '0' && r <= '9' })
	if i < 0 {
		return ""
	}
	rest := port[i:]
	if j := strings.IndexByte(rest, '/'); j > 0 {
		return rest[:j]
	}
	return ""
}

func sameMember(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if members(t.Device) < 2 {
		return nil
	}
	var out []assess.Finding
	for _, a := range t.Device.Aggregates {
		if len(a.Members) < 2 {
			continue
		}
		seen := map[string]bool{}
		for _, m := range a.Members {
			seen[memberOf(m.Port)] = true
		}
		if len(seen) == 1 {
			out = append(out, finding(t, portSubject(t.Device, a.Name), "聚合未跨 IRF 成员",
				fmt.Sprintf("%d 个成员均位于同一台成员设备，该成员故障时聚合中断", len(a.Members))))
		}
	}
	return out
}

func stpDown(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, p := range t.Device.L2.STP.Ports {
		if p.Down {
			out = append(out, finding(t, portSubject(t.Device, p.Port), "端口被 STP 关闭", p.Reason))
		}
	}
	return out
}

func routingRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "routing.peer_down", Title: "路由邻居未建立", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
		}, peerDown),
		assess.Check(assess.Meta{
			ID: "routing.peer_recent", Title: "路由邻居近期重建", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimBGP),
			Params:   []assess.Param{assess.Integer("hours", 24)},
		}, peerRecent),
		assess.Check(assess.Meta{
			ID: "routing.peer_lost", Title: "路由邻居消失", Severity: assess.SeverityHigh, Category: assess.CategoryDrift,
		}, peerLost),
	}
}

// observed reports whether the peers of proto were decoded completely.
func observed(d *swtele.Device, proto swtele.Protocol) bool {
	dim := swtele.DimOSPF
	if proto == swtele.ProtoBGP {
		dim = swtele.DimBGP
	}
	return d.Coverage.Status(dim).Complete()
}

func peerKey(p swtele.Peer) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", p.Proto, p.VRF, p.Family, p.Address, p.RouterID)
}

func peerSubject(t *Target, p swtele.Peer) assess.Subject {
	return deviceSubject(t.Device).Child(string(p.Proto), p.Address.String())
}

func peerDown(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, p := range t.Device.L3.Peers {
		if !p.Established {
			out = append(out, finding(t, peerSubject(t, p), "路由邻居未建立", fmt.Sprintf("%s %s 状态 %s", p.Proto, p.Address, p.State)))
		}
	}
	return out
}

func peerRecent(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	window := time.Duration(in.Params.Integer("hours")) * time.Hour
	var out []assess.Finding
	for _, p := range t.Device.L3.Peers {
		if up, ok := p.Up.Get(); ok && p.Established && up < window {
			out = append(out, finding(t, peerSubject(t, p), "路由邻居近期重建", fmt.Sprintf("%s %s 已建立 %s", p.Proto, p.Address, up.Round(time.Minute))))
		}
	}
	return out
}

func peerLost(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if t.Prev == nil {
		return nil
	}
	now := map[string]bool{}
	for _, p := range t.Device.L3.Peers {
		now[peerKey(p)] = true
	}
	var out []assess.Finding
	for _, p := range t.Prev.L3.Peers {
		// Only a protocol observed completely both times can lose a peer.
		if !observed(t.Device, p.Proto) || !observed(t.Prev, p.Proto) {
			continue
		}
		if !now[peerKey(p)] {
			out = append(out, finding(t, peerSubject(t, p), "路由邻居消失", fmt.Sprintf("上次存在的 %s 邻居 %s 本次未出现", p.Proto, p.Address)))
		}
	}
	return out
}

func linkRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "link.speed_mismatch", Title: "互联两端速率或双工不一致", Severity: assess.SeverityMedium, Category: assess.CategoryConsistency,
			Requires: dims(swtele.DimNeighbors, swtele.DimInterfaces),
		}, speedMismatch),
		assess.Check(assess.Meta{
			ID: "link.half_duplex", Title: "端口工作在半双工", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimInterfaces),
		}, halfDuplex),
		assess.Check(assess.Meta{
			ID: "link.pvid_mismatch", Title: "互联两端 PVID 不一致", Severity: assess.SeverityLow, Category: assess.CategoryConsistency,
			Requires: dims(swtele.DimNeighbors, swtele.DimInterfaces),
		}, pvidMismatch),
		assess.Check(assess.Meta{
			ID: "link.allowed_vlans", Title: "互联两端允许 VLAN 不一致", Severity: assess.SeverityMedium, Category: assess.CategoryConsistency,
			Requires: dims(swtele.DimNeighbors, swtele.DimInterfaces),
		}, allowedMismatch),
		assess.Check(assess.Meta{
			ID: "link.mtu_mismatch", Title: "互联两端 MTU 不一致", Severity: assess.SeverityLow, Category: assess.CategoryConsistency,
			Requires: dims(swtele.DimNeighbors, swtele.DimInterfaces),
		}, mtuMismatch),
		assess.Check(assess.Meta{
			ID: "link.one_way", Title: "邻居仅单向可见", Severity: assess.SeverityLow, Category: assess.CategoryConsistency,
			Requires: dims(swtele.DimNeighbors),
		}, oneWay),
	}
}

func speedMismatch(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, l := range t.Graph.LinksOf(t.Device) {
		if l.State != topology.Confirmed || l.B.Device == nil {
			continue
		}
		a, b := t.Device.Interfaces.Get(l.A.Port), l.B.Device.Interfaces.Get(l.B.Port)
		if a == nil || b == nil || !a.Up() || !b.Up() || !a.Speed.OK || !b.Speed.OK {
			continue
		}
		// Report once per link, from the lower-addressed end.
		if t.Device.Identity.Mgmt.Compare(l.B.Device.Identity.Mgmt) > 0 {
			continue
		}
		if a.Speed.V != b.Speed.V || a.Duplex != b.Duplex && a.Duplex != "" && b.Duplex != "" {
			out = append(out, finding(t, portSubject(t.Device, a.Name), "互联两端协商不一致",
				fmt.Sprintf("本端 %d Mb/s %s，对端 %s %s %d Mb/s %s", a.Speed.V/1e6, a.Duplex, l.B.Device.Name(), b.Name, b.Speed.V/1e6, b.Duplex),
				field("peer", l.B.Device.Name()), field("peer_port", b.Name)))
		}
	}
	return out
}

func halfDuplex(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, i := range physicalUp(t.Device) {
		if i.Duplex == swtele.DuplexHalf {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "半双工", "端口协商为半双工，易产生冲突与错包"))
		}
	}
	return out
}

func pvidMismatch(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, n := range t.Device.Neighbors {
		i := t.Device.Interfaces.Get(n.LocalPort)
		if !n.PVID.OK || i == nil || i.Switching == nil || !i.Switching.PVID.OK || i.Aggregate != "" {
			continue
		}
		if t.Ledger.Remote(n) == nil {
			continue // endpoints advertise their own VLAN conventions
		}
		if n.PVID.V != i.Switching.PVID.V {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "PVID 不一致",
				fmt.Sprintf("本端 PVID %d，对端 %s %s 通告 %d", i.Switching.PVID.V, n.System, n.Port, n.PVID.V)))
		}
	}
	return out
}

func oneWay(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, l := range t.Graph.LinksOf(t.Device) {
		if l.State == topology.OneWay && l.A.Device == t.Device {
			out = append(out, finding(t, portSubject(t.Device, l.A.Port), "邻居单向可见",
				fmt.Sprintf("本端看到 %s %s，对端未看到本端（对端 LLDP 关闭或链路异常）", l.B.Device.Name(), l.B.Port)))
		}
	}
	return out
}

// peers yields the confirmed links of t's device with both ports up,
// once per link (from the lower-addressed end).
func peers(t *Target, yield func(a, b *swtele.Interface, remote *swtele.Device)) {
	for _, l := range t.Graph.LinksOf(t.Device) {
		if l.State != topology.Confirmed || l.B.Device == nil || l.B.Device == t.Device {
			continue
		}
		if t.Device.Identity.Mgmt.Compare(l.B.Device.Identity.Mgmt) > 0 {
			continue
		}
		a, b := t.Device.Interfaces.Get(l.A.Port), l.B.Device.Interfaces.Get(l.B.Port)
		if a == nil || b == nil || !a.Up() || !b.Up() {
			continue
		}
		yield(a, b, l.B.Device)
	}
}

// logical is the port that carries the switching settings: the
// aggregate of a member.
func logical(d *swtele.Device, i *swtele.Interface) *swtele.Interface {
	if i.Aggregate != "" {
		if agg := d.Interfaces.Get(i.Aggregate); agg != nil && agg.Switching != nil {
			return agg
		}
	}
	return i
}

func allowedMismatch(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	seen := map[[2]string]bool{}
	peers(t, func(a, b *swtele.Interface, remote *swtele.Device) {
		la, lb := logical(t.Device, a), logical(remote, b)
		k := [2]string{la.Key(), remote.Name() + "|" + lb.Key()}
		if seen[k] {
			return // the other members of the same aggregate
		}
		seen[k] = true
		sa, sb := la.Switching, lb.Switching
		if sa == nil || sb == nil || sa.Mode != swtele.ModeTrunk || sb.Mode != swtele.ModeTrunk || sa.Allowed == nil || sb.Allowed == nil {
			return
		}
		if sa.Allowed.Equal(sb.Allowed) {
			return
		}
		onlyA, onlyB := sa.Allowed.Difference(sb.Allowed), sb.Allowed.Difference(sa.Allowed)
		detail := fmt.Sprintf("对端 %s %s", remote.Name(), lb.Name)
		if c := onlyA.Compact(); c != "" {
			detail += "；仅本端允许 " + c
		}
		if c := onlyB.Compact(); c != "" {
			detail += "；仅对端允许 " + c
		}
		f := finding(t, portSubject(t.Device, la.Name), "互联两端允许 VLAN 不一致", detail,
			field("peer", remote.Name()), field("peer_port", lb.Name), field("only_local", onlyA.Compact()), field("only_remote", onlyB.Compact()))
		f.Expected, f.Actual = sb.Allowed.Compact(), sa.Allowed.Compact()
		f.Remediation = &assess.Remediation{Summary: "核对两端 trunk 允许列表，只在一端放行的 VLAN 在该链路上不通", Manual: true}
		if onlyVLAN1(onlyA) && onlyVLAN1(onlyB) {
			f.Severity = assess.SeverityLow // VLAN 1 removed on one end only: usually harmless
		}
		out = append(out, f)
	})
	return out
}

const (
	jumbo       = 9000
	headerSlack = 100
)

func mtuMismatch(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	peers(t, func(a, b *swtele.Interface, remote *swtele.Device) {
		if a.Kind != swtele.KindPhysical || b.Kind != swtele.KindPhysical || !a.MTU.OK || !b.MTU.OK {
			return
		}
		// Platforms report the frame length or the MTU, a few header
		// bytes apart, and default jumbo limits differ by model: only a
		// non-jumbo end facing a larger one drops traffic.
		lo, hi := min(a.MTU.V, b.MTU.V), max(a.MTU.V, b.MTU.V)
		if lo >= jumbo || hi-lo <= headerSlack {
			return
		}
		out = append(out, finding(t, portSubject(t.Device, a.Name), "互联两端 MTU 不一致",
			fmt.Sprintf("本端 %d，对端 %s %s 为 %d；大包会在较小一端被丢弃", a.MTU.V, remote.Name(), b.Name, b.MTU.V),
			field("peer", remote.Name()), field("peer_port", b.Name)))
	})
	return out
}

// onlyVLAN1 reports a set that is empty or just VLAN 1.
func onlyVLAN1(s *set.Set[int]) bool {
	c := s.Compact()
	return c == "" || c == "1"
}
