package path_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/path"
	"github.com/gatework/swtele/topology"
)

func mac(s string) swtele.MAC {
	m, err := swtele.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func sw(name, mgmt, chassis string) *swtele.Device {
	d := swtele.New(device.Device{Name: name, Mgmt: netip.MustParseAddr(mgmt)}, time.Unix(0, 0))
	d.Stack = &swtele.Stack{Kind: swtele.StackIRF, MAC: mac(chassis)}
	return d
}

func port(d *swtele.Device, name string, sp *swtele.Switchport) {
	i := d.Interfaces.Ensure(name)
	i.Kind, i.Oper, i.Switching = swtele.KindPhysical, swtele.StateUp, sp
}

func trunk(vlans ...int) *swtele.Switchport {
	allowed := set.New[int]()
	for _, v := range vlans {
		allowed.Add(v, v)
	}
	return &swtele.Switchport{Mode: swtele.ModeTrunk, PVID: swtele.Some(1), Allowed: allowed}
}

func access(vlan int) *swtele.Switchport {
	return &swtele.Switchport{Mode: swtele.ModeAccess, PVID: swtele.Some(vlan)}
}

func link(a *swtele.Device, ap string, b *swtele.Device, bp string, chA, chB string) {
	a.Neighbors = append(a.Neighbors, swtele.Neighbor{LocalPort: ap, System: b.Identity.Name, Port: bp, ChassisMAC: mac(chB)})
	b.Neighbors = append(b.Neighbors, swtele.Neighbor{LocalPort: bp, System: a.Identity.Name, Port: ap, ChassisMAC: mac(chA)})
}

// fleet: a1 (pc1, VLAN 10) and a2 (pc2, VLAN 10; pc3, VLAN 20) hang off
// core, which routes VLANs 10 and 20. The a2 uplink carries only 10 and
// 20; a third switch a3 (pc4, VLAN 30) has an uplink that does not
// allow 30.
func fleet() *ledger.Ledger {
	core := sw("core", "192.0.2.1", "0000-0000-0c01")
	a1 := sw("a1", "192.0.2.2", "0000-0000-0a01")
	a2 := sw("a2", "192.0.2.3", "0000-0000-0a02")
	a3 := sw("a3", "192.0.2.4", "0000-0000-0a03")
	port(core, "XGE1/0/1", trunk(10, 20, 30))
	port(core, "XGE1/0/2", trunk(10, 20))
	port(core, "XGE1/0/3", trunk(30))
	port(a1, "XGE1/0/49", trunk(10, 20))
	port(a2, "XGE1/0/49", trunk(10, 20))
	port(a3, "XGE1/0/49", trunk(10))
	port(a1, "GE1/0/1", access(10))
	port(a2, "GE1/0/1", access(10))
	port(a2, "GE1/0/2", access(20))
	port(a3, "GE1/0/1", access(30))
	link(core, "XGE1/0/1", a1, "XGE1/0/49", "0000-0000-0c01", "0000-0000-0a01")
	link(core, "XGE1/0/2", a2, "XGE1/0/49", "0000-0000-0c01", "0000-0000-0a02")
	link(core, "XGE1/0/3", a3, "XGE1/0/49", "0000-0000-0c01", "0000-0000-0a03")
	for n, pfx := range []string{"198.51.100.1/24", "198.51.101.1/24", "198.51.102.1/24"} {
		svi := core.Interfaces.Ensure([]string{"Vlan10", "Vlan20", "Vlan30"}[n])
		svi.Kind, svi.Oper = swtele.KindSVI, swtele.StateUp
		svi.Addresses = []swtele.IfAddr{{Prefix: netip.MustParsePrefix(pfx), Primary: true}}
	}
	hosts := []struct {
		ip, mac string
		vlan    int
		on      *swtele.Device
		port    string
		upl     string
	}{
		{"198.51.100.10", "aaaa-0000-0001", 10, a1, "GE1/0/1", "XGE1/0/1"},
		{"198.51.100.11", "aaaa-0000-0002", 10, a2, "GE1/0/1", "XGE1/0/2"},
		{"198.51.101.12", "aaaa-0000-0003", 20, a2, "GE1/0/2", "XGE1/0/2"},
		{"198.51.102.13", "aaaa-0000-0004", 30, a3, "GE1/0/1", "XGE1/0/3"},
	}
	for _, h := range hosts {
		m := mac(h.mac)
		core.L3.ARP = append(core.L3.ARP, swtele.ARPEntry{IP: netip.MustParseAddr(h.ip), MAC: m, VLAN: h.vlan, Interface: "Vlan10"})
		core.L2.MACs = append(core.L2.MACs, swtele.MACEntry{MAC: m, VLAN: h.vlan, Port: h.upl, Kind: swtele.MACDynamic})
		h.on.L2.MACs = append(h.on.L2.MACs, swtele.MACEntry{MAC: m, VLAN: h.vlan, Port: h.port, Kind: swtele.MACDynamic})
	}
	return ledger.New("t", time.Unix(0, 0), []*swtele.Device{core, a1, a2, a3})
}

func names(hops []path.Hop) []string {
	var out []string
	for _, h := range hops {
		out = append(out, h.Name+":"+h.In+">"+h.Out)
	}
	return out
}

func TestTrace(t *testing.T) {
	t.Parallel()
	l := fleet()
	g := topology.Build(l)
	tr := path.New(l, g, locate.New(l, g, locate.Options{}))

	same := tr.Trace("198.51.100.10", "198.51.100.11")
	want := []string{"a1:GE1/0/1>XGE1/0/49", "core:XGE1/0/1>XGE1/0/2", "a2:XGE1/0/49>GE1/0/1"}
	if same.Status != path.Found || len(same.Hops) != 3 || names(same.Hops)[0] != want[0] || names(same.Hops)[1] != want[1] || names(same.Hops)[2] != want[2] {
		t.Errorf("same VLAN %s %v %s", same.Status, names(same.Hops), same.Reason)
	}

	// VLAN 10 to 20: up to core, routed there, down to a2.
	routed := tr.Trace("198.51.100.10", "198.51.101.12")
	if routed.Status != path.Found || len(routed.Hops) != 3 || !routed.Hops[1].Routed || routed.Hops[2].VLAN != 20 {
		t.Errorf("routed %s %v %s", routed.Status, names(routed.Hops), routed.Reason)
	}

	// VLAN 30 is not allowed on a3's uplink.
	if p := tr.Trace("198.51.102.13", "198.51.100.10"); p.Status != path.Partial {
		t.Errorf("pruned VLAN %s %v", p.Status, names(p.Hops))
	}
	if p := tr.Trace("203.0.113.9", "198.51.100.10"); p.Status != path.Unlocated {
		t.Errorf("unknown end %s", p.Status)
	}
}
