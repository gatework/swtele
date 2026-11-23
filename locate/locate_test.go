package locate_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/locate"
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

func port(d *swtele.Device, name string, up bool) *swtele.Interface {
	i := d.Interfaces.Ensure(name)
	i.Kind = swtele.KindPhysical
	if up {
		i.Oper = swtele.StateUp
	} else {
		i.Oper = swtele.StateDown
	}
	return i
}

// fleet: core (gateway) -- Te1/0/1 ... Te1/0/49 -- access; access has
// a PC on GE1/0/5 and an AP on GE1/0/7 with two wireless clients.
func fleet() *ledger.Ledger {
	core := sw("core", "192.0.2.1", "0000-0000-0c01")
	access := sw("access", "192.0.2.2", "0000-0000-0a01")
	port(core, "Ten-GigabitEthernet1/0/1", true)
	for n, pfx := range []string{"192.0.2.1/26", "198.51.100.1/24"} {
		svi := core.Interfaces.Ensure("Vlan-interface" + []string{"10", "20"}[n])
		svi.Kind, svi.Oper = swtele.KindSVI, swtele.StateUp
		svi.Addresses = []swtele.IfAddr{{Prefix: netip.MustParsePrefix(pfx), Primary: true}}
	}
	port(access, "Ten-GigabitEthernet1/0/49", true)
	port(access, "GigabitEthernet1/0/5", true)
	port(access, "GigabitEthernet1/0/7", true)
	port(access, "GigabitEthernet1/0/9", false)
	core.Neighbors = []swtele.Neighbor{{LocalPort: "Ten-GigabitEthernet1/0/1", System: "access", Port: "Ten-GigabitEthernet1/0/49", ChassisMAC: mac("0000-0000-0a01")}}
	access.Neighbors = []swtele.Neighbor{
		{LocalPort: "Ten-GigabitEthernet1/0/49", System: "core", Port: "Ten-GigabitEthernet1/0/1", ChassisMAC: mac("0000-0000-0c01")},
		{LocalPort: "GigabitEthernet1/0/7", System: "ap-3f", Capabilities: []string{"Bridge", "WLAN Access Point"}},
	}
	pc, w1, w2 := mac("aaaa-0000-0001"), mac("aaaa-0000-0002"), mac("aaaa-0000-0003")
	core.L3.ARP = []swtele.ARPEntry{
		{IP: netip.MustParseAddr("192.0.2.10"), MAC: pc, VLAN: 10, Interface: "Vlan-interface10"},
		{IP: netip.MustParseAddr("192.0.2.11"), MAC: w1, VLAN: 10, Interface: "Vlan-interface10"},
	}
	core.L2.MACs = []swtele.MACEntry{
		{MAC: pc, VLAN: 10, Port: "Ten-GigabitEthernet1/0/1", Kind: swtele.MACDynamic},
		{MAC: w1, VLAN: 10, Port: "Ten-GigabitEthernet1/0/1", Kind: swtele.MACDynamic},
	}
	access.L2.MACs = []swtele.MACEntry{
		{MAC: pc, VLAN: 10, Port: "GE1/0/5", Kind: swtele.MACDynamic},
		{MAC: w1, VLAN: 10, Port: "GigabitEthernet1/0/7", Kind: swtele.MACDynamic},
		{MAC: w2, VLAN: 10, Port: "GigabitEthernet1/0/7", Kind: swtele.MACDynamic},
	}
	return ledger.New("t", time.Unix(0, 0), []*swtele.Device{core, access})
}

func TestLocate(t *testing.T) {
	t.Parallel()
	l := fleet()
	g := topology.Build(l)
	if len(g.Links) != 2 || g.Links[0].State != topology.Confirmed {
		t.Fatalf("links %+v", g.Links)
	}
	x := locate.New(l, g, locate.Options{})

	pc := x.Locate("192.0.2.10")
	if pc.Confidence != locate.Exact || len(pc.Access) != 1 || pc.Access[0].Device != "access" || pc.Access[0].Interface != "GE1/0/5" {
		t.Errorf("pc %+v", pc)
	}
	if len(pc.Gateways) != 1 || pc.Gateways[0].Device != "core" || pc.Gateways[0].Interface != "Vlan-interface10" || len(pc.Path) != 1 || pc.Path[0].Device != "core" {
		t.Errorf("pc gateway/path %+v %+v", pc.Gateways, pc.Path)
	}

	// A wireless client is learned on the port facing the AP, an
	// unmanaged bridge: located behind it.
	w := x.Locate("192.0.2.11")
	if w.Confidence != locate.Shared || w.Access[0].Interface != "GigabitEthernet1/0/7" || w.Access[0].Neighbor != "ap-3f" {
		t.Errorf("wireless %+v", w)
	}

	// Located by MAC alone, without ARP.
	if m := x.Locate("aaaa.0000.0003"); m.Confidence != locate.Shared || m.IP.IsValid() {
		t.Errorf("by mac %+v", m)
	}
	if u := x.Locate("198.51.100.99"); u.Confidence != locate.Unknown {
		t.Errorf("unknown %+v", u)
	}
	if r := g.Role(l.Device("access"), "GigabitEthernet1/0/9"); r != topology.RoleUnused {
		t.Errorf("down port role %s", r)
	}
}
