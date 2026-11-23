package topology_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/topology"
)

func mac(s string) swtele.MAC {
	m, _ := swtele.ParseMAC(s)
	return m
}

// A neighbor advertised twice on one port, once by port name and once by
// port MAC, is one confirmed cable.
func TestDuplicateAdvertisements(t *testing.T) {
	t.Parallel()
	leaf := swtele.New(device.Device{Name: "leaf", Mgmt: netip.MustParseAddr("192.0.2.1")}, time.Unix(0, 0))
	mg := swtele.New(device.Device{Name: "mg", Mgmt: netip.MustParseAddr("192.0.2.2")}, time.Unix(0, 0))
	mg.Stack = &swtele.Stack{Kind: swtele.StackIRF, MAC: mac("0000-0000-0002")}
	ge := mg.Interfaces.Ensure("GigabitEthernet1/0/1")
	ge.Kind, ge.MAC = swtele.KindPhysical, mac("0000-0000-0a01")
	leaf.Neighbors = []swtele.Neighbor{
		{LocalPort: "mgmt0", System: "mg", Port: "GigabitEthernet1/0/1", Protocol: "lldp"},
		{LocalPort: "mgmt0", System: "mg", Port: "0000.0000.0a01", Protocol: "cdp"},
	}
	mg.Neighbors = []swtele.Neighbor{{LocalPort: "GigabitEthernet1/0/1", System: "leaf", Port: "mgmt0", Protocol: "lldp"}}
	g := topology.Build(ledger.New("t", time.Unix(0, 0), []*swtele.Device{leaf, mg}))
	if len(g.Links) != 1 || g.Links[0].State != topology.Confirmed {
		t.Fatalf("links %+v", g.Links)
	}
}

func TestHostAdapter(t *testing.T) {
	t.Parallel()
	d := swtele.New(device.Device{Name: "leaf", Mgmt: netip.MustParseAddr("192.0.2.1")}, time.Unix(0, 0))
	i := d.Interfaces.Ensure("Ethernet1/1")
	i.Kind, i.Oper = swtele.KindPhysical, swtele.StateUp
	d.Neighbors = []swtele.Neighbor{{LocalPort: "Ethernet1/1", Platform: "Broadcom P210p NetXtreme-E Dual-port 10Gb Ethernet PCIe Adapter", Capabilities: []string{"Bridge"}}}
	d.Neighbors = append(d.Neighbors, swtele.Neighbor{LocalPort: "Ethernet1/2", Protocol: "lldp", System: "host", Platform: "x", Capabilities: []string{"S"}})
	i = d.Interfaces.Ensure("Ethernet1/2")
	i.Kind, i.Oper = swtele.KindPhysical, swtele.StateUp
	g := topology.Build(ledger.New("t", time.Unix(0, 0), []*swtele.Device{d}))
	if r := g.Role(d, "Ethernet1/2"); r != topology.RoleEdge {
		t.Errorf("station port role %s, want edge", r)
	}
	if r := g.Role(d, "Ethernet1/1"); r != topology.RoleEdge {
		t.Errorf("server NIC port role %s, want edge", r)
	}
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	d := swtele.New(device.Device{Name: "core", Mgmt: netip.MustParseAddr("192.0.2.1")}, time.Unix(0, 0))
	for _, p := range []string{"XGE1/0/1", "XGE1/0/2", "GE1/0/3"} {
		i := d.Interfaces.Ensure(p)
		i.Kind, i.Oper = swtele.KindPhysical, swtele.StateUp
	}
	d.Neighbors = []swtele.Neighbor{
		{LocalPort: "XGE1/0/1", Protocol: "lldp", System: "edge-9", Capabilities: []string{"Bridge", "Router"}, MgmtAddr: netip.MustParseAddr("192.0.2.9"),
			SysDesc: "H3C Comware Platform Software"},
		{LocalPort: "XGE1/0/2", Protocol: "lldp", System: "EDGE-9", Capabilities: []string{"Bridge"}},
		{LocalPort: "GE1/0/3", Protocol: "lldp", System: "pc", Capabilities: []string{"S"}},
		{LocalPort: "GE1/0/3", Protocol: "lldp", System: "SIP-T31P", Capabilities: []string{"Bridge", "Telephone"}},
	}
	l := ledger.New("t", time.Unix(0, 0), []*swtele.Device{d})
	got := topology.Build(l).Discover(l)
	if len(got) != 1 || got[0].Name != "edge-9" || got[0].Platform != "h3c" || len(got[0].SeenBy) != 2 || got[0].Mgmt.String() != "192.0.2.9" {
		t.Errorf("discover %+v", got)
	}
}
