package delta_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/delta"
	"github.com/gatework/swtele/ledger"
)

func dev(mgmt string, up bool, serial string, nbr bool) *swtele.Device {
	d := swtele.New(device.Device{Name: mgmt, Mgmt: netip.MustParseAddr(mgmt)}, time.Unix(0, 0))
	for _, dim := range []evidence.Dimension{swtele.DimInterfaces, swtele.DimOpticsInv, swtele.DimNeighbors} {
		d.Observe(dim, evidence.StatusComplete)
	}
	i := d.Interfaces.Ensure("GigabitEthernet1/0/1")
	i.Kind, i.Oper = swtele.KindPhysical, swtele.StateDown
	if up {
		i.Oper = swtele.StateUp
	}
	i.Optics = &swtele.Transceiver{Present: true, Inventory: swtele.XcvrInventory{Serial: serial}}
	if nbr {
		d.Neighbors = []swtele.Neighbor{{LocalPort: "GigabitEthernet1/0/1", System: "core", Port: "Te1/0/1"}}
	}
	return d
}

func TestCompare(t *testing.T) {
	t.Parallel()
	prev := ledger.New("a", time.Unix(0, 0), []*swtele.Device{dev("192.0.2.1", true, "SN1", true), dev("192.0.2.2", true, "X", false)})
	cur := ledger.New("b", time.Unix(0, 0), []*swtele.Device{dev("192.0.2.1", false, "SN2", false), dev("192.0.2.3", true, "Y", false)})
	got := map[delta.Kind]int{}
	for _, c := range delta.Compare(prev, cur) {
		got[c.Kind]++
	}
	want := map[delta.Kind]int{delta.DeviceAdded: 1, delta.DeviceRemoved: 1, delta.PortState: 1, delta.OpticsSwapped: 1, delta.Neighbor: 1}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], n, got)
		}
	}
	// A dimension that failed in one batch is not compared.
	broken := dev("192.0.2.1", true, "SN1", false)
	broken.Coverage = broken.Coverage.With(swtele.DimNeighbors, evidence.StatusFailed)
	for _, c := range delta.Device(dev("192.0.2.1", true, "SN1", true), broken) {
		if c.Kind == delta.Neighbor {
			t.Errorf("neighbor change from a failed dimension: %+v", c)
		}
	}
}
