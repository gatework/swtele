package comware_test

import (
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/comware"
)

const running = `dis cur
#
 version 7.1.070, Release 6530P02
#
 sysname sw1
#
 irf member 1 priority 32
#
 stp global enable
 stp instance 0 priority 8192
#
vlan 10
 name users
#
interface Bridge-Aggregation100
 description uplink
 port link-type trunk
 undo port trunk permit vlan 1
 port trunk permit vlan 2 to 998 1000 to 4094
 link-aggregation mode dynamic
#
interface GigabitEthernet1/0/1
 port link-mode bridge
 port access vlan 10
 stp edged-port
#
interface GigabitEthernet1/0/2
 port link-mode bridge
 shutdown
 port link-type hybrid
 port hybrid vlan 20 30 untagged
 port hybrid pvid vlan 20
#
interface Ten-GigabitEthernet1/0/49
 port link-mode bridge
 port link-type trunk
 port trunk permit vlan all
 port link-aggregation group 100
#
interface Vlan-interface10
 ip address 192.0.2.1 255.255.255.0
 ip binding vpn-instance office
#
 ip route-static 0.0.0.0 0 192.0.2.254
#
return
<sw1>`

func TestOverlay(t *testing.T) {
	t.Parallel()
	dev := swtele.New(device.Device{}, time.Unix(0, 0))
	if err := comware.Overlay(t.Context(), dev, running, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	c := dev.Config
	switch {
	case c.Hostname != "sw1" || c.IRFPriority[1] != 32 || !c.STPEnabled.V || c.STPPriority.V != 8192 || c.BPDUProtection.OK:
		t.Errorf("globals %+v", c)
	case len(c.VLANs) != 1 || c.VLANs[0].Name != "users":
		t.Errorf("vlans %+v", c.VLANs)
	case len(c.Static) != 1 || c.Static[0].Prefix.String() != "0.0.0.0/0" || c.Static[0].NextHops[0] != "192.0.2.254":
		t.Errorf("static %+v", c.Static)
	}
	if p := c.Port("BAGG100"); p.Mode != swtele.ModeTrunk || p.Allowed.Compact() != "2-998,1000-4094" || !p.LACP.V {
		t.Errorf("BAGG100 %+v %s", p, p.Allowed)
	}
	if p := c.Port("GE1/0/1"); p.Mode != swtele.ModeAccess || p.PVID.V != 10 || !p.Edge.V || p.Shutdown.V {
		t.Errorf("GE1/0/1 %+v", p)
	}
	if p := c.Port("GE1/0/2"); !p.Shutdown.V || p.PVID.V != 20 || p.Allowed.Compact() != "1,20,30" {
		t.Errorf("GE1/0/2 %+v %s", p, p.Allowed)
	}
	if p := c.Port("XGE1/0/49"); p.Aggregate != "Bridge-Aggregation100" || p.Allowed.Compact() != "1-4094" {
		t.Errorf("XGE1/0/49 %+v", p)
	}
	if p := c.Port("Vlan10"); p.VRF != "office" || p.Addresses[0].String() != "192.0.2.1/24" {
		t.Errorf("Vlan10 %+v", p)
	}
}
