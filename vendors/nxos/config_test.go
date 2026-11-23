package nxos_test

import (
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/nxos"
)

const running = `show running-config
version 10.4(3) Bios:version 01.09
hostname leaf1
feature lldp
spanning-tree port type edge bpduguard default
vlan 1,10-11
vlan 10
  name users
vrf context tenant
  ip route 0.0.0.0/0 192.0.2.254
vpc domain 150

interface port-channel101
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10-20
  switchport trunk allowed vlan add 30
  vpc 101

interface Ethernet1/1
  switchport
  switchport mode trunk
  channel-group 101 mode active
  no shutdown

interface Ethernet1/2
  switchport access vlan 10
  spanning-tree port type edge

interface Vlan10
  vrf member tenant
  ip address 192.0.2.1/24
leaf1#`

func TestOverlay(t *testing.T) {
	t.Parallel()
	dev := swtele.New(device.Device{}, time.Unix(0, 0))
	if err := nxos.Overlay(t.Context(), dev, running, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	c := dev.Config
	if c.Hostname != "leaf1" || !c.LLDP.V || !c.BPDUProtection.V || c.VPCDomain != "150" || len(c.VLANs) != 4 {
		t.Errorf("globals %+v", c)
	}
	if len(c.Static) != 1 || c.Static[0].VRF != "tenant" {
		t.Errorf("static %+v", c.Static)
	}
	if p := c.Port("Po101"); p.Mode != swtele.ModeTrunk || p.Allowed.Compact() != "10-20,30" || p.VPC != "101" {
		t.Errorf("Po101 %+v %s", p, p.Allowed)
	}
	if p := c.Port("Eth1/1"); p.Aggregate != "port-channel101" || !p.LACP.V || p.Shutdown.V || !p.Shutdown.OK {
		t.Errorf("Eth1/1 %+v", p)
	}
	if p := c.Port("Eth1/2"); p.Shutdown.OK || !p.Edge.V || p.PVID.V != 10 {
		t.Errorf("Eth1/2 %+v", p)
	}
	if p := c.Port("Vlan10"); p.VRF != "tenant" || p.Addresses[0].String() != "192.0.2.1/24" {
		t.Errorf("Vlan10 %+v", p)
	}
}
