package nxos_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/nxos"
)

func out(cmd, body string) capture.Output {
	return capture.Output{Command: cmd, Raw: cmd + "\n" + strings.TrimPrefix(body, "\n") + "leaf1#", Prompt: "leaf1#"}
}

const iface = `
Ethernet1/1 is up
admin state is up, Dedicated Interface
  Belongs to Po101
  Hardware: 100/1000/10000/25000 Ethernet, address: c446.06c9.12fc (bia c446.06c9.12fc)
  MTU 9216 bytes, BW 25000000 Kbit , DLY 10 usec
  reliability 255/255, txload 1/255, rxload 2/255
  Encapsulation ARPA, medium is broadcast
  Port mode is trunk
  full-duplex, 25 Gb/s, media type is 25G
  Last link flapped 13week(s) 1day(s)
  17 interface resets
  Load-Interval #1: 30 seconds
    30 seconds input rate 223071760 bits/sec, 19890 packets/sec
    30 seconds output rate 10689952 bits/sec, 2228 packets/sec
  Load-Interval #2: 5 minute (300 seconds)
    300 seconds input rate 118128840 bits/sec, 11375 packets/sec
    300 seconds output rate 31895880 bits/sec, 3835 packets/sec
  RX
    211367285916 unicast packets  954848 multicast packets  20732255 broadcast packets
    211388973019 input packets  223303668456425 bytes
    0 runts  2 giants  9 CRC  0 no buffer
    11 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 input with dribble  4 input discard
    0 Rx pause
  TX
    158111904662 output packets  194866095193746 bytes
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  3 output discard

Ethernet1/14 is down (XCVR not inserted)
admin state is up, Dedicated Interface

Vlan2 is up, line protocol is up, autostate enabled
  Hardware is EtherSVI, address is  c446.06c9.12fb
  Description: SOP
  Internet Address is 192.0.2.254/24
  MTU 9216 bytes, BW 1000000 Kbit, DLY 10 usec,
`

const xcvr = `
Ethernet1/1
    transceiver is present
    type is SFP-H25GB-SR
    name is CISCO-ACCELINK
    part number is RTXM330-550-C99
    serial number is SN0000TEST1
    cisco product id is SFP-25G-SR-S

           SFP Detail Diagnostics Information (internal calibration)
  ----------------------------------------------------------------------------
                Current              Alarms                  Warnings
                Measurement     High        Low         High          Low
  ----------------------------------------------------------------------------
  Temperature   28.12 C        75.00 C     -5.00 C     70.00 C        0.00 C
  Voltage        3.26 V         3.63 V      2.97 V      3.46 V        3.13 V
  Current        7.40 mA       15.00 mA     3.00 mA    15.00 mA       4.00 mA
  Tx Power      -0.40 dBm       5.39 dBm  -12.44 dBm    2.39 dBm     -8.41 dBm
  Rx Power     -11.60 dBm -     5.39 dBm  -14.31 dBm    2.39 dBm    -10.31 dBm
  Transmit Fault Count = 0
  ----------------------------------------------------------------------------
  Note: ++  high-alarm; +  high-warning; --  low-alarm; -  low-warning

Ethernet1/14
    transceiver is not present
`

const pc = `
Flags:  D - Down        P - Up in port-channel (members)
        U - Up (port-channel)
--------------------------------------------------------------------------------
Group Port-       Type     Protocol  Member Ports
      Channel
--------------------------------------------------------------------------------
101   Po101(SU)   Eth      LACP      Eth1/1(P)    Eth1/2(D)
                                     Eth1/3(s)
`

const bgp = `
BGP summary information for VRF default, address family IPv4 Unicast
BGP router identifier 192.0.2.9, local AS number 65111
BGP table version is 1053, IPv4 Unicast config peers 2, capable peers 2

Neighbor        V    AS    MsgRcvd    MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.21      4 65111     582994     416932     1053    0    0    43w0d 78
192.0.2.22      4 65111          0          0        0    0    0 00:01:02 Idle
`

func TestDecode(t *testing.T) {
	t.Parallel()
	c := capture.Capture{Prompt: "leaf1#", Outputs: []capture.Output{
		out("show interface", iface), out("show interface transceiver details", xcvr),
		out("show port-channel summary", pc), out("show bgp vrf all all summary", bgp),
		out("show ip arp vrf all", "Address         Age       MAC Address     Interface       Flags\n192.0.2.1    0.462022  5254.b1dd.ba99  Vlan2        +\n192.0.2.3    00:00:10  INCOMPLETE  Vlan2\n"),
	}}
	dev, err := nxos.Decode(t.Context(), device.Device{}, c, nxos.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, dim := range []evidence.Dimension{swtele.DimInterfaces, swtele.DimOptics, swtele.DimAggregates, swtele.DimBGP, swtele.DimARP} {
		if s := dev.Coverage.Status(dim); s != evidence.StatusComplete {
			t.Errorf("%s = %s %v", dim, s, dev.Issues)
		}
	}
	i := dev.Interfaces.Get("Eth1/1")
	switch {
	case i == nil:
		t.Fatal("Eth1/1 missing")
	case !i.Up() || i.Speed.V != 25e9 || i.Aggregate != "port-channel101" || i.Switching.Mode != swtele.ModeTrunk:
		t.Errorf("state %+v", i)
	case i.Counters.CRC.V != 9 || i.Counters.Giants.V != 2 || i.Counters.In.Errors.V != 11 || i.Counters.In.Discards.V != 4 || i.Counters.Out.Discards.V != 3 || i.Counters.Resets.V != 17:
		t.Errorf("counters %+v", i.Counters)
	case i.Rates.Window != 300*time.Second || i.Rates.InBps.V != 118128840:
		t.Errorf("rates %+v", i.Rates)
	case i.Flap.Since.V != 92*24*time.Hour:
		t.Errorf("flap %v", i.Flap.Since)
	}
	rx := i.Optics.Lanes[0].RxPower
	if !i.Optics.Present || rx.Value.V != -11.6 || rx.Th.LowWarn.V != -10.31 || rx.Level() != swtele.LevelWarn || i.Optics.Inventory.ProductID != "SFP-25G-SR-S" {
		t.Errorf("optics %+v", i.Optics)
	}
	if d := dev.Interfaces.Get("Ethernet1/14"); d.DownCause != swtele.CauseNoXcvr || d.Optics.Present {
		t.Errorf("Eth1/14 %+v", d)
	}
	if a := dev.Aggregate("Po101"); a == nil || len(a.Members) != 3 || !a.Members[0].Selected || a.Members[1].Selected || a.Mode != swtele.AggLACP {
		t.Errorf("port-channel %+v", a)
	}
	if len(dev.L3.Peers) != 2 || !dev.L3.Peers[0].Established || dev.L3.Peers[0].Prefixes.V != 78 || dev.L3.Peers[1].Established {
		t.Errorf("bgp %+v", dev.L3.Peers)
	}
	if a := dev.L3.ARP; len(a) != 2 || a[0].VLAN != 2 || !a[1].Incomplete {
		t.Errorf("arp %+v", a)
	}
}
