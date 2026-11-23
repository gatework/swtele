package comware_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/failure"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/comware"
)

// out builds a recorded output: echo, body, prompt.
func out(cmd, body string) capture.Output {
	return capture.Output{Command: cmd, Raw: cmd + "\n" + strings.TrimPrefix(body, "\n") + "<sw1>", Prompt: "<sw1>",
		RecordedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

const iface = `
Ten-GigabitEthernet1/0/49
Current state: UP
Line protocol state: UP
IP packet frame type: Ethernet II, hardware address: 7c7a-3c7b-3212
Description: TO_core_TE1/2/0/12
Bandwidth: 10000000 kbps
Loopback is not set
Media type is optical fiber, Port hardware type is 10G_BASE_SR_SFP
10Gbps-speed mode, full-duplex mode
Link speed type is autonegotiation, link duplex type is autonegotiation
Maximum frame length: 10000
PVID: 1
Port link-type: Trunk
 VLAN Passing:   8, 10-21
                 3101-3299
 VLAN permitted: 2-998, 1000-4094
 Trunk port encapsulation: IEEE 802.1q
Last link flapping: 2 hours 3 minutes 4 seconds
Last clearing of counters: Never
Current system time:2026-11-23 17:33:34 beijing+08:00:00
Last time when physical state changed to up:2023-09-23 15:26:14 beijing+08:00:00
Last time when physical state changed to down:2023-09-23 15:26:14 beijing+08:00:00
 Last 300 seconds input: 13348 packets/sec 10052307 bytes/sec 1%
 Last 300 seconds output: 4821 packets/sec 4249304 bytes/sec 0%
 Input (total):  364983029931 packets, 114900662617987 bytes
	 360435603709 unicasts, 2422085357 broadcasts, 2125340865 multicasts, 0 pauses
 Input (normal):  364983029916 packets, - bytes
	 360435603709 unicasts, 2422085357 broadcasts, 2125340865 multicasts, 0 pauses
 Input:  7 input errors, 0 runts, 1 giants, 0 throttles
	 5 CRC, 0 frame, - overruns, 0 aborts
	 - ignored, - parity errors
 Output (total): 357914717204 packets, 419666819189283 bytes
	 357366972447 unicasts, 127723003 broadcasts, 420021754 multicasts, 0 pauses
 Output: 0 output errors, - underruns, - buffer failures
	 0 aborts, 0 deferred, 0 collisions, 0 late collisions
	 0 lost carrier, - no carrier

Vlan-interface8
Current state: UP
Line protocol state: UP
Description: MGMT
Maximum transmission unit: 1500
Internet address: 192.0.2.32/24 (primary)
IP packet frame type: Ethernet II, hardware address: 7c7a-3c7b-31b9
`

const diag = `
Ten-GigabitEthernet1/0/49 transceiver diagnostic information:
  Current diagnostic parameters:
    Temp.(C)   Voltage(V)  Bias(mA)  RX power(dBm)  TX power(dBm)
    39         3.36        6.66      -3.49          -1.88
  Alarm thresholds:
          Temp.(C)   Voltage(V)  Bias(mA)  RX power(dBm)  TX power(dBm)
    High  73         3.80        9.90      1.00           1.00
    Low   -3         2.81        1.00      -13.10         -10.30
FortyGigE1/0/53 transceiver diagnostic information:
  Current diagnostic parameters:
[module]  Temp.(C)   Voltage(V)
          0          0.00
[channel] Bias(mA)  RX power(dBm)  TX power(dBm)
    1     0.00      -40.00         -40.00
    2     0.00      -40.00         -40.00
  Alarm thresholds:
          Temp.(C)   Voltage(V)  Bias(mA)  RX power(dBm)  TX power(dBm)
    High  N/A        N/A         N/A       N/A            N/A
    Low   N/A        N/A         N/A       N/A            N/A
GigabitEthernet1/0/1 transceiver diagnostic information:
The transceiver is absent.
`

const lag = `
Loadsharing Type: Shar -- Loadsharing, NonS -- Non-Loadsharing
Port Status: S -- Selected, U -- Unselected, I -- Individual
Port: A -- Auto port, M -- Management port, R -- Reference port
Flags:  A -- LACP_Activity, B -- LACP_Timeout, C -- Aggregation,
        D -- Synchronization, E -- Collecting, F -- Distributing,
        G -- Defaulted, H -- Expired

Aggregate Interface: Bridge-Aggregation100
Creation Mode: Manual
Aggregation Mode: Dynamic
Loadsharing Type: Shar
Management VLANs: None
System ID: 0x8000, 7c7a-3c7b-31b8
Local:
  Port                Status   Priority Index    Oper-Key               Flag
  XGE1/0/49           S        32768    1        1                      {ACDEF}
  XGE2/0/49           U        32768    54       1                      {ACG}
Remote:
  Actor               Priority Index    Oper-Key SystemID               Flag
  XGE1/0/49(R)        32768    29       14       0x8000, 28e4-24bc-f000 {ACDEF}
  XGE2/0/49           32768    30       14       0x8000, 28e4-24bc-f000 {EF}
`

const lldpVerbose = `
LLDP neighbor-information of port 3[GigabitEthernet1/0/3]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Chassis type        : MAC address
 Chassis ID          : 2cda-3f4b-03b5
 Port ID             : 2cda-3f4b-03b4
 System name         : pc1
 LLDP neighbor index : 2
 Chassis type        : Locally assigned
 Chassis ID          : phone-7
 Port ID             : 30c5-99b7-19a3
 System capabilities enabled   : Bridge,
                                 Telephone
 Port VLAN ID(PVID)  : 10
LLDP neighbor-information of port 49[Ten-GigabitEthernet1/0/49]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Chassis ID          : 28e4-24bc-f000
 Port ID             : Ten-GigabitEthernet1/2/0/12
 System name         : core1
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070
   H3C S10508X
 Management address                : 198.51.100.1
`

func TestDecode(t *testing.T) {
	t.Parallel()
	c := capture.Capture{Host: netip.MustParseAddr("192.0.2.32"), Prompt: "<sw1>", Outputs: []capture.Output{
		out("display interface", iface),
		out("display transceiver diagnosis interface", diag),
		out("display link-aggregation verbose", lag),
		out("display lldp neighbor-information verbose", lldpVerbose),
		out("display cpu-usage", "Slot 1 CPU 0 CPU usage:\n      40% in last 5 seconds\n      14% in last 1 minute\n      12% in last 5 minutes\n"),
		out("display arp all", "  Type: S-Static   D-Dynamic   O-Openflow   R-Rule   M-Multiport  I-Invalid\nIP address      MAC address    VLAN/VSI name Interface                Aging Type\n192.0.2.1       d478-9b19-f378 8             BAGG100                  959   D\n"),
		out("display mac-address", "MAC Address      VLAN ID    State            Port/Nickname            Aging\n2cda-3f4b-03b4   10         Learned          GE1/0/3                  Y\n"),
		out("display irf", "MemberID    Role    Priority  CPU-Mac         Description\n *+1        Master  1         f010-90db-7402  ---\n   2        Standby 1         f010-90db-7403  ---\n The bridge MAC of the IRF is: 7c7a-3c7b-31b8\n"),
		out("display mad verbose", "Multi-active recovery state: No\nMAD ARP disabled.\nMAD ND disabled.\nMAD LACP disabled.\nMAD BFD disabled.\n"),
		{Command: "display alarm", Raw: "display alarm\n              ^\n % Unrecognized command found at '^' position.\n<sw1>", Failure: failure.CodeRejected},
	}}
	dev, err := comware.Decode(t.Context(), device.Device{Mgmt: c.Host}, c, comware.Options{Location: time.FixedZone("UTC+8", 8*3600)})
	if err != nil {
		t.Fatal(err)
	}
	for _, dim := range []evidence.Dimension{swtele.DimInterfaces, swtele.DimOptics, swtele.DimAggregates, swtele.DimNeighbors, swtele.DimCPU, swtele.DimARP, swtele.DimMAC, swtele.DimStack, swtele.DimMAD} {
		if s := dev.Coverage.Status(dim); s != evidence.StatusComplete {
			t.Errorf("%s = %s, issues %v", dim, s, dev.Issues)
		}
	}

	i := dev.Interfaces.Get("XGE1/0/49")
	if i == nil {
		t.Fatal("XGE1/0/49 missing")
	}
	switch {
	case !i.Up() || i.Speed.V != 1e10 || i.Duplex != swtele.DuplexFull || i.MTU.V != 10000:
		t.Errorf("state %+v", i)
	case i.Media != "10G_BASE_SR_SFP" || !i.Fiber.V:
		t.Errorf("media %q %v", i.Media, i.Fiber)
	case i.Switching.Mode != swtele.ModeTrunk || i.Switching.Allowed.Compact() != "2-998,1000-4094":
		t.Errorf("switching %+v %s", i.Switching, i.Switching.Allowed)
	case i.Counters.CRC.V != 5 || i.Counters.In.Errors.V != 7 || i.Counters.Giants.V != 1 || i.Counters.Overruns.OK:
		t.Errorf("counters %+v", i.Counters)
	case i.Rates.InBps.V != 10052307*8 || i.Rates.Window != 300*time.Second:
		t.Errorf("rates %+v", i.Rates)
	case i.Flap.Since.V != 2*time.Hour+3*time.Minute+4*time.Second || !i.Flap.LastUp.V.Equal(time.Date(2023, 9, 23, 7, 26, 14, 0, time.UTC)):
		t.Errorf("flap %+v", i.Flap)
	case i.Aggregate != "Bridge-Aggregation100":
		t.Errorf("aggregate %q", i.Aggregate)
	}
	x := i.Optics
	if x == nil || x.DOM != swtele.DOMSupported || x.Lanes[0].RxPower.Value.V != -3.49 || x.Lanes[0].RxPower.Th.LowAlarm.V != -13.1 || x.Temp.Th.HighAlarm.V != 73 {
		t.Errorf("optics %+v", x)
	}
	if q := dev.Interfaces.Get("FortyGigE1/0/53").Optics; q.DOM != swtele.DOMUnsupported || len(q.Lanes) != 0 {
		t.Errorf("placeholder DOM kept: %+v", q)
	}
	if a := dev.Interfaces.Get("GE1/0/1").Optics; a.Present {
		t.Error("absent transceiver present")
	}
	if v := dev.Interfaces.Get("Vlan8"); v == nil || v.Addresses[0].Prefix.String() != "192.0.2.32/24" || v.Kind != swtele.KindSVI {
		t.Errorf("svi %+v", v)
	}

	a := dev.Aggregate("BAGG100")
	if a == nil || a.Mode != swtele.AggLACP || len(a.Members) != 2 || !a.Members[0].Reference || a.Members[1].Selected || a.Members[1].PartnerFlags != "EF" {
		t.Errorf("aggregate %+v", a)
	}

	if len(dev.Neighbors) != 3 {
		t.Fatalf("neighbors %d: %+v", len(dev.Neighbors), dev.Neighbors)
	}
	phone, core := dev.Neighbors[1], dev.Neighbors[2]
	if phone.ChassisID != "phone-7" || phone.PVID.V != 10 || len(phone.Capabilities) != 2 {
		t.Errorf("phone %+v", phone)
	}
	if core.System != "core1" || core.ChassisMAC.String() != "28:e4:24:bc:f0:00" || !strings.Contains(core.SysDesc, "S10508X") || core.MgmtAddr.String() != "198.51.100.1" {
		t.Errorf("core %+v", core)
	}

	if cpu := dev.System.CPU[0]; cpu.Unit.Slot != 1 || cpu.Now.V != 40 || cpu.Min5.V != 12 {
		t.Errorf("cpu %+v", cpu)
	}
	if e := dev.L3.ARP[0]; e.Interface != "Bridge-Aggregation100" || e.VLAN != 8 || e.Age.V != 959*time.Minute {
		t.Errorf("arp %+v", e)
	}
	if e := dev.L2.MACs[0]; e.Port != "GigabitEthernet1/0/3" || e.Kind != swtele.MACDynamic || e.VLAN != 10 {
		t.Errorf("mac %+v", e)
	}
	if s := dev.Stack; s == nil || len(s.Members) != 2 || !s.Members[0].Self || s.MAD.Enabled() || s.MAC.String() != "7c:7a:3c:7b:31:b8" {
		t.Errorf("stack %+v", s)
	}
}

func TestRejected(t *testing.T) {
	t.Parallel()
	c := capture.Capture{Outputs: []capture.Output{
		out("display link-flap protection", "                ^\n % Unrecognized command found at '^' position.\n"),
		out("display ospf peer", "OSPF is not configured.\n"),
	}}
	dev, err := comware.Decode(t.Context(), device.Device{}, c, comware.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s := dev.Coverage.Status(swtele.DimFlap); s != evidence.StatusFailed {
		t.Errorf("rejected flap = %s", s)
	}
	if s := dev.Coverage.Status(swtele.DimOSPF); s != evidence.StatusComplete || len(dev.L3.Peers) != 0 {
		t.Errorf("unconfigured ospf = %s", s)
	}
	if s := dev.Coverage.Status(swtele.DimBGP); s != evidence.StatusNotRequested {
		t.Errorf("absent bgp = %s", s)
	}
}

func TestUnparsedDegrades(t *testing.T) {
	t.Parallel()
	c := capture.Capture{Outputs: []capture.Output{out("display cpu-usage", "Slot 1 CPU 0 CPU usage:\n      40% in last 5 seconds\nsomething new\n")}}
	dev, err := comware.Decode(t.Context(), device.Device{}, c, comware.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s := dev.Coverage.Status(swtele.DimCPU); s != evidence.StatusPartial {
		t.Errorf("cpu = %s", s)
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{iface, diag, lag, lldpVerbose} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		c := capture.Capture{Outputs: []capture.Output{}}
		for _, cmd := range comware.Commands() {
			c.Outputs = append(c.Outputs, out(cmd, body))
		}
		if _, err := comware.Decode(t.Context(), device.Device{}, c, comware.Options{}); err != nil {
			t.Fatal(err)
		}
	})
}
