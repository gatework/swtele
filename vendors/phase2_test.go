package vendors_test

import (
	"strings"
	"testing"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors"
)

func out(prompt, cmd, body string) capture.Output {
	return capture.Output{Command: cmd, Raw: cmd + "\n" + strings.TrimPrefix(body, "\n") + prompt, Prompt: prompt}
}

func decode(t *testing.T, platform, prompt string, outs ...capture.Output) *swtele.Device {
	t.Helper()
	d, err := vendors.Decode(t.Context(), device.Device{Platform: platform}, capture.Capture{Prompt: prompt, Outputs: outs}, vendors.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, dim := range d.Coverage.Dimensions() {
		if s := d.Coverage.Status(dim); s != evidence.StatusComplete {
			t.Errorf("%s %s = %s %v", platform, dim, s, d.Issues)
		}
	}
	return d
}

func TestHillstone(t *testing.T) {
	t.Parallel()
	p := "fw1(M)#"
	d := decode(t, "hillstone", p,
		out(p, "show interface", "\nH:physical state;A:admin state;L:link state;P:protocol state;U:up;D:down;K:ha keep up;C:lacp down\n====\nInterface name       IPv4 address/mask    Zone name       H A L P MAC address     Description\n----\nethernet0/1          192.0.2.1/24         trust           U U U U 7473.e201.15df  uplink\n"),
		out(p, "show transceiver", "Transceiver status information is shown as below:\n================       ethernet0/1       =====================\nSFP+/XFP information:\t\tVENDOR / 230101\nSerial Number: \t\t\tSN0000TEST2\nModule temperature: \t\t21.80\t C\nModule temperature normal range:[0.00 , 70.00]\nTx supply voltage: \t\t3.30\t V\nTx bias current: \t\t6.24\tmA\nRx optical power:\t\t-12.93\tdBm\nRx optical power normal range:[-9.90 , -1.00]\n===============================================================\n"),
		out(p, "show cpu", "Average cpu utilization : 1.3%\nCurrent cpu utilization : 4.1%\nLast 1 minute : 1.6%\nLast 5 minutes : 1.6%\nLast 15 minutes : 1.6%\n"),
	)
	i := d.Interfaces.Get("ethernet0/1")
	if i == nil || !i.Up() || i.Desc != "uplink" || i.Addresses[0].Prefix.String() != "192.0.2.1/24" {
		t.Fatalf("interface %+v", i)
	}
	if rx := i.Optics.Lanes[0].RxPower; rx.Value.V != -12.93 || rx.Th.LowAlarm.V != -9.9 || rx.Level() != swtele.LevelAlarm {
		t.Errorf("optics %+v", rx)
	}
	if d.Stack == nil || d.Stack.Members[0].Role != "master" || d.System.CPU[0].Min5.V != 1.6 {
		t.Errorf("ha/cpu %+v %+v", d.Stack, d.System.CPU)
	}
}

func TestAlteon(t *testing.T) {
	t.Parallel()
	p := ">> Standalone ADC - Information#"
	d := decode(t, "radware", p,
		out(p, "/info/link", "------------------------------------------------------------------\nAlias    Port   Speed   Duplex    Flow Ctrl       Link\n------   ----   -----   -------   --TX---RX--     -----\n1        1      10G*    full*     no*    no*      up\n3        3      any     any       yes    yes      disabled\n* = value set by configuration; not autonegotiated.\n"),
		out(p, "/info/l2/fdb/dump", "     MAC address    VLAN Port   Trunk State Age Referenced SPs Learned port Referenced ports\n  ----------------- ---- ------ ----- ----- --- -------------- ------------ ----------------\n  00:00:5e:00:01:01 1117 1             FWD       1-6            1            1\n"),
		out(">> Port 1 Statistics#", "/stats/port 1/if", "------------------------------------------------------------------\nInterface statistics for port 1:\n                     ifHCIn Counters       ifHCOut Counters\nOctets:             1016                   398\nErrors:                            5                      0\nPer second Interface statistics:\nOctets:                    100               50\n"),
	)
	i := d.Interfaces.Get("1")
	if !i.Up() || i.Speed.V != 1e10 || i.Counters.In.Errors.V != 5 || i.Rates.InBps.V != 800 {
		t.Errorf("port 1 %+v", i)
	}
	if d.Interfaces.Get("3").DownCause != swtele.CauseAdmin || len(d.L2.MACs) != 1 || d.L2.MACs[0].Port != "1" {
		t.Errorf("port 3 / fdb %+v", d.L2.MACs)
	}
}

func TestPANOS(t *testing.T) {
	t.Parallel()
	p := "admin@fw1(active)>"
	d := decode(t, "palo_alto", p,
		capture.Output{Command: "show transceiver all", Prompt: p, Raw: p + " show transceiver all\n\n--------\n         Port   Temperature      Voltage      Current    Tx Power    Rx Power\n--------\n ethernet1/19       30.75 C       3.29 V      6.36 mA     0.50 mW     0.00 mW\n" + p},
	)
	ln := d.Interfaces.Get("ethernet1/19").Optics.Lanes[0]
	if ln.TxPower.Value.V != -3.01 || !ln.RxPower.Dark() {
		t.Errorf("mW conversion %+v %+v", ln.TxPower, ln.RxPower)
	}
	if d.Stack.Members[0].Role != "active" || d.System.Hostname != "fw1" {
		t.Errorf("ha %+v %q", d.Stack, d.System.Hostname)
	}
}

func TestIOS(t *testing.T) {
	t.Parallel()
	p := "core1#"
	d := decode(t, "cisco_ios", p,
		out(p, "show interfaces", "TwentyFiveGigE1/0/1 is up, line protocol is up (connected)\n  Hardware is Twenty Five Gigabit Ethernet, address is 4464.3cb0.1461 (bia 4464.3cb0.1461)\n  Description: to-ips\n  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,\n  Full-duplex, 10Gb/s, link type is auto, media type is SFP-10GBase-SR\n  5 minute input rate 207330000 bits/sec, 29143 packets/sec\n     31313584398 packets input, 26239446480682 bytes, 0 no buffer\n     0 runts, 0 giants, 0 throttles\n     4 input errors, 3 CRC, 0 frame, 0 overrun, 0 ignored\n"),
		out(p, "show etherchannel summary", "Group  Port-channel  Protocol    Ports\n------+-------------+-----------+-----------------------------------------------\n81     Po81(SU)       LACP        Twe1/0/1(P)    Twe2/0/1(D)\n"),
		out(p, "show processes cpu sorted", "CPU utilization for five seconds: 3%/1%; one minute: 2%; five minutes: 7%\n PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process\n"),
	)
	i := d.Interfaces.Get("Twe1/0/1")
	if i == nil || i.Speed.V != 1e10 || i.Counters.CRC.V != 3 || i.Counters.In.Errors.V != 4 || i.Aggregate != "Port-channel81" {
		t.Fatalf("interface %+v", i)
	}
	if a := d.Aggregate("Po81"); a.Mode != swtele.AggLACP || !a.Members[0].Selected || a.Members[1].Selected || d.System.CPU[0].Min5.V != 7 {
		t.Errorf("etherchannel/cpu %+v", a)
	}
}
