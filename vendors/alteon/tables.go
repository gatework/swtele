package alteon

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	xcvrEmpty = regexp.MustCompile(`^\s*(\d+)\s+NA\s*$`)
	xcvrRow   = regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)
	xcvrInfo  = regexp.MustCompile(`^(?:Port\s+Temperature|\s+\(Celsius\)|\s+\(dBm\)|-{4,}\s)`)
)

// decodeTransceiver reads Port, Temperature, Voltage, Current, Tx and Rx
// power, then vendor, part number, revision, serial and date code; NA
// rows are empty cages. The vendor name may contain spaces, so the
// identity columns are read from the right.
func decodeTransceiver(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), xcvrInfo.MatchString(l.Text):
		case xcvrEmpty.MatchString(l.Text):
			port(st, xcvrEmpty.FindStringSubmatch(l.Text)[1]).Optics = &swtele.Transceiver{Present: false}
		case xcvrRow.MatchString(l.Text):
			m := xcvrRow.FindStringSubmatch(l.Text)
			i := port(st, m[1])
			if clidoc.Null(m[2]) && clidoc.Null(m[6]) {
				i.Optics = &swtele.Transceiver{Present: false}
				break
			}
			x := &swtele.Transceiver{Present: true, DOM: swtele.DOMSupported}
			x.Temp.Value, x.Voltage.Value = clidoc.Float(m[2]), clidoc.Float(m[3])
			x.Lanes = []swtele.Lane{{Index: 1}}
			x.Lanes[0].Bias.Value, x.Lanes[0].TxPower.Value, x.Lanes[0].RxPower.Value = clidoc.Float(m[4]), clidoc.Float(m[5]), clidoc.Float(m[6])
			if f := strings.Fields(m[7]); len(f) >= 5 {
				n := len(f)
				x.Inventory.Date, x.Inventory.Serial, x.Inventory.PartNumber = f[n-1], f[n-2], f[n-4]
				x.Inventory.Vendor = strings.Join(f[:n-4], " ")
			}
			i.Optics = x
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	trunkHeader = regexp.MustCompile(`^Trunk group (\d+), .*?name: ([^,]*), port state:`)
	trunkMember = regexp.MustCompile(`^\s+(\d+): STG\s+\d+\s+(\S+)`)
)

// decodeTrunk reads static trunk groups; a member forwarding traffic is
// selected.
func decodeTrunk(doc *clidoc.Doc, st *state) {
	var cur *swtele.Aggregate
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), strings.TrimSpace(l.Text) == "All Trunk groups are disabled.":
		case trunkHeader.MatchString(l.Text):
			m := trunkHeader.FindStringSubmatch(l.Text)
			st.dev.Aggregates = append(st.dev.Aggregates, swtele.Aggregate{Name: "trunk" + m[1], Mode: swtele.AggStatic})
			cur = &st.dev.Aggregates[len(st.dev.Aggregates)-1]
			a := st.dev.Interfaces.Ensure(cur.Name)
			a.Kind, a.Desc = swtele.KindAggregate, strings.TrimSpace(m[2])
		case cur != nil && trunkMember.MatchString(l.Text):
			m := trunkMember.FindStringSubmatch(l.Text)
			state := strings.ToLower(m[2])
			cur.Members = append(cur.Members, swtele.AggMember{Port: m[1], Status: m[2], Selected: state == "forwarding" || state == "fwd"})
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	mpCPU  = regexp.MustCompile(`^cpuUtil(1Second|4Seconds|64Seconds) \(time base\):(\d+)%`)
	mpInfo = regexp.MustCompile(`^(?:-{10,}|CPU utilization:)`)
	spRow  = regexp.MustCompile(`^SP\s+(\d+) : \[[#.]+\] (\d+)%`)
	spInfo = regexp.MustCompile(`^(?:-{10,}|SPs (?:CPU utilization|memory) percentage|Average : |\s+\[[#.]+\] \d+%)`)
)

// decodeMPCPU reads the management processor: 1-second as now, 64-second
// as the minute load.
func decodeMPCPU(doc *clidoc.Doc, st *state) {
	c := swtele.CPULoad{Unit: swtele.Unit{Slot: 0}}
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), mpInfo.MatchString(l.Text):
		case mpCPU.MatchString(l.Text):
			m := mpCPU.FindStringSubmatch(l.Text)
			switch m[1] {
			case "1Second":
				c.Now = clidoc.Float(m[2])
			case "64Seconds":
				c.Min1 = clidoc.Float(m[2])
			}
		default:
			continue
		}
		doc.Mark(l)
	}
	st.dev.System.CPU = append(st.dev.System.CPU, c)
}

// decodeSP reads the switch processors' CPU (allcpu) or memory (allmem)
// bars; SP n is CPU n of slot 1.
func decodeSP(doc *clidoc.Doc, st *state) {
	mem := strings.HasSuffix(doc.Command, "allmem")
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), spInfo.MatchString(l.Text):
		case spRow.MatchString(l.Text):
			m := spRow.FindStringSubmatch(l.Text)
			u := swtele.Unit{Slot: 1, CPU: clidoc.Int(m[1]).Or(0)}
			v := clidoc.Float(m[2])
			if mem {
				st.dev.System.Memory = append(st.dev.System.Memory, swtele.MemoryUsage{Unit: u, FreeRatio: swtele.Some(100 - v.V)})
			} else {
				st.dev.System.CPU = append(st.dev.System.CPU, swtele.CPULoad{Unit: u, Now: v})
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	statsPort = regexp.MustCompile(`^/stats/port (\d+)/if$`)
	statsRow  = regexp.MustCompile(`^(Octets|UcastPkts|BroadcastPkts|MulticastPkts|Discards|Errors):\s+(\d+)\s+(\d+)\s*$`)
	statsInfo = regexp.MustCompile(`^(?:-{10,}|Interface statistics for port|\s+ifHCIn Counters|Per second Interface statistics:)`)
)

// decodePortStats reads one "/stats/port N/if": cumulative counters, then
// per-second rates.
func decodePortStats(doc *clidoc.Doc, st *state) {
	m := statsPort.FindStringSubmatch(doc.Command)
	if m == nil {
		return // the all-ports summary
	}
	i := port(st, m[1])
	perSecond := false
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text):
		case strings.HasPrefix(l.Text, "Per second"):
			perSecond = true
		case statsInfo.MatchString(l.Text):
		case statsRow.MatchString(l.Text):
			r := statsRow.FindStringSubmatch(l.Text)
			in, out := clidoc.Uint(r[2]), clidoc.Uint(r[3])
			if perSecond {
				if r[1] == "Octets" {
					i.Rates.Window = time.Second
					i.Rates.InBps, i.Rates.OutBps = swtele.Some(float64(in.V)*8), swtele.Some(float64(out.V)*8)
				}
				break
			}
			switch r[1] {
			case "Octets":
				i.Counters.In.Octets, i.Counters.Out.Octets = in, out
			case "UcastPkts":
				i.Counters.In.Unicast, i.Counters.Out.Unicast = in, out
			case "BroadcastPkts":
				i.Counters.In.Bcast, i.Counters.Out.Bcast = in, out
			case "MulticastPkts":
				i.Counters.In.Multicst, i.Counters.Out.Multicst = in, out
			case "Discards":
				i.Counters.In.Discards, i.Counters.Out.Discards = in, out
			case "Errors":
				i.Counters.In.Errors, i.Counters.Out.Errors = in, out
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	tempRow  = regexp.MustCompile(`^Sensor (\d+) has (-?\d+) degree Celsius`)
	tempInfo = regexp.MustCompile(`^(?:Current device temperature is|Note:|High temperature is|Critical temperature|System will shutdown)`)
	tempHigh = regexp.MustCompile(`^High temperature is (\d+)-(\d+) degree`)
	fanRow   = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(\S+(?: \S+)?)\s+(\d+%|\S+)\s*$`)
	fanInfo  = regexp.MustCompile(`^(?:Fans table:|Fan-Number\s+Type|-{5,})`)
	psRow    = regexp.MustCompile(`^(?:Dual )?Power Supply(?: (\d+))? Status: (\S+)`)
)

func decodeTemp(doc *clidoc.Doc, st *state) {
	warn, alarm := swtele.Opt[float64]{}, swtele.Opt[float64]{}
	for _, l := range doc.Lines {
		if m := tempHigh.FindStringSubmatch(l.Text); m != nil {
			warn, alarm = clidoc.Float(m[1]), clidoc.Float(m[2])
		}
	}
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), tempInfo.MatchString(l.Text):
		case tempRow.MatchString(l.Text):
			m := tempRow.FindStringSubmatch(l.Text)
			st.dev.System.Sensors = append(st.dev.System.Sensors, swtele.Sensor{Name: "sensor " + m[1], Value: clidoc.Float(m[2]), Warning: warn, Alarm: alarm})
		default:
			continue
		}
		doc.Mark(l)
	}
}

func decodeFan(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), fanInfo.MatchString(l.Text):
		case fanRow.MatchString(l.Text):
			m := fanRow.FindStringSubmatch(l.Text)
			st.dev.System.Fans = append(st.dev.System.Fans, swtele.Component{ID: m[1], Status: m[3], OK: swtele.Some(strings.EqualFold(m[3], "Operational"))})
		default:
			continue
		}
		doc.Mark(l)
	}
}

func decodePS(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		m := psRow.FindStringSubmatch(strings.TrimSpace(l.Text))
		if m == nil {
			continue
		}
		id := m[1]
		if id == "" {
			id = "dual"
		}
		st.dev.System.PSUs = append(st.dev.System.PSUs, swtele.Component{ID: id, Status: m[2], OK: swtele.Some(strings.EqualFold(m[2], "OK"))})
		doc.Mark(l)
	}
}

var (
	arpRow  = regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+([PRUM ]*?\d?)\s*([0-9a-f:]{17})\s+(\d*)\s*(\d*)\s+\S+\s*$`)
	arpInfo = regexp.MustCompile(`^\s*(?:IP address\s+Flags|-{5,})`)
	fdbRow  = regexp.MustCompile(`^\s*([0-9a-f:]{17})\s+(\d+)\s+(\d*)\s+(\d*)\s+([A-Z]{3})\b`)
	fdbInfo = regexp.MustCompile(`^\s*(?:MAC address\s+VLAN|-{5,})`)
)

// decodeARP reads the ARP dump; a "P" (permanent) entry without port is
// one of the device's own addresses.
func decodeARP(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), arpInfo.MatchString(l.Text):
		case arpRow.MatchString(l.Text):
			m := arpRow.FindStringSubmatch(l.Text)
			e := swtele.ARPEntry{VLAN: clidoc.Int(m[4]).Or(0), Interface: m[5], Kind: strings.TrimSpace(m[2])}
			e.IP, _ = netip.ParseAddr(m[1])
			e.MAC, _ = swtele.ParseMAC(m[3])
			st.dev.L3.ARP = append(st.dev.L3.ARP, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

// decodeFDB reads the forwarding database; FWD entries are learned on a
// port (or trunk), VIR/VPR/VSR are the device's own virtual MACs.
func decodeFDB(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), fdbInfo.MatchString(l.Text):
		case fdbRow.MatchString(l.Text):
			m := fdbRow.FindStringSubmatch(l.Text)
			mac, err := swtele.ParseMAC(m[1])
			if err != nil {
				continue
			}
			e := swtele.MACEntry{MAC: mac, VLAN: clidoc.Int(m[2]).Or(0), Port: m[3], Kind: swtele.MACDynamic}
			if m[4] != "" {
				e.Port = "trunk" + m[4]
			}
			if m[5] != "FWD" {
				e.Kind = swtele.MACSystem
			}
			st.dev.L2.MACs = append(st.dev.L2.MACs, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var haState = regexp.MustCompile(`^\s*State: (\S+)`)

// decodeHA reads the high-availability role of the device.
func decodeHA(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		if m := haState.FindStringSubmatch(l.Text); m != nil {
			s := stack(st)
			s.Members = []swtele.Member{{ID: 1, Role: m[1], Self: true}}
		}
		doc.Mark(l) // tracking counters carry no ledger value
	}
}

// decodeDisabled accepts "BGP is disabled." and "OSPF is disabled.";
// enabled protocols are not decoded yet and stay unparsed.
func decodeDisabled(doc *clidoc.Doc, _ *state) {
	for _, l := range doc.Lines {
		if strings.HasSuffix(strings.TrimSpace(l.Text), "is disabled.") || blank(l.Text) {
			doc.Mark(l)
		}
	}
}

var logEntry = regexp.MustCompile(`^\s*(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(EMERG|ALERT|CRITICAL|CRIT|ERROR|ERR|WARNING|NOTICE|INFO|DEBUG)\s+([^:]+):\s?(.*)$`)

var logSeverity = map[string]int{"EMERG": 0, "ALERT": 1, "CRITICAL": 2, "CRIT": 2, "ERROR": 3, "ERR": 3, "WARNING": 4, "NOTICE": 5, "INFO": 6, "DEBUG": 7}

func decodeLog(doc *clidoc.Doc, st *state) {
	year := st.dev.Observed.Year()
	for _, l := range doc.Lines {
		text := strings.TrimSpace(l.Text)
		switch {
		case text == "", strings.HasPrefix(text, "Showing "):
		case logEntry.MatchString(l.Text):
			m := logEntry.FindStringSubmatch(l.Text)
			if strings.Contains(m[4], " login from ") || strings.Contains(m[4], " logout from ") {
				break // the collector's own sessions
			}
			e := swtele.LogEvent{Module: strings.TrimSpace(m[3]), Severity: logSeverity[m[2]], Mnemonic: m[2], Text: m[4]}
			if t, err := time.ParseInLocation("Jan _2 15:04:05 2006", strings.Join(strings.Fields(m[1]), " ")+" "+strconv.Itoa(year), st.loc); err == nil {
				e.At = swtele.Some(t.UTC())
			} else if t, err := time.Parse(time.RFC3339, m[1]); err == nil {
				e.At = swtele.Some(t.UTC())
			}
			st.dev.Logs = append(st.dev.Logs, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}
