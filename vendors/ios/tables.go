package ios

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/parse"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// decodeStatus reads "Port Name Status Vlan Duplex Speed Type"; Name is
// truncated and Type may contain spaces, so cells are cut at offsets.
func decodeStatus(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text):
		case strings.HasPrefix(text, "Port ") && strings.Contains(text, "Status"):
			cols, _ = parse.HeaderColumns(text, "Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type")
		case cols.Len() > 0:
			c := cols.Cells(text)
			if c[0] == "" {
				continue
			}
			i := port(st, c[0])
			if i.Desc == "" {
				i.Desc = c[1]
			}
			fill(&i.Speed, clidoc.Speed(strings.TrimPrefix(c[5], "a-")))
			if i.Media == "" && !clidoc.Null(c[6]) {
				i.Media = c[6]
			}
			switch v := c[3]; {
			case v == "trunk":
				sw(i).Mode = swtele.ModeTrunk
			case v == "routed":
				sw(i).Mode = swtele.ModeRouted
			case clidoc.Int(v).OK:
				s := sw(i)
				s.Mode, s.PVID = swtele.ModeAccess, clidoc.Int(v)
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

func sw(i *swtele.Interface) *swtele.Switchport {
	if i.Switching == nil {
		i.Switching = &swtele.Switchport{}
	}
	return i.Switching
}

func decodeDescription(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text):
		case strings.HasPrefix(l.Text, "Interface ") && strings.Contains(l.Text, "Description"):
			cols, _ = parse.HeaderColumns(l.Text, "Interface", "Status", "Protocol", "Description")
		case cols.Len() > 0:
			c := cols.Cells(l.Text)
			if c[0] == "" {
				continue
			}
			if i := port(st, c[0]); c[3] != "" {
				i.Desc = c[3]
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var errRow = regexp.MustCompile(`^(\S+)\s+.*\s(err-disabled)\s+(\S+)\s*$`)

func decodeErrDisabled(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), strings.HasPrefix(l.Text, "Port "):
		case errRow.MatchString(l.Text):
			i := port(st, errRow.FindStringSubmatch(l.Text)[1])
			i.Oper, i.DownCause = swtele.StateDown, swtele.CauseErrDisabled
		default:
			continue
		}
		doc.Mark(l)
	}
}

// decodeAccount accounts for an output without ledger value.
func decodeAccount(doc *clidoc.Doc, _ *state) { doc.Mark(doc.Lines...) }

var ipRow = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(?:YES|NO)\s+\S+\s+(up|down|administratively down|deleted)\s+(up|down)\s*$`)

func decodeIPBrief(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), strings.HasPrefix(l.Text, "Interface "):
		case ipRow.MatchString(l.Text):
			m := ipRow.FindStringSubmatch(l.Text)
			i := port(st, m[1])
			if a, err := netip.ParseAddr(m[2]); err == nil && len(i.Addresses) == 0 {
				i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: netip.PrefixFrom(a, 32), Primary: true})
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	xcvrTable  = regexp.MustCompile(`^\s+(Temperature|Voltage|Current|Transmit|Receive|Optical)\b`)
	xcvrRow    = regexp.MustCompile(`^(\S+)\s+(?:(\d+|N/A)\s+)?(-?[\d.]+|N/A)\s*(\+\+|--|\+|-)?\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s*$`)
	xcvrLegend = regexp.MustCompile(`^(?:mA: milliamperes|\+\+ : high alarm|A2D readouts|The threshold values|\s+High Alarm\s+High Warn|Port\s+(?:Lane\s+)?\(|-{5,}\s|\s+(?:Temperature|Voltage|Current|Transmit|Receive|Optical)\s+)`)
)

// decodeTransceiver reads the five tables of "show interfaces
// transceiver detail": temperature, voltage, current, transmit and
// receive power, each with high alarm, high warning, low warning and low
// alarm thresholds; current and power tables carry a lane column.
func decodeTransceiver(doc *clidoc.Doc, st *state) {
	table := ""
	for _, l := range doc.Lines {
		text := l.Text
		if m := xcvrTable.FindStringSubmatch(text); m != nil && !xcvrRow.MatchString(text) {
			table = m[1]
			if table == "Optical" {
				table = map[bool]string{true: "Transmit", false: "Receive"}[strings.Contains(text, "Transmit")]
			}
		}
		switch {
		case blank(text), xcvrLegend.MatchString(text):
		case table != "" && xcvrRow.MatchString(text):
			m := xcvrRow.FindStringSubmatch(text)
			i := port(st, m[1])
			if i.Optics == nil {
				i.Optics = &swtele.Transceiver{Present: true, DOM: swtele.DOMSupported, Lanes: []swtele.Lane{{Index: 1}}}
			}
			r := swtele.Reading{Value: clidoc.Float(m[3]), Th: swtele.Thresholds{
				HighAlarm: clidoc.Float(m[5]), HighWarn: clidoc.Float(m[6]), LowWarn: clidoc.Float(m[7]), LowAlarm: clidoc.Float(m[8])}}
			x, ln := i.Optics, &i.Optics.Lanes[0]
			switch table {
			case "Temperature":
				x.Temp = r
			case "Voltage":
				x.Voltage = r
			case "Current":
				ln.Bias = r
			case "Transmit":
				ln.TxPower = r
			case "Receive":
				ln.RxPower = r
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	ecRow    = regexp.MustCompile(`^(\d+)\s+(Po\d+)\((\w+)\)\s+(\S+)\s*(.*)$`)
	ecMember = regexp.MustCompile(`(\S+?)\((\w+)\)`)
	ecInfo   = regexp.MustCompile(`^(?:Flags:|\s+[A-Za-z] - |Number of (?:channel-groups|aggregators)|Group\s+Port-channel|-+\+)`)
)

func decodeEtherchannel(doc *clidoc.Doc, st *state) {
	var cur *swtele.Aggregate
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), ecInfo.MatchString(text):
		case ecRow.MatchString(text):
			m := ecRow.FindStringSubmatch(text)
			a := swtele.Aggregate{Name: longName(m[2]), Mode: swtele.AggStatic}
			if m[4] == "LACP" {
				a.Mode = swtele.AggLACP
			}
			port(st, a.Name).Kind = swtele.KindAggregate
			st.dev.Aggregates = append(st.dev.Aggregates, a)
			cur = &st.dev.Aggregates[len(st.dev.Aggregates)-1]
			members(cur, m[5])
		case cur != nil && strings.HasPrefix(text, " ") && ecMember.MatchString(text):
			members(cur, text)
		default:
			continue
		}
		doc.Mark(l)
	}
}

func members(a *swtele.Aggregate, text string) {
	for _, m := range ecMember.FindAllStringSubmatch(text, -1) {
		a.Members = append(a.Members, swtele.AggMember{Port: longName(m[1]), Status: m[2], Selected: m[2] == "P"})
	}
}

var (
	cpuLine = regexp.MustCompile(`^CPU utilization for five seconds: (\d+)%(?:/\d+%)?; one minute: (\d+)%; five minutes: (\d+)%`)
	procRow = regexp.MustCompile(`^\s*(?:PID\s|\d+\s+\d+|\d+ Total\s*$)`)
	poolRow = regexp.MustCompile(`^\s*(\S+(?: \S)?) Pool Total:\s*(\d+) Used:\s*(\d+) Free:\s*(\d+)`)
)

func decodeCPU(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), procRow.MatchString(l.Text):
		case cpuLine.MatchString(l.Text):
			m := cpuLine.FindStringSubmatch(l.Text)
			st.dev.System.CPU = append(st.dev.System.CPU, swtele.CPULoad{Unit: swtele.Unit{Slot: 1},
				Now: clidoc.Float(m[1]), Min1: clidoc.Float(m[2]), Min5: clidoc.Float(m[3])})
		default:
			continue
		}
		doc.Mark(l)
	}
}

// decodeMemory reads the processor pool; the other pools and the process
// table carry no ledger value.
func decodeMemory(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), procRow.MatchString(l.Text):
		case poolRow.MatchString(l.Text):
			if m := poolRow.FindStringSubmatch(l.Text); m[1] == "Processor" {
				st.dev.System.Memory = append(st.dev.System.Memory, swtele.MemoryUsage{Unit: swtele.Unit{Slot: 1},
					Total: clidoc.Uint(m[2]), Used: clidoc.Uint(m[3]), Free: clidoc.Uint(m[4])})
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	envSwitch = regexp.MustCompile(`^Switch:? ?(\d+)\s*$`)
	envSensor = regexp.MustCompile(`^\s(.+?)\s{2,}(\S+)\s+(\S+)\s+(-?\d+) (mV|Celsius|mA|W)\s*$`)
	envPSU    = regexp.MustCompile(`^(PS\d+)\s+(\S+)\s+\S+\s+(?:\d+ W\s+)?(\S+)\s`)
	envFan    = regexp.MustCompile(`^(FM\d+|\d+)\s+(\S+)\s+`)
	envInfo   = regexp.MustCompile(`^(?:Sensor List:|\s+Sensor\s+Location|Power\s+Fan States|Supply\s+Model|Fan\s+Fan States|Tray\s+Status|-{5,}|\s*SYSTEM|Switch\s+FAN|---)`)
)

func decodeEnvironment(doc *clidoc.Doc, st *state) {
	sys := &st.dev.System
	member := 0
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), envInfo.MatchString(text):
		case envSwitch.MatchString(text):
			member = clidoc.Int(envSwitch.FindStringSubmatch(text)[1]).Or(0)
		case envSensor.MatchString(text):
			m := envSensor.FindStringSubmatch(text)
			if m[5] == "Celsius" {
				sys.Sensors = append(sys.Sensors, swtele.Sensor{Name: strings.TrimSpace(m[1]) + " " + m[2], Value: clidoc.Float(m[4])})
			}
		case envPSU.MatchString(text):
			m := envPSU.FindStringSubmatch(text)
			sys.PSUs = append(sys.PSUs, swtele.Component{Unit: swtele.Unit{Chassis: member}, ID: m[1], Model: m[2], Status: m[3], OK: swtele.Some(m[3] == "ok" || m[3] == "OK")})
		case envFan.MatchString(text):
			m := envFan.FindStringSubmatch(text)
			sys.Fans = append(sys.Fans, swtele.Component{Unit: swtele.Unit{Chassis: member}, ID: m[1], Status: m[2], OK: swtele.Some(strings.EqualFold(m[2], "ok"))})
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	ospfRow = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+/\s*\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s*$`)
	bgpRow  = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+4\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+(?: \(\S+\))?)\s*$`)
	bgpInfo = regexp.MustCompile(`^(?:BGP router identifier|BGP table version|\d+(?:/\d+)? .*(?:entries|bytes)|BGP using|\d+ received paths|BGP activity|\d+ networks peaked|Neighbor\s+V\s+AS)`)
)

func decodeOSPF(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), strings.HasPrefix(l.Text, "Neighbor ID"):
		case ospfRow.MatchString(l.Text):
			m := ospfRow.FindStringSubmatch(l.Text)
			p := swtele.Peer{Proto: swtele.ProtoOSPF, RouterID: m[1], State: strings.ReplaceAll(m[3], " ", ""), Interface: longName(m[6])}
			p.Address, _ = netip.ParseAddr(m[5])
			s := strings.ToUpper(p.State)
			p.Established = strings.HasPrefix(s, "FULL") || s == "2WAY/DROTHER"
			st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		default:
			continue
		}
		doc.Mark(l)
	}
}

func decodeBGP(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), bgpInfo.MatchString(l.Text):
		case bgpRow.MatchString(l.Text):
			m := bgpRow.FindStringSubmatch(l.Text)
			p := swtele.Peer{Proto: swtele.ProtoBGP, Family: "ipv4", AS: m[2], Up: clidoc.Duration(m[3])}
			p.Address, _ = netip.ParseAddr(m[1])
			if n := clidoc.Int(m[4]); n.OK {
				p.State, p.Prefixes, p.Established = "Established", n, true
			} else {
				p.State = m[4]
			}
			st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var arpRow = regexp.MustCompile(`^Internet\s+(\S+)\s+(\S+)\s+([0-9a-f.]{14}|Incomplete)\s+ARPA\s*(\S*)`)

func decodeARP(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), strings.HasPrefix(l.Text, "Protocol "):
		case arpRow.MatchString(l.Text):
			m := arpRow.FindStringSubmatch(l.Text)
			e := swtele.ARPEntry{Interface: longName(m[4])}
			e.IP, _ = netip.ParseAddr(m[1])
			if mac, err := swtele.ParseMAC(m[3]); err == nil {
				e.MAC = mac
			} else {
				e.Incomplete = true
			}
			if m[2] == "-" {
				e.Kind = "local"
			} else if age := clidoc.Int(m[2]); age.OK {
				e.Age = swtele.Some(time.Duration(age.V) * time.Minute)
			}
			if v, ok := strings.CutPrefix(e.Interface, "Vlan"); ok {
				e.VLAN = clidoc.Int(v).Or(0)
			}
			st.dev.L3.ARP = append(st.dev.L3.ARP, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	macRow  = regexp.MustCompile(`^\s*(\d+|All)\s+([0-9a-f.]{14})\s+(\S+)\s+(\S+)\s*$`)
	macInfo = regexp.MustCompile(`^(?:\s+Mac Address Table|-{5,}|Vlan\s+Mac Address|----\s|Total Mac Addresses)`)
)

func decodeMAC(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), macInfo.MatchString(l.Text):
		case macRow.MatchString(l.Text):
			m := macRow.FindStringSubmatch(l.Text)
			mac, err := swtele.ParseMAC(m[2])
			if err != nil {
				continue
			}
			e := swtele.MACEntry{MAC: mac, VLAN: clidoc.Int(m[1]).Or(0), Port: longName(m[4]), Kind: swtele.MACDynamic}
			switch {
			case m[4] == "CPU" || m[1] == "All":
				e.Kind = swtele.MACSystem
			case strings.EqualFold(m[3], "STATIC"):
				e.Kind = swtele.MACStatic
			}
			st.dev.L2.MACs = append(st.dev.L2.MACs, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var logEntry = regexp.MustCompile(`^[*.]?(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: \S+)?: %([A-Z0-9_]+)-(\d)-([A-Z0-9_]+): (.*)$`)

func decodeLog(doc *clidoc.Doc, st *state) {
	year := st.dev.Observed.Year()
	for _, l := range doc.Lines {
		m := logEntry.FindStringSubmatch(l.Text)
		if m == nil {
			continue
		}
		e := swtele.LogEvent{Module: m[2], Severity: clidoc.Int(m[3]).Or(0), Mnemonic: m[4], Text: m[5]}
		stamp := strings.Join(strings.Fields(strings.SplitN(m[1], ".", 2)[0]), " ")
		if t, err := time.ParseInLocation("Jan _2 15:04:05 2006", stamp+" "+itoaYear(year), st.loc); err == nil {
			e.At = swtele.Some(t.UTC())
		}
		st.dev.Logs = append(st.dev.Logs, e)
		doc.Mark(l)
	}
}

func itoaYear(y int) string { return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006") }

var (
	lldpRule = regexp.MustCompile(`^-{10,}$`)
	lldpKV   = regexp.MustCompile(`^([A-Za-z][A-Za-z ]*?)\s*:\s?(.*)$`)
)

// decodeLLDP reads "------" separated neighbor blocks; the system
// description and management addresses continue on following lines.
func decodeLLDP(doc *clidoc.Doc, st *state) {
	var cur *swtele.Neighbor
	flush := func() {
		if cur != nil && cur.LocalPort != "" {
			port(st, cur.LocalPort)
			st.dev.Neighbors = append(st.dev.Neighbors, *cur)
		}
		cur = nil
	}
	inDesc := false
	for _, l := range doc.Lines {
		text := strings.TrimSpace(l.Text)
		switch {
		case lldpRule.MatchString(text):
			flush()
			cur, inDesc = &swtele.Neighbor{Protocol: "lldp"}, false
		case cur == nil, text == "":
		case strings.HasPrefix(text, "Time remaining:"):
			inDesc = false
		case strings.HasPrefix(text, "System Description:"):
			inDesc = true
		case inDesc:
			cur.SysDesc = strings.TrimSpace(cur.SysDesc + "\n" + text)
		case strings.HasPrefix(text, "IP: "):
			if !cur.MgmtAddr.IsValid() {
				cur.MgmtAddr, _ = netip.ParseAddr(strings.TrimPrefix(text, "IP: "))
			}
		case lldpKV.MatchString(text):
			m := lldpKV.FindStringSubmatch(text)
			switch v := strings.TrimSpace(m[2]); strings.ToLower(m[1]) {
			case "local intf":
				cur.LocalPort = longName(v)
			case "chassis id":
				cur.ChassisID = v
				cur.ChassisMAC, _ = swtele.ParseMAC(v)
			case "port id":
				cur.Port = v
			case "port description":
				cur.PortDesc = v
			case "system name":
				cur.System = v
			case "vlan id":
				cur.PVID = clidoc.Int(v)
			case "enabled capabilities":
				cur.Capabilities = strings.Split(v, ",")
			}
		case strings.HasPrefix(l.Text, "    "):
			// indented detail of a multi-line TLV (capabilities, OIDs)
		case strings.HasPrefix(text, "OID") || strings.HasPrefix(text, "IPV6") || strings.Count(text, ".") > 5 || strings.Contains(text, " - "):
		default:
			continue
		}
		doc.Mark(l)
	}
	flush()
}

var (
	cdpStart = regexp.MustCompile(`^Device ID: ?(.*)$`)
	cdpIntf  = regexp.MustCompile(`^Interface: (\S+),\s+Port ID \(outgoing port\): (\S+)`)
	cdpPlat  = regexp.MustCompile(`^Platform: ([^,]+),`)
	cdpAddr  = regexp.MustCompile(`^\s+IP address: (\S+)`)
)

// decodeCDP adds neighbors seen only through CDP and the platform of the
// LLDP ones.
func decodeCDP(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(cdpStart.MatchString)
	doc.Mark(doc.Lines...)
	for _, block := range blocks {
		n := swtele.Neighbor{Protocol: "cdp", System: strings.TrimSpace(cdpStart.FindStringSubmatch(block[0].Text)[1])}
		for _, l := range block[1:] {
			switch text := l.Text; {
			case cdpIntf.MatchString(text):
				m := cdpIntf.FindStringSubmatch(text)
				n.LocalPort, n.Port = longName(m[1]), m[2]
			case cdpPlat.MatchString(text):
				n.Platform = strings.TrimSpace(cdpPlat.FindStringSubmatch(text)[1])
			case cdpAddr.MatchString(text) && !n.MgmtAddr.IsValid():
				n.MgmtAddr, _ = netip.ParseAddr(cdpAddr.FindStringSubmatch(text)[1])
			}
		}
		if n.LocalPort == "" {
			continue
		}
		merged := false
		for i := range st.dev.Neighbors {
			x := &st.dev.Neighbors[i]
			if swtele.InterfaceKey(x.LocalPort) == swtele.InterfaceKey(n.LocalPort) && x.Protocol == "lldp" {
				x.Platform, merged = n.Platform, true
			}
		}
		if !merged {
			port(st, n.LocalPort)
			st.dev.Neighbors = append(st.dev.Neighbors, n)
		}
	}
}
