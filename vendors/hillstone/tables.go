package hillstone

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/parse"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	verProduct = regexp.MustCompile(`^Product name: (\S+)\s+S/N: (\S+)`)
	verVersion = regexp.MustCompile(`StoneOS software, Version (\S+)`)
	verBoot    = regexp.MustCompile(`^Boot file is (\S+)`)
	verUptime  = regexp.MustCompile(`^Uptime is (.+)$`)
)

func decodeVersion(doc *clidoc.Doc, st *state) {
	sys := &st.dev.System
	for _, l := range doc.Lines {
		switch text := l.Text; {
		case verProduct.MatchString(text):
			m := verProduct.FindStringSubmatch(text)
			sys.Model, sys.Serial = m[1], m[2]
		case verBoot.MatchString(text):
			sys.Version = verBoot.FindStringSubmatch(text)[1]
		case verVersion.MatchString(text) && sys.Version == "":
			sys.Version = verVersion.FindStringSubmatch(text)[1]
		case verUptime.MatchString(text):
			sys.Uptime = clidoc.Duration(verUptime.FindStringSubmatch(text)[1])
		}
		doc.Mark(l) // feature and license lines carry no ledger value
	}
}

var (
	lacpMember = regexp.MustCompile(`^\s*member \d+: (\S+)`)
	lacpLink   = regexp.MustCompile(`^\s*speed:(\d+)\s+duplex:(\w+)\s+link state:(\w+)`)
	lacpStatus = regexp.MustCompile(`^\s*status: (\S+)`)
	lacpFlags  = regexp.MustCompile(`^\s*(local|remote)\s+-->\s+id:\S+\s+priority:\S+\s+oper-key:\S+\s+Flags:([A-H]*)`)
	lacpSys    = regexp.MustCompile(`^\s*(local|remote)\s+-->\s+system id:(.+?)\s+oper-key`)
	lacpInfo   = regexp.MustCompile(`^\s*(?:Flags:|D -- SYNC|G -- DEFAULTED|\*{10,}|state:|port_num:|load balance:|send lacp packet:|-{10,}|={10,})`)
)

// decodeLACP reads one "show lacp aggregateN" output.
func decodeLACP(doc *clidoc.Doc, st *state) {
	name := strings.TrimPrefix(doc.Command, "show lacp ")
	a := swtele.Aggregate{Name: name, Mode: swtele.AggLACP}
	port(st, name).Kind = swtele.KindAggregate
	var cur *swtele.AggMember
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), lacpInfo.MatchString(text):
		case lacpSys.MatchString(text):
			if m := lacpSys.FindStringSubmatch(text); m[1] == "local" {
				a.SystemID = strings.TrimSpace(m[2])
			}
		case lacpMember.MatchString(text):
			a.Members = append(a.Members, swtele.AggMember{Port: lacpMember.FindStringSubmatch(text)[1]})
			cur = &a.Members[len(a.Members)-1]
		case cur != nil && lacpLink.MatchString(text):
		case cur != nil && lacpStatus.MatchString(text):
			cur.Status = lacpStatus.FindStringSubmatch(text)[1]
			cur.Selected = cur.Status == "active" || cur.Status == "selected"
		case cur != nil && lacpFlags.MatchString(text):
			m := lacpFlags.FindStringSubmatch(text)
			if m[1] == "local" {
				cur.Flags = swtele.LACPFlags(m[2])
			} else {
				cur.PartnerFlags = swtele.LACPFlags(m[2])
			}
		default:
			continue
		}
		doc.Mark(l)
	}
	st.dev.Aggregates = append(st.dev.Aggregates, a)
}

var (
	cpuLine = regexp.MustCompile(`^(Average cpu utilization|Current cpu utilization|Last 1 minute|Last 5 minutes|Last 15 minutes)\s*:\s*([\d.]+)%`)
	memPct  = regexp.MustCompile(`^The percentage of memory utilization: ([\d.]+)%`)
	memCols = regexp.MustCompile(`^\s*total\(KB\)\s+used\(KB\)\s+free\(KB\)`)
	memRow  = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\d+)\s*$`)
	memHist = regexp.MustCompile(`^(?:Memory utilization in last \d+ (?:seconds|minutes|hours|days)|\s+memoryutil|\d+\s*:\s+[\d.]+\s*$)`)
)

func decodeCPU(doc *clidoc.Doc, st *state) {
	c := swtele.CPULoad{Unit: swtele.Unit{Slot: 1}}
	for _, l := range doc.Lines {
		m := cpuLine.FindStringSubmatch(l.Text)
		if m == nil {
			continue
		}
		v := clidoc.Float(m[2])
		switch m[1] {
		case "Current cpu utilization":
			c.Now = v
		case "Last 1 minute":
			c.Min1 = v
		case "Last 5 minutes":
			c.Min5 = v
		}
		doc.Mark(l)
	}
	st.dev.System.CPU = append(st.dev.System.CPU, c)
}

func decodeMemory(doc *clidoc.Doc, st *state) {
	m := swtele.MemoryUsage{Unit: swtele.Unit{Slot: 1}}
	for _, l := range doc.Lines {
		switch text := l.Text; {
		case blank(text), memCols.MatchString(text), memHist.MatchString(text), memPct.MatchString(text):
		case memRow.MatchString(text):
			r := memRow.FindStringSubmatch(text)
			kb := func(s string) swtele.Opt[uint64] {
				v := clidoc.Uint(s)
				v.V *= 1024
				return v
			}
			m.Total, m.Used, m.Free = kb(r[1]), kb(r[2]), kb(r[3])
		default:
			continue
		}
		doc.Mark(l)
	}
	st.dev.System.Memory = append(st.dev.System.Memory, m)
}

var (
	envSection = regexp.MustCompile(`^(Temperature information\(C\)|Fan information|Power information):\s*$`)
	envHeader  = regexp.MustCompile(`^Description\s+(?:Temperature|Status)`)
	tempRow    = regexp.MustCompile(`^(\S+)\s+(-?\d+)\s+(-?\d+)-(\d+)\s*$`)
	statusRow  = regexp.MustCompile(`^(\S+)\s+(\S+)\s*$`)
)

func decodeEnvironment(doc *clidoc.Doc, st *state) {
	sys := &st.dev.System
	section := ""
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text), envHeader.MatchString(text):
		case envSection.MatchString(text):
			section = envSection.FindStringSubmatch(text)[1]
		case strings.HasPrefix(section, "Temperature") && tempRow.MatchString(text):
			m := tempRow.FindStringSubmatch(text)
			sys.Sensors = append(sys.Sensors, swtele.Sensor{Name: m[1], Value: clidoc.Float(m[2]), Lower: clidoc.Float(m[3]), Alarm: clidoc.Float(m[4])})
		case section != "" && !strings.HasPrefix(section, "Temperature") && statusRow.MatchString(text):
			m := statusRow.FindStringSubmatch(text)
			c := swtele.Component{ID: m[1], Status: m[2], OK: swtele.Some(strings.EqualFold(m[2], "Fine") || strings.EqualFold(m[2], "Normal"))}
			if strings.HasPrefix(section, "Fan") {
				sys.Fans = append(sys.Fans, c)
			} else {
				sys.PSUs = append(sys.PSUs, c)
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	rateRow  = regexp.MustCompile(`^Interface (\S+)\s+Vsys \S+\s+last (\d+)sec : up (\d+)\s+down (\d+)`)
	rateInfo = regexp.MustCompile(`^(?:Item number|Target:|\s+Group-by:)`)
)

// decodeRates reads the interface bandwidth statistics: bytes over the
// last window, "up" sent and "down" received.
func decodeRates(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), rateInfo.MatchString(l.Text):
		case rateRow.MatchString(l.Text):
			m := rateRow.FindStringSubmatch(l.Text)
			i := port(st, m[1])
			secs := float64(clidoc.Int(m[2]).Or(5))
			i.Rates.Window = time.Duration(secs) * time.Second
			i.Rates.OutBps = swtele.Some(clidoc.Float(m[3]).V * 8 / secs)
			i.Rates.InBps = swtele.Some(clidoc.Float(m[4]).V * 8 / secs)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	arpRow  = regexp.MustCompile(`^Internet\s+(\S+)\s+(\S+)\s+([0-9a-fA-F.]{14}|Incomplete)\s+\S+\s+(\S+)`)
	arpInfo = regexp.MustCompile(`^(?:Total entries:|Protocol\s+Address)`)
	macRow  = regexp.MustCompile(`^([0-9a-fA-F.]{14})\s+(\S+)\s+(\S+)\s+([ILSD])\s+(\S+)\s*$`)
	macInfo = regexp.MustCompile(`^(?:Type: I:invalid|MAC Address\s+Switch|Total \d+ MAC entr(?:y|ies) showed)`)
)

func decodeARP(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), clidoc.Rule(l.Text), arpInfo.MatchString(l.Text):
		case arpRow.MatchString(l.Text):
			m := arpRow.FindStringSubmatch(l.Text)
			ip, err := netip.ParseAddr(m[1])
			if err != nil {
				continue
			}
			e := swtele.ARPEntry{IP: ip, Interface: m[4]}
			if mac, err := swtele.ParseMAC(m[3]); err == nil {
				e.MAC = mac
			} else {
				e.Incomplete = true
			}
			if age := clidoc.Int(m[2]); age.OK {
				e.Age = swtele.Some(time.Duration(age.V) * time.Second)
			}
			st.dev.L3.ARP = append(st.dev.L3.ARP, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

func decodeMAC(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), clidoc.Rule(l.Text), macInfo.MatchString(l.Text):
		case macRow.MatchString(l.Text):
			m := macRow.FindStringSubmatch(l.Text)
			mac, err := swtele.ParseMAC(m[1])
			if err != nil {
				continue
			}
			kind := map[string]swtele.MACKind{"D": swtele.MACDynamic, "S": swtele.MACStatic, "L": swtele.MACSystem, "I": swtele.MACOther}[m[4]]
			st.dev.L2.MACs = append(st.dev.L2.MACs, swtele.MACEntry{MAC: mac, Port: m[3], Kind: kind})
		default:
			continue
		}
		doc.Mark(l)
	}
}

var vrRow = regexp.MustCompile(`^(?:Total VR count:|\s*Name\s+Zone-count|\s*\S+\s+\d+\s+\d+\s*$)`)

// decodeVRouter only accounts for the virtual router list.
func decodeVRouter(doc *clidoc.Doc, _ *state) {
	for _, l := range doc.Lines {
		if blank(l.Text) || clidoc.Rule(l.Text) || vrRow.MatchString(l.Text) {
			doc.Mark(l)
		}
	}
}

var (
	ospfRow = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+(?:/\s*\S+)?)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)`)
	ospfHdr = regexp.MustCompile(`^(?:Neighbor ID|OSPF process|Total|\s*$)`)
	bgpRow  = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+4\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*$`)
	bgpInfo = regexp.MustCompile(`^(?:No IPv4 neighbor is configured|BGP router identifier|BGP table version|Neighbor\s+V\s+AS|\d+ BGP)`)
)

func decodeOSPF(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case ospfHdr.MatchString(l.Text), clidoc.Rule(l.Text):
		case ospfRow.MatchString(l.Text):
			m := ospfRow.FindStringSubmatch(l.Text)
			p := swtele.Peer{Proto: swtele.ProtoOSPF, RouterID: m[1], State: strings.ReplaceAll(m[3], " ", ""), Interface: m[6]}
			p.Address, _ = netip.ParseAddr(m[5])
			p.Established = strings.HasPrefix(strings.ToLower(p.State), "full")
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
			p := swtele.Peer{Proto: swtele.ProtoBGP, AS: m[2], Up: clidoc.Duration(m[3])}
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

var (
	logEntry = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), (\w+)@(\w+)\(([0-9A-Fa-fx]+)\): (.*)$`)
	logNone  = regexp.MustCompile(`^Info: There is no logging message`)
)

var severities = map[string]int{"EMERG": 0, "ALERT": 1, "CRIT": 2, "ERR": 3, "WARNING": 4, "NOTIF": 5, "INFO": 6, "DEBUG": 7}

func decodeLog(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), logNone.MatchString(l.Text):
		case logEntry.MatchString(l.Text):
			m := logEntry.FindStringSubmatch(l.Text)
			e := swtele.LogEvent{Module: m[3], Severity: severities[strings.ToUpper(m[2])], Mnemonic: m[4], Text: m[5]}
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], st.loc); err == nil {
				e.At = swtele.Some(t.UTC())
			}
			st.dev.Logs = append(st.dev.Logs, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	lldpTotal = regexp.MustCompile(`^Total lldp neighbor number: \d+`)
	lldpHdr   = regexp.MustCompile(`^System Name\s+Local Interface\s+Chassis ID\s+Port ID`)
)

// decodeLLDP cuts rows at header offsets: the system name may be empty
// and port IDs may carry raw bytes.
func decodeLLDP(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), clidoc.Rule(l.Text), lldpTotal.MatchString(l.Text):
		case lldpHdr.MatchString(l.Text):
			cols, _ = parse.HeaderColumns(l.Text, "System Name", "Local Interface", "Chassis ID", "Port ID")
		case cols.Len() == 4:
			m := cols.Cells(l.Text)
			if m[1] == "" {
				continue
			}
			n := swtele.Neighbor{System: m[0], LocalPort: m[1], ChassisID: m[2], Port: printable(m[3]), Protocol: "lldp"}
			n.ChassisMAC, _ = swtele.ParseMAC(m[3])
			port(st, n.LocalPort)
			st.dev.Neighbors = append(st.dev.Neighbors, n)
		default:
			continue
		}
		doc.Mark(l)
	}
}

// printable drops the bytes some neighbors put in their port ID.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '\uFFFD' {
			return -1
		}
		return r
	}, s)
}
