package panos

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// decodeLACP accepts an empty answer (no aggregate group); groups are not
// decoded yet and stay unparsed.
func decodeLACP(doc *clidoc.Doc, _ *state) {
	for _, l := range doc.Lines {
		if blank(l.Text) {
			doc.Mark(l)
		}
	}
}

var (
	monCore    = regexp.MustCompile(`^core(\s+\d+)+\s*$`)
	monSample  = regexp.MustCompile(`^\s+([*\d]+\s+)*[*\d]+\s*$`)
	monSection = regexp.MustCompile(`^(?:Resource monitoring sampling data|CPU load sampling by group:|CPU load \(%\) during last|Resource utilization \(%\) during last|[a-z][a-z ]*:\s*$|[a-z_]+\s+:\s+\d+%)`)
)

// decodeMonitor reads the data-plane cores of the latest sample: the mean
// of the cores in use (management cores print "*").
func decodeMonitor(doc *clidoc.Doc, st *state) {
	inCores, done := false, false
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), monSection.MatchString(text):
			if strings.HasPrefix(text, "Resource utilization") {
				inCores = false
			}
		case monCore.MatchString(text):
			inCores = true
		case monSample.MatchString(text):
			if inCores && !done {
				sum, n := 0.0, 0
				for f := range strings.FieldsSeq(text) {
					if v := clidoc.Float(f); v.OK {
						sum += v.V
						n++
					}
				}
				if n > 0 {
					st.dev.System.CPU = append(st.dev.System.CPU, swtele.CPULoad{Unit: swtele.Unit{Slot: 1}, Now: swtele.Some(sum / float64(n))})
				}
				done = true
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	topCPU  = regexp.MustCompile(`^%Cpu\(s\):.*?([\d.]+) id`)
	topMem  = regexp.MustCompile(`^MiB Mem\s*:\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used`)
	topAvl  = regexp.MustCompile(`^MiB Swap:.*?([\d.]+) avail Mem`)
	topSkip = regexp.MustCompile(`^(?:top - |Tasks:|MiB Swap:|\s*PID\s+USER|\s*\d+\s+\S*\s+-?\d+|\s*\d+\s+-?\d+\s+-?\d+)`)
)

// decodeResources reads the management plane from top: CPU busy and
// memory, with the available memory as the free share.
func decodeResources(doc *clidoc.Doc, st *state) {
	mem := swtele.MemoryUsage{Unit: swtele.Unit{Slot: 0}}
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text):
		case topCPU.MatchString(text):
			idle := clidoc.Float(topCPU.FindStringSubmatch(text)[1])
			st.dev.System.CPU = append(st.dev.System.CPU, swtele.CPULoad{Unit: swtele.Unit{Slot: 0}, Now: swtele.Some(100 - idle.V)})
		case topMem.MatchString(text):
			m := topMem.FindStringSubmatch(text)
			mib := func(s string) swtele.Opt[uint64] { return swtele.Some(uint64(clidoc.Float(s).V * 1024 * 1024)) }
			mem.Total, mem.Free, mem.Used = mib(m[1]), mib(m[2]), mib(m[3])
		case topAvl.MatchString(text):
			if avail := clidoc.Float(topAvl.FindStringSubmatch(text)[1]); avail.OK && mem.Total.V > 0 {
				mem.FreeRatio = swtele.Some(avail.V * 1024 * 1024 * 100 / float64(mem.Total.V))
			}
		case topSkip.MatchString(text):
		default:
			continue
		}
		doc.Mark(l)
	}
	st.dev.System.Memory = append(st.dev.System.Memory, mem)
}

var (
	envRow  = regexp.MustCompile(`^\s*(S\d+)\s+(.+?)\s+(True|False)\s+(-?[\d.]+)\s+(-?[\d.]+)(?:\s+(-?[\d.]+))?\s*$`)
	envInfo = regexp.MustCompile(`^(?:----\w+----|Slot\s+Description)`)
)

// decodeEnv reads one environment table: temperatures become sensors,
// fans and power rails components judged by their alarm flag.
func decodeEnv(kind string) func(*clidoc.Doc, *state) {
	return func(doc *clidoc.Doc, st *state) {
		sys := &st.dev.System
		for _, l := range doc.Lines {
			switch {
			case blank(l.Text), envInfo.MatchString(l.Text):
			case envRow.MatchString(l.Text):
				m := envRow.FindStringSubmatch(l.Text)
				ok := swtele.Some(m[3] == "False")
				switch kind {
				case "thermal":
					s := swtele.Sensor{Name: m[2], Value: clidoc.Float(m[4]), Lower: clidoc.Float(m[5]), Alarm: clidoc.Float(m[6])}
					sys.Sensors = append(sys.Sensors, s)
				case "fans":
					sys.Fans = append(sys.Fans, swtele.Component{ID: m[2], Status: m[4] + " RPM", OK: ok})
				default:
					sys.PSUs = append(sys.PSUs, swtele.Component{ID: m[2], Status: m[4] + " V", OK: ok})
				}
			default:
				continue
			}
			doc.Mark(l)
		}
	}
}

var (
	ospfLegend = regexp.MustCompile(`^\s+(?:Options:|N/P:NSSA)`)
	ospfRow    = regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)`)
)

// decodeOSPF reads neighbor rows; the options legend is accounted for.
func decodeOSPF(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), ospfLegend.MatchString(l.Text):
		case ospfRow.MatchString(l.Text):
			m := ospfRow.FindStringSubmatch(l.Text)
			p := swtele.Peer{Proto: swtele.ProtoOSPF, RouterID: m[2], State: m[4], VRF: m[3]}
			p.Address, _ = netip.ParseAddr(m[1])
			p.Established = strings.EqualFold(p.State, "full")
			st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		default:
			continue
		}
		doc.Mark(l)
	}
}

// decodeBGP accepts an empty summary (BGP not running); peers are not
// decoded yet and stay unparsed.
func decodeBGP(doc *clidoc.Doc, _ *state) {
	for _, l := range doc.Lines {
		if blank(l.Text) {
			doc.Mark(l)
		}
	}
}

var (
	arpRow  = regexp.MustCompile(`^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17}|\(incomplete\))\s+(\S+)\s+([scei])\s+(\d+)\s*$`)
	tblInfo = regexp.MustCompile(`^(?:maximum of entries supported|default timeout|total (?:ARP|MAC) entries|status: s - static|interface\s+ip address|vlan\s+hw address|-{10,})`)
	macRow  = regexp.MustCompile(`^(\S+)\s+([0-9a-f:]{17})\s+(\S+)\s+([sci])\s+(\d+)\s*$`)
)

func decodeARP(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), tblInfo.MatchString(l.Text):
		case arpRow.MatchString(l.Text):
			m := arpRow.FindStringSubmatch(l.Text)
			e := swtele.ARPEntry{Interface: m[1], Kind: m[5]}
			e.IP, _ = netip.ParseAddr(m[2])
			if mac, err := swtele.ParseMAC(m[3]); err == nil {
				e.MAC = mac
			} else {
				e.Incomplete = true
			}
			if ttl := clidoc.Int(m[6]); ttl.OK {
				e.Age = swtele.Some(time.Duration(ttl.V) * time.Second)
			}
			if vlan, ok := strings.CutPrefix(m[1], "vlan."); ok {
				e.VLAN = clidoc.Int(vlan).Or(0)
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
		case blank(l.Text), tblInfo.MatchString(l.Text):
		case macRow.MatchString(l.Text):
			m := macRow.FindStringSubmatch(l.Text)
			mac, err := swtele.ParseMAC(m[2])
			if err != nil {
				continue
			}
			kind := swtele.MACDynamic
			if m[4] == "s" {
				kind = swtele.MACStatic
			}
			st.dev.L2.MACs = append(st.dev.L2.MACs, swtele.MACEntry{MAC: mac, Port: m[3], Kind: kind})
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	logRow  = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(\S+)\s+(\S*)\s+(\S+)\s+(\d+)\s+(.*)$`)
	logInfo = regexp.MustCompile(`^(?:Time\s+Severity|={10,})`)
)

var severities = map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5, "informational": 6}

func decodeLog(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), logInfo.MatchString(l.Text):
		case logRow.MatchString(l.Text):
			m := logRow.FindStringSubmatch(l.Text)
			e := swtele.LogEvent{Module: m[3], Severity: severities[m[2]], Mnemonic: m[5], Text: strings.TrimSpace(m[7])}
			if t, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], st.loc); err == nil {
				e.At = swtele.Some(t.UTC())
			}
			st.dev.Logs = append(st.dev.Logs, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var lldpKV = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z ]*?)\s*:\s*(.*)$`)

// decodeLLDP reads "Local information:" blocks and the neighbor fields
// that follow "Neighbor information:".
func decodeLLDP(doc *clidoc.Doc, st *state) {
	var cur *swtele.Neighbor
	local := ""
	flush := func() {
		if cur != nil && (cur.ChassisID != "" || cur.System != "") {
			st.dev.Neighbors = append(st.dev.Neighbors, *cur)
		}
		cur = nil
	}
	for _, l := range doc.Lines {
		text := strings.TrimSpace(l.Text)
		switch {
		case text == "":
		case text == "Local information:":
			flush()
		case text == "Neighbor information:":
			cur = &swtele.Neighbor{LocalPort: local, Protocol: "lldp"}
		case lldpKV.MatchString(text):
			m := lldpKV.FindStringSubmatch(text)
			key, value := strings.ToLower(m[1]), strings.TrimSpace(m[2])
			switch {
			case key == "local interface":
				local = value
				port(st, value)
			case cur == nil:
			case key == "chassis id":
				cur.ChassisID = value
				cur.ChassisMAC, _ = swtele.ParseMAC(value)
			case key == "port id":
				cur.Port = value
			case key == "system name":
				cur.System = value
			case key == "port description":
				cur.PortDesc = value
			case strings.HasPrefix(key, "management address"):
				cur.MgmtAddr, _ = netip.ParseAddr(value)
			}
		case strings.HasPrefix(text, "Index "):
		default:
			continue
		}
		doc.Mark(l)
	}
	flush()
}
