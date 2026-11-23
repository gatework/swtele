package nxos

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/parse"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// decodeStatus reads "Port Name Status Vlan Duplex Speed Type" sections.
// Name is truncated and may contain spaces, so cells are cut at header
// offsets.
func decodeStatus(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text):
		case strings.HasPrefix(text, "Port ") && strings.Contains(text, "Status"):
			c, ok := parse.HeaderColumns(text, "Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type")
			if !ok {
				continue
			}
			cols = c
		case cols.Len() > 0:
			if !statusRow(st, cols.Cells(text)) {
				continue
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

// statusRow fills an interface from one status row: Port, Name, Status,
// Vlan, Duplex, Speed, Type.
func statusRow(st *state, cells []string) bool {
	if cells[0] == "" {
		return false
	}
	i := port(st, cells[0])
	if i.Desc == "" && !clidoc.Null(cells[1]) {
		i.Desc = cells[1]
	}
	status := strings.ToLower(cells[2])
	if i.Oper == swtele.StateUnknown {
		i.Oper = swtele.StateDown
		if status == "connected" {
			i.Oper = swtele.StateUp
		}
	}
	if i.DownCause == swtele.CauseNone {
		i.DownCause = statusCause(status)
	}
	fill(&i.Speed, clidoc.Speed(cells[5]))
	if i.Media == "" && !clidoc.Null(cells[6]) {
		i.Media = cells[6]
	}
	if pvid := clidoc.Int(cells[3]); pvid.OK {
		sw := switching(i)
		if sw.Mode == swtele.ModeUnknown {
			sw.Mode = swtele.ModeAccess
		}
		fill(&sw.PVID, pvid)
	}
	return true
}

func statusCause(status string) swtele.DownCause {
	switch status {
	case "connected":
		return swtele.CauseNone
	case "notconnec", "notconnect", "down":
		return swtele.CauseNotConnected
	case "disabled":
		return swtele.CauseAdmin
	case "xcvrabsen", "sfpabsent":
		return swtele.CauseNoXcvr
	case "suspnd", "nooperme", "noopermem":
		return swtele.CauseSuspended
	case "err-disabled", "errdisable":
		return swtele.CauseErrDisabled
	}
	return swtele.CauseOther
}

func decodeDescription(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text):
		case strings.HasPrefix(text, "Interface ") && strings.Contains(text, "Description"):
			cols, _ = parse.HeaderColumns(text, "Interface", "Description")
		case strings.HasPrefix(text, "Port ") && strings.Contains(text, "Description"):
			cols, _ = parse.HeaderColumns(text, "Port", "Description")
		case cols.Len() > 0:
			cells := cols.Cells(text)
			if cells[0] == "" {
				continue
			}
			i := port(st, strings.Fields(cells[0])[0])
			if d := cells[len(cells)-1]; !clidoc.Null(d) {
				i.Desc = d
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

func decodeErrDisabled(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text):
		case strings.HasPrefix(text, "Port ") && strings.Contains(text, "Reason"):
			cols, _ = parse.HeaderColumns(text, "Port", "Name", "Status", "Reason")
		case cols.Len() > 0:
			cells := cols.Cells(text)
			if cells[0] == "" {
				continue
			}
			i := port(st, cells[0])
			i.Oper, i.DownCause = swtele.StateDown, swtele.CauseErrDisabled
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	vrfHeader = regexp.MustCompile(`^IP Interface Status for VRF "([^"]*)"`)
	ipRow     = regexp.MustCompile(`^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)$`)
	ipNoAddr  = regexp.MustCompile(`^(\S+)\s+(?:forward-enabled|unassigned|unnumbered.*)\s+\S+$`)
)

func decodeIPBrief(doc *clidoc.Doc, st *state) {
	vrf := ""
	for _, l := range doc.Lines {
		text := strings.TrimSpace(l.Text)
		switch {
		case text == "", strings.HasPrefix(text, "Interface ") && strings.Contains(text, "IP Address"):
		case vrfHeader.MatchString(text):
			vrf = vrfHeader.FindStringSubmatch(text)[1]
		case ipNoAddr.MatchString(text):
			port(st, ipNoAddr.FindStringSubmatch(text)[1])
		case ipRow.MatchString(text):
			m := ipRow.FindStringSubmatch(text)
			i := port(st, m[1])
			if vrf != "default" {
				i.VRF = vrf
			}
			if len(i.Addresses) == 0 {
				if a, err := netip.ParseAddr(m[2]); err == nil {
					i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: netip.PrefixFrom(a, 32), Primary: true})
				}
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

// decodeCounters joins the column sections of show interface counters.
func decodeCounters(doc *clidoc.Doc, st *state) {
	columnSections(doc, func(col, name, value string) {
		i := port(st, name)
		v := clidoc.Uint(value)
		switch col {
		case "InOctets":
			fill(&i.Counters.In.Octets, v)
		case "InUcastPkts":
			fill(&i.Counters.In.Unicast, v)
		case "InMcastPkts":
			fill(&i.Counters.In.Multicst, v)
		case "InBcastPkts":
			fill(&i.Counters.In.Bcast, v)
		case "OutOctets":
			fill(&i.Counters.Out.Octets, v)
		case "OutUcastPkts":
			fill(&i.Counters.Out.Unicast, v)
		case "OutMcastPkts":
			fill(&i.Counters.Out.Multicst, v)
		case "OutBcastPkts":
			fill(&i.Counters.Out.Bcast, v)
		}
	})
}

func decodeErrors(doc *clidoc.Doc, st *state) {
	columnSections(doc, func(col, name, value string) {
		i := port(st, name)
		v := clidoc.Uint(value)
		switch col {
		case "FCS-Err":
			fill(&i.Counters.CRC, v)
		case "Rcv-Err":
			fill(&i.Counters.In.Errors, v)
		case "Xmit-Err":
			fill(&i.Counters.Out.Errors, v)
		case "OutDiscards":
			fill(&i.Counters.Out.Discards, v)
		case "InDiscards":
			fill(&i.Counters.In.Discards, v)
		case "Runts":
			fill(&i.Counters.Runts, v)
		case "Giants":
			fill(&i.Counters.Giants, v)
		case "Late-Col":
			fill(&i.Counters.LateColl, v)
		case "Stomped-CRC":
			fill(&i.Counters.StompedCRC, v)
		case "Align-Err":
			fill(&i.Counters.Frame, v)
		}
	})
}

// columnSections reads tables whose header is "Port <col>...": every row
// is a port name followed by one value per column.
func columnSections(doc *clidoc.Doc, cell func(col, port, value string)) {
	var cols []string
	for _, l := range doc.Lines {
		text := l.Text
		f := strings.Fields(text)
		switch {
		case blank(text), clidoc.Rule(text):
		case len(f) > 1 && f[0] == "Port":
			cols = f[1:]
		case len(cols) > 0 && len(f) == len(cols)+1:
			for n, c := range cols {
				cell(c, f[0], f[n+1])
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	pcLegend = regexp.MustCompile(`^(?:Flags:|\s+[A-Za-z] - |\s+Channel\s*$|Group Port-)`)
	pcRow    = regexp.MustCompile(`^(\d+)\s+(Po\d+)\((\w+)\)\s+(\S+)\s+(\S+)\s*(.*)$`)
	pcMember = regexp.MustCompile(`(\S+?)\((\w+)\)`)
)

func decodePortChannel(doc *clidoc.Doc, st *state) {
	var cur *swtele.Aggregate
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text), pcLegend.MatchString(text):
		case pcRow.MatchString(text):
			m := pcRow.FindStringSubmatch(text)
			a := swtele.Aggregate{Name: longName(m[2]), Mode: swtele.AggStatic}
			if m[5] == "LACP" {
				a.Mode = swtele.AggLACP
			}
			port(st, a.Name).Kind = swtele.KindAggregate
			st.dev.Aggregates = append(st.dev.Aggregates, a)
			cur = &st.dev.Aggregates[len(st.dev.Aggregates)-1]
			members(cur, m[6])
		case cur != nil && strings.HasPrefix(text, " ") && pcMember.MatchString(text):
			members(cur, text)
		default:
			continue
		}
		doc.Mark(l)
	}
}

func members(a *swtele.Aggregate, text string) {
	for _, m := range pcMember.FindAllStringSubmatch(text, -1) {
		a.Members = append(a.Members, swtele.AggMember{Port: longName(m[1]), Status: m[2], Selected: m[2] == "P"})
	}
}

var (
	ospfProcess = regexp.MustCompile(`^\s*OSPF Process ID (\S+) VRF (\S+)`)
	ospfRow     = regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+/\s*\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)
	ospfInfo    = regexp.MustCompile(`^\s*(?:Total number of neighbors|Neighbor ID\s+Pri)`)
)

func decodeOSPF(doc *clidoc.Doc, st *state) {
	process, vrf := "", ""
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), ospfInfo.MatchString(l.Text):
		case ospfProcess.MatchString(l.Text):
			m := ospfProcess.FindStringSubmatch(l.Text)
			process, vrf = m[1], m[2]
		case ospfRow.MatchString(l.Text):
			m := ospfRow.FindStringSubmatch(l.Text)
			state := strings.ReplaceAll(m[3], " ", "")
			p := swtele.Peer{Proto: swtele.ProtoOSPF, Process: process, VRF: vrf, RouterID: m[1], State: state,
				Up: clidoc.Duration(m[4]), Interface: longName(m[6])}
			p.Address, _ = netip.ParseAddr(m[5])
			s := strings.ToUpper(state)
			p.Established = strings.HasPrefix(s, "FULL") || s == "2WAY/DROTHER"
			st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	bgpVRF  = regexp.MustCompile(`^BGP summary information for VRF (\S+), address family (.+)$`)
	bgpHead = regexp.MustCompile(`^Neighbor\s+V\s+AS\s+MsgRcvd`)
	bgpRow  = regexp.MustCompile(`^(\S+)\s+4\s+(\S+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*$`)
	bgpInfo = regexp.MustCompile(`^(?:BGP router identifier|BGP table version|\d+ network entries|BGP attribute entries|BGP community entries|\d+ received paths|\d+ identical|Neighbor\s+T\s+AS|Dampening|History paths|BGP AS path|.*\s+(?:I|E)\s+\d+\s+\d+\s+\d+)`)
)

func decodeBGP(doc *clidoc.Doc, st *state) {
	vrf, family, inTable := "", "", false
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text):
			inTable = false
		case bgpVRF.MatchString(text):
			m := bgpVRF.FindStringSubmatch(text)
			vrf, family = m[1], strings.ToLower(m[2])
		case bgpHead.MatchString(text):
			inTable = true
		case inTable && bgpRow.MatchString(text):
			m := bgpRow.FindStringSubmatch(text)
			addr, err := netip.ParseAddr(m[1])
			if err != nil {
				continue
			}
			p := swtele.Peer{Proto: swtele.ProtoBGP, VRF: vrf, Family: family, Address: addr, AS: m[2], Up: clidoc.Duration(m[3])}
			if n := clidoc.Int(m[4]); n.OK {
				p.State, p.Prefixes, p.Established = "Established", n, true
			} else {
				p.State = m[4]
			}
			st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		case bgpInfo.MatchString(text):
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	arpLegend = regexp.MustCompile(`^(?:Flags:|\s+[*+#D] - |\s+(?:CP|PS|RO) - |IP ARP Table|Total number of entries)`)
	arpHead   = regexp.MustCompile(`^Address\s+Age\s+MAC Address\s+Interface`)
	arpRow    = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$`)
)

func decodeARP(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), arpLegend.MatchString(text), arpHead.MatchString(text):
		case arpRow.MatchString(text):
			m := arpRow.FindStringSubmatch(text)
			e := swtele.ARPEntry{Interface: longName(m[4]), Kind: strings.TrimSpace(m[5])}
			e.IP, _ = netip.ParseAddr(m[1])
			if mac, err := swtele.ParseMAC(m[3]); err == nil {
				e.MAC = mac
			} else {
				e.Incomplete = true
			}
			e.Age = arpAge(m[2])
			if id, ok := strings.CutPrefix(e.Interface, "Vlan"); ok {
				e.VLAN = clidoc.Int(id).Or(0)
			}
			st.dev.L3.ARP = append(st.dev.L3.ARP, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}

// arpAge parses "00:02:50" or the fractional seconds some releases print.
func arpAge(s string) swtele.Opt[time.Duration] {
	if strings.Contains(s, ":") {
		return clidoc.Duration(s)
	}
	if f := clidoc.Float(s); f.OK {
		return swtele.Some(time.Duration(f.V * float64(time.Second)))
	}
	return swtele.Opt[time.Duration]{}
}

var (
	macLegend = regexp.MustCompile(`^(?:Legend:|\s+TL - True Learned|\s+\* - primary|\s+age - seconds|\s+\(T\) - True|\s+\(NA\)- Not|\s+VLAN\s+MAC Address)`)
	macRow    = regexp.MustCompile(`^([*+GCO ]?)\s*(\d+|-)\s+([0-9a-fA-F.]{14})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$`)
	nveRemote = regexp.MustCompile(`^nve\d+\((\S+)\)$`)
)

func decodeMAC(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text), macLegend.MatchString(text), strings.HasPrefix(text, "---------+"):
		case macRow.MatchString(text):
			m := macRow.FindStringSubmatch(text)
			mac, err := swtele.ParseMAC(m[3])
			if err != nil {
				continue
			}
			e := swtele.MACEntry{MAC: mac, VLAN: clidoc.Int(m[2]).Or(0), Port: longName(m[8])}
			switch {
			case m[1] == "G" || strings.Contains(m[8], "sup-eth") || strings.Contains(m[8], "(R)"):
				e.Kind = swtele.MACSystem
			case nveRemote.MatchString(m[8]):
				e.Kind = swtele.MACRemote
				e.Remote, _ = netip.ParseAddr(nveRemote.FindStringSubmatch(m[8])[1])
			case m[4] == "static":
				e.Kind = swtele.MACStatic
			default:
				e.Kind = swtele.MACDynamic
			}
			st.dev.L2.MACs = append(st.dev.L2.MACs, e)
		default:
			continue
		}
		doc.Mark(l)
	}
}
