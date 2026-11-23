package comware

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// legend matches the key lines Comware prints above its tables.
var legend = regexp.MustCompile(`^\s*(?:Brief information on interfaces in (?:route|bridge) mode:|Link: ADM|Protocol: \(s\)|Speed: \(a\)|Duplex: \(a\)|Type: A - access|\*down: administratively down|\(s\): spoofing|Usage: Bandwidth utilization|Type: S-Static|Chassis ID : \*|\s+# -- -- Nearest|\s+Default -- -- Nearest|\s+(?:Default|#) -- -- |\s*Overflow: More than \d+ digits|\s*--: Not supported\.)`)

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func decodeBrief(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(legend)
	route := clidoc.Header{"Interface", "Link", "Protocol"}
	bridge := clidoc.Header{"Interface", "Link", "Speed", "Duplex", "Type", "PVID"}
	from := 0
	for {
		t, next, ok := doc.FindTable(from, blank, bridge, route)
		if !ok {
			return
		}
		from = next
		for _, row := range t.Rows {
			if t.Variant == 0 {
				briefBridgeRow(doc, st, row.Text)
			} else {
				briefRouteRow(st, row.Text)
			}
			doc.Mark(row)
		}
	}
}

func briefRouteRow(st *state, row string) {
	f := clidoc.Fields(row, 5)
	if len(f) < 3 {
		return
	}
	i := port(st, f[0])
	setLink(i, f[1])
	if i.Protocol == swtele.StateUnknown {
		i.Protocol = upDown(f[2])
	}
	if len(f) > 4 && i.Desc == "" {
		i.Desc = f[4]
	}
}

func briefBridgeRow(_ *clidoc.Doc, st *state, row string) {
	f := clidoc.Fields(row, 7)
	if len(f) < 6 {
		return
	}
	i := port(st, f[0])
	setLink(i, f[1])
	if !i.Speed.OK {
		i.Speed = clidoc.Speed(f[2])
	}
	i.AutoSpeed = swtele.Some(strings.Contains(f[2], "(a)") || strings.EqualFold(f[2], "auto"))
	if i.Duplex == swtele.DuplexUnknown {
		switch {
		case strings.HasPrefix(f[3], "F"):
			i.Duplex = swtele.DuplexFull
		case strings.HasPrefix(f[3], "H"):
			i.Duplex = swtele.DuplexHalf
		}
	}
	sw := switching(i)
	if sw.Mode == swtele.ModeUnknown {
		switch f[4] {
		case "A":
			sw.Mode = swtele.ModeAccess
		case "T":
			sw.Mode = swtele.ModeTrunk
		case "H":
			sw.Mode = swtele.ModeHybrid
		}
	}
	if !sw.PVID.OK {
		sw.PVID = clidoc.Int(f[5])
	}
	if len(f) > 6 && (i.Desc == "" || len(f[6]) > len(i.Desc)) {
		i.Desc = f[6]
	}
}

func setLink(i *swtele.Interface, link string) {
	if i.Oper != swtele.StateUnknown {
		return
	}
	switch strings.ToUpper(link) {
	case "UP":
		i.Admin, i.Oper = swtele.StateUp, swtele.StateUp
	case "DOWN":
		i.Admin, i.Oper = swtele.StateUp, swtele.StateDown
	case "ADM":
		i.Admin, i.Oper, i.DownCause = swtele.StateDown, swtele.StateDown, swtele.CauseAdmin
	case "STBY":
		i.Oper = swtele.StateStandby
	}
}

func decodeBriefDown(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(legend)
	from := 0
	for {
		t, next, ok := doc.FindTable(from, blank, clidoc.Header{"Interface", "Link", "Cause"})
		if !ok {
			return
		}
		from = next
		for _, row := range t.Rows {
			f := clidoc.Fields(row.Text, 3)
			if len(f) < 2 {
				continue
			}
			i := port(st, f[0])
			setLink(i, f[1])
			cause := ""
			if len(f) == 3 {
				cause = strings.ToLower(f[2])
			}
			if i.DownCause == swtele.CauseNone {
				i.DownCause = downCause(cause)
			}
			doc.Mark(row)
		}
	}
}

func downCause(cause string) swtele.DownCause {
	switch {
	case cause == "":
		return swtele.CauseNone
	case strings.HasPrefix(cause, "not connected"):
		return swtele.CauseNotConnected
	case strings.HasPrefix(cause, "administratively"):
		return swtele.CauseAdmin
	case strings.HasPrefix(cause, "stp"):
		return swtele.CauseSTP
	case strings.Contains(cause, "link-aggregation"):
		return swtele.CauseAggregate
	}
	return swtele.CauseOther
}

func decodeIPBrief(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(legend)
	t, _, ok := doc.FindTable(0, blank, clidoc.Header{"Interface", "Physical", "Protocol", "IP"})
	if !ok {
		return
	}
	for _, row := range t.Rows {
		f := strings.Fields(row.Text)
		if len(f) < 4 {
			continue
		}
		i := port(st, f[0])
		if i.Oper == swtele.StateUnknown {
			i.Oper = upDown(f[1])
			if strings.HasPrefix(f[1], "*") {
				i.Admin, i.DownCause = swtele.StateDown, swtele.CauseAdmin
			}
		}
		if i.Protocol == swtele.StateUnknown {
			i.Protocol = upDown(f[2])
		}
		if len(i.Addresses) == 0 {
			if p, ok := addrCell(f[3]); ok {
				i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: p, Primary: true})
			}
		}
		if len(f) > 4 && !clidoc.Null(f[4]) && t.Header.Text != "" && strings.Contains(t.Header.Text, "VPN") {
			i.VRF = f[4]
		}
		doc.Mark(row)
	}
}

// addrCell parses "10.0.0.1" (as a host prefix) or "10.0.0.1/24".
func addrCell(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func decodeCounts(in bool) func(*clidoc.Doc, *state) {
	return func(doc *clidoc.Doc, st *state) {
		doc.MarkMatching(legend)
		t, _, ok := doc.FindTable(0, blank, clidoc.Header{"Interface", "Total (pkts)", "Broadcast", "Multicast", "Err"})
		if !ok {
			return
		}
		for _, row := range t.Rows {
			f := strings.Fields(row.Text)
			if len(f) != 5 {
				continue
			}
			i := port(st, f[0])
			dir := &i.Counters.Out
			if in {
				dir = &i.Counters.In
			}
			fill(&dir.Packets, clidoc.Uint(f[1]))
			fill(&dir.Bcast, clidoc.Uint(f[2]))
			fill(&dir.Multicst, clidoc.Uint(f[3]))
			fill(&dir.Errors, clidoc.Uint(f[4]))
			doc.Mark(row)
		}
	}
}

func decodeRates(in bool) func(*clidoc.Doc, *state) {
	return func(doc *clidoc.Doc, st *state) {
		doc.MarkMatching(legend)
		t, _, ok := doc.FindTable(0, blank, clidoc.Header{"Interface", "Usage", "Total"}, clidoc.Header{"Interface", "Total"})
		if !ok {
			return
		}
		total := 2 - t.Variant // the second spelling has no Usage column
		for _, row := range t.Rows {
			f := strings.Fields(row.Text)
			if len(f) <= total {
				continue
			}
			i := port(st, f[0])
			if in {
				fill(&i.Rates.InPps, clidoc.Float(f[total]))
			} else {
				fill(&i.Rates.OutPps, clidoc.Float(f[total]))
			}
			doc.Mark(row)
		}
	}
}

// fill sets dst from v when dst is absent: display interface is the
// preferred source and decoded first.
func fill[T any](dst *swtele.Opt[T], v swtele.Opt[T]) {
	if !dst.OK {
		*dst = v
	}
}

func decodeFlapProtection(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(regexp.MustCompile(`^Link-flap protection: `))
	t, _, ok := doc.FindTable(0, blank, clidoc.Header{"Interface", "Link-flap", "Status"})
	if !ok {
		return
	}
	for _, row := range t.Rows {
		f := strings.Fields(row.Text)
		if len(f) < 3 {
			continue
		}
		port(st, f[0])
		doc.Mark(row)
	}
}

func decodeSTPDown(doc *clidoc.Doc, st *state) {
	t, _, ok := doc.FindTable(0, blank, clidoc.Header{"Down Port", "Reason"})
	if !ok {
		return
	}
	for _, row := range t.Rows {
		f := clidoc.Fields(row.Text, 2)
		if len(f) < 1 {
			continue
		}
		p := swtele.STPPort{Port: longName(f[0]), Down: true}
		if len(f) == 2 {
			p.Reason = f[1]
		}
		st.dev.L2.STP.Ports = append(st.dev.L2.STP.Ports, p)
		doc.Mark(row)
	}
}

// arpHeaders are the spellings of the ARP table header across releases.
var arpHeader = regexp.MustCompile(`^IP [Aa]ddress\s+MAC [Aa]ddress\s+(?:VLAN/VSI name|VLAN/VSI|VLAN|VID)\s+Interface`)

func decodeARP(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(legend)
	in := false
	for _, l := range doc.Lines {
		switch {
		case arpHeader.MatchString(strings.TrimSpace(l.Text)):
			in = true
			doc.Mark(l)
			continue
		case !in, blank(l.Text):
			continue
		}
		f := strings.Fields(l.Text)
		if len(f) < 6 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		e := swtele.ARPEntry{IP: ip, Interface: longName(f[3]), Kind: f[len(f)-1]}
		if mac, err := swtele.ParseMAC(f[1]); err == nil {
			e.MAC = mac
		} else {
			e.Incomplete = true
		}
		e.VLAN = clidoc.Int(f[2]).Or(0)
		if age := clidoc.Int(f[4]); age.OK {
			e.Age = swtele.Some(time.Duration(age.V) * time.Minute)
		}
		st.dev.L3.ARP = append(st.dev.L3.ARP, e)
		doc.Mark(l)
	}
}

var macHeader = regexp.MustCompile(`^MAC Address\s+VLAN ID\s+State\s+Port`)

func decodeMAC(doc *clidoc.Doc, st *state) {
	in := false
	for _, l := range doc.Lines {
		switch {
		case macHeader.MatchString(strings.TrimSpace(l.Text)):
			in = true
			doc.Mark(l)
			continue
		case !in, blank(l.Text):
			continue
		}
		f := strings.Fields(l.Text)
		if len(f) < 4 {
			continue
		}
		mac, err := swtele.ParseMAC(f[0])
		if err != nil {
			continue
		}
		e := swtele.MACEntry{MAC: mac, VLAN: clidoc.Int(f[1]).Or(0), Port: longName(f[3]), Kind: macKind(f[2])}
		st.dev.L2.MACs = append(st.dev.L2.MACs, e)
		doc.Mark(l)
	}
}

func macKind(state string) swtele.MACKind {
	switch strings.ToLower(state) {
	case "learned", "client":
		return swtele.MACDynamic
	case "config", "static":
		return swtele.MACStatic
	case "dot1x", "auth", "mac-auth", "portsecurity":
		return swtele.MACAuth
	case "blocked", "blackhole":
		return swtele.MACBlocked
	}
	return swtele.MACOther
}

var (
	ospfProcess = regexp.MustCompile(`^\s*OSPF Process (\d+) with Router ID (\S+)`)
	ospfArea    = regexp.MustCompile(`^\s*Area: (\S+)`)
	ospfHeader  = regexp.MustCompile(`^\s*Router ID\s+Address\s+Pri\s+Dead-Time\s+State\s+Interface`)
	ospfRow     = regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+/\s*\S+)\s+(\S+)\s*$`)
	ospfLegend  = regexp.MustCompile(`^\s*(?:Neighbor Brief Information|OSPF is not configured\.|Area: )`)
)

func decodeOSPF(doc *clidoc.Doc, st *state) {
	process, area := "", ""
	doc.MarkMatching(ospfLegend)
	for _, l := range doc.Lines {
		if m := ospfProcess.FindStringSubmatch(l.Text); m != nil {
			process = m[1]
			doc.Mark(l)
			continue
		}
		if m := ospfArea.FindStringSubmatch(l.Text); m != nil {
			area = m[1]
			continue
		}
		if ospfHeader.MatchString(l.Text) {
			doc.Mark(l)
			continue
		}
		m := ospfRow.FindStringSubmatch(l.Text)
		if m == nil {
			continue
		}
		state := strings.ReplaceAll(m[5], " ", "")
		p := swtele.Peer{Proto: swtele.ProtoOSPF, Process: process, Area: area, RouterID: m[1], State: state, Interface: longName(m[6])}
		p.Address, _ = netip.ParseAddr(m[2])
		p.Established = ospfUp(state)
		st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		doc.Mark(l)
	}
}

// ospfUp accepts Full, and 2-Way between two DROthers.
func ospfUp(state string) bool {
	s := strings.ToLower(state)
	return strings.HasPrefix(s, "full") || s == "2-way/drother"
}

var (
	bgpHeader = regexp.MustCompile(`^\s*\*?\s*Peer\s+AS\s+MsgRcvd\s+MsgSent\s+OutQ\s+PrefRcv\s+Up/Down\s+State`)
	bgpRow    = regexp.MustCompile(`^\s*\*?\s*(\S+)\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\S+)\s+(\S+)\s*$`)
	bgpInfo   = regexp.MustCompile(`^\s*(?:BGP local router ID|Local AS number|Total number of peers|\* - Dynamically created peer|\^ - Peer created|Peers in established state)`)
)

func decodeBGP(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(bgpInfo)
	doc.MarkMatching(bgpHeader)
	for _, l := range doc.Lines {
		m := bgpRow.FindStringSubmatch(l.Text)
		if m == nil {
			continue
		}
		addr, err := netip.ParseAddr(m[1])
		if err != nil {
			continue
		}
		p := swtele.Peer{Proto: swtele.ProtoBGP, Family: "ipv4", Address: addr, AS: m[2], State: m[5]}
		p.Prefixes = clidoc.Int(m[3])
		p.Up = bgpUptime(m[4])
		p.Established = strings.EqualFold(m[5], "Established")
		st.dev.L3.Peers = append(st.dev.L3.Peers, p)
		doc.Mark(l)
	}
}

// bgpUptime parses "0568h44m"; "****h00m" overflows at 9999 hours and is
// reported as that bound.
func bgpUptime(s string) swtele.Opt[time.Duration] {
	if strings.HasPrefix(s, "****h") {
		return swtele.Some(9999 * time.Hour)
	}
	return clidoc.Duration(s)
}

// count is a small helper for cross-checks.
func mismatch(doc *clidoc.Doc, what string, want, got int) {
	if want != got {
		doc.Issue(clidoc.IssueMismatch, nil, evidence.Field{Key: "what", Value: what})
	}
}
