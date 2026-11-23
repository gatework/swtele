package comware

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/gatework/netops/neighbor"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// decodeLLDPList reuses the netops LLDP probe, which cross-checks its
// rows against an independent count; the list only sets the expected
// neighbor count for the verbose output, which carries every field.
func decodeLLDPList(doc *clidoc.Doc, st *state) {
	p, ok := neighbor.Lookup("h3c")
	if !ok {
		return
	}
	var b strings.Builder
	for _, l := range doc.Lines {
		b.WriteString(l.Text + "\n")
	}
	doc.Mark(doc.Lines...)
	st.lldpListed = lldpRows(doc)
	if ns, err := p.Parse(b.String()); err == nil && len(ns) == st.lldpListed {
		return
	}
	// netops does not know every layout yet (System Name first, or a Port
	// ID overflowing its column); the row count above stands.
	// TODO(netops): teach neighbor the other comware_lldp_list layouts.
}

// lldpRows counts the rows under the list header.
func lldpRows(doc *clidoc.Doc) int {
	n, in := 0, false
	for _, l := range doc.Lines {
		switch {
		case lldpListHead.MatchString(l.Text):
			in = true
		case in && lldpLocal.MatchString(l.Text):
			// a long system name may wrap onto a line without a local port
			n++
		}
	}
	return n
}

var (
	lldpLocal    = regexp.MustCompile(`(?:^|\s)(?:GE|XGE|FGE|HGE|WGE|SGE|MGE|M-GE|BAGG|RAGG)\d+(?:/\d+)+(?:\s|$)`)
	lldpListHead = regexp.MustCompile(`(?:Local Interface|LocalIf)\s.*(?:Chassis ID|chassis ID)`)
	lldpPort     = regexp.MustCompile(`^LLDP neighbor-information of port (\d+)\[(\S+)\]:\s*$`)
	lldpAgent    = regexp.MustCompile(`^LLDP agent (\S+):\s*$`)
	lldpKV       = regexp.MustCompile(`^ (\S[^:]*?)\s*:\s?(.*)$`)
	lldpCont     = regexp.MustCompile(`^\s{3,}\S`)
	lldpTLV      = regexp.MustCompile(`^\s{2,}(?:TLV OUI|TLV subtype|Index|TLV information)\s*:`)
)

func decodeLLDPVerbose(doc *clidoc.Doc, st *state) {
	var (
		cur      *swtele.Neighbor
		local    string
		lastKey  string
		verbose  []swtele.Neighbor
		localIdx = map[string]int{}
	)
	flush := func() {
		if cur != nil {
			verbose = append(verbose, *cur)
			cur = nil
		}
	}
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case lldpPort.MatchString(text):
			flush()
			m := lldpPort.FindStringSubmatch(text)
			local = m[2]
			if i := port(st, local); !i.Index.OK {
				i.Index = clidoc.Int(m[1])
			}
			localIdx[local]++
		case lldpAgent.MatchString(text):
			flush()
			agent := lldpAgent.FindStringSubmatch(text)[1]
			cur = &swtele.Neighbor{LocalPort: local, Protocol: "lldp"}
			if agent != "nearest-bridge" {
				cur.Protocol = "lldp-" + agent
			}
		case lldpTLV.MatchString(text):
			// organizationally specific TLVs without ledger value
		case cur != nil && lldpCont.MatchString(text):
			// a value wrapped onto the next line
			switch lastKey {
			case "system description":
				if cur.SysDesc != "" {
					cur.SysDesc += "\n"
				}
				cur.SysDesc += strings.TrimSpace(text)
			case "system capabilities enabled":
				lldpField(cur, lastKey, strings.TrimSpace(text))
			}
		case cur != nil && lldpKV.MatchString(text):
			m := lldpKV.FindStringSubmatch(text)
			lastKey = strings.ToLower(m[1])
			if lastKey == "lldp neighbor index" && (cur.ChassisID != "" || cur.System != "") {
				// another neighbor on the same port and agent
				proto := cur.Protocol
				flush()
				cur = &swtele.Neighbor{LocalPort: local, Protocol: proto}
			}
			lldpField(cur, lastKey, strings.TrimSpace(m[2]))
		case cur != nil && strings.HasPrefix(text, "  "):
			// sub-TLV detail (DCBX, PFC, ETS) without ledger value
		default:
			continue
		}
		doc.Mark(l)
	}
	flush()
	st.dev.Neighbors = append(st.dev.Neighbors, verbose...)
	if st.lldpListed > 0 {
		mismatch(doc, "lldp neighbors", st.lldpListed, len(verbose))
	}
}

func lldpField(n *swtele.Neighbor, key, value string) {
	if clidoc.Null(value) {
		return
	}
	switch key {
	case "chassis id":
		n.ChassisID = value
		if mac, err := swtele.ParseMAC(value); err == nil {
			n.ChassisMAC = mac
		}
	case "port id":
		n.Port = value
	case "port description":
		n.PortDesc = value
	case "system name":
		n.System = value
	case "system description":
		n.SysDesc = value
	case "system capabilities enabled":
		for c := range strings.SplitSeq(value, ",") {
			if c = strings.TrimSpace(c); c != "" {
				n.Capabilities = append(n.Capabilities, c)
			}
		}
	case "management address":
		if a, err := netip.ParseAddr(value); err == nil && !n.MgmtAddr.IsValid() {
			n.MgmtAddr = a
		}
	case "port vlan id(pvid)":
		n.PVID = clidoc.Int(value)
	}
}
