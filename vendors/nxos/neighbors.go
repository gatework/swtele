package nxos

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	lldpStart  = regexp.MustCompile(`^Chassis id: (.*)$`)
	lldpKV     = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 /()\[\]:-]*?)\s*:\s?(.*)$`)
	lldpLegend = regexp.MustCompile(`^(?:\[Vlan ID: Vlan Name\]|Capability codes:|\s+\([A-Z]\) |Device ID\s+Local Intf|Total entries displayed)`)
)

func decodeLLDP(doc *clidoc.Doc, st *state) {
	pre, blocks := doc.Blocks(lldpStart.MatchString)
	for _, l := range pre {
		if blank(l.Text) || lldpLegend.MatchString(l.Text) {
			doc.Mark(l)
		}
	}
	for _, block := range blocks {
		n := swtele.Neighbor{Protocol: "lldp"}
		inDesc := false
		for _, l := range block {
			text := l.Text
			if lldpLegend.MatchString(text) || blank(text) {
				doc.Mark(l)
				continue
			}
			if strings.HasPrefix(text, "Time remaining:") {
				inDesc = false
			}
			if inDesc {
				n.SysDesc += "\n" + strings.TrimSpace(text)
				doc.Mark(l)
				continue
			}
			m := lldpKV.FindStringSubmatch(text)
			if m == nil {
				continue
			}
			if lldpField(&n, strings.ToLower(m[1]), strings.TrimSpace(m[2])) {
				inDesc = true
			}
			doc.Mark(l)
		}
		if n.LocalPort != "" {
			port(st, n.LocalPort)
			st.dev.Neighbors = append(st.dev.Neighbors, n)
		}
	}
}

// lldpField sets one field of n; it reports the start of the system
// description, which continues on the following lines.
func lldpField(n *swtele.Neighbor, key, value string) (description bool) {
	switch key {
	case "chassis id":
		n.ChassisID = value
		n.ChassisMAC, _ = swtele.ParseMAC(value)
	case "port id":
		n.Port = value
	case "local port id":
		n.LocalPort = longName(value)
	case "port description":
		n.PortDesc = nonNull(value)
	case "system name":
		n.System = nonNull(value)
	case "system description":
		n.SysDesc = value
		return true
	case "enabled capabilities":
		for c := range strings.SplitSeq(value, ",") {
			if c = strings.TrimSpace(c); c != "" {
				n.Capabilities = append(n.Capabilities, c)
			}
		}
	case "management address":
		if a, err := netip.ParseAddr(value); err == nil {
			n.MgmtAddr = a
		}
	case "vlan id":
		n.PVID = clidoc.Int(value)
	}
	return false
}

func nonNull(s string) string {
	if clidoc.Null(s) || strings.EqualFold(s, "not advertised") || s == "null" {
		return ""
	}
	return s
}

var (
	cdpStart  = regexp.MustCompile(`^Device ID:\s*(.*)$`)
	cdpIntf   = regexp.MustCompile(`^Interface: (\S+), Port ID \(outgoing port\): (\S+)`)
	cdpPlat   = regexp.MustCompile(`^Platform: ([^,]+),\s*Capabilities: (.*)$`)
	cdpAddr   = regexp.MustCompile(`^\s+IPv4 Address: (\S+)`)
	cdpSerial = regexp.MustCompile(`^(.*?)\(([A-Z0-9]+)\)$`)
)

// decodeCDP adds CDP neighbors: they carry the platform LLDP lacks, and
// cover ports where LLDP is off.
func decodeCDP(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(cdpStart.MatchString)
	doc.Mark(doc.Lines...) // every CDP line is either decoded or descriptive
	for _, block := range blocks {
		n := swtele.Neighbor{Protocol: "cdp"}
		id := strings.TrimSpace(cdpStart.FindStringSubmatch(block[0].Text)[1])
		if m := cdpSerial.FindStringSubmatch(id); m != nil {
			id = m[1]
		}
		n.System = id
		mgmt := false
		for _, l := range block[1:] {
			text := l.Text
			switch {
			case strings.HasPrefix(text, "System Name:"):
				if v := strings.TrimSpace(strings.TrimPrefix(text, "System Name:")); v != "" {
					n.System = v
				}
			case cdpIntf.MatchString(text):
				m := cdpIntf.FindStringSubmatch(text)
				n.LocalPort, n.Port = longName(m[1]), m[2]
			case cdpPlat.MatchString(text):
				m := cdpPlat.FindStringSubmatch(text)
				n.Platform = strings.TrimSpace(m[1])
				n.Capabilities = strings.Fields(m[2])
			case strings.HasPrefix(text, "Mgmt address(es):"):
				mgmt = true
			case cdpAddr.MatchString(text):
				a, err := netip.ParseAddr(cdpAddr.FindStringSubmatch(text)[1])
				if err == nil && (mgmt || !n.MgmtAddr.IsValid()) {
					n.MgmtAddr = a
				}
			}
		}
		if n.LocalPort == "" {
			continue
		}
		port(st, n.LocalPort)
		if merged := mergeCDP(st.dev, n); !merged {
			st.dev.Neighbors = append(st.dev.Neighbors, n)
		}
	}
}

// mergeCDP fills the platform of the LLDP neighbor on the same port and
// remote port; it reports whether one was found.
func mergeCDP(dev *swtele.Device, cdp swtele.Neighbor) bool {
	for i := range dev.Neighbors {
		n := &dev.Neighbors[i]
		if n.Protocol != "lldp" || swtele.InterfaceKey(n.LocalPort) != swtele.InterfaceKey(cdp.LocalPort) ||
			swtele.InterfaceKey(n.Port) != swtele.InterfaceKey(cdp.Port) {
			continue
		}
		n.Platform = cdp.Platform
		if !n.MgmtAddr.IsValid() {
			n.MgmtAddr = cdp.MgmtAddr
		}
		return true
	}
	return false
}
