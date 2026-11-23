package comware

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	irfHeader = regexp.MustCompile(`^\s*MemberID\s+(?:Slot\s+)?Role\s+Priority\s+CPU-Mac\s+Description`)
	irfRow    = regexp.MustCompile(`^\s*([*+]*)\s*(\d+)\s+(?:(\d+)\s+)?(Master|Standby|Loading|Slave)\s+(\d+)\s+([0-9a-fA-F-]{14})\s*(.*)$`)
	irfBridge = regexp.MustCompile(`^\s*The bridge MAC of the IRF is: (\S+)`)
	irfInfo   = regexp.MustCompile(`^\s*(?:\* indicates|\+ indicates|Auto upgrade|Auto merge|Mac persistent|Domain ID|IRF mode|Topology Info|Link\s+neighbor|IRF-Port1\s+IRF-Port2|MemberID\s+Link|-{5,})`)
	irfMember = regexp.MustCompile(`^Member (\d+)\s*$`)
	irfLinkH  = regexp.MustCompile(`^\s*IRF Port\s+Interface\s+Status\s*$`)
	irfLinkR  = regexp.MustCompile(`^\s*(\d+)?\s+(\S+)\s+(\S+)\s*$`)
	topoRow   = regexp.MustCompile(`^\s*(\d+)\s+(UP|DOWN|DIS|TIMEOUT|ISOLATE)\s+(\S+)\s+(UP|DOWN|DIS|TIMEOUT|ISOLATE)\s+(\S+)\s+(\S+)\s*$`)
)

func stack(st *state) *swtele.Stack {
	if st.dev.Stack == nil {
		st.dev.Stack = &swtele.Stack{Kind: swtele.StackIRF}
	}
	return st.dev.Stack
}

func decodeIRF(doc *clidoc.Doc, st *state) {
	s := stack(st)
	for _, l := range doc.Lines {
		switch {
		case irfHeader.MatchString(l.Text), irfInfo.MatchString(l.Text):
			if m := regexp.MustCompile(`Domain ID\s*:\s*(\S+)`).FindStringSubmatch(l.Text); m != nil {
				s.Domain = m[1]
			}
		case irfBridge.MatchString(l.Text):
			s.MAC, _ = swtele.ParseMAC(irfBridge.FindStringSubmatch(l.Text)[1])
		case irfRow.MatchString(l.Text):
			m := irfRow.FindStringSubmatch(l.Text)
			mem := swtele.Member{ID: clidoc.Int(m[2]).Or(0), Role: m[4], Priority: clidoc.Int(m[5]), Self: strings.Contains(m[1], "+")}
			mem.MAC, _ = swtele.ParseMAC(m[6])
			if d := strings.TrimSpace(m[7]); !clidoc.Null(d) {
				mem.Desc = d
			}
			s.Members = append(s.Members, mem)
		default:
			continue
		}
		doc.Mark(l)
	}
}

func decodeIRFTopology(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		if irfInfo.MatchString(l.Text) || topoRow.MatchString(l.Text) {
			doc.Mark(l)
		}
	}
}

func decodeIRFLink(doc *clidoc.Doc, st *state) {
	s := stack(st)
	member, irfPort := 0, 0
	for _, l := range doc.Lines {
		switch {
		case irfMember.MatchString(l.Text):
			member = clidoc.Int(irfMember.FindStringSubmatch(l.Text)[1]).Or(0)
		case irfLinkH.MatchString(l.Text):
		case irfLinkR.MatchString(l.Text):
			m := irfLinkR.FindStringSubmatch(l.Text)
			if m[1] != "" {
				irfPort = clidoc.Int(m[1]).Or(0)
			}
			if strings.EqualFold(m[2], "disable") {
				break
			}
			s.Links = append(s.Links, swtele.StackLink{Member: member, Port: irfPort, Interface: longName(m[2]), State: upDown(m[3])})
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	madRecovery = regexp.MustCompile(`^Multi-active recovery state: (\S+)`)
	madMode     = regexp.MustCompile(`^MAD (ARP|ND|LACP|BFD) (disabled|enabled)\.?(?: interface: (\S+))?`)
	madModeIf   = regexp.MustCompile(`^MAD (ARP|ND|LACP|BFD) enabled (?:interface|on interface)s?:?\s*(\S*)`)
	madStatus   = regexp.MustCompile(`^\s*MAD status\s*:\s*(\S+)`)
	madTableH   = regexp.MustCompile(`^\s*Member ID\s+(?:MAD IP address|Port)\s+`)
	madBFDRow   = regexp.MustCompile(`^\s*(\d+)\s+(\S+/\d+)\s+(\S+)\s+(\S+)\s*$`)
	madPortRow  = regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+(\S+)\s*$`)
	madExcluded = regexp.MustCompile(`^\s*(?:Excluded ports|IRF physical interfaces:|BFD MAD interfaces:|[A-Za-z-]+\d[\d/:.]*\s*$)`)
)

func decodeMAD(doc *clidoc.Doc, st *state) {
	mad := &swtele.MAD{}
	stack(st).MAD = mad
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case madRecovery.MatchString(text):
			mad.Recovering = strings.EqualFold(madRecovery.FindStringSubmatch(text)[1], "Recovery") || strings.EqualFold(madRecovery.FindStringSubmatch(text)[1], "Yes")
		case madModeIf.MatchString(text):
			m := madModeIf.FindStringSubmatch(text)
			mad.Modes = append(mad.Modes, strings.ToLower(m[1]))
			mad.Interface = longName(m[2])
		case madMode.MatchString(text):
			m := madMode.FindStringSubmatch(text)
			if m[2] == "enabled" {
				mad.Modes = append(mad.Modes, strings.ToLower(m[1]))
			}
		case madStatus.MatchString(text):
			mad.Status = madStatus.FindStringSubmatch(text)[1]
		case madTableH.MatchString(text), madExcluded.MatchString(text):
		case madBFDRow.MatchString(text):
			m := madBFDRow.FindStringSubmatch(text)
			mm := swtele.MADMember{Member: clidoc.Int(m[1]).Or(0), Status: m[4]}
			if p, err := netip.ParsePrefix(m[2]); err == nil {
				mm.Address = p.Addr()
			}
			mad.Members = append(mad.Members, mm)
		case madPortRow.MatchString(text):
			m := madPortRow.FindStringSubmatch(text)
			mad.Members = append(mad.Members, swtele.MADMember{Member: clidoc.Int(m[1]).Or(0), Port: longName(m[2]), Status: m[3]})
		default:
			continue
		}
		doc.Mark(l)
	}
}
