package comware

import (
	"regexp"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	aggHeader = regexp.MustCompile(`^Aggregate Interface: (\S+)$`)
	aggLegend = regexp.MustCompile(`^\s*(?:Loadsharing Type: Shar|Port Status: S|Port: A -- Auto|Flags:\s+A -- LACP|D -- Synchronization|G -- Defaulted|I -- Individual|Role: P -- Primary|No link aggregation groups? exists?\.|-{10,}\s*$)`)
	aggInfo   = regexp.MustCompile(`^(?:Creation Mode|Loadsharing Type|Management VLANs?|Aggregation Description|Aggregate Interface Description|Port Group|Ignored VLANs)\s*:`)
	aggFlags  = regexp.MustCompile(`\{([A-H]*)\}\s*$`)
	sysIDCell = regexp.MustCompile(`0x[0-9a-fA-F]+,\s*[0-9a-fA-F-]+`)
)

func decodeLAG(doc *clidoc.Doc, st *state) {
	doc.MarkMatching(aggLegend)
	_, blocks := doc.Blocks(aggHeader.MatchString)
	for _, block := range blocks {
		a := swtele.Aggregate{Name: longName(aggHeader.FindStringSubmatch(block[0].Text)[1])}
		doc.Mark(block[0])
		port(st, a.Name).Kind = swtele.KindAggregate
		section := ""
		for _, l := range block[1:] {
			text := strings.TrimSpace(l.Text)
			switch {
			case text == "", aggInfo.MatchString(text):
			case strings.HasPrefix(text, "Aggregation Mode:"):
				_, v, _ := clidoc.Label(text)
				if strings.EqualFold(v, "Dynamic") {
					a.Mode = swtele.AggLACP
				} else {
					a.Mode = swtele.AggStatic
				}
			case strings.HasPrefix(text, "System ID:"):
				_, v, _ := strings.Cut(text, ":")
				a.SystemID = strings.TrimSpace(v)
			case text == "Local:" || text == "Remote:":
				section = strings.ToLower(strings.TrimSuffix(text, ":"))
			case strings.HasPrefix(text, "Port ") && strings.Contains(text, "Status"):
				if section == "" {
					section = "local"
				}
			case strings.HasPrefix(text, "Actor ") && strings.Contains(text, "SystemID"):
			case section == "local":
				if !localMember(&a, text) {
					continue
				}
			case section == "remote":
				if !remoteMember(&a, text) {
					continue
				}
			default:
				continue
			}
			doc.Mark(l)
		}
		st.dev.Aggregates = append(st.dev.Aggregates, a)
	}
}

// localMember reads "XGE1/0/49  S  32768  1  1  {ACDEF}" (dynamic) or
// "GE1/0/1  S  32768  1" (static).
func localMember(a *swtele.Aggregate, text string) bool {
	f := strings.Fields(text)
	if len(f) < 3 {
		return false
	}
	m := swtele.AggMember{Port: longName(f[0]), Status: f[1], Selected: f[1] == "S", Reference: strings.HasSuffix(f[0], "(R)")}
	if fl := aggFlags.FindStringSubmatch(text); fl != nil {
		m.Flags = swtele.LACPFlags(fl[1])
	}
	a.Members = append(a.Members, m)
	return true
}

// remoteMember reads "XGE1/0/49  32768  29  14  0x8000, 28e4-24bc-f000 {ACDEF}".
func remoteMember(a *swtele.Aggregate, text string) bool {
	f := strings.Fields(text)
	if len(f) < 2 {
		return false
	}
	name := longName(f[0])
	for n := range a.Members {
		if swtele.InterfaceKey(a.Members[n].Port) != swtele.InterfaceKey(name) {
			continue
		}
		m := &a.Members[n]
		if strings.HasSuffix(f[0], "(R)") {
			m.Reference = true
		}
		if id := sysIDCell.FindString(text); id != "" {
			m.PartnerID = id
		}
		if fl := aggFlags.FindStringSubmatch(text); fl != nil {
			m.PartnerFlags = swtele.LACPFlags(fl[1])
		}
		if len(f) > 2 {
			m.PartnerPort = f[2] // the partner's port index
		}
		return true
	}
	return false
}
