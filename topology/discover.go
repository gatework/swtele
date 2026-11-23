package topology

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
)

// Candidate is a network device that neighbors advertise but the ledger
// does not hold: a device to add to the inventory.
type Candidate struct {
	Name     string     `json:"name"`
	Mgmt     netip.Addr `json:"mgmt,omitzero"`
	Platform string     `json:"platform,omitempty"` // guessed transport platform key
	Model    string     `json:"model,omitempty"`
	// SeenBy lists the managed ports the candidate was heard on.
	SeenBy []End `json:"-"`
}

// platformHints map advertised platform or description text to a
// transport platform key, first match wins.
var platformHints = []struct{ text, platform string }{
	{"nx-os", "cisco_nxos"}, {"nexus", "cisco_nxos"}, {"n9k", "cisco_nxos"}, {"n5k", "cisco_nxos"}, {"n7k", "cisco_nxos"},
	{"ios-xe", "cisco_ios"}, {"cisco ios", "cisco_ios"}, {"catalyst", "cisco_ios"}, {"ws-c", "cisco_ios"},
	{"h3c", "h3c"}, {"comware", "h3c"}, {"hpe", "h3c"},
	{"huawei", "huawei"}, {"vrp", "huawei"},
	{"ruijie", "ruijie"}, {"juniper", "juniper"}, {"junos", "juniper"}, {"arista", "arista"},
	{"hillstone", "hillstone"}, {"stoneos", "hillstone"}, {"palo alto", "palo_alto"}, {"pan-os", "palo_alto"},
	{"fortigate", "fortinet"}, {"centec", "centec"},
}

func guessPlatform(n swtele.Neighbor) string {
	t := strings.ToLower(n.Platform + " " + n.SysDesc)
	for _, h := range platformHints {
		if strings.Contains(t, h.text) {
			return h.platform
		}
	}
	return ""
}

// Discover returns the unmanaged network devices neighbors advertise,
// merged by chassis or name, ordered by how many ports see them.
func (g *Graph) Discover(l *ledger.Ledger) []Candidate {
	by := map[string]*Candidate{}
	var order []string
	for _, link := range g.Links {
		n := link.Neighbor
		if link.State != Unmanaged || !networkDevice(n) {
			continue
		}
		if n.MgmtAddr.IsValid() && l.Device(n.MgmtAddr.String()) != nil {
			continue // known by address under another name
		}
		key := ledger.NameKey(n.System)
		if key == "" {
			key = n.ChassisID
		}
		if key == "" {
			continue
		}
		c := by[key]
		if c == nil {
			c = &Candidate{Name: cmp.Or(n.System, n.ChassisID)}
			by[key] = c
			order = append(order, key)
		}
		if !c.Mgmt.IsValid() {
			c.Mgmt = n.MgmtAddr
		}
		c.Platform = cmp.Or(c.Platform, guessPlatform(n))
		c.Model = cmp.Or(c.Model, model(n))
		c.SeenBy = append(c.SeenBy, link.A)
	}
	out := make([]Candidate, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	slices.SortStableFunc(out, func(a, b Candidate) int {
		return cmp.Or(cmp.Compare(len(b.SeenBy), len(a.SeenBy)), strings.Compare(a.Name, b.Name))
	})
	return out
}

// model is the advertised hardware: the CDP platform, or a short LLDP
// description line.
func model(n swtele.Neighbor) string {
	if n.Platform != "" && !strings.Contains(n.Platform, " ") {
		return n.Platform
	}
	if p := strings.Fields(n.Platform); len(p) == 2 {
		return p[1] // "cisco WS-C3850-48T"
	}
	return ""
}
