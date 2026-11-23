// Package topology derives the physical topology of a ledger from LLDP and
// CDP: links between managed devices, unmanaged neighbors, and the role
// of every port (infrastructure versus edge), which endpoint location
// depends on.
package topology

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
)

// State classifies a link.
type State string

// Link states.
const (
	// Confirmed links are advertised from both ends.
	Confirmed State = "confirmed"
	// OneWay links are seen from one end only.
	OneWay State = "one_way"
	// Unmanaged links end at a device outside the ledger.
	Unmanaged State = "unmanaged"
	// Shared links are seen on a port with several neighbors: a hub or an
	// unmanaged switch forwards LLDP between them, so no end is adjacent.
	Shared State = "shared"
)

// End is one side of a link.
type End struct {
	Device *swtele.Device
	// Name is the remote system name when Device is nil.
	Name string
	Port string
}

// Link is a cable between two ports.
type Link struct {
	A, B     End
	State    State
	Neighbor swtele.Neighbor // the advertisement seen at A
}

// Role classifies a port.
type Role string

// Port roles.
const (
	RoleEdge   Role = "edge"   // faces endpoints
	RoleInfra  Role = "infra"  // faces another managed or network device
	RoleStack  Role = "stack"  // IRF, vPC peer-link, overlay
	RoleUnused Role = "unused" // down
)

// Graph is the topology of one ledger.
type Graph struct {
	Links []Link
	roles map[portKey]Role
	byDev map[*swtele.Device][]int // indexes into Links, either end
}

type portKey struct {
	dev  *swtele.Device
	port string
}

// infraCapabilities are LLDP/CDP capabilities of network devices; a port
// facing one is infrastructure even when the device is not in the ledger.
var infraCapabilities = []string{"bridge", "router", "switch", "b", "r", "s"}

// Build derives the graph of l.
func Build(l *ledger.Ledger) *Graph {
	g := &Graph{roles: map[portKey]Role{}}
	seen := map[[2]portKey]bool{}
	for _, d := range l.Devices() {
		shared := sharedSegments(l, d)
		for _, n := range d.Neighbors {
			g.add(l, d, n, shared(n), seen)
		}
		markStack(g, d)
	}
	slices.SortFunc(g.Links, func(a, b Link) int {
		return cmp.Or(a.A.Device.Identity.Mgmt.Compare(b.A.Device.Identity.Mgmt), cmp.Compare(a.A.Port, b.A.Port))
	})
	g.byDev = map[*swtele.Device][]int{}
	for i, k := range g.Links {
		g.byDev[k.A.Device] = append(g.byDev[k.A.Device], i)
		if k.B.Device != nil && k.B.Device != k.A.Device {
			g.byDev[k.B.Device] = append(g.byDev[k.B.Device], i)
		}
	}
	return g
}

// sharedSegments returns a predicate telling which advertisements of d
// cross a shared segment. Bridges never forward LLDP nearest-bridge
// frames, so an LLDP neighbor is adjacent unless its port sees several
// systems; CDP crosses non-Cisco switches, so a CDP neighbor is adjacent
// only when its port has no other system.
func sharedSegments(l *ledger.Ledger, d *swtele.Device) func(swtele.Neighbor) bool {
	lldp, cdp := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, n := range d.Neighbors {
		k := swtele.InterfaceKey(n.LocalPort)
		m := cdp
		if n.Protocol == "lldp" {
			m = lldp
		}
		if m[k] == nil {
			m[k] = map[string]bool{}
		}
		m[k][remoteID(l, n)] = true
	}
	return func(n swtele.Neighbor) bool {
		k := swtele.InterfaceKey(n.LocalPort)
		if n.Protocol == "lldp" {
			return len(lldp[k]) > 1
		}
		return len(cdp[k]) > 1 || len(lldp[k]) > 0 && !lldp[k][remoteID(l, n)]
	}
}

// remoteID identifies the system behind an advertisement.
func remoteID(l *ledger.Ledger, n swtele.Neighbor) string {
	if d := l.Remote(n); d != nil {
		return "dev:" + d.Identity.Mgmt.String()
	}
	if k := ledger.NameKey(n.System); k != "" {
		return "name:" + k
	}
	return "chassis:" + strings.ToLower(n.ChassisID)
}

func networkDevice(n swtele.Neighbor) bool {
	for _, c := range n.Capabilities {
		if slices.Contains(infraCapabilities, strings.ToLower(strings.TrimSpace(c))) {
			return true
		}
	}
	return n.Platform != "" && !strings.Contains(strings.ToLower(n.Platform), "phone")
}

// advertises reports whether remote sees local on port.
func advertises(remote *swtele.Device, port string, local *swtele.Device) bool {
	k := swtele.InterfaceKey(port)
	for _, n := range remote.Neighbors {
		if swtele.InterfaceKey(n.LocalPort) != k {
			continue
		}
		if ledgerMatch(n, local) {
			return true
		}
	}
	return false
}

func ledgerMatch(n swtele.Neighbor, d *swtele.Device) bool {
	if ledger.NameKey(n.System) != "" && (ledger.NameKey(n.System) == ledger.NameKey(d.System.Hostname) || ledger.NameKey(n.System) == ledger.NameKey(d.Identity.Name)) {
		return true
	}
	if d.Stack != nil && n.ChassisMAC == d.Stack.MAC && !n.ChassisMAC.IsZero() {
		return true
	}
	return n.MgmtAddr.IsValid() && n.MgmtAddr == d.Identity.Mgmt
}

// markStack marks IRF ports and aggregates whose members face other
// network devices.
func markStack(g *Graph, d *swtele.Device) {
	if d.Stack != nil {
		for _, s := range d.Stack.Links {
			g.mark(d, s.Interface, RoleStack)
		}
	}
	for _, i := range d.Interfaces.All() {
		if i.Kind == swtele.KindTunnel {
			g.mark(d, i.Name, RoleStack)
		}
	}
	for _, a := range d.Aggregates {
		for _, m := range a.Members {
			if r := g.roles[portKey{d, swtele.InterfaceKey(m.Port)}]; r == RoleInfra || r == RoleStack {
				g.mark(d, a.Name, r)
			}
		}
	}
}

// Role returns the role of port on d: infra or stack when the topology
// says so, unused when it is down, edge otherwise.
func (g *Graph) Role(d *swtele.Device, port string) Role {
	if r, ok := g.roles[portKey{d, swtele.InterfaceKey(port)}]; ok {
		return r
	}
	k := strings.ToLower(port)
	if strings.HasPrefix(k, "nve") || strings.HasPrefix(k, "peer-link") || strings.HasPrefix(k, "sup-eth") || strings.HasPrefix(k, "vpc peer") {
		return RoleStack
	}
	if i := d.Interfaces.Get(port); i != nil {
		if i.Aggregate != "" {
			if r, ok := g.roles[portKey{d, swtele.InterfaceKey(i.Aggregate)}]; ok {
				return r
			}
		}
		if i.Oper == swtele.StateDown {
			return RoleUnused
		}
	}
	return RoleEdge
}

// LinksOf returns the links with an end on d, as seen from d.
func (g *Graph) LinksOf(d *swtele.Device) []Link {
	var out []Link
	for _, n := range g.byDev[d] {
		l := g.Links[n]
		switch {
		case l.A.Device == d:
			out = append(out, l)
		case l.B.Device == d:
			out = append(out, Link{A: l.B, B: l.A, State: l.State, Neighbor: l.Neighbor})
		}
	}
	return out
}

// Peer returns the far end of the link on port of d. For an aggregate it
// is the far end of its first member with a link, preferring a managed
// device.
func (g *Graph) Peer(d *swtele.Device, port string) (End, bool) {
	ports := map[string]bool{swtele.InterfaceKey(port): true}
	if a := d.Aggregate(port); a != nil {
		for _, m := range a.Members {
			ports[swtele.InterfaceKey(m.Port)] = true
		}
	}
	var found End
	ok := false
	for _, l := range g.LinksOf(d) {
		if !ports[swtele.InterfaceKey(l.A.Port)] {
			continue
		}
		if l.B.Device != nil {
			return l.B, true
		}
		found, ok = l.B, true
	}
	return found, ok
}

func (g *Graph) mark(d *swtele.Device, port string, r Role) {
	k := portKey{d, swtele.InterfaceKey(port)}
	if g.roles[k] == RoleStack {
		return
	}
	g.roles[k] = r
}

// add records the link one advertisement of d describes.
func (g *Graph) add(l *ledger.Ledger, d *swtele.Device, n swtele.Neighbor, shared bool, seen map[[2]portKey]bool) {
	local := End{Device: d, Port: n.LocalPort}
	remote := l.Remote(n)
	switch remote {
	case nil:
		g.Links = append(g.Links, Link{A: local, B: End{Name: n.System, Port: n.Port}, State: Unmanaged, Neighbor: n})
		if networkDevice(n) {
			g.mark(d, n.LocalPort, RoleInfra)
		}
		return
	case d:
		g.mark(d, n.LocalPort, RoleStack)
		return
	}
	g.mark(d, n.LocalPort, RoleInfra)
	far := End{Device: remote, Port: n.Port}
	if shared {
		g.Links = append(g.Links, Link{A: local, B: far, State: Shared, Neighbor: n})
		return
	}
	a, b := portKey{d, swtele.InterfaceKey(n.LocalPort)}, portKey{remote, swtele.InterfaceKey(n.Port)}
	if seen[[2]portKey{a, b}] {
		return
	}
	seen[[2]portKey{a, b}] = true
	state := OneWay
	if advertises(remote, n.Port, d) {
		state = Confirmed
		seen[[2]portKey{b, a}] = true
	}
	g.Links = append(g.Links, Link{A: local, B: far, State: state, Neighbor: n})
}
