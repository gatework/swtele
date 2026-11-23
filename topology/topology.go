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
// infraCapabilities name network devices; "s" is the CDP Switch code
// (LLDP Station is handled by hostAdapter).
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
	g.Links = dedupe(g.Links)
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

// remotePort resolves a port ID advertised as a MAC address (Comware
// management ports, some servers) to the remote interface owning it.
func remotePort(remote *swtele.Device, port string) string {
	mac, err := swtele.ParseMAC(port)
	if err != nil {
		return port
	}
	for _, i := range remote.Interfaces.All() {
		if i.MAC == mac && (i.Kind == swtele.KindPhysical || i.Kind == swtele.KindMgmt) {
			return i.Name
		}
	}
	return port
}

// stateRank orders link states from best to worst.
var stateRank = map[State]int{Confirmed: 0, OneWay: 1, Shared: 2, Unmanaged: 3}

// dedupe keeps one link per local port and managed remote device: a
// neighbor seen through several advertisements (LLDP agents, CDP, a port
// ID given once by name and once by MAC) is one cable, recorded with its
// best state.
func dedupe(links []Link) []Link {
	type key struct {
		dev  *swtele.Device
		port string
		far  *swtele.Device
	}
	best := map[key]int{}
	keys := func(l Link) []key {
		if l.B.Device == nil {
			return nil
		}
		return []key{{l.A.Device, swtele.InterfaceKey(l.A.Port), l.B.Device}, {l.B.Device, swtele.InterfaceKey(l.B.Port), l.A.Device}}
	}
	for _, l := range links {
		for _, k := range keys(l) {
			if r, ok := best[k]; !ok || stateRank[l.State] < r {
				best[k] = stateRank[l.State]
			}
		}
	}
	out := links[:0]
	kept := map[key]bool{}
	for _, l := range links {
		ks := keys(l)
		if len(ks) == 0 {
			out = append(out, l)
			continue
		}
		// The local end decides; a one-way record from the far end of a
		// confirmed cable is the same cable.
		if stateRank[l.State] > best[ks[0]] || kept[ks[0]] {
			continue
		}
		kept[ks[0]], kept[ks[1]] = true, true
		out = append(out, l)
	}
	return out
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
	if hostAdapter(n) {
		return false
	}
	for _, c := range n.Capabilities {
		if slices.Contains(infraCapabilities, strings.ToLower(strings.TrimSpace(c))) {
			return true
		}
	}
	return n.Platform != "" && !strings.Contains(strings.ToLower(n.Platform), "phone")
}

// hostAdapter reports a server NIC speaking LLDP: firmware agents
// advertise the adapter model, not a network platform.
func hostAdapter(n swtele.Neighbor) bool {
	// IP phones bridge the PC behind them but are endpoints.
	if slices.ContainsFunc(n.Capabilities, func(c string) bool {
		c = strings.ToLower(strings.TrimSpace(c))
		return c == "telephone" || c == "phone" || strings.EqualFold(n.Protocol, "lldp") && c == "t"
	}) && !slices.ContainsFunc(n.Capabilities, func(c string) bool { return strings.EqualFold(strings.TrimSpace(c), "router") }) {
		return true
	}
	// LLDP "S" is Station (CDP "S" is Switch): a neighbor advertising
	// only that is an end host.
	if strings.EqualFold(n.Protocol, "lldp") && len(n.Capabilities) > 0 && !slices.ContainsFunc(n.Capabilities, func(c string) bool {
		c = strings.ToLower(strings.TrimSpace(c))
		return c != "s" && c != "station" && c != "station only"
	}) {
		return true
	}
	desc := strings.ToLower(n.System + " " + n.Platform + " " + n.SysDesc)
	for _, k := range []string{"adapter", "ethernet controller", "network connection", "converged network", " nic "} {
		if strings.Contains(desc, k) {
			return !slices.ContainsFunc(n.Capabilities, func(c string) bool {
				c = strings.ToLower(strings.TrimSpace(c))
				return c == "router" || c == "wlan access point"
			})
		}
	}
	return false
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
	n.Port = remotePort(remote, n.Port)
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
