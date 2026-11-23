// Package locate finds where an endpoint attaches to the network: from an
// IP to its MAC through the fleet's ARP tables, then from the MAC to the
// one edge port that learned it, discarding the infrastructure ports
// (uplinks, stack links, aggregates toward switches) that also learned it
// on the way.
package locate

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/topology"
)

// Confidence grades a location.
type Confidence string

// Confidences, from best to worst.
const (
	// Exact: one edge port learned the endpoint alone.
	Exact Confidence = "exact"
	// Shared: one edge port learned it with other endpoints, so an
	// unmanaged switch, AP or hypervisor sits behind the port.
	Shared Confidence = "behind_unmanaged"
	// Ambiguous: several edge ports learned it (a loop, a moving or
	// duplicated MAC).
	Ambiguous Confidence = "ambiguous"
	// GatewayOnly: the IP resolves to a MAC but no switch forwards it.
	GatewayOnly Confidence = "gateway_only"
	// Unknown: neither ARP nor any forwarding table knows the endpoint.
	Unknown Confidence = "unknown"
	// Device: the address belongs to a network device of the ledger.
	Device Confidence = "network_device"
)

// Options tune location.
type Options struct {
	// TrunkLimit is how many MACs a trunk port may learn before it counts
	// as infrastructure although no neighbor is advertised. 0 means 32.
	TrunkLimit int
}

// Gateway is a layer-3 interface resolving the endpoint.
type Gateway struct {
	Device    string `json:"device"`
	Mgmt      string `json:"mgmt"`
	Interface string `json:"interface"`
	VRF       string `json:"vrf,omitempty"`
	VLAN      int    `json:"vlan,omitempty"`
}

// Port is a switch port that learned the endpoint.
type Port struct {
	Device    string `json:"device"`
	Mgmt      string `json:"mgmt"`
	Interface string `json:"interface"`
	Desc      string `json:"description,omitempty"`
	VLAN      int    `json:"vlan,omitempty"`
	Role      string `json:"role"`
	Speed     uint64 `json:"speed_bps,omitempty"`
	Up        bool   `json:"up"`
	// MACs is how many endpoints the port learned.
	MACs int `json:"macs"`
	// Neighbor is what LLDP/CDP sees behind the port.
	Neighbor string `json:"neighbor,omitempty"`
}

// Location is the answer for one endpoint.
type Location struct {
	Query      string     `json:"query"`
	IP         netip.Addr `json:"ip,omitzero"`
	MAC        swtele.MAC `json:"mac,omitzero"`
	OUI        string     `json:"oui,omitempty"`
	Confidence Confidence `json:"confidence"`
	Gateways   []Gateway  `json:"gateways,omitempty"`
	// Seen are the other devices holding an ARP entry for the IP, such as
	// switches whose management SVI shares the subnet.
	Seen []Gateway `json:"seen,omitempty"`
	// Access is the edge port the endpoint attaches to.
	Access []Port `json:"access,omitempty"`
	// Path is every other port that learned it, upstream first.
	Path []Port `json:"path,omitempty"`
	// Device and Interface name the network device owning the address,
	// when Confidence is Device.
	Device    string `json:"device,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Notes explain anomalies: IP conflicts, MAC on several edges.
	Notes []string `json:"notes,omitempty"`
}

// Locator answers location queries against one ledger.
type Locator struct {
	l     *ledger.Ledger
	g     *topology.Graph
	limit int
}

// New returns a locator for l and its topology.
func New(l *ledger.Ledger, g *topology.Graph, o Options) *Locator {
	if o.TrunkLimit <= 0 {
		o.TrunkLimit = 32
	}
	return &Locator{l: l, g: g, limit: o.TrunkLimit}
}

// Locate resolves an IP address or a MAC address.
func (x *Locator) Locate(query string) Location {
	loc := Location{Query: query, Confidence: Unknown}
	if ip, err := netip.ParseAddr(strings.TrimSpace(query)); err == nil {
		loc.IP = ip
		x.resolveIP(&loc)
	} else if mac, err := swtele.ParseMAC(query); err == nil {
		loc.MAC = mac
		for _, r := range x.l.ARPByMAC(mac) {
			loc.IP = r.Entry.IP
			x.addGateway(&loc, r)
		}
	} else {
		loc.Notes = append(loc.Notes, "无法识别的 IP 或 MAC 地址")
		return loc
	}
	x.pickGateways(&loc)
	if loc.MAC.IsZero() {
		return loc
	}
	loc.OUI = loc.MAC.OUI()
	if x.device(&loc) {
		return loc
	}
	x.place(&loc)
	return loc
}

func hasAddr(i *swtele.Interface, ip netip.Addr) bool {
	for _, a := range i.Addresses {
		if a.Prefix.Addr() == ip {
			return true
		}
	}
	return false
}

func appendGateway(gs []Gateway, r ledger.ARPRef) []Gateway {
	g := Gateway{Device: r.Device.Name(), Mgmt: r.Device.Identity.Mgmt.String(), Interface: r.Entry.Interface, VLAN: r.Entry.VLAN, VRF: r.Entry.VRF}
	// Comware ARP tables name the port the entry was learned on; the
	// gateway is the layer-3 interface whose subnet holds the address.
	for _, i := range r.Device.Interfaces.All() {
		for _, a := range i.Addresses {
			if a.Prefix.Bits() < a.Prefix.Addr().BitLen() && a.Prefix.Masked().Contains(r.Entry.IP) {
				g.Interface = i.Name
			}
		}
	}
	if i := r.Device.Interfaces.Get(r.Entry.Interface); i != nil && g.VRF == "" {
		g.VRF = i.VRF
	}
	if slices.Contains(gs, g) {
		return gs
	}
	return append(gs, g)
}

// virtualMAC matches first-hop redundancy MACs (VRRP, HSRP v1/v2), which
// every switch on the segment learns toward the active gateway.
func virtualMAC(m swtele.MAC) bool {
	switch {
	case m[0] == 0 && m[1] == 0 && m[2] == 0x5e && m[3] == 0 && (m[4] == 1 || m[4] == 2):
		return true
	case m[0] == 0 && m[1] == 0 && m[2] == 0x0c && (m[3] == 0x07 && m[4] == 0xac || m[3] == 0x9f && m[4]&0xf0 == 0xf0):
		return true
	}
	return false
}

// Sighting is where one endpoint was attached in one batch.
type Sighting struct {
	IP         netip.Addr `json:"ip"`
	MAC        swtele.MAC `json:"mac"`
	VLAN       int        `json:"vlan,omitempty"`
	Device     string     `json:"device"`
	Mgmt       string     `json:"mgmt"`
	Port       string     `json:"port"`
	Confidence Confidence `json:"confidence"`
}

// Sightings locates every resolved ARP entry of the ledger, one per IP
// and MAC pair, keeping those placed on an access port.
func (x *Locator) Sightings() []Sighting {
	seen := map[string]bool{}
	var out []Sighting
	for _, d := range x.l.Devices() {
		for _, e := range d.L3.ARP {
			if e.Incomplete || e.MAC.IsZero() {
				continue
			}
			k := e.IP.String() + "|" + e.MAC.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			loc := Location{IP: e.IP, MAC: e.MAC, Confidence: Unknown}
			x.place(&loc)
			if (loc.Confidence != Exact && loc.Confidence != Shared) || len(loc.Access) == 0 {
				continue
			}
			a := loc.Access[0]
			out = append(out, Sighting{IP: e.IP, MAC: e.MAC, VLAN: a.VLAN, Device: a.Device, Mgmt: a.Mgmt, Port: a.Interface, Confidence: loc.Confidence})
		}
	}
	return out
}

func (x *Locator) resolveIP(loc *Location) {
	macs := map[swtele.MAC]bool{}
	for _, r := range x.l.ARP(loc.IP) {
		if r.Entry.Incomplete || r.Entry.MAC.IsZero() {
			continue
		}
		macs[r.Entry.MAC] = true
		x.addGateway(loc, r)
	}
	switch len(macs) {
	case 0:
		if owner := x.l.Device(loc.IP.String()); owner != nil {
			loc.Notes = append(loc.Notes, fmt.Sprintf("该地址属于网络设备 %s", owner.Name()))
		}
		return
	case 1:
	default:
		loc.Notes = append(loc.Notes, fmt.Sprintf("IP 冲突嫌疑：%d 个不同 MAC 解析到该地址", len(macs)))
	}
	// Prefer the MAC most gateways agree on; ties resolve by order.
	best, n := swtele.MAC{}, 0
	for m := range macs {
		c := 0
		for _, r := range x.l.ARP(loc.IP) {
			if r.Entry.MAC == m {
				c++
			}
		}
		if c > n || c == n && m.String() < best.String() {
			best, n = m, c
		}
	}
	loc.MAC = best
}

// place sorts every port that learned the MAC into transit and terminal
// ports. A port facing a managed device is transit even when that device
// has aged the entry out: the endpoint sits further along. Edge ports, and
// ports facing an unmanaged neighbor (an AP, a desk switch), are terminal.
func (x *Locator) place(loc *Location) {
	if owner := x.l.Owner(loc.MAC); owner != nil {
		loc.Notes = append(loc.Notes, fmt.Sprintf("该 MAC 属于网络设备 %s", owner.Name()))
	}
	if virtualMAC(loc.MAC) {
		loc.Notes = append(loc.Notes, "该 MAC 为 VRRP/HSRP 虚拟网关地址")
	}
	var behind []Port // terminal ports facing unmanaged neighbors
	seen := map[string]bool{}
	for _, r := range x.l.MACs(loc.MAC) {
		if r.Entry.Kind == swtele.MACSystem || r.Entry.Kind == swtele.MACRemote || r.Entry.Port == "" {
			continue
		}
		key := r.Device.Identity.Mgmt.String() + "|" + swtele.InterfaceKey(r.Entry.Port)
		if seen[key] {
			continue // the same port in another VLAN
		}
		seen[key] = true
		p, far := x.port(r)
		switch {
		case far != nil, p.Role == string(topology.RoleStack), p.Role == string(topology.RoleUnused):
			loc.Path = append(loc.Path, p)
		case p.Role == string(topology.RoleEdge):
			loc.Access = append(loc.Access, p)
		default:
			behind = append(behind, p)
		}
	}
	byMACs := func(a, b Port) int { return cmp.Compare(a.MACs, b.MACs) }
	slices.SortFunc(loc.Path, func(a, b Port) int { return cmp.Compare(b.MACs, a.MACs) })
	slices.SortFunc(loc.Access, byMACs)
	slices.SortFunc(behind, byMACs)
	switch {
	case len(loc.Access) == 1:
		loc.Confidence = Exact
		if n := loc.Access[0].MACs; n > 1 {
			loc.Confidence = Shared
			loc.Notes = append(loc.Notes, fmt.Sprintf("接入口学到 %d 个 MAC，口下可能有非管交换机、AP 或虚拟化主机", n))
		}
		loc.Path = append(loc.Path, behind...)
	case len(loc.Access) > 1:
		loc.Confidence = Ambiguous
		loc.Notes = append(loc.Notes, fmt.Sprintf("同一 MAC 出现在 %d 个接入口：MAC 漂移、环路或重复 MAC", len(loc.Access)))
		loc.Path = append(loc.Path, behind...)
	case len(behind) > 0:
		loc.Confidence = Shared
		loc.Access = behind[:1]
		loc.Path = append(loc.Path, behind[1:]...)
		loc.Notes = append(loc.Notes, fmt.Sprintf("终端位于非受管设备 %s 之后", cmp.Or(behind[0].Neighbor, "（未通告邻居）")))
	case len(loc.Gateways) > 0 || len(loc.Seen) > 0 || len(loc.Path) > 0:
		loc.Confidence = GatewayOnly
		if len(loc.Path) > 0 {
			loc.Notes = append(loc.Notes, "仅在设备互联端口上学到：接入层表项可能已老化，或终端位于台账外设备之后")
		}
	}
}

// port describes the port of r and returns the managed device at its far
// end, if any.
func (x *Locator) port(r ledger.MACRef) (Port, *swtele.Device) {
	d := r.Device
	p := Port{Device: d.Name(), Mgmt: d.Identity.Mgmt.String(), Interface: r.Entry.Port, VLAN: r.Entry.VLAN, MACs: x.l.PortMACs(d, r.Entry.Port)}
	role := x.g.Role(d, r.Entry.Port)
	i := d.Interfaces.Get(r.Entry.Port)
	if i != nil {
		p.Desc, p.Up = i.Desc, i.Up()
		p.Speed = i.Speed.Or(0)
		if role == topology.RoleEdge && i.Switching != nil && i.Switching.Mode == swtele.ModeTrunk && p.MACs > x.limit {
			role = topology.RoleInfra
		}
	}
	var far *swtele.Device
	if e, ok := x.g.Peer(d, r.Entry.Port); ok {
		p.Neighbor, far = e.Name, e.Device
		if e.Device != nil {
			p.Neighbor = e.Device.Name()
		}
	}
	p.Role = string(role)
	return p, far
}

// device answers for an address of a network device in the ledger: the
// device itself, and the port its owning interface connects to.
func (x *Locator) device(loc *Location) bool {
	owner := x.l.Owner(loc.MAC)
	if owner == nil && loc.IP.IsValid() {
		owner = x.l.Device(loc.IP.String())
	}
	if owner == nil {
		return false
	}
	loc.Confidence = Device
	loc.Device = owner.Name()
	for _, i := range owner.Interfaces.All() {
		if i.MAC != loc.MAC && !hasAddr(i, loc.IP) {
			continue
		}
		loc.Interface = i.Name
		if e, ok := x.g.Peer(owner, i.Name); ok && e.Device != nil {
			loc.Access = []Port{{Device: e.Device.Name(), Mgmt: e.Device.Identity.Mgmt.String(), Interface: e.Port, Role: string(x.g.Role(e.Device, e.Port)), Neighbor: owner.Name()}}
		}
		if i.Kind == swtele.KindPhysical || i.Kind == swtele.KindMgmt {
			break
		}
	}
	return true
}

// addGateway files an ARP holder as candidate gateway when it routes, as
// a mere observer otherwise; pickGateways narrows the candidates.
func (x *Locator) addGateway(loc *Location, r ledger.ARPRef) {
	if x.l.Router(r.Device) {
		loc.Gateways = appendGateway(loc.Gateways, r)
	} else {
		loc.Seen = appendGateway(loc.Seen, r)
	}
}

// pickGateways keeps, when some candidates are default gateways of other
// devices, only those: the switches of a management VLAN all route and
// all hold its ARP entries, but only the core is their gateway.
func (x *Locator) pickGateways(loc *Location) {
	var gw, rest []Gateway
	for _, g := range loc.Gateways {
		if d := x.l.Device(g.Mgmt); d != nil && x.l.DefaultGateway(d) {
			gw = append(gw, g)
		} else {
			rest = append(rest, g)
		}
	}
	if len(gw) > 0 {
		loc.Gateways, loc.Seen = gw, append(loc.Seen, rest...)
	}
}
