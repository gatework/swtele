package swtele

import (
	"net/netip"
	"time"
)

// Routing is the layer-3 state of a device.
type Routing struct {
	ARP    []ARPEntry `json:"arp,omitempty"`
	Peers  []Peer     `json:"peers,omitempty"`
	Routes []Route    `json:"routes,omitempty"`
}

// ARPEntry binds an IPv4 address to a MAC on an interface.
type ARPEntry struct {
	IP        netip.Addr         `json:"ip"`
	MAC       MAC                `json:"mac,omitzero"`
	VLAN      int                `json:"vlan,omitempty"`
	Interface string             `json:"interface,omitempty"`
	VRF       string             `json:"vrf,omitempty"`
	Age       Opt[time.Duration] `json:"age,omitzero"`
	Kind      string             `json:"kind,omitempty"`
	// Incomplete is an unresolved entry.
	Incomplete bool `json:"incomplete,omitempty"`
}

// Protocol is a routing protocol.
type Protocol string

// Routing protocols.
const (
	ProtoOSPF   Protocol = "ospf"
	ProtoBGP    Protocol = "bgp"
	ProtoStatic Protocol = "static"
)

// Peer is a routing adjacency or session.
type Peer struct {
	Proto     Protocol           `json:"protocol"`
	VRF       string             `json:"vrf,omitempty"`
	Family    string             `json:"family,omitempty"`
	Process   string             `json:"process,omitempty"`
	Area      string             `json:"area,omitempty"`
	RouterID  string             `json:"router_id,omitempty"`
	Address   netip.Addr         `json:"address,omitzero"`
	AS        string             `json:"as,omitempty"`
	State     string             `json:"state"`
	Up        Opt[time.Duration] `json:"up,omitzero"`
	Interface string             `json:"interface,omitempty"`
	Prefixes  Opt[int]           `json:"prefixes,omitzero"`
	// Established is the vendor-independent verdict: OSPF Full (or 2-Way
	// with a DROther), BGP Established.
	Established bool `json:"established"`
}

// Route is one route; the first phase reads static routes from
// configuration only.
type Route struct {
	VRF      string       `json:"vrf,omitempty"`
	Prefix   netip.Prefix `json:"prefix"`
	Proto    Protocol     `json:"protocol"`
	NextHops []string     `json:"next_hops,omitempty"`
}
