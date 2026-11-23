// Package ledger assembles the devices of one observation batch into a
// fleet-wide ledger and indexes it: devices by address, name and MAC,
// endpoints by IP and MAC. Analyses (topology, location, checks) read a
// Ledger; it does no I/O.
package ledger

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gatework/swtele"
)

// Manifest describes one stored batch.
type Manifest struct {
	Schema  int       `json:"schema"`
	Batch   string    `json:"batch"`
	At      time.Time `json:"at"`
	Source  string    `json:"source,omitempty"`
	Devices []string  `json:"devices"`
	// Failed lists the hosts whose capture could not be decoded.
	Failed []string `json:"failed,omitempty"`
}

// Ledger is the devices of one batch with their indexes. Build it with
// New; it is immutable afterwards and safe for concurrent reads.
type Ledger struct {
	Batch   string
	At      time.Time
	devices []*swtele.Device

	byMgmt map[netip.Addr]*swtele.Device
	byName map[string]*swtele.Device
	byMAC  map[swtele.MAC]*swtele.Device // device-owned MACs: bridge, chassis, interface
	arp    map[netip.Addr][]ARPRef
	arpMAC map[swtele.MAC][]ARPRef
	macs   map[swtele.MAC][]MACRef
	ports  map[portKey]int // MAC entries learned per port
}

type portKey struct {
	dev  *swtele.Device
	port string // interface key
}

// ARPRef is one ARP entry and the device holding it.
type ARPRef struct {
	Device *swtele.Device
	Entry  swtele.ARPEntry
}

// MACRef is one forwarding entry and the device holding it.
type MACRef struct {
	Device *swtele.Device
	Entry  swtele.MACEntry
}

// New indexes devices observed in batch at at.
func New(batch string, at time.Time, devices []*swtele.Device) *Ledger {
	l := &Ledger{
		Batch: batch, At: at, devices: slices.Clone(devices),
		byMgmt: map[netip.Addr]*swtele.Device{}, byName: map[string]*swtele.Device{}, byMAC: map[swtele.MAC]*swtele.Device{},
		arp: map[netip.Addr][]ARPRef{}, arpMAC: map[swtele.MAC][]ARPRef{}, macs: map[swtele.MAC][]MACRef{}, ports: map[portKey]int{},
	}
	slices.SortFunc(l.devices, func(a, b *swtele.Device) int { return a.Identity.Mgmt.Compare(b.Identity.Mgmt) })
	for _, d := range l.devices {
		l.index(d)
	}
	return l
}

// NameKey normalizes a host name for matching: lowercase, without a
// domain suffix or an appended serial ("SPN01.example.com", "spn01").
func NameKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	if i := strings.IndexByte(name, '('); i > 0 {
		name = name[:i]
	}
	return name
}

// Devices returns the devices in management-address order.
func (l *Ledger) Devices() []*swtele.Device { return slices.Clone(l.devices) }

// Len returns the number of devices.
func (l *Ledger) Len() int { return len(l.devices) }

// Device finds a device by management address, address on any of its
// interfaces, or host name.
func (l *Ledger) Device(query string) *swtele.Device {
	if a, err := netip.ParseAddr(strings.TrimSpace(query)); err == nil {
		return l.byMgmt[a]
	}
	return l.byName[NameKey(query)]
}

// Remote resolves the device a neighbor advertisement names: by chassis
// MAC, then system name, then management address. Link-local management
// addresses (Comware advertises 169.254/16) are not trusted.
func (l *Ledger) Remote(n swtele.Neighbor) *swtele.Device {
	if !n.ChassisMAC.IsZero() {
		if d := l.byMAC[n.ChassisMAC]; d != nil {
			return d
		}
	}
	if d := l.byName[NameKey(n.System)]; d != nil && n.System != "" {
		return d
	}
	if n.MgmtAddr.IsValid() && !n.MgmtAddr.IsLinkLocalUnicast() {
		return l.byMgmt[n.MgmtAddr]
	}
	return nil
}

// Owner returns the device that owns mac as a bridge, chassis or
// interface address, or nil for an endpoint.
func (l *Ledger) Owner(mac swtele.MAC) *swtele.Device { return l.byMAC[mac] }

// ARP returns every ARP entry for ip across the fleet.
func (l *Ledger) ARP(ip netip.Addr) []ARPRef { return slices.Clone(l.arp[ip]) }

// ARPByMAC returns every ARP entry resolving to mac.
func (l *Ledger) ARPByMAC(mac swtele.MAC) []ARPRef { return slices.Clone(l.arpMAC[mac]) }

// MACs returns every forwarding entry for mac across the fleet.
func (l *Ledger) MACs(mac swtele.MAC) []MACRef { return slices.Clone(l.macs[mac]) }

// PortMACs returns how many forwarding entries d learned on port.
func (l *Ledger) PortMACs(d *swtele.Device, port string) int {
	return l.ports[portKey{d, swtele.InterfaceKey(port)}]
}

// EntriesOn returns the forwarding entries d learned on port.
func (l *Ledger) EntriesOn(d *swtele.Device, port string) []swtele.MACEntry {
	k := swtele.InterfaceKey(port)
	var out []swtele.MACEntry
	for _, e := range d.L2.MACs {
		if swtele.InterfaceKey(e.Port) == k {
			out = append(out, e)
		}
	}
	return out
}

// Subnet returns the interfaces whose prefix contains ip: the gateways of
// its subnet.
func (l *Ledger) Subnet(ip netip.Addr) []Gateway {
	var out []Gateway
	for _, d := range l.devices {
		for _, i := range d.Interfaces.All() {
			for _, a := range i.Addresses {
				if a.Prefix.Bits() < a.Prefix.Addr().BitLen() && a.Prefix.Masked().Contains(ip) {
					out = append(out, Gateway{Device: d, Interface: i, Prefix: a.Prefix})
				}
			}
		}
	}
	return out
}

// Gateway is an interface whose subnet contains an address.
type Gateway struct {
	Device    *swtele.Device
	Interface *swtele.Interface
	Prefix    netip.Prefix
}

func (l *Ledger) index(d *swtele.Device) {
	if d.Identity.Mgmt.IsValid() {
		l.byMgmt[d.Identity.Mgmt] = d
	}
	for _, n := range []string{d.Identity.Name, d.System.Hostname} {
		if k := NameKey(n); k != "" {
			l.byName[k] = d
		}
	}
	if d.Stack != nil && !d.Stack.MAC.IsZero() {
		l.byMAC[d.Stack.MAC] = d
	}
	for _, i := range d.Interfaces.All() {
		if !i.MAC.IsZero() {
			l.byMAC[i.MAC] = d
		}
		for _, a := range i.Addresses {
			if _, taken := l.byMgmt[a.Prefix.Addr()]; !taken {
				l.byMgmt[a.Prefix.Addr()] = d
			}
		}
	}
	for _, e := range d.L3.ARP {
		ref := ARPRef{Device: d, Entry: e}
		l.arp[e.IP] = append(l.arp[e.IP], ref)
		if !e.MAC.IsZero() {
			l.arpMAC[e.MAC] = append(l.arpMAC[e.MAC], ref)
		}
	}
	for _, e := range d.L2.MACs {
		l.macs[e.MAC] = append(l.macs[e.MAC], MACRef{Device: d, Entry: e})
		if e.Port != "" {
			l.ports[portKey{d, swtele.InterfaceKey(e.Port)}]++
		}
	}
}
