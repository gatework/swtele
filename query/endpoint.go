package query

import (
	"net/netip"
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/locate"
)

// EndpointRow is one endpoint located on an access port.
type EndpointRow struct {
	locate.Sighting

	// Device and Port are the access device and port.
	Device *swtele.Device
	Port   *swtele.Interface
	// Vendor is the organization of the MAC's OUI, "" when unknown.
	Vendor string
	// Record is the endpoint's history, nil when none was kept.
	Record *locate.Record
	// SameIP is how many distinct MACs answer for this IP.
	SameIP int
}

// Endpoints joins sightings with their access ports, vendor names and
// history. oui maps "aa:bb:cc" to the vendor and may be nil.
func (c Context) Endpoints(seen []locate.Sighting, history []locate.Record, oui map[string]string) []EndpointRow {
	recs := make(map[string]*locate.Record, len(history))
	for n := range history {
		recs[history[n].MAC+"|"+history[n].IP] = &history[n]
	}
	macs := map[netip.Addr]map[swtele.MAC]bool{}
	for _, s := range seen {
		if macs[s.IP] == nil {
			macs[s.IP] = map[swtele.MAC]bool{}
		}
		macs[s.IP][s.MAC] = true
	}
	out := make([]EndpointRow, 0, len(seen))
	for _, s := range seen {
		r := EndpointRow{Sighting: s, Vendor: oui[s.MAC.OUI()], Record: recs[s.MAC.String()+"|"+s.IP.String()], SameIP: len(macs[s.IP])}
		if r.Device = c.Ledger.Device(s.Mgmt); r.Device != nil {
			r.Port = r.Device.Interfaces.Get(s.Port)
		}
		out = append(out, r)
	}
	return out
}

// Endpoint is an endpoint predicate.
type Endpoint = func(EndpointRow) bool

// OnVLAN matches endpoints in vlan.
func OnVLAN(vlan int) Endpoint { return func(r EndpointRow) bool { return r.VLAN == vlan } }

// InSubnet matches endpoints whose address is in p.
func InSubnet(p netip.Prefix) Endpoint {
	return func(r EndpointRow) bool { return p.Contains(r.IP) }
}

// OUIPrefix matches a MAC prefix of at least six hex digits in any
// spelling ("aa:bb:cc", "aabb.cc") or, otherwise, a vendor name substring.
func OUIPrefix(text string) Endpoint {
	hex := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(text))
	isHex := len(hex) >= 6 && strings.Trim(hex, "0123456789abcdef") == ""
	word := strings.ToLower(text)
	return func(r EndpointRow) bool {
		if isHex {
			return strings.HasPrefix(strings.ReplaceAll(r.MAC.String(), ":", ""), hex)
		}
		return r.Vendor != "" && strings.Contains(strings.ToLower(r.Vendor), word)
	}
}

// PortDesc matches endpoints whose access port description contains kw.
func PortDesc(kw string) Endpoint {
	k := strings.ToLower(kw)
	return func(r EndpointRow) bool {
		return r.Port != nil && strings.Contains(strings.ToLower(r.Port.Desc), k)
	}
}

// BehindUnmanaged matches endpoints behind an unmanaged bridge (AP,
// desktop switch) rather than directly on the port.
func BehindUnmanaged() Endpoint {
	return func(r EndpointRow) bool { return r.Confidence == locate.Shared }
}

// NewSince matches endpoints first seen within d of now.
func NewSince(d time.Duration, now time.Time) Endpoint {
	return func(r EndpointRow) bool { return r.Record != nil && now.Sub(r.Record.First) <= d }
}

// MovedSince matches endpoints that changed port within d of now.
func MovedSince(d time.Duration, now time.Time) Endpoint {
	return func(r EndpointRow) bool {
		return r.Record != nil && len(r.Record.Moves) > 0 && now.Sub(r.Record.Place.Since) <= d
	}
}

// MovesAbove matches endpoints that moved more than n times in their
// kept history: roaming hosts, or a MAC claimed in several places.
func MovesAbove(n int) Endpoint {
	return func(r EndpointRow) bool { return r.Record != nil && len(r.Record.Moves) > n }
}

// IPConflict matches endpoints whose IP several MACs answer for.
func IPConflict() Endpoint { return func(r EndpointRow) bool { return r.SameIP > 1 } }
