// Package path traces the layer-2 forwarding path between two endpoints
// over the confirmed links of the topology.
//
// Both ends are first located on their access ports. Within one VLAN the
// path is the shortest walk over confirmed links whose two ends carry the
// VLAN. Across VLANs the path runs to the source's gateway, marks a
// layer-3 hop, and continues from the destination's gateway; routes
// between gateways are not inferred.
package path

import (
	"fmt"
	"slices"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/topology"
)

// Hop is one device on the path.
type Hop struct {
	Device *swtele.Device `json:"-"`
	Name   string         `json:"device"`
	// In and Out are the ports the traffic enters and leaves by; In is
	// empty at the first hop and Out at the last.
	In   string `json:"in,omitempty"`
	Out  string `json:"out,omitempty"`
	VLAN int    `json:"vlan,omitempty"`
	// Routed marks a layer-3 gateway, where the VLAN changes.
	Routed bool `json:"routed,omitempty"`
	// Unchecked marks a link whose VLAN carriage is unknown (no
	// switchport data on one end).
	Unchecked bool `json:"unchecked,omitempty"`
}

// Status is the outcome of a trace.
type Status string

const (
	// Found means a full path joins the source and destination.
	Found Status = "found"
	// Partial means both ends were located without a carrying path.
	Partial Status = "partial"
	// Unlocated means an end could not be located on an access port.
	Unlocated Status = "unlocated"
)

// Result is a traced path.
type Result struct {
	From   locate.Location `json:"from"`
	To     locate.Location `json:"to"`
	Status Status          `json:"status"`
	Hops   []Hop           `json:"hops,omitempty"`
	// Reason explains a Partial or Unlocated result.
	Reason string `json:"reason,omitempty"`
}

// Tracer traces paths in one ledger.
type Tracer struct {
	l *ledger.Ledger
	g *topology.Graph
	x *locate.Locator
}

// New returns a tracer.
func New(l *ledger.Ledger, g *topology.Graph, x *locate.Locator) *Tracer {
	return &Tracer{l: l, g: g, x: x}
}

// end is a located endpoint: its access device, port and VLAN, and its
// gateway device.
type end struct {
	dev  *swtele.Device
	port string
	vlan int
	gw   *swtele.Device
	gwIf string
}

// Trace returns the path from src to dst (IP or MAC each).
func (t *Tracer) Trace(src, dst string) Result {
	r := Result{From: t.x.Locate(src), To: t.x.Locate(dst)}
	a, errA := t.end(r.From)
	b, errB := t.end(r.To)
	if errA != nil || errB != nil {
		r.Status, r.Reason = Unlocated, firstErr(errA, errB).Error()
		return r
	}
	if a.vlan == b.vlan || a.vlan == 0 || b.vlan == 0 {
		hops, ok := t.walk(a.dev, a.port, b.dev, b.port, max(a.vlan, b.vlan))
		r.Hops = hops
		if !ok {
			r.Status, r.Reason = Partial, fmt.Sprintf("在 VLAN %d 中找不到连接 %s 与 %s 的已确认链路", a.vlan, a.dev.Name(), b.dev.Name())
			return r
		}
		r.Status = Found
		return r
	}
	if a.gw == nil || b.gw == nil {
		r.Status, r.Reason = Partial, "跨 VLAN，但台账中找不到网关设备"
		return r
	}
	up, ok1 := t.walk(a.dev, a.port, a.gw, a.gwIf, a.vlan)
	down, ok2 := t.walk(b.gw, b.gwIf, b.dev, b.port, b.vlan)
	switch {
	case !ok1:
		r.Hops, r.Status, r.Reason = up, Partial, fmt.Sprintf("源端到网关 %s 的路径在 VLAN %d 中不通", a.gw.Name(), a.vlan)
		return r
	case !ok2:
		up = append(up, down...)
		r.Hops, r.Status, r.Reason = up, Partial, fmt.Sprintf("网关 %s 到目的端的路径在 VLAN %d 中不通", b.gw.Name(), b.vlan)
		return r
	}
	up[len(up)-1].Routed = true
	if a.gw == b.gw {
		// One gateway routes between the two VLANs: merge its hops.
		down[0].In, down[0].Routed = up[len(up)-1].In, true
		up = up[:len(up)-1]
	} else {
		down[0].Routed = true
	}
	up = append(up, down...)
	r.Hops, r.Status = up, Found
	return r
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *Tracer) end(loc locate.Location) (end, error) {
	var e end
	switch {
	case loc.Confidence == locate.Device && len(loc.Access) == 0:
		d := t.l.Device(loc.Device)
		if d == nil {
			return e, fmt.Errorf("%s 是网络设备 %s 的地址，但找不到它的上联口", loc.Query, loc.Device)
		}
		e.dev, e.port = d, loc.Interface
	case len(loc.Access) == 0:
		return e, fmt.Errorf("%s 未定位到接入口（%s）", loc.Query, loc.Confidence)
	default:
		p := loc.Access[0]
		e.dev, e.port, e.vlan = t.l.Device(p.Mgmt), p.Interface, p.VLAN
		if e.dev == nil {
			return e, fmt.Errorf("%s 的接入设备 %s 不在台账中", loc.Query, p.Device)
		}
	}
	if len(loc.Gateways) > 0 {
		g := loc.Gateways[0]
		e.gw, e.gwIf = t.l.Device(g.Mgmt), g.Interface
		if e.vlan == 0 {
			e.vlan = g.VLAN
		}
	}
	return e, nil
}

// step is a device reached by the search: in is its port the link
// arrives on, via the parent's port it leaves by.
type step struct {
	dev       *swtele.Device
	in, via   string
	prev      int
	unchecked bool
}

// walk runs a breadth-first search from (from, fromPort) to to over
// confirmed links carrying vlan. It returns the hops and whether to was
// reached; when not, the hops are just the first device.
func (t *Tracer) walk(from *swtele.Device, fromPort string, to *swtele.Device, toPort string, vlan int) ([]Hop, bool) {
	steps := []step{{dev: from, prev: -1}}
	seen := map[*swtele.Device]bool{from: true}
	found := -1
	for n := 0; n < len(steps) && found < 0; n++ {
		s := steps[n]
		if s.dev == to {
			found = n
			break
		}
		for _, l := range t.g.LinksOf(s.dev) {
			nb := l.B.Device
			if l.State != topology.Confirmed || nb == nil || seen[nb] {
				continue
			}
			okA, knownA := carries(s.dev, l.A.Port, vlan)
			okB, knownB := carries(nb, l.B.Port, vlan)
			if !okA || !okB {
				continue
			}
			seen[nb] = true
			steps = append(steps, step{dev: nb, in: l.B.Port, via: l.A.Port, prev: n, unchecked: !knownA || !knownB})
		}
	}
	if found < 0 {
		return []Hop{{Device: from, Name: from.Name(), In: fromPort, VLAN: vlan}}, false
	}
	var rev []step
	for n := found; n >= 0; n = steps[n].prev {
		rev = append(rev, steps[n])
	}
	hops := make([]Hop, 0, len(rev))
	for n, s := range slices.Backward(rev) {
		h := Hop{Device: s.dev, Name: s.dev.Name(), In: s.in, VLAN: vlan, Unchecked: s.unchecked}
		if n > 0 {
			h.Out = rev[n-1].via
		}
		hops = append(hops, h)
	}
	hops[0].In, hops[len(hops)-1].Out = fromPort, toPort
	return hops, true
}

// carries reports whether port of d forwards vlan, and whether that is
// known. An aggregate member answers for its aggregate.
func carries(d *swtele.Device, port string, vlan int) (ok, known bool) {
	i := d.Interfaces.Get(port)
	if i == nil {
		return true, false
	}
	if i.Aggregate != "" {
		if agg := d.Interfaces.Get(i.Aggregate); agg != nil && agg.Switching != nil {
			i = agg
		}
	}
	sw := i.Switching
	if !i.Up() {
		return false, true
	}
	if sw == nil || vlan == 0 {
		return true, false
	}
	switch sw.Mode {
	case swtele.ModeRouted:
		return false, true
	case swtele.ModeAccess:
		p, known := sw.PVID.Get()
		return !known || p == vlan, known
	case swtele.ModeUnknown, swtele.ModeTrunk, swtele.ModeHybrid:
	}
	if sw.Allowed == nil {
		return true, false
	}
	return sw.Allowed.Contains(vlan) || sw.PVID.Or(-1) == vlan, true
}
