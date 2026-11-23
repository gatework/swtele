package query

import (
	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

// LinkRow is one link with both interfaces when known.
type LinkRow struct {
	Link          topology.Link
	Local, Remote *swtele.Interface
}

// Links returns the links with an end on devs, seen from that end, each
// cable once.
func (c Context) Links(devs []*swtele.Device) []LinkRow {
	in := map[*swtele.Device]bool{}
	for _, d := range devs {
		in[d] = true
	}
	seen := map[[2]string]bool{}
	var out []LinkRow
	for _, d := range devs {
		for _, l := range c.Graph.LinksOf(d) {
			key := [2]string{d.Identity.Mgmt.String() + "|" + swtele.InterfaceKey(l.A.Port), ""}
			if l.B.Device != nil {
				key[1] = l.B.Device.Identity.Mgmt.String() + "|" + swtele.InterfaceKey(l.B.Port)
				if seen[[2]string{key[1], key[0]}] {
					continue
				}
			}
			seen[key] = true
			r := LinkRow{Link: l, Local: d.Interfaces.Get(l.A.Port)}
			if l.B.Device != nil {
				r.Remote = l.B.Device.Interfaces.Get(l.B.Port)
			}
			out = append(out, r)
		}
	}
	return out
}

// Link is a link predicate.
type Link = func(LinkRow) bool

// LinkState matches one-way, shared, unmanaged or confirmed links.
func LinkState(s string) Link {
	want := map[string]topology.State{"one-way": topology.OneWay, "shared": topology.Shared, "unmanaged": topology.Unmanaged, "confirmed": topology.Confirmed}[s]
	return func(r LinkRow) bool { return r.Link.State == want }
}

// Mismatches returns how the two ends of a confirmed link disagree:
// speed, duplex, mtu, pvid, vlans.
func Mismatches(r LinkRow) []string {
	a, b := r.Local, r.Remote
	if r.Link.State != topology.Confirmed || a == nil || b == nil || !a.Up() || !b.Up() {
		return nil
	}
	var out []string
	if a.Speed.OK && b.Speed.OK && a.Speed.V != b.Speed.V {
		out = append(out, "speed")
	}
	if a.Duplex != "" && b.Duplex != "" && a.Duplex != b.Duplex {
		out = append(out, "duplex")
	}
	if a.MTU.OK && b.MTU.OK && a.MTU.V != b.MTU.V && a.Kind == swtele.KindPhysical && b.Kind == swtele.KindPhysical {
		out = append(out, "mtu")
	}
	// Switching settings live on the aggregate of a member.
	sa, sb := logical(r.Link.A.Device, a).Switching, logical(r.Link.B.Device, b).Switching
	if sa != nil && sb != nil {
		if sa.Mode == swtele.ModeAccess && sb.Mode == swtele.ModeAccess && sa.PVID.OK && sb.PVID.OK && sa.PVID.V != sb.PVID.V {
			out = append(out, "pvid")
		}
		if sa.Mode == swtele.ModeTrunk && sb.Mode == swtele.ModeTrunk && sa.Allowed != nil && sb.Allowed != nil && !sa.Allowed.Equal(sb.Allowed) {
			out = append(out, "vlans")
		}
	}
	return out
}

// Mismatch matches links whose ends disagree on kind ("" for any).
func Mismatch(kind string) Link {
	return func(r LinkRow) bool {
		for _, m := range Mismatches(r) {
			if kind == "" || m == kind {
				return true
			}
		}
		return false
	}
}

func logical(d *swtele.Device, i *swtele.Interface) *swtele.Interface {
	if i.Aggregate != "" {
		if agg := d.Interfaces.Get(i.Aggregate); agg != nil && agg.Switching != nil {
			return agg
		}
	}
	return i
}
