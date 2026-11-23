package query

import (
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

// PortRow is one port with its context.
type PortRow struct {
	Device *swtele.Device
	Port   *swtele.Interface
	Role   topology.Role
	// MACs is how many endpoints the port learned.
	MACs int
	// Peer is the far end of the link, when the topology knows one.
	Peer    topology.End
	HasPeer bool
	// Prev is the same port in the previous batch, or nil.
	Prev    *swtele.Interface
	Elapsed time.Duration
	// Config is the port's configured intent, or nil.
	Config *swtele.PortConfig
}

// Ports returns the physical and aggregate ports of devs.
func (c Context) Ports(devs []*swtele.Device) []PortRow {
	var out []PortRow
	for _, d := range devs {
		prev := c.prev(d)
		for _, i := range d.Interfaces.All() {
			if i.Kind != swtele.KindPhysical && i.Kind != swtele.KindAggregate && i.Kind != swtele.KindMgmt {
				continue
			}
			r := PortRow{Device: d, Port: i, Role: c.Graph.Role(d, i.Name), MACs: c.Ledger.PortMACs(d, i.Name), Elapsed: c.elapsed(d)}
			r.Peer, r.HasPeer = c.Graph.Peer(d, i.Name)
			if prev != nil {
				r.Prev = prev.Interfaces.Get(i.Name)
			}
			if d.Config != nil {
				r.Config = d.Config.Port(i.Name)
			}
			out = append(out, r)
		}
	}
	return out
}

// Port is a port predicate.
type Port = func(PortRow) bool

// Status matches "up", "down", "admin-down", "err-disabled", "stp-down".
func Status(s string) Port {
	return func(r PortRow) bool {
		i := r.Port
		switch s {
		case "up":
			return i.Up()
		case "down":
			return !i.Up() && i.Admin != swtele.StateDown
		case "admin-down":
			return i.Admin == swtele.StateDown
		case "err-disabled":
			return i.DownCause == swtele.CauseErrDisabled
		case "stp-down":
			return i.DownCause == swtele.CauseSTP
		}
		return false
	}
}

// DownFor returns how long a down port has been down, and whether that is
// known: never up, or the time since its last flap or down event.
func DownFor(r PortRow) (d time.Duration, never, ok bool) {
	i := r.Port
	switch {
	case i.Up() || i.Admin == swtele.StateDown:
		return 0, false, false
	case i.Flap.Never:
		return 0, true, true
	case i.Flap.Since.OK:
		return i.Flap.Since.V, false, true
	case i.Flap.LastDown.OK:
		return r.Device.Observed.Sub(i.Flap.LastDown.V), false, true
	}
	return 0, false, false
}

// Idle matches a down, enabled physical port down for at least window
// (or never up): a port to reclaim.
func Idle(window time.Duration) Port {
	return func(r PortRow) bool {
		if r.Port.Kind != swtele.KindPhysical {
			return false
		}
		d, never, ok := DownFor(r)
		return ok && (never || d >= window)
	}
}

// ErrorCount returns the inbound error total (CRC or input errors).
func ErrorCount(i *swtele.Interface) uint64 {
	return max(i.Counters.CRC.Or(0), i.Counters.In.Errors.Or(0))
}

// ErrorRate returns the share of received packets that were errored, from
// 0 to 1: CRC errors over received packets, or input errors when the
// device counts no CRC. Input errors also count events such as aborts, so
// the share is capped at 1.
func ErrorRate(i *swtele.Interface) float64 {
	pkts := i.Counters.In.Packets.Or(0)
	if pkts == 0 {
		return 0
	}
	errs := i.Counters.CRC.Or(0)
	if !i.Counters.CRC.OK {
		errs = i.Counters.In.Errors.Or(0)
	}
	return min(1, float64(errs)/float64(pkts))
}

// Growth returns how much the inbound errors grew since the previous
// batch, and whether it is known (both present and not cleared).
func Growth(r PortRow) (uint64, bool) {
	if r.Prev == nil {
		return 0, false
	}
	now, was := ErrorCount(r.Port), ErrorCount(r.Prev)
	if now < was {
		return 0, false // counters cleared or device restarted
	}
	return now - was, true
}

// Errors matches ports with inbound errors.
func Errors() Port { return func(r PortRow) bool { return ErrorCount(r.Port) > 0 } }

// Growing matches ports whose errors grew since the previous batch.
func Growing() Port {
	return func(r PortRow) bool {
		g, ok := Growth(r)
		return ok && g > 0
	}
}

// RateAbove matches ports whose error rate exceeds limit.
func RateAbove(limit float64) Port { return func(r PortRow) bool { return ErrorRate(r.Port) > limit } }

// Kind matches ports with a nonzero counter of one kind: crc, giants,
// runts, discards, pause.
func Kind(kind string) Port {
	return func(r PortRow) bool {
		c := r.Port.Counters
		switch kind {
		case "crc":
			return c.CRC.Or(0) > 0
		case "giants":
			return c.Giants.Or(0) > 0
		case "runts":
			return c.Runts.Or(0) > 0
		case "discards":
			return c.In.Discards.Or(0)+c.Out.Discards.Or(0) > 0
		case "pause":
			return c.In.Pause.Or(0)+c.Out.Pause.Or(0) > 0
		}
		return false
	}
}

// Flapping matches ports whose link changed within window.
func Flapping(window time.Duration) Port {
	return func(r PortRow) bool {
		s, ok := r.Port.Flap.Since.Get()
		return ok && !r.Port.Flap.Never && s < window
	}
}

// HalfDuplex matches up ports running half duplex.
func HalfDuplex() Port {
	return func(r PortRow) bool { return r.Port.Up() && r.Port.Duplex == swtele.DuplexHalf }
}

// SpeedBelow matches up ports slower than bps.
func SpeedBelow(bps uint64) Port {
	return func(r PortRow) bool { s, ok := r.Port.Speed.Get(); return r.Port.Up() && ok && s < bps }
}

// Utilization returns the busier direction's load in percent of speed.
func Utilization(i *swtele.Interface) (float64, bool) {
	s, ok := i.Speed.Get()
	if !ok || s == 0 || !i.Up() {
		return 0, false
	}
	return max(i.Rates.InBps.Or(0), i.Rates.OutBps.Or(0)) * 100 / float64(s), true
}

// UtilAbove matches ports loaded above pct.
func UtilAbove(pct float64) Port {
	return func(r PortRow) bool { u, ok := Utilization(r.Port); return ok && u >= pct }
}

// Mode matches the switching mode (access, trunk, hybrid, routed).
func Mode(m string) Port {
	return func(r PortRow) bool { return r.Port.Switching != nil && string(r.Port.Switching.Mode) == m }
}

// VLAN matches ports carrying vlan (access VLAN or allowed on a trunk).
func VLAN(vlan int) Port {
	return func(r PortRow) bool {
		sw := r.Port.Switching
		if sw == nil {
			return false
		}
		return sw.PVID.Or(0) == vlan || sw.Allowed != nil && sw.Allowed.Contains(vlan)
	}
}

// Role matches the topology role (edge, infra, stack, unused).
func Role(role string) Port { return func(r PortRow) bool { return string(r.Role) == role } }

// Desc matches a description containing keyword, case-insensitively.
func Desc(keyword string) Port {
	k := strings.ToLower(keyword)
	return func(r PortRow) bool { return strings.Contains(strings.ToLower(r.Port.Desc), k) }
}

// NoDesc matches up physical ports without a description.
func NoDesc() Port {
	return func(r PortRow) bool {
		return r.Port.Up() && r.Port.Kind == swtele.KindPhysical && strings.TrimSpace(r.Port.Desc) == ""
	}
}

// DescMismatch matches infrastructure ports whose description does not
// name the neighbor the topology sees.
func DescMismatch() Port {
	return func(r PortRow) bool {
		if !r.HasPeer || r.Peer.Device == nil || r.Port.Desc == "" {
			return false
		}
		d := strings.ToUpper(r.Port.Desc)
		return !strings.Contains(d, strings.ToUpper(r.Peer.Device.Name()))
	}
}

// MACsAbove matches edge ports that learned more than n endpoints: an
// unmanaged switch or hub behind an access port.
func MACsAbove(n int) Port {
	return func(r PortRow) bool { return r.Role == topology.RoleEdge && r.MACs > n }
}

// Drift returns how the port differs from its configuration, or nil.
func Drift(r PortRow) []string {
	c, i := r.Config, r.Port
	if c == nil {
		return nil
	}
	var out []string
	if i.Switching != nil && c.Mode != swtele.ModeUnknown && c.Mode != swtele.ModeRouted &&
		i.Switching.Mode != swtele.ModeUnknown && i.Switching.Mode != c.Mode && i.Aggregate == "" {
		out = append(out, "mode")
	}
	if i.Switching != nil && i.Switching.Allowed != nil && c.Allowed != nil && c.Mode == swtele.ModeTrunk &&
		i.Switching.Mode == swtele.ModeTrunk && i.Aggregate == "" && !i.Switching.Allowed.Equal(c.Allowed) {
		out = append(out, "vlans")
	}
	if shut, ok := c.Shutdown.Get(); ok && i.Admin != swtele.StateUnknown && i.Kind == swtele.KindPhysical && (i.Admin == swtele.StateDown) != shut {
		out = append(out, "admin")
	}
	if i.Kind == swtele.KindPhysical && swtele.InterfaceKey(i.Aggregate) != swtele.InterfaceKey(c.Aggregate) {
		out = append(out, "aggregate")
	}
	return out
}

// Drifted matches ports differing from their configuration.
func Drifted() Port { return func(r PortRow) bool { return len(Drift(r)) > 0 } }

// SortPorts orders rows by device, then interface name.
func SortPorts(rows []PortRow) {
	sortDevices(rows, func(r PortRow) *swtele.Device { return r.Device })
}
