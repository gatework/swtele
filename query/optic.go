package query

import (
	"math"
	"slices"
	"strings"

	"github.com/gatework/swtele"
)

// OpticRow is one present transceiver with its port.
type OpticRow struct {
	Device *swtele.Device
	Port   *swtele.Interface
	Optic  *swtele.Transceiver
	// Prev is the module of the same port in the previous batch, or nil.
	Prev *swtele.Transceiver
}

// Optics returns the present transceivers of devs.
func (c Context) Optics(devs []*swtele.Device) []OpticRow {
	var out []OpticRow
	for _, d := range devs {
		prev := c.prev(d)
		for _, i := range d.Interfaces.All() {
			if i.Optics == nil || !i.Optics.Present {
				continue
			}
			r := OpticRow{Device: d, Port: i, Optic: i.Optics}
			if prev != nil {
				if p := prev.Interfaces.Get(i.Name); p != nil {
					r.Prev = p.Optics
				}
			}
			out = append(out, r)
		}
	}
	return out
}

// Optic is a transceiver predicate.
type Optic = func(OpticRow) bool

// Graded reports a module whose readings mean something: the port is up
// and the module reports diagnostics. A down port neither sends nor
// receives light.
func Graded(r OpticRow) bool {
	return r.Port.Up() && r.Optic.DOM != swtele.DOMUnsupported && len(r.Optic.Lanes) > 0
}

// Worst returns the worst level of every reading of a graded module, with
// an up port receiving no light as an alarm.
func Worst(r OpticRow) swtele.Level {
	if !Graded(r) {
		return swtele.LevelUnknown
	}
	x := r.Optic
	worst := swtele.LevelNormal
	note := func(l swtele.Level) {
		if rank[l] > rank[worst] {
			worst = l
		}
	}
	note(x.Temp.Level())
	note(x.Voltage.Level())
	for _, l := range x.Lanes {
		note(l.Bias.Level())
		note(l.TxPower.Level())
		note(l.RxPower.Level())
		if l.RxPower.Dark() {
			note(swtele.LevelAlarm)
		}
	}
	return worst
}

var rank = map[swtele.Level]int{swtele.LevelUnknown: 0, swtele.LevelNormal: 1, swtele.LevelWarn: 2, swtele.LevelAlarm: 3}

// RxMargin returns the smallest receive margin to the low warning (or
// alarm) threshold over the lanes of a graded module.
func RxMargin(r OpticRow) (float64, bool) {
	if !Graded(r) {
		return 0, false
	}
	best, ok := math.Inf(1), false
	for _, l := range r.Optic.Lanes {
		lo := l.RxPower.Th.LowWarn
		if !lo.OK {
			lo = l.RxPower.Th.LowAlarm
		}
		if v, has := l.RxPower.Value.Get(); has && lo.OK && v > swtele.NoLight {
			best, ok = min(best, v-lo.V), true
		}
	}
	return best, ok
}

// Spread returns the receive power spread across lanes, in dB.
func Spread(r OpticRow) float64 {
	if !Graded(r) || len(r.Optic.Lanes) < 2 {
		return 0
	}
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, l := range r.Optic.Lanes {
		if v, ok := l.RxPower.Value.Get(); ok {
			lo, hi = min(lo, v), max(hi, v)
		}
	}
	return hi - lo
}

// Level matches a graded module whose worst reading is at least level.
func Level(level swtele.Level) Optic {
	return func(r OpticRow) bool { return rank[Worst(r)] >= rank[level] }
}

// Dark matches an up port receiving no light.
func Dark() Optic {
	return func(r OpticRow) bool {
		if !Graded(r) {
			return false
		}
		for _, l := range r.Optic.Lanes {
			if l.RxPower.Dark() {
				return true
			}
		}
		return false
	}
}

// MarginBelow matches graded modules with less than db receive margin.
func MarginBelow(db float64) Optic {
	return func(r OpticRow) bool { m, ok := RxMargin(r); return ok && m < db }
}

// Abnormal matches every graded module needing attention: a reading at
// warning or alarm, no light, a receive margin below marginDB, or lanes
// apart by more than spreadDB.
func Abnormal(marginDB, spreadDB float64) Optic {
	return func(r OpticRow) bool {
		return Level(swtele.LevelWarn)(r) || Dark()(r) || MarginBelow(marginDB)(r) || Spread(r) > spreadDB
	}
}

// NoDOM matches modules without diagnostics.
func NoDOM() Optic {
	return func(r OpticRow) bool { return r.Optic.DOM == swtele.DOMUnsupported || len(r.Optic.Lanes) == 0 }
}

// IdleModule matches a module plugged into a port that is down or shut:
// a module to reclaim.
func IdleModule() Optic { return func(r OpticRow) bool { return !r.Port.Up() } }

// Vendor matches the module vendor, case-insensitively by substring.
func Vendor(v string) Optic {
	k := strings.ToLower(v)
	return func(r OpticRow) bool { return strings.Contains(strings.ToLower(r.Optic.Inventory.Vendor), k) }
}

// Type matches the module type or part number by substring (SR, LR, AOC).
func Type(t string) Optic {
	k := strings.ToUpper(t)
	return func(r OpticRow) bool {
		inv := r.Optic.Inventory
		return strings.Contains(strings.ToUpper(inv.Type+" "+inv.PartNumber+" "+inv.ProductID+" "+r.Port.Media), k)
	}
}

// Speed matches modules in ports running at bps.
func Speed(bps uint64) Optic { return func(r OpticRow) bool { return r.Port.Speed.Or(0) == bps } }

// NonOriginal matches modules whose vendor differs from the device's
// brand (an H3C switch with a third-party module).
func NonOriginal() Optic {
	return func(r OpticRow) bool {
		v := strings.ToUpper(r.Optic.Inventory.Vendor)
		if v == "" {
			return false
		}
		brand := map[string]string{"comware": "H3C", "nxos": "CISCO", "ios": "CISCO"}[r.Device.Identity.Platform]
		if brand == "" {
			switch r.Device.Identity.Platform {
			case "h3c", "h3c_wireless":
				brand = "H3C"
			case "cisco_nxos", "cisco_ios":
				brand = "CISCO"
			default:
				return false
			}
		}
		return !strings.Contains(v, brand)
	}
}

// Swapped matches modules whose serial changed since the previous batch.
func Swapped() Optic {
	return func(r OpticRow) bool {
		if r.Prev == nil {
			return false
		}
		now, was := r.Optic.Inventory.Serial, r.Prev.Inventory.Serial
		return now != "" && was != "" && now != was
	}
}

// SortOptics orders rows by device.
func SortOptics(rows []OpticRow) {
	sortDevices(rows, func(r OpticRow) *swtele.Device { return r.Device })
}

// Issue is one reason a graded module is abnormal.
type Issue struct {
	What  string // temperature, voltage, bias, tx, rx, dark, margin, spread
	High  bool   // above the high threshold (else below the low one)
	Level swtele.Level
	Lane  int
}

// Issues explains why a graded module is abnormal, worst first.
func Issues(r OpticRow, marginDB, spreadDB float64) []Issue {
	if !Graded(r) {
		return nil
	}
	var out []Issue
	note := func(what string, rd swtele.Reading, lane int) {
		if l := rd.Level(); l == swtele.LevelWarn || l == swtele.LevelAlarm {
			high := rd.Th.HighWarn.OK && rd.Value.V > rd.Th.HighWarn.V || rd.Th.HighAlarm.OK && rd.Value.V > rd.Th.HighAlarm.V
			out = append(out, Issue{What: what, High: high, Level: l, Lane: lane})
		}
	}
	x := r.Optic
	note("temperature", x.Temp, 0)
	note("voltage", x.Voltage, 0)
	for _, l := range x.Lanes {
		if l.RxPower.Dark() {
			out = append(out, Issue{What: "dark", Level: swtele.LevelAlarm, Lane: l.Index})
			continue
		}
		note("rx", l.RxPower, l.Index)
		note("tx", l.TxPower, l.Index)
		note("bias", l.Bias, l.Index)
	}
	if m, ok := RxMargin(r); ok && m < marginDB && len(out) == 0 {
		out = append(out, Issue{What: "margin", Level: swtele.LevelWarn})
	}
	if Spread(r) > spreadDB {
		out = append(out, Issue{What: "spread", Level: swtele.LevelWarn})
	}
	slices.SortStableFunc(out, func(a, b Issue) int { return rank[b.Level] - rank[a.Level] })
	return out
}
