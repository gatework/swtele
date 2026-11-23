// Package capacity summarizes the port capacity of devices: how many
// ports are in use, which have been idle long enough to reclaim, and
// which run hot.
package capacity

import (
	"cmp"
	"slices"
	"time"

	"github.com/gatework/swtele"
)

// Options tune the summary.
type Options struct {
	// IdleDays is how long a down port must have been down to count as
	// idle (default 30).
	IdleDays int
	// HotPercent is the utilization of a hot port (default 70).
	HotPercent float64
}

// Idle is a port that can be reclaimed.
type Idle struct {
	Port string `json:"port"`
	Desc string `json:"description,omitempty"`
	// Since is how long the port has been down; zero when it never came up.
	Since time.Duration `json:"since,omitempty"`
	Never bool          `json:"never_up,omitempty"`
}

// Hot is a port running above the threshold.
type Hot struct {
	Port    string  `json:"port"`
	Desc    string  `json:"description,omitempty"`
	Percent float64 `json:"percent"`
	Speed   uint64  `json:"speed_bps"`
}

// Summary is the capacity of one device.
type Summary struct {
	Device   string `json:"device"`
	Mgmt     string `json:"mgmt"`
	Physical int    `json:"physical"`
	Up       int    `json:"up"`
	Down     int    `json:"down"`
	Disabled int    `json:"disabled"`
	Idle     []Idle `json:"idle,omitempty"`
	Hot      []Hot  `json:"hot,omitempty"`
}

// Device summarizes d.
func Device(d *swtele.Device, o Options) Summary {
	if o.IdleDays <= 0 {
		o.IdleDays = 30
	}
	if o.HotPercent <= 0 {
		o.HotPercent = 70
	}
	window := time.Duration(o.IdleDays) * 24 * time.Hour
	s := Summary{Device: d.Name(), Mgmt: d.Identity.Mgmt.String()}
	for _, i := range d.Interfaces.All() {
		if i.Kind != swtele.KindPhysical {
			continue
		}
		s.Physical++
		switch {
		case i.Admin == swtele.StateDown:
			s.Disabled++
		case i.Up():
			s.Up++
			if h, ok := hot(i, o.HotPercent); ok {
				s.Hot = append(s.Hot, h)
			}
		default:
			s.Down++
			if idle, ok := idleFor(d, i, window); ok {
				s.Idle = append(s.Idle, idle)
			}
		}
	}
	slices.SortFunc(s.Hot, func(a, b Hot) int { return cmp.Compare(b.Percent, a.Percent) })
	return s
}

// idleFor reports a down port idle for at least window: it never flapped
// (never came up), or its last change is older than window.
func idleFor(d *swtele.Device, i *swtele.Interface, window time.Duration) (Idle, bool) {
	idle := Idle{Port: i.Name, Desc: i.Desc}
	switch {
	case i.Flap.Never:
		idle.Never = true
		return idle, true
	case i.Flap.Since.OK:
		idle.Since = i.Flap.Since.V
	case i.Flap.LastDown.OK:
		idle.Since = d.Observed.Sub(i.Flap.LastDown.V)
	default:
		return idle, false // no evidence of how long it has been down
	}
	return idle, idle.Since >= window
}

func hot(i *swtele.Interface, limit float64) (Hot, bool) {
	speed, ok := i.Speed.Get()
	if !ok || speed == 0 {
		return Hot{}, false
	}
	pct := max(i.Rates.InBps.Or(0), i.Rates.OutBps.Or(0)) * 100 / float64(speed)
	return Hot{Port: i.Name, Desc: i.Desc, Percent: pct, Speed: speed}, pct >= limit
}
