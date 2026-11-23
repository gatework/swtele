package query

import (
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

// DeviceRow is one device with its health score and finding count, which
// the caller computes with the risk catalog.
type DeviceRow struct {
	Device   *swtele.Device
	Score    int
	Findings int
	Uplinks  int
}

// DeviceRows wraps devs; scores are filled by the caller.
func (c Context) DeviceRows(devs []*swtele.Device) []DeviceRow {
	out := make([]DeviceRow, 0, len(devs))
	for _, d := range devs {
		r := DeviceRow{Device: d, Score: -1}
		for _, l := range c.Graph.LinksOf(d) {
			if l.State == topology.Confirmed && l.B.Device != nil {
				r.Uplinks++
			}
		}
		out = append(out, r)
	}
	return out
}

// Device is a device predicate.
type Device = func(DeviceRow) bool

func contains(field, v string) bool {
	return strings.Contains(strings.ToLower(field), strings.ToLower(v))
}

// Platform matches the platform by substring; Model and Version likewise.
func Platform(v string) Device {
	return func(r DeviceRow) bool { return contains(r.Device.Identity.Platform, v) }
}

// Model matches the model by substring.
func Model(v string) Device {
	return func(r DeviceRow) bool { return contains(r.Device.System.Model, v) }
}

// Version matches the software version by substring.
func Version(v string) Device {
	return func(r DeviceRow) bool { return contains(r.Device.System.Version, v) }
}

// CPU returns the highest CPU load of d (5-minute, else current).
func CPU(d *swtele.Device) (float64, bool) {
	best, ok := 0.0, false
	for _, c := range d.System.CPU {
		v, has := c.Min5.Get()
		if !has {
			v, has = c.Now.Get()
		}
		if has && (!ok || v > best) {
			best, ok = v, true
		}
	}
	return best, ok
}

// Memory returns the highest memory utilization of d.
func Memory(d *swtele.Device) (float64, bool) {
	best, ok := 0.0, false
	for _, m := range d.System.Memory {
		if v, has := m.UsedPercent(); has && (!ok || v > best) {
			best, ok = v, true
		}
	}
	return best, ok
}

// Temperature returns the hottest sensor of d.
func Temperature(d *swtele.Device) (float64, bool) {
	best, ok := 0.0, false
	for _, s := range d.System.Sensors {
		if v, has := s.Value.Get(); has && (!ok || v > best) {
			best, ok = v, true
		}
	}
	return best, ok
}

// CPUAbove matches devices with a CPU at or above pct.
func CPUAbove(pct float64) Device {
	return func(r DeviceRow) bool { v, ok := CPU(r.Device); return ok && v >= pct }
}

// MemAbove matches devices with memory at or above pct.
func MemAbove(pct float64) Device {
	return func(r DeviceRow) bool { v, ok := Memory(r.Device); return ok && v >= pct }
}

// TempAlarm matches devices with a sensor at its warning or alarm limit.
func TempAlarm() Device {
	return func(r DeviceRow) bool {
		for _, s := range r.Device.System.Sensors {
			v, ok := s.Value.Get()
			if !ok {
				continue
			}
			if s.Warning.OK && v >= s.Warning.V || s.Alarm.OK && v >= s.Alarm.V {
				return true
			}
		}
		return false
	}
}

// FanPSUFault matches devices with a failed fan or power supply.
func FanPSUFault() Device {
	return func(r DeviceRow) bool {
		for _, c := range append(append([]swtele.Component{}, r.Device.System.Fans...), r.Device.System.PSUs...) {
			if ok, known := c.OK.Get(); known && !ok {
				return true
			}
		}
		return false
	}
}

// ScoreBelow matches devices scoring under n.
func ScoreBelow(n int) Device { return func(r DeviceRow) bool { return r.Score >= 0 && r.Score < n } }

// IRFNoMAD matches multi-member IRF fabrics without multi-active
// detection.
func IRFNoMAD() Device {
	return func(r DeviceRow) bool {
		s := r.Device.Stack
		return s != nil && s.Kind == swtele.StackIRF && len(s.Members) > 1 && s.MAD != nil && !s.MAD.Enabled()
	}
}

// IRFSplit matches IRF fabrics with fewer members than configured.
func IRFSplit() Device {
	return func(r DeviceRow) bool {
		s, c := r.Device.Stack, r.Device.Config
		return s != nil && c != nil && len(c.IRFPriority) > len(s.Members)
	}
}

// StaleConfig matches devices whose configuration backup is older than
// age at the observation, or missing.
func StaleConfig(age time.Duration) Device {
	return func(r DeviceRow) bool {
		c := r.Device.Config
		return c == nil || r.Device.Observed.Sub(c.At) > age
	}
}

// Incomplete matches devices with a dimension not observed completely.
func Incomplete() Device {
	return func(r DeviceRow) bool {
		for _, dim := range r.Device.Coverage.Dimensions() {
			if !r.Device.Coverage.Status(dim).Complete() && r.Device.Coverage.Status(dim) != "not_requested" {
				return true
			}
		}
		return false
	}
}

// SingleUplink matches devices with exactly one confirmed link to another
// managed device: no redundancy.
func SingleUplink() Device { return func(r DeviceRow) bool { return r.Uplinks == 1 } }
