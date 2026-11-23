package metrics

import (
	"cmp"
	"fmt"
	"slices"
	"time"
)

// Metric names a trended number.
type Metric string

// Metrics: counters grow and are trended by their deltas; gauges are
// trended by value.
const (
	CRC      Metric = "crc"
	Errors   Metric = "errors"
	Discards Metric = "discards"
	Util     Metric = "util"
	Rx       Metric = "rx"
	CPU      Metric = "cpu"
	Memory   Metric = "mem"
	Temp     Metric = "temp"
)

// Metrics lists the known metrics.
var Metrics = []Metric{CRC, Errors, Discards, Util, Rx, CPU, Memory, Temp}

// Counter reports whether m is a cumulative counter.
func (m Metric) Counter() bool { return m == CRC || m == Errors || m == Discards }

// PortLevel reports whether m is measured per port.
func (m Metric) PortLevel() bool { return m != CPU && m != Memory && m != Temp }

// ParseMetric validates a metric name.
func ParseMetric(s string) (Metric, error) {
	if m := Metric(s); slices.Contains(Metrics, m) {
		return m, nil
	}
	return "", fmt.Errorf("metrics: unknown metric %q", s)
}

// Point is one batch's value of a series.
type Point struct {
	Batch string    `json:"batch"`
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
	// Delta is the growth since the previous point (counters only) and
	// Reset marks a counter that went backwards (cleared or rebooted):
	// its delta is unknown.
	Delta float64 `json:"delta,omitempty"`
	Reset bool    `json:"reset,omitempty"`
	// PerHour is Delta per hour of elapsed time.
	PerHour float64 `json:"per_hour,omitempty"`
}

// Series is one device or port over the batches.
type Series struct {
	Mgmt   string  `json:"mgmt"`
	Device string  `json:"device"`
	Port   string  `json:"port,omitempty"`
	Metric Metric  `json:"metric"`
	Points []Point `json:"points"`
}

// Growth sums the known deltas of a counter series.
func (s Series) Growth() float64 {
	var g float64
	for _, p := range s.Points {
		g += p.Delta
	}
	return g
}

// Growing counts the intervals in which a counter grew.
func (s Series) Growing() int {
	n := 0
	for _, p := range s.Points {
		if p.Delta > 0 {
			n++
		}
	}
	return n
}

// Sustained reports a counter that grew in every known interval, or a
// gauge that moved the bad way in every interval (receive power falling,
// the others rising), over at least two intervals.
func (s Series) Sustained() bool {
	if len(s.Points) < 3 {
		return false
	}
	for n := 1; n < len(s.Points); n++ {
		p, q := s.Points[n-1], s.Points[n]
		switch {
		case s.Metric.Counter():
			if q.Reset || q.Delta <= 0 {
				return false
			}
		case s.Metric == Rx:
			if q.Value >= p.Value {
				return false
			}
		case q.Value <= p.Value:
			return false
		}
	}
	return true
}

// Change is the last value minus the first.
func (s Series) Change() float64 {
	if len(s.Points) == 0 {
		return 0
	}
	return s.Points[len(s.Points)-1].Value - s.Points[0].Value
}

// Trend builds the series of m from snapshots (oldest first) for the
// devices in keep (by management address; nil keeps all) and, when port
// is not "", that port only.
func Trend(snaps []Snapshot, m Metric, keep map[string]bool, port func(string) bool) []Series {
	by := map[seriesKey]*Series{}
	for _, s := range snaps {
		for mgmt, d := range s.Devices {
			if keep != nil && !keep[mgmt] {
				continue
			}
			add := func(portName string, v float64) {
				k := seriesKey{mgmt, portName}
				addPoint(by, k, d.Name, m, Point{Batch: s.Batch, At: d.Observed, Value: v})
			}
			if !m.PortLevel() {
				if v, ok := deviceValue(d, m); ok {
					add("", v)
				}
				continue
			}
			for name, p := range d.Ports {
				if port != nil && !port(name) {
					continue
				}
				if v, ok := portValue(p, m); ok {
					add(name, v)
				}
			}
		}
	}
	out := make([]Series, 0, len(by))
	for _, se := range by {
		if m.Counter() {
			deltas(se)
		}
		out = append(out, *se)
	}
	slices.SortFunc(out, func(a, b Series) int {
		return cmp.Or(cmp.Compare(a.Device, b.Device), cmp.Compare(a.Mgmt, b.Mgmt), cmp.Compare(a.Port, b.Port))
	})
	return out
}

type seriesKey struct{ mgmt, port string }

func addPoint(by map[seriesKey]*Series, key seriesKey, device string, metric Metric, point Point) {
	series := by[key]
	if series == nil {
		series = &Series{Mgmt: key.mgmt, Device: device, Port: key.port, Metric: metric}
		by[key] = series
	}
	series.Points = append(series.Points, point)
}

func deltas(s *Series) {
	for n := 1; n < len(s.Points); n++ {
		p, q := &s.Points[n-1], &s.Points[n]
		if q.Value < p.Value {
			q.Reset = true
			continue
		}
		q.Delta = q.Value - p.Value
		if h := q.At.Sub(p.At).Hours(); h > 0 {
			q.PerHour = q.Delta / h
		}
	}
}

func deviceValue(d Device, m Metric) (float64, bool) {
	switch m {
	case CPU:
		return d.CPU.Get()
	case Memory:
		return d.Memory.Get()
	case Temp:
		return d.Temp.Get()
	case CRC, Errors, Discards, Util, Rx:
		return 0, false
	}
	return 0, false
}

func portValue(p Port, m Metric) (float64, bool) {
	switch m {
	case CRC:
		v, ok := p.CRC.Get()
		return float64(v), ok
	case Errors:
		v, ok := p.InErrors.Get()
		return float64(v), ok
	case Discards:
		v, ok := p.OutDiscards.Get()
		return float64(v), ok
	case Rx:
		return p.Rx.Get()
	case Util:
		s, ok := p.Speed.Get()
		if !ok || s == 0 || !p.Up {
			return 0, false
		}
		return max(p.InBps.Or(0), p.OutBps.Or(0)) * 100 / float64(s), true
	case CPU, Memory, Temp:
		return 0, false
	}
	return 0, false
}
