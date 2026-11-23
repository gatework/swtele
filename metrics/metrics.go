// Package metrics keeps a small per-batch snapshot of the numbers that
// trend over time: port counters, load and receive power, and device CPU,
// memory and temperature. Trends read these snapshots instead of whole
// ledger batches.
package metrics

import (
	"math"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/query"
)

// Schema versions the snapshot file.
const Schema = 1

// Port is one port's numbers.
type Port struct {
	Up          bool                `json:"up,omitempty"`
	Speed       swtele.Opt[uint64]  `json:"speed,omitzero"`
	CRC         swtele.Opt[uint64]  `json:"crc,omitzero"`
	InErrors    swtele.Opt[uint64]  `json:"in_errors,omitzero"`
	InPackets   swtele.Opt[uint64]  `json:"in_packets,omitzero"`
	OutDiscards swtele.Opt[uint64]  `json:"out_discards,omitzero"`
	InBps       swtele.Opt[float64] `json:"in_bps,omitzero"`
	OutBps      swtele.Opt[float64] `json:"out_bps,omitzero"`
	// Rx is the weakest lane's receive power in dBm, on up ports with DOM.
	Rx swtele.Opt[float64] `json:"rx_dbm,omitzero"`
}

// Device is one device's numbers.
type Device struct {
	Name     string              `json:"name"`
	Observed time.Time           `json:"observed"`
	CPU      swtele.Opt[float64] `json:"cpu,omitzero"`
	Memory   swtele.Opt[float64] `json:"memory,omitzero"`
	Temp     swtele.Opt[float64] `json:"temperature,omitzero"`
	Ports    map[string]Port     `json:"ports,omitempty"`
}

// Snapshot is the metrics of one batch, keyed by management address.
type Snapshot struct {
	Schema  int               `json:"schema"`
	Batch   string            `json:"batch"`
	At      time.Time         `json:"at"`
	Devices map[string]Device `json:"devices"`
}

// From derives the snapshot of a batch.
func From(batch string, at time.Time, devs []*swtele.Device) Snapshot {
	s := Snapshot{Schema: Schema, Batch: batch, At: at.UTC(), Devices: make(map[string]Device, len(devs))}
	for _, d := range devs {
		m := Device{Name: d.Name(), Observed: d.Observed.UTC(), Ports: map[string]Port{}}
		m.CPU = opt(query.CPU(d))
		m.Memory = opt(query.Memory(d))
		m.Temp = opt(query.Temperature(d))
		for _, i := range d.Interfaces.All() {
			if i.Kind != swtele.KindPhysical && i.Kind != swtele.KindAggregate {
				continue
			}
			c := i.Counters
			p := Port{Up: i.Up(), Speed: i.Speed, CRC: c.CRC, InErrors: c.In.Errors, InPackets: c.In.Packets, OutDiscards: c.Out.Discards,
				InBps: i.Rates.InBps, OutBps: i.Rates.OutBps}
			if x := i.Optics; x != nil && i.Up() && x.DOM == swtele.DOMSupported {
				p.Rx = weakest(x)
			}
			m.Ports[i.Name] = p
		}
		s.Devices[d.Identity.Mgmt.String()] = m
	}
	return s
}

func opt(v float64, ok bool) swtele.Opt[float64] {
	if !ok {
		return swtele.Opt[float64]{}
	}
	return swtele.Some(v)
}

func weakest(x *swtele.Transceiver) swtele.Opt[float64] {
	lo, ok := math.Inf(1), false
	for _, l := range x.Lanes {
		if v, has := l.RxPower.Value.Get(); has && v < lo {
			lo, ok = v, true
		}
	}
	if !ok {
		return swtele.Opt[float64]{}
	}
	return swtele.Some(lo)
}
