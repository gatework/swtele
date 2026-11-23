package swtele

import (
	"fmt"
	"time"
)

// Unit locates a CPU or board: an IRF member or chassis, a slot and a CPU.
// Zero fields are "not applicable".
type Unit struct {
	Chassis int `json:"chassis,omitempty"`
	Slot    int `json:"slot,omitempty"`
	CPU     int `json:"cpu,omitempty"`
}

// String formats the unit as "chassis/slot/cpu" without empty levels.
func (u Unit) String() string {
	if u.Chassis > 0 {
		return fmt.Sprintf("%d/%d/%d", u.Chassis, u.Slot, u.CPU)
	}
	return fmt.Sprintf("%d/%d", u.Slot, u.CPU)
}

// System is the platform of a device: identity, CPU, memory and
// environment.
type System struct {
	Hostname string             `json:"hostname,omitempty"`
	Model    string             `json:"model,omitempty"`
	Version  string             `json:"version,omitempty"`
	Serial   string             `json:"serial,omitempty"`
	Uptime   Opt[time.Duration] `json:"uptime,omitzero"`
	// Clock is the device's own time when observed.
	Clock   Opt[time.Time] `json:"clock,omitzero"`
	CPU     []CPULoad      `json:"cpu,omitempty"`
	Memory  []MemoryUsage  `json:"memory,omitempty"`
	Sensors []Sensor       `json:"sensors,omitempty"`
	Fans    []Component    `json:"fans,omitempty"`
	PSUs    []Component    `json:"psus,omitempty"`
}

// CPULoad is the utilization of one CPU, in percent.
type CPULoad struct {
	Unit Unit         `json:"unit"`
	Now  Opt[float64] `json:"now,omitzero"`  // last 5 seconds or current
	Min1 Opt[float64] `json:"min1,omitzero"` // last minute
	Min5 Opt[float64] `json:"min5,omitzero"` // last 5 minutes
}

// MemoryUsage is the memory of one unit, in bytes.
type MemoryUsage struct {
	Unit  Unit        `json:"unit"`
	Total Opt[uint64] `json:"total,omitzero"`
	Used  Opt[uint64] `json:"used,omitzero"`
	Free  Opt[uint64] `json:"free,omitzero"`
	// FreeRatio is the device's own free percentage when it reports one;
	// it accounts for caches and is preferred over Free/Total.
	FreeRatio Opt[float64] `json:"free_ratio,omitzero"`
}

// UsedPercent returns the memory utilization in percent.
func (m MemoryUsage) UsedPercent() (float64, bool) {
	if r, ok := m.FreeRatio.Get(); ok {
		return 100 - r, true
	}
	if m.Total.OK && m.Total.V > 0 && m.Used.OK {
		return float64(m.Used.V) * 100 / float64(m.Total.V), true
	}
	return 0, false
}

// Sensor is a temperature (°C) or other environmental reading.
type Sensor struct {
	Unit     Unit         `json:"unit"`
	Name     string       `json:"name"`
	Value    Opt[float64] `json:"value,omitzero"`
	Lower    Opt[float64] `json:"lower,omitzero"`
	Warning  Opt[float64] `json:"warning,omitzero"`
	Alarm    Opt[float64] `json:"alarm,omitzero"`
	Shutdown Opt[float64] `json:"shutdown,omitzero"`
}

// Component is a fan or power supply.
type Component struct {
	Unit   Unit   `json:"unit"`
	ID     string `json:"id"`
	Model  string `json:"model,omitempty"`
	Status string `json:"status,omitempty"`
	// OK is the vendor-independent verdict on Status.
	OK Opt[bool] `json:"ok,omitzero"`
}
