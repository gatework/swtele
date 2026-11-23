package swtele

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
)

// Schema is the version of the Device JSON encoding.
const Schema = 1

// Dimensions a device is observed in. Coverage records each one's status
// so that analyses skip what was not observed instead of reporting a
// false finding.
const (
	DimSystem      evidence.Dimension = "system"
	DimCPU         evidence.Dimension = "cpu"
	DimMemory      evidence.Dimension = "memory"
	DimEnvironment evidence.Dimension = "environment"
	DimInterfaces  evidence.Dimension = "interfaces"
	DimCounters    evidence.Dimension = "counters"
	DimRates       evidence.Dimension = "rates"
	DimAddresses   evidence.Dimension = "addresses"
	DimOptics      evidence.Dimension = "optics"
	DimOpticsInv   evidence.Dimension = "optics_inventory"
	DimAggregates  evidence.Dimension = "aggregates"
	DimStack       evidence.Dimension = "stack"
	DimMAD         evidence.Dimension = "mad"
	DimSTP         evidence.Dimension = "stp"
	DimNeighbors   evidence.Dimension = "neighbors"
	DimARP         evidence.Dimension = "arp"
	DimMAC         evidence.Dimension = "mac"
	DimOSPF        evidence.Dimension = "ospf"
	DimBGP         evidence.Dimension = "bgp"
	DimFlap        evidence.Dimension = "flap"
	DimLogs        evidence.Dimension = "logs"
	DimConfig      evidence.Dimension = "config"
)

// Device is the runtime state of one device at one observation: the
// ledger entry.
type Device struct {
	Identity   device.Device     `json:"identity"`
	Observed   time.Time         `json:"observed"`
	Coverage   evidence.Coverage `json:"coverage"`
	System     System            `json:"system"`
	Stack      *Stack            `json:"stack,omitempty"`
	Interfaces Interfaces        `json:"interfaces"`
	Aggregates []Aggregate       `json:"aggregates,omitempty"`
	L2         Bridging          `json:"l2"`
	L3         Routing           `json:"l3"`
	Neighbors  []Neighbor        `json:"neighbors,omitempty"`
	Logs       []LogEvent        `json:"logs,omitempty"`
	// Config is the configured intent, when a configuration was read.
	Config *DeviceConfig    `json:"config,omitempty"`
	Issues []evidence.Issue `json:"issues,omitempty"`
}

// New returns an empty device for identity, observed at at.
func New(identity device.Device, at time.Time) *Device {
	return &Device{Identity: identity, Observed: at.UTC()}
}

// Name returns the best display name: the inventory name, else the
// hostname, else the management address.
func (d *Device) Name() string {
	switch {
	case d.Identity.Name != "":
		return d.Identity.Name
	case d.System.Hostname != "":
		return d.System.Hostname
	}
	return d.Identity.Mgmt.String()
}

// Observe records the status of a dimension, keeping the worse one when
// several outputs feed it.
func (d *Device) Observe(dim evidence.Dimension, status evidence.Status, issues ...evidence.Issue) {
	if prev := d.Coverage.Status(dim); prev != "" && prev != evidence.StatusNotRequested {
		status = evidence.Worse(prev, status)
	}
	d.Coverage = d.Coverage.With(dim, status)
	d.Issues = append(d.Issues, issues...)
}

// Usable reports whether every dimension was observed completely or
// partially.
func (d *Device) Usable(dims ...evidence.Dimension) bool {
	for _, dim := range dims {
		if !d.Coverage.Status(dim).Usable() {
			return false
		}
	}
	return true
}

// Aggregate returns the aggregate named name, or nil.
func (d *Device) Aggregate(name string) *Aggregate {
	k := InterfaceKey(name)
	for i := range d.Aggregates {
		if InterfaceKey(d.Aggregates[i].Name) == k {
			return &d.Aggregates[i]
		}
	}
	return nil
}

// MarshalJSON encodes the table as a list in device order.
func (t *Interfaces) MarshalJSON() ([]byte, error) {
	list := t.list
	if list == nil {
		list = []*Interface{}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("swtele: encode interfaces: %w", err)
	}
	return b, nil
}

// UnmarshalJSON decodes a list and rebuilds the index.
func (t *Interfaces) UnmarshalJSON(b []byte) error {
	var list []*Interface
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("swtele: decode interfaces: %w", err)
	}
	*t = Interfaces{}
	for _, i := range list {
		t.Add(i)
	}
	return nil
}
