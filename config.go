package swtele

import (
	"net/netip"
	"time"

	"github.com/gatework/netops/set"
)

// PortConfig is the configured intent of an interface, kept apart from
// what the device reports so that drift between the two is visible.
type PortConfig struct {
	Desc string `json:"description,omitempty"`
	// Shutdown is known when the configuration states it (or the platform
	// default is certain).
	Shutdown Opt[bool]     `json:"shutdown,omitzero"`
	Mode     PortMode      `json:"mode,omitempty"`
	PVID     Opt[int]      `json:"pvid,omitzero"`
	Allowed  *set.Set[int] `json:"allowed,omitempty"`
	// Aggregate is the configured aggregation group, as an aggregate
	// interface name.
	Aggregate string         `json:"aggregate,omitempty"`
	LACP      Opt[bool]      `json:"lacp,omitzero"`
	VRF       string         `json:"vrf,omitempty"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	MTU       Opt[int]       `json:"mtu,omitzero"`
	// Edge is an STP edge (port fast) port.
	Edge Opt[bool] `json:"stp_edge,omitzero"`
	// BPDUProtection is per-port BPDU guard.
	BPDUProtection Opt[bool] `json:"bpdu_protection,omitzero"`
	VPC            string    `json:"vpc,omitempty"`
}

// DeviceConfig is the configured intent of a device.
type DeviceConfig struct {
	// At is when the configuration was backed up.
	At       time.Time `json:"at,omitzero"`
	Source   string    `json:"source,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	Version  string    `json:"version,omitempty"`
	VLANs    []VLAN    `json:"vlans,omitempty"`
	// STP global settings.
	STPEnabled     Opt[bool] `json:"stp_enabled,omitzero"`
	STPMode        string    `json:"stp_mode,omitempty"`
	STPPriority    Opt[int]  `json:"stp_priority,omitzero"`
	BPDUProtection Opt[bool] `json:"bpdu_protection,omitzero"`
	LLDP           Opt[bool] `json:"lldp,omitzero"`
	// IRF member priorities by member ID.
	IRFPriority map[int]int `json:"irf_priority,omitempty"`
	// MADBFD lists the interfaces with BFD MAD enabled.
	MADBFD    []string `json:"mad_bfd,omitempty"`
	VPCDomain string   `json:"vpc_domain,omitempty"`
	Static    []Route  `json:"static_routes,omitempty"`
	// Ports holds the configuration of each interface by name.
	Ports map[string]*PortConfig `json:"ports,omitempty"`
}

// Port returns the configuration of the interface with any spelling of
// name, or nil.
func (c *DeviceConfig) Port(name string) *PortConfig {
	if c == nil {
		return nil
	}
	if p, ok := c.Ports[name]; ok {
		return p
	}
	k := InterfaceKey(name)
	for n, p := range c.Ports {
		if InterfaceKey(n) == k {
			return p
		}
	}
	return nil
}
