package swtele

import (
	"net/netip"
	"time"
)

// Neighbor is a device seen on a local port through LLDP or CDP.
type Neighbor struct {
	LocalPort string `json:"local_port"`
	Protocol  string `json:"protocol"`
	System    string `json:"system,omitempty"`
	Port      string `json:"port,omitempty"`
	PortDesc  string `json:"port_description,omitempty"`
	ChassisID string `json:"chassis_id,omitempty"`
	// ChassisMAC is ChassisID when it is a MAC address.
	ChassisMAC   MAC        `json:"chassis_mac,omitzero"`
	MgmtAddr     netip.Addr `json:"mgmt_address,omitzero"`
	Platform     string     `json:"platform,omitempty"`
	SysDesc      string     `json:"system_description,omitempty"`
	Capabilities []string   `json:"capabilities,omitempty"`
	PVID         Opt[int]   `json:"pvid,omitzero"`
}

// LogEvent is one notable device log message.
type LogEvent struct {
	At       Opt[time.Time] `json:"at,omitzero"`
	Module   string         `json:"module"`
	Severity int            `json:"severity"`
	Mnemonic string         `json:"mnemonic"`
	// Interface is the port the message is about, when it names one.
	Interface string `json:"interface,omitempty"`
	Text      string `json:"text"`
}
