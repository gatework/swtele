package swtele

import "net/netip"

// AggMode is the aggregation protocol.
type AggMode string

// Aggregation modes.
const (
	AggUnknown AggMode = ""
	AggStatic  AggMode = "static"
	AggLACP    AggMode = "lacp"
)

// Aggregate is a link aggregation group.
type Aggregate struct {
	Name     string      `json:"name"`
	Mode     AggMode     `json:"mode,omitempty"`
	SystemID string      `json:"system_id,omitempty"`
	Members  []AggMember `json:"members,omitempty"`
}

// Selected returns the members carrying traffic.
func (a *Aggregate) Selected() []AggMember {
	var out []AggMember
	for _, m := range a.Members {
		if m.Selected {
			out = append(out, m)
		}
	}
	return out
}

// AggMember is one member port of an aggregate.
type AggMember struct {
	Port     string `json:"port"`
	Selected bool   `json:"selected"`
	// Status is the device's own code (Comware S/U/I, NX-OS P/D/s...).
	Status    string `json:"status,omitempty"`
	Reference bool   `json:"reference,omitempty"`
	// Flags are the LACP actor and partner state letters.
	Flags        LACPFlags `json:"flags,omitempty"`
	PartnerFlags LACPFlags `json:"partner_flags,omitempty"`
	PartnerID    string    `json:"partner_system,omitempty"`
	PartnerPort  string    `json:"partner_port,omitempty"`
}

// LACPFlags are LACP state letters A-H in IEEE order: A activity, B timeout,
// C aggregation, D synchronization, E collecting, F distributing, G
// defaulted, H expired.
type LACPFlags string

// Healthy reports an actor or partner that is aggregated, in sync,
// collecting and distributing (ACDEF), and not defaulted or expired.
func (f LACPFlags) Healthy() bool {
	for _, c := range "ACDEF" {
		if !f.has(c) {
			return false
		}
	}
	return !f.has('G') && !f.has('H')
}

func (f LACPFlags) has(c rune) bool {
	for _, r := range f {
		if r == c {
			return true
		}
	}
	return false
}

// Bridging is the layer-2 state of a device.
type Bridging struct {
	VLANs []VLAN     `json:"vlans,omitempty"`
	MACs  []MACEntry `json:"macs,omitempty"`
	STP   STP        `json:"stp,omitzero"`
}

// VLAN is one configured VLAN.
type VLAN struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
}

// MACKind is how a MAC entry was learned.
type MACKind string

// MAC entry kinds.
const (
	MACDynamic MACKind = "dynamic"
	MACStatic  MACKind = "static"
	MACAuth    MACKind = "auth"
	MACBlocked MACKind = "blocked"
	MACRemote  MACKind = "remote"
	MACSystem  MACKind = "system"
	MACOther   MACKind = "other"
)

// MACEntry is one forwarding-table entry.
type MACEntry struct {
	MAC  MAC     `json:"mac"`
	VLAN int     `json:"vlan,omitempty"`
	Port string  `json:"port,omitempty"`
	Kind MACKind `json:"kind,omitempty"`
	// Remote is the VTEP an overlay entry was learned from.
	Remote netip.Addr `json:"remote,omitzero"`
}

// STP is the spanning-tree state of a device.
type STP struct {
	Enabled        Opt[bool] `json:"enabled,omitzero"`
	Mode           string    `json:"mode,omitempty"`
	Priority       Opt[int]  `json:"priority,omitzero"`
	BPDUProtection Opt[bool] `json:"bpdu_protection,omitzero"`
	RootBridge     string    `json:"root_bridge,omitempty"`
	Ports          []STPPort `json:"ports,omitempty"`
}

// IsZero reports that nothing is known about STP.
func (s STP) IsZero() bool {
	return !s.Enabled.OK && s.Mode == "" && !s.Priority.OK && !s.BPDUProtection.OK && s.RootBridge == "" && len(s.Ports) == 0
}

// STPPort is the spanning-tree state of one port.
type STPPort struct {
	Port   string    `json:"port"`
	Role   string    `json:"role,omitempty"`
	State  string    `json:"state,omitempty"`
	Edge   Opt[bool] `json:"edge,omitzero"`
	Down   bool      `json:"down,omitempty"`
	Reason string    `json:"reason,omitempty"`
}
