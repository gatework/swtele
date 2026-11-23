package swtele

import "net/netip"

// StackKind is the stacking or multi-chassis technology.
type StackKind string

// Stack kinds.
const (
	StackIRF StackKind = "irf"
	StackVPC StackKind = "vpc"
	StackHA  StackKind = "ha"
)

// Stack is a multi-member system: an IRF fabric, a vPC pair or an HA pair.
type Stack struct {
	Kind    StackKind   `json:"kind"`
	Domain  string      `json:"domain,omitempty"`
	MAC     MAC         `json:"mac,omitzero"`
	Members []Member    `json:"members,omitempty"`
	Links   []StackLink `json:"links,omitempty"`
	MAD     *MAD        `json:"mad,omitempty"`
}

// Member is one stack member.
type Member struct {
	ID       int      `json:"id"`
	Role     string   `json:"role"`
	Priority Opt[int] `json:"priority,omitzero"`
	MAC      MAC      `json:"mac,omitzero"`
	// Self marks the member the session is logged in to.
	Self bool   `json:"self,omitempty"`
	Desc string `json:"description,omitempty"`
}

// StackLink is one physical port bound to a stack port.
type StackLink struct {
	Member    int    `json:"member"`
	Port      int    `json:"port"`
	Interface string `json:"interface"`
	State     State  `json:"state,omitempty"`
}

// MAD is multi-active detection: how a split stack avoids two masters.
type MAD struct {
	// Modes lists the enabled mechanisms (bfd, lacp, arp, nd); empty means
	// MAD is disabled.
	Modes []string `json:"modes,omitempty"`
	// Status is the device's verdict, such as "Normal".
	Status string `json:"status,omitempty"`
	// Recovering is true when the stack is in multi-active recovery.
	Recovering bool        `json:"recovering,omitempty"`
	Interface  string      `json:"interface,omitempty"`
	Members    []MADMember `json:"members,omitempty"`
}

// Enabled reports whether any detection mechanism is on.
func (m *MAD) Enabled() bool { return m != nil && len(m.Modes) > 0 }

// MADMember is the detection state of one member.
type MADMember struct {
	Member  int        `json:"member"`
	Address netip.Addr `json:"address,omitzero"`
	Port    string     `json:"port,omitempty"`
	Status  string     `json:"status,omitempty"`
}
