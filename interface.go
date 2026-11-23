package swtele

import (
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/netops/set"
)

// Kind classifies an interface.
type Kind string

// Interface kinds.
const (
	KindUnknown   Kind = ""
	KindPhysical  Kind = "physical"
	KindAggregate Kind = "aggregate"
	KindSVI       Kind = "svi"
	KindLoopback  Kind = "loopback"
	KindTunnel    Kind = "tunnel"
	KindMgmt      Kind = "mgmt"
	KindNull      Kind = "null"
	KindVirtual   Kind = "virtual"
)

// State is an administrative or operational state.
type State string

// States.
const (
	StateUnknown State = ""
	StateUp      State = "up"
	StateDown    State = "down"
	StateStandby State = "standby"
	StateTesting State = "testing"
)

// DownCause explains why a port is down.
type DownCause string

// Down causes.
const (
	CauseNone         DownCause = ""
	CauseNotConnected DownCause = "not_connected"
	CauseAdmin        DownCause = "admin"
	CauseSTP          DownCause = "stp"
	CauseAggregate    DownCause = "aggregate"
	CauseErrDisabled  DownCause = "err_disabled"
	CauseNoXcvr       DownCause = "transceiver_absent"
	CauseSuspended    DownCause = "suspended"
	CauseOther        DownCause = "other"
)

// Duplex is the negotiated duplex mode.
type Duplex string

// Duplex modes.
const (
	DuplexUnknown Duplex = ""
	DuplexFull    Duplex = "full"
	DuplexHalf    Duplex = "half"
	DuplexAuto    Duplex = "auto"
)

// PortMode is the switching mode of a layer-2 port.
type PortMode string

// Port modes.
const (
	ModeUnknown PortMode = ""
	ModeAccess  PortMode = "access"
	ModeTrunk   PortMode = "trunk"
	ModeHybrid  PortMode = "hybrid"
	ModeRouted  PortMode = "routed"
)

// Interface is one interface of a device and everything observed on it.
type Interface struct {
	// Name is the full name the device uses in configuration, such as
	// "GigabitEthernet1/0/1"; Key() compares across spellings.
	Name      string      `json:"name"`
	Kind      Kind        `json:"kind,omitempty"`
	Index     Opt[int]    `json:"index,omitzero"`
	Desc      string      `json:"description,omitempty"`
	Admin     State       `json:"admin,omitempty"`
	Oper      State       `json:"oper,omitempty"`
	Protocol  State       `json:"protocol,omitempty"`
	DownCause DownCause   `json:"down_cause,omitempty"`
	Speed     Opt[uint64] `json:"speed_bps,omitzero"`
	Duplex    Duplex      `json:"duplex,omitempty"`
	AutoSpeed Opt[bool]   `json:"auto_speed,omitzero"`
	MTU       Opt[int]    `json:"mtu,omitzero"`
	MAC       MAC         `json:"mac,omitzero"`
	// Media is the port hardware type the device reports, such as
	// "10G_BASE_SR_SFP" or "1000_BASE_T".
	Media     string      `json:"media,omitempty"`
	Fiber     Opt[bool]   `json:"fiber,omitzero"`
	Switching *Switchport `json:"switching,omitempty"`
	Addresses []IfAddr    `json:"addresses,omitempty"`
	VRF       string      `json:"vrf,omitempty"`
	// Aggregate is the name of the aggregate this port is a member of.
	Aggregate string       `json:"aggregate,omitempty"`
	Counters  Counters     `json:"counters,omitzero"`
	Rates     Rates        `json:"rates,omitzero"`
	Flap      Flap         `json:"flap,omitzero"`
	Optics    *Transceiver `json:"optics,omitempty"`
}

// Key returns the vendor-independent comparison key of the interface.
func (i *Interface) Key() string { return InterfaceKey(i.Name) }

// Up reports an operationally up interface.
func (i *Interface) Up() bool { return i.Oper == StateUp }

// Switchport is the layer-2 configuration of a port.
type Switchport struct {
	Mode     PortMode      `json:"mode,omitempty"`
	PVID     Opt[int]      `json:"pvid,omitzero"`
	Allowed  *set.Set[int] `json:"allowed,omitempty"`
	Untagged *set.Set[int] `json:"untagged,omitempty"`
}

// IfAddr is an address configured on an interface.
type IfAddr struct {
	Prefix  netip.Prefix `json:"prefix"`
	Primary bool         `json:"primary,omitempty"`
}

// Direction holds the cumulative counters of one direction.
type Direction struct {
	Octets   Opt[uint64] `json:"octets,omitzero"`
	Packets  Opt[uint64] `json:"packets,omitzero"`
	Unicast  Opt[uint64] `json:"unicast,omitzero"`
	Multicst Opt[uint64] `json:"multicast,omitzero"`
	Bcast    Opt[uint64] `json:"broadcast,omitzero"`
	Pause    Opt[uint64] `json:"pause,omitzero"`
	Errors   Opt[uint64] `json:"errors,omitzero"`
	Discards Opt[uint64] `json:"discards,omitzero"`
}

// Counters are cumulative interface counters since the last clear.
type Counters struct {
	In  Direction `json:"in,omitzero"`
	Out Direction `json:"out,omitzero"`

	CRC        Opt[uint64] `json:"crc,omitzero"`
	Frame      Opt[uint64] `json:"frame,omitzero"`
	Runts      Opt[uint64] `json:"runts,omitzero"`
	Giants     Opt[uint64] `json:"giants,omitzero"`
	Overruns   Opt[uint64] `json:"overruns,omitzero"`
	Aborts     Opt[uint64] `json:"aborts,omitzero"`
	Throttles  Opt[uint64] `json:"throttles,omitzero"`
	NoBuffer   Opt[uint64] `json:"no_buffer,omitzero"`
	Underruns  Opt[uint64] `json:"underruns,omitzero"`
	Collisions Opt[uint64] `json:"collisions,omitzero"`
	LateColl   Opt[uint64] `json:"late_collisions,omitzero"`
	StompedCRC Opt[uint64] `json:"stomped_crc,omitzero"`
	Resets     Opt[uint64] `json:"resets,omitzero"`
}

// Rates are the device's own averaged rates over Window.
type Rates struct {
	Window time.Duration `json:"window,omitempty"`
	InBps  Opt[float64]  `json:"in_bps,omitzero"`
	OutBps Opt[float64]  `json:"out_bps,omitzero"`
	InPps  Opt[float64]  `json:"in_pps,omitzero"`
	OutPps Opt[float64]  `json:"out_pps,omitzero"`
}

// Flap records when the link last changed.
type Flap struct {
	// Never is true when the device reports the link has never flapped.
	Never bool `json:"never,omitempty"`
	// Since is how long ago the link last flapped, as of the observation.
	Since Opt[time.Duration] `json:"since,omitzero"`
	// LastUp is when the physical state last changed to up.
	LastUp Opt[time.Time] `json:"last_up,omitzero"`
	// LastDown is when the physical state last changed to down.
	LastDown Opt[time.Time] `json:"last_down,omitzero"`
}

// Interfaces is the interface table of a device, kept in device order.
type Interfaces struct {
	list  []*Interface
	index map[string]int
}

// Add inserts i, or returns the existing interface with the same key.
// Callers merge facts into the returned interface.
func (t *Interfaces) Add(i *Interface) *Interface {
	if t.index == nil {
		t.index = map[string]int{}
	}
	k := i.Key()
	if at, ok := t.index[k]; ok {
		return t.list[at]
	}
	t.index[k] = len(t.list)
	t.list = append(t.list, i)
	return i
}

// Ensure returns the interface named name, creating it when absent.
func (t *Interfaces) Ensure(name string) *Interface {
	if i := t.Get(name); i != nil {
		return i
	}
	return t.Add(&Interface{Name: CleanName(name)})
}

// Get returns the interface with any spelling of name, or nil.
func (t *Interfaces) Get(name string) *Interface {
	at, ok := t.index[InterfaceKey(name)]
	if !ok {
		return nil
	}
	return t.list[at]
}

// All returns the interfaces in device order.
func (t *Interfaces) All() []*Interface { return slices.Clone(t.list) }

// Len returns the number of interfaces.
func (t *Interfaces) Len() int { return len(t.list) }
