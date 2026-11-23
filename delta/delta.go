// Package delta compares two ledger batches: devices added or removed,
// and per device the ports, optics, neighbors, routing peers, stack roles,
// aggregate members and VLANs that changed. It flattens each device into
// keyed facts and compares them with netops diff.Maps.
package delta

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/netops/diff"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
)

// Kind is what changed.
type Kind string

// Change kinds.
const (
	DeviceAdded   Kind = "device_added"
	DeviceRemoved Kind = "device_removed"
	PortState     Kind = "port_state"
	PortSpeed     Kind = "port_speed"
	PortDesc      Kind = "port_description"
	OpticsSwapped Kind = "optics"
	Neighbor      Kind = "neighbor"
	Peer          Kind = "routing_peer"
	StackRole     Kind = "stack"
	Aggregate     Kind = "aggregate"
	VLAN          Kind = "vlan"
	Version       Kind = "version"
)

// Change is one difference between two batches.
type Change struct {
	Device string    `json:"device"`
	Mgmt   string    `json:"mgmt"`
	Kind   Kind      `json:"kind"`
	Op     diff.Kind `json:"op"`
	Key    string    `json:"key"`
	Before string    `json:"before,omitempty"`
	After  string    `json:"after,omitempty"`
}

// Compare returns the changes from prev to cur, ordered by device, kind
// and key. Dimensions observed incompletely in either batch are skipped,
// so a failed command never reads as everything removed.
func Compare(prev, cur *ledger.Ledger) []Change {
	var out []Change
	before := map[string]*swtele.Device{}
	for _, d := range prev.Devices() {
		before[d.Identity.Mgmt.String()] = d
	}
	after := map[string]*swtele.Device{}
	for _, d := range cur.Devices() {
		after[d.Identity.Mgmt.String()] = d
	}
	for _, dl := range diff.Maps(before, after, func(_, _ *swtele.Device) bool { return false }) {
		switch dl.Kind {
		case diff.KindAdded:
			out = append(out, Change{Device: dl.After.Name(), Mgmt: dl.Key, Kind: DeviceAdded, Op: dl.Kind})
		case diff.KindRemoved:
			out = append(out, Change{Device: dl.Before.Name(), Mgmt: dl.Key, Kind: DeviceRemoved, Op: dl.Kind})
		case diff.KindChanged:
			out = append(out, Device(dl.Before, dl.After)...)
		}
	}
	slices.SortFunc(out, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.Mgmt, b.Mgmt), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Key, b.Key))
	})
	return out
}

// Device returns the changes of one device between two observations.
func Device(prev, cur *swtele.Device) []Change {
	a, b := facts(prev, cur), facts(cur, prev)
	var out []Change
	for _, dl := range diff.Maps(a, b, func(x, y fact) bool { return x.value == y.value }) {
		f := dl.After
		if dl.Kind == diff.KindRemoved {
			f = dl.Before
		}
		out = append(out, Change{Device: cur.Name(), Mgmt: cur.Identity.Mgmt.String(), Kind: f.kind, Op: dl.Kind,
			Key: f.label, Before: dl.Before.value, After: dl.After.value})
	}
	return out
}

type fact struct {
	kind  Kind
	label string
	value string
}

// facts flattens d into keyed facts, keeping only dimensions observed
// completely in both d and other.
func facts(d, other *swtele.Device) map[string]fact {
	ok := func(dim ...evidence.Dimension) bool {
		for _, x := range dim {
			if !d.Coverage.Status(x).Complete() || !other.Coverage.Status(x).Complete() {
				return false
			}
		}
		return true
	}
	out := map[string]fact{}
	put := func(kind Kind, label, value string) {
		out[string(kind)+"|"+label] = fact{kind: kind, label: label, value: value}
	}
	if d.System.Version != "" && other.System.Version != "" {
		put(Version, "software", d.System.Version)
	}
	if ok(swtele.DimInterfaces) {
		portFacts(d, put)
	}
	if ok(swtele.DimOpticsInv) || ok(swtele.DimOptics) {
		opticsFacts(d, put)
	}
	if ok(swtele.DimNeighbors) {
		for _, n := range d.Neighbors {
			put(Neighbor, n.LocalPort+" → "+cmp.Or(n.System, n.ChassisID)+" "+n.Port, "present")
		}
	}
	peerFacts(d, ok, put)
	if ok(swtele.DimStack) && d.Stack != nil {
		for _, m := range d.Stack.Members {
			put(StackRole, fmt.Sprintf("member %d", m.ID), m.Role)
		}
	}
	if ok(swtele.DimAggregates) {
		aggregateFacts(d, put)
	}
	if d.Config != nil && other.Config != nil {
		for _, v := range d.Config.VLANs {
			put(VLAN, strconv.Itoa(v.ID), v.Name)
		}
	}
	return out
}

func portFacts(d *swtele.Device, put func(Kind, string, string)) {
	for _, i := range d.Interfaces.All() {
		if i.Kind != swtele.KindPhysical && i.Kind != swtele.KindAggregate {
			continue
		}
		put(PortState, i.Name, portState(i))
		if s, has := i.Speed.Get(); has && i.Up() {
			put(PortSpeed, i.Name, fmt.Sprintf("%d Mb/s", s/1_000_000))
		}
		if i.Desc != "" {
			put(PortDesc, i.Name, i.Desc)
		}
	}
}

func opticsFacts(d *swtele.Device, put func(Kind, string, string)) {
	for _, i := range d.Interfaces.All() {
		if i.Optics != nil && i.Optics.Inventory.Serial != "" {
			put(OpticsSwapped, i.Name, i.Optics.Inventory.Serial)
		}
	}
}

func peerFacts(d *swtele.Device, ok func(...evidence.Dimension) bool, put func(Kind, string, string)) {
	for _, p := range d.L3.Peers {
		dim := swtele.DimOSPF
		if p.Proto == swtele.ProtoBGP {
			dim = swtele.DimBGP
		}
		if ok(dim) {
			put(Peer, fmt.Sprintf("%s %s %s %s", p.Proto, p.VRF, p.Family, p.Address), p.State)
		}
	}
}

func aggregateFacts(d *swtele.Device, put func(Kind, string, string)) {
	for _, a := range d.Aggregates {
		var sel []string
		for _, m := range a.Members {
			if m.Selected {
				sel = append(sel, m.Port)
			}
		}
		slices.Sort(sel)
		put(Aggregate, a.Name, strings.Join(sel, ","))
	}
}

func portState(i *swtele.Interface) string {
	switch {
	case i.Admin == swtele.StateDown:
		return "admin-down"
	case i.Up():
		return "up"
	}
	return "down"
}
