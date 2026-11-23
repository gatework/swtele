package check_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/check"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/topology"
)

func dev(at time.Time) *swtele.Device {
	d := swtele.New(device.Device{Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1")}, at)
	for _, dim := range []evidence.Dimension{swtele.DimInterfaces, swtele.DimOptics, swtele.DimCounters, swtele.DimStack, swtele.DimMAD} {
		d.Observe(dim, evidence.StatusComplete)
	}
	return d
}

func run(t *testing.T, d, prev *swtele.Device) map[assess.RuleID]int {
	t.Helper()
	cat, err := check.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := assess.NewEngine(cat, assess.Policy{}, assess.Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New("t", d.Observed, []*swtele.Device{d})
	a, err := eng.Run(t.Context(), &check.Target{Ledger: l, Graph: topology.Build(l), Device: d, Prev: prev}, d.Coverage)
	if err != nil {
		t.Fatal(err)
	}
	out := map[assess.RuleID]int{}
	for _, f := range a.Findings {
		out[f.Rule]++
	}
	return out
}

func TestRules(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev, now := dev(t0), dev(t0.Add(time.Hour))
	for _, d := range []*swtele.Device{prev, now} {
		d.Stack = &swtele.Stack{Kind: swtele.StackIRF, Members: []swtele.Member{{ID: 1}, {ID: 2}}, MAD: &swtele.MAD{}}
	}
	th := swtele.Thresholds{LowAlarm: swtele.Some(-13.0), LowWarn: swtele.Some(-10.0)}
	set := func(d *swtele.Device, name string, crc, pkts uint64, rx float64) {
		i := d.Interfaces.Ensure(name)
		i.Kind, i.Oper = swtele.KindPhysical, swtele.StateUp
		i.Counters.CRC, i.Counters.In.Packets = swtele.Some(crc), swtele.Some(pkts)
		i.Optics = &swtele.Transceiver{Present: true, Lanes: []swtele.Lane{{Index: 1, RxPower: swtele.Reading{Value: swtele.Some(rx), Th: th}}}}
	}
	set(prev, "GE1/0/1", 100, 1_000_000, -5) // CRC grows by 500
	set(now, "GE1/0/1", 600, 2_000_000, -5)
	set(prev, "GE1/0/2", 900, 1_000_000, -5) // counters cleared: no growth
	set(now, "GE1/0/2", 3, 10, -40)          // dark while up
	// A down port with a dark, overheating module raises nothing.
	down := now.Interfaces.Ensure("GE1/0/3")
	down.Kind, down.Oper = swtele.KindPhysical, swtele.StateDown
	down.Optics = &swtele.Transceiver{Present: true, Temp: swtele.Reading{Value: swtele.Some(99.0), Th: swtele.Thresholds{HighAlarm: swtele.Some(70.0)}},
		Lanes: []swtele.Lane{{Index: 1, RxPower: swtele.Reading{Value: swtele.Some(-40.0), Th: th}}}}
	got := run(t, now, prev)
	want := map[assess.RuleID]int{"counters.error_growth": 1, "optics.rx_power": 1, "optics.module": 0, "stack.mad_disabled": 1}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s = %d, want %d (all %v)", id, got[id], n, got)
		}
	}

	// Without a previous batch the growth rule has nothing to compare.
	if got := run(t, now, nil); got["counters.error_growth"] != 0 {
		t.Errorf("growth without previous batch: %v", got)
	}
}

func TestInsufficientEvidence(t *testing.T) {
	t.Parallel()
	d := swtele.New(device.Device{Mgmt: netip.MustParseAddr("192.0.2.1")}, time.Unix(0, 0))
	d.Observe(swtele.DimOptics, evidence.StatusPartial)
	i := d.Interfaces.Ensure("GE1/0/1")
	i.Kind, i.Oper = swtele.KindPhysical, swtele.StateUp
	i.Optics = &swtele.Transceiver{Present: true, Lanes: []swtele.Lane{{Index: 1, RxPower: swtele.Reading{Value: swtele.Some(-40.0)}}}}
	if got := run(t, d, nil); got["optics.rx_power"] != 0 {
		t.Errorf("rule ran on partial evidence: %v", got)
	}
}

func TestLinkConsistency(t *testing.T) {
	t.Parallel()
	at := time.Unix(0, 0)
	mk := func(name, mgmt, chassis string) *swtele.Device {
		d := swtele.New(device.Device{Name: name, Mgmt: netip.MustParseAddr(mgmt)}, at)
		d.Observe(swtele.DimInterfaces, evidence.StatusComplete)
		d.Observe(swtele.DimNeighbors, evidence.StatusComplete)
		m, _ := swtele.ParseMAC(chassis)
		d.Stack = &swtele.Stack{Kind: swtele.StackIRF, MAC: m}
		return d
	}
	a, b := mk("a", "192.0.2.1", "0000-0000-0a01"), mk("b", "192.0.2.2", "0000-0000-0b01")
	vlans := func(lo, hi int) *set.Set[int] {
		s := set.New[int]()
		s.Add(lo, hi)
		return s
	}
	// Two members of one aggregate per side; the aggregates disagree on
	// VLANs 30-40, and member 2 disagrees on MTU.
	for _, x := range []struct {
		d       *swtele.Device
		agg     string
		allowed *set.Set[int]
	}{{a, "BAGG1", vlans(10, 40)}, {b, "BAGG9", vlans(10, 29)}} {
		agg := x.d.Interfaces.Ensure(x.agg)
		agg.Kind, agg.Oper = swtele.KindAggregate, swtele.StateUp
		agg.Switching = &swtele.Switchport{Mode: swtele.ModeTrunk, Allowed: x.allowed}
		for n, p := range []string{"XGE1/0/1", "XGE1/0/2"} {
			i := x.d.Interfaces.Ensure(p)
			i.Kind, i.Oper, i.Aggregate, i.MTU = swtele.KindPhysical, swtele.StateUp, x.agg, swtele.Some(1500)
			switch {
			case x.d == b && n == 1:
				i.MTU = swtele.Some(9216) // non-jumbo 1500 facing jumbo: reported
			case x.d == b:
				i.MTU = swtele.Some(1518) // frame length vs MTU: tolerated
			}
		}
	}
	for _, p := range []string{"XGE1/0/1", "XGE1/0/2"} {
		a.Neighbors = append(a.Neighbors, swtele.Neighbor{LocalPort: p, System: "b", Port: p, ChassisMAC: b.Stack.MAC})
		b.Neighbors = append(b.Neighbors, swtele.Neighbor{LocalPort: p, System: "a", Port: p, ChassisMAC: a.Stack.MAC})
	}
	cat, err := check.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := assess.NewEngine(cat, assess.Policy{}, assess.Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New("t", at, []*swtele.Device{a, b})
	g := topology.Build(l)
	got := map[assess.RuleID][]assess.Finding{}
	for _, d := range []*swtele.Device{a, b} {
		res, err := eng.Run(t.Context(), &check.Target{Ledger: l, Graph: g, Device: d}, d.Coverage)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range res.Findings {
			got[f.Rule] = append(got[f.Rule], f)
		}
	}
	if fs := got["link.allowed_vlans"]; len(fs) != 1 || fs[0].Subject.String() != "device:a/interface:BAGG1" {
		t.Errorf("allowed vlans %+v", fs)
	} else if fs[0].Detail != "对端 b BAGG9；仅本端允许 30-40" {
		t.Errorf("detail %q", fs[0].Detail)
	}
	if fs := got["link.mtu_mismatch"]; len(fs) != 1 {
		t.Errorf("mtu %+v", fs)
	}
}
