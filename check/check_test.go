package check_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

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
