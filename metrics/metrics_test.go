package metrics_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/metrics"
)

func snap(batch string, at time.Time, crc uint64, rx, cpu float64) metrics.Snapshot {
	d := swtele.New(device.Device{Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1")}, at)
	i := d.Interfaces.Ensure("GE1/0/1")
	i.Kind, i.Oper = swtele.KindPhysical, swtele.StateUp
	i.Counters.CRC = swtele.Some(crc)
	i.Optics = &swtele.Transceiver{Present: true, DOM: swtele.DOMSupported,
		Lanes: []swtele.Lane{{Index: 1, RxPower: swtele.Reading{Value: swtele.Some(rx)}}, {Index: 2, RxPower: swtele.Reading{Value: swtele.Some(rx + 1)}}}}
	d.System.CPU = []swtele.CPULoad{{Now: swtele.Some(cpu)}}
	return metrics.From(batch, at, []*swtele.Device{d})
}

func TestTrend(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []metrics.Snapshot{
		snap("b1", t0, 100, -3, 10),
		snap("b2", t0.Add(2*time.Hour), 300, -4, 20),
		snap("b3", t0.Add(4*time.Hour), 500, -5, 30),
		snap("b4", t0.Add(6*time.Hour), 20, -6, 25), // counters cleared
	}
	crc := metrics.Trend(snaps, metrics.CRC, nil, nil)
	if len(crc) != 1 || crc[0].Growth() != 400 || crc[0].Growing() != 2 || !crc[0].Points[3].Reset || crc[0].Points[1].PerHour != 100 {
		t.Fatalf("crc %+v", crc)
	}
	if crc[0].Sustained() {
		t.Error("a reset counter is not sustained growth")
	}
	if s := metrics.Trend(snaps[:3], metrics.CRC, nil, nil); !s[0].Sustained() {
		t.Error("growth in every interval is sustained")
	}
	rx := metrics.Trend(snaps, metrics.Rx, nil, func(p string) bool { return p == "GE1/0/1" })
	if len(rx) != 1 || rx[0].Points[0].Value != -3 || !rx[0].Sustained() || rx[0].Change() != -3 {
		t.Errorf("rx (weakest lane, falling) %+v", rx)
	}
	cpu := metrics.Trend(snaps, metrics.CPU, map[string]bool{"192.0.2.1": true}, nil)
	if len(cpu) != 1 || cpu[0].Port != "" || cpu[0].Sustained() || cpu[0].Change() != 15 {
		t.Errorf("cpu %+v", cpu)
	}
	if none := metrics.Trend(snaps, metrics.CPU, map[string]bool{"198.51.100.1": true}, nil); len(none) != 0 {
		t.Errorf("filtered %+v", none)
	}
}
