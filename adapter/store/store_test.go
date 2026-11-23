package store_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/adapter/store"
)

func TestRoundTripAndPrune(t *testing.T) {
	t.Parallel()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := swtele.New(device.Device{Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1")}, time.Unix(100, 0))
	d.Observe(swtele.DimInterfaces, evidence.StatusComplete)
	i := d.Interfaces.Ensure("GigabitEthernet1/0/1")
	i.Speed = swtele.Some[uint64](1e9)
	i.Optics = &swtele.Transceiver{Present: true, Lanes: []swtele.Lane{{Index: 1, RxPower: swtele.Reading{Value: swtele.Some(-3.5)}}}}
	for n := range 3 {
		if _, err := s.Save(t.Context(), time.Unix(int64(1000+n), 0), "test", []*swtele.Device{d}, nil); err != nil {
			t.Fatal(err)
		}
	}
	l, m, err := s.Load(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	got := l.Device("sw1")
	if got == nil || m.Devices[0] != "192.0.2.1" || got.Coverage.Status(swtele.DimInterfaces) != evidence.StatusComplete {
		t.Fatalf("loaded %+v %+v", got, m)
	}
	gi := got.Interfaces.Get("GE1/0/1")
	if gi.Speed.V != 1e9 || gi.Optics.Lanes[0].RxPower.Value.V != -3.5 || gi.Counters.CRC.OK {
		t.Errorf("interface %+v", gi)
	}
	if n, err := s.Prune(t.Context(), 1); err != nil || n != 2 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if all, _ := s.Batches(); len(all) != 1 || all[0] != m.Batch {
		t.Errorf("batches after prune %v", all)
	}
}
