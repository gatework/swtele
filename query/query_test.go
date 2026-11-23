package query_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/query"
	"github.com/gatework/swtele/topology"
)

func setup(t *testing.T) (query.Context, *swtele.Device) {
	t.Helper()
	at := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	d := swtele.New(device.Device{Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1"), Platform: "h3c"}, at)
	prev := swtele.New(d.Identity, at.Add(-time.Hour))
	add := func(dev *swtele.Device, name string, f func(*swtele.Interface)) {
		i := dev.Interfaces.Ensure(name)
		i.Kind, i.Admin, i.Oper = swtele.KindPhysical, swtele.StateUp, swtele.StateUp
		f(i)
	}
	th := swtele.Thresholds{HighWarn: swtele.Some(-1.0), LowWarn: swtele.Some(-10.0), LowAlarm: swtele.Some(-13.0)}
	optic := func(rx float64) *swtele.Transceiver {
		return &swtele.Transceiver{Present: true, DOM: swtele.DOMSupported, Inventory: swtele.XcvrInventory{Vendor: "FINISAR", Serial: "S1"},
			Lanes: []swtele.Lane{{Index: 1, RxPower: swtele.Reading{Value: swtele.Some(rx), Th: th}}}}
	}
	add(d, "GE1/0/1", func(i *swtele.Interface) {
		i.Counters.CRC, i.Counters.In.Packets = swtele.Some[uint64](50), swtele.Some[uint64](1000)
	})
	add(prev, "GE1/0/1", func(i *swtele.Interface) {
		i.Counters.CRC, i.Counters.In.Packets = swtele.Some[uint64](10), swtele.Some[uint64](500)
	})
	add(d, "GE1/0/2", func(i *swtele.Interface) { i.Oper, i.Flap.Never = swtele.StateDown, true })
	add(d, "GE1/0/3", func(i *swtele.Interface) { i.Optics = optic(-12) })                                               // warning, low margin
	add(d, "GE1/0/4", func(i *swtele.Interface) { i.Optics = optic(-40) })                                               // dark
	add(d, "GE1/0/5", func(i *swtele.Interface) { i.Optics = optic(-5) })                                                // normal
	add(d, "GE1/0/6", func(i *swtele.Interface) { i.Oper, i.Flap.Never, i.Optics = swtele.StateDown, true, optic(-40) }) // down: not graded
	l, p := ledger.New("b", at, []*swtele.Device{d}), ledger.New("a", at, []*swtele.Device{prev})
	return query.Context{Ledger: l, Graph: topology.Build(l), Prev: p}, d
}

func names[T any](rows []T, port func(T) string) []string {
	var out []string
	for _, r := range rows {
		out = append(out, port(r))
	}
	return out
}

func TestPorts(t *testing.T) {
	t.Parallel()
	c, d := setup(t)
	rows := c.Ports([]*swtele.Device{d})
	pn := func(r query.PortRow) string { return r.Port.Name }
	cases := []struct {
		name string
		pred query.Port
		want []string
	}{
		{"errors", query.Errors(), []string{"GE1/0/1"}},
		{"growing", query.Growing(), []string{"GE1/0/1"}},
		{"idle", query.Idle(30 * 24 * time.Hour), []string{"GE1/0/2", "GE1/0/6"}},
		{"down", query.Status("down"), []string{"GE1/0/2", "GE1/0/6"}},
		{"rate", query.RateAbove(0.01), []string{"GE1/0/1"}},
		{"and", query.All(query.Errors(), query.Status("down")), nil},
	}
	for _, c := range cases {
		got := names(query.Filter(rows, c.pred), pn)
		if len(got) != len(c.want) || len(got) > 0 && got[0] != c.want[0] {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	if g, ok := query.Growth(rows[0]); !ok || g != 40 || query.ErrorRate(rows[0].Port) != 0.05 {
		t.Errorf("growth %d %v rate %v", g, ok, query.ErrorRate(rows[0].Port))
	}
}

func TestOptics(t *testing.T) {
	t.Parallel()
	c, d := setup(t)
	rows := c.Optics([]*swtele.Device{d})
	pn := func(r query.OpticRow) string { return r.Port.Name }
	cases := []struct {
		name string
		pred query.Optic
		want []string
	}{
		{"abnormal", query.Abnormal(2, 3), []string{"GE1/0/3", "GE1/0/4"}},
		{"dark", query.Dark(), []string{"GE1/0/4"}},
		{"margin", query.MarginBelow(3), []string{"GE1/0/3"}},
		{"idle module", query.IdleModule(), []string{"GE1/0/6"}},
		{"non-original", query.NonOriginal(), []string{"GE1/0/3", "GE1/0/4", "GE1/0/5", "GE1/0/6"}},
	}
	for _, c := range cases {
		got := names(query.Filter(rows, c.pred), pn)
		if len(got) != len(c.want) || got[0] != c.want[0] {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	for _, r := range rows {
		if r.Port.Name == "GE1/0/6" && (query.Graded(r) || query.Worst(r) != swtele.LevelUnknown) {
			t.Error("a down port's module is graded")
		}
	}
}

func TestEndpoints(t *testing.T) {
	t.Parallel()
	c, d := setup(t)
	mac := func(s string) swtele.MAC {
		m, err := swtele.ParseMAC(s)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ip := netip.MustParseAddr
	now := d.Observed
	seen := []locate.Sighting{
		{IP: ip("192.0.2.10"), MAC: mac("aabb-cc00-0001"), VLAN: 10, Mgmt: "192.0.2.1", Port: "GE1/0/1", Confidence: locate.Exact},
		{IP: ip("192.0.2.10"), MAC: mac("aabb-cc00-0002"), VLAN: 10, Mgmt: "192.0.2.1", Port: "GE1/0/2", Confidence: locate.Exact},
		{IP: ip("198.51.100.5"), MAC: mac("0011-2200-0003"), VLAN: 20, Mgmt: "192.0.2.1", Port: "GE1/0/3", Confidence: locate.Shared},
	}
	hist := []locate.Record{
		{IP: "198.51.100.5", MAC: "00:11:22:00:00:03", First: now.Add(-time.Hour), Place: locate.Place{Since: now.Add(-time.Hour)},
			Moves: []locate.Place{{}, {}}},
	}
	rows := c.Endpoints(seen, hist, map[string]string{"00:11:22": "Example Corp"})
	count := func(p query.Endpoint) int { return len(query.Filter(rows, p)) }
	cases := []struct {
		name string
		pred query.Endpoint
		want int
	}{
		{"vlan", query.OnVLAN(10), 2},
		{"subnet", query.InSubnet(netip.MustParsePrefix("198.51.100.0/24")), 1},
		{"oui hex", query.OUIPrefix("aabb.cc"), 2},
		{"oui vendor", query.OUIPrefix("example"), 1},
		{"behind", query.BehindUnmanaged(), 1},
		{"new", query.NewSince(24*time.Hour, now), 1},
		{"moved", query.MovedSince(24*time.Hour, now), 1},
		{"moves", query.MovesAbove(1), 1},
		{"conflict", query.IPConflict(), 2},
	}
	for _, tc := range cases {
		if got := count(tc.pred); got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, got, tc.want)
		}
	}
	if rows[0].Port == nil || rows[2].Vendor != "Example Corp" {
		t.Errorf("join %+v", rows[0])
	}
}
