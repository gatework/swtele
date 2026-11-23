package capacity_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/capacity"
)

func TestDevice(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	d := swtele.New(device.Device{Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1")}, now)
	add := func(name string, oper swtele.State, f func(*swtele.Interface)) {
		i := d.Interfaces.Ensure(name)
		i.Kind, i.Admin, i.Oper = swtele.KindPhysical, swtele.StateUp, oper
		f(i)
	}
	add("GE1/0/1", swtele.StateDown, func(i *swtele.Interface) { i.Flap.Never = true })
	add("GE1/0/2", swtele.StateDown, func(i *swtele.Interface) { i.Flap.Since = swtele.Some(90 * 24 * time.Hour) })
	add("GE1/0/3", swtele.StateDown, func(i *swtele.Interface) { i.Flap.Since = swtele.Some(time.Hour) })
	add("GE1/0/4", swtele.StateUp, func(i *swtele.Interface) {
		i.Speed, i.Rates.InBps = swtele.Some[uint64](1e9), swtele.Some(9e8)
	})
	add("GE1/0/5", swtele.StateDown, func(i *swtele.Interface) { i.Admin = swtele.StateDown })
	s := capacity.Device(d, capacity.Options{})
	if s.Physical != 5 || s.Up != 1 || s.Down != 3 || s.Disabled != 1 {
		t.Errorf("counts %+v", s)
	}
	if len(s.Idle) != 2 || !s.Idle[0].Never || s.Idle[1].Port != "GE1/0/2" {
		t.Errorf("idle %+v", s.Idle)
	}
	if len(s.Hot) != 1 || s.Hot[0].Percent != 90 {
		t.Errorf("hot %+v", s.Hot)
	}
}
