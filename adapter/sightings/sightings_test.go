package sightings_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/adapter/sightings"
	"github.com/gatework/swtele/locate"
)

func TestRecord(t *testing.T) {
	t.Parallel()
	s, err := sightings.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := swtele.ParseMAC("aaaa-0000-0001")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seen := func(port string) []locate.Sighting {
		return []locate.Sighting{{IP: netip.MustParseAddr("192.0.2.10"), MAC: mac, Device: "sw1", Mgmt: "192.0.2.1", Port: port}}
	}
	if m, err := s.Record(t.Context(), "b1", at, seen("GE1/0/1"), 0); err != nil || len(m) != 0 {
		t.Fatalf("first = %v, %v", m, err)
	}
	m, err := s.Record(t.Context(), "b2", at.Add(time.Hour), seen("GE1/0/2"), 0)
	if err != nil || len(m) != 1 || m[0].From.Port != "GE1/0/1" || m[0].To.Port != "GE1/0/2" {
		t.Fatalf("move = %v, %v", m, err)
	}
	recs, err := s.Find(t.Context(), "", mac.String())
	if err != nil || len(recs) != 1 || !recs[0].First.Equal(at) || len(recs[0].Moves) != 1 || recs[0].Place.Port != "GE1/0/2" {
		t.Fatalf("find = %+v, %v", recs, err)
	}
	// Unseen for longer than keep: dropped.
	if _, err := s.Record(t.Context(), "b3", at.Add(100*24*time.Hour), nil, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.Find(t.Context(), "192.0.2.10", ""); len(recs) != 0 {
		t.Errorf("stale record kept: %+v", recs)
	}
}
