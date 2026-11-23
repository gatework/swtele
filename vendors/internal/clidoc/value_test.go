package clidoc_test

import (
	"slices"
	"testing"
	"time"

	"github.com/gatework/swtele/vendors/internal/clidoc"
)

func TestDuration(t *testing.T) {
	t.Parallel()
	day, week := 24*time.Hour, 7*24*time.Hour
	cases := map[string]time.Duration{
		"161 weeks 5 days 7 hours 26 minutes":        161*week + 5*day + 7*time.Hour + 26*time.Minute,
		"3 hours 2 minutes 1 seconds":                3*time.Hour + 2*time.Minute + time.Second,
		"426 days, 20 hours, 10 minutes, 25 seconds": 426*day + 20*time.Hour + 10*time.Minute + 25*time.Second,
		"13week(s) 1day(s)":                          13*week + day,
		"3y34w":                                      3*365*day + 34*week,
		"2d03h":                                      2*day + 3*time.Hour,
		"01:02:03":                                   time.Hour + 2*time.Minute + 3*time.Second,
		"1d02:03:04":                                 day + 2*time.Hour + 3*time.Minute + 4*time.Second,
		"0568h44m":                                   568*time.Hour + 44*time.Minute,
		"12w3d":                                      12*week + 3*day,
		"Kernel uptime is 11 day(s), 5 hour(s), 2 minute": 11*day + 5*time.Hour + 2*time.Minute,
	}
	for in, want := range cases {
		if got := clidoc.Duration(in); !got.OK || got.V != want {
			t.Errorf("Duration(%q) = %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{"", "--", "never", "N/A"} {
		if clidoc.Duration(in).OK {
			t.Errorf("Duration(%q) is present", in)
		}
	}
}

func TestSpeed(t *testing.T) {
	t.Parallel()
	cases := map[string]uint64{"1G(a)": 1e9, "2.5G(a)": 2.5e9, "100M": 1e8, "10Gbps": 1e10, "25Gb/s": 25e9, "1000": 1e9, "40G": 4e10}
	for in, want := range cases {
		if got := clidoc.Speed(in); !got.OK || got.V != want {
			t.Errorf("Speed(%q) = %v, want %d", in, got, want)
		}
	}
	if clidoc.Speed("auto").OK {
		t.Error("auto is not a speed")
	}
}

func TestTimestamp(t *testing.T) {
	t.Parallel()
	want := time.Date(2023, 10, 18, 2, 46, 0, 0, time.UTC)
	for _, in := range []string{"2023-10-18 10:46:00 beijing+08:00:00", "2023-10-18 10:46:00 BJ+8+08:00:00", "2023-10-18 10:46:00"} {
		got := clidoc.Timestamp(in, time.FixedZone("UTC+8", 8*3600))
		if !got.OK || !got.V.Equal(want) {
			t.Errorf("Timestamp(%q) = %v", in, got)
		}
	}
	if clidoc.Timestamp("-", time.UTC).OK {
		t.Error("- is not a time")
	}
}

func TestNulls(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"-", "--", "N/A", "NA", "Overflow", ""} {
		if clidoc.Uint(in).OK || clidoc.Float(in).OK {
			t.Errorf("%q is present", in)
		}
	}
	if v := clidoc.Float("62.8%"); !v.OK || v.V != 62.8 {
		t.Errorf("Float(62.8%%) = %v", v)
	}
	if v := clidoc.Uint("1,234"); !v.OK || v.V != 1234 {
		t.Errorf("Uint(1,234) = %v", v)
	}
}

func TestFields(t *testing.T) {
	t.Parallel()
	got := clidoc.Fields("GE1/0/1   UP   1G(a)  F(a)  A  10   to printer room", 7)
	want := []string{"GE1/0/1", "UP", "1G(a)", "F(a)", "A", "10", "to printer room"}
	if !slices.Equal(got, want) {
		t.Errorf("Fields = %q", got)
	}
}
