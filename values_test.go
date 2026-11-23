package swtele_test

import (
	"encoding/json"
	"testing"

	"github.com/gatework/swtele"
)

func TestParseMAC(t *testing.T) {
	t.Parallel()
	want := "7c:7a:3c:7b:31:e2"
	for _, in := range []string{"7c7a-3c7b-31e2", "7c7a.3c7b.31e2", "7C:7A:3C:7B:31:E2", "7c-7a-3c-7b-31-e2"} {
		m, err := swtele.ParseMAC(in)
		if err != nil || m.String() != want {
			t.Errorf("ParseMAC(%q) = %v, %v", in, m, err)
		}
	}
	for _, in := range []string{"", "INCOMPLETE", "7c7a-3c7b", "zz7a-3c7b-31e2"} {
		if _, err := swtele.ParseMAC(in); err == nil {
			t.Errorf("ParseMAC(%q) accepted", in)
		}
	}
}

func TestOptJSON(t *testing.T) {
	t.Parallel()
	type doc struct {
		A swtele.Opt[uint64] `json:"a"`
		B swtele.Opt[uint64] `json:"b,omitzero"`
		C swtele.Opt[uint64] `json:"c"`
	}
	b, err := json.Marshal(doc{A: swtele.Some[uint64](0), C: swtele.Opt[uint64]{}})
	if err != nil || string(b) != `{"a":0,"c":null}` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
	var back doc
	if err := json.Unmarshal(b, &back); err != nil || !back.A.OK || back.A.V != 0 || back.C.OK {
		t.Errorf("unmarshal = %+v, %v", back, err)
	}
}

func TestInterfaceKey(t *testing.T) {
	t.Parallel()
	same := [][]string{
		{"GE1/0/1", "GigabitEthernet1/0/1", "Gi1/0/1"},
		{"XGE1/0/49", "Ten-GigabitEthernet1/0/49", "Te1/0/49"},
		{"BAGG100", "Bridge-Aggregation100"},
		{"Vlan8", "Vlan-interface8", "vlan8"},
		{"Loop0", "LoopBack0", "lo0", "loopback0"},
		{"MGE0/0/0", "M-GE0/0/0", "M-GigabitEthernet0/0/0"},
		{"SGE1/0/1", "Smartrate-Ethernet1/0/1"},
		{"Eth1/1", "Ethernet1/1"},
		{"Po101", "port-channel101"},
		{"XGE1/0/50(R)", "Ten-GigabitEthernet1/0/50"},
	}
	for _, group := range same {
		for _, n := range group[1:] {
			if swtele.InterfaceKey(n) != swtele.InterfaceKey(group[0]) {
				t.Errorf("InterfaceKey(%q) = %q, want %q", n, swtele.InterfaceKey(n), swtele.InterfaceKey(group[0]))
			}
		}
	}
}

func TestReadingLevel(t *testing.T) {
	t.Parallel()
	th := swtele.Thresholds{HighAlarm: swtele.Some(1.0), HighWarn: swtele.Some(-1.0), LowWarn: swtele.Some(-10.0), LowAlarm: swtele.Some(-13.0)}
	cases := []struct {
		v    float64
		want swtele.Level
	}{{-5, swtele.LevelNormal}, {-11, swtele.LevelWarn}, {-14, swtele.LevelAlarm}, {0, swtele.LevelWarn}, {2, swtele.LevelAlarm}}
	for _, c := range cases {
		r := swtele.Reading{Value: swtele.Some(c.v), Th: th}
		if got := r.Level(); got != c.want {
			t.Errorf("Level(%v) = %s, want %s", c.v, got, c.want)
		}
	}
	if m, ok := (swtele.Reading{Value: swtele.Some(-8.0), Th: th}).Margin(); !ok || m != 2 {
		t.Errorf("Margin = %v, %v", m, ok)
	}
	if !(swtele.Reading{Value: swtele.Some(-40.0)}).Dark() {
		t.Error("-40 dBm is dark")
	}
}

func TestLACPFlags(t *testing.T) {
	t.Parallel()
	if !swtele.LACPFlags("ACDEF").Healthy() || swtele.LACPFlags("ACG").Healthy() || swtele.LACPFlags("ACDEFG").Healthy() {
		t.Error("Healthy")
	}
}
