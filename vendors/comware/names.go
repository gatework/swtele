package comware

import (
	"regexp"
	"strings"

	"github.com/gatework/swtele"
)

// abbreviations maps the short interface names of Comware tables to the
// full names of display interface and configuration.
var abbreviations = []struct {
	short, long string
}{
	{"BAGG", "Bridge-Aggregation"}, {"RAGG", "Route-Aggregation"},
	{"M-GE", "M-GigabitEthernet"}, {"MGE", "M-GigabitEthernet"},
	{"XGE", "Ten-GigabitEthernet"}, {"FGE", "FortyGigE"}, {"HGE", "HundredGigE"}, {"WGE", "Twenty-FiveGigE"},
	{"SGE", "Smartrate-Ethernet"}, {"GE", "GigabitEthernet"},
	{"InLoop", "InLoopBack"}, {"Loop", "LoopBack"}, {"REG", "Register-Tunnel"},
	{"Vlan", "Vlan-interface"}, {"Tun", "Tunnel"},
}

var shortName = regexp.MustCompile(`^([A-Za-z-]+)(\d.*)$`)

// longName expands a table abbreviation ("XGE1/0/49") to the full name
// ("Ten-GigabitEthernet1/0/49"); full names are returned unchanged.
func longName(name string) string {
	name = swtele.CleanName(name)
	m := shortName.FindStringSubmatch(name)
	if m == nil {
		return name
	}
	for _, a := range abbreviations {
		if m[1] == a.short {
			return a.long + m[2]
		}
	}
	if strings.EqualFold(m[1], "vlan") {
		return "Vlan-interface" + m[2]
	}
	return name
}

// port returns the interface named by a table cell, creating it when
// display interface did not list it.
func port(st *state, name string) *swtele.Interface {
	i := st.dev.Interfaces.Ensure(longName(name))
	if i.Kind == swtele.KindUnknown {
		i.Kind = kindOf(i.Name)
	}
	return i
}
