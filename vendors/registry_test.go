package vendors_test

import (
	"slices"
	"testing"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors"
)

func TestCommandsFor(t *testing.T) {
	t.Parallel()
	got := vendors.CommandsFor("h3c", []evidence.Dimension{swtele.DimOptics}, false)
	if len(got) != 1 || got[0] != "display transceiver diagnosis interface" {
		t.Errorf("optics commands %v", got)
	}
	if all := vendors.CommandsFor("h3c", nil, false); len(all) != len(vendors.Profile("h3c", false)) {
		t.Errorf("no dims means the whole profile")
	}
	nb := vendors.CommandsFor("cisco_nxos", []evidence.Dimension{swtele.DimNeighbors}, false)
	if len(nb) == 0 {
		t.Error("nxos neighbors commands")
	}
	for _, c := range nb {
		if !slices.Contains(vendors.Profile("cisco_nxos", false), c) {
			t.Errorf("%q is not in the profile", c)
		}
	}
	if vendors.CommandsFor("fortinet", nil, false) != nil {
		t.Error("unsupported platform")
	}
}
