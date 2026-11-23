package nxos_test

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/store/snapshot"

	"github.com/gatework/swtele/vendors/nxos"
)

var digits = regexp.MustCompile(`\d+`)

// TestPrivateCorpus decodes every NX-OS device of a private snapshot
// corpus (SWTELE_CORPUS) and prints only aggregate counts and the shapes
// (digits masked) of unparsed lines.
func TestPrivateCorpus(t *testing.T) {
	root := os.Getenv("SWTELE_CORPUS")
	if root == "" {
		t.Skip("SWTELE_CORPUS not set")
	}
	dirs, err := filepath.Glob(filepath.Join(root, "*"))
	if err != nil {
		t.Fatal(err)
	}
	type stat struct{ total, complete, partial, failed int }
	stats := map[string]*stat{}
	shapes := map[string]map[string]int{}
	devices, ifaces, optics, arp, macs, nbrs := 0, 0, 0, 0, 0, 0
	loc := time.FixedZone("UTC+8", 8*3600)
	for _, dir := range dirs {
		addr, err := netip.ParseAddr(filepath.Base(dir))
		if err != nil {
			continue
		}
		c, err := snapshot.ReadDir(t.Context(), dir)
		if err != nil {
			continue
		}
		if _, nxos := c.Output("show port-channel summary"); !nxos {
			continue
		}
		devices++
		dev, err := nxos.Decode(t.Context(), device.Device{Mgmt: addr}, c, nxos.Options{
			Location: loc,
			OnOutput: func(cmd string, s evidence.Status, unparsed []string) {
				st := stats[cmd]
				if st == nil {
					st = &stat{}
					stats[cmd] = st
				}
				st.total++
				//nolint:exhaustive // every other status counts as failed
				switch s {
				case evidence.StatusComplete:
					st.complete++
				case evidence.StatusPartial:
					st.partial++
				default:
					st.failed++
				}
				for _, u := range unparsed {
					if shapes[cmd] == nil {
						shapes[cmd] = map[string]int{}
					}
					shapes[cmd][digits.ReplaceAllString(u, "N")]++
				}
			},
		})
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		ifaces += dev.Interfaces.Len()
		for _, i := range dev.Interfaces.All() {
			if i.Optics != nil && i.Optics.Present {
				optics++
			}
		}
		arp += len(dev.L3.ARP)
		macs += len(dev.L2.MACs)
		nbrs += len(dev.Neighbors)
	}
	t.Logf("devices=%d interfaces=%d optics=%d arp=%d mac=%d neighbors=%d", devices, ifaces, optics, arp, macs, nbrs)
	for _, cmd := range slices.Sorted(maps.Keys(stats)) {
		s := stats[cmd]
		t.Logf("%-45s total=%4d complete=%4d partial=%4d failed=%4d", cmd, s.total, s.complete, s.partial, s.failed)
		type kv struct {
			k string
			n int
		}
		var list []kv
		for k, n := range shapes[cmd] {
			list = append(list, kv{k, n})
		}
		slices.SortFunc(list, func(a, b kv) int { return cmp.Compare(b.n, a.n) })
		for _, e := range list[:min(len(list), 8)] {
			t.Logf("    %5d %s", e.n, truncate(e.k, 140))
		}
	}
	_ = fmt.Sprint()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
