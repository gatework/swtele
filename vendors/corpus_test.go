package vendors_test

import (
	"cmp"
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

	"github.com/gatework/swtele/vendors"
)

var digits = regexp.MustCompile(`\d+`)

// TestPrivateCorpus decodes every device of SWTELE_CORPUS whose platform
// is given by SWTELE_VENDOR (default: every phase-two vendor) and prints
// per-command status counts and the masked shapes of unparsed lines.
func TestPrivateCorpus(t *testing.T) {
	root := os.Getenv("SWTELE_CORPUS")
	if root == "" {
		t.Skip("SWTELE_CORPUS not set")
	}
	want := map[string]bool{vendors.Hillstone: true}
	if v := os.Getenv("SWTELE_VENDOR"); v != "" {
		want = map[string]bool{v: true}
	}
	dirs, _ := filepath.Glob(filepath.Join(root, "*"))
	type stat struct{ total, complete, partial, failed int }
	stats := map[string]*stat{}
	shapes := map[string]map[string]int{}
	n := 0
	for _, dir := range dirs {
		addr, err := netip.ParseAddr(filepath.Base(dir))
		if err != nil {
			continue
		}
		c, err := snapshot.ReadDir(t.Context(), dir)
		if err != nil {
			continue
		}
		if name, ok := vendors.Resolve("", c); !ok || !want[name] {
			continue
		}
		n++
		_, err = vendors.Decode(t.Context(), device.Device{Mgmt: addr}, c, vendors.Options{Location: time.UTC,
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
			}})
		if err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	t.Logf("devices=%d", n)
	for _, cmd := range slices.Sorted(maps.Keys(stats)) {
		s := stats[cmd]
		t.Logf("%-45s total=%4d complete=%4d partial=%4d failed=%4d", cmd, s.total, s.complete, s.partial, s.failed)
		keys := slices.SortedFunc(maps.Keys(shapes[cmd]), func(a, b string) int { return cmp.Compare(shapes[cmd][b], shapes[cmd][a]) })
		for _, k := range keys[:min(len(keys), 6)] {
			t.Logf("    %4d %.140s", shapes[cmd][k], k)
		}
	}
}
