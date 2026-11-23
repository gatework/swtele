// Package corpus_test runs the whole pipeline over a private snapshot
// corpus (SWTELE_CORPUS) and prints only aggregates.
package corpus_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/store/snapshot"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/topology"
	"github.com/gatework/swtele/vendors"
)

func TestPrivateCorpus(t *testing.T) {
	root := os.Getenv("SWTELE_CORPUS")
	if root == "" {
		t.Skip("SWTELE_CORPUS not set")
	}
	devs := load(t)
	l := ledger.New("corpus", time.Now(), devs)
	g := topology.Build(l)
	states := map[topology.State]int{}
	for _, k := range g.Links {
		states[k.State]++
	}
	t.Logf("devices=%d links=%v", l.Len(), states)
	x := locate.New(l, g, locate.Options{})
	conf := map[locate.Confidence]int{}
	n := 0
	for _, d := range l.Devices() {
		for _, e := range d.L3.ARP {
			if n >= 3000 {
				break
			}
			n++
			r := x.Locate(e.IP.String())
			conf[r.Confidence]++
			if os.Getenv("SWTELE_DEBUG") != "" && conf[r.Confidence]%500 == 1 {
				b, _ := json.Marshal(r)
				t.Logf("%s", b)
			}
		}
	}
	t.Logf("located %d ARP IPs: %v", n, conf)
}

func load(t *testing.T) []*swtele.Device {
	t.Helper()
	root := os.Getenv("SWTELE_CORPUS")
	dirs, _ := filepath.Glob(filepath.Join(root, "*"))
	var devs []*swtele.Device
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
		d, err := vendors.Decode(t.Context(), device.Device{Mgmt: addr}, c, vendors.Options{Location: loc})
		if err != nil {
			continue
		}
		devs = append(devs, d)
	}
	return devs
}
