package bootstrap

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/credential"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/secret"
	nsnap "github.com/gatework/netops/store/snapshot"

	"github.com/gatework/swtele/adapter/store"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/vendors"
)

// fakeDialer answers every command with a canned Comware output.
type fakeDialer struct{ asked []string }

type fakeSession struct{ d *fakeDialer }

var answers = map[string]string{
	"display interface brief": "Brief information on interfaces in bridge mode:\nInterface            Link Speed   Duplex Type PVID Description\nGE1/0/1              UP   1G(a)   F(a)   A    10   pc\n",
	"display cpu-usage":       "Slot 1 CPU 0 CPU usage:\n      5% in last 5 seconds\n      4% in last 1 minute\n      3% in last 5 minutes\n",
}

func (f *fakeDialer) Open(ctx context.Context, _ device.Device, fn func(context.Context, ops.Session) error) (error, error) {
	return fn(ctx, fakeSession{f}), nil
}

func (f *fakeDialer) CanConnect(context.Context, device.Device) bool { return true }

func (s fakeSession) Collect(_ context.Context, cmds []string) (capture.Capture, error) {
	c := capture.Capture{Prompt: "<sw1>"}
	for _, cmd := range cmds {
		s.d.asked = append(s.d.asked, cmd)
		c.Outputs = append(c.Outputs, capture.Output{Command: cmd, Raw: cmd + "\n" + answers[cmd] + "<sw1>", Prompt: "<sw1>", RecordedAt: time.Now()})
	}
	return c, nil
}
func (fakeSession) Write(context.Context, change.Command) error { return nil }
func (fakeSession) Save(context.Context) error                  { return nil }
func (fakeSession) CanCheckpoint() bool                         { return false }
func (fakeSession) Checkpoint(context.Context, string) error    { return nil }
func (fakeSession) Rollback(context.Context, string) error      { return nil }

func TestCollect(t *testing.T) {
	t.Parallel()
	data := t.TempDir()
	rawDir := filepath.Join(data, "raw")
	raw, err := nsnap.Open(rawDir)
	if err != nil {
		t.Fatal(err)
	}
	fd := &fakeDialer{}
	sw := device.Device{ID: "sw1", Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1"), Platform: "h3c"}
	fw := device.Device{ID: "fw1", Name: "fw1", Mgmt: netip.MustParseAddr("192.0.2.2"), Platform: "fortinet"}
	c := &collector{creds: credential.Static{Username: "u", Password: secret.New("p")}, inv: []device.Device{sw, fw}, raw: raw, rawDir: rawDir, dialer: fd, workers: 2, timeout: time.Minute}

	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	app := &workflow.App{Ledgers: st, Decoder: decoder{loc: time.UTC}, Inventory: inventoryIndex{sw.Mgmt: sw}, Collector: c}
	cr, ir, err := app.Collect(t.Context(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Devices != 1 || cr.Collected != 1 || ir.Decoded != 1 {
		t.Fatalf("collect %+v import %+v", cr, ir)
	}
	if want := len(vendors.Profile("h3c", false)); len(fd.asked) != want {
		t.Errorf("asked %d commands, want the %d of the profile", len(fd.asked), want)
	}
	v, err := app.Open(t.Context(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	d := v.Ledger.Device("sw1")
	if d == nil || d.Interfaces.Get("GE1/0/1") == nil || d.System.CPU[0].Min5.V != 3 || d.Identity.Platform != "h3c" {
		t.Fatalf("ledger device %+v", d)
	}
}

func TestCollectWithoutCredentials(t *testing.T) {
	t.Parallel()
	fd := &fakeDialer{}
	sw := device.Device{ID: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1"), Platform: "h3c"}
	c := &collector{creds: credential.Env{Environ: map[string]string{}}, inv: []device.Device{sw}, dialer: fd}
	if _, err := c.Collect(t.Context(), nil); !errors.Is(err, ErrNoCredentials) || len(fd.asked) != 0 {
		t.Fatalf("err %v, asked %d commands", err, len(fd.asked))
	}
}
