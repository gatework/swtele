package bootstrap

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	nboot "github.com/gatework/netops/bootstrap"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/credential"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/secret"
	nsnap "github.com/gatework/netops/store/snapshot"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/adapter/store"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/vendors"
)

// fakeDialer answers every command with a canned Comware output, or its
// own answer when it has one.
type fakeDialer struct {
	asked []string
	own   map[string]string
}

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
		body, ok := s.d.own[cmd]
		if !ok {
			body = answers[cmd]
		}
		c.Outputs = append(c.Outputs, capture.Output{Command: cmd, Raw: cmd + "\n" + body + "<sw1>", Prompt: "<sw1>", RecordedAt: time.Now()})
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

func TestWebhookRoutes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "swtele.yml")
	body := "data_dir: data\nwebhook:\n  url: https://hooks.example.net/swtele\n  secret_env: SWTELE_HOOK_KEY\n  min_severity: high\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := nboot.Env{Home: dir, Environ: map[string]string{}}
	if _, err := Load(t.Context(), env, cfg); !errors.Is(err, ErrWebhookSecret) {
		t.Fatalf("missing secret: %v", err)
	}
	env.Environ["SWTELE_HOOK_KEY"] = "k"
	r, err := Load(t.Context(), env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Routes) != 1 || r.Routes[0].Name != "webhook" || r.Routes[0].Filter.MinSeverity != assess.SeverityHigh {
		t.Errorf("routes %+v", r.Routes)
	}
}

// seedDir writes an imported snapshot directory of hosts, captured two
// days ago with the canned answers.
func seedDir(t *testing.T, at time.Time, hosts ...netip.Addr) string {
	t.Helper()
	dir := t.TempDir()
	for _, h := range hosts {
		c := capture.Capture{Host: h, Prompt: "<sw>"}
		for _, cmd := range []string{"display interface brief", "display cpu-usage"} {
			c.Outputs = append(c.Outputs, capture.Output{Command: cmd, Raw: cmd + "\n" + answers[cmd] + "<sw>", Prompt: "<sw>", RecordedAt: at})
		}
		if err := nsnap.WriteDir(t.Context(), filepath.Join(dir, h.String()), c); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRefresh(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	sw1 := device.Device{ID: "sw1", Name: "sw1", Mgmt: netip.MustParseAddr("192.0.2.1"), Platform: "h3c"}
	sw2 := device.Device{ID: "sw2", Name: "sw2", Mgmt: netip.MustParseAddr("192.0.2.2"), Platform: "h3c"}
	src := seedDir(t, now.Add(-48*time.Hour), sw1.Mgmt, sw2.Mgmt)

	data := t.TempDir()
	rawDir := filepath.Join(data, "raw")
	raw, err := nsnap.Open(rawDir)
	if err != nil {
		t.Fatal(err)
	}
	fd := &fakeDialer{own: map[string]string{"display cpu-usage": "Slot 1 CPU 0 CPU usage:\n     55% in last 5 seconds\n     50% in last 1 minute\n     45% in last 5 minutes\n"}}
	c := &collector{creds: credential.Static{Username: "u", Password: secret.New("p")}, inv: []device.Device{sw1, sw2}, raw: raw, rawDir: rawDir, dialer: fd, workers: 2, timeout: time.Minute}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	app := &workflow.App{Ledgers: st, Decoder: decoder{loc: time.UTC}, Inventory: inventoryIndex{sw1.Mgmt: sw1, sw2.Mgmt: sw2},
		Collector: c, Refresher: c, OpenSource: Source}
	seed, err := Source(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Import(t.Context(), seed, nil); err != nil {
		t.Fatal(err)
	}
	v, err := app.Open(t.Context(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	one := []*swtele.Device{v.Ledger.Device("sw1")}
	dims := []evidence.Dimension{swtele.DimCPU}

	res, nv, err := app.Refresh(t.Context(), v, workflow.RefreshRequest{Devices: one, Dims: dims, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if want := vendors.CommandsFor("h3c", dims, false); !slices.Equal(fd.asked, want) {
		t.Errorf("asked %v, want only %v", fd.asked, want)
	}
	if res.Batch == "" || nv.Manifest.Parent != v.Manifest.Batch || len(res.Refreshed) != 1 {
		t.Fatalf("refresh %+v manifest %+v", res, nv.Manifest)
	}
	d := nv.Ledger.Device("sw1")
	if d.System.CPU[0].Min5.V != 45 || d.Interfaces.Get("GE1/0/1") == nil {
		t.Errorf("refreshed device keeps other dimensions and renews cpu: cpu %+v", d.System.CPU)
	}
	if now.Sub(d.CollectedAt(swtele.DimCPU)) > time.Minute || now.Sub(d.CollectedAt(swtele.DimInterfaces)) < 47*time.Hour {
		t.Errorf("collected times %v", d.Collected)
	}
	old := filepath.Join(data, "ledger", v.Manifest.Batch, "devices", "192.0.2.2.json")
	fresh := filepath.Join(data, "ledger", nv.Manifest.Batch, "devices", "192.0.2.2.json")
	a, errA := os.Stat(old)
	b, errB := os.Stat(fresh)
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Errorf("untouched device is not a hard link of the parent's (%v %v)", errA, errB)
	}
	if m, err := st.Metrics(t.Context(), nv.Manifest.Batch); err != nil || m.Devices["192.0.2.1"].CPU.V != 45 || len(m.Devices) != 2 {
		t.Errorf("derived metrics %+v %v", m, err)
	}

	// Just collected: within --max-age, nothing is dialed again.
	fd.asked = nil
	again, same, err := app.Refresh(t.Context(), nv, workflow.RefreshRequest{Devices: []*swtele.Device{d}, Dims: dims, MaxAge: time.Hour})
	if err != nil || again.Batch != "" || same != nv || len(fd.asked) != 0 || len(again.Fresh) != 1 {
		t.Errorf("fresh refresh %+v asked %v err %v", again, fd.asked, err)
	}
}
