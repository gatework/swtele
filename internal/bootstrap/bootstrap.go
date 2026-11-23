// Package bootstrap reads the configuration and wires the adapters into
// the workflow ports. It is the only package that knows concrete
// adapters.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/gatework/netops/assess"
	nboot "github.com/gatework/netops/bootstrap"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/event"
	"github.com/gatework/netops/inventory"
	"github.com/gatework/netops/lifecycle"
	"github.com/gatework/netops/notify"
	"github.com/gatework/netops/secret"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/adapter/backup"
	"github.com/gatework/swtele/adapter/oui"
	"github.com/gatework/swtele/adapter/sightings"
	"github.com/gatework/swtele/adapter/snapshot"
	"github.com/gatework/swtele/adapter/store"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/vendors"
)

// ErrNoDataDir reports a run without home directory or data_dir.
var ErrNoDataDir = errors.New("bootstrap: no data directory: set HOME or data_dir")

// App is the tool name for configuration and data paths.
const App = "swtele"

// Config is ~/.gatework/swtele.yml. Every field is optional.
type Config struct {
	// DataDir overrides ~/.local/share/gatework/swtele.
	DataDir string `yaml:"data_dir"`
	// Timezone is the zone of device clocks that print no offset, as a
	// fixed offset in hours (default 8).
	Timezone *int `yaml:"timezone"`
	// Inventory is a netops inventory file naming devices by address.
	Inventory string `yaml:"inventory"`
	// TrunkLimit is how many MACs a trunk port without neighbor may learn
	// before locate treats it as an uplink.
	TrunkLimit int `yaml:"trunk_limit"`
	// Policy is a netops assess policy file that enables, disables and
	// tunes risk rules.
	Policy string `yaml:"policy"`
	// HistoryDays is how long an endpoint unseen stays in the history
	// (default 90).
	HistoryDays int `yaml:"history_days"`
	// RetentionBatches is how many ledger batches to keep (default 30).
	RetentionBatches *int `yaml:"retention_batches"`
	// Configs is a directory of configuration backups overlaid on every
	// import and collection.
	Configs string `yaml:"configs"`
	// Online collection: SSH settings, concurrency, per-device timeout,
	// and whether to collect the decoded but not yet lab-verified extra
	// commands. Credentials come from NC_DEVICE_USERNAME/PASSWORD (or the
	// platform-specific NC_<PLATFORM>_* variables) in ~/.gatework/.env.
	SSH           SSH    `yaml:"ssh"`
	Workers       int    `yaml:"workers"`
	DeviceTimeout string `yaml:"device_timeout"`
	ExtraCommands bool   `yaml:"extra_commands"`
	// Lifecycle is a netops lifecycle policy file: target and minimum
	// releases, blocked releases, end-of-sale and end-of-support dates.
	Lifecycle string `yaml:"lifecycle"`
	// OUIFile is a local copy of the IEEE oui.txt registry, for endpoint
	// vendor names.
	OUIFile string `yaml:"oui_file"`
	// Webhook receives watch events at or above a severity.
	Webhook *Webhook `yaml:"webhook"`
	// Watch: the schedule (cron or @every) and the events file.
	Schedule   string `yaml:"schedule"`
	EventsFile string `yaml:"events_file"`
}

// Webhook posts watch events as signed JSON.
type Webhook struct {
	URL string `yaml:"url"`
	// SecretEnv names the variable (in ~/.gatework/.env or the process)
	// holding the HMAC signing key; empty sends unsigned bodies.
	SecretEnv string `yaml:"secret_env"`
	// MinSeverity is the lowest severity posted (default medium).
	MinSeverity string `yaml:"min_severity"`
}

// Resources are the wired dependencies of one run.
type Resources struct {
	Config Config
	Path   string // the configuration file, "" when none
	App    *workflow.App
	Policy assess.Policy
	Data   string
	// ConfigsDir is the configured backup directory, "" when none.
	ConfigsDir string
	// EventsFile receives watch events, "" when none.
	EventsFile string
	// Location is the operators' zone for displaying times.
	Location *time.Location
	// OUI maps "aa:bb:cc" to the organization, empty without oui_file.
	OUI map[string]string
	// Lifecycle is the software lifecycle policy, nil without one.
	Lifecycle *lifecycle.Policy
	// Routes deliver watch events: the events file and the webhook.
	Routes []event.Route
}

// Load reads the configuration and wires the workflow.
func Load(ctx context.Context, env nboot.Env, explicit string) (*Resources, error) {
	env.App = App
	path := explicit
	if path == "" {
		path = env.Discover()
	}
	var cfg Config
	if path != "" {
		if _, err := nboot.ReadYAML(ctx, path, explicit == "", &cfg); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}
	base := filepath.Dir(path)
	resolve := func(p string) string {
		if p == "" {
			return ""
		}
		return nboot.ResolvePath(p, base, env.Home)
	}
	data := env.DataDir()
	if cfg.DataDir != "" {
		data = resolve(cfg.DataDir)
	}
	if data == "" {
		// Without a home directory the data area would be the working
		// directory; refuse rather than scatter batches there.
		return nil, ErrNoDataDir
	}
	hours := 8
	if cfg.Timezone != nil {
		hours = *cfg.Timezone
	}
	r := &Resources{Config: cfg, Path: path, Data: data, ConfigsDir: resolve(cfg.Configs), EventsFile: resolve(cfg.EventsFile),
		Location: time.FixedZone(fmt.Sprintf("UTC%+d", hours), hours*3600)}
	app, err := newApp(cfg, data)
	if err != nil {
		return nil, err
	}
	r.App = app
	if cfg.Inventory != "" {
		if err := wireInventory(ctx, r, resolve(cfg.Inventory), path, env.Environ); err != nil {
			return nil, err
		}
	}
	if cfg.Policy != "" {
		if r.Policy, err = loadPolicy(ctx, resolve(cfg.Policy)); err != nil {
			return nil, err
		}
	}
	if cfg.Lifecycle != "" {
		if r.Lifecycle, err = loadLifecycle(ctx, resolve(cfg.Lifecycle)); err != nil {
			return nil, err
		}
	}
	if r.Routes, err = routes(ctx, cfg, r.EventsFile, path, env.Environ); err != nil {
		return nil, err
	}
	if cfg.OUIFile != "" {
		if r.OUI, err = oui.ReadFile(resolve(cfg.OUIFile)); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}
	return r, nil
}

// newApp wires the stores and the decoder.
func newApp(cfg Config, data string) (*workflow.App, error) {
	st, err := store.Open(data)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	hist, err := sightings.Open(data)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	hours := 8
	if cfg.Timezone != nil {
		hours = *cfg.Timezone
	}
	keep := 90
	if cfg.HistoryDays > 0 {
		keep = cfg.HistoryDays
	}
	app := &workflow.App{
		Ledgers: st, History: hist, Keep: time.Duration(keep) * 24 * time.Hour, Retain: 30,
		Decoder:    decoder{loc: time.FixedZone(fmt.Sprintf("UTC%+d", hours), hours*3600)},
		OpenSource: Source,
	}
	if cfg.RetentionBatches != nil {
		app.Retain = *cfg.RetentionBatches
	}
	return app, nil
}

// wireInventory names imported devices and enables online collection.
func wireInventory(ctx context.Context, r *Resources, inventoryPath, configPath string, environ map[string]string) error {
	devs, err := loadInventory(ctx, inventoryPath)
	if err != nil {
		return err
	}
	idx := inventoryIndex{}
	for _, d := range devs {
		idx[d.Mgmt] = d
	}
	r.App.Inventory = idx
	if len(devs) == 0 {
		return nil
	}
	env, err := nboot.LoadEnv(ctx, "", configPath, environ)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	c, err := newCollector(r.Config, env, devs, r.Data)
	if err != nil {
		return err
	}
	r.App.Collector, r.App.Refresher = c, c
	return nil
}

func loadPolicy(ctx context.Context, path string) (assess.Policy, error) {
	body, _, err := nboot.ReadFile(ctx, path, false)
	if err != nil {
		return assess.Policy{}, fmt.Errorf("bootstrap: policy: %w", err)
	}
	p, err := assess.DecodePolicy(body)
	if err != nil {
		return assess.Policy{}, fmt.Errorf("bootstrap: policy: %w", err)
	}
	return p, nil
}

// ErrWebhookSecret reports a webhook whose secret variable is unset.
var ErrWebhookSecret = errors.New("bootstrap: webhook secret variable is not set")

// routes wires the event sinks; nothing is sent until watch publishes.
func routes(ctx context.Context, cfg Config, eventsFile, configPath string, environ map[string]string) ([]event.Route, error) {
	var out []event.Route
	if eventsFile != "" {
		f, err := notify.NewFile(eventsFile)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: events: %w", err)
		}
		out = append(out, event.Route{Name: "file", Sink: f})
	}
	w := cfg.Webhook
	if w == nil || w.URL == "" {
		return out, nil
	}
	floor := assess.SeverityMedium
	if w.MinSeverity != "" {
		if err := floor.UnmarshalText([]byte(w.MinSeverity)); err != nil {
			return nil, fmt.Errorf("bootstrap: webhook min_severity: %w", err)
		}
	}
	o := notify.WebhookOptions{URL: w.URL}
	if w.SecretEnv != "" {
		env, err := nboot.LoadEnv(ctx, "", configPath, environ)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
		if env[w.SecretEnv] == "" {
			return nil, fmt.Errorf("%w: %s", ErrWebhookSecret, w.SecretEnv)
		}
		o.Secret = secret.New(env[w.SecretEnv])
	}
	hook, err := notify.NewWebhook(o)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: webhook: %w", err)
	}
	return append(out, event.Route{Name: "webhook", Filter: event.Filter{MinSeverity: floor}, Sink: hook}), nil
}

func loadLifecycle(ctx context.Context, path string) (*lifecycle.Policy, error) {
	body, _, err := nboot.ReadFile(ctx, path, false)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: lifecycle: %w", err)
	}
	p, err := lifecycle.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: lifecycle: %w", err)
	}
	return &p, nil
}

// Source opens a snapshot directory.
func Source(dir string) (workflow.Source, error) {
	d, err := snapshot.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return d, nil
}

type decoder struct{ loc *time.Location }

func (d decoder) Decode(ctx context.Context, id device.Device, c capture.Capture) (*swtele.Device, error) {
	dev, err := vendors.Decode(ctx, id, c, vendors.Options{Location: d.loc})
	if errors.Is(err, vendors.ErrUnsupported) {
		return nil, fmt.Errorf("%w: %w", workflow.ErrUnsupported, err)
	}
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return dev, nil
}

func (d decoder) Overlay(ctx context.Context, dev *swtele.Device, text string, at time.Time) error {
	err := vendors.Overlay(ctx, dev, text, at)
	if errors.Is(err, vendors.ErrUnsupported) {
		return fmt.Errorf("%w: %w", workflow.ErrUnsupported, err)
	}
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	return nil
}

// Configs opens a directory of configuration backups.
func Configs(dir string) (workflow.Configs, error) {
	b, err := backup.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return b, nil
}

type inventoryIndex map[netip.Addr]device.Device

func (i inventoryIndex) Lookup(host netip.Addr) (device.Device, bool) {
	d, ok := i[host]
	return d, ok
}

func loadInventory(ctx context.Context, path string) ([]device.Device, error) {
	body, _, err := nboot.ReadFile(ctx, path, false)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: inventory: %w", err)
	}
	devs, err := inventory.DecodeFile(body)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: inventory: %w", err)
	}
	return devs, nil
}
