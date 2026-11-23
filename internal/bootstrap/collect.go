package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gatework/net-connector/connector"
	"github.com/gatework/net-connector/transport"
	"github.com/gatework/net-connector/transport/ssh"
	ncvendors "github.com/gatework/net-connector/vendors"

	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/credential"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/ops"
	nsnap "github.com/gatework/netops/store/snapshot"

	"github.com/gatework/swtele/adapter/snapshot"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/vendors"
)

// ErrNoCredentials reports collection without device credentials.
var ErrNoCredentials = errors.New("bootstrap: no device credentials")

// ErrCollect reports online collection that cannot start.
var ErrCollect = errors.New("bootstrap: online collection")

// SSH tunes the transport of online collection.
type SSH struct {
	KnownHosts     string `yaml:"known_hosts"`
	HostKeyPolicy  string `yaml:"host_key_policy"` // strict (default), accept-new, replace
	Jump           string `yaml:"jump"`
	Port           int    `yaml:"port"`
	Legacy         bool   `yaml:"legacy"`
	ConnectRetries int    `yaml:"connect_retries"`
	LoginTimeout   string `yaml:"login_timeout"`
	CommandTimeout string `yaml:"command_timeout"`
}

// collector collects the profile commands of each device into the raw
// snapshot store with netops ops.Collect over net-connector sessions.
type collector struct {
	creds   credential.Provider
	inv     []device.Device
	raw     *nsnap.Store
	rawDir  string
	dialer  ops.Dialer
	workers int
	timeout time.Duration
	extra   bool
}

var _ workflow.Collector = (*collector)(nil)

// newCollector wires online collection of devices.
func newCollector(cfg Config, env map[string]string, devices []device.Device, data string) (*collector, error) {
	rawDir := filepath.Join(data, "raw")
	raw, err := nsnap.Open(rawDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCollect, err)
	}
	creds := credential.Env{Environ: env}
	sshDialer, err := ssh.New(ssh.Options{
		KnownHosts: cfg.SSH.KnownHosts, HostKeys: ssh.Policy(or(cfg.SSH.HostKeyPolicy, string(ssh.Strict))),
		Jump: cfg.SSH.Jump, Legacy: cfg.SSH.Legacy, Timeout: duration(cfg.SSH.LoginTimeout, 30*time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: ssh: %w", ErrCollect, err)
	}
	d, err := connector.NewDialer(connector.Options{
		Registry: ncvendors.Builtin(), Credentials: creds,
		Transport: transport.Retrying{Dialer: sshDialer, Retries: cfg.SSH.ConnectRetries},
		Port:      cfg.SSH.Port, Timeout: duration(cfg.SSH.CommandTimeout, 5*time.Minute),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCollect, err)
	}
	return &collector{creds: creds, inv: devices, raw: raw, rawDir: rawDir, dialer: d.Port(), workers: or(cfg.Workers, 16),
		timeout: duration(cfg.DeviceTimeout, 15*time.Minute), extra: cfg.ExtraCommands}, nil
}

// probes maps the per-command dimensions "c00", "c01"... to the profile
// commands of each device's platform: one swtele dimension is fed by
// several commands, so collection addresses commands directly.
type probes struct{ extra bool }

func dimension(n int) evidence.Dimension { return evidence.Dimension(fmt.Sprintf("c%02d", n)) }

func (p probes) Command(d device.Device, dim evidence.Dimension) (string, bool) {
	cmds := vendors.Profile(d.Platform, p.extra)
	for n, c := range cmds {
		if dimension(n) == dim {
			return c, true
		}
	}
	return "", false
}

func (c *collector) Collect(ctx context.Context, selectors []string) (workflow.CollectResult, error) {
	targets, err := c.targets(selectors)
	if err != nil {
		return workflow.CollectResult{}, err
	}
	// Refuse before dialing anything when a platform has no credentials:
	// every device would fail authentication, and be contacted for it.
	for _, d := range targets {
		if cr, err := c.creds.Lookup(ctx, d); err != nil || !cr.Valid() {
			return workflow.CollectResult{}, fmt.Errorf("%w: platform %s", ErrNoCredentials, d.Platform)
		}
	}
	most := 0
	for _, d := range targets {
		most = max(most, len(vendors.Profile(d.Platform, c.extra)))
	}
	dims := make([]evidence.Dimension, most)
	for n := range dims {
		dims[n] = dimension(n)
	}
	rep, err := ops.Collect(ctx, ops.CollectRequest{
		Devices: targets, Dimensions: dims, Probes: probes{extra: c.extra},
		Dialer: c.dialer, Snapshots: c.raw, Workers: c.workers, Timeout: c.timeout,
	})
	res := workflow.CollectResult{Devices: len(targets)}
	for _, r := range rep.Results {
		if r.State == batch.StateSucceeded {
			res.Collected++
		} else {
			res.Failed = append(res.Failed, r.Device.Mgmt.String())
		}
	}
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrCollect, err)
	}
	return res, nil
}

func (c *collector) Source() workflow.Source {
	d, _ := snapshot.Open(c.rawDir)
	return d
}

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

func duration(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// targets returns the inventory devices of a supported platform matching
// the selectors (all when none).
func (c *collector) targets(selectors []string) ([]device.Device, error) {
	inv, _ := device.New(c.inv)
	all := inv.All()
	if len(selectors) > 0 {
		sel, err := device.ParseSelector(selectors...)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCollect, err)
		}
		all = inv.Select(sel)
	}
	var out []device.Device
	for _, d := range all {
		if len(vendors.Profile(d.Platform, false)) > 0 {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no device of a supported platform in the inventory matches", ErrCollect)
	}
	return out, nil
}
