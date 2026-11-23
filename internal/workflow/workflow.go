// Package workflow holds the use cases of swtele: import captures into a
// ledger batch, load batches, locate endpoints, assess risks. It reaches
// the outside world only through the ports defined here.
package workflow

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/lifecycle"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/check"
	"github.com/gatework/swtele/delta"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/metrics"
	"github.com/gatework/swtele/path"
	"github.com/gatework/swtele/topology"
)

// Source yields captures, such as a snapshot directory.
type Source interface {
	Hosts(ctx context.Context) ([]netip.Addr, error)
	Load(ctx context.Context, host netip.Addr) (capture.Capture, error)
	Name() string
}

// Decoder turns a capture into the device model, and a configuration into
// its intent.
type Decoder interface {
	Decode(ctx context.Context, id device.Device, c capture.Capture) (*swtele.Device, error)
	Overlay(ctx context.Context, dev *swtele.Device, text string, at time.Time) error
}

// Configs yields configuration backups by management address.
type Configs interface {
	Config(ctx context.Context, host netip.Addr) (text string, at time.Time, ok bool, err error)
}

// Ledgers stores batches.
type Ledgers interface {
	Save(ctx context.Context, at time.Time, source string, devs []*swtele.Device, failed []string) (ledger.Manifest, error)
	Load(ctx context.Context, batch string) (*ledger.Ledger, ledger.Manifest, error)
	Previous(batch string) (string, error)
	Batches() ([]string, error)
	Latest(ctx context.Context) (string, error)
	Manifest(ctx context.Context, batch string) (ledger.Manifest, error)
	Prune(ctx context.Context, keep int) (int, error)
	// Metrics reads a batch's snapshot, failing for batches written
	// before snapshots existed; SaveMetrics fills those in.
	Metrics(ctx context.Context, batch string) (metrics.Snapshot, error)
	SaveMetrics(ctx context.Context, m metrics.Snapshot) error
	// SaveDerived writes a batch that is parent with fresh devices
	// replaced (or added), refreshed for dims, and makes it the latest.
	SaveDerived(ctx context.Context, parent ledger.Manifest, at time.Time, fresh []*swtele.Device, dims []evidence.Dimension) (ledger.Manifest, error)
}

// Inventory names the devices of a source: identity, platform, site.
// Hosts it does not know keep their address as identity.
type Inventory interface {
	Lookup(host netip.Addr) (device.Device, bool)
}

// History keeps endpoint attachments across batches.
type History interface {
	Record(ctx context.Context, batch string, at time.Time, seen []locate.Sighting, keep time.Duration) ([]locate.Move, error)
	Find(ctx context.Context, ip, mac string) ([]locate.Record, error)
	All(ctx context.Context) ([]locate.Record, error)
}

// Collector fetches fresh captures from devices into a raw snapshot
// store, which then serves as an import Source.
type Collector interface {
	Collect(ctx context.Context, selectors []string) (CollectResult, error)
	Source() Source
}

// CollectResult summarizes a collection.
type CollectResult struct {
	Devices   int      `json:"devices"`
	Collected int      `json:"collected"`
	Failed    []string `json:"failed,omitempty"`
}

// ErrNoCollector reports online collection without its configuration.
var ErrNoCollector = errors.New("workflow: online collection is not configured")

// Collect fetches the selected devices and imports the raw store as a new
// batch, overlaying configurations when cfg is set.
func (a *App) Collect(ctx context.Context, selectors []string, cfg Configs) (CollectResult, ImportResult, error) {
	if a.Collector == nil {
		return CollectResult{}, ImportResult{}, ErrNoCollector
	}
	cr, err := a.Collector.Collect(ctx, selectors)
	if err != nil {
		return cr, ImportResult{}, fmt.Errorf("workflow: %w", err)
	}
	if cr.Collected == 0 {
		return cr, ImportResult{}, fmt.Errorf("%w: no device answered", ErrNoCaptures)
	}
	ir, err := a.Import(ctx, a.Collector.Source(), cfg)
	return cr, ir, err
}

// App wires the ports.
type App struct {
	Ledgers Ledgers
	History History
	// Keep is how long an endpoint unseen stays in the history.
	Keep time.Duration
	// Retain is how many batches to keep (0 keeps all).
	Retain    int
	Decoder   Decoder
	Inventory Inventory
	Collector Collector
	// Refresher collects some dimensions again, nil without online
	// collection; OpenSource reopens a batch's import source by name.
	Refresher  Refresher
	OpenSource func(name string) (Source, error)
	Now        func() time.Time
}

// ImportResult summarizes an import.
type ImportResult struct {
	Manifest ledger.Manifest
	Decoded  int
	// Configured counts devices whose configuration was overlaid.
	Configured int
	Failed     []string
	// Unsupported lists hosts of platforms without a decoder yet.
	Unsupported []string `json:"unsupported,omitempty"`
	// Endpoints is how many endpoints were placed on an access port, and
	// Moves those that changed port since the previous batch.
	Endpoints int           `json:"endpoints"`
	Moves     []locate.Move `json:"moves,omitempty"`
}

// Import decodes every capture of src into a new batch. When cfg is not
// nil, each device's configuration backup is overlaid as its intent.
func (a *App) Import(ctx context.Context, src Source, cfg Configs) (ImportResult, error) {
	hosts, err := src.Hosts(ctx)
	if err != nil {
		return ImportResult{}, fmt.Errorf("workflow: %w", err)
	}
	results := a.decodeAll(ctx, src, cfg, hosts)
	if err := ctx.Err(); err != nil {
		return ImportResult{}, fmt.Errorf("workflow: %w", err)
	}
	var out ImportResult
	devs := make([]*swtele.Device, 0, len(results))
	for _, r := range results {
		switch {
		case errors.Is(r.err, ErrUnsupported):
			out.Unsupported = append(out.Unsupported, r.host.String())
			continue
		case r.err != nil:
			out.Failed = append(out.Failed, r.host.String())
			continue
		}
		devs = append(devs, r.dev)
	}
	out.Decoded = len(devs)
	for _, d := range devs {
		if d.Config != nil {
			out.Configured++
		}
	}
	if len(devs) == 0 {
		return out, fmt.Errorf("%w: %s", ErrNoCaptures, src.Name())
	}
	m, err := a.Ledgers.Save(ctx, a.now(), src.Name(), devs, out.Failed)
	if err != nil {
		return out, fmt.Errorf("workflow: %w", err)
	}
	out.Manifest = m
	if _, err := a.Ledgers.Prune(ctx, a.Retain); err != nil {
		return out, fmt.Errorf("workflow: %w", err)
	}
	if a.History != nil {
		l := ledger.New(m.Batch, m.At, devs)
		seen := locate.New(l, topology.Build(l), locate.Options{}).Sightings()
		out.Endpoints = len(seen)
		if out.Moves, err = a.History.Record(ctx, m.Batch, m.At, seen, a.Keep); err != nil {
			return out, fmt.Errorf("workflow: %w", err)
		}
	}
	return out, nil
}

// Changes compares two batches ("" for the latest and the one before it).
func (a *App) Changes(ctx context.Context, from, to string) ([]delta.Change, string, string, error) {
	cur, err := a.Open(ctx, to, from == "")
	if err != nil {
		return nil, "", "", err
	}
	prev := cur.Prev
	if from != "" {
		if prev, _, err = a.Ledgers.Load(ctx, from); err != nil {
			return nil, "", "", fmt.Errorf("workflow: %w", err)
		}
	}
	if prev == nil {
		return nil, "", cur.Ledger.Batch, ErrNoPrevious
	}
	return delta.Compare(prev, cur.Ledger), prev.Batch, cur.Ledger.Batch, nil
}

// Snapshots returns the metrics snapshots of the last n batches up to
// and including batch ("" for the latest), oldest first. A batch without
// a snapshot is loaded once and its snapshot written back.
func (a *App) Snapshots(ctx context.Context, batch string, n int) ([]metrics.Snapshot, error) {
	list, err := a.Ledgers.Batches()
	if err != nil {
		return nil, fmt.Errorf("workflow: %w", err)
	}
	if batch == "" {
		if batch, err = a.Ledgers.Latest(ctx); err != nil {
			return nil, fmt.Errorf("workflow: %w", err)
		}
	}
	end := slices.Index(list, batch)
	if end < 0 {
		return nil, fmt.Errorf("workflow: unknown batch %s", batch)
	}
	list = list[max(0, end+1-n) : end+1]
	out := make([]metrics.Snapshot, 0, len(list))
	for _, b := range list {
		m, err := a.Ledgers.Metrics(ctx, b)
		if err != nil {
			l, mf, lerr := a.Ledgers.Load(ctx, b)
			if lerr != nil {
				return nil, fmt.Errorf("workflow: %w", lerr)
			}
			m = metrics.From(b, mf.At, l.Devices())
			if err := a.Ledgers.SaveMetrics(ctx, m); err != nil {
				return nil, fmt.Errorf("workflow: %w", err)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// ErrNoPrevious reports a comparison without an earlier batch.
var ErrNoPrevious = errors.New("workflow: no previous batch")

// View is a loaded batch with its derived topology, and the previous
// batch when there is one.
type View struct {
	Ledger   *ledger.Ledger
	Manifest ledger.Manifest
	Graph    *topology.Graph
	Prev     *ledger.Ledger
}

// ErrUnsupported is what a Decoder returns for a platform it cannot
// decode; Import lists such hosts apart from failures.
var ErrUnsupported = errors.New("workflow: unsupported platform")

// ErrNoCaptures reports a source without any decodable capture.
var ErrNoCaptures = errors.New("workflow: no decodable capture")

// ErrNoDevice reports a device query that matches nothing.
var ErrNoDevice = errors.New("workflow: no such device")

// Open loads batch ("" for the latest) with its topology. withPrev also
// loads the batch before it, for growth checks.
func (a *App) Open(ctx context.Context, batch string, withPrev bool) (*View, error) {
	l, m, err := a.Ledgers.Load(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("workflow: %w", err)
	}
	v := &View{Ledger: l, Manifest: m, Graph: topology.Build(l)}
	if withPrev {
		prev, err := a.Ledgers.Previous(m.Batch)
		if err != nil {
			return nil, fmt.Errorf("workflow: %w", err)
		}
		if prev != "" {
			if v.Prev, _, err = a.Ledgers.Load(ctx, prev); err != nil {
				return nil, fmt.Errorf("workflow: %w", err)
			}
		}
	}
	return v, nil
}

// Device returns the device matching query.
func (v *View) Device(query string) (*swtele.Device, error) {
	if d := v.Ledger.Device(query); d != nil {
		return d, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNoDevice, query)
}

// Locate answers endpoint queries.
func (v *View) Locate(query string, o locate.Options) locate.Location {
	return locate.New(v.Ledger, v.Graph, o).Locate(query)
}

// Sightings returns the endpoints located on access ports.
func (v *View) Sightings(o locate.Options) []locate.Sighting {
	return locate.New(v.Ledger, v.Graph, o).Sightings()
}

// Lifecycle judges the software of devs under p.
func (v *View) Lifecycle(p lifecycle.Policy, devs []*swtele.Device) map[*swtele.Device]lifecycle.Verdict {
	out := make(map[*swtele.Device]lifecycle.Verdict, len(devs))
	for _, d := range devs {
		id := d.Identity.Clone()
		id.Name = d.Name()
		id.Version = cmp.Or(d.System.Version, id.Version)
		id.Model = cmp.Or(d.System.Model, id.Model)
		out[d] = p.Evaluate(id, v.Ledger.At)
	}
	return out
}

// Trace returns the layer-2 path between two endpoints.
func (v *View) Trace(src, dst string, o locate.Options) path.Result {
	return path.New(v.Ledger, v.Graph, locate.New(v.Ledger, v.Graph, o)).Trace(src, dst)
}

// DeviceAssessment is the assessment of one device.
type DeviceAssessment struct {
	Device     *swtele.Device
	Assessment assess.Assessment
}

// AssessPrevious runs the risk catalog over the devices of the previous
// batch that match devs by address, for comparing findings.
func (v *View) AssessPrevious(ctx context.Context, policy assess.Policy, devs []*swtele.Device) ([]DeviceAssessment, error) {
	if v.Prev == nil {
		return nil, nil
	}
	want := map[netip.Addr]bool{}
	for _, d := range devs {
		want[d.Identity.Mgmt] = true
	}
	pv := &View{Ledger: v.Prev, Graph: topology.Build(v.Prev)}
	return pv.Assess(ctx, policy, func(d *swtele.Device) bool { return want[d.Identity.Mgmt] })
}

// Assess runs the risk catalog under policy over every device matching
// keep (nil keeps all).
func (v *View) Assess(ctx context.Context, policy assess.Policy, keep func(*swtele.Device) bool) ([]DeviceAssessment, error) {
	cat, err := check.Catalog()
	if err != nil {
		return nil, fmt.Errorf("workflow: %w", err)
	}
	eng, err := assess.NewEngine(cat, policy, assess.Options{})
	if err != nil {
		return nil, fmt.Errorf("workflow: %w", err)
	}
	var out []DeviceAssessment
	for _, d := range v.Ledger.Devices() {
		if keep != nil && !keep(d) {
			continue
		}
		t := &check.Target{Ledger: v.Ledger, Graph: v.Graph, Device: d}
		if v.Prev != nil {
			t.Prev = v.Prev.Device(d.Identity.Mgmt.String())
		}
		a, err := eng.Run(ctx, t, d.Coverage)
		if err != nil {
			return nil, fmt.Errorf("workflow: assess %s: %w", d.Name(), err)
		}
		out = append(out, DeviceAssessment{Device: d, Assessment: a})
	}
	slices.SortFunc(out, func(a, b DeviceAssessment) int {
		return cmp.Or(cmp.Compare(b.Assessment.Highest(), a.Assessment.Highest()), cmp.Compare(len(b.Assessment.Findings), len(a.Assessment.Findings)))
	})
	return out, nil
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

type decoded struct {
	dev  *swtele.Device
	host netip.Addr
	err  error
}

// decodeAll decodes the captures of hosts concurrently, overlaying their
// configurations when cfg is set.
func (a *App) decodeAll(ctx context.Context, src Source, cfg Configs, hosts []netip.Addr) []decoded {
	results := make([]decoded, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for n, h := range hosts {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			results[n] = a.decodeOne(ctx, src, cfg, h)
		})
	}
	wg.Wait()
	return results
}

func (a *App) decodeOne(ctx context.Context, src Source, cfg Configs, h netip.Addr) decoded {
	r := decoded{host: h}
	c, err := src.Load(ctx, h)
	if err != nil {
		r.err = err
		return r
	}
	id := device.Device{ID: h.String(), Mgmt: h}
	if a.Inventory != nil {
		if d, ok := a.Inventory.Lookup(h); ok {
			id = d
		}
	}
	if r.dev, r.err = a.Decoder.Decode(ctx, id, c); r.err != nil || cfg == nil {
		return r
	}
	text, at, ok, err := cfg.Config(ctx, h)
	if err == nil && ok {
		err = a.Decoder.Overlay(ctx, r.dev, text, at)
	}
	if err != nil && !errors.Is(err, ErrUnsupported) {
		r.dev.Issues = append(r.dev.Issues, evidence.Issue{Code: "config_unreadable"})
	}
	return r
}
