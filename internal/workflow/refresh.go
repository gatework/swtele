package workflow

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/locate"
)

// Refresher collects some dimensions of some devices again, merging the
// fresh outputs into the raw snapshot store that Source serves. A host
// the raw store does not hold yet is first seeded from seed, the
// source the current batch was imported from, so that its other outputs
// survive the merge.
type Refresher interface {
	Refresh(ctx context.Context, hosts []netip.Addr, dims []evidence.Dimension, seed Source) (CollectResult, error)
	Source() Source
}

// RefreshRequest selects what to collect again.
type RefreshRequest struct {
	// Devices are devices of the view to refresh.
	Devices []*swtele.Device
	// Dims are the dimensions the analysis reads; empty means all.
	Dims []evidence.Dimension
	// MaxAge skips devices whose Dims were all collected within MaxAge;
	// zero refreshes every device.
	MaxAge time.Duration
	// Configs, when set, are overlaid on the refreshed devices.
	Configs Configs
}

// RefreshResult reports a refresh.
type RefreshResult struct {
	// Batch is the new batch, "" when every device was fresh enough.
	Batch     string   `json:"batch,omitempty"`
	Refreshed []string `json:"refreshed,omitempty"`
	Fresh     []string `json:"fresh,omitempty"`
	Failed    []string `json:"failed,omitempty"`
}

// ErrNoRefresher reports a refresh without online collection.
var ErrNoRefresher = errors.New("workflow: refresh needs online collection (inventory and credentials)")

// ErrNoSource reports a batch whose import source cannot be reopened to
// seed the raw store.
var ErrNoSource = errors.New("workflow: the batch source cannot be reopened")

// Stale returns the devices whose dims were collected more than maxAge
// before now (all of them when maxAge is zero).
func Stale(devs []*swtele.Device, dims []evidence.Dimension, maxAge time.Duration, now time.Time) []*swtele.Device {
	if maxAge <= 0 {
		return devs
	}
	var out []*swtele.Device
	for _, d := range devs {
		check := dims
		if len(check) == 0 {
			check = d.Coverage.Dimensions()
		}
		if slices.ContainsFunc(check, func(dim evidence.Dimension) bool { return now.Sub(d.CollectedAt(dim)) > maxAge }) {
			out = append(out, d)
		}
	}
	return out
}

// Refresh collects req.Dims of the stale req.Devices again and saves the
// view's batch with those devices replaced as a new batch derived from
// it. It returns the new view (v itself when nothing was stale).
func (a *App) Refresh(ctx context.Context, v *View, req RefreshRequest) (RefreshResult, *View, error) {
	var res RefreshResult
	stale := Stale(req.Devices, req.Dims, req.MaxAge, a.now())
	for _, d := range req.Devices {
		if !slices.Contains(stale, d) {
			res.Fresh = append(res.Fresh, d.Name())
		}
	}
	if len(stale) == 0 {
		return res, v, nil
	}
	if a.Refresher == nil {
		return res, v, ErrNoRefresher
	}
	var seed Source
	if a.OpenSource != nil && v.Manifest.Source != "" {
		seed, _ = a.OpenSource(v.Manifest.Source) // a missing source only matters for unseeded hosts
	}
	hosts := make([]netip.Addr, len(stale))
	for n, d := range stale {
		hosts[n] = d.Identity.Mgmt
	}
	cr, err := a.Refresher.Refresh(ctx, hosts, req.Dims, seed)
	if err != nil {
		return res, v, fmt.Errorf("workflow: %w", err)
	}
	failed := map[string]bool{}
	for _, h := range cr.Failed {
		failed[h] = true
		res.Failed = append(res.Failed, h)
	}
	src := a.Refresher.Source()
	fresh := map[netip.Addr]*swtele.Device{}
	for _, h := range hosts {
		if failed[h.String()] {
			continue
		}
		r := a.decodeOne(ctx, src, req.Configs, h)
		if r.err != nil {
			res.Failed = append(res.Failed, h.String())
			continue
		}
		fresh[h] = r.dev
		res.Refreshed = append(res.Refreshed, r.dev.Name())
	}
	if len(fresh) == 0 {
		return res, v, fmt.Errorf("%w: no device answered", ErrNoCaptures)
	}
	m, err := a.Ledgers.SaveDerived(ctx, v.Manifest, a.now(), slices.Collect(maps.Values(fresh)), req.Dims)
	if err != nil {
		return res, v, fmt.Errorf("workflow: %w", err)
	}
	res.Batch = m.Batch
	if _, err := a.Ledgers.Prune(ctx, a.Retain); err != nil {
		return res, v, fmt.Errorf("workflow: %w", err)
	}
	nv, err := a.Open(ctx, m.Batch, v.Prev != nil)
	if err != nil {
		return res, v, err
	}
	if a.History != nil {
		seen := locate.New(nv.Ledger, nv.Graph, locate.Options{}).Sightings()
		if _, err := a.History.Record(ctx, m.Batch, m.At, seen, a.Keep); err != nil {
			return res, nv, fmt.Errorf("workflow: %w", err)
		}
	}
	return res, nv, nil
}
