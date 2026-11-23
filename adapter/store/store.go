// Package store keeps ledger batches as JSON files under the tool's data
// directory, through netops store:
//
//	ledger/<batch>/manifest.json
//	ledger/<batch>/devices/<mgmt-ip>.json
//	ledger/<batch>/metrics.json    (small snapshot for trends)
//	ledger/LATEST
//
// Writes are atomic; a batch becomes LATEST only after every device and
// the manifest are written.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/evidence"
	nstore "github.com/gatework/netops/store"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/metrics"
)

// ErrNoBatch reports a store without batches, or an unknown batch.
var ErrNoBatch = errors.New("store: no ledger batch")

// deviceLimit bounds one device file; MAC tables of core switches are the
// largest part.
const deviceLimit = 256 << 20

// Store is the ledger area of the data directory.
type Store struct {
	root *nstore.Store
}

// Open opens (creating) the store at root.
func Open(root string) (*Store, error) {
	s, err := nstore.Open(root)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{root: s}, nil
}

// Root returns the store directory.
func (s *Store) Root() string { return s.root.Root() }

// Save writes a new batch of devices and makes it the latest.
func (s *Store) Save(ctx context.Context, at time.Time, source string, devs []*swtele.Device, failed []string) (ledger.Manifest, error) {
	lroot, err := s.root.Path("ledger")
	if err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	b, err := nstore.NewBatch(lroot, at)
	if err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	name := filepath.Base(b.Root())
	m := ledger.Manifest{Schema: swtele.Schema, Batch: name, At: at.UTC(), Source: source, Failed: failed}
	for _, d := range devs {
		file := d.Identity.Mgmt.String()
		if _, err := b.WriteJSON(ctx, "devices/"+file+".json", d); err != nil {
			return ledger.Manifest{}, fmt.Errorf("store: %w", err)
		}
		m.Devices = append(m.Devices, file)
	}
	if _, err := b.WriteJSON(ctx, "metrics.json", metrics.From(name, at, devs)); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	if _, err := b.WriteJSON(ctx, "manifest.json", m); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	if _, err := s.root.Write(ctx, "ledger/LATEST", []byte(name+"\n")); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	return m, nil
}

// Batches lists the batch names, oldest first.
func (s *Store) Batches() ([]string, error) {
	names, err := s.root.List("ledger")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := slices.DeleteFunc(names, func(n string) bool { return n == "LATEST" || strings.HasPrefix(n, ".") })
	return out, nil
}

// Latest returns the latest batch name.
func (s *Store) Latest(ctx context.Context) (string, error) {
	body, err := s.root.Read(ctx, "ledger/LATEST", 1<<10)
	if errors.Is(err, nstore.ErrNotFound) {
		return "", ErrNoBatch
	}
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

// Previous returns the batch before batch, or "" for the first.
func (s *Store) Previous(batch string) (string, error) {
	all, err := s.Batches()
	if err != nil {
		return "", err
	}
	i := slices.Index(all, batch)
	if i <= 0 {
		return "", nil
	}
	return all[i-1], nil
}

// Load reads a batch ("" for the latest) into a ledger.
func (s *Store) Load(ctx context.Context, batch string) (*ledger.Ledger, ledger.Manifest, error) {
	if batch == "" {
		var err error
		if batch, err = s.Latest(ctx); err != nil {
			return nil, ledger.Manifest{}, err
		}
	}
	var m ledger.Manifest
	if err := s.root.ReadJSON(ctx, "ledger/"+batch+"/manifest.json", 1<<20, &m); err != nil {
		if errors.Is(err, nstore.ErrNotFound) {
			return nil, ledger.Manifest{}, fmt.Errorf("%w: %s", ErrNoBatch, batch)
		}
		return nil, ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	devs := make([]*swtele.Device, 0, len(m.Devices))
	for _, f := range m.Devices {
		d := &swtele.Device{}
		if err := s.root.ReadJSON(ctx, "ledger/"+batch+"/devices/"+f+".json", deviceLimit, d); err != nil {
			return nil, ledger.Manifest{}, fmt.Errorf("store: %w", err)
		}
		devs = append(devs, d)
	}
	return ledger.New(m.Batch, m.At, devs), m, nil
}

// Prune removes the oldest batches beyond keep (keep <= 0 keeps all) and
// returns how many it removed. The latest batch is never removed.
func (s *Store) Prune(ctx context.Context, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	all, err := s.Batches()
	if err != nil {
		return 0, err
	}
	latest, err := s.Latest(ctx)
	if err != nil && !errors.Is(err, ErrNoBatch) {
		return 0, err
	}
	n := 0
	for _, b := range all[:max(len(all)-keep, 0)] {
		if b == latest {
			continue
		}
		if err := s.root.Remove("ledger/" + b); err != nil {
			return n, fmt.Errorf("store: %w", err)
		}
		n++
	}
	return n, nil
}

// Manifest reads the manifest of batch.
func (s *Store) Manifest(ctx context.Context, batch string) (ledger.Manifest, error) {
	var m ledger.Manifest
	if err := s.root.ReadJSON(ctx, "ledger/"+batch+"/manifest.json", 1<<20, &m); err != nil {
		if errors.Is(err, nstore.ErrNotFound) {
			return m, fmt.Errorf("%w: %s", ErrNoBatch, batch)
		}
		return m, fmt.Errorf("store: %w", err)
	}
	return m, nil
}

// ErrNoMetrics reports a batch written before metrics snapshots existed.
var ErrNoMetrics = errors.New("store: batch has no metrics snapshot")

// metricsLimit bounds one metrics snapshot.
const metricsLimit = 64 << 20

// Metrics reads the metrics snapshot of batch.
func (s *Store) Metrics(ctx context.Context, batch string) (metrics.Snapshot, error) {
	var m metrics.Snapshot
	if err := s.root.ReadJSON(ctx, "ledger/"+batch+"/metrics.json", metricsLimit, &m); err != nil {
		if errors.Is(err, nstore.ErrNotFound) {
			return m, fmt.Errorf("%w: %s", ErrNoMetrics, batch)
		}
		return m, fmt.Errorf("store: %w", err)
	}
	return m, nil
}

// SaveMetrics writes the metrics snapshot of an existing batch.
func (s *Store) SaveMetrics(ctx context.Context, m metrics.Snapshot) error {
	if _, err := s.root.WriteJSON(ctx, "ledger/"+m.Batch+"/metrics.json", m); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// SaveDerived writes a batch that is parent with fresh devices replaced
// or added, and makes it the latest. Devices left as they were are hard
// links to the parent's files (copies where links fail), so a refresh of
// a few devices costs their files only and pruning either batch leaves
// the other intact.
func (s *Store) SaveDerived(ctx context.Context, parent ledger.Manifest, at time.Time, fresh []*swtele.Device, dims []evidence.Dimension) (ledger.Manifest, error) {
	lroot, err := s.root.Path("ledger")
	if err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	b, err := nstore.NewBatch(lroot, at)
	if err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	name := filepath.Base(b.Root())
	m := ledger.Manifest{Schema: swtele.Schema, Batch: name, At: at.UTC(), Source: parent.Source, Failed: parent.Failed,
		Parent: parent.Batch, Refreshed: &ledger.Refreshed{Dims: dims}}
	renewed := map[string]bool{}
	for _, d := range fresh {
		file := d.Identity.Mgmt.String()
		if _, err := b.WriteJSON(ctx, "devices/"+file+".json", d); err != nil {
			return ledger.Manifest{}, fmt.Errorf("store: %w", err)
		}
		renewed[file] = true
		m.Refreshed.Hosts = append(m.Refreshed.Hosts, file)
		m.Failed = slices.DeleteFunc(slices.Clone(m.Failed), func(h string) bool { return h == file })
	}
	m.Devices = append(m.Devices, m.Refreshed.Hosts...)
	from := filepath.Join(lroot, parent.Batch, "devices")
	to := filepath.Join(b.Root(), "devices")
	for _, file := range parent.Devices {
		if renewed[file] {
			continue
		}
		if err := linkOrCopy(filepath.Join(from, file+".json"), filepath.Join(to, file+".json")); err != nil {
			return ledger.Manifest{}, fmt.Errorf("store: %w", err)
		}
		m.Devices = append(m.Devices, file)
	}
	slices.Sort(m.Refreshed.Hosts)
	if err := ctx.Err(); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	snap, err := s.derivedMetrics(ctx, parent.Batch, name, at, fresh)
	if err != nil {
		return ledger.Manifest{}, err
	}
	if _, err := b.WriteJSON(ctx, "metrics.json", snap); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	if _, err := b.WriteJSON(ctx, "manifest.json", m); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	if _, err := s.root.Write(ctx, "ledger/LATEST", []byte(name+"\n")); err != nil {
		return ledger.Manifest{}, fmt.Errorf("store: %w", err)
	}
	return m, nil
}

// derivedMetrics is the parent's snapshot with the fresh devices'
// entries replaced; a parent without one is loaded whole.
func (s *Store) derivedMetrics(ctx context.Context, parent, name string, at time.Time, fresh []*swtele.Device) (metrics.Snapshot, error) {
	base, err := s.Metrics(ctx, parent)
	if errors.Is(err, ErrNoMetrics) {
		l, _, lerr := s.Load(ctx, parent)
		if lerr != nil {
			return metrics.Snapshot{}, lerr
		}
		base, err = metrics.From(parent, l.At, l.Devices()), nil
	}
	if err != nil {
		return metrics.Snapshot{}, err
	}
	maps.Copy(base.Devices, metrics.From(name, at, fresh).Devices)
	base.Batch, base.At = name, at.UTC()
	return base, nil
}

func linkOrCopy(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return fmt.Errorf("create device directory: %w", err)
	}
	if err := os.Link(from, to); err == nil {
		return nil
	}
	in, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("open parent device: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create derived device: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy parent device: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close derived device: %w", err)
	}
	return nil
}
