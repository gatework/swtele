// Package store keeps ledger batches as JSON files under the tool's data
// directory, through netops store:
//
//	ledger/<batch>/manifest.json
//	ledger/<batch>/devices/<mgmt-ip>.json
//	ledger/LATEST
//
// Writes are atomic; a batch becomes LATEST only after every device and
// the manifest are written.
package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	nstore "github.com/gatework/netops/store"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
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
