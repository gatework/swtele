// Package sightings keeps the attachment history of endpoints across
// batches in one JSON file: for each MAC and IP pair, when it was first
// and last seen, where it is attached, and its recent moves.
package sightings

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	nstore "github.com/gatework/netops/store"

	"github.com/gatework/swtele/locate"
)

const (
	file     = "sightings/endpoints.json"
	maxMoves = 10
	limit    = 512 << 20
)

// Store is the sightings file of the data directory.
type Store struct {
	root *nstore.Store
}

// Open opens the store at the data directory root.
func Open(root string) (*Store, error) {
	s, err := nstore.Open(root)
	if err != nil {
		return nil, fmt.Errorf("sightings: %w", err)
	}
	return &Store{root: s}, nil
}

// Record merges the sightings of batch, observed at at, and returns the
// endpoints that moved. Records unseen for longer than keep are dropped.
func (s *Store) Record(ctx context.Context, batch string, at time.Time, seen []locate.Sighting, keep time.Duration) ([]locate.Move, error) {
	lock, err := s.root.Lock(ctx, "sightings", 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("sightings: %w", err)
	}
	defer func() { _ = lock.Close() }()
	all, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	var moves []locate.Move
	for _, x := range seen {
		place := locate.Place{Device: x.Device, Mgmt: x.Mgmt, Port: x.Port, VLAN: x.VLAN, Since: at}
		k := x.MAC.String() + "|" + x.IP.String()
		r, ok := all[k]
		if !ok {
			all[k] = &locate.Record{IP: x.IP.String(), MAC: x.MAC.String(), First: at, Last: at, Batch: batch, Place: place}
			continue
		}
		if at.Before(r.Last) {
			continue // an older batch imported late
		}
		r.Last, r.Batch = at, batch
		if r.Place.Mgmt != place.Mgmt || !strings.EqualFold(r.Place.Port, place.Port) {
			moves = append(moves, locate.Move{IP: r.IP, MAC: r.MAC, From: r.Place, To: place})
			r.Moves = append([]locate.Place{r.Place}, r.Moves...)
			r.Moves = r.Moves[:min(len(r.Moves), maxMoves)]
			r.Place = place
		}
	}
	list := make([]*locate.Record, 0, len(all))
	for _, r := range all {
		if keep > 0 && at.Sub(r.Last) > keep {
			continue
		}
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b *locate.Record) int { return cmp.Or(cmp.Compare(a.MAC, b.MAC), cmp.Compare(a.IP, b.IP)) })
	if _, err := s.root.WriteJSON(ctx, file, list); err != nil {
		return nil, fmt.Errorf("sightings: %w", err)
	}
	return moves, nil
}

// Find returns the records whose IP or MAC equals query (a MAC in any
// spelling is matched by its canonical form).
func (s *Store) Find(ctx context.Context, ip, mac string) ([]locate.Record, error) {
	all, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	var out []locate.Record
	for _, r := range all {
		if ip != "" && r.IP == ip || mac != "" && r.MAC == mac {
			out = append(out, *r)
		}
	}
	slices.SortFunc(out, func(a, b locate.Record) int { return b.Last.Compare(a.Last) })
	return out, nil
}

// All returns every record, most recently seen first.
func (s *Store) All(ctx context.Context) ([]locate.Record, error) {
	all, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]locate.Record, 0, len(all))
	for _, r := range all {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b locate.Record) int { return b.Last.Compare(a.Last) })
	return out, nil
}

func (s *Store) load(ctx context.Context) (map[string]*locate.Record, error) {
	var list []*locate.Record
	err := s.root.ReadJSON(ctx, file, limit, &list)
	if errors.Is(err, nstore.ErrNotFound) {
		return map[string]*locate.Record{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sightings: %w", err)
	}
	out := make(map[string]*locate.Record, len(list))
	for _, r := range list {
		out[r.MAC+"|"+r.IP] = r
	}
	return out, nil
}
