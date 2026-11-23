// Package query turns operations questions into row predicates: which
// ports have errors that grow, which optics on up links are abnormal,
// which devices run hot. Each object kind has a row type carrying the
// facts its predicates need; predicates compose with All. The package
// reads the model only and reuses the judgments of the analyses (reading
// levels, counter deltas, topology roles, idle ports).
package query

import (
	"cmp"
	"slices"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/topology"
)

// All combines predicates: a row matches when every one matches.
func All[T any](preds ...func(T) bool) func(T) bool {
	return func(r T) bool {
		for _, p := range preds {
			if !p(r) {
				return false
			}
		}
		return true
	}
}

// Filter returns the rows matching pred, in order.
func Filter[T any](rows []T, pred func(T) bool) []T {
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

// Context is what rows are built from: the batch, its topology and the
// previous batch for growth (nil without one).
type Context struct {
	Ledger *ledger.Ledger
	Graph  *topology.Graph
	Prev   *ledger.Ledger
}

func (c Context) prev(d *swtele.Device) *swtele.Device {
	if c.Prev == nil {
		return nil
	}
	return c.Prev.Device(d.Identity.Mgmt.String())
}

// elapsed returns the time between the previous and current observation
// of d, or 0.
func (c Context) elapsed(d *swtele.Device) time.Duration {
	if p := c.prev(d); p != nil {
		return d.Observed.Sub(p.Observed)
	}
	return 0
}

// sortDevices orders rows by device address.
func sortDevices[T any](rows []T, dev func(T) *swtele.Device) {
	slices.SortStableFunc(rows, func(a, b T) int { return cmp.Compare(dev(a).Identity.Mgmt.String(), dev(b).Identity.Mgmt.String()) })
}
