// Package check is the risk catalog of the ledger: netops assess rules
// over one device in its fleet context (topology, previous observation).
// A rule declares the dimensions it reads; the engine skips it with
// "insufficient evidence" when one was not observed, so a missing command
// never reads as a healthy device.
package check

import (
	"fmt"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/ledger"
	"github.com/gatework/swtele/topology"
)

// Target is what a rule evaluates: one device, the fleet around it, and
// the same device in the previous batch (nil when there is none).
type Target struct {
	Ledger *ledger.Ledger
	Graph  *topology.Graph
	Device *swtele.Device
	Prev   *swtele.Device
}

// Elapsed returns the time between the previous and current observation,
// or 0 without a previous one.
func (t *Target) Elapsed() time.Duration {
	if t.Prev == nil {
		return 0
	}
	return t.Device.Observed.Sub(t.Prev.Observed)
}

// Rule kinds.
type rule = assess.Rule[*Target]

// Catalog returns every rule.
func Catalog() (*assess.Catalog[*Target], error) {
	rules := make([]rule, 0, 40)
	rules = append(rules, opticsRules()...)
	rules = append(rules, counterRules()...)
	rules = append(rules, flapRules()...)
	rules = append(rules, healthRules()...)
	rules = append(rules, stackRules()...)
	rules = append(rules, lagRules()...)
	rules = append(rules, routingRules()...)
	rules = append(rules, linkRules()...)
	rules = append(rules, configRules()...)
	c, err := assess.NewCatalog(rules...)
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	return c, nil
}

func dims(d ...evidence.Dimension) []evidence.Dimension { return d }

func deviceSubject(d *swtele.Device) assess.Subject {
	return assess.NewSubject("device", d.Name())
}

func portSubject(d *swtele.Device, port string) assess.Subject {
	return deviceSubject(d).Child("interface", port)
}

func finding(t *Target, subject assess.Subject, title, detail string, fields ...evidence.Field) assess.Finding {
	return assess.Finding{
		Subject: subject, Title: title, Detail: detail,
		Fields: append([]evidence.Field{{Key: "mgmt", Value: t.Device.Identity.Mgmt.String()}}, fields...),
	}
}

func field(k string, v any) evidence.Field { return evidence.Field{Key: k, Value: fmt.Sprint(v)} }

// physicalUp returns the physical ports that are up.
func physicalUp(d *swtele.Device) []*swtele.Interface {
	var out []*swtele.Interface
	for _, i := range d.Interfaces.All() {
		if i.Kind == swtele.KindPhysical && i.Up() {
			out = append(out, i)
		}
	}
	return out
}

func prevInterface(t *Target, name string) *swtele.Interface {
	if t.Prev == nil {
		return nil
	}
	return t.Prev.Interfaces.Get(name)
}
