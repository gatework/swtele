// Package hillstone decodes Hillstone StoneOS (SG-6000 firewalls) command
// outputs into the swtele device model.
package hillstone

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

type state struct {
	dev *swtele.Device
	loc *time.Location
}

var steps = []clidoc.Step[*state]{
	clidoc.NewStep("show version", decodeVersion, swtele.DimSystem),
	clidoc.NewStep("show interface", decodeInterface, swtele.DimInterfaces, swtele.DimAddresses),
	clidoc.NewPrefixStep("show lacp aggregate", decodeLACP, swtele.DimAggregates),
	clidoc.NewStep("show transceiver", decodeTransceiver, swtele.DimOptics, swtele.DimOpticsInv),
	clidoc.NewStep("show cpu", decodeCPU, swtele.DimCPU),
	clidoc.NewStep("show memory", decodeMemory, swtele.DimMemory),
	clidoc.NewStep("show environment", decodeEnvironment, swtele.DimEnvironment),
	clidoc.NewStep("show statistics-set predef_if_bw current", decodeRates, swtele.DimRates),
	clidoc.NewStep("show arp", decodeARP, swtele.DimARP),
	clidoc.NewStep("show mac", decodeMAC, swtele.DimMAC),
	clidoc.NewStep("show ip vrouter", decodeVRouter),
	clidoc.NewStep("show ip ospf neighbor", decodeOSPF, swtele.DimOSPF),
	clidoc.NewStep("show ip bgp summary", decodeBGP, swtele.DimBGP),
	clidoc.NewStep("show logging event severity err", decodeLog, swtele.DimLogs),
	clidoc.NewStep("show lldp neighbor-information", decodeLLDP, swtele.DimNeighbors),
}

// Options tune decoding.
type Options struct {
	Location *time.Location
	OnOutput clidoc.Observer
}

// haRole reads the HA role a StoneOS prompt carries: "fw1(M)#" is the
// master, "fw1(B)#" the backup.
var haRole = regexp.MustCompile(`\((M|B)\)[#>]?\s*$`)

// Decode builds the device model from the outputs of one capture.
func Decode(ctx context.Context, id device.Device, c capture.Capture, o Options) (*swtele.Device, error) {
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	dev := swtele.New(id, c.RecordedAt())
	st := &state{dev: dev, loc: loc}
	if err := clidoc.Run(ctx, dev, c, steps, st, o.OnOutput); err != nil {
		return nil, fmt.Errorf("hillstone: %w", err)
	}
	if m := haRole.FindStringSubmatch(c.Prompt); m != nil {
		role := "master"
		if m[1] == "B" {
			role = "backup"
		}
		dev.Stack = &swtele.Stack{Kind: swtele.StackHA, Members: []swtele.Member{{ID: 1, Role: role, Self: true}}}
	}
	for _, a := range dev.Aggregates {
		for _, m := range a.Members {
			if i := dev.Interfaces.Get(m.Port); i != nil {
				i.Aggregate = a.Name
			}
		}
	}
	return dev, nil
}

// Commands returns every command the decoder understands.
func Commands() []string { return clidoc.Commands(steps) }

func blank(s string) bool { return strings.TrimSpace(s) == "" }

// kindOf classifies a StoneOS interface by name.
func kindOf(name string) swtele.Kind {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "aggregate"), strings.HasPrefix(n, "redundant"):
		return swtele.KindAggregate
	case strings.HasPrefix(n, "mgt"):
		return swtele.KindMgmt
	case strings.HasPrefix(n, "vswitchif"), strings.HasPrefix(n, "vlan"):
		return swtele.KindSVI
	case strings.HasPrefix(n, "loopback"):
		return swtele.KindLoopback
	case strings.HasPrefix(n, "tunnel"):
		return swtele.KindTunnel
	case strings.Contains(n, "ethernet"):
		if strings.Contains(n, ".") {
			return swtele.KindVirtual // subinterface
		}
		return swtele.KindPhysical
	}
	return swtele.KindVirtual
}

func port(st *state, name string) *swtele.Interface {
	i := st.dev.Interfaces.Ensure(name)
	if i.Kind == swtele.KindUnknown {
		i.Kind = kindOf(i.Name)
	}
	return i
}

// letters reads one H/A/L/P state letter: U up, D down, K HA keep-up,
// C LACP down.
func letter(s string) swtele.State {
	switch s {
	case "U", "K":
		return swtele.StateUp
	case "D", "C":
		return swtele.StateDown
	}
	return swtele.StateUnknown
}

var ifRow = regexp.MustCompile(`^(\S+)\s+(\S+/\d+)\s+(?:(\S+)\s+)?(\S+)\s+([UDKC])\s+([UDKC])\s+([UDKC])\s+([UDKC])\s+([0-9a-fA-F.]{14})\s*(.*)$`)

var ifLegend = regexp.MustCompile(`^(?:H:physical state|Interface name\s)`)

func decodeInterface(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		text := strings.TrimRight(l.Text, " ")
		switch {
		case blank(text), clidoc.Rule(text), ifLegend.MatchString(text):
		case ifRow.MatchString(text):
			m := ifRow.FindStringSubmatch(text)
			i := port(st, m[1])
			i.Oper, i.Admin, i.Protocol = letter(m[7]), letter(m[6]), letter(m[8])
			if m[5] == "D" && i.Oper == swtele.StateUp {
				i.Oper = swtele.StateDown
			}
			if i.Admin == swtele.StateDown {
				i.DownCause = swtele.CauseAdmin
			}
			if p, err := netip.ParsePrefix(m[2]); err == nil && p.Addr().IsValid() && !p.Addr().IsUnspecified() {
				i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: p, Primary: true})
			}
			i.MAC, _ = swtele.ParseMAC(m[9])
			if d := strings.TrimSpace(m[10]); d != "" && strings.Trim(d, "-") != "" {
				i.Desc = d
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}
