// Package ios decodes Cisco IOS and IOS-XE command outputs (Catalyst
// switches) into the swtele device model.
package ios

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
	clidoc.NewStep("show interfaces", decodeInterfaces, swtele.DimInterfaces, swtele.DimCounters, swtele.DimRates, swtele.DimAddresses),
	clidoc.NewStep("show interfaces status", decodeStatus, swtele.DimInterfaces),
	clidoc.NewStep("show interfaces description", decodeDescription, swtele.DimInterfaces),
	clidoc.NewStep("show interfaces status err-disabled", decodeErrDisabled, swtele.DimInterfaces),
	clidoc.NewStep("show errdisable recovery", decodeAccount),
	clidoc.NewStep("show ip interface brief", decodeIPBrief, swtele.DimAddresses),
	clidoc.NewStep("show interfaces transceiver detail", decodeTransceiver, swtele.DimOptics),
	clidoc.NewStep("show etherchannel summary", decodeEtherchannel, swtele.DimAggregates),
	clidoc.NewStep("show processes cpu sorted", decodeCPU, swtele.DimCPU),
	clidoc.NewStep("show processes memory sorted", decodeMemory, swtele.DimMemory),
	clidoc.NewStep("show environment all", decodeEnvironment, swtele.DimEnvironment),
	clidoc.NewStep("show ip ospf neighbor", decodeOSPF, swtele.DimOSPF),
	clidoc.NewStep("show ip bgp summary", decodeBGP, swtele.DimBGP),
	clidoc.NewStep("show ip arp", decodeARP, swtele.DimARP),
	clidoc.NewStep("show mac address-table", decodeMAC, swtele.DimMAC),
	clidoc.NewPrefixStep("show logging", decodeLog, swtele.DimLogs),
	clidoc.NewStep("show lldp neighbors detail", decodeLLDP, swtele.DimNeighbors),
	clidoc.NewStep("show cdp neighbors detail", decodeCDP, swtele.DimNeighbors),
}

// Options tune decoding.
type Options struct {
	Location *time.Location
	OnOutput clidoc.Observer
}

// Decode builds the device model from the outputs of one capture.
func Decode(ctx context.Context, id device.Device, c capture.Capture, o Options) (*swtele.Device, error) {
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	dev := swtele.New(id, c.RecordedAt())
	if err := clidoc.Run(ctx, dev, c, steps, &state{dev: dev, loc: loc}, o.OnOutput); err != nil {
		return nil, fmt.Errorf("ios: %w", err)
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

// abbreviations of IOS tables.
var abbreviations = map[string]string{
	"Twe": "TwentyFiveGigE", "Hu": "HundredGigE", "Fo": "FortyGigabitEthernet", "Te": "TenGigabitEthernet",
	"Gi": "GigabitEthernet", "Fa": "FastEthernet", "Po": "Port-channel", "Vl": "Vlan", "Lo": "Loopback",
	"Ap": "AppGigabitEthernet", "Tu": "Tunnel",
}

var shortName = regexp.MustCompile(`^([A-Za-z-]+)(\d.*)$`)

func longName(name string) string {
	name = swtele.CleanName(name)
	if m := shortName.FindStringSubmatch(name); m != nil {
		if long, ok := abbreviations[m[1]]; ok {
			return long + m[2]
		}
	}
	return name
}

func kindOf(name string) swtele.Kind {
	switch n := strings.ToLower(name); {
	case strings.HasPrefix(n, "port-channel"):
		return swtele.KindAggregate
	case strings.HasPrefix(n, "vlan"):
		return swtele.KindSVI
	case strings.HasPrefix(n, "loopback"):
		return swtele.KindLoopback
	case strings.HasPrefix(n, "tunnel"):
		return swtele.KindTunnel
	case strings.HasPrefix(n, "null"):
		return swtele.KindNull
	case strings.Contains(n, "ethernet") && strings.HasPrefix(n, "gigabitethernet0/0"):
		return swtele.KindMgmt
	case strings.Contains(n, "gig") || strings.Contains(n, "ethernet"):
		return swtele.KindPhysical
	}
	return swtele.KindVirtual
}

func port(st *state, name string) *swtele.Interface {
	i := st.dev.Interfaces.Ensure(longName(name))
	if i.Kind == swtele.KindUnknown {
		i.Kind = kindOf(i.Name)
	}
	return i
}

func fill[T any](dst *swtele.Opt[T], v swtele.Opt[T]) {
	if !dst.OK {
		*dst = v
	}
}

var (
	ifHeader = regexp.MustCompile(`^(\S+) is (up|down|administratively down|deleted), line protocol is (up|down)(?:\s*\((\S+)\))?`)
	ifRules  = []struct {
		re *regexp.Regexp
		do func(m []string, i *swtele.Interface)
	}{
		{regexp.MustCompile(`^Hardware is .*?, address is ([0-9a-f.]{14})`), func(m []string, i *swtele.Interface) { i.MAC, _ = swtele.ParseMAC(m[1]) }},
		{regexp.MustCompile(`^Description: (.*)$`), func(m []string, i *swtele.Interface) { i.Desc = strings.TrimSpace(m[1]) }},
		{regexp.MustCompile(`^Internet address is (\S+)`), func(m []string, i *swtele.Interface) {
			if p, err := netip.ParsePrefix(m[1]); err == nil {
				i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: p, Primary: true})
			}
		}},
		{regexp.MustCompile(`^MTU (\d+) bytes`), func(m []string, i *swtele.Interface) { i.MTU = clidoc.Int(m[1]) }},
		{regexp.MustCompile(`^(Full|Half|Auto)-duplex, ([^,]+)(?:, link type is \S+)?(?:, media type is (.*))?$`), func(m []string, i *swtele.Interface) {
			switch m[1] {
			case "Full":
				i.Duplex = swtele.DuplexFull
			case "Half":
				i.Duplex = swtele.DuplexHalf
			}
			if !strings.HasPrefix(strings.ToLower(m[2]), "auto") {
				i.Speed = clidoc.Speed(strings.ReplaceAll(m[2], " ", ""))
			}
			if m[3] != "" {
				i.Media = strings.TrimSpace(m[3])
			}
		}},
		{regexp.MustCompile(`^(\d+) (minute|second)s? (input|output) rate (\d+) bits/sec, (\d+) packets/sec`), func(m []string, i *swtele.Interface) {
			unit := time.Second
			if m[2] == "minute" {
				unit = time.Minute
			}
			i.Rates.Window = time.Duration(clidoc.Int(m[1]).Or(0)) * unit
			if m[3] == "input" {
				i.Rates.InBps, i.Rates.InPps = clidoc.Float(m[4]), clidoc.Float(m[5])
			} else {
				i.Rates.OutBps, i.Rates.OutPps = clidoc.Float(m[4]), clidoc.Float(m[5])
			}
		}},
		{regexp.MustCompile(`^Input queue: .*Total output drops: (\d+)`), func(m []string, i *swtele.Interface) { i.Counters.Out.Discards = clidoc.Uint(m[1]) }},
		{regexp.MustCompile(`^Received (\d+) broadcasts \((\d+) (?:IP )?multicasts?\)`), func(m []string, i *swtele.Interface) {
			i.Counters.In.Bcast, i.Counters.In.Multicst = clidoc.Uint(m[1]), clidoc.Uint(m[2])
		}},
		{regexp.MustCompile(`^Output (\d+) broadcasts \((\d+) (?:IP )?multicasts?\)`), func(m []string, i *swtele.Interface) {
			i.Counters.Out.Bcast, i.Counters.Out.Multicst = clidoc.Uint(m[1]), clidoc.Uint(m[2])
		}},
	}
	ifIgnored = regexp.MustCompile(`^(?:Fec is |reliability |Encapsulation |Keepalive |input flow-control|output flow-control|ARP type|Last input|Last clearing|Queueing strategy|Output queue|Members in this channel|No. of active members|Member \d+ :|Interface is unnumbered|Internet address will|MTU |Auto-duplex|Down Reason|L2 Switched|L3 in Switched|L3 out Switched|Encapsulation 802|Carrier delay|Tunnel |Time since|Last state change|.*VLAN Id|Media-type configured|Hardware is |Full-duplex|Half-duplex|Auto-speed|Port-channel|Keepalive not|Interface .* is in|Timeout|Total|Unknown|Down)`)
)

func decodeInterfaces(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(ifHeader.MatchString)
	for _, block := range blocks {
		m := ifHeader.FindStringSubmatch(block[0].Text)
		i := port(st, m[1])
		i.Admin, i.Oper, i.Protocol = swtele.StateUp, swtele.StateDown, swtele.StateDown
		switch m[2] {
		case "up":
			i.Oper = swtele.StateUp
		case "administratively down":
			i.Admin, i.DownCause = swtele.StateDown, swtele.CauseAdmin
		}
		if m[3] == "up" {
			i.Protocol = swtele.StateUp
		}
		if m[4] == "err-disabled" {
			i.DownCause = swtele.CauseErrDisabled
		}
		doc.Mark(block[0])
		for _, l := range block[1:] {
			if ifLine(strings.TrimSpace(l.Text), i) {
				doc.Mark(l)
			}
		}
	}
}

func ifLine(text string, i *swtele.Interface) bool {
	if text == "" {
		return true
	}
	for _, r := range ifRules {
		if m := r.re.FindStringSubmatch(text); m != nil {
			r.do(m, i)
			return true
		}
	}
	if items, ok := counterItems(text); ok {
		counters(i, items)
		return true
	}
	return ifIgnored.MatchString(text)
}

// counterItem is one "<n> <label>" pair of a counter line.
type counterItem struct{ value, label string }

// counterItems splits "0 runts, 0 giants, 0 throttles" into pairs; ok is
// false for any other line shape.
func counterItems(text string) ([]counterItem, bool) {
	var out []counterItem
	for part := range strings.SplitSeq(text, ",") {
		f := strings.Fields(part)
		if len(f) < 2 || !clidoc.Uint(f[0]).OK {
			return nil, false
		}
		out = append(out, counterItem{value: f[0], label: strings.Join(f[1:], " ")})
	}
	return out, len(out) > 0
}

func counters(i *swtele.Interface, items []counterItem) {
	c := &i.Counters
	for _, it := range items {
		v := clidoc.Uint(it.value)
		switch it.label {
		case "packets input":
			c.In.Packets = v
		case "packets output":
			c.Out.Packets = v
		case "bytes":
			if !c.In.Octets.OK {
				c.In.Octets = v
			} else {
				c.Out.Octets = v
			}
		case "runts":
			c.Runts = v
		case "giants":
			c.Giants = v
		case "throttles":
			c.Throttles = v
		case "input errors":
			c.In.Errors = v
		case "CRC":
			c.CRC = v
		case "frame":
			c.Frame = v
		case "overrun":
			c.Overruns = v
		case "no buffer":
			c.NoBuffer = v
		case "pause input":
			c.In.Pause = v
		case "pause output":
			c.Out.Pause = v
		case "output errors":
			c.Out.Errors = v
		case "collisions":
			c.Collisions = v
		case "interface resets":
			c.Resets = v
		case "late collision":
			c.LateColl = v
		case "underruns":
			c.Underruns = v
		}
	}
}
