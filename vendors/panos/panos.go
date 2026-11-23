// Package panos decodes Palo Alto PAN-OS operational command outputs into
// the swtele device model.
package panos

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

type state struct {
	dev *swtele.Device
	loc *time.Location
}

var steps = []clidoc.Step[*state]{
	clidoc.NewStep("show interface all", decodeInterfaces, swtele.DimInterfaces, swtele.DimAddresses),
	clidoc.NewStep("show counter interface all", decodeCounters, swtele.DimCounters),
	clidoc.NewStep("show lacp aggregate-ethernet all", decodeLACP, swtele.DimAggregates),
	clidoc.NewStep("show running resource-monitor second last 5", decodeMonitor, swtele.DimCPU),
	clidoc.NewStep("show system resources", decodeResources, swtele.DimCPU, swtele.DimMemory),
	clidoc.NewStep("show system environmentals thermal", decodeEnv("thermal"), swtele.DimEnvironment), //nolint:misspell // PAN-OS command
	clidoc.NewStep("show system environmentals fans", decodeEnv("fans"), swtele.DimEnvironment),       //nolint:misspell // PAN-OS command
	clidoc.NewStep("show system environmentals power", decodeEnv("power"), swtele.DimEnvironment),     //nolint:misspell // PAN-OS command
	clidoc.NewStep("show routing protocol ospf neighbor", decodeOSPF, swtele.DimOSPF),
	clidoc.NewStep("show routing protocol bgp summary", decodeBGP, swtele.DimBGP),
	clidoc.NewStep("show arp all", decodeARP, swtele.DimARP),
	clidoc.NewStep("show mac all", decodeMAC, swtele.DimMAC),
	clidoc.NewStep("show transceiver all", decodeTransceiver, swtele.DimOptics),
	clidoc.NewPrefixStep("show log system", decodeLog, swtele.DimLogs),
	clidoc.NewStep("show lldp neighbors all", decodeLLDP, swtele.DimNeighbors),
}

// Options tune decoding.
type Options struct {
	Location *time.Location
	OnOutput clidoc.Observer
}

// haRole reads "user@fw1(active)>".
var haRole = regexp.MustCompile(`\((active|passive|suspended|non-functional)\)[>#]`)

// Decode builds the device model from the outputs of one capture.
func Decode(ctx context.Context, id device.Device, c capture.Capture, o Options) (*swtele.Device, error) {
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	dev := swtele.New(id, c.RecordedAt())
	if err := clidoc.Run(ctx, dev, c, steps, &state{dev: dev, loc: loc}, o.OnOutput); err != nil {
		return nil, fmt.Errorf("panos: %w", err)
	}
	if m := haRole.FindStringSubmatch(c.Prompt); m != nil {
		dev.Stack = &swtele.Stack{Kind: swtele.StackHA, Members: []swtele.Member{{ID: 1, Role: m[1], Self: true}}}
	}
	return dev, nil
}

// Commands returns every command the decoder understands.
func Commands() []string { return clidoc.Commands(steps) }

// Feeds returns the dimensions command feeds.
func Feeds(command string) []evidence.Dimension { return clidoc.Feeds(steps, command) }

// Hostname reads the host from a "user@host(role)>" prompt.
func Hostname(prompt string) string {
	p := strings.TrimSpace(prompt)
	if i := strings.IndexByte(p, '@'); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.IndexAny(p, "(>#"); i >= 0 {
		p = p[:i]
	}
	return p
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func kindOf(name string) swtele.Kind {
	switch n := strings.ToLower(name); {
	case strings.HasPrefix(n, "ae"):
		return swtele.KindAggregate
	case strings.HasPrefix(n, "vlan"):
		return swtele.KindSVI
	case strings.HasPrefix(n, "loopback"):
		return swtele.KindLoopback
	case strings.HasPrefix(n, "tunnel"):
		return swtele.KindTunnel
	case strings.HasPrefix(n, "ha"), strings.HasPrefix(n, "hsci"):
		return swtele.KindVirtual
	case strings.HasPrefix(n, "ethernet") && strings.Contains(n, "."):
		return swtele.KindVirtual
	case strings.HasPrefix(n, "ethernet"):
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

var (
	hwRow    = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\S+)/(\S+)/(up|down)\S*\s+([0-9a-f:]{17})\s*$`)
	lifRow   = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\d+)\s+(\S*)\s+(\S+)\s+(\d+)\s+(\S+)\s*$`)
	addrCont = regexp.MustCompile(`^\s{20,}(\S+/\d+)\s*$`)
	ifInfo   = regexp.MustCompile(`^(?:total configured (?:hardware|logical) interfaces|name\s+id\s+|-{5,}|aggregation groups:)`)
)

// decodeInterfaces reads the hardware table (speed/duplex/state, MAC) and
// the logical table (zone, forwarding, addresses; extra addresses wrap
// onto lines of their own).
func decodeInterfaces(doc *clidoc.Doc, st *state) {
	var cur *swtele.Interface
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), ifInfo.MatchString(text):
		case hwRow.MatchString(text):
			m := hwRow.FindStringSubmatch(text)
			i := port(st, m[1])
			i.Index = clidoc.Int(m[2])
			i.Admin, i.Oper = swtele.StateUp, swtele.StateDown
			if m[5] == "up" {
				i.Oper = swtele.StateUp
			}
			if sp := clidoc.Int(m[3]); sp.OK {
				i.Speed = swtele.Some(uint64(sp.V) * 1_000_000)
			}
			switch m[4] {
			case "full":
				i.Duplex = swtele.DuplexFull
			case "half":
				i.Duplex = swtele.DuplexHalf
			}
			i.MAC, _ = swtele.ParseMAC(m[6])
		case lifRow.MatchString(text):
			m := lifRow.FindStringSubmatch(text)
			cur = port(st, m[1])
			if vr, ok := strings.CutPrefix(m[5], "vr:"); ok {
				cur.VRF = vr
			}
			if m[4] != "" {
				cur.Desc = "zone " + m[4]
			}
			addAddr(cur, m[7])
		case cur != nil && addrCont.MatchString(text):
			addAddr(cur, addrCont.FindStringSubmatch(text)[1])
		default:
			continue
		}
		doc.Mark(l)
	}
}

func addAddr(i *swtele.Interface, s string) {
	if p, err := netip.ParsePrefix(s); err == nil {
		i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: p, Primary: len(i.Addresses) == 0})
	}
}

var (
	ctrIface = regexp.MustCompile(`^Interface: (\S+)`)
	ctrRow   = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 -]*[A-Za-z0-9])\s{2,}(\d+)\s*$`)
	ctrInfo  = regexp.MustCompile(`^(?:-{10,}|Hardware interface counters|Physical port counters|Logical interface counters)`)
)

// decodeCounters reads the MAC counters of each hardware interface and
// the errors the CPU counted.
func decodeCounters(doc *clidoc.Doc, st *state) {
	var cur *swtele.Interface
	logical := false // logical counters repeat the hardware ones per zone
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), ctrInfo.MatchString(text):
			if strings.HasPrefix(text, "Logical interface counters") {
				logical = true
			}
		case ctrIface.MatchString(text):
			cur = port(st, ctrIface.FindStringSubmatch(text)[1])
		case cur != nil && ctrRow.MatchString(text):
			if !logical {
				m := ctrRow.FindStringSubmatch(text)
				counter(cur, m[1], clidoc.Uint(m[2]))
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

func counter(i *swtele.Interface, name string, v swtele.Opt[uint64]) {
	c := &i.Counters
	switch name {
	case "rx-bytes":
		c.In.Octets = v
	case "tx-bytes":
		c.Out.Octets = v
	case "rx-unicast":
		c.In.Unicast = v
	case "tx-unicast":
		c.Out.Unicast = v
	case "rx-multicast":
		c.In.Multicst = v
	case "tx-multicast":
		c.Out.Multicst = v
	case "rx-broadcast":
		c.In.Bcast = v
	case "tx-broadcast":
		c.Out.Bcast = v
	case "packets received":
		c.In.Packets = v
	case "packets transmitted":
		c.Out.Packets = v
	case "receive errors":
		c.In.Errors = v
	case "receive discarded":
		c.In.Discards = v
	case "packets dropped":
		c.Out.Discards = v
	}
}

// mW converts milliwatts to dBm; no light reads as the -40 dBm sentinel.
func mW(v swtele.Opt[float64]) swtele.Opt[float64] {
	if !v.OK {
		return v
	}
	if v.V <= 0.0001 {
		return swtele.Some(swtele.NoLight)
	}
	return swtele.Some(math.Round(10*math.Log10(v.V)*100) / 100)
}

var (
	xcvrRow  = regexp.MustCompile(`^\s*(\S+)\s+(-?[\d.]+) C\s+([\d.]+) V\s+([\d.]+) mA\s+([\d.]+) mW\s+([\d.]+) mW\s*$`)
	xcvrInfo = regexp.MustCompile(`^(?:-{10,}|\s+Port\s+Temperature)`)
)

// decodeTransceiver reads diagnostics; PAN-OS reports power in mW.
func decodeTransceiver(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), clidoc.Rule(l.Text), xcvrInfo.MatchString(l.Text):
		case xcvrRow.MatchString(l.Text):
			m := xcvrRow.FindStringSubmatch(l.Text)
			x := &swtele.Transceiver{Present: true, DOM: swtele.DOMSupported, Lanes: []swtele.Lane{{Index: 1}}}
			x.Temp.Value, x.Voltage.Value = clidoc.Float(m[2]), clidoc.Float(m[3])
			x.Lanes[0].Bias.Value = clidoc.Float(m[4])
			x.Lanes[0].TxPower.Value, x.Lanes[0].RxPower.Value = mW(clidoc.Float(m[5])), mW(clidoc.Float(m[6]))
			port(st, m[1]).Optics = x
		default:
			continue
		}
		doc.Mark(l)
	}
}
