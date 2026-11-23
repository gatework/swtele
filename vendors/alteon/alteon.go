// Package alteon decodes Radware Alteon ADC menu outputs (/info/...,
// /stats/...) into the swtele device model. Ports are numbered; port N is
// the interface named "N" and the management port "mgmt".
package alteon

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

type state struct {
	dev *swtele.Device
	loc *time.Location
}

var steps = []clidoc.Step[*state]{
	clidoc.NewStep("/info/sys/general", decodeGeneral, swtele.DimSystem),
	clidoc.NewStep("/info/link", decodeLink, swtele.DimInterfaces),
	clidoc.NewStep("/info/port", decodePort, swtele.DimInterfaces),
	clidoc.NewStep("/info/transceiver", decodeTransceiver, swtele.DimOptics, swtele.DimOpticsInv),
	clidoc.NewStep("/info/l2/trunk", decodeTrunk, swtele.DimAggregates),
	clidoc.NewStep("/info/l3/ip", decodeIP, swtele.DimAddresses),
	clidoc.NewStep("/stats/mp/cpu", decodeMPCPU, swtele.DimCPU),
	clidoc.NewPrefixStep("/stats/sp", decodeSP, swtele.DimCPU, swtele.DimMemory),
	clidoc.NewPrefixStep("/stats/port ", decodePortStats, swtele.DimCounters, swtele.DimRates),
	clidoc.NewStep("/info/sys/temp", decodeTemp, swtele.DimEnvironment),
	clidoc.NewStep("/info/sys/fan", decodeFan, swtele.DimEnvironment),
	clidoc.NewStep("/info/sys/ps", decodePS, swtele.DimEnvironment),
	clidoc.NewStep("/info/l3/arp/dump", decodeARP, swtele.DimARP),
	clidoc.NewStep("/info/l2/fdb/dump", decodeFDB, swtele.DimMAC),
	clidoc.NewStep("/info/l3/ha", decodeHA, swtele.DimStack),
	clidoc.NewStep("/info/l3/bgp/summary", decodeDisabled, swtele.DimBGP),
	clidoc.NewStep("/info/l3/ospf/nbr", decodeDisabled, swtele.DimOSPF),
	clidoc.NewStep("/info/sys/log", decodeLog, swtele.DimLogs),
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
		return nil, fmt.Errorf("alteon: %w", err)
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

// Feeds returns the dimensions command feeds.
func Feeds(command string) []evidence.Dimension { return clidoc.Feeds(steps, command) }

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func port(st *state, name string) *swtele.Interface {
	i := st.dev.Interfaces.Ensure(name)
	if i.Kind == swtele.KindUnknown {
		i.Kind = swtele.KindPhysical
		if name == "mgmt" {
			i.Kind = swtele.KindMgmt
		}
	}
	return i
}

var (
	genModel   = regexp.MustCompile(`^(Alteon .+)$`)
	genUp      = regexp.MustCompile(`^Switch is up (.+)\.$`)
	genMAC     = regexp.MustCompile(`^MAC Address\s+:\s+(\S+)`)
	genSerial  = regexp.MustCompile(`^Hardware Serial Number\s+:\s+(\S+)`)
	genVersion = regexp.MustCompile(`^Software Version (\S+)`)
)

func decodeGeneral(doc *clidoc.Doc, st *state) {
	sys := &st.dev.System
	for _, l := range doc.Lines {
		text := strings.TrimSpace(l.Text)
		switch {
		case genModel.MatchString(text) && sys.Model == "":
			sys.Model = text
		case genUp.MatchString(text):
			sys.Uptime = clidoc.Duration(strings.ReplaceAll(genUp.FindStringSubmatch(text)[1], " and ", ", "))
		case genSerial.MatchString(text):
			sys.Serial = genSerial.FindStringSubmatch(text)[1]
		case genVersion.MatchString(text):
			sys.Version = genVersion.FindStringSubmatch(text)[1]
		case genMAC.MatchString(text):
			if mac, err := swtele.ParseMAC(genMAC.FindStringSubmatch(text)[1]); err == nil {
				st.dev.Stack = stack(st)
				st.dev.Stack.MAC = mac
			}
		}
		doc.Mark(l) // boot, apply and note lines carry no ledger value
	}
}

func stack(st *state) *swtele.Stack {
	if st.dev.Stack == nil {
		st.dev.Stack = &swtele.Stack{Kind: swtele.StackHA}
	}
	return st.dev.Stack
}

var (
	linkRow  = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(up|down|disabled|inoperative)\s*$`)
	linkInfo = regexp.MustCompile(`^(?:Alias\s+Port\s+Speed|------|\* = value set by configuration)`)
)

func decodeLink(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), clidoc.Rule(l.Text), linkInfo.MatchString(l.Text):
		case linkRow.MatchString(l.Text):
			m := linkRow.FindStringSubmatch(l.Text)
			i := port(st, m[1])
			if m[1] != "mgmt" {
				i.Index = clidoc.Int(m[2])
			}
			switch m[7] {
			case "up":
				i.Admin, i.Oper = swtele.StateUp, swtele.StateUp
			case "disabled":
				i.Admin, i.Oper, i.DownCause = swtele.StateDown, swtele.StateDown, swtele.CauseAdmin
			default:
				i.Admin, i.Oper = swtele.StateUp, swtele.StateDown
			}
			if sp := strings.TrimSuffix(m[3], "*"); sp != "any" && i.Up() {
				i.Speed = clidoc.Speed(sp)
				i.AutoSpeed = swtele.Some(!strings.HasSuffix(m[3], "*"))
			}
			switch strings.TrimSuffix(m[4], "*") {
			case "full":
				i.Duplex = swtele.DuplexFull
			case "half":
				i.Duplex = swtele.DuplexHalf
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	portRow  = regexp.MustCompile(`^(\S+)\s+(\d+)\s+([yn])\s+(\S+)\s+(\d+)\s+(\d+)\s*(.*)$`)
	portCont = regexp.MustCompile(`^\s{20,}[\d ]+$`)
	portInfo = regexp.MustCompile(`^\s*(?:Alias\s+Port\s+Tag|-{5,})`)
	trailing = regexp.MustCompile(`^(.*?)\s*((?:\s*\d+)+)\s*$`)
)

// decodePort reads Alias, Port, Tag, RMON, PVID, BWC, NAME and VLAN(s);
// the VLAN list wraps onto indented lines.
func decodePort(doc *clidoc.Doc, st *state) {
	var cur *swtele.Interface
	for _, l := range doc.Lines {
		switch {
		case blank(l.Text), portInfo.MatchString(l.Text):
		case portRow.MatchString(l.Text):
			m := portRow.FindStringSubmatch(l.Text)
			cur = port(st, m[1])
			sw := &swtele.Switchport{Mode: swtele.ModeAccess, PVID: clidoc.Int(m[5]), Allowed: set.New[int]()}
			if m[3] == "y" {
				sw.Mode = swtele.ModeTrunk
			}
			cur.Switching = sw
			name, vlans := m[7], ""
			if t := trailing.FindStringSubmatch(m[7]); t != nil {
				name, vlans = t[1], t[2]
			}
			if name = strings.TrimSpace(name); name != "" {
				cur.Desc = name
			}
			addVLANs(sw, vlans)
		case cur != nil && portCont.MatchString(l.Text):
			addVLANs(cur.Switching, l.Text)
		default:
			continue
		}
		doc.Mark(l)
	}
}

func addVLANs(sw *swtele.Switchport, text string) {
	for f := range strings.FieldsSeq(text) {
		if v := clidoc.Int(f); v.OK {
			sw.Allowed.Add(v.V, v.V)
		}
	}
}

var (
	ipRow  = regexp.MustCompile(`^\s*(\d+): IP4 (\S+)\s+(\S+)\s+\S+\s*, vlan (\d+), (up|down|disabled)`)
	ipInfo = regexp.MustCompile(`^(?:IP information:|\s*Router ID:|\s*AS number \d+|,?Interface information:|IPv6 Link Local|Default gateway information|\s*\d+: \S+,\s+vlan \S+,\s+\S+\s*$)`)
)

// decodeIP reads the IP interfaces; each becomes interface "IF<n>" on its
// VLAN.
func decodeIP(doc *clidoc.Doc, st *state) {
	tail := false // gateways, local networks and port settings follow the interfaces
	for _, l := range doc.Lines {
		if strings.HasPrefix(l.Text, "Default gateway information") {
			tail = true
		}
		switch {
		case tail, blank(l.Text), ipInfo.MatchString(l.Text):
		case ipRow.MatchString(l.Text):
			m := ipRow.FindStringSubmatch(l.Text)
			i := st.dev.Interfaces.Ensure("IF" + m[1])
			i.Kind, i.Desc = swtele.KindSVI, "vlan "+m[4]
			i.Oper = swtele.StateDown
			if m[5] == "up" {
				i.Oper, i.Admin = swtele.StateUp, swtele.StateUp
			}
			addr, err1 := netip.ParseAddr(m[2])
			mask, err2 := netip.ParseAddr(m[3])
			if err1 == nil && err2 == nil {
				bits := 0
				for _, b := range mask.As4() {
					for ; b&0x80 != 0; b <<= 1 {
						bits++
					}
				}
				i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: netip.PrefixFrom(addr, bits), Primary: true})
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}
