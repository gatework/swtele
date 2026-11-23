// Package nxos decodes Cisco NX-OS command outputs into the swtele device
// model. show interface is decoded first and is the master interface
// list; the status, counters and transceiver tables enrich it.
package nxos

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// Commands.
const (
	cmdVersion     = "show version"
	cmdInterface   = "show interface"
	cmdStatus      = "show interface status"
	cmdDescription = "show interface description"
	cmdErrDisabled = "show interface status err-disabled"
	cmdIPBrief     = "show ip interface brief vrf all"
	cmdCounters    = "show interface counters"
	cmdErrors      = "show interface counters errors"
	cmdTransceiver = "show interface transceiver details"
	cmdPortChannel = "show port-channel summary"
	cmdResources   = "show system resources"
	cmdEnvironment = "show environment"
	cmdOSPF        = "show ip ospf neighbors vrf all"
	cmdBGP         = "show bgp vrf all all summary"
	cmdARP         = "show ip arp vrf all"
	cmdMAC         = "show mac address-table"
	cmdLog         = "show logging last 100"
	cmdLLDP        = "show lldp neighbors detail"
	cmdCDP         = "show cdp neighbors detail"
)

type state struct {
	dev *swtele.Device
	loc *time.Location
}

var steps = []clidoc.Step[*state]{
	clidoc.NewStep(cmdVersion, decodeVersion, swtele.DimSystem),
	clidoc.NewStep(cmdInterface, decodeInterface, swtele.DimInterfaces, swtele.DimCounters, swtele.DimRates, swtele.DimFlap, swtele.DimAddresses),
	clidoc.NewStep(cmdStatus, decodeStatus, swtele.DimInterfaces),
	clidoc.NewStep(cmdDescription, decodeDescription, swtele.DimInterfaces),
	clidoc.NewStep(cmdErrDisabled, decodeErrDisabled, swtele.DimInterfaces),
	clidoc.NewStep(cmdIPBrief, decodeIPBrief, swtele.DimAddresses),
	clidoc.NewStep(cmdCounters, decodeCounters, swtele.DimCounters),
	clidoc.NewStep(cmdErrors, decodeErrors, swtele.DimCounters),
	clidoc.NewStep(cmdTransceiver, decodeTransceiver, swtele.DimOptics, swtele.DimOpticsInv),
	clidoc.NewStep(cmdPortChannel, decodePortChannel, swtele.DimAggregates),
	clidoc.NewStep(cmdResources, decodeResources, swtele.DimCPU, swtele.DimMemory),
	clidoc.NewStep(cmdEnvironment, decodeEnvironment, swtele.DimEnvironment),
	clidoc.NewStep(cmdOSPF, decodeOSPF, swtele.DimOSPF),
	clidoc.NewStep(cmdBGP, decodeBGP, swtele.DimBGP),
	clidoc.NewStep(cmdARP, decodeARP, swtele.DimARP),
	clidoc.NewStep(cmdMAC, decodeMAC, swtele.DimMAC),
	clidoc.NewStep(cmdLog, decodeLog, swtele.DimLogs),
	clidoc.NewStep(cmdLLDP, decodeLLDP, swtele.DimNeighbors),
	clidoc.NewStep(cmdCDP, decodeCDP, swtele.DimNeighbors),
}

// Options tune decoding.
type Options struct {
	// Location is the device clock's zone. Nil means UTC.
	Location *time.Location
	// OnOutput receives each decoded command's status, for diagnostics.
	OnOutput clidoc.Observer
}

// Decode builds the device model from the outputs of one capture.
func Decode(ctx context.Context, id device.Device, c capture.Capture, o Options) (*swtele.Device, error) {
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	dev := swtele.New(id, c.RecordedAt())
	st := &state{dev: dev, loc: loc}
	if err := clidoc.Run(ctx, dev, c, steps, st, o.OnOutput); err != nil {
		return nil, fmt.Errorf("nxos: %w", err)
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

// Commands returns every command the decoder understands, in order.
func Commands() []string { return clidoc.Commands(steps) }

var shortName = regexp.MustCompile(`^([A-Za-z-]+)(\d.*)$`)

// longName expands table abbreviations (Eth1/1, Po101, Lo0) to the names
// of show interface.
func longName(name string) string {
	name = swtele.CleanName(name)
	m := shortName.FindStringSubmatch(name)
	if m == nil {
		return name
	}
	switch strings.ToLower(m[1]) {
	case "eth":
		return "Ethernet" + m[2]
	case "po":
		return "port-channel" + m[2]
	case "lo":
		return "loopback" + m[2]
	case "vlan":
		return "Vlan" + m[2]
	}
	return name
}

func port(st *state, name string) *swtele.Interface {
	i := st.dev.Interfaces.Ensure(longName(name))
	if i.Kind == swtele.KindUnknown {
		i.Kind = kindOf(i.Name)
	}
	return i
}

func kindOf(name string) swtele.Kind {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "port-channel"):
		return swtele.KindAggregate
	case strings.HasPrefix(n, "vlan"):
		return swtele.KindSVI
	case strings.HasPrefix(n, "loopback"):
		return swtele.KindLoopback
	case strings.HasPrefix(n, "mgmt"):
		return swtele.KindMgmt
	case strings.HasPrefix(n, "nve"), strings.HasPrefix(n, "tunnel"):
		return swtele.KindTunnel
	case strings.HasPrefix(n, "ethernet"):
		return swtele.KindPhysical
	}
	return swtele.KindVirtual
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func fill[T any](dst *swtele.Opt[T], v swtele.Opt[T]) {
	if !dst.OK {
		*dst = v
	}
}
