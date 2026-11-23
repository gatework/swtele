// Package comware decodes H3C Comware 7 command outputs into the swtele
// device model.
//
// Each command has one decoder that consumes the lines it understands;
// what it leaves is reported as unparsed and degrades the dimensions the
// command feeds to partial. Commands the device rejected mark their
// dimensions failed. display interface is decoded first and is the master
// interface list; the brief, counters and transceiver tables enrich it.
package comware

import (
	"context"
	"fmt"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// Commands.
const (
	cmdInterface       = "display interface"
	cmdBrief           = "display interface brief"
	cmdBriefDesc       = "display interface brief description"
	cmdBriefDown       = "display interface brief down"
	cmdIPBrief         = "display ip interface brief"
	cmdDiagnosis       = "display transceiver diagnosis interface"
	cmdManuinfo        = "display transceiver manuinfo interface"
	cmdLAG             = "display link-aggregation verbose"
	cmdCPU             = "display cpu-usage"
	cmdMemory          = "display memory"
	cmdEnvironment     = "display environment"
	cmdRateIn          = "display counters rate inbound interface"
	cmdRateOut         = "display counters rate outbound interface"
	cmdCountIn         = "display counters inbound interface"
	cmdCountOut        = "display counters outbound interface"
	cmdOSPF            = "display ospf peer"
	cmdBGP             = "display bgp peer ipv4"
	cmdARP             = "display arp all"
	cmdMAC             = "display mac-address"
	cmdLog             = "display logbuffer reverse size 50"
	cmdSTPDown         = "display stp down-port"
	cmdFlapProtection  = "display link-flap protection"
	cmdIRF             = "display irf"
	cmdIRFTopology     = "display irf topology"
	cmdIRFLink         = "display irf link"
	cmdMAD             = "display mad verbose"
	cmdLLDPList        = "display lldp neighbor-information list"
	cmdLLDPVerbose     = "display lldp neighbor-information verbose"
	cmdVersion         = "display version"
	cmdBGPUnicast      = "display bgp peer ipv4 unicast"
	cmdCurrentConfig   = "display current-configuration"
	cmdTransceiverInfo = "display transceiver interface"
)

// state is the decoding context of one device.
type state struct {
	dev *swtele.Device
	loc *time.Location
	// lldpListed counts neighbors in the list output, for the cross-check
	// against the verbose output.
	lldpListed int
}

// steps run in order: display interface first, as the master list.
var steps = []clidoc.Step[*state]{
	clidoc.NewStep(cmdVersion, decodeVersion, swtele.DimSystem),
	clidoc.NewStep(cmdInterface, decodeInterface, swtele.DimInterfaces, swtele.DimCounters, swtele.DimRates, swtele.DimFlap, swtele.DimAddresses),
	clidoc.NewStep(cmdBrief, decodeBrief, swtele.DimInterfaces),
	clidoc.NewStep(cmdBriefDesc, decodeBrief, swtele.DimInterfaces),
	clidoc.NewStep(cmdBriefDown, decodeBriefDown, swtele.DimInterfaces),
	clidoc.NewStep(cmdIPBrief, decodeIPBrief, swtele.DimAddresses),
	clidoc.NewStep(cmdCountIn, decodeCounts(true), swtele.DimCounters),
	clidoc.NewStep(cmdCountOut, decodeCounts(false), swtele.DimCounters),
	clidoc.NewStep(cmdRateIn, decodeRates(true), swtele.DimRates),
	clidoc.NewStep(cmdRateOut, decodeRates(false), swtele.DimRates),
	clidoc.NewStep(cmdDiagnosis, decodeDiagnosis, swtele.DimOptics),
	clidoc.NewStep(cmdManuinfo, decodeManuinfo, swtele.DimOpticsInv),
	clidoc.NewStep(cmdLAG, decodeLAG, swtele.DimAggregates),
	clidoc.NewStep(cmdCPU, decodeCPU, swtele.DimCPU),
	clidoc.NewStep(cmdMemory, decodeMemory, swtele.DimMemory),
	clidoc.NewStep(cmdEnvironment, decodeEnvironment, swtele.DimEnvironment),
	clidoc.NewStep(cmdIRF, decodeIRF, swtele.DimStack),
	clidoc.NewStep(cmdIRFTopology, decodeIRFTopology, swtele.DimStack),
	clidoc.NewStep(cmdIRFLink, decodeIRFLink, swtele.DimStack),
	clidoc.NewStep(cmdMAD, decodeMAD, swtele.DimMAD),
	clidoc.NewStep(cmdSTPDown, decodeSTPDown, swtele.DimSTP),
	clidoc.NewStep(cmdFlapProtection, decodeFlapProtection, swtele.DimFlap),
	clidoc.NewStep(cmdLLDPList, decodeLLDPList, swtele.DimNeighbors),
	clidoc.NewStep(cmdLLDPVerbose, decodeLLDPVerbose, swtele.DimNeighbors),
	clidoc.NewStep(cmdARP, decodeARP, swtele.DimARP),
	clidoc.NewStep(cmdMAC, decodeMAC, swtele.DimMAC),
	clidoc.NewStep(cmdOSPF, decodeOSPF, swtele.DimOSPF),
	clidoc.NewStep(cmdBGP, decodeBGP, swtele.DimBGP),
	clidoc.NewStep(cmdBGPUnicast, decodeBGP, swtele.DimBGP),
	clidoc.NewStep(cmdLog, decodeLog, swtele.DimLogs),
}

// Options tune decoding.
type Options struct {
	// Location is the device clock's zone, used for timestamps printed
	// without an offset. Nil means UTC.
	Location *time.Location
	// OnOutput receives each decoded command's status, for diagnostics.
	OnOutput clidoc.Observer
}

// Decode builds the device model from the outputs of one capture.
// Commands absent from the capture leave their dimensions not requested.
func Decode(ctx context.Context, id device.Device, c capture.Capture, o Options) (*swtele.Device, error) {
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	dev := swtele.New(id, c.RecordedAt())
	st := &state{dev: dev, loc: loc}
	if err := clidoc.Run(ctx, dev, c, steps, st, o.OnOutput); err != nil {
		return nil, fmt.Errorf("comware: %w", err)
	}
	finish(st)
	return dev, nil
}

// Commands returns every command the decoder understands, in order.
func Commands() []string { return clidoc.Commands(steps) }

// Feeds returns the dimensions command feeds.
func Feeds(command string) []evidence.Dimension { return clidoc.Feeds(steps, command) }

// finish runs the cross-command consistency checks and derivations.
func finish(st *state) {
	linkAggregates(st.dev)
}

// linkAggregates records each member's aggregate on the interface.
func linkAggregates(dev *swtele.Device) {
	for _, a := range dev.Aggregates {
		for _, m := range a.Members {
			if i := dev.Interfaces.Get(m.Port); i != nil {
				i.Aggregate = a.Name
			}
		}
	}
}
