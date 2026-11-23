// Package vendors dispatches a capture to the decoder of its platform.
package vendors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/alteon"
	"github.com/gatework/swtele/vendors/comware"
	"github.com/gatework/swtele/vendors/hillstone"
	"github.com/gatework/swtele/vendors/internal/clidoc"
	"github.com/gatework/swtele/vendors/ios"
	"github.com/gatework/swtele/vendors/nxos"
	"github.com/gatework/swtele/vendors/panos"
)

// Decoder names.
const (
	Comware   = "comware"
	NXOS      = "nxos"
	Hillstone = "hillstone"
	Alteon    = "alteon"
	PANOS     = "panos"
	IOS       = "ios"
)

// ErrUnsupported reports a platform without a decoder.
var ErrUnsupported = errors.New("vendors: unsupported platform")

// aliases maps net-connector platform keys to decoders.
var aliases = map[string]string{
	"h3c": Comware, "h3c_wireless": Comware, "hp_comware": Comware, "comware": Comware,
	"cisco_nxos": NXOS, "nxos": NXOS,
	"hillstone": Hillstone, "stoneos": Hillstone,
	"radware": Alteon, "alteon": Alteon,
	"palo_alto": PANOS, "panos": PANOS,
	"cisco_ios": IOS, "cisco_xe": IOS, "ios": IOS,
}

// Options tune decoding.
type Options struct {
	// Location is the zone of device clocks that print no offset.
	Location *time.Location
	// OnOutput receives each decoded command's status, for diagnostics.
	OnOutput clidoc.Observer
}

// Resolve returns the decoder name for a platform key, or detects it from
// the commands of the capture when the platform is unknown.
func Resolve(platform string, c capture.Capture) (string, bool) {
	if name, ok := aliases[strings.ToLower(platform)]; ok {
		return name, true
	}
	switch {
	case has(c, "show port-channel summary"), has(c, "show interface transceiver details"):
		return NXOS, true
	case has(c, "display interface brief"), has(c, "display interface"):
		return Comware, true
	case has(c, "show statistics-set predef_if_bw current"):
		return Hillstone, true
	case has(c, "/info/sys/general"), has(c, "/info/link"):
		return Alteon, true
	case has(c, "show counter interface all"), has(c, "show interface all"):
		return PANOS, true
	case has(c, "show etherchannel summary"), has(c, "show interfaces"):
		return IOS, true
	}
	return "", false
}

func has(c capture.Capture, cmd string) bool {
	_, ok := c.Output(cmd)
	return ok
}

// Decode builds the device model of one capture.
func Decode(ctx context.Context, id device.Device, c capture.Capture, o Options) (*swtele.Device, error) {
	name, ok := Resolve(id.Platform, c)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, id.Platform)
	}
	var (
		dev *swtele.Device
		err error
	)
	switch name {
	case Comware:
		dev, err = comware.Decode(ctx, id, c, comware.Options{Location: o.Location, OnOutput: o.OnOutput})
	case NXOS:
		dev, err = nxos.Decode(ctx, id, c, nxos.Options{Location: o.Location, OnOutput: o.OnOutput})
	case Hillstone:
		dev, err = hillstone.Decode(ctx, id, c, hillstone.Options{Location: o.Location, OnOutput: o.OnOutput})
	case Alteon:
		dev, err = alteon.Decode(ctx, id, c, alteon.Options{Location: o.Location, OnOutput: o.OnOutput})
	case PANOS:
		dev, err = panos.Decode(ctx, id, c, panos.Options{Location: o.Location, OnOutput: o.OnOutput})
	case IOS:
		dev, err = ios.Decode(ctx, id, c, ios.Options{Location: o.Location, OnOutput: o.OnOutput})
	}
	if err != nil {
		return nil, fmt.Errorf("vendors: %w", err)
	}
	if dev.Identity.Platform == "" {
		dev.Identity.Platform = name
	}
	if dev.System.Hostname == "" {
		dev.System.Hostname = Hostname(c.Prompt)
		if name == PANOS {
			dev.System.Hostname = panos.Hostname(c.Prompt)
		}
	}
	return dev, nil
}

// Hostname derives the device name from its CLI prompt: "<sw1>",
// "[sw1]", "sw1#" and "sw1(M)#" all name sw1.
func Hostname(prompt string) string {
	p := strings.TrimSpace(strings.ReplaceAll(prompt, "\x00", ""))
	p = strings.TrimPrefix(strings.TrimPrefix(p, "<"), "[")
	p = strings.TrimRight(p, ">]#$ ")
	if i := strings.Index(p, "("); i > 0 {
		p = p[:i]
	}
	return p
}

// Commands returns the commands a decoder understands.
func Commands(name string) []string {
	switch name {
	case Comware:
		return comware.Commands()
	case NXOS:
		return nxos.Commands()
	case Hillstone:
		return hillstone.Commands()
	case Alteon:
		return alteon.Commands()
	case PANOS:
		return panos.Commands()
	case IOS:
		return ios.Commands()
	}
	return nil
}

// Overlay reads the configuration text of dev, backed up at at, into
// dev.Config with the decoder of its platform.
func Overlay(ctx context.Context, dev *swtele.Device, text string, at time.Time) error {
	name, _ := Resolve(dev.Identity.Platform, capture.Capture{})
	var err error
	switch name {
	case Comware:
		err = comware.Overlay(ctx, dev, text, at)
	case NXOS:
		err = nxos.Overlay(ctx, dev, text, at)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupported, dev.Identity.Platform)
	}
	if err != nil {
		return fmt.Errorf("vendors: %w", err)
	}
	return nil
}
