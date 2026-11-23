package cli

import (
	"io"
	"strconv"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

func speed(o swtele.Opt[uint64]) string {
	v, ok := o.Get()
	switch {
	case !ok || v == 0:
		return "-"
	case v >= 1e9 && v%1e9 == 0:
		return strconv.FormatUint(v/1e9, 10) + "G"
	case v >= 1e9:
		return strconv.FormatFloat(float64(v)/1e9, 'f', 1, 64) + "G"
	}
	return strconv.FormatUint(v/1e6, 10) + "M"
}

func count(o swtele.Opt[uint64]) string {
	if !o.OK {
		return "-"
	}
	return strconv.FormatUint(o.V, 10)
}

func reading(r swtele.Reading) string {
	if !r.Value.OK {
		return "-"
	}
	return strconv.FormatFloat(r.Value.V, 'f', 2, 64)
}

func percent(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) + "%" }

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// peerText renders the far end of a link: "SW02 GE1/0/48".
func peerText(e topology.End, ok bool) string {
	if !ok {
		return "-"
	}
	name := e.Name
	if e.Device != nil {
		name = e.Device.Name()
	}
	if name == "" {
		name = "（未通告名称）"
	}
	return strings.TrimSpace(name + " " + e.Port)
}

// vlanText renders the VLANs of a port: the access VLAN, or the allowed
// list of a trunk.
func vlanText(i *swtele.Interface) string {
	sw := i.Switching
	if sw == nil {
		return "-"
	}
	if sw.Mode == swtele.ModeTrunk || sw.Mode == swtele.ModeHybrid {
		if sw.Allowed != nil && !sw.Allowed.IsEmpty() {
			c := sw.Allowed.Compact()
			if len(c) > 24 {
				c = c[:21] + "…"
			}
			return c
		}
		return "-"
	}
	if p, ok := sw.PVID.Get(); ok {
		return strconv.Itoa(p)
	}
	return "-"
}

func (a *app) out() io.Writer { return a.env.Stdout }

// rateText renders an error share: "100%", "0.0123%", "<0.0001%".
func rateText(r float64) string {
	switch {
	case r == 0:
		return "0"
	case r >= 0.01:
		return strconv.FormatFloat(r*100, 'f', 1, 64) + "%"
	case r >= 0.000001:
		return strconv.FormatFloat(r*100, 'f', 4, 64) + "%"
	}
	return "<0.0001%"
}
