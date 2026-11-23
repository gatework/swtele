package hillstone

import (
	"regexp"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	xcvrHeader = regexp.MustCompile(`^=+\s+(\S+)\s+=+\s*$`)
	xcvrIntro  = regexp.MustCompile(`^Transceiver status information is shown as below:`)
	// xcvrKV: "Module temperature: 21.80 C", "Rx channel 2 optical power: -15.92 dBm".
	xcvrKV    = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+/ ]*?)\s*:\s*(.*)$`)
	xcvrRange = regexp.MustCompile(`^(.*?) normal range\s*:\s*\[\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\]`)
	xcvrLane  = regexp.MustCompile(`(?i)^(tx|rx) channel (\d+) (bias current|optical power)$`)
)

// decodeTransceiver reads "=== port ===" blocks of tab-separated labels.
// The "normal range" of a reading becomes its alarm thresholds.
func decodeTransceiver(doc *clidoc.Doc, st *state) {
	pre, blocks := doc.Blocks(func(s string) bool { return xcvrHeader.MatchString(s) && !clidoc.Rule(s) })
	for _, l := range pre {
		if blank(l.Text) || xcvrIntro.MatchString(l.Text) {
			doc.Mark(l)
		}
	}
	for _, block := range blocks {
		i := port(st, xcvrHeader.FindStringSubmatch(block[0].Text)[1])
		x := &swtele.Transceiver{Present: true, DOM: swtele.DOMSupported}
		doc.Mark(block[0])
		for _, l := range block[1:] {
			text := strings.TrimSpace(strings.ReplaceAll(l.Text, "\t", " "))
			if text == "" || clidoc.Rule(text) || xcvrLine(x, text) {
				doc.Mark(l)
			}
		}
		if placeholder(x) {
			x.DOM, x.Temp, x.Voltage, x.Lanes = swtele.DOMUnsupported, swtele.Reading{}, swtele.Reading{}, nil
		}
		i.Optics = x
	}
}

// xcvrLine applies one label line; it reports whether the line was
// understood.
func xcvrLine(x *swtele.Transceiver, text string) bool {
	if m := xcvrRange.FindStringSubmatch(text); m != nil {
		lo, hi := clidoc.Float(m[2]), clidoc.Float(m[3])
		for _, r := range readings(x, strings.ToLower(strings.TrimSpace(m[1]))) {
			r.Th.LowAlarm, r.Th.HighAlarm = lo, hi
		}
		return true
	}
	m := xcvrKV.FindStringSubmatch(text)
	if m == nil {
		return false
	}
	key, value := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
	switch {
	case strings.HasSuffix(key, "information"): // "SFP+/XFP information: VENDOR / datecode"
		vendor, date, _ := strings.Cut(value, "/")
		x.Inventory.Vendor, x.Inventory.Date = strings.TrimSpace(vendor), strings.TrimSpace(date)
		x.Inventory.Type = strings.TrimSuffix(m[1], " information")
	case key == "part number":
		x.Inventory.PartNumber = value
	case key == "serial number":
		x.Inventory.Serial = value
	case key == "module wavelength":
		if v := clidoc.Float(value); v.OK {
			x.Inventory.Wavelength = swtele.Some(int(v.V))
		}
	case strings.Contains(key, "transmit distance"), key == "transmission media":
	default:
		rs := readings(x, key)
		if len(rs) == 0 {
			return false
		}
		rs[0].Value = clidoc.Float(value)
	}
	return true
}

// readings returns the readings a label names; a range label without a
// channel ("RX optical power normal range") applies to every lane.
func readings(x *swtele.Transceiver, key string) []*swtele.Reading {
	if m := xcvrLane.FindStringSubmatch(key); m != nil {
		n := clidoc.Int(m[2]).Or(1)
		l := lane(x, n)
		switch {
		case m[3] == "bias current":
			return []*swtele.Reading{&l.Bias}
		case m[1] == "tx":
			return []*swtele.Reading{&l.TxPower}
		default:
			return []*swtele.Reading{&l.RxPower}
		}
	}
	switch key {
	case "module temperature":
		return []*swtele.Reading{&x.Temp}
	case "tx supply voltage":
		return []*swtele.Reading{&x.Voltage}
	}
	var pick func(*swtele.Lane) *swtele.Reading
	switch key {
	case "tx bias current":
		pick = func(l *swtele.Lane) *swtele.Reading { return &l.Bias }
	case "tx optical power":
		pick = func(l *swtele.Lane) *swtele.Reading { return &l.TxPower }
	case "rx optical power":
		pick = func(l *swtele.Lane) *swtele.Reading { return &l.RxPower }
	default:
		return nil
	}
	if len(x.Lanes) == 0 {
		lane(x, 1)
	}
	out := make([]*swtele.Reading, len(x.Lanes))
	for n := range x.Lanes {
		out[n] = pick(&x.Lanes[n])
	}
	return out
}

func lane(x *swtele.Transceiver, n int) *swtele.Lane {
	for len(x.Lanes) < n {
		x.Lanes = append(x.Lanes, swtele.Lane{Index: len(x.Lanes) + 1})
	}
	return &x.Lanes[n-1]
}

// placeholder reports a module whose temperature, voltage and bias all
// read zero: it has no real diagnostics.
func placeholder(x *swtele.Transceiver) bool {
	if x.Temp.Value.Or(-1) != 0 || x.Voltage.Value.Or(-1) != 0 {
		return false
	}
	for _, l := range x.Lanes {
		if l.Bias.Value.Or(0) != 0 {
			return false
		}
	}
	return true
}
