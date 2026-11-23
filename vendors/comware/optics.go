package comware

import (
	"regexp"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	diagHeader = regexp.MustCompile(`^(\S+) transceiver diagnostic information:$`)
	manuHeader = regexp.MustCompile(`^(\S+) transceiver manufacture information:$`)
	// singleCols is the column order of the single-lane parameter table.
	singleCols = regexp.MustCompile(`^\s*Temp\.\(°?C\)\s+Voltage\(V\)\s+Bias\(mA\)\s+RX power\(dBm\)\s+TX power\(dBm\)\s*$`)
	moduleCols = regexp.MustCompile(`^\s*\[module\]\s+Temp\.\(°?C\)\s+Voltage\(V\)\s*$`)
	powerCols  = regexp.MustCompile(`^\s*RX power\(dBm\)\s+TX power\(dBm\)\s*$`)
	laneCols   = regexp.MustCompile(`^\s*\[channel\]\s+Bias\(mA\)\s+RX power\(dBm\)\s+TX power\(dBm\)\s*$`)
	thHeads    = regexp.MustCompile(`^\s*(Current diagnostic parameters|Alarm thresholds|Warning thresholds|User-set power thresholds|Warning parameters):\s*$`)
	thRow      = regexp.MustCompile(`^\s*(High|Low)\s+(.+)$`)
	xcvrAbsent = regexp.MustCompile(`(?i)^\s*(?:The transceiver is absent|The transceiver does not support this function|The operation is not supported|Error: The transceiver is absent)`)
)

func decodeDiagnosis(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(diagHeader.MatchString)
	for _, block := range blocks {
		name := diagHeader.FindStringSubmatch(block[0].Text)[1]
		i := port(st, name)
		x := optics(i)
		x.Present = true
		doc.Mark(block[0])
		section, mode := "", ""
		for _, l := range block[1:] {
			text := l.Text
			switch {
			case blank(text):
			case xcvrAbsent.MatchString(text):
				if strings.Contains(strings.ToLower(text), "absent") {
					x.Present = false
				} else {
					x.DOM = swtele.DOMUnsupported
				}
			case thHeads.MatchString(text):
				section = strings.ToLower(thHeads.FindStringSubmatch(text)[1])
			case singleCols.MatchString(text):
				mode = "single"
			case moduleCols.MatchString(text):
				mode = "module"
			case laneCols.MatchString(text):
				mode = "lane"
			case powerCols.MatchString(text):
			case section == "current diagnostic parameters":
				if !currentRow(x, mode, text) {
					continue
				}
			case strings.Contains(section, "thresholds"):
				m := thRow.FindStringSubmatch(text)
				if m == nil {
					continue
				}
				thresholdRow(x, section, m[1] == "High", strings.Fields(m[2]))
			default:
				continue
			}
			doc.Mark(l)
		}
		if x.Present && x.DOM == swtele.DOMUnknown {
			x.DOM = swtele.DOMSupported
		}
		if placeholderDOM(x) {
			// Modules without diagnostics (DAC, some AOC) report all zeros
			// and -40 dBm: that is no data, not a dark link.
			x.DOM = swtele.DOMUnsupported
			x.Temp, x.Voltage, x.Lanes = swtele.Reading{}, swtele.Reading{}, nil
		}
	}
}

func optics(i *swtele.Interface) *swtele.Transceiver {
	if i.Optics == nil {
		i.Optics = &swtele.Transceiver{}
	}
	return i.Optics
}

func lane(x *swtele.Transceiver, n int) *swtele.Lane {
	for len(x.Lanes) < n {
		x.Lanes = append(x.Lanes, swtele.Lane{Index: len(x.Lanes) + 1})
	}
	return &x.Lanes[n-1]
}

// currentRow reads one row of current values.
func currentRow(x *swtele.Transceiver, mode, text string) bool {
	f := strings.Fields(text)
	switch {
	case mode == "single" && len(f) == 5:
		x.Temp.Value, x.Voltage.Value = clidoc.Float(f[0]), clidoc.Float(f[1])
		l := lane(x, 1)
		l.Bias.Value, l.RxPower.Value, l.TxPower.Value = clidoc.Float(f[2]), clidoc.Float(f[3]), clidoc.Float(f[4])
	case mode == "module" && len(f) == 2:
		x.Temp.Value, x.Voltage.Value = clidoc.Float(f[0]), clidoc.Float(f[1])
	case mode == "lane" && len(f) == 4:
		n := clidoc.Int(f[0])
		if !n.OK || n.V < 1 || n.V > 16 {
			return false
		}
		l := lane(x, n.V)
		l.Bias.Value, l.RxPower.Value, l.TxPower.Value = clidoc.Float(f[1]), clidoc.Float(f[2]), clidoc.Float(f[3])
	default:
		return false
	}
	return true
}

// thresholdRow applies one High/Low row (Temp, Voltage, Bias, RX, TX) to
// every lane. Alarm thresholds fill the alarm limits, warning ones the
// warning limits; user-set power thresholds override the RX/TX alarms.
func thresholdRow(x *swtele.Transceiver, section string, high bool, f []string) {
	if len(f) < 2 {
		return
	}
	set := func(r *swtele.Reading, v swtele.Opt[float64]) {
		switch {
		case strings.HasPrefix(section, "warning") && high:
			r.Th.HighWarn = v
		case strings.HasPrefix(section, "warning"):
			r.Th.LowWarn = v
		case high:
			r.Th.HighAlarm = v
		default:
			r.Th.LowAlarm = v
		}
	}
	if strings.HasPrefix(section, "user-set") {
		// "High/Low <rx> <tx>" power-only thresholds
		if len(f) == 2 {
			for n := range x.Lanes {
				set(&x.Lanes[n].RxPower, clidoc.Float(f[0]))
				set(&x.Lanes[n].TxPower, clidoc.Float(f[1]))
			}
		}
		return
	}
	if len(f) != 5 {
		return
	}
	set(&x.Temp, clidoc.Float(f[0]))
	set(&x.Voltage, clidoc.Float(f[1]))
	if len(x.Lanes) == 0 {
		lane(x, 1)
	}
	for n := range x.Lanes {
		set(&x.Lanes[n].Bias, clidoc.Float(f[2]))
		set(&x.Lanes[n].RxPower, clidoc.Float(f[3]))
		set(&x.Lanes[n].TxPower, clidoc.Float(f[4]))
	}
}

func decodeManuinfo(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(manuHeader.MatchString)
	for _, block := range blocks {
		i := port(st, manuHeader.FindStringSubmatch(block[0].Text)[1])
		x := optics(i)
		doc.Mark(block[0])
		for _, l := range block[1:] {
			if blank(l.Text) {
				continue
			}
			if xcvrAbsent.MatchString(l.Text) {
				doc.Mark(l)
				continue
			}
			label, value, ok := clidoc.Label(l.Text)
			if !ok {
				continue
			}
			switch label {
			case "Manu. Serial Number":
				x.Inventory.Serial = value
			case "Manufacturing Date":
				x.Inventory.Date = value
			case "Vendor Name":
				x.Inventory.Vendor = value
			default:
				continue
			}
			x.Present = true
			doc.Mark(l)
		}
		if x.Inventory.Type == "" && i.Media != "" {
			x.Inventory.Type = i.Media
		}
	}
}

// placeholderDOM reports a module whose every reading is zero, the
// pattern of a transceiver without real diagnostics.
func placeholderDOM(x *swtele.Transceiver) bool {
	if !x.Present || x.Temp.Value.Or(-1) != 0 || x.Voltage.Value.Or(-1) != 0 {
		return false
	}
	for _, l := range x.Lanes {
		if l.Bias.Value.Or(-1) != 0 {
			return false
		}
	}
	return true
}
