package nxos

import (
	"regexp"
	"strings"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	xcvrHeader = regexp.MustCompile(`^(Ethernet\S+)\s*$`)
	xcvrKV     = regexp.MustCompile(`^\s+(transceiver|type|name|part number|revision|serial number|nominal bitrate|cisco product id|cisco part number|cisco version id|cisco id|cisco extended id number|cable type|Link length supported.*?) is (.*)$`)
	xcvrLane   = regexp.MustCompile(`^\s*Lane Number:(\d+)`)
	// xcvrRow: "Temperature   28.12 C  [flag]  75.00 C  -5.00 C  70.00 C  0.00 C".
	xcvrRow  = regexp.MustCompile(`^\s*(Temperature|Voltage|Current|Tx Power|Rx Power)\s+(.*)$`)
	xcvrInfo = regexp.MustCompile(`^\s*(?:SFP Detail Diagnostics|QSFP Detail Diagnostics|.*Diagnostics Information|Current\s+Alarms|Measurement\s+High|Transmit Fault Count|Note: \+\+|DOM is not supported|-{10,}|transceiver is (?:not present|not applicable)|Network Lane|Host Lane|.*Lane Number)`)
	xcvrVal  = regexp.MustCompile(`(-?[\d.]+|N/A)\s*(?:C|V|mA|dBm)?`)
)

func decodeTransceiver(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(xcvrHeader.MatchString)
	for _, block := range blocks {
		i := port(st, xcvrHeader.FindStringSubmatch(block[0].Text)[1])
		x := &swtele.Transceiver{}
		doc.Mark(block[0])
		laneNo := 1
		for _, l := range block[1:] {
			text := l.Text
			switch {
			case blank(text):
			case xcvrLane.MatchString(text):
				laneNo = clidoc.Int(xcvrLane.FindStringSubmatch(text)[1]).Or(1)
			case xcvrKV.MatchString(text):
				m := xcvrKV.FindStringSubmatch(text)
				inventory(x, m[1], strings.TrimSpace(m[2]))
			case strings.Contains(text, "DOM is not supported"):
				x.DOM = swtele.DOMUnsupported
			case xcvrRow.MatchString(text):
				m := xcvrRow.FindStringSubmatch(text)
				domRow(x, laneNo, m[1], m[2])
				x.DOM = swtele.DOMSupported
			case xcvrInfo.MatchString(text):
			default:
				continue
			}
			doc.Mark(l)
		}
		if x.Present || x.Inventory.Type != "" {
			i.Optics = x
		} else {
			i.Optics = &swtele.Transceiver{Present: false}
		}
	}
}

func inventory(x *swtele.Transceiver, key, value string) {
	switch key {
	case "transceiver":
		x.Present = value == "present"
	case "type":
		x.Inventory.Type = value
	case "name":
		x.Inventory.Vendor = value
	case "part number":
		x.Inventory.PartNumber = value
	case "serial number":
		x.Inventory.Serial = value
	case "cisco product id":
		x.Inventory.ProductID = value
	}
}

// domRow reads the current value and the four thresholds; a flag token
// (++ + -- -) may sit between the value and the thresholds.
func domRow(x *swtele.Transceiver, laneNo int, name, rest string) {
	var vals []swtele.Opt[float64]
	for _, m := range xcvrVal.FindAllStringSubmatch(rest, -1) {
		vals = append(vals, clidoc.Float(m[1]))
	}
	if len(vals) < 5 {
		for len(vals) < 5 {
			vals = append(vals, swtele.Opt[float64]{})
		}
	}
	r := swtele.Reading{Value: vals[0], Th: swtele.Thresholds{HighAlarm: vals[1], LowAlarm: vals[2], HighWarn: vals[3], LowWarn: vals[4]}}
	switch name {
	case "Temperature":
		x.Temp = r
	case "Voltage":
		x.Voltage = r
	default:
		for len(x.Lanes) < laneNo {
			x.Lanes = append(x.Lanes, swtele.Lane{Index: len(x.Lanes) + 1})
		}
		ln := &x.Lanes[laneNo-1]
		switch name {
		case "Current":
			ln.Bias = r
		case "Tx Power":
			ln.TxPower = r
		case "Rx Power":
			ln.RxPower = r
		}
	}
}
