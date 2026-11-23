package comware

import (
	"regexp"
	"strings"

	"github.com/gatework/netops/parse"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	// unitHeader matches "Slot 1 CPU 0", "Chassis 1 Slot 0 CPU 0" and the
	// memory form "Slot 1:" / "Chassis 1 Slot 0:".
	cpuHeader  = regexp.MustCompile(`^(?:Chassis (\d+) )?(?:Slot (\d+) )?(?:CPU (\d+) )?(?:Unit )?CPU usage:\s*$`)
	cpuValue   = regexp.MustCompile(`^\s*(\d+)% in last (5 seconds|1 minute|5 minutes)\s*$`)
	memHeader  = regexp.MustCompile(`^(?:Chassis (\d+) )?Slot (\d+)(?: CPU (\d+))?:\s*$`)
	memUnit    = regexp.MustCompile(`^(?:Memory statistics are measured in KB|The statistics about memory is measured in KB):\s*$`)
	memCols    = regexp.MustCompile(`^\s+Total\s+Used\s+Free\s+Shared\s+Buffers\s+Cached\s+FreeRatio\s*$`)
	memRow     = regexp.MustCompile(`^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+([\d.]+)%\s*$`)
	memOther   = regexp.MustCompile(`^(?:-/\+ Buffers/Cache|Swap|LowMem|HighMem):`)
	envTitle   = regexp.MustCompile(`(?i)^\s*System temperature information \(degree centigrade\):\s*$`)
	envChassis = regexp.MustCompile(`^\s*Chassis (\d+):\s*$`)
	envPart    = regexp.MustCompile(`^\s*(?:Fan|Power) temperature information:\s*$`)
	envPartRow = regexp.MustCompile(`^\s*(Fan|Power) (\d+): (\S+)\s*$`)
	versionSW  = regexp.MustCompile(`^H3C Comware Software, Version (\S+), Release (\S+)`)
	versionUp  = regexp.MustCompile(`^(?:H3C )?(\S+) uptime is (.+)$`)
	unitNumber = func(s string) int { return clidoc.Int(s).Or(0) }
)

func decodeCPU(doc *clidoc.Doc, st *state) {
	var cur *swtele.CPULoad
	for _, l := range doc.Lines {
		if m := cpuHeader.FindStringSubmatch(l.Text); m != nil {
			st.dev.System.CPU = append(st.dev.System.CPU, swtele.CPULoad{Unit: swtele.Unit{Chassis: unitNumber(m[1]), Slot: unitNumber(m[2]), CPU: unitNumber(m[3])}})
			cur = &st.dev.System.CPU[len(st.dev.System.CPU)-1]
			doc.Mark(l)
			continue
		}
		m := cpuValue.FindStringSubmatch(l.Text)
		if m == nil || cur == nil {
			continue
		}
		v := clidoc.Float(m[1])
		switch m[2] {
		case "5 seconds":
			cur.Now = v
		case "1 minute":
			cur.Min1 = v
		case "5 minutes":
			cur.Min5 = v
		}
		doc.Mark(l)
	}
}

func decodeMemory(doc *clidoc.Doc, st *state) {
	unit := swtele.Unit{}
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case memUnit.MatchString(text), memCols.MatchString(text), memOther.MatchString(text):
		case memHeader.MatchString(text):
			m := memHeader.FindStringSubmatch(text)
			unit = swtele.Unit{Chassis: unitNumber(m[1]), Slot: unitNumber(m[2]), CPU: unitNumber(m[3])}
		case memRow.MatchString(text):
			m := memRow.FindStringSubmatch(text)
			kb := func(s string) swtele.Opt[uint64] {
				v := clidoc.Uint(s)
				v.V *= 1024
				return v
			}
			st.dev.System.Memory = append(st.dev.System.Memory, swtele.MemoryUsage{
				Unit: unit, Total: kb(m[1]), Used: kb(m[2]), Free: kb(m[3]), FreeRatio: clidoc.Float(m[4]),
			})
		default:
			continue
		}
		doc.Mark(l)
	}
}

// envLabels are the header labels of the temperature table, in order;
// Chassis is optional and the limit labels may carry a "Limit" suffix.
func decodeEnvironment(doc *clidoc.Doc, st *state) {
	var cols parse.Columns
	chassis, hotspot, part := false, false, 0
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), envTitle.MatchString(text), clidoc.Rule(text), envPart.MatchString(text):
			doc.Mark(l)
			continue
		case envChassis.MatchString(text):
			part = clidoc.Int(envChassis.FindStringSubmatch(text)[1]).Or(0)
			doc.Mark(l)
			continue
		case envPartRow.MatchString(text):
			m := envPartRow.FindStringSubmatch(text)
			st.dev.System.Sensors = append(st.dev.System.Sensors, swtele.Sensor{
				Unit: swtele.Unit{Chassis: part}, Name: strings.ToLower(m[1]) + " " + m[2], Value: clidoc.Float(m[3]),
			})
			doc.Mark(l)
			continue
		case strings.Contains(text, "Temperature") && strings.Contains(text, "Slot") && (strings.Contains(text, "Sensor") || strings.Contains(text, "Hotspot")):
			chassis = strings.Contains(text, "Chassis")
			hotspot = strings.Contains(text, "Hotspot")
			labels := []string{"Slot", "Sensor", "Temperature", "Lower", "Warning", "Alarm", "Shutdown"}
			if hotspot {
				name := "Name"
				if strings.Contains(text, "Sensor") {
					name = "Sensor"
				}
				labels = []string{"Slot", "Hotspot", name, "Temperature", "Lower", "Warning", "Alarm", "Shutdown"}
			}
			if chassis {
				labels = append([]string{"Chassis"}, labels...)
			}
			c, ok := parse.HeaderColumns(text, labels...)
			if !ok {
				continue
			}
			cols = c
			doc.Mark(l)
			continue
		case cols.Len() == 0:
			continue
		}
		cells := cols.Cells(text)
		if chassis {
			cells = cells[1:]
		}
		if hotspot {
			cells = append([]string{cells[0], cells[1] + " " + cells[2]}, cells[3:]...)
		}
		slot := clidoc.Int(cells[0])
		if !slot.OK {
			continue
		}
		s := swtele.Sensor{Unit: swtele.Unit{Slot: slot.V}, Name: strings.Join(strings.Fields(cells[1]), " "),
			Value: clidoc.Float(cells[2]), Lower: clidoc.Float(cells[3]), Warning: clidoc.Float(cells[4]),
			Alarm: clidoc.Float(cells[5]), Shutdown: clidoc.Float(cells[6])}
		if chassis {
			s.Unit.Chassis = clidoc.Int(cols.Cells(text)[0]).Or(0)
		}
		st.dev.System.Sensors = append(st.dev.System.Sensors, s)
		doc.Mark(l)
	}
}

func decodeVersion(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		text := strings.TrimSpace(l.Text)
		if m := versionSW.FindStringSubmatch(text); m != nil {
			st.dev.System.Version = m[1] + " " + m[2]
			doc.Mark(l)
			continue
		}
		if m := versionUp.FindStringSubmatch(text); m != nil {
			st.dev.System.Model = m[1]
			st.dev.System.Uptime = clidoc.Duration(m[2])
			doc.Mark(l)
			continue
		}
		// Board and copyright details carry no ledger value.
		doc.Mark(l)
	}
}
