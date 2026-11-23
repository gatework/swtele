package nxos

import (
	"regexp"
	"strings"
	"time"

	"github.com/gatework/netops/parse"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	verSoftware = regexp.MustCompile(`^\s*(?:NXOS|system):\s+version (\S+)`)
	verModel    = regexp.MustCompile(`^\s*cisco (Nexus\S* \S+.*?) (?:[Cc]hassis|\()`)
	verHost     = regexp.MustCompile(`^\s*Device name: (\S+)`)
	verUptime   = regexp.MustCompile(`^Kernel uptime is (.+)$`)
	verSerial   = regexp.MustCompile(`^\s*Processor Board ID (\S+)`)
)

func decodeVersion(doc *clidoc.Doc, st *state) {
	sys := &st.dev.System
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case verSoftware.MatchString(text):
			sys.Version = verSoftware.FindStringSubmatch(text)[1]
		case verModel.MatchString(text):
			sys.Model = verModel.FindStringSubmatch(text)[1]
		case verHost.MatchString(text):
			sys.Hostname = verHost.FindStringSubmatch(text)[1]
		case verUptime.MatchString(text):
			sys.Uptime = clidoc.Duration(verUptime.FindStringSubmatch(text)[1])
		case verSerial.MatchString(text):
			sys.Serial = verSerial.FindStringSubmatch(text)[1]
		}
		// The rest (copyright, BIOS, plugins) carries no ledger value.
		doc.Mark(l)
	}
}

var (
	resLoad   = regexp.MustCompile(`^Load average:`)
	resCPU    = regexp.MustCompile(`^CPU states\s*:\s*([\d.]+)% user,\s*([\d.]+)% kernel,\s*([\d.]+)% idle`)
	resCore   = regexp.MustCompile(`^\s+CPU\d+ states\s*:`)
	resMemory = regexp.MustCompile(`^Memory usage:\s*(\d+)K total,\s*(\d+)K used,\s*(\d+)K free`)
	resInfo   = regexp.MustCompile(`^(?:Processes\s*:|Kernel vmalloc|Kernel buffers|Kernel cached|Current memory status)`)
)

func decodeResources(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), resLoad.MatchString(text), resCore.MatchString(text), resInfo.MatchString(text):
		case resCPU.MatchString(text):
			m := resCPU.FindStringSubmatch(text)
			idle := clidoc.Float(m[3])
			if idle.OK {
				st.dev.System.CPU = append(st.dev.System.CPU, swtele.CPULoad{Unit: swtele.Unit{Slot: 1}, Now: swtele.Some(100 - idle.V)})
			}
		case resMemory.MatchString(text):
			m := resMemory.FindStringSubmatch(text)
			kb := func(s string) swtele.Opt[uint64] {
				v := clidoc.Uint(s)
				v.V *= 1024
				return v
			}
			st.dev.System.Memory = append(st.dev.System.Memory, swtele.MemoryUsage{Unit: swtele.Unit{Slot: 1}, Total: kb(m[1]), Used: kb(m[2]), Free: kb(m[3])})
		default:
			continue
		}
		doc.Mark(l)
	}
}

var (
	envSection = regexp.MustCompile(`^(Fan|Power Supply|Temperature|Power Usage Summary):\s*$`)
	envFanRow  = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)
	envPSURow  = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(\d+) W\s+(\d+) W\s+(\d+) W\s+(.+?)\s*$`)
	envTempRow = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$`)
	envInfo    = regexp.MustCompile(`^(?:Fan Zone Speed|Fan Air Filter|Voltage:|Power\s+Actual|Supply\s+Model|\s+\(Watts|\s+\(Celsius|Module\s+Sensor|Fan\s+Model|Power Supply redundancy|Total |Mode\s|\S.*\s{2,}(?:PS-Redundant|Redundant|Non-Redundant|N/A|[\d.]+ W)\s*$)`)
)

func decodeEnvironment(doc *clidoc.Doc, st *state) {
	sys := &st.dev.System
	section := ""
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case blank(text), clidoc.Rule(text), envInfo.MatchString(text), parseRuleMix(text):
		case envSection.MatchString(text):
			section = envSection.FindStringSubmatch(text)[1]
		case section == "Fan" && envFanRow.MatchString(text):
			m := envFanRow.FindStringSubmatch(text)
			sys.Fans = append(sys.Fans, component(m[1], m[2], m[5]))
		case section == "Power Supply" && envPSURow.MatchString(text):
			m := envPSURow.FindStringSubmatch(text)
			sys.PSUs = append(sys.PSUs, component(m[1], m[2], m[6]))
		case section == "Temperature" && envTempRow.MatchString(text):
			m := envTempRow.FindStringSubmatch(text)
			sys.Sensors = append(sys.Sensors, swtele.Sensor{Unit: swtele.Unit{Slot: clidoc.Int(m[1]).Or(0)}, Name: m[2],
				Alarm: clidoc.Float(m[3]), Warning: clidoc.Float(m[4]), Value: clidoc.Float(m[5])})
		default:
			continue
		}
		doc.Mark(l)
	}
}

// parseRuleMix reports a "-------  ------  ---" column ruler.
func parseRuleMix(s string) bool {
	_, ok := parse.RulerColumns(s, '-')
	return ok
}

func component(id, model, status string) swtele.Component {
	c := swtele.Component{ID: id, Model: model, Status: status}
	if model == "--" {
		c.Model = ""
	}
	s := strings.ToLower(status)
	c.OK = swtele.Some(s == "ok" || s == "good")
	return c
}

var (
	logEntry = regexp.MustCompile(`^(\d{4} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2})(?:\.\d+)? \S+ %([A-Z0-9_]+)(?:-SLOT\d+)?-(\d)-([A-Z0-9_]+): (.*)$`)
	logOther = regexp.MustCompile(`^(?:\d{4} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+ last message repeated \d+ times?|Logging disabled)\s*$`)
	logPort  = regexp.MustCompile(`\b((?:Ethernet|port-channel|Vlan|loopback)\d[\d/]*)\b`)
)

// noise are facilities that record sessions and housekeeping only.
var noise = map[string]bool{"AUTHPRIV": true, "VSHD": true, "DAEMON": true, "USER": true}

func decodeLog(doc *clidoc.Doc, st *state) {
	for _, l := range doc.Lines {
		if logOther.MatchString(l.Text) {
			doc.Mark(l)
			continue
		}
		m := logEntry.FindStringSubmatch(l.Text)
		if m == nil {
			continue
		}
		doc.Mark(l)
		if noise[m[2]] {
			continue
		}
		e := swtele.LogEvent{Module: m[2], Severity: clidoc.Int(m[3]).Or(0), Mnemonic: m[4], Text: m[5]}
		if t, err := time.ParseInLocation("2006 Jan _2 15:04:05", strings.Join(strings.Fields(m[1]), " "), st.loc); err == nil {
			e.At = swtele.Some(t.UTC())
		}
		if p := logPort.FindStringSubmatch(m[5]); p != nil {
			e.Interface = p[1]
		}
		st.dev.Logs = append(st.dev.Logs, e)
	}
}
