package comware

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// ifHeader is the first line of a display interface block: a bare
// interface name at column 0.
var ifHeader = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*\d[\d/:.]*$`)

// lineRule decodes one recognized line shape into the interface.
type lineRule struct {
	re *regexp.Regexp
	do func(m []string, i *swtele.Interface, b *ifBlock)
}

// ifBlock carries the multi-line context of one interface block.
type ifBlock struct {
	st      *state
	section string // counter section: "in", "out", "in_normal", "out_normal", "ipv4"
	vlans   string // which VLAN list a continuation line extends
	lists   map[string]*strings.Builder
}

// ignored are informational lines without ledger value.
var ignored = regexp.MustCompile(`(?i)^(?:` + strings.Join([]string{
	`Loopback is not set`, `Flow-control is (?:not )?enabled`, `(?:Allow|Forbid) jumbo frames to pass`,
	`(?:Known-unicast|Unknown-unicast|Unicast|Broadcast|Multicast|Unknown-multicast) max-(?:ratio|pps): .*`,
	`MDI type: .*`, `Port priority: .*`, `Trunk port encapsulation: .*`, `Peak (?:input|output) rate: .*`,
	`Traffic statistic: .*`, `Physical: .*`, `Internet protocol processing: .*`, `Last hardware down reason: .*`,
	`Packets (?:transmitted|received) of length \[Byte\]:`, `\[.*\]: \d+.*`, `IPv[46] traffic statistics:`,
	`Link speed type is .*`, `Bandwidth: .*`, `Media type is .*loopback (?:is )?not set`, `Port link-type: .*`,
	`Last clearing of counters: .*`, `Current system time:.*`, `Last \d+ seconds? (?:input|output) rate: .*`,
	`(?:Input|Output):\s+\d+ packets, (?:\d+|-) bytes(?:, \d+ drops)?`,
	`Port mode: .*`, `Output queue .*`, `Internet Address is .*`, `Link delay is .*`, `Storm-constrain .*`,
	`IPv6 is .*`, `PVID: .*`, `Encapsulation is .*`, `Promiscuous mode .*`, `Primary-IP .*`, `Tunnel .*`,
}, "|") + `)$`)

var ifRules = []lineRule{
	{regexp.MustCompile(`^Current state: (.+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		s := strings.TrimSpace(m[1])
		switch {
		case strings.HasPrefix(s, "UP"):
			i.Admin, i.Oper = swtele.StateUp, swtele.StateUp
		case strings.HasPrefix(s, "Administratively DOWN"):
			i.Admin, i.Oper, i.DownCause = swtele.StateDown, swtele.StateDown, swtele.CauseAdmin
		case strings.HasPrefix(s, "STP DOWN"):
			i.Admin, i.Oper, i.DownCause = swtele.StateUp, swtele.StateDown, swtele.CauseSTP
		case strings.Contains(s, "Link-Aggregation"):
			i.Admin, i.Oper, i.DownCause = swtele.StateUp, swtele.StateDown, swtele.CauseAggregate
		case strings.HasPrefix(s, "DOWN"):
			i.Admin, i.Oper = swtele.StateUp, swtele.StateDown
		default:
			i.Oper = swtele.StateUnknown
		}
	}},
	{regexp.MustCompile(`^Line protocol (?:state|current state): (.+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.Protocol = upDown(m[1])
	}},
	{regexp.MustCompile(`^IP(?:v[46])? [Pp]acket [Ff]rame [Tt]ype: .*?, [Hh]ardware [Aa]ddress: (\S+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if mac, err := swtele.ParseMAC(m[1]); err == nil {
			i.MAC = mac
		}
	}},
	{regexp.MustCompile(`^Description: ?(.*)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.Desc = strings.TrimSpace(m[1])
	}},
	{regexp.MustCompile(`^(?:Maximum (?:frame length|transmission unit) ?:|The Maximum Frame Length is) (\d+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.MTU = clidoc.Int(m[1])
	}},
	{regexp.MustCompile(`^Internet [Aa]ddress(?: is)?:? ?(\S+?)(?: \(([\w-]+)\))?$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if p, err := netip.ParsePrefix(m[1]); err == nil {
			i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: p, Primary: !strings.EqualFold(m[2], "Sub")})
		}
	}},
	{regexp.MustCompile(`^Media type is ([^,]+?)(?:, [Pp]ort hardware type is (.+))?$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		media(i, m[1], m[2])
	}},
	{regexp.MustCompile(`^Port hardware type is (.+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		media(i, "", m[1])
	}},
	{regexp.MustCompile(`^(\S+?)-speed mode, (\S+?)-duplex mode$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if strings.EqualFold(m[1], "unknown") {
			return
		}
		i.Speed = clidoc.Speed(m[1])
		switch strings.ToLower(m[2]) {
		case "full":
			i.Duplex = swtele.DuplexFull
		case "half":
			i.Duplex = swtele.DuplexHalf
		}
	}},
	{regexp.MustCompile(`^Port link-type: (\w+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		sw := switching(i)
		switch strings.ToLower(m[1]) {
		case "access":
			sw.Mode = swtele.ModeAccess
		case "trunk":
			sw.Mode = swtele.ModeTrunk
		case "hybrid":
			sw.Mode = swtele.ModeHybrid
		}
	}},
	{regexp.MustCompile(`^PVID: (\d+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		switching(i).PVID = clidoc.Int(m[1])
	}},
	{regexp.MustCompile(`^(VLAN [Pp]assing|VLAN [Pp]ermitted|Tagged VLANs|Untagged VLANs) ?: *(.*)$`), func(m []string, _ *swtele.Interface, b *ifBlock) {
		b.vlans = strings.ToLower(m[1])
		b.list(b.vlans).WriteString(m[2])
	}},
	{regexp.MustCompile(`^Last link flapping: (.+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if strings.EqualFold(strings.TrimSpace(m[1]), "never") {
			i.Flap.Never = true
			return
		}
		i.Flap.Since = clidoc.Duration(m[1])
	}},
	{regexp.MustCompile(`^Last time when physical state changed to (up|down):\s*(.*)$`), func(m []string, i *swtele.Interface, b *ifBlock) {
		t := clidoc.Timestamp(m[2], b.st.loc)
		if m[1] == "up" {
			i.Flap.LastUp = t
		} else {
			i.Flap.LastDown = t
		}
	}},
	{regexp.MustCompile(`^Last (\d+) seconds? (input|output):\s+(\d+) packets/sec (\d+) bytes/sec (?:-|[\d.]+)%$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		win, _ := strconv.Atoi(m[1])
		i.Rates.Window = time.Duration(win) * time.Second
		pps, bps := clidoc.Float(m[3]), clidoc.Float(m[4])
		if bps.OK {
			bps.V *= 8
		}
		if m[2] == "input" {
			i.Rates.InPps, i.Rates.InBps = pps, bps
		} else {
			i.Rates.OutPps, i.Rates.OutBps = pps, bps
		}
	}},
	{regexp.MustCompile(`^(Input|Output) \((total|normal)\):\s+(.*)$`), func(m []string, i *swtele.Interface, b *ifBlock) {
		b.section = strings.ToLower(m[1])
		if m[2] == "normal" {
			b.section += "_normal"
		}
		b.counters(i, m[3])
	}},
	{regexp.MustCompile(`^(?i)(Input|Output):\s+(.*(?:errors|runts|underruns).*)$`), func(m []string, i *swtele.Interface, b *ifBlock) {
		b.section = strings.ToLower(m[1]) + "_errors"
		b.counters(i, m[2])
	}},
}

// counterItem is one "<n> <label>" pair of a counter line.
var counterItem = regexp.MustCompile(`(-|\d+)\s*([A-Za-z][A-Za-z ]*[A-Za-z])`)

// counterLine is a line made only of counter items.
var counterLine = regexp.MustCompile(`^(?:(?:-|\d+)\s*[A-Za-z][A-Za-z ]*[A-Za-z]\s*,?\s*)+$`)

func (b *ifBlock) counters(i *swtele.Interface, text string) {
	in := strings.HasPrefix(b.section, "input")
	dir := &i.Counters.Out
	if in {
		dir = &i.Counters.In
	}
	for _, m := range counterItem.FindAllStringSubmatch(text, -1) {
		v := clidoc.Uint(m[1])
		switch label := strings.ToLower(strings.TrimSpace(m[2])); {
		case strings.HasSuffix(b.section, "_normal") || b.section == "ipv4":
			// totals already recorded; normal counts exclude errored frames
		case label == "packets":
			dir.Packets = v
		case label == "bytes":
			dir.Octets = v
		case label == "unicasts":
			dir.Unicast = v
		case label == "broadcasts":
			dir.Bcast = v
		case label == "multicasts":
			dir.Multicst = v
		case label == "pauses":
			dir.Pause = v
		case label == "input errors" || label == "output errors":
			dir.Errors = v
		case label == "runts":
			i.Counters.Runts = v
		case label == "giants":
			i.Counters.Giants = v
		case label == "throttles":
			i.Counters.Throttles = v
		case label == "crc":
			i.Counters.CRC = v
		case label == "frame":
			i.Counters.Frame = v
		case label == "overruns":
			i.Counters.Overruns = v
		case label == "aborts" && in:
			i.Counters.Aborts = v
		case label == "underruns":
			i.Counters.Underruns = v
		case label == "collisions":
			i.Counters.Collisions = v
		case label == "late collisions":
			i.Counters.LateColl = v
		case label == "buffer failures" && !in:
			dir.Discards = v
		}
	}
}

func (b *ifBlock) list(name string) *strings.Builder {
	if b.lists == nil {
		b.lists = map[string]*strings.Builder{}
	}
	if b.lists[name] == nil {
		b.lists[name] = &strings.Builder{}
	}
	return b.lists[name]
}

var vlanContinuation = regexp.MustCompile(`^[\d, ()a-z-]+$`)

func decodeInterface(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(ifHeader.MatchString)
	for _, block := range blocks {
		i := st.dev.Interfaces.Ensure(block[0].Text)
		i.Kind = kindOf(i.Name)
		doc.Mark(block[0])
		b := &ifBlock{st: st}
		for _, l := range block[1:] {
			if decodeIfLine(doc, l, i, b) {
				doc.Mark(l)
			}
		}
		finishVLANs(i, b)
	}
}

func decodeIfLine(_ *clidoc.Doc, l parse.Line, i *swtele.Interface, b *ifBlock) bool {
	text := strings.TrimSpace(l.Text)
	if text == "" {
		return true
	}
	// A VLAN list wraps onto lines indented under its value.
	if b.vlans != "" && strings.HasPrefix(l.Text, "  ") && vlanContinuation.MatchString(text) {
		b.list(b.vlans).WriteString(", " + text)
		return true
	}
	b.vlans = ""
	for _, r := range ifRules {
		if m := r.re.FindStringSubmatch(text); m != nil {
			r.do(m, i, b)
			return true
		}
	}
	if strings.HasPrefix(l.Text, "\t") || counterLine.MatchString(text) {
		if counterLine.MatchString(text) {
			if b.section != "" {
				b.counters(i, text)
			}
			return true
		}
	}
	return ignored.MatchString(text)
}

// finishVLANs turns the collected VLAN lists into sets.
func finishVLANs(i *swtele.Interface, b *ifBlock) {
	if b.lists == nil {
		return
	}
	sw := switching(i)
	for name, text := range b.lists {
		s := vlanSet(text.String())
		switch name {
		case "vlan permitted", "tagged vlans":
			if name == "tagged vlans" && sw.Allowed != nil {
				sw.Allowed.Merge(s)
				continue
			}
			sw.Allowed = s
		case "untagged vlans":
			sw.Untagged = s
			if sw.Allowed == nil {
				sw.Allowed = s.Clone()
			} else {
				sw.Allowed.Merge(s)
			}
		}
	}
}

// vlanSet parses "1(default vlan), 2-998, 1000" and "None".
func vlanSet(text string) *set.Set[int] {
	out := set.New[int]()
	for item := range strings.SplitSeq(text, ",") {
		item = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(item), "(default vlan)"))
		if item == "" || strings.EqualFold(item, "none") {
			continue
		}
		if s, err := set.Parse[int](item); err == nil {
			out.Merge(s)
		}
	}
	return out
}

func switching(i *swtele.Interface) *swtele.Switchport {
	if i.Switching == nil {
		i.Switching = &swtele.Switchport{}
	}
	return i.Switching
}

func media(i *swtele.Interface, kind, hw string) {
	kind, hw = strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(hw)
	switch {
	case strings.Contains(kind, "fiber"):
		i.Fiber = swtele.Some(true)
	case strings.Contains(kind, "twisted"):
		i.Fiber = swtele.Some(false)
	}
	if hw != "" && !strings.EqualFold(hw, "no connector") {
		i.Media = hw
	}
}

func upDown(s string) swtele.State {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(s, "UP"):
		return swtele.StateUp
	case strings.HasPrefix(s, "DOWN"), strings.HasPrefix(s, "ADM"), strings.HasPrefix(s, "*DOWN"):
		return swtele.StateDown
	case strings.HasPrefix(s, "STBY"):
		return swtele.StateStandby
	}
	return swtele.StateUnknown
}

// kindOf classifies a Comware interface by name.
func kindOf(name string) swtele.Kind {
	k := swtele.InterfaceKey(name)
	switch {
	case strings.HasPrefix(k, "bridge-aggregation"), strings.HasPrefix(k, "route-aggregation"):
		return swtele.KindAggregate
	case strings.HasPrefix(k, "vlan"):
		return swtele.KindSVI
	case strings.HasPrefix(k, "loopback"), strings.HasPrefix(k, "inloopback"):
		return swtele.KindLoopback
	case strings.HasPrefix(k, "null"):
		return swtele.KindNull
	case strings.HasPrefix(k, "m-gigabitethernet"):
		return swtele.KindMgmt
	case strings.HasPrefix(k, "register-tunnel"), strings.Contains(k, "tunnel"):
		return swtele.KindTunnel
	}
	return swtele.KindPhysical
}
