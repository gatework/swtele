package nxos

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// ifHeader: "Ethernet1/1 is up", "Ethernet1/14 is down (XCVR not
// inserted)", "Vlan2 is up, line protocol is up, autostate enabled".
var ifHeader = regexp.MustCompile(`^(\S+) is (up|down|admin down|administratively down)(?:\s*\((.*)\))?(?:, line protocol is (up|down))?`)

type ifRule struct {
	re *regexp.Regexp
	do func(m []string, i *swtele.Interface, b *ifBlock)
}

type ifBlock struct {
	section string // "rx", "tx" or ""
	window  time.Duration
}

var ifRules = []ifRule{
	{regexp.MustCompile(`^admin state is (up|down)`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if m[1] == "down" {
			i.Admin, i.DownCause = swtele.StateDown, swtele.CauseAdmin
		} else {
			i.Admin = swtele.StateUp
		}
	}},
	{regexp.MustCompile(`^Belongs to (\S+)`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.Aggregate = longName(m[1])
	}},
	{regexp.MustCompile(`^Hardware(?: is|:) .*?address(?: is|:)\s+([0-9a-fA-F.]{14})`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.MAC, _ = swtele.ParseMAC(m[1])
	}},
	{regexp.MustCompile(`^Description: (.*)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.Desc = strings.TrimSpace(m[1])
	}},
	{regexp.MustCompile(`^Internet Address is (\S+)(?: secondary)?`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if p, err := netip.ParsePrefix(m[1]); err == nil {
			i.Addresses = append(i.Addresses, swtele.IfAddr{Prefix: p, Primary: !strings.Contains(m[0], "secondary")})
		}
	}},
	{regexp.MustCompile(`^MTU (\d+) bytes`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.MTU = clidoc.Int(m[1])
	}},
	{regexp.MustCompile(`^Port mode is (\w+)`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		sw := switching(i)
		switch m[1] {
		case "access":
			sw.Mode = swtele.ModeAccess
		case "trunk":
			sw.Mode = swtele.ModeTrunk
		case "routed":
			sw.Mode = swtele.ModeRouted
		}
	}},
	{regexp.MustCompile(`^(full|half|auto)-duplex, ([^,]+?)(?:, media type is (.*))?$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		switch m[1] {
		case "full":
			i.Duplex = swtele.DuplexFull
		case "half":
			i.Duplex = swtele.DuplexHalf
		}
		if m[2] == "auto-speed" {
			i.AutoSpeed = swtele.Some(true)
		} else {
			i.Speed = clidoc.Speed(strings.ReplaceAll(m[2], " ", ""))
		}
		if m[3] != "" {
			i.Media = strings.TrimSpace(m[3])
		}
	}},
	{regexp.MustCompile(`^Last link flapped (.+)$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		if strings.EqualFold(strings.TrimSpace(m[1]), "never") {
			i.Flap.Never = true
			return
		}
		i.Flap.Since = clidoc.Duration(m[1])
	}},
	{regexp.MustCompile(`^(\d+) interface resets$`), func(m []string, i *swtele.Interface, _ *ifBlock) {
		i.Counters.Resets = clidoc.Uint(m[1])
	}},
	{regexp.MustCompile(`^(\d+) seconds (input|output) rate (\d+) bits/sec, (\d+) packets/sec$`), func(m []string, i *swtele.Interface, b *ifBlock) {
		w := time.Duration(clidoc.Int(m[1]).Or(0)) * time.Second
		if w < b.window {
			return // keep the longest load interval
		}
		b.window = w
		i.Rates.Window = w
		if m[2] == "input" {
			i.Rates.InBps, i.Rates.InPps = clidoc.Float(m[3]), clidoc.Float(m[4])
		} else {
			i.Rates.OutBps, i.Rates.OutPps = clidoc.Float(m[3]), clidoc.Float(m[4])
		}
	}},
	{regexp.MustCompile(`^(?i)(RX|TX)$`), func(m []string, _ *swtele.Interface, b *ifBlock) {
		b.section = strings.ToLower(m[1])
	}},
	{regexp.MustCompile(`^(\d+) minutes? (input|output) rate (\d+) bits/sec, (\d+) packets/sec$`), func(m []string, i *swtele.Interface, b *ifBlock) {
		w := time.Duration(clidoc.Int(m[1]).Or(0)) * time.Minute
		if w < b.window {
			return
		}
		b.window = w
		i.Rates.Window = w
		if m[2] == "input" {
			i.Rates.InBps, i.Rates.InPps = clidoc.Float(m[3]), clidoc.Float(m[4])
		} else {
			i.Rates.OutBps, i.Rates.OutPps = clidoc.Float(m[3]), clidoc.Float(m[4])
		}
	}},
	{regexp.MustCompile(`^vPC Status: .*`), func([]string, *swtele.Interface, *ifBlock) {}},
	{regexp.MustCompile(`^Members in this channel: (.*)$`), func([]string, *swtele.Interface, *ifBlock) {}},
}

// ifIgnored are informational lines without ledger value.
var ifIgnored = regexp.MustCompile(`^(?:` + strings.Join([]string{
	`reliability .*`, `Encapsulation .*`, `Beacon is .*`, `Auto-Negotiation is .*`, `Input flow-control .*`,
	`Auto-mdix is .*`, `Rate mode is .*`, `Switchport monitor is .*`, `EtherType is .*`, `EEE \(efficient-ethernet\).*`,
	`admin fec state .*`, `Last clearing of .*`, `Load-Interval #\d+: .*`, `input rate .* output rate .*`,
	`Keepalive .*`, `ARP type: .*`, `L3 in Switched:`, `L3 out Switched:`, `ucast: .*`, `mcast: .*`,
	`Last link flapped never`, `\d+ seconds input rate .*`, `Hardware(?: is|:) .*`, `admin state is .*`,
	`Dedicated Interface`, `Port-Channel`, `Lacp .*`, `LACP .*`, `Down Reason: .*`, `Belongs to .*`,
	`Active members in this channel: .*`, `Members in this channel: .*`, `minimum links .*`,
	`Last \d+ seconds? .*`, `(?:Rx|Tx) pause .*`, `Rx\s+\d+.*`, `Tx\s+\d+.*`, `Internet Address is .*`,
	`MTU \d+ bytes.*`, `Port mode is .*`, `Auto-Negotiation .*`, `FEC mode is .*`, `Lane .*`,
	`Debounce Time .*`, `Link Down count .*`, `Last link down .*`, `Last link up .*`, `Rx Down .*`,
	`Link Training .*`, `Fec mode is .*`, `\d+ (?:rx|tx) pause`, `.*Mbps, .*Kpps.*`, `.*bps, .*pps.*`,
	`Nve .*`, `nve .*`, `Source-Interface: .*`, `Source Interface: .*`, `Encapsulation: .*`, `VPC Capability: .*`,
	`Local Router MAC: .*`, `Host Learning Mode: .*`, `Source-Interface State: .*`, `Multisite .*`,
	`Interface.*Statistics.*`, `Active connector: .*`, `\d+ out_carrier_errors`, `Configured Media-type: .*`, `L\d Switched:`, `input: .* - output: .*`, `No members`, `Management transceiver: .*`, `In: .*`, `Out: .*`, `\[.*\]`, `.*packets\s+\d+.*bytes.*`,
}, "|") + `)$`)

// counterItem is one "<n> <label>" pair of a counter line.
type counterItem struct{ value, label string }

// counterItems splits "0 runts  0 giants  0 CRC" or "5 input packets 3
// unicast packets" into pairs; ok is false for any other line shape.
func counterItems(text string) ([]counterItem, bool) {
	var out []counterItem
	for tok := range strings.FieldsSeq(text) {
		if clidoc.Uint(tok).OK {
			out = append(out, counterItem{value: tok})
			continue
		}
		if len(out) == 0 || strings.IndexFunc(tok, func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') }) >= 0 {
			return nil, false
		}
		last := &out[len(out)-1]
		last.label = strings.TrimSpace(last.label + " " + tok)
	}
	for _, it := range out {
		if it.label == "" {
			return nil, false
		}
	}
	return out, len(out) > 0
}

func decodeInterface(doc *clidoc.Doc, st *state) {
	_, blocks := doc.Blocks(ifHeader.MatchString)
	for _, block := range blocks {
		m := ifHeader.FindStringSubmatch(block[0].Text)
		i := port(st, m[1])
		switch m[2] {
		case "up":
			i.Oper = swtele.StateUp
		default:
			i.Oper = swtele.StateDown
		}
		if m[4] != "" {
			i.Protocol = upDown(m[4])
		}
		if reason := strings.ToLower(m[3]); reason != "" {
			i.DownCause = downCause(reason)
		}
		doc.Mark(block[0])
		b := &ifBlock{}
		for _, l := range block[1:] {
			if decodeIfLine(l.Text, i, b) {
				doc.Mark(l)
			}
		}
		if i.Admin == swtele.StateUnknown && i.Oper == swtele.StateUp {
			i.Admin = swtele.StateUp
		}
	}
}

func decodeIfLine(raw string, i *swtele.Interface, b *ifBlock) bool {
	text := strings.TrimSpace(raw)
	if text == "" {
		return true
	}
	for _, r := range ifRules {
		if m := r.re.FindStringSubmatch(text); m != nil {
			r.do(m, i, b)
			return true
		}
	}
	if items, ok := counterItems(text); ok {
		rx := b.section == "rx"
		if b.section == "" {
			// mgmt0 prints counters without RX/TX headings
			rx = !strings.Contains(text, "output") && !strings.Contains(text, "collisions")
		}
		counters(i, rx, items)
		return true
	}
	return ifIgnored.MatchString(text)
}

func counters(i *swtele.Interface, rx bool, items []counterItem) {
	dir := &i.Counters.Out
	if rx {
		dir = &i.Counters.In
	}
	for _, it := range items {
		v := clidoc.Uint(it.value)
		switch it.label {
		case "unicast packets":
			dir.Unicast = v
		case "multicast packets":
			dir.Multicst = v
		case "broadcast packets":
			dir.Bcast = v
		case "input packets", "output packets", "packets input", "packets output":
			dir.Packets = v
		case "bytes":
			dir.Octets = v
		case "runts":
			i.Counters.Runts = v
		case "giants":
			i.Counters.Giants = v
		case "CRC":
			i.Counters.CRC = v
		case "no buffer":
			i.Counters.NoBuffer = v
		case "input error", "output error", "input errors", "output errors":
			dir.Errors = v
		case "overrun":
			i.Counters.Overruns = v
		case "underrun":
			if !rx {
				i.Counters.Underruns = v
			}
		case "input discard", "output discard":
			dir.Discards = v
		case "Rx pause", "Tx pause":
			dir.Pause = v
		case "Stomped CRC":
			i.Counters.StompedCRC = v
		case "collision":
			i.Counters.Collisions = v
		case "late collision":
			i.Counters.LateColl = v
		}
	}
}

func downCause(reason string) swtele.DownCause {
	switch {
	case strings.Contains(reason, "administratively"):
		return swtele.CauseAdmin
	case strings.Contains(reason, "xcvr not inserted"), strings.Contains(reason, "sfp not inserted"):
		return swtele.CauseNoXcvr
	case strings.Contains(reason, "link not connected"):
		return swtele.CauseNotConnected
	case strings.Contains(reason, "suspended"), strings.Contains(reason, "no lacp"):
		return swtele.CauseSuspended
	case strings.Contains(reason, "errdisabled"), strings.Contains(reason, "err-disabled"):
		return swtele.CauseErrDisabled
	case strings.Contains(reason, "channel"):
		return swtele.CauseAggregate
	case reason == "":
		return swtele.CauseNone
	}
	return swtele.CauseOther
}

func upDown(s string) swtele.State {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up":
		return swtele.StateUp
	case "down":
		return swtele.StateDown
	}
	return swtele.StateUnknown
}

func switching(i *swtele.Interface) *swtele.Switchport {
	if i.Switching == nil {
		i.Switching = &swtele.Switchport{}
	}
	return i.Switching
}
