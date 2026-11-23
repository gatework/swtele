package swtele

import (
	"regexp"
	"strings"
	"sync"

	"github.com/gatework/netops/iface"
)

// extraFamilies are interface families netops iface does not know yet:
// logical and management interfaces, and Comware abbreviations that
// collide with iface's prefixes. Each maps its spellings to one stem.
// TODO(netops): move into netops iface and drop this table.
var extraFamilies = []struct {
	re   *regexp.Regexp
	stem string
}{
	{regexp.MustCompile(`(?i)^(?:vlan-interface|vlanif|vlan|vl)\s*([0-9].*)$`), "vlan"},
	{regexp.MustCompile(`(?i)^(?:inloopback|inloop)\s*([0-9].*)$`), "inloopback"},
	{regexp.MustCompile(`(?i)^(?:loopback|loop|lo)\s*([0-9].*)$`), "loopback"},
	{regexp.MustCompile(`(?i)^(?:m-gigabitethernet|m-ge|mge)\s*([0-9].*)$`), "m-gigabitethernet"},
	{regexp.MustCompile(`(?i)^(?:smartrate-ethernet|sge)\s*([0-9].*)$`), "smartrate-ethernet"},
	{regexp.MustCompile(`(?i)^(?:register-tunnel|reg)\s*([0-9].*)$`), "register-tunnel"},
	{regexp.MustCompile(`(?i)^(?:null)\s*([0-9].*)$`), "null"},
}

// suffixes are annotations some commands append to a port name: Comware
// marks a LAG reference port "(R)" and chassis IRF ports "(MDC1)".
var suffix = regexp.MustCompile(`\((?:R|MDC\d+)\)$`)

// CleanName strips command annotations and surrounding space from an
// interface name.
func CleanName(name string) string {
	return strings.TrimSpace(suffix.ReplaceAllString(strings.TrimSpace(name), ""))
}

// InterfaceKey returns the vendor-independent comparison key of an
// interface name: every spelling of one interface, abbreviated or long,
// maps to the same key.
func InterfaceKey(name string) string {
	if k, ok := keyCache.Load(name); ok {
		if key, ok := k.(string); ok {
			return key
		}
	}
	k := interfaceKey(name)
	keyCache.Store(name, k)
	return k
}

// keyCache memoizes InterfaceKey: a fleet has a bounded set of interface
// spellings, and analyses compare them millions of times.
var keyCache sync.Map

func interfaceKey(name string) string {
	name = CleanName(name)
	for _, f := range extraFamilies {
		if m := f.re.FindStringSubmatch(name); m != nil {
			return f.stem + strings.ToLower(m[1])
		}
	}
	return iface.Key(name)
}
