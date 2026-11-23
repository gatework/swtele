package vendors

// profiles are the commands collected per decoder: every one ran on the
// fleet when the corpus was recorded (2026-11-23), so it is known to be
// accepted. display alarm* and show interface counters rates are left
// out: almost every device rejects them.
var profiles = map[string][]string{
	Comware: {
		"display interface brief", "display transceiver diagnosis interface", "display link-aggregation verbose",
		"display cpu-usage", "display memory", "display environment",
		"display counters rate inbound interface", "display counters rate outbound interface",
		"display counters inbound interface", "display counters outbound interface",
		"display ospf peer", "display arp all", "display mac-address", "display ip interface brief",
		"display interface", "display logbuffer reverse size 50", "display interface brief down",
		"display stp down-port", "display link-flap protection", "display irf",
		"display transceiver manuinfo interface", "display irf topology", "display irf link", "display mad verbose",
		"display lldp neighbor-information list", "display lldp neighbor-information verbose",
	},
	NXOS: {
		"show interface status", "show interface transceiver details", "show port-channel summary",
		"show system resources", "show environment", "show interface counters", "show interface counters errors",
		"show interface", "show ip ospf neighbors vrf all", "show bgp vrf all all summary", "show ip arp vrf all",
		"show mac address-table", "show ip interface brief vrf all", "show interface description",
		"show logging last 100", "show interface status err-disabled", "show lldp neighbors detail",
		"show cdp neighbors detail",
	},
	Hillstone: {
		"show interface", "show transceiver", "show cpu", "show memory", "show statistics-set predef_if_bw current",
		"show arp", "show mac", "show ip vrouter", "show ip ospf neighbor", "show ip bgp summary", "show environment",
		"show logging event severity err", "show lldp neighbor-information",
	},
	// Alteon answers /stats/port N/if per port; the decoder reads the
	// ports from /info/link, so per-port statistics are extras.
	Alteon: {
		"/info/sys/general", "/info/link", "/info/port", "/info/transceiver", "/info/l2/trunk", "/info/l3/ip",
		"/stats/mp/cpu", "/stats/sp/allcpu", "/stats/sp/allmem", "/info/sys/temp", "/info/sys/fan", "/info/sys/ps",
		"/info/l3/arp/dump", "/info/l2/fdb/dump", "/info/l3/ha", "/info/l3/bgp/summary", "/info/l3/ospf/nbr", "/info/sys/log",
	},
	//nolint:misspell // "environmentals" is the PAN-OS command spelling
	PANOS: {
		"show interface all", "show counter interface all", "show lacp aggregate-ethernet all",
		"show running resource-monitor second last 5", "show system resources", "show system environmentals thermal",
		"show routing protocol ospf neighbor", "show routing protocol bgp summary", "show arp all", "show mac all",
		"show transceiver all", "show system environmentals fans", "show system environmentals power",
		"show log system severity greater-than-or-equal high receive_time in last-24-hrs", "show lldp neighbors all",
	},
	IOS: {
		"show interfaces status", "show interfaces transceiver detail", "show etherchannel summary",
		"show processes cpu sorted", "show processes memory sorted", "show environment all", "show interfaces",
		"show ip ospf neighbor", "show ip bgp summary", "show ip arp", "show mac address-table", "show ip interface brief",
		"show interfaces description", "show logging | include -[0-3]-", "show interfaces status err-disabled",
		"show errdisable recovery", "show lldp neighbors detail", "show cdp neighbors detail",
	},
}

// extras are decoded but not yet verified on a device of the fleet; they
// are collected only when enabled.
var extras = map[string][]string{
	Comware: {"display version"},
	NXOS:    {"show version"},
	// show version answered on 2 of 20 firewalls; show lacp aggregateN
	// needs the aggregate numbers first.
	Hillstone: {"show version"},
	IOS:       {"show version"},
}

// Profile returns the commands to collect from a platform, with the
// unverified extras when extra is set. It is empty for an unsupported
// platform.
func Profile(platform string, extra bool) []string {
	name, ok := aliases[platform]
	if !ok {
		return nil
	}
	out := append([]string(nil), profiles[name]...)
	if extra {
		out = append(out, extras[name]...)
	}
	return out
}

// Platforms lists the platform keys with a profile.
func Platforms() []string {
	out := make([]string, 0, len(aliases))
	for k := range aliases {
		out = append(out, k)
	}
	return out
}
