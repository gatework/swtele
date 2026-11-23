package nxos

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// Overlay reads an NX-OS running configuration into dev.Config.
func Overlay(ctx context.Context, dev *swtele.Device, text string, at time.Time) error {
	doc, err := config.Parse(ctx, text, config.Cisco(), parse.Limits{})
	if err != nil {
		return fmt.Errorf("nxos: config: %w", err)
	}
	c := &swtele.DeviceConfig{At: at.UTC(), Source: "backup", Ports: map[string]*swtele.PortConfig{}}
	for _, n := range doc.Root().Children {
		globalLine(c, n, "")
	}
	dev.Config = c
	if dev.System.Version == "" {
		dev.System.Version = c.Version
	}
	dev.Observe(swtele.DimConfig, evidence.StatusComplete)
	return nil
}

func globalLine(c *swtele.DeviceConfig, n *parse.Node, vrf string) {
	f := strings.Fields(n.Text)
	if len(f) == 0 {
		return
	}
	switch {
	case f[0] == "version" && len(f) > 1:
		c.Version = f[1]
	case f[0] == "hostname" && len(f) > 1:
		c.Hostname = f[1]
	case f[0] == "interface" && len(f) == 2:
		c.Ports[f[1]] = portConfig(f[1], n)
	case f[0] == "vlan" && len(f) == 2:
		vlans(c, f[1], n)
	case len(f) == 3 && f[0] == "spanning-tree" && f[1] == "mode":
		c.STPMode = f[2]
	case f[0] == "spanning-tree" && len(f) >= 5 && f[1] == "vlan" && f[3] == "priority":
		c.STPPriority = clidoc.Int(f[4])
	case n.Text == "spanning-tree port type edge bpduguard default":
		c.BPDUProtection = swtele.Some(true)
	case n.Text == "feature lldp":
		c.LLDP = swtele.Some(true)
	case len(f) == 3 && f[0] == "vpc" && f[1] == "domain":
		c.VPCDomain = f[2]
	case len(f) == 3 && f[0] == "vrf" && f[1] == "context":
		for _, ch := range n.Children {
			globalLine(c, ch, f[2])
		}
	case len(f) >= 4 && f[0] == "ip" && f[1] == "route":
		if p, err := netip.ParsePrefix(f[2]); err == nil {
			c.Static = append(c.Static, swtele.Route{VRF: vrf, Prefix: p, Proto: swtele.ProtoStatic, NextHops: f[3:4]})
		}
	}
}

func vlans(c *swtele.DeviceConfig, list string, n *parse.Node) {
	s, err := set.Parse[int](list)
	if err != nil {
		return
	}
	name := ""
	for _, ch := range n.ChildrenWithPrefix("name") {
		name = strings.TrimSpace(strings.TrimPrefix(ch.Text, "name"))
	}
	for r := range s.All() {
		for id := r.Min; id <= r.Max && id-r.Min < 4096; id++ {
			c.VLANs = append(c.VLANs, swtele.VLAN{ID: id, Name: name})
		}
	}
}

func portConfig(_ string, n *parse.Node) *swtele.PortConfig {
	// The NX-OS default admin state depends on the release and on
	// "system default switchport shutdown"; the running configuration
	// omits it, so only an explicit line is known.
	p := &swtele.PortConfig{}
	allowed := set.New[int](set.Range[int]{Min: 1, Max: 4094})
	for _, ch := range n.Children {
		f := strings.Fields(ch.Text)
		switch {
		case len(f) == 0:
		case f[0] == "description":
			p.Desc = strings.TrimSpace(strings.TrimPrefix(ch.Text, "description"))
		case ch.Text == "shutdown":
			p.Shutdown = swtele.Some(true)
		case ch.Text == "no shutdown":
			p.Shutdown = swtele.Some(false)
		case ch.Text == "no switchport":
			p.Mode = swtele.ModeRouted
		case ch.Text == "switchport" && p.Mode == swtele.ModeUnknown:
			p.Mode = swtele.ModeAccess
		case len(f) == 3 && f[0] == "switchport" && f[1] == "mode":
			p.Mode = swtele.PortMode(f[2])
		case len(f) == 4 && f[0] == "switchport" && f[1] == "access" && f[2] == "vlan":
			p.PVID = clidoc.Int(f[3])
		case len(f) == 5 && f[0] == "switchport" && f[1] == "trunk" && f[2] == "native" && f[3] == "vlan":
			p.PVID = clidoc.Int(f[4])
		case len(f) >= 5 && f[0] == "switchport" && f[1] == "trunk" && f[2] == "allowed" && f[3] == "vlan":
			allowed = allowedVLANs(allowed, f[4:])
		case len(f) >= 2 && f[0] == "channel-group":
			p.Aggregate = "port-channel" + f[1]
			p.LACP = swtele.Some(len(f) >= 4 && (f[3] == "active" || f[3] == "passive"))
		case len(f) == 3 && f[0] == "vrf" && f[1] == "member":
			p.VRF = f[2]
		case len(f) >= 3 && f[0] == "ip" && f[1] == "address":
			if pr, err := netip.ParsePrefix(f[2]); err == nil {
				p.Addresses = append(p.Addresses, pr)
			}
		case len(f) == 2 && f[0] == "mtu":
			p.MTU = clidoc.Int(f[1])
		case strings.HasPrefix(ch.Text, "spanning-tree port type edge"):
			p.Edge = swtele.Some(true)
		case ch.Text == "spanning-tree bpduguard enable":
			p.BPDUProtection = swtele.Some(true)
		case len(f) == 2 && f[0] == "vpc":
			p.VPC = f[1]
		}
	}
	finishPort(p, allowed)
	return p
}

// finishPort applies the NX-OS defaults: VLAN 1 for access and native,
// every VLAN allowed on a trunk.
func finishPort(p *swtele.PortConfig, allowed *set.Set[int]) {
	switch p.Mode {
	case swtele.ModeAccess:
		if !p.PVID.OK {
			p.PVID = swtele.Some(1)
		}
		p.Allowed = set.New(set.Range[int]{Min: p.PVID.V, Max: p.PVID.V})
	case swtele.ModeTrunk:
		if !p.PVID.OK {
			p.PVID = swtele.Some(1)
		}
		p.Allowed = allowed
	case swtele.ModeUnknown, swtele.ModeHybrid, swtele.ModeRouted:
	}
}

// allowedVLANs applies "1-10,20", "add 30", "remove 5", "all", "none".
func allowedVLANs(cur *set.Set[int], f []string) *set.Set[int] {
	op, list := "", f[0]
	if len(f) >= 2 && (f[0] == "add" || f[0] == "remove" || f[0] == "except") {
		op, list = f[0], f[1]
	}
	var s *set.Set[int]
	switch list {
	case "all":
		s = set.New(set.Range[int]{Min: 1, Max: 4094})
	case "none":
		s = set.New[int]()
	default:
		var err error
		if s, err = set.Parse[int](list); err != nil {
			return cur
		}
	}
	switch op {
	case "add":
		cur.Merge(s)
		return cur
	case "remove":
		return cur.Difference(s)
	case "except":
		return set.New(set.Range[int]{Min: 1, Max: 4094}).Difference(s)
	}
	return s
}
