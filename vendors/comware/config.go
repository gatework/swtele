package comware

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/set"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

// Overlay reads a Comware configuration (display current-configuration)
// into dev.Config: the intent that drift checks compare with the runtime
// state. It never overwrites runtime facts.
func Overlay(ctx context.Context, dev *swtele.Device, text string, at time.Time) error {
	doc, err := config.Parse(ctx, text, config.Comware(), parse.Limits{})
	if err != nil {
		return fmt.Errorf("comware: config: %w", err)
	}
	c := &swtele.DeviceConfig{At: at.UTC(), Source: "backup", Ports: map[string]*swtele.PortConfig{}, IRFPriority: map[int]int{}}
	for _, n := range doc.Root().Children {
		globalLine(c, n)
	}
	dev.Config = c
	if dev.System.Version == "" {
		dev.System.Version = c.Version
	}
	dev.Observe(swtele.DimConfig, evidence.StatusComplete)
	return nil
}

func globalLine(c *swtele.DeviceConfig, n *parse.Node) {
	f := strings.Fields(n.Text)
	if len(f) == 0 {
		return
	}
	switch {
	case f[0] == "version" && len(f) > 1:
		c.Version = strings.TrimSuffix(strings.Join(f[1:], " "), ",")
	case f[0] == "sysname" && len(f) > 1:
		c.Hostname = f[1]
	case f[0] == "interface" && len(f) == 2:
		c.Ports[f[1]] = portConfig(c, f[1], n)
	case f[0] == "vlan" && len(f) == 2:
		if id := clidoc.Int(f[1]); id.OK {
			v := swtele.VLAN{ID: id.V}
			for _, ch := range n.ChildrenWithPrefix("name") {
				v.Name = strings.TrimSpace(strings.TrimPrefix(ch.Text, "name"))
			}
			c.VLANs = append(c.VLANs, v)
		}
	case n.Text == "stp global enable":
		c.STPEnabled = swtele.Some(true)
	case n.Text == "undo stp global enable":
		c.STPEnabled = swtele.Some(false)
	case len(f) == 3 && f[0] == "stp" && f[1] == "mode":
		c.STPMode = f[2]
	case n.Text == "stp bpdu-protection":
		c.BPDUProtection = swtele.Some(true)
	case f[0] == "stp" && len(f) >= 3 && f[len(f)-2] == "priority" && (len(f) == 3 || f[1] == "instance" && f[2] == "0"):
		c.STPPriority = clidoc.Int(f[len(f)-1])
	case n.Text == "lldp global enable":
		c.LLDP = swtele.Some(true)
	case n.Text == "undo lldp global enable":
		c.LLDP = swtele.Some(false)
	case len(f) == 5 && f[0] == "irf" && f[1] == "member" && f[3] == "priority":
		if id, p := clidoc.Int(f[2]), clidoc.Int(f[4]); id.OK && p.OK {
			c.IRFPriority[id.V] = p.V
		}
	case f[0] == "ip" && len(f) > 1 && f[1] == "route-static":
		if r, ok := staticRoute(f[2:]); ok {
			c.Static = append(c.Static, r)
		}
	}
}

// staticRoute reads "[vpn-instance V] dest mask|len nexthop|interface...".
func staticRoute(f []string) (swtele.Route, bool) {
	r := swtele.Route{Proto: swtele.ProtoStatic}
	if len(f) >= 2 && f[0] == "vpn-instance" {
		r.VRF, f = f[1], f[2:]
	}
	if len(f) < 3 {
		return r, false
	}
	p, ok := prefix(f[0], f[1])
	if !ok {
		return r, false
	}
	r.Prefix = p
	for _, hop := range f[2:] {
		if strings.EqualFold(hop, "preference") || strings.EqualFold(hop, "tag") || strings.EqualFold(hop, "description") {
			break
		}
		r.NextHops = append(r.NextHops, hop)
	}
	return r, true
}

// prefix builds a prefix from an address and a dotted mask or a length.
func prefix(addr, mask string) (netip.Prefix, bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	if n, err := strconv.Atoi(mask); err == nil {
		p, err := a.Prefix(n)
		return p, err == nil
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return netip.Prefix{}, false
	}
	bits := 0
	for _, b := range m.As4() {
		for b&0x80 != 0 {
			bits++
			b <<= 1
		}
	}
	return netip.PrefixFrom(a, bits), true
}

func portConfig(c *swtele.DeviceConfig, name string, n *parse.Node) *swtele.PortConfig {
	p := &swtele.PortConfig{}
	ps := &portState{trunk: set.New[int](set.Range[int]{Min: 1, Max: 1})} // Comware trunks permit VLAN 1 by default
	for _, ch := range n.Children {
		portLine(c, name, p, ps, ch.Text)
	}
	finishPort(name, p, ps)
	return p
}

// portState carries what an interface section accumulates.
type portState struct {
	route bool
	trunk *set.Set[int]
}

func portLine(c *swtele.DeviceConfig, name string, p *swtele.PortConfig, ps *portState, text string) {
	f := strings.Fields(text)
	switch {
	case len(f) == 0:
	case f[0] == "description":
		p.Desc = strings.TrimSpace(strings.TrimPrefix(text, "description"))
	case text == "shutdown":
		p.Shutdown = swtele.Some(true)
	case text == "port link-mode route":
		ps.route = true
	case len(f) == 3 && f[0] == "port" && f[1] == "link-type":
		p.Mode = swtele.PortMode(f[2])
	case len(f) == 4 && f[0] == "port" && f[1] == "access" && f[2] == "vlan":
		p.PVID = clidoc.Int(f[3])
	case len(f) == 5 && f[0] == "port" && (f[1] == "trunk" || f[1] == "hybrid") && f[2] == "pvid":
		p.PVID = clidoc.Int(f[4])
	case len(f) >= 5 && f[0] == "port" && f[1] == "trunk" && f[2] == "permit" && f[3] == "vlan":
		ps.trunk.Merge(vlanWords(f[4:]))
	case len(f) >= 6 && f[0] == "undo" && f[1] == "port" && f[2] == "trunk" && f[3] == "permit":
		ps.trunk = ps.trunk.Difference(vlanWords(f[5:]))
	case len(f) >= 5 && f[0] == "port" && f[1] == "hybrid" && f[2] == "vlan":
		ps.trunk.Merge(vlanWords(f[3:]))
	case len(f) == 4 && f[0] == "port" && f[1] == "link-aggregation" && f[2] == "group":
		p.Aggregate = "Bridge-Aggregation" + f[3]
	case len(f) == 3 && f[0] == "link-aggregation" && f[1] == "mode":
		p.LACP = swtele.Some(f[2] == "dynamic")
	case len(f) == 4 && f[0] == "ip" && f[1] == "binding" && f[2] == "vpn-instance":
		p.VRF = f[3]
	case len(f) >= 4 && f[0] == "ip" && f[1] == "address":
		if pr, ok := prefix(f[2], f[3]); ok {
			p.Addresses = append(p.Addresses, pr)
		}
	case len(f) == 2 && f[0] == "mtu", len(f) == 3 && f[0] == "jumboframe" && f[1] == "enable":
		p.MTU = clidoc.Int(f[len(f)-1])
	case text == "stp edged-port" || text == "stp edged-port enable":
		p.Edge = swtele.Some(true)
	case text == "stp port bpdu-protection enable" || text == "stp bpdu-protection":
		p.BPDUProtection = swtele.Some(true)
	case len(f) >= 3 && f[0] == "mad" && f[1] == "bfd" && f[2] == "enable":
		c.MADBFD = append(c.MADBFD, name)
	}
}

func finishPort(name string, p *swtele.PortConfig, ps *portState) {
	route, trunk := ps.route, ps.trunk
	if !p.Shutdown.OK {
		p.Shutdown = swtele.Some(false) // Comware ports are enabled unless shut down
	}
	physical := kindOf(name) == swtele.KindPhysical || kindOf(name) == swtele.KindAggregate
	switch {
	case route || strings.HasPrefix(name, "Route-Aggregation"):
		p.Mode = swtele.ModeRouted
		if p.Aggregate != "" {
			p.Aggregate = "Route-" + strings.TrimPrefix(p.Aggregate, "Bridge-")
		}
	case !physical:
	case p.Mode == swtele.ModeUnknown:
		p.Mode = swtele.ModeAccess
	}
	switch p.Mode {
	case swtele.ModeAccess:
		if !p.PVID.OK {
			p.PVID = swtele.Some(1)
		}
		p.Allowed = set.New(set.Range[int]{Min: p.PVID.V, Max: p.PVID.V})
	case swtele.ModeTrunk, swtele.ModeHybrid:
		if !p.PVID.OK {
			p.PVID = swtele.Some(1)
		}
		p.Allowed = trunk
	case swtele.ModeUnknown, swtele.ModeRouted:
	}
}

// vlanWords parses "2 to 998 1000 to 4094" and "all".
func vlanWords(f []string) *set.Set[int] {
	out := set.New[int]()
	for i := 0; i < len(f); i++ {
		if f[i] == "all" {
			out.Add(1, 4094)
			continue
		}
		lo := clidoc.Int(f[i])
		if !lo.OK {
			continue
		}
		hi := lo
		if i+2 < len(f) && f[i+1] == "to" {
			if v := clidoc.Int(f[i+2]); v.OK {
				hi = v
				i += 2
			}
		}
		out.Add(lo.V, hi.V)
	}
	return out
}
