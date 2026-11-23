package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/internal/bootstrap"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/locate"
	"github.com/gatework/swtele/query"
)

// maxRefresh bounds a refresh from an analysis command; a whole-fleet
// collection is swtele collect.
const maxRefresh = 50

// refreshSpec is what an analysis command collects again on --refresh:
// the dimensions it reads, and the devices beyond the selection its
// answer depends on.
type refreshSpec struct {
	dims    []evidence.Dimension
	related func(s *session, args []string) []*swtele.Device
	on      bool
	maxAge  string
}

// Dimension sets of the analyses.
var (
	dimsAll      []evidence.Dimension // every dimension of the profile
	dimsPorts    = []evidence.Dimension{swtele.DimInterfaces, swtele.DimCounters, swtele.DimRates, swtele.DimOptics, swtele.DimNeighbors, swtele.DimMAC, swtele.DimAggregates}
	dimsErrors   = []evidence.Dimension{swtele.DimInterfaces, swtele.DimCounters, swtele.DimRates}
	dimsOptics   = []evidence.Dimension{swtele.DimInterfaces, swtele.DimOptics, swtele.DimOpticsInv}
	dimsTopology = []evidence.Dimension{swtele.DimInterfaces, swtele.DimNeighbors, swtele.DimAggregates, swtele.DimStack}
	dimsLocate   = []evidence.Dimension{swtele.DimInterfaces, swtele.DimNeighbors, swtele.DimAggregates, swtele.DimARP, swtele.DimMAC, swtele.DimAddresses}
	dimsFlap     = []evidence.Dimension{swtele.DimInterfaces, swtele.DimFlap, swtele.DimLogs}
	dimsHealth   = []evidence.Dimension{swtele.DimSystem, swtele.DimCPU, swtele.DimMemory, swtele.DimEnvironment, swtele.DimStack, swtele.DimMAD, swtele.DimAggregates, swtele.DimOSPF, swtele.DimBGP, swtele.DimSTP}
)

// refreshable adds --refresh and --max-age to cmd.
func (a *app) refreshable(cmd *cobra.Command, dims []evidence.Dimension, related func(*session, []string) []*swtele.Device) *cobra.Command {
	sp := &refreshSpec{dims: dims, related: related}
	cmd.Flags().BoolVar(&sp.on, "refresh", false, flagRefresh)
	cmd.Flags().StringVar(&sp.maxAge, "max-age", "", flagMaxAge)
	if a.refresh == nil {
		a.refresh = map[*cobra.Command]*refreshSpec{}
	}
	a.refresh[cmd] = sp
	return cmd
}

// neighbors is the related set of topology views: the managed one-hop
// neighbors of the selection.
func neighbors(s *session, _ []string) []*swtele.Device { return expand(s, 1) }

// endpointDevices is the related set of locate and path: the gateways,
// ARP holders and switches the current batch places the queries on.
func endpointDevices(s *session, args []string) []*swtele.Device {
	x := locate.New(s.v.Ledger, s.v.Graph, locate.Options{TrunkLimit: s.r.Config.TrunkLimit})
	var out []*swtele.Device
	add := func(mgmt string) {
		if d := s.v.Ledger.Device(mgmt); d != nil && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, q := range args {
		l := x.Locate(q)
		for _, g := range append(append([]locate.Gateway(nil), l.Gateways...), l.Seen...) {
			add(g.Mgmt)
		}
		for _, p := range append(append([]locate.Port(nil), l.Access...), l.Path...) {
			add(p.Mgmt)
		}
		if l.Device != "" {
			add(l.Device)
		}
	}
	return out
}

// applyRefresh collects the command's dimensions of the session's
// devices again when --refresh or --max-age asks, and moves the session
// to the new batch.
func (a *app) applyRefresh(cmd *cobra.Command, s *session, args []string) error {
	sp := a.refresh[cmd]
	if sp == nil || !sp.on && sp.maxAge == "" {
		return nil
	}
	maxAge, err := parseAge(sp.maxAge)
	if err != nil {
		return err
	}
	sp.on, sp.maxAge = false, "" // once per run
	var targets []*swtele.Device
	if s.selected {
		targets = slices.Clone(s.devs)
	}
	if sp.related != nil {
		for _, d := range sp.related(s, args) {
			if !slices.Contains(targets, d) {
				targets = append(targets, d)
			}
		}
	}
	switch {
	case len(targets) == 0:
		return errors.New("刷新需要用选择器指定设备；全网采集请用 swtele collect")
	case len(targets) > maxRefresh:
		return fmt.Errorf("将刷新 %d 台设备，超过 %d 台上限；请缩小选择范围，或用 swtele collect 全量采集", len(targets), maxRefresh)
	}
	cfg, _, err := a.configs(s.r, "")
	if err != nil {
		return err
	}
	res, nv, err := s.r.App.Refresh(cmd.Context(), s.v, workflow.RefreshRequest{Devices: targets, Dims: sp.dims, MaxAge: maxAge, Configs: cfg})
	switch {
	case errors.Is(err, workflow.ErrNoRefresher):
		return errors.New("刷新需要在线采集：请在配置中设置 inventory，并在 ~/.gatework/.env 提供设备凭据")
	case errors.Is(err, bootstrap.ErrNoCredentials):
		return fmt.Errorf("缺少设备凭据，未连接任何设备：%w", err)
	case err != nil:
		return fmt.Errorf("刷新失败：%w", err)
	}
	a.refreshNote(res, maxAge > 0)
	if nv == s.v {
		return nil
	}
	keep := map[string]bool{}
	for _, d := range s.devs {
		keep[d.Identity.Mgmt.String()] = true
	}
	s.v, s.q = nv, query.Context{Ledger: nv.Ledger, Graph: nv.Graph, Prev: nv.Prev}
	s.devs = slices.DeleteFunc(nv.Ledger.Devices(), func(d *swtele.Device) bool { return !keep[d.Identity.Mgmt.String()] })
	return nil
}

// refreshNote tells on stderr what was collected, so that table output
// on stdout stays clean.
func (a *app) refreshNote(res workflow.RefreshResult, maxAge bool) {
	w := a.env.Stderr
	if res.Batch == "" {
		fmt.Fprintf(w, "数据均在 --max-age 内，未刷新（%d 台）\n", len(res.Fresh))
		return
	}
	line := fmt.Sprintf("已刷新 %d 台（%s），生成批次 %s", len(res.Refreshed), strings.Join(res.Refreshed, "、"), res.Batch)
	if maxAge && len(res.Fresh) > 0 {
		line += fmt.Sprintf("；%d 台在 --max-age 内沿用", len(res.Fresh))
	}
	if len(res.Failed) > 0 {
		line += fmt.Sprintf("；%d 台失败沿用旧数据（%s）", len(res.Failed), strings.Join(res.Failed, "、"))
	}
	fmt.Fprintln(w, line)
}
