package check

import (
	"fmt"
	"math"
	"strings"

	"github.com/gatework/netops/assess"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/topology"
)

func opticsRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "optics.rx_power", Title: "光模块收光越限", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimOptics, swtele.DimInterfaces),
		}, rxPower),
		assess.Check(assess.Meta{
			ID: "optics.module", Title: "端口 up 时光模块温度、电压、偏置或发光越限", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimOptics),
		}, moduleHealth),
		assess.Check(assess.Meta{
			ID: "optics.rx_margin", Title: "光模块收光余量不足", Severity: assess.SeverityLow, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimOptics, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Number("margin_db", 2)},
		}, rxMargin),
		assess.Check(assess.Meta{
			ID: "optics.lane_imbalance", Title: "多通道光模块各通道收光不均", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimOptics, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Number("spread_db", 3)},
		}, laneImbalance),
		assess.Check(assess.Meta{
			ID: "optics.link_loss", Title: "光链路衰耗过大", Severity: assess.SeverityMedium, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimOptics, swtele.DimNeighbors),
			Params:   []assess.Param{assess.Number("multimode_db", 3), assess.Number("singlemode_db", 10)},
		}, linkLoss),
		assess.Check(assess.Meta{
			ID: "optics.swapped", Title: "光模块已更换", Severity: assess.SeverityInfo, Category: assess.CategoryDrift,
			Requires: dims(swtele.DimOpticsInv),
		}, swapped),
	}
}

// rxPower: an up link receiving below its alarm or warning threshold, or
// no light at all.
func rxPower(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, i := range physicalUp(t.Device) {
		if i.Optics == nil || !i.Optics.Present {
			continue
		}
		for _, l := range i.Optics.Lanes {
			lvl := l.RxPower.Level()
			if l.RxPower.Dark() {
				lvl = swtele.LevelAlarm
			}
			if lvl != swtele.LevelAlarm && lvl != swtele.LevelWarn {
				continue
			}
			dir := "偏低"
			if hi, ok := l.RxPower.Th.HighWarn.Get(); ok && l.RxPower.Value.V > hi {
				dir = "偏高（过载，短距链路宜加衰减器或换模块）"
			}
			f := finding(t, portSubject(t.Device, i.Name), "端口 up 但收光越限",
				fmt.Sprintf("通道 %d 收光 %.2f dBm %s（%s）", l.Index, l.RxPower.Value.V, dir, levelName(lvl)),
				field("rx_dbm", l.RxPower.Value.V), field("level", lvl), field("lane", l.Index))
			f.Actual = fmt.Sprintf("%.2f dBm", l.RxPower.Value.V)
			if lo, ok := l.RxPower.Th.LowWarn.Get(); ok {
				f.Expected = fmt.Sprintf(">= %.2f dBm", lo)
			}
			if lvl == swtele.LevelWarn {
				f.Severity = assess.SeverityMedium
			}
			f.Remediation = &assess.Remediation{Summary: "清洁光纤端面、检查跳线与对端发光，必要时更换模块", Manual: true}
			out = append(out, f)
		}
	}
	return out
}

func moduleHealth(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	// A down port's module does not transmit or receive; its readings say
	// nothing about the link, so only up ports are graded.
	for _, i := range physicalUp(t.Device) {
		x := i.Optics
		if x == nil || !x.Present {
			continue
		}
		check := func(what string, r swtele.Reading, unit string) {
			if lvl := r.Level(); lvl == swtele.LevelWarn || lvl == swtele.LevelAlarm {
				out = append(out, finding(t, portSubject(t.Device, i.Name), what+"越限",
					fmt.Sprintf("%s %.2f %s（%s）", what, r.Value.V, unit, levelName(lvl)), field("level", lvl)))
			}
		}
		check("模块温度", x.Temp, "°C")
		check("供电电压", x.Voltage, "V")
		for _, l := range x.Lanes {
			check(fmt.Sprintf("通道 %d 偏置电流", l.Index), l.Bias, "mA")
			check(fmt.Sprintf("通道 %d 发光功率", l.Index), l.TxPower, "dBm")
		}
	}
	return out
}

func rxMargin(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	limit := in.Params.Number("margin_db")
	var out []assess.Finding
	for _, i := range physicalUp(t.Device) {
		if i.Optics == nil {
			continue
		}
		for _, l := range i.Optics.Lanes {
			if l.RxPower.Level() != swtele.LevelNormal || l.RxPower.Dark() {
				continue // rxPower reports it
			}
			lo := l.RxPower.Th.LowWarn
			if !lo.OK {
				lo = l.RxPower.Th.LowAlarm
			}
			if !lo.OK || !l.RxPower.Value.OK {
				continue
			}
			if m := l.RxPower.Value.V - lo.V; m < limit {
				out = append(out, finding(t, portSubject(t.Device, i.Name), "收光接近下限",
					fmt.Sprintf("通道 %d 收光 %.2f dBm，距下限 %.2f dB", l.Index, l.RxPower.Value.V, m), field("margin_db", round(m))))
			}
		}
	}
	return out
}

func laneImbalance(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	spread := in.Params.Number("spread_db")
	var out []assess.Finding
	for _, i := range physicalUp(t.Device) {
		if i.Optics == nil || len(i.Optics.Lanes) < 2 {
			continue
		}
		lo, hi := math.Inf(1), math.Inf(-1)
		for _, l := range i.Optics.Lanes {
			if v, ok := l.RxPower.Value.Get(); ok {
				lo, hi = min(lo, v), max(hi, v)
			}
		}
		if hi-lo > spread {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "通道收光差异过大",
				fmt.Sprintf("最强 %.2f dBm，最弱 %.2f dBm，相差 %.2f dB", hi, lo, hi-lo), field("spread_db", round(hi-lo))))
		}
	}
	return out
}

// linkLoss estimates each direction of a confirmed link: the far end's
// transmit power minus the local receive power.
func linkLoss(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	mm, sm := in.Params.Number("multimode_db"), in.Params.Number("singlemode_db")
	var out []assess.Finding
	for _, link := range t.Graph.LinksOf(t.Device) {
		if link.State != topology.Confirmed || link.B.Device == nil {
			continue
		}
		local, remote := t.Device.Interfaces.Get(link.A.Port), link.B.Device.Interfaces.Get(link.B.Port)
		if local == nil || remote == nil || local.Optics == nil || remote.Optics == nil || !local.Up() || !remote.Up() {
			continue
		}
		rx, tx := firstLane(local.Optics).RxPower.Value, firstLane(remote.Optics).TxPower.Value
		if !rx.OK || !tx.OK || rx.V <= swtele.NoLight || tx.V <= swtele.NoLight {
			continue
		}
		budget := sm
		if multimode(local) || multimode(remote) {
			budget = mm
		}
		if loss := tx.V - rx.V; loss > budget {
			f := finding(t, portSubject(t.Device, local.Name), "光链路衰耗过大",
				fmt.Sprintf("对端 %s %s 发光 %.2f dBm，本端收光 %.2f dBm，衰耗 %.2f dB", link.B.Device.Name(), remote.Name, tx.V, rx.V, loss),
				field("loss_db", round(loss)), field("peer", link.B.Device.Name()), field("peer_port", remote.Name))
			f.Remediation = &assess.Remediation{Summary: "检查光纤、跳线、配线架与熔接点；确认两端模块类型与波长一致", Manual: true}
			out = append(out, f)
		}
	}
	return out
}

func firstLane(x *swtele.Transceiver) swtele.Lane {
	if len(x.Lanes) == 0 {
		return swtele.Lane{}
	}
	return x.Lanes[0]
}

func swapped(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		p := prevInterface(t, i.Name)
		if p == nil || i.Optics == nil || p.Optics == nil {
			continue
		}
		now, was := i.Optics.Inventory.Serial, p.Optics.Inventory.Serial
		if now != "" && was != "" && now != was {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "光模块序列号变化",
				fmt.Sprintf("%s → %s", was, now), field("serial", now), field("previous", was)))
		}
	}
	return out
}

func round(v float64) float64 { return math.Round(v*100) / 100 }

// multimode reports a short-reach multimode module (SR, SX), whose links
// lose little: a few dB already points at a dirty or bad connector.
func multimode(i *swtele.Interface) bool {
	text := strings.ToUpper(i.Media + " " + i.Optics.Inventory.Type + " " + i.Optics.Inventory.ProductID)
	for _, k := range []string{"SR", "SX", "MM", "MULTIMODE", "OM3", "OM4"} {
		if strings.Contains(text, k) {
			return true
		}
	}
	return false
}

func levelName(l swtele.Level) string {
	if l == swtele.LevelAlarm {
		return "告警"
	}
	return "预警"
}
