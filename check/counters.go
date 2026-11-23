package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/gatework/netops/assess"

	"github.com/gatework/swtele"
)

// errorCounters are the inbound error counters a growth check watches.
var errorCounters = []struct {
	name string
	get  func(*swtele.Interface) swtele.Opt[uint64]
}{
	{"CRC", func(i *swtele.Interface) swtele.Opt[uint64] { return i.Counters.CRC }},
	{"input_errors", func(i *swtele.Interface) swtele.Opt[uint64] { return i.Counters.In.Errors }},
	{"giants", func(i *swtele.Interface) swtele.Opt[uint64] { return i.Counters.Giants }},
	{"runts", func(i *swtele.Interface) swtele.Opt[uint64] { return i.Counters.Runts }},
	{"output_errors", func(i *swtele.Interface) swtele.Opt[uint64] { return i.Counters.Out.Errors }},
}

func counterRules() []rule {
	return []rule{
		assess.Check(assess.Meta{
			ID: "counters.error_growth", Title: "端口错包持续增长", Severity: assess.SeverityHigh, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimCounters, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Integer("min_delta", 10), assess.Number("min_ratio", 1e-6)},
		}, errorGrowth),
		assess.Check(assess.Meta{
			ID: "counters.error_history", Title: "端口历史错包累计较多", Severity: assess.SeverityLow, Category: assess.CategoryRuntime,
			Requires: dims(swtele.DimCounters, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Integer("min_errors", 1000), assess.Number("min_ratio", 1e-5)},
		}, errorHistory),
		assess.Check(assess.Meta{
			ID: "counters.discard_growth", Title: "端口出方向丢包增长（拥塞）", Severity: assess.SeverityMedium, Category: assess.CategoryCapacity,
			Requires: dims(swtele.DimCounters, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Integer("min_delta", 1000)},
		}, discardGrowth),
		assess.Check(assess.Meta{
			ID: "capacity.utilization", Title: "端口利用率过高", Severity: assess.SeverityMedium, Category: assess.CategoryCapacity,
			Requires: dims(swtele.DimRates, swtele.DimInterfaces),
			Params:   []assess.Param{assess.Number("percent", 80)},
		}, utilization),
	}
}

// delta returns now-was, and false when the counter went backwards (the
// counters were cleared or the device restarted) or either is missing.
func delta(now, was swtele.Opt[uint64]) (uint64, bool) {
	if !now.OK || !was.OK || now.V < was.V {
		return 0, false
	}
	return now.V - was.V, true
}

func errorGrowth(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if t.Prev == nil {
		return nil
	}
	minDelta, minRatio := uint64(max(in.Params.Integer("min_delta"), 1)), in.Params.Number("min_ratio")
	elapsed := t.Elapsed()
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		p := prevInterface(t, i.Name)
		if p == nil || i.Kind != swtele.KindPhysical {
			continue
		}
		pkts, okPkts := delta(i.Counters.In.Packets, p.Counters.In.Packets)
		var grew []string
		for _, c := range errorCounters {
			d, ok := delta(c.get(i), c.get(p))
			if !ok || d < minDelta {
				continue
			}
			if okPkts && pkts > 0 && float64(d)/float64(pkts) < minRatio {
				continue
			}
			grew = append(grew, fmt.Sprintf("%s +%d", c.name, d))
		}
		if len(grew) == 0 {
			continue
		}
		f := finding(t, portSubject(t.Device, i.Name), "错包增长",
			fmt.Sprintf("%s 内：%s", elapsed.Round(time.Minute), strings.Join(grew, "，")), field("elapsed", elapsed.Round(time.Second)))
		f.Remediation = &assess.Remediation{Summary: "CRC 增长多为线缆、光模块或光纤问题：对照 optics 结果与对端端口逐段排查；giants 多为 MTU 不一致", Manual: true}
		out = append(out, f)
	}
	return out
}

func errorHistory(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	minErrors, minRatio := uint64(in.Params.Integer("min_errors")), in.Params.Number("min_ratio")
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		if i.Kind != swtele.KindPhysical {
			continue
		}
		crc, errs := i.Counters.CRC.Or(0), i.Counters.In.Errors.Or(0)
		total := max(crc, errs)
		pkts := i.Counters.In.Packets.Or(0)
		if total < minErrors || pkts > 0 && float64(total)/float64(pkts) < minRatio {
			continue
		}
		out = append(out, finding(t, portSubject(t.Device, i.Name), "历史错包累计",
			fmt.Sprintf("自上次清零累计 CRC %d、输入错误 %d（输入包 %d）", crc, errs, pkts),
			field("crc", crc), field("input_errors", errs)))
	}
	return out
}

func discardGrowth(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	if t.Prev == nil {
		return nil
	}
	minDelta := uint64(in.Params.Integer("min_delta"))
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		p := prevInterface(t, i.Name)
		if p == nil {
			continue
		}
		if d, ok := delta(i.Counters.Out.Discards, p.Counters.Out.Discards); ok && d >= minDelta {
			out = append(out, finding(t, portSubject(t.Device, i.Name), "出方向丢包增长",
				fmt.Sprintf("%s 内丢弃 %d 个报文", t.Elapsed().Round(time.Minute), d), field("discards", d)))
		}
	}
	return out
}

func utilization(in assess.Input[*Target]) []assess.Finding {
	t := in.Model
	limit := in.Params.Number("percent")
	var out []assess.Finding
	for _, i := range t.Device.Interfaces.All() {
		speed, ok := i.Speed.Get()
		if !ok || speed == 0 || !i.Up() {
			continue
		}
		for dir, r := range map[string]swtele.Opt[float64]{"入": i.Rates.InBps, "出": i.Rates.OutBps} {
			if !r.OK {
				continue
			}
			if pct := r.V * 100 / float64(speed); pct >= limit {
				out = append(out, finding(t, portSubject(t.Device, i.Name), "利用率过高",
					fmt.Sprintf("%s方向 %.1f%%（%s 平均）", dir, pct, i.Rates.Window), field("percent", round(pct)), field("direction", dir)))
			}
		}
	}
	return out
}
