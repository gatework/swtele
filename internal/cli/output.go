package cli

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/report"
	"github.com/gatework/netops/term"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/internal/bootstrap"
	"github.com/gatework/swtele/internal/workflow"
	"github.com/gatework/swtele/query"
)

// outFlags are the output options every listing command takes.
type outFlags struct {
	format string
	sort   string
	desc   bool
	limit  int
}

func (o *outFlags) add(cmd *cobra.Command, limit int) {
	cmd.Flags().StringVar(&o.format, "format", "table", flagFormat)
	cmd.Flags().StringVar(&o.sort, "sort", "", flagSort)
	cmd.Flags().BoolVar(&o.desc, "desc-order", false, flagDescOrder)
	cmd.Flags().IntVar(&o.limit, "limit", limit, flagLimit)
}

var errFormat = errors.New("cli: unknown format")

// emit renders t in the chosen format. data is what JSON prints (rows of
// the model, English enums); notes follow a table.
func (a *app) emit(o *outFlags, title string, t *report.Table, data any, notes ...string) error {
	format := o.format
	if a.json {
		format = "json"
	}
	if o.sort != "" {
		if err := sortTable(t, o.sort, o.desc); err != nil {
			return err
		}
	}
	shown := t
	if o.limit > 0 && len(t.Rows) > o.limit && format != "json" {
		shown = &report.Table{Columns: t.Columns, Rows: t.Rows[:o.limit]}
	}
	switch format {
	case "json":
		return term.WriteJSON(a.out(), data)
	case "csv":
		return report.CSV(a.out(), shown)
	case "markdown", "md":
		doc := report.Document{Title: title, Sections: []report.Section{{Title: title, Table: shown, Text: notes}}}
		return report.Markdown(a.out(), doc)
	case "table", "":
		if len(t.Rows) == 0 {
			fmt.Fprintln(a.out(), "没有符合条件的"+title)
			for _, n := range notes {
				fmt.Fprintln(a.out(), n)
			}
			return nil
		}
		tt := term.NewTable(t.Columns...)
		for _, r := range shown.Rows {
			tt.Add(r...)
		}
		if _, err := tt.Render(a.out(), 0); err != nil {
			return err
		}
		if len(shown.Rows) < len(t.Rows) {
			fmt.Fprintf(a.out(), "……另有 %d 行未显示（--limit 0 显示全部）\n", len(t.Rows)-len(shown.Rows))
		}
		for _, n := range notes {
			fmt.Fprintln(a.out(), n)
		}
		return nil
	}
	return fmt.Errorf("%w: %s（可选 table、json、csv、markdown）", errFormat, format)
}

// sortTable orders rows by the named column, numerically when the cells
// are numbers ("12.5%", "3 天前" sort by their leading number).
func sortTable(t *report.Table, column string, desc bool) error {
	col := slices.Index(t.Columns, column)
	if col < 0 {
		return fmt.Errorf("没有名为 %q 的列（可选：%s）", column, strings.Join(t.Columns, "、"))
	}
	num := func(s string) (float64, bool) {
		end := 0
		for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.' || s[end] == '-' && end == 0) {
			end++
		}
		v, err := strconv.ParseFloat(s[:end], 64)
		return v, err == nil
	}
	slices.SortStableFunc(t.Rows, func(x, y []string) int {
		a, b := cell(x, col), cell(y, col)
		r := cmp.Compare(a, b)
		if na, ok := num(a); ok {
			if nb, ok := num(b); ok {
				r = cmp.Compare(na, nb)
			}
		}
		if desc {
			return -r
		}
		return r
	})
	return nil
}

func cell(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

// session is one command's view of the ledger: the batch, the selected
// devices and the query context.
type session struct {
	v    *workflow.View
	r    *bootstrap.Resources
	clk  clock
	devs []*swtele.Device
	q    query.Context
	// selected is true when selectors narrowed the fleet.
	selected bool
}

// session opens the batch and selects devices with the netops selector
// expressions of args (all devices without one).
func (a *app) session(cmd *cobra.Command, args []string, withPrev bool) (*session, error) {
	v, r, err := a.view(cmd.Context(), withPrev)
	if err != nil {
		return nil, err
	}
	sel, err := device.ParseSelector(args...)
	if err != nil {
		return nil, fmt.Errorf("无效的设备选择器：%w", err)
	}
	s := &session{v: v, r: r, clk: clock{loc: r.Location}, devs: v.Ledger.Select(sel), selected: len(args) > 0,
		q: query.Context{Ledger: v.Ledger, Graph: v.Graph, Prev: v.Prev}}
	if len(s.devs) == 0 {
		return nil, fmt.Errorf("台账中没有设备匹配：%s", strings.Join(args, " "))
	}
	if err := a.applyRefresh(cmd, s, cmd.Flags().Args()); err != nil {
		return nil, err
	}
	return s, nil
}

// dataNote tells which batch and observation time a result comes from.
func (s *session) dataNote() string {
	first, last := time.Time{}, time.Time{}
	for _, d := range s.devs {
		if first.IsZero() || d.Observed.Before(first) {
			first = d.Observed
		}
		if d.Observed.After(last) {
			last = d.Observed
		}
	}
	at := s.clk.time(first)
	if last.Sub(first) > time.Minute {
		at += " ～ " + s.clk.time(last)
	}
	return fmt.Sprintf("数据：批次 %s，采集于 %s（%s）", s.v.Ledger.Batch, at, s.clk.zone())
}

// matched is the "匹配 N / 共 M" footer.
func matched(n, total int, what string) string {
	return fmt.Sprintf("匹配 %d / 共 %d %s", n, total, what)
}

// parseAge parses "30d", "12h", "90m".
func parseAge(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, fmt.Errorf("无效的时长 %q（例如 30d、12h）", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("无效的时长 %q（例如 30d、12h）", s)
	}
	return v, nil
}

// parseSpeed parses "1G", "10G", "100M".
func parseSpeed(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	mult := map[byte]float64{'K': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12}
	u := strings.ToUpper(strings.TrimSuffix(strings.ToUpper(s), "B"))
	m, ok := mult[u[len(u)-1]]
	if !ok {
		return 0, fmt.Errorf("无效的速率 %q（例如 1G、100M）", s)
	}
	v, err := strconv.ParseFloat(u[:len(u)-1], 64)
	if err != nil {
		return 0, fmt.Errorf("无效的速率 %q（例如 1G、100M）", s)
	}
	return uint64(v * m), nil
}
