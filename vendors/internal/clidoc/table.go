package clidoc

import (
	"strings"

	"github.com/gatework/netops/parse"
)

// Header is one spelling of a table header: the labels, left to right.
type Header []string

// Table is a fixed-width table found in a body.
type Table struct {
	// Variant is the index of the matching header spelling.
	Variant int
	Header  parse.Line
	Rows    []parse.Line
	cols    parse.Columns
}

// FindTable locates the first line at or after from that carries every
// label of one of variants, and collects the rows after it until a line
// for which end returns true (nil ends at the first blank line). It marks
// the header and rows as consumed; the caller marks nothing else for them.
func (d *Doc) FindTable(from int, end func(string) bool, variants ...Header) (t Table, next int, ok bool) {
	if end == nil {
		end = func(s string) bool { return strings.TrimSpace(s) == "" }
	}
	for i := from; i < len(d.Lines); i++ {
		for v, labels := range variants {
			cols, found := parse.HeaderColumns(d.Lines[i].Text, labels...)
			if !found || !startsWithLabel(d.Lines[i].Text, labels[0]) {
				continue
			}
			t = Table{Variant: v, Header: d.Lines[i], cols: cols}
			d.Mark(d.Lines[i])
			j := i + 1
			for ; j < len(d.Lines) && !end(d.Lines[j].Text); j++ {
				t.Rows = append(t.Rows, d.Lines[j])
			}
			return t, j, true
		}
	}
	return Table{}, len(d.Lines), false
}

// startsWithLabel rejects a line where the first label is not the first
// word, so that prose mentioning the labels is not taken for a header.
func startsWithLabel(line, first string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), first)
}

// Cells slices a row by the header offsets.
func (t Table) Cells(row string) []string { return t.cols.Cells(row) }

// Fields splits a row on whitespace into at most n fields; the last field
// keeps the rest of the row. Use it where values may overflow their
// column but only the last column can contain spaces.
func Fields(row string, n int) []string {
	f := strings.Fields(row)
	if len(f) <= n || n <= 0 {
		return f
	}
	rest := row
	for range n - 1 {
		rest = strings.TrimLeft(rest, " \t")
		cut := strings.IndexAny(rest, " \t")
		rest = rest[cut:]
	}
	return append(f[:n-1], strings.TrimSpace(rest))
}

// Rule reports a separator line such as "-----" or "=====".
func Rule(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && strings.Trim(s, "-=+* ") == ""
}

// Label splits "label : value" or "label: value", trimming both.
func Label(s string) (label, value string, ok bool) {
	return parse.SplitLabel(s, ":")
}
