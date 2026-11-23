package clidoc

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"
)

// Issue codes.
const (
	IssueRejected = "command_rejected"
	IssueFailed   = "command_failed"
	IssueMismatch = "count_mismatch"
	IssueValue    = "bad_value"
)

// rejections are the bodies CLIs print for a command they refuse.
var rejections = regexp.MustCompile(`^\s*(?:% ?(?:Unrecognized command|Invalid (?:input|command)|Incomplete command|Too many parameters|Wrong parameter|Ambiguous command)|\^-+unrecognized keyword|Error: unknown command|Unknown command)`)

// menuPrompt matches the menu prompts of Alteon, which change with the
// menu: ">> Standalone ADC - Information#", ">> Port 1 Statistics#".
var menuPrompt = regexp.MustCompile(`^>> .*#$`)

var promptLike = capture.PromptLike()

func isPrompt(line string) bool {
	return promptLike(line) || menuPrompt.MatchString(strings.TrimSpace(line))
}

// Doc is one command output being decoded.
type Doc struct {
	Command string
	Source  evidence.SourceRef
	// Lines are the body lines, without echo and prompt, in order.
	Lines []parse.Line

	cursor *parse.Cursor
	scan   *parse.Scanner
	failed string
}

// Open prepares output o of device. A transport failure, or a body the CLI
// rejected, makes Failed return its code; the decoder then stops.
func Open(ctx context.Context, device string, o capture.Output) (*Doc, error) {
	content, err := parse.New(ctx, o.Normalized(), parse.Limits{})
	if err != nil {
		return nil, fmt.Errorf("clidoc: index %q: %w", o.Command, err)
	}
	src := o.Ref(device)
	d := &Doc{Command: o.Command, Source: src, cursor: content.Cursor(), scan: parse.NewScanner(src)}
	body, err := o.Body(ctx, isPrompt)
	if err != nil {
		return nil, fmt.Errorf("clidoc: body of %q: %w", o.Command, err)
	}
	if n := content.Len(); n > 0 {
		_ = d.cursor.Mark(1, n) // everything outside the body is parsed
	}
	for _, l := range body {
		_ = d.cursor.Unmark(l.Number, l.Number)
		if strings.TrimSpace(l.Text) == "" {
			_ = d.cursor.Mark(l.Number, l.Number)
		}
	}
	// PAN-OS echoes "user@host(role)> command" on the first line.
	if len(body) > 0 && strings.HasSuffix(strings.TrimSpace(body[0].Text), "> "+o.Command) {
		_ = d.cursor.Mark(body[0].Number, body[0].Number)
		body = body[1:]
	}
	d.Lines = body
	switch {
	case !o.OK() && !looksValid(body):
		d.fail(IssueFailed)
	case rejected(body):
		d.fail(IssueRejected)
	}
	return d, nil
}

// looksValid reports a body that carries data although the collector
// flagged the command, as Alteon does for some statistics menus.
func looksValid(body []parse.Line) bool {
	if len(body) < 3 {
		return false
	}
	for _, l := range body {
		if rejections.MatchString(l.Text) {
			return false
		}
	}
	return true
}

// rejected reports a CLI refusal in the first lines of a body; a caret
// line pointing at the bad keyword may come first.
func rejected(body []parse.Line) bool {
	seen := 0
	for _, l := range body {
		text := strings.TrimSpace(l.Text)
		if text == "" || text == "^" {
			continue
		}
		if rejections.MatchString(l.Text) {
			return true
		}
		if seen++; seen == 2 {
			return false
		}
	}
	return false
}

// Failed returns the failure code, or "" for a usable output.
func (d *Doc) Failed() string { return d.failed }

// Empty reports a body without any text.
func (d *Doc) Empty() bool {
	for _, l := range d.Lines {
		if strings.TrimSpace(l.Text) != "" {
			return false
		}
	}
	return true
}

// Mark flags lines as understood.
func (d *Doc) Mark(lines ...parse.Line) {
	for _, l := range lines {
		_ = d.cursor.Mark(l.Number, l.Number)
	}
}

// MarkMatching flags every body line matching re, such as legends.
func (d *Doc) MarkMatching(re *regexp.Regexp) {
	for _, l := range d.Lines {
		if re.MatchString(l.Text) {
			d.Mark(l)
		}
	}
}

// Issue records a problem at line l (nil for the whole output).
func (d *Doc) Issue(code string, l *parse.Line, fields ...evidence.Field) {
	n := 0
	if l != nil {
		n = l.Number
	}
	d.scan.Issue(code, n, fields...)
}

// Finish records unconsumed lines and returns the status and issues.
func (d *Doc) Finish() (evidence.Status, []evidence.Issue) {
	d.scan.Unparsed(d.cursor, 5)
	return d.scan.Status(true), d.scan.Issues()
}

// Unparsed returns the texts of up to n unconsumed lines, for corpus
// diagnostics only: they are device text and never enter issues.
func (d *Doc) Unparsed(n int) []string {
	var out []string
	for l := range d.cursor.Unparsed() {
		if len(out) == n {
			break
		}
		out = append(out, l.Text)
	}
	return out
}

// Blocks splits the body at lines for which start is true; each block
// begins with its start line. Lines before the first start are returned
// as the preamble.
func (d *Doc) Blocks(start func(string) bool) (preamble []parse.Line, blocks [][]parse.Line) {
	for _, l := range d.Lines {
		if start(l.Text) {
			blocks = append(blocks, []parse.Line{l})
			continue
		}
		if len(blocks) == 0 {
			preamble = append(preamble, l)
			continue
		}
		blocks[len(blocks)-1] = append(blocks[len(blocks)-1], l)
	}
	return preamble, blocks
}

func (d *Doc) fail(code string) {
	d.failed = code
	d.scan.Fail(code)
	for _, l := range d.Lines {
		_ = d.cursor.Mark(l.Number, l.Number)
	}
}
