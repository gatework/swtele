package clidoc

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/swtele"
)

// Step decodes one command into the dimensions it feeds. S is the vendor's
// decoding state.
type Step[S any] struct {
	Command string
	Dims    []evidence.Dimension
	Decode  func(*Doc, S)
	// Prefix makes Command match every command that starts with it, for
	// numbered commands such as "show lacp aggregate1".
	Prefix bool
}

// Observer receives each decoded command's status and its first
// unconsumed lines. It is for corpus diagnostics: the lines are device
// text and must not be logged or reported.
type Observer func(command string, status evidence.Status, unparsed []string)

// Run decodes the outputs of c with steps, in order, recording each
// step's status on the dimensions it feeds. A command absent from c
// leaves its dimensions not requested; a rejected one marks them failed.
func Run[S any](ctx context.Context, dev *swtele.Device, c capture.Capture, steps []Step[S], st S, on Observer) error {
	name := dev.Identity.Mgmt.String()
	for _, s := range steps {
		for _, out := range outputs(c, s) {
			if err := run(ctx, dev, name, out, s, st, on); err != nil {
				return err
			}
		}
	}
	return nil
}

func outputs[S any](c capture.Capture, s Step[S]) []capture.Output {
	if !s.Prefix {
		if out, ok := c.Output(s.Command); ok {
			return []capture.Output{out}
		}
		return nil
	}
	var out []capture.Output
	for _, o := range c.Outputs {
		if strings.HasPrefix(o.Command, s.Command) {
			out = append(out, o)
		}
	}
	return out
}

func run[S any](ctx context.Context, dev *swtele.Device, name string, out capture.Output, s Step[S], st S, on Observer) error {
	doc, err := Open(ctx, name, out)
	if err != nil {
		return err
	}
	if doc.Failed() == "" {
		s.Decode(doc, st)
	}
	status, issues := doc.Finish()
	for _, dim := range s.Dims {
		dev.Observe(dim, status)
		dev.Collect(dim, out.RecordedAt)
	}
	dev.Issues = append(dev.Issues, issues...)
	if on != nil {
		on(s.Command, status, doc.Unparsed(5))
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("clidoc: %w", err)
	}
	return nil
}

// NewPrefixStep returns a step decoding every command starting with
// prefix.
func NewPrefixStep[S any](prefix string, decode func(*Doc, S), dims ...evidence.Dimension) Step[S] {
	return Step[S]{Command: prefix, Dims: dims, Decode: decode, Prefix: true}
}

// Commands returns the commands of steps, in order.
func Commands[S any](steps []Step[S]) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Command
	}
	return out
}

// Feeds returns the dimensions the steps decode command into.
func Feeds[S any](steps []Step[S], command string) []evidence.Dimension {
	var out []evidence.Dimension
	for _, s := range steps {
		if s.Command == command || s.Prefix && strings.HasPrefix(command, s.Command) {
			for _, d := range s.Dims {
				if !slices.Contains(out, d) {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// NewStep returns the step decoding command into dims.
func NewStep[S any](command string, decode func(*Doc, S), dims ...evidence.Dimension) Step[S] {
	return Step[S]{Command: command, Dims: dims, Decode: decode}
}
