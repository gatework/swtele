// Package snapshot reads captures from a netops snapshot directory: one
// <mgmt-ip>/ subdirectory per device holding NN-<command>.output files and
// their .json sidecars.
package snapshot

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/gatework/netops/capture"
	nsnap "github.com/gatework/netops/store/snapshot"
)

// Dir is a snapshot directory.
type Dir struct {
	root string
}

// Open returns the snapshot directory at root.
func Open(root string) (*Dir, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return &Dir{root: abs}, nil
}

// Name returns the directory path.
func (d *Dir) Name() string { return d.root }

// Hosts lists the device addresses in the directory.
func (d *Dir) Hosts(context.Context) ([]netip.Addr, error) {
	names, err := nsnap.List(d.root)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	out := make([]netip.Addr, 0, len(names))
	for _, n := range names {
		if a, err := netip.ParseAddr(filepath.Base(n)); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// Load reads the capture of host.
func (d *Dir) Load(ctx context.Context, host netip.Addr) (capture.Capture, error) {
	c, err := nsnap.ReadDir(ctx, filepath.Join(d.root, host.String()))
	if err != nil {
		return capture.Capture{}, fmt.Errorf("snapshot: %w", err)
	}
	if !c.Host.IsValid() {
		c.Host = host
	}
	return c, nil
}
