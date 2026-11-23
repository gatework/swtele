// Package backup reads configuration backups from a directory of text
// files named "<hostname>-<mgmt-ip>.txt", as the gatework backup tools
// write them.
package backup

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	nboot "github.com/gatework/netops/bootstrap"
)

// maxConfig bounds one configuration file.
const maxConfig = 32 << 20

// Dir is a backup directory indexed by management address.
type Dir struct {
	files map[netip.Addr]string
}

// Open indexes the backups in dir.
func Open(dir string) (*Dir, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	d := &Dir{files: map[netip.Addr]string{}}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".txt") {
			continue
		}
		base := strings.TrimSuffix(name, ".txt")
		i := strings.LastIndexByte(base, '-')
		if i < 0 {
			continue
		}
		if a, err := netip.ParseAddr(base[i+1:]); err == nil {
			d.files[a] = filepath.Join(dir, name)
		}
	}
	return d, nil
}

// Len returns the number of indexed backups.
func (d *Dir) Len() int { return len(d.files) }

// Config returns the backup of host and its modification time.
func (d *Dir) Config(ctx context.Context, host netip.Addr) (string, time.Time, bool, error) {
	path, ok := d.files[host]
	if !ok {
		return "", time.Time{}, false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("backup: %w", err)
	}
	if info.Size() > maxConfig {
		return "", time.Time{}, false, fmt.Errorf("backup: %s exceeds %d bytes", path, maxConfig)
	}
	body, _, err := nboot.ReadFile(ctx, path, false)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("backup: %w", err)
	}
	return string(body), info.ModTime(), true, nil
}
