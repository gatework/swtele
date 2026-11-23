// Package oui reads the IEEE MA-L registry (oui.txt) into a map from
// OUI ("aa:bb:cc") to organization name.
package oui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxLine bounds one registry line.
const maxLine = 4096

// Read parses an oui.txt stream: lines "AA-BB-CC   (hex)\t\tOrganization".
func Read(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, maxLine), maxLine)
	for sc.Scan() {
		prefix, organization, found := strings.Cut(sc.Text(), "(hex)")
		if !found {
			continue
		}
		prefix = strings.TrimSpace(prefix)
		if len(prefix) != 8 || prefix[2] != '-' || prefix[5] != '-' {
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(prefix, "-", ":"))
		if org := strings.TrimSpace(organization); org != "" {
			out[key] = org
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("oui: %w", err)
	}
	return out, nil
}

// ReadFile parses the registry file at path.
func ReadFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("oui: %w", err)
	}
	defer f.Close()
	return Read(f)
}
