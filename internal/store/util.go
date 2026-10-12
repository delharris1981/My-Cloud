package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// nowMillis is unix milliseconds, the timestamp convention used throughout
// the database schema and the JSON documents being migrated.
func nowMillis() int64 { return time.Now().UnixMilli() }

// writeRaw replaces the document with pre-encoded bytes, atomically.
//
// Unlike Write it takes the lock path from the receiver, so Update can hold a
// single lock acquisition across its read and write. Callers inside the package
// that already hold the lock must use this rather than Write, which would
// deadlock against itself.
func (j *JSON) writeRaw(b []byte) error {
	dir := filepath.Dir(j.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	// Copy: the caller may reuse its buffer, and we append a newline below.
	buf := make([]byte, len(b), len(b)+1)
	copy(buf, b)
	buf = append(buf, '\n')

	tmp, err := os.CreateTemp(dir, filepath.Base(j.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("store: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, j.Path); err != nil {
		return fmt.Errorf("store: rename into place: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// MarshalJSON is a small helper for callers assembling a document from parts.
func MarshalJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("store: encode: %w", err)
	}
	return append(b, '\n'), nil
}
