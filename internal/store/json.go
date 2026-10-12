// Package store holds the on-disk primitives: an atomically-written JSON
// document and the helpers used to quarantine a corrupt one.
//
// Scope note: this file exists for settings only. Credentials and shares live
// in SQLite (internal/store/sqlite). Settings stay JSON because humans edit
// them by hand.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// ErrCorrupt is returned by Read when a JSON document exists but will not parse.
var ErrCorrupt = errors.New("store: document is corrupt")

// JSON is a single JSON document on disk, updated atomically and guarded by an
// advisory file lock.
//
// The Node version needed no lock: its single-threaded event loop cannot
// interleave a read-modify-write. Go's server has real concurrency, and the
// strangler rollout deliberately runs both servers against the same volumes,
// so cross-process exclusion is required, not optional.
type JSON struct {
	// Path is the document itself.
	Path string
	// LockPath is the lock file guarding it. Defaults to Path + ".lock".
	LockPath string

	mu sync.Mutex
}

// NewJSON returns a JSON store for path.
func NewJSON(path string) *JSON {
	return &JSON{Path: path, LockPath: path + ".lock"}
}

// Lock takes the advisory lock and returns an unlock function. It is exported
// so callers can hold the lock across several operations.
func (j *JSON) Lock() (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Dir(j.LockPath), 0o755); err != nil {
		return nil, fmt.Errorf("store: mkdir for lock: %w", err)
	}
	f, err := os.OpenFile(j.LockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("store: open lock: %w", err)
	}
	// Blocking: a concurrent writer is short-lived (a single small document),
	// so waiting is correct and spinning is not.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("store: flock: %w", err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// Read decodes the document into v. Returns fs.ErrNotExist if absent, and
// ErrCorrupt if present but unparseable. v may be nil to skip decoding.
func (j *JSON) Read(v any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.readLocked(v)
}

func (j *JSON) readLocked(v any) error {
	b, err := os.ReadFile(j.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return fmt.Errorf("store: read %s: %w", j.Path, err)
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCorrupt, j.Path, err)
	}
	return nil
}

// Write encodes v and replaces the document atomically: write a temp file in
// the same directory, fsync, then rename. A crash leaves either the old
// document or the new one, never a truncated blend of both.
func (j *JSON) Write(v any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	return j.writeLocked(v)
}

func (j *JSON) writeLocked(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode %s: %w", j.Path, err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(j.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	// The temp name carries the PID so two processes cannot collide on it.
	tmp, err := os.CreateTemp(dir, filepath.Base(j.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write temp: %w", err)
	}
	// Flush before rename: a crash between the two must not leave a document
	// that is present but empty.
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
	// Sync the directory so the rename itself survives a power cut.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Update performs a read-modify-write under a single lock acquisition, so two
// concurrent updates cannot lose one another's changes. fn receives the current
// value and returns the value to store.
func (j *JSON) Update(fn func(current []byte) (next []byte, err error)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	cur, err := os.ReadFile(j.Path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: read %s: %w", j.Path, err)
	}
	next, err := fn(cur)
	if err != nil {
		return err
	}
	tmp := &JSON{Path: j.Path}
	return tmp.writeRaw(next)
}

// Quarantine moves a corrupt document aside, returning the path it was moved
// to. The caller decides whether that is safe; users.json is NOT safe to reset
// (resetting it would delete every account and reopen admin setup), so its
// reader aborts startup instead of calling this.
//
// The corrupt file is copied, not renamed, and the original is left in place:
// whoever calls this has already decided to replace it, and keeping the
// original costs one file's worth of disk.
func Quarantine(path string) (string, error) {
	dst := fmt.Sprintf("%s.corrupt-%d", path, nowMillis())
	if err := copyFile(path, dst); err != nil {
		return "", err
	}
	return dst, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("store: open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("store: create %s: %w", dst, err)
	}
	if _, err := out.ReadFrom(in); err != nil {
		out.Close()
		return fmt.Errorf("store: copy: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("store: close copy: %w", err)
	}
	return nil
}
