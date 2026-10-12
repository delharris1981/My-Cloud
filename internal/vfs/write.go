package vfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// OpenResolved opens a file at a path that has already been produced by
// Resolve.
//
// It exists so callers that hold a resolved path — the zip builder walking a
// tree, for instance — can still route their filesystem access through this
// package. Every user-data file open in the codebase goes through Resolve or
// this function; the CI grep audit enforces that.
func OpenResolved(abs string) (*os.File, error) {
	f, err := os.Open(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

// WriteStream copies r into abs atomically.
//
// The body goes to a temp file which is fsynced and renamed into place, so a
// dropped connection mid-upload cannot leave a truncated file at the
// destination: the caller either gets the whole file or nothing. Streaming
// rather than buffering matters because a WebDAV PUT can be gigabytes.
//
// abs must already be resolved.
func WriteStream(abs string, r io.Reader, perm os.FileMode) error {
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("vfs: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(abs)+".tmp-*")
	if err != nil {
		return fmt.Errorf("vfs: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vfs: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vfs: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("vfs: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return fmt.Errorf("vfs: rename into place: %w", err)
	}
	return nil
}

// RemovePath deletes the resolved path abs, which must not be the root.
func RemovePath(abs, root string) error {
	if abs == root {
		return fmt.Errorf("%w: cannot delete the root", ErrInvalidPath)
	}
	return os.RemoveAll(abs)
}

// WriteFileAtomic replaces the file at abs with data, atomically.
//
// The write goes to a temp file in the same directory, is fsynced, and is then
// renamed into place, so a crash mid-write leaves either the old contents or
// the new ones and never a truncated blend. abs must already be resolved.
func WriteFileAtomic(abs string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("vfs: mkdir %s: %w", dir, err)
	}
	// The temp name carries the PID so two concurrent writers cannot collide.
	tmp, err := os.CreateTemp(dir, filepath.Base(abs)+".tmp-*")
	if err != nil {
		return fmt.Errorf("vfs: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("vfs: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vfs: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vfs: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("vfs: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return fmt.Errorf("vfs: rename into place: %w", err)
	}
	return nil
}
