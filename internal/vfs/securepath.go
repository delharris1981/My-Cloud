// Package vfs is the only package permitted to touch user data.
//
// Every path that arrives from a browser, WebDAV client, or share link is
// client-supplied, and that is the entire attack surface. Resolve below is
// the single place those rules are enforced; if you find yourself calling
// os.Open on something under the data directory from another package, you have
// found a bug.
package vfs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrInvalidPath is returned for any client path that cannot be safely
// resolved inside the root. Callers surface it as a 400; the message is
// deliberately generic so it does not describe which rule was hit.
var ErrInvalidPath = errors.New("invalid path")

// ErrNotFound means the resolved path is valid but does not exist.
var ErrNotFound = errors.New("not found")

// maxComponent is the per-segment byte ceiling, matching the common Linux
// NAME_MAX. Applied before touching the filesystem so an absurd segment is
// rejected cheaply.
const maxComponent = 255

// FS is a confined view of one user's files, trash, or thumbs directory.
type FS struct {
	// root is the absolute, cleaned directory this FS is confined to.
	root string
}

// New returns an FS rooted at dir, creating it if absent.
//
// The root is resolved through EvalSymlinks once, here. Storing the real
// path means a symlinked root (common when /data points into a pool) does not
// cause every later containment check to fail against its own prefix.
func New(dir string) (*FS, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("vfs: abs %s: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("vfs: create %s: %w", abs, err)
	}
	// The root itself may legitimately be a symlink; resolve it once so the
	// comparison below is against the real location.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("vfs: resolve root %s: %w", abs, err)
	}
	return &FS{root: real}, nil
}

// Root returns the absolute root directory.
func (fs *FS) Root() string { return fs.root }

// Resolve maps a client-supplied path to an absolute path inside root, or an
// error. This is the choke point: the browser, WebDAV, shares, search, and
// thumbnails all go through here and nowhere else.
//
// The checks, in order:
//
//  1. Reject NUL bytes outright.
//  2. Normalise separators and reject any component over 255 bytes.
//  3. path.Clean, then confirm the result is lexically inside root.
//  4. EvalSymlinks on the deepest existing ancestor and confirm it is still
//     inside root. This is what stops a symlink planted inside a shared
//     folder from becoming an escape hatch; cleaning cannot catch it because
//     the symlink is a valid path component.
//
// A leaf that does not exist yet is allowed — that is how mkdir and upload
// work — but its parent must resolve inside root.
func (fs *FS) Resolve(clientPath string) (string, error) {
	if strings.ContainsRune(clientPath, 0) {
		return "", fmt.Errorf("%w: NUL byte", ErrInvalidPath)
	}

	// Windows-style separators from a WebDAV client on any OS.
	clean := strings.ReplaceAll(clientPath, "\\", "/")

	// Validate each raw segment before cleaning, so a traversal attempt with
	// an over-long segment is still rejected rather than normalised away.
	for _, seg := range strings.Split(clean, "/") {
		if len(seg) > maxComponent {
			return "", fmt.Errorf("%w: component too long", ErrInvalidPath)
		}
	}

	// path.Clean on "/"+rel gives an absolute, normalised path; "." and ""
	// both become "/" which joins to the root.
	rel := path.Clean("/" + strings.TrimPrefix(clean, "/"))
	abs := filepath.Join(fs.root, filepath.FromSlash(rel))

	if err := fs.checkContained(abs); err != nil {
		return "", err
	}
	if err := fs.checkRealContained(abs); err != nil {
		return "", err
	}
	return abs, nil
}

// checkContained is the lexical guard: abs must be root or under root/.
// Rel is used rather than a string prefix so a sibling directory whose name
// merely starts with the root's name (…/alice vs …/alice2) cannot pass.
func (fs *FS) checkContained(abs string) error {
	r, err := filepath.Rel(fs.root, abs)
	if err != nil {
		return fmt.Errorf("%w: rel failed", ErrInvalidPath)
	}
	if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: escapes root", ErrInvalidPath)
	}
	if filepath.IsAbs(r) {
		return fmt.Errorf("%w: absolute", ErrInvalidPath)
	}
	return nil
}

// checkRealContained resolves symlinks on the deepest existing ancestor of abs
// and confirms the real location is still inside root.
//
// The ancestor, not the full path: EvalSymlinks fails on a not-yet-created
// leaf (uploads and mkdir), and resolving only what exists still catches a
// symlinked parent — which is the actual escape route.
func (fs *FS) checkRealContained(abs string) error {
	real, err := resolveExisting(abs)
	if err != nil {
		// Nothing along the path exists yet. The lexical check above already
		// passed, and there is no symlink to follow, so the path is safe to
		// hand to a creating operation.
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	r, err := filepath.Rel(fs.root, real)
	if err != nil {
		return fmt.Errorf("%w: real path outside root", ErrInvalidPath)
	}
	if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		// A symlink inside the tree points out of the tree. Refuse even though
		// the lexical path looked fine.
		return fmt.Errorf("%w: symlink escapes root", ErrInvalidPath)
	}
	return nil
}

// resolveExisting returns the fully symlink-resolved path of the deepest
// existing ancestor of abs, with the non-existent remainder appended.
func resolveExisting(abs string) (string, error) {
	cur := abs
	var tail []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the filesystem root without finding anything.
			return "", os.ErrNotExist
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
	real, err := filepath.EvalSymlinks(cur)
	if err != nil {
		return "", err
	}
	// Re-append the remainder, preserving order: tail was collected leaf-first.
	for i := len(tail) - 1; i >= 0; i-- {
		real = filepath.Join(real, tail[i])
	}
	return real, nil
}

// RelPath is the inverse of Resolve: an absolute path inside root back to the
// slash-separated form used in URLs, share rows, and search results.
func (fs *FS) RelPath(abs string) (string, error) {
	r, err := filepath.Rel(fs.root, abs)
	if err != nil {
		return "", fmt.Errorf("%w: not under root", ErrInvalidPath)
	}
	r = filepath.ToSlash(r)
	if r == "." {
		return "", nil
	}
	return r, nil
}

// ValidName reports whether name is usable as a single filesystem entry.
//
// Separate from Resolve because a *new* name has no parent to resolve: this
// is the check that keeps "/" and ".." and control characters out of names a
// user creates. Mirrors the Node validName().
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > maxComponent {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	// Control characters, including NUL, are rejected.
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// JoinChild resolves dirPath/name as a child of a directory, validating name
// as a single entry. Used by every create/rename operation so a name can never
// smuggle a separator into a path.
func (fs *FS) JoinChild(dirPath, name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("%w: bad name", ErrInvalidPath)
	}
	return fs.Resolve(filepath.Join(dirPath, name))
}
