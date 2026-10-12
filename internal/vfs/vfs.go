package vfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry is one listed item. No database stores this — it is derived from the
// filesystem on every call, which is what keeps user data browseable with any
// other tool.
type Entry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
}

// Stat returns metadata for a resolved path.
func (fs *FS) Stat(clientPath string) (Entry, error) {
	abs, err := fs.Resolve(clientPath)
	if err != nil {
		return Entry{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}
	return entryFrom(st, filepath.Base(abs)), nil
}

func entryFrom(st os.FileInfo, name string) Entry {
	e := Entry{
		Name:    name,
		IsDir:   st.IsDir(),
		ModTime: st.ModTime().UnixMilli(),
	}
	if !st.IsDir() {
		e.Size = st.Size()
	}
	return e
}

// List returns the entries of a directory, directories first then name, which
// is what the file browser expects.
func (fs *FS) List(clientPath string) ([]Entry, error) {
	abs, err := fs.Resolve(clientPath)
	if err != nil {
		return nil, err
	}
	dirents, err := os.ReadDir(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	out := make([]Entry, 0, len(dirents))
	for _, de := range dirents {
		info, err := de.Info()
		if err != nil {
			// Entry vanished or is unreadable mid-listing; skip rather than
			// fail the whole listing, matching the Node listDir.
			continue
		}
		// A symlink is listed by its own name but stat'd through the link, so
		// a link pointing at a directory still browses. Resolve already
		// guaranteed the target is inside root.
		out = append(out, entryFrom(info, de.Name()))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Mkdir creates a directory (and parents) inside the FS.
func (fs *FS) Mkdir(clientPath string) error {
	abs, err := fs.Resolve(clientPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("already exists")
		}
		return err
	}
	return nil
}

// MkdirSingle creates exactly one directory, refusing if the name is taken.
// Distinct from Mkdir because a file browser creating "New folder" should not
// silently succeed when it already exists.
func (fs *FS) MkdirSingle(dirPath, name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("%w: bad name", ErrInvalidPath)
	}
	abs, err := fs.ResolveChild(dirPath, name)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(abs, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("already exists")
		}
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: parent does not exist", ErrNotFound)
		}
		return "", err
	}
	return name, nil
}

// ResolveChild resolves a single validated name inside dirPath.
func (fs *FS) ResolveChild(dirPath, name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("%w: bad name", ErrInvalidPath)
	}
	parent, err := fs.Resolve(dirPath)
	if err != nil {
		return "", err
	}
	abs := filepath.Join(parent, name)
	// Re-run the full checks so the child cannot escape via a symlinked
	// parent that Resolve would have caught on its own.
	if err := fs.checkContained(abs); err != nil {
		return "", err
	}
	if err := fs.checkRealContained(abs); err != nil {
		return "", err
	}
	return abs, nil
}

// Rename renames an entry within the FS. Both the old and new locations are
// resolved, so a rename cannot move something out of the tree.
func (fs *FS) Rename(from, newName string) (string, error) {
	src, err := fs.Resolve(from)
	if err != nil {
		return "", err
	}
	if !ValidName(newName) {
		return "", fmt.Errorf("%w: bad name", ErrInvalidPath)
	}
	dst, err := fs.ResolveChild(filepath.Dir(from), newName)
	if err != nil {
		return "", err
	}
	if src == dst {
		return newName, nil
	}
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("already exists")
	}
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
	return newName, nil
}

// Move relocates srcPath to dstDirPath. Used by move-to-folder and by trash
// restore, which lives in a different root.
func (fs *FS) Move(srcPath, dstDirPath string) (string, error) {
	src, err := fs.Resolve(srcPath)
	if err != nil {
		return "", err
	}
	dir, err := fs.Resolve(dstDirPath)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(dstDirPath, "/") {
		dir, err = fs.Resolve(dstDirPath + "/")
		if err != nil {
			return "", err
		}
	}
	return fs.moveAbs(src, dir)
}

// moveAbs moves a pre-resolved source into an already-resolved directory,
// avoiding a unique name only if one is forced.
func (fs *FS) moveAbs(src, dstDir string) (string, error) {
	name := filepath.Base(src)
	dst := filepath.Join(dstDir, name)
	if _, err := os.Stat(dst); err == nil {
		// Collisions are resolved by the caller choosing uniqueName first;
		// a bare overwrite here would silently destroy data.
		return "", fmt.Errorf("already exists")
	}
	if err := os.Rename(src, dst); err != nil {
		// EXDEV: trash may be on a different mount. Fall back to copy+delete.
		if isCrossDevice(err) {
			if err := CopyTree(src, dst); err != nil {
				return "", err
			}
			if err := os.RemoveAll(src); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}
	return name, nil
}

func isCrossDevice(err error) bool {
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err == syscallEXDEV
	}
	return false
}

// Copy duplicates a file or directory tree within the FS.
func (fs *FS) Copy(srcPath, dstDirPath string) (string, error) {
	src, err := fs.Resolve(srcPath)
	if err != nil {
		return "", err
	}
	dir, err := fs.Resolve(dstDirPath)
	if err != nil {
		return "", err
	}
	name := filepath.Base(src)
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("already exists")
	}
	if err := CopyTree(src, dst); err != nil {
		return "", err
	}
	return name, nil
}

// CopyTo copies srcPath to destPath exactly as named.
//
// WebDAV's Destination header specifies the full target path including the new
// name, which is different from Copy's "into this directory, keep the name"
// contract. Both paths are resolved, so a hostile Destination cannot land
// outside the root. destPath must not already exist.
func (fs *FS) CopyTo(srcPath, destPath string) error {
	src, err := fs.Resolve(srcPath)
	if err != nil {
		return err
	}
	dst, err := fs.Resolve(destPath)
	if err != nil {
		return err
	}
	// A copy must not become a duplicate of itself.
	if src == dst {
		return fmt.Errorf("source and destination are the same")
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("already exists")
	}
	// Copying a collection into its own descendant would recurse forever.
	if strings.HasPrefix(dst, src+"/") {
		return fmt.Errorf("cannot copy a collection into itself")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return CopyTree(src, dst)
}

// MoveTo moves srcPath to destPath exactly as named, as WebDAV MOVE requires.
// Both paths are resolved.
func (fs *FS) MoveTo(srcPath, destPath string) error {
	src, err := fs.Resolve(srcPath)
	if err != nil {
		return err
	}
	dst, err := fs.Resolve(destPath)
	if err != nil {
		return err
	}
	if src == dst {
		return nil
	}
	if src == fs.root {
		return fmt.Errorf("%w: cannot move the root", ErrInvalidPath)
	}
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("already exists")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if isCrossDevice(err) {
			if err := CopyTree(src, dst); err != nil {
				return err
			}
			return os.RemoveAll(src)
		}
		return err
	}
	return nil
}

// CopyTree recursively copies src to dst. dst must not exist.
func CopyTree(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		// Copy the link, not its target: following it could pull data from
		// outside the tree into a user's own area.
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)
	case st.IsDir():
		if err := os.Mkdir(dst, st.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := CopyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	default:
		return copyFileContents(src, dst, st.Mode().Perm())
	}
}

func copyFileContents(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Remove deletes a file or directory tree permanently.
func (fs *FS) Remove(clientPath string) error {
	abs, err := fs.Resolve(clientPath)
	if err != nil {
		return err
	}
	if abs == fs.root {
		return fmt.Errorf("%w: cannot delete the root", ErrInvalidPath)
	}
	if _, err := os.Stat(abs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return os.RemoveAll(abs)
}

// Open opens a file for reading. Callers must go through this or Resolve —
// never os.Open on a path under the data directory.
func (fs *FS) Open(clientPath string) (*os.File, error) {
	abs, err := fs.Resolve(clientPath)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

// UniqueName returns name, or "name (1).ext" and so on, until it is free in
// dir. Upload and drop-box writes use this so a second upload of the same
// filename does not overwrite the first.
func (fs *FS) UniqueName(dirPath, name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("%w: bad name", ErrInvalidPath)
	}
	dir, err := fs.Resolve(dirPath)
	if err != nil {
		return "", err
	}
	candidate := name
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i < 10000; i++ {
		if _, err := os.Lstat(filepath.Join(dir, candidate)); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
	}
	return "", fmt.Errorf("could not find a unique name")
}

// maxDepth bounds recursion in DirSize and Search, matching the Node MAX_DEPTH.
const maxDepth = 40

// DirSize totals the bytes under abs. Symlinks are never followed: that would
// escape the root and can also loop forever.
func DirSize(abs string, depth int) int64 {
	if depth > maxDepth {
		return 0
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		p := filepath.Join(abs, e.Name())
		if e.IsDir() {
			total += DirSize(p, depth+1)
			continue
		}
		// Lstat, not Stat: a symlink's own size is counted, never its target.
		if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total
}

// Usage is DirSize for a client path.
func (fs *FS) Usage(clientPath string) int64 {
	abs, err := fs.Resolve(clientPath)
	if err != nil {
		return 0
	}
	return DirSize(abs, 0)
}

// SearchResult is one filename match. Content search is explicitly out of
// scope, matching the Node version.
type SearchResult struct {
	Entry
	Path string `json:"path"` // relative to the FS root
}

// Search finds entries whose name contains query, case-insensitively, capped
// at limit results. Trashed files are out of scope: they live in a separate
// root and are searched explicitly.
func (fs *FS) Search(query string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 200
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, nil
	}
	var out []SearchResult
	var walk func(dirAbs, rel string, depth int)
	walk = func(dirAbs, rel string, depth int) {
		if len(out) >= limit || depth > maxDepth {
			return
		}
		entries, err := os.ReadDir(dirAbs)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(out) >= limit {
				return
			}
			childRel := e.Name()
			if rel != "" {
				childRel = rel + "/" + e.Name()
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if strings.Contains(strings.ToLower(e.Name()), q) {
				out = append(out, SearchResult{
					Entry: entryFrom(info, e.Name()),
					Path:  childRel,
				})
			}
			if e.IsDir() {
				walk(filepath.Join(dirAbs, e.Name()), childRel, depth+1)
			}
		}
	}
	walk(fs.root, "", 0)
	return out, nil
}

// PurgeOlder removes entries under abs older than the cutoff, returning how
// many were removed. Used for trash retention.
func PurgeOlder(abs string, cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(abs)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		p := filepath.Join(abs, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if os.RemoveAll(p) == nil {
				removed++
			}
		}
	}
	return removed, nil
}
