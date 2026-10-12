package vfs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Trash is a user's deleted-items directory, paired with the live files root so
// an item can be moved between them and restored to where it came from.
//
// The two roots are separate FS values rather than one tree with a "trash"
// subdirectory: keeping trash outside the files root means a deleted item is
// genuinely gone from the user's view, and a stray path into trash cannot
// resolve within files.
type Trash struct {
	files *FS
	bin   *FS
}

// NewTrash pairs a files root with a trash root. Both are created if absent.
func NewTrash(filesDir, trashDir string) (*Trash, error) {
	f, err := New(filesDir)
	if err != nil {
		return nil, err
	}
	b, err := New(trashDir)
	if err != nil {
		return nil, err
	}
	return &Trash{files: f, bin: b}, nil
}

// Files returns the live files root.
func (t *Trash) Files() *FS { return t.files }

// Bin returns the trash root.
func (t *Trash) Bin() *FS { return t.bin }

// TrashItem is one deleted item.
type TrashItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"` // original path, relative to the files root
	IsDir     bool   `json:"isDir"`
	Size      int64  `json:"size"`
	DeletedAt int64  `json:"deletedAt"`
}

// metaSuffix marks the sidecar files in the trash directory.
const metaSuffix = ".meta.json"

// trashMeta is the sidecar recording where an item came from.
//
// It is stored as a file rather than a database row on purpose: the trash has
// to remain inspectable and recoverable with plain tools, and a user who
// deletes something must be able to find and recover it without this server.
type trashMeta struct {
	OriginalPath string `json:"originalPath"`
	Name         string `json:"name"`
	DeletedAt    int64  `json:"deletedAt"`
}

// newTrashID returns a timestamped, collision-resistant id. The timestamp
// prefix keeps the directory listing in rough chronological order.
func newTrashID() (string, error) {
	raw := make([]byte, 6)
	if err := randomRead(raw); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hexEncode(raw)), nil
}

// Delete moves an item from the files root into the trash.
//
// The meta sidecar is written BEFORE the data moves. A crash between the two
// leaves a meta file with no data (harmless, and cleaned up by the sweeper),
// whereas the other order would leave orphaned data that can never be restored
// or purged.
func (t *Trash) Delete(clientPath string) (*TrashItem, error) {
	src, err := t.files.Resolve(clientPath)
	if err != nil {
		return nil, err
	}
	if src == t.files.Root() {
		return nil, fmt.Errorf("%w: cannot delete the root", ErrInvalidPath)
	}
	st, err := os.Stat(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	rel, err := t.files.RelPath(src)
	if err != nil {
		return nil, err
	}
	id, err := newTrashID()
	if err != nil {
		return nil, err
	}

	item := &TrashItem{
		ID:        id,
		Name:      filepath.Base(src),
		Path:      rel,
		IsDir:     st.IsDir(),
		DeletedAt: time.Now().UnixMilli(),
	}
	if !st.IsDir() {
		item.Size = st.Size()
	} else {
		item.Size = DirSize(src, 0)
	}

	metaAbs, err := t.bin.Resolve(id + metaSuffix)
	if err != nil {
		return nil, err
	}
	metaBytes, err := json.Marshal(trashMeta{
		OriginalPath: rel, Name: item.Name, DeletedAt: item.DeletedAt,
	})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(metaAbs, metaBytes, 0o600); err != nil {
		return nil, fmt.Errorf("trash: write meta: %w", err)
	}

	dst, err := t.bin.Resolve(id)
	if err != nil {
		return nil, err
	}
	if err := t.moveAcross(src, dst); err != nil {
		// Roll the sidecar back so a failed delete leaves no debris.
		os.Remove(metaAbs)
		return nil, err
	}
	return item, nil
}

// moveAcross moves between the files root and the trash. A plain rename fails
// across devices (trash on a separate mount), so fall back to copy and delete.
func (t *Trash) moveAcross(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !isCrossDevice(err) {
		return err
	}
	if err := CopyTree(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

// List returns trashed items, newest first.
func (t *Trash) List() ([]TrashItem, error) {
	dirents, err := os.ReadDir(t.bin.Root())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []TrashItem
	for _, de := range dirents {
		name := de.Name()
		if !strings.HasSuffix(name, metaSuffix) {
			continue
		}
		id := strings.TrimSuffix(name, metaSuffix)
		item, err := t.readItem(id)
		if err != nil {
			// Orphaned sidecar with no data: skip. The sweeper reclaims it.
			continue
		}
		out = append(out, *item)
	}
	// Newest first.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].DeletedAt > out[i].DeletedAt {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// readItem loads one trashed item from its sidecar plus a stat of the data.
func (t *Trash) readItem(id string) (*TrashItem, error) {
	metaAbs, err := t.bin.Resolve(id + metaSuffix)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(metaAbs)
	if err != nil {
		return nil, err
	}
	var meta trashMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, err
	}
	item := &TrashItem{
		ID: id, Name: meta.Name, Path: meta.OriginalPath, DeletedAt: meta.DeletedAt,
	}
	dataAbs, err := t.bin.Resolve(id)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(dataAbs)
	if err != nil {
		return nil, err
	}
	item.IsDir = st.IsDir()
	if st.IsDir() {
		item.Size = DirSize(dataAbs, 0)
	} else {
		item.Size = st.Size()
	}
	return item, nil
}

// Restore moves a trashed item back to its original path.
//
// If something now occupies the original name it is not overwritten: a
// unique name is chosen instead, because silently replacing a file the user
// created after the delete would destroy their data.
func (t *Trash) Restore(id string) (*TrashItem, error) {
	item, err := t.readItem(id)
	if err != nil {
		return nil, ErrNotFound
	}
	// The recorded path is untrusted input read from a file on disk, so it is
	// resolved through the files root exactly like a client-supplied path.
	// A tampered sidecar therefore cannot restore outside the user's area.
	originalAbs, err := t.files.Resolve(item.Path)
	if err != nil {
		return nil, fmt.Errorf("trash: bad recorded path: %w", err)
	}
	origDir := filepath.Dir(originalAbs)
	origName := filepath.Base(originalAbs)

	if err := os.MkdirAll(origDir, 0o755); err != nil {
		return nil, err
	}

	// Never overwrite: if something occupies the original name now, pick a
	// unique one. Silently replacing a file created after the delete would
	// destroy the user's data.
	finalName := origName
	if _, err := os.Lstat(originalAbs); err == nil {
		origRel, err := t.files.RelPath(origDir)
		if err != nil {
			return nil, err
		}
		finalName, err = t.files.UniqueName(origRel, origName)
		if err != nil {
			return nil, err
		}
	}
	final, err := t.files.ResolveChild(filepath.Dir(item.Path), finalName)
	if err != nil {
		return nil, err
	}
	src, err := t.bin.Resolve(id)
	if err != nil {
		return nil, err
	}
	if err := t.moveAcross(src, final); err != nil {
		return nil, err
	}
	metaAbs, err := t.bin.Resolve(id + metaSuffix)
	if err == nil {
		os.Remove(metaAbs)
	}
	item.Name = finalName
	return item, nil
}

// Purge permanently deletes one trashed item.
func (t *Trash) Purge(id string) error {
	if !ValidName(id) {
		return fmt.Errorf("%w: bad trash id", ErrInvalidPath)
	}
	dataAbs, err := t.bin.Resolve(id)
	if err != nil {
		return err
	}
	metaAbs, err := t.bin.Resolve(id + metaSuffix)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dataAbs); err != nil {
		return err
	}
	if err := os.Remove(metaAbs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Empty removes every trashed item, returning how many.
func (t *Trash) Empty() (int, error) {
	items, err := t.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if err := t.Purge(it.ID); err == nil {
			n++
		}
	}
	return n, nil
}

// PurgeOlderThan permanently removes items deleted before cutoff. Items whose
// sidecar is missing are cleaned up too, so a crash between the two steps
// cannot leak disk forever.
func (t *Trash) PurgeOlderThan(cutoff time.Time) (int, error) {
	items, err := t.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if it.DeletedAt < cutoff.UnixMilli() {
			if err := t.Purge(it.ID); err == nil {
				n++
			}
		}
	}
	// Sweep orphaned sidecars whose data is gone.
	dirents, err := os.ReadDir(t.bin.Root())
	if err != nil {
		return n, nil
	}
	for _, de := range dirents {
		if !strings.HasSuffix(de.Name(), metaSuffix) {
			continue
		}
		id := strings.TrimSuffix(de.Name(), metaSuffix)
		dataAbs, err := t.bin.Resolve(id)
		if err != nil {
			continue
		}
		if _, err := os.Lstat(dataAbs); errors.Is(err, os.ErrNotExist) {
			if metaAbs, err := t.bin.Resolve(id + metaSuffix); err == nil {
				os.Remove(metaAbs)
			}
		}
	}
	return n, nil
}
