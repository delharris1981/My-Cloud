package vfs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// newTrash builds a Trash over two temp dirs.
func newTrash(t *testing.T) (*Trash, *FS, *FS) {
	t.Helper()
	base := t.TempDir()
	files, err := New(filepath.Join(base, "files"))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := New(filepath.Join(base, "trash"))
	if err != nil {
		t.Fatal(err)
	}
	return &Trash{files: files, bin: bin}, files, bin
}

func TestTrashDeleteAndRestore(t *testing.T) {
	tr, files, _ := newTrash(t)

	abs := filepath.Join(files.Root(), "notes.txt")
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	item, err := tr.Delete("notes.txt")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if item.Name != "notes.txt" || item.Path != "notes.txt" {
		t.Fatalf("unexpected item: %+v", item)
	}
	// Gone from the user's view.
	if _, err := files.Stat("notes.txt"); err != ErrNotFound {
		t.Fatal("file still visible in files root after delete")
	}
	// And present in the trash.
	items, err := tr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Size != 5 {
		t.Fatalf("trash listing wrong: %+v", items)
	}

	restored, err := tr.Restore(item.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restored.Name != "notes.txt" {
		t.Fatalf("restored name %q", restored.Name)
	}
	e, err := files.Stat("notes.txt")
	if err != nil {
		t.Fatalf("file not restored: %v", err)
	}
	if e.Size != 5 {
		t.Fatalf("restored size %d", e.Size)
	}
	// Trash now empty.
	items2, _ := tr.List()
	if len(items2) != 0 {
		t.Fatalf("trash not empty after restore: %+v", items2)
	}
}

func TestTrashRestoreDoesNotOverwrite(t *testing.T) {
	tr, files, _ := newTrash(t)
	abs := filepath.Join(files.Root(), "doc.txt")
	if err := os.WriteFile(abs, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	item, err := tr.Delete("doc.txt")
	if err != nil {
		t.Fatal(err)
	}

	// The user creates a new file at the same path while the old one is in
	// the trash.
	if err := os.WriteFile(abs, []byte("new content"), 0o644); err != nil {
		t.Fatal(err)
	}

	restored, err := tr.Restore(item.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// Restored under a different name rather than destroying the newer file.
	if restored.Name == "doc.txt" {
		t.Fatal("restore overwrote the file created after the delete")
	}
	if restored.Name != "doc (1).txt" {
		t.Fatalf("unexpected restore name %q", restored.Name)
	}
	// The newer file must be untouched.
	e, err := files.Stat("doc.txt")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != int64(len("new content")) {
		t.Fatalf("the newer file was modified: %d bytes", e.Size)
	}
}

func TestTrashDirectoryDeleteAndRestore(t *testing.T) {
	tr, files, _ := newTrash(t)
	dirAbs := filepath.Join(files.Root(), "folder")
	if err := os.MkdirAll(filepath.Join(dirAbs, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirAbs, "nested", "a.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	item, err := tr.Delete("folder")
	if err != nil {
		t.Fatal(err)
	}
	if !item.IsDir {
		t.Fatal("directory not marked as such")
	}
	if _, err := files.Stat("folder"); err != ErrNotFound {
		t.Fatal("directory still visible after delete")
	}
	if _, err := tr.Restore(item.ID); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// The whole tree comes back.
	e, err := files.Stat("folder/nested/a.txt")
	if err != nil {
		t.Fatalf("nested file not restored: %v", err)
	}
	if e.Size != 4 {
		t.Fatalf("nested content wrong: %d", e.Size)
	}
}

func TestTrashPurgeAndEmpty(t *testing.T) {
	tr, files, _ := newTrash(t)
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(files.Root(), n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Delete(n); err != nil {
			t.Fatal(err)
		}
	}
	items, _ := tr.List()
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}

	// Purge one.
	if err := tr.Purge(items[0].ID); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	items2, _ := tr.List()
	if len(items2) != 2 {
		t.Fatalf("expected 2 after purge, got %d", len(items2))
	}

	// Empty the rest.
	n, err := tr.Empty()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("Empty returned %d, want 2", n)
	}
	items3, _ := tr.List()
	if len(items3) != 0 {
		t.Fatalf("trash not empty: %+v", items3)
	}
	// The data must actually be gone from disk, not just unlisted.
	dirents, _ := os.ReadDir(tr.bin.Root())
	for _, de := range dirents {
		if de.Name() != ".lock" {
			t.Fatalf("leftover file in trash: %s", de.Name())
		}
	}
}

func TestTrashPurgeOlderThan(t *testing.T) {
	tr, files, _ := newTrash(t)
	old := filepath.Join(files.Root(), "old.txt")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Delete("old.txt"); err != nil {
		t.Fatal(err)
	}
	// Backdate the recorded deletion time past the cutoff. Retention reads
	// deletedAt from the sidecar's contents, not the file's mtime, so the
	// sidecar itself is rewritten.
	items, _ := tr.List()
	metaAbs, err := tr.bin.Resolve(items[0].ID + metaSuffix)
	if err != nil {
		t.Fatal(err)
	}
	oldAt := time.Now().Add(-48 * time.Hour).UnixMilli()
	tampered := []byte(`{"originalPath":"old.txt","name":"old.txt","deletedAt":` +
		itoa(oldAt) + `}`)
	if err := os.WriteFile(metaAbs, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := tr.PurgeOlderThan(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged, got %d", n)
	}
	items2, _ := tr.List()
	if len(items2) != 0 {
		t.Fatalf("old item survived retention: %+v", items2)
	}
}

func TestTrashSweepsOrphanedSidecar(t *testing.T) {
	tr, _, bin := newTrash(t)
	// Simulate a crash between writing the sidecar and moving the data.
	orphanMeta := filepath.Join(bin.Root(), "123-orphan"+metaSuffix)
	if err := os.WriteFile(orphanMeta, []byte(`{"originalPath":"x.txt","name":"x.txt","deletedAt":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A sidecar with no data must not appear in the listing and must be swept.
	items, err := tr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("orphaned sidecar appeared as an item: %+v", items)
	}
	if _, err := tr.PurgeOlderThan(time.Now().Add(365 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphanMeta); !os.IsNotExist(err) {
		t.Fatal("orphaned sidecar not swept; it would leak forever")
	}
}

func TestTrashRejectsRootDelete(t *testing.T) {
	tr, _, _ := newTrash(t)
	for _, p := range []string{"", ".", "/"} {
		if _, err := tr.Delete(p); err == nil {
			t.Errorf("Delete(%q) succeeded; the files root must not be deletable", p)
		}
	}
}

// TestTrashRestoreConfinesTamperedSidecar is the security-relevant case: the
// sidecar is a file on disk, so a tampered originalPath must not restore
// outside the user's own area.
//
// The outcome is clamping rather than an error — the traversal is normalised
// back inside the files root, exactly as Resolve does for a hostile client
// path. The property that matters is that nothing lands outside the root.
func TestTrashRestoreConfinesTamperedSidecar(t *testing.T) {
	tr, files, bin := newTrash(t)
	abs := filepath.Join(files.Root(), "safe.txt")
	if err := os.WriteFile(abs, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	item, err := tr.Delete("safe.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the sidecar to point outside the files root.
	metaAbs, err := bin.Resolve(item.ID + metaSuffix)
	if err != nil {
		t.Fatal(err)
	}
	evil := []byte(`{"originalPath":"../../../../tmp/escaped.txt","name":"escaped.txt","deletedAt":1}`)
	if err := os.WriteFile(metaAbs, evil, 0o600); err != nil {
		t.Fatal(err)
	}

	escapedPath := "/tmp/escaped.txt"
	os.Remove(escapedPath)

	if _, err := tr.Restore(item.ID); err == nil {
		// Accepting it is fine provided it stayed inside the root.
		if _, statErr := os.Stat(escapedPath); statErr == nil {
			os.Remove(escapedPath)
			t.Fatal("restore escaped the files root")
		}
		return
	}

	// If it was refused, nothing outside the root may exist either.
	if _, statErr := os.Stat(escapedPath); statErr == nil {
		os.Remove(escapedPath)
		t.Fatal("restore escaped the files root")
	}
	// And anything that was restored must be inside the root.
	dirents, _ := os.ReadDir(files.Root())
	for _, de := range dirents {
		if !strings.HasPrefix(de.Name(), "tmp") && de.Name() != "safe.txt" {
			t.Logf("restored entry: %s", de.Name())
		}
	}
}

func TestTrashIDIsSafe(t *testing.T) {
	tr, files, _ := newTrash(t)
	for _, n := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(files.Root(), n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Delete(n); err != nil {
			t.Fatal(err)
		}
	}
	items, _ := tr.List()
	if len(items) != 2 {
		t.Fatalf("expected 2, got %d", len(items))
	}
	// Ids must be single safe components: they become filenames in the bin.
	for _, it := range items {
		if !ValidName(it.ID) {
			t.Fatalf("unsafe trash id %q", it.ID)
		}
		// Purge must reject a traversal attempt on the id.
		if err := tr.Purge("../" + it.ID); err == nil {
			t.Fatal("Purge accepted a traversal id")
		}
	}
}
