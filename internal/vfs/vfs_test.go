package vfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFile creates a file inside the FS with the given contents.
func writeFile(t *testing.T, fs *FS, rel, content string) string {
	t.Helper()
	abs, err := fs.Resolve(rel)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", rel, err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestListSortsDirsFirst(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "zebra.txt", "z")
	writeFile(t, fs, "apple.txt", "a")
	if err := fs.Mkdir("zdir"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir("adir"); err != nil {
		t.Fatal(err)
	}

	entries, err := fs.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d: %+v", len(entries), entries)
	}
	// Directories first, then alphabetical.
	want := []string{"adir", "zdir", "apple.txt", "zebra.txt"}
	for i, w := range want {
		if entries[i].Name != w {
			t.Fatalf("position %d: got %q, want %q (order: %+v)", i, entries[i].Name, w, entries)
		}
	}
}

func TestStatReportsSizeAndType(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "a/b/file.txt", "hello world")

	e, err := fs.Stat("a/b/file.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if e.Size != int64(len("hello world")) {
		t.Fatalf("size: got %d", e.Size)
	}
	if e.IsDir {
		t.Fatal("file reported as directory")
	}
	d, err := fs.Stat("a/b")
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if !d.IsDir || d.Size != 0 {
		t.Fatalf("directory stat wrong: %+v", d)
	}
}

func TestStatMissingIsNotFound(t *testing.T) {
	fs, _ := newFS(t)
	if _, err := fs.Stat("nope.txt"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMkdirSingleRejectsExisting(t *testing.T) {
	fs, _ := newFS(t)
	if _, err := fs.MkdirSingle("", "docs"); err != nil {
		t.Fatalf("MkdirSingle: %v", err)
	}
	// A second attempt must fail rather than silently succeed: a file browser
	// creating "New folder" twice should tell the user.
	if _, err := fs.MkdirSingle("", "docs"); err == nil {
		t.Fatal("duplicate mkdir succeeded")
	}
}

func TestMkdirSingleRejectsBadNames(t *testing.T) {
	fs, _ := newFS(t)
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, "a\x00b"} {
		if _, err := fs.MkdirSingle("", n); err == nil {
			t.Errorf("MkdirSingle(%q) succeeded; bad name must be rejected", n)
		}
	}
}

func TestRenameWithinFS(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "old.txt", "content")

	name, err := fs.Rename("old.txt", "new.txt")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if name != "new.txt" {
		t.Fatalf("returned name %q", name)
	}
	if _, err := fs.Stat("old.txt"); err != ErrNotFound {
		t.Fatal("old name still resolves")
	}
	e, err := fs.Stat("new.txt")
	if err != nil {
		t.Fatalf("new name missing: %v", err)
	}
	if e.Size != int64(len("content")) {
		t.Fatalf("content lost on rename: %d bytes", e.Size)
	}
}

func TestRenameRejectsBadTargetName(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "a.txt", "x")
	for _, n := range []string{"../escape.txt", "sub/b.txt", "", ".."} {
		if _, err := fs.Rename("a.txt", n); err == nil {
			t.Errorf("Rename to %q succeeded; must be rejected", n)
		}
	}
}

func TestRenameRefusesOverwrite(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "a.txt", "AAA")
	writeFile(t, fs, "b.txt", "BBB")
	// Silently clobbering b.txt would destroy data.
	if _, err := fs.Rename("a.txt", "b.txt"); err == nil {
		t.Fatal("rename overwrote an existing file")
	}
	e, _ := fs.Stat("b.txt")
	if e.Size != 3 {
		t.Fatalf("existing file was modified: %d bytes", e.Size)
	}
}

func TestCopyTreeRecursive(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "src/a.txt", "aaa")
	writeFile(t, fs, "src/sub/b.txt", "bbb")
	if err := fs.Mkdir("dst"); err != nil {
		t.Fatal(err)
	}

	name, err := fs.Copy("src", "dst")
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if name != "src" {
		t.Fatalf("copied name %q", name)
	}
	// The copy must be a full, independent tree.
	for _, p := range []string{"dst/src/a.txt", "dst/src/sub/b.txt"} {
		if _, err := fs.Stat(p); err != nil {
			t.Fatalf("copied file missing: %s (%v)", p, err)
		}
	}
	// Original still present.
	if _, err := fs.Stat("src/a.txt"); err != nil {
		t.Fatal("copy removed the original")
	}
}

func TestCopyRefusesOverwrite(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "a.txt", "x")
	if err := fs.Mkdir("dst"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, fs, "dst/a.txt", "original")
	if _, err := fs.Copy("a.txt", "dst"); err == nil {
		t.Fatal("copy overwrote an existing file")
	}
	e, _ := fs.Stat("dst/a.txt")
	if e.Size != int64(len("original")) {
		t.Fatalf("existing file modified: %d", e.Size)
	}
}

func TestMoveBetweenDirs(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "from/file.txt", "data")
	if err := fs.Mkdir("to"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Move("from/file.txt", "to"); err != nil {
		t.Fatalf("Move: %v", err)
	}
	if _, err := fs.Stat("to/file.txt"); err != nil {
		t.Fatalf("moved file missing: %v", err)
	}
	if _, err := fs.Stat("from/file.txt"); err != ErrNotFound {
		t.Fatal("source still exists after move")
	}
}

func TestRemoveRefusesRoot(t *testing.T) {
	fs, _ := newFS(t)
	// Deleting the user's entire files root must be impossible via a path.
	for _, p := range []string{"", ".", "/"} {
		if err := fs.Remove(p); err == nil {
			t.Errorf("Remove(%q) deleted the root", p)
		}
	}
}

func TestUniqueName(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "photo.jpg", "1")
	writeFile(t, fs, "photo (1).jpg", "2")

	got, err := fs.UniqueName("", "photo.jpg")
	if err != nil {
		t.Fatalf("UniqueName: %v", err)
	}
	if got != "photo (2).jpg" {
		t.Fatalf("got %q, want %q", got, "photo (2).jpg")
	}
	// A free name is returned unchanged.
	got2, err := fs.UniqueName("", "free.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if got2 != "free.jpg" {
		t.Fatalf("free name was altered: %q", got2)
	}
}

func TestUniqueNameExtensionless(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "README", "x")
	got, err := fs.UniqueName("", "README")
	if err != nil {
		t.Fatal(err)
	}
	if got != "README (1)" {
		t.Fatalf("got %q", got)
	}
}

func TestSearchFindsByName(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "Holiday/beach.jpg", "x")
	writeFile(t, fs, "work/report.pdf", "x")
	writeFile(t, fs, "notes.txt", "x")

	res, err := fs.Search("holiday", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	// Matches the directory name too, since it is an entry in the root.
	if len(res) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(res), res)
	}
	if res[0].Path != "Holiday" {
		t.Fatalf("unexpected path %q", res[0].Path)
	}

	res2, _ := fs.Search("REPORT", 0)
	if len(res2) != 1 || res2[0].Path != "work/report.pdf" {
		t.Fatalf("case-insensitive nested search failed: %+v", res2)
	}
}

func TestSearchRespectsLimit(t *testing.T) {
	fs, _ := newFS(t)
	for i := 0; i < 20; i++ {
		writeFile(t, fs, filepath.Join("d", string(rune('a'+i))+"file.txt"), "x")
	}
	res, err := fs.Search("file", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 5 {
		t.Fatalf("limit ignored: got %d results", len(res))
	}
}

func TestSearchEmptyQueryReturnsNothing(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "a.txt", "x")
	res, err := fs.Search("   ", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("blank query returned results: %+v", res)
	}
}

func TestDirSizeCountsFilesNotSymlinks(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "a.txt", "12345")
	writeFile(t, fs, "sub/b.txt", "123")

	// A symlink to a big file outside must not be counted.
	outside := t.TempDir()
	big := filepath.Join(outside, "big.bin")
	if err := os.WriteFile(big, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(big, filepath.Join(fs.Root(), "link.bin")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	got := fs.Usage("")
	// 5 + 3 = 8; the 1MB symlink target must not be followed.
	if got != 8 {
		t.Fatalf("DirSize = %d, want 8 (symlink followed?)", got)
	}
}

func TestQuotaCacheTTL(t *testing.T) {
	c := NewQuotaCache(50 * time.Millisecond)
	calls := 0
	compute := func() int64 { calls++; return int64(calls) }

	first := c.Get("alice", compute)
	if calls != 1 {
		t.Fatalf("compute called %d times on first Get", calls)
	}
	// Within the TTL the cached value is returned.
	if second := c.Get("alice", compute); second != first || calls != 1 {
		t.Fatalf("cache miss inside TTL: got %d calls=%d", second, calls)
	}
	// After expiry it recomputes.
	time.Sleep(60 * time.Millisecond)
	if third := c.Get("alice", compute); third != 2 || calls != 2 {
		t.Fatalf("cache did not expire: got %d calls=%d", third, calls)
	}
}

func TestQuotaCacheInvalidate(t *testing.T) {
	c := NewQuotaCache(time.Minute)
	calls := 0
	compute := func() int64 { calls++; return int64(calls) }
	c.Get("alice", compute)
	c.Invalidate("alice")
	c.Get("alice", compute)
	if calls != 2 {
		t.Fatalf("Invalidate did not force recompute: calls=%d", calls)
	}
}

func TestPurgeOlder(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.txt")
	recent := filepath.Join(dir, "recent.txt")
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recent, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Backdate one file past the cutoff.
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	n, err := PurgeOlder(dir, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeOlder: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged, got %d", n)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old file not purged")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("recent file was purged")
	}
}

// TestListCannotReachOutsideRoot asserts the property that matters: listing a
// hostile path never surfaces entries from outside the FS. Such a path is
// clamped to somewhere non-existent under the root, so ErrNotFound is the
// correct and safe outcome — the caller renders an empty folder.
func TestListCannotReachOutsideRoot(t *testing.T) {
	fs, _ := newFS(t)
	writeFile(t, fs, "visible.txt", "x")

	// The real /etc exists and has entries. A payload that reached it would
	// list successfully and return directory contents rather than ErrNotFound.
	for _, p := range []string{"/etc", "../../etc", "/../../etc", "/dev"} {
		if _, err := fs.List(p); err == nil {
			t.Fatalf("List(%q) succeeded; a hostile path must not resolve to a listable directory", p)
		}
	}

	// "../.." clamps to the root itself, which is listable — but it lists
	// this user's files, never a parent. That is the correct outcome.
	entries, err := fs.List("../..")
	if err != nil {
		t.Fatalf("clamped listing failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "visible.txt" {
		t.Fatalf("clamped listing escaped the root: %+v", entries)
	}

	// The root itself lists only what belongs to this user.
	rootEntries, err := fs.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rootEntries) != 1 || rootEntries[0].Name != "visible.txt" {
		t.Fatalf("root listing wrong: %+v", rootEntries)
	}
}
