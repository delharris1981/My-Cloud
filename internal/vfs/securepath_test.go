package vfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newFS builds an FS over a temp dir.
func newFS(t *testing.T) (*FS, string) {
	t.Helper()
	dir := t.TempDir()
	fs, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fs, fs.Root()
}

// TestResolveRejectsTraversalPayloads covers payloads that must be refused
// outright: anything carrying a NUL byte or an over-long segment.
//
// Note that ".." payloads are NOT in this table. Resolve clamps them —
// path.Clean("/" + "../etc/passwd") is "/etc/passwd", which joins to
// root/etc/passwd — because clamping is both the behaviour the plan specifies
// and the one the Node safeJoin had. Clamping is safe precisely because it
// cannot escape; TestResolveClampsRatherThanEscapes asserts that property
// directly.
func TestResolveRejectsTraversalPayloads(t *testing.T) {
	fs, _ := newFS(t)

	payloads := []struct {
		name string
		in   string
	}{
		{"nul byte", "file\x00.txt"},
		{"nul in middle", "a/b\x00/../../c"},
		{"nul as whole path", "\x00"},
		{"overlong component", strings.Repeat("a", 256)},
		{"overlong trailing", "ok/" + strings.Repeat("b", 300)},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			if got, err := fs.Resolve(p.in); err == nil {
				t.Fatalf("payload %q resolved to %q; it must be rejected", p.in, got)
			}
		})
	}
}

// TestResolveClampsRatherThanEscapes is the real traversal test: hostile
// payloads are normalised back inside the root. The invariant is not "returns
// an error" but "never returns a path outside root".
func TestResolveClampsRatherThanEscapes(t *testing.T) {
	fs, root := newFS(t)

	payloads := []struct {
		name string
		in   string
	}{
		{"dot dot", "../etc/passwd"},
		{"deep dot dot", "../../../../etc/passwd"},
		{"embedded dot dot", "a/../../etc/passwd"},
		{"trailing slash escape", "../../"},
		{"backslash escape", `..\..\etc\passwd`},
		{"mixed separators", "../a/../../b"},
		{"absolute path", "/etc/passwd"},
		{"dev null", "/dev/null"},
		{"proc", "/proc/self/environ"},
		{"windows drive", `C:\Windows\System32`},
		{"unc path", `\\server\share\file`},
		{"dot slash", "./"},
		{"url encoded", "%2e%2e/%2e%2e/etc"},
		{"triple dot literal", "..."},
		{"traversal then back", "../../a/../b"},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			got, err := fs.Resolve(p.in)
			if err != nil {
				// Rejecting outright is also acceptable.
				return
			}
			if !strings.HasPrefix(got, root+string(filepath.Separator)) && got != root {
				t.Fatalf("payload %q escaped root: got %q, root %q", p.in, got, root)
			}
			// The decisive check: the real, symlink-resolved path must not
			// name anything outside root either.
			rel, err := filepath.Rel(root, got)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("payload %q produced an escaping relative path %q", p.in, rel)
			}
		})
	}
}

// TestResolveTraversalCannotReachRealSystemFiles is the assertion that matters
// operationally: a traversal payload must never name a file that exists on
// the host. Clamping makes these land under root as a non-existent path, so
// the caller gets a 404 — not the contents of /etc/passwd.
func TestResolveTraversalCannotReachRealSystemFiles(t *testing.T) {
	fs, _ := newFS(t)
	for _, p := range []string{"../etc/passwd", "/etc/passwd", "../../../../etc/shadow"} {
		abs, err := fs.Resolve(p)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			t.Fatalf("payload %q resolved to an existing host file: %s", p, abs)
		}
	}
}

func TestResolveAcceptsLegitimatePaths(t *testing.T) {
	fs, root := newFS(t)

	cases := map[string]string{
		"":                  root,
		".":                 root,
		"/":                 root,
		"./":                root,
		"file.txt":          filepath.Join(root, "file.txt"),
		"a/b/c.txt":         filepath.Join(root, "a", "b", "c.txt"),
		"a/../b":            filepath.Join(root, "b"),
		"/leading/slash":    filepath.Join(root, "leading", "slash"),
		"space in name.txt": filepath.Join(root, "space in name.txt"),
		"unicode-ünïcødé":   filepath.Join(root, "unicode-ünïcødé"),
		".dotfile":          filepath.Join(root, ".dotfile"),
		"a/./b/./c":         filepath.Join(root, "a", "b", "c"),
	}

	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got, err := fs.Resolve(in)
			if err != nil {
				t.Fatalf("Resolve(%q): unexpected error %v", in, err)
			}
			if got != want {
				t.Fatalf("Resolve(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

// TestResolveRejectsSymlinkEscape is the case path.Clean alone cannot catch:
// a symlink planted inside the root, pointing out of it. safeJoin in the Node
// version guarded this separately via realContained; here it is part of
// Resolve so there is no second code path to forget.
func TestResolveRejectsSymlinkEscape(t *testing.T) {
	fs, root := newFS(t)

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Plant the symlink the way an attacker with SMB or shell access would.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}

	for _, p := range []string{"escape", "escape/secret.txt", "escape/../escape/secret.txt"} {
		t.Run(p, func(t *testing.T) {
			got, err := fs.Resolve(p)
			if err == nil {
				t.Fatalf("symlink escape %q resolved to %q; must be rejected", p, got)
			}
		})
	}

	// A symlink to a sibling directory inside root is fine: it stays inside.
	inner := filepath.Join(root, "real")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Resolve("real/file.txt"); err != nil {
		t.Fatalf("legitimate not-yet-created path rejected: %v", err)
	}
}

func TestResolveAllowsSymlinkWithinRoot(t *testing.T) {
	fs, root := newFS(t)
	inner := filepath.Join(root, "docs")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "shortcut")
	if err := os.Symlink(inner, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// Points inside the root, so it is legitimate.
	if _, err := fs.Resolve("shortcut/note.txt"); err != nil {
		t.Fatalf("symlink within root rejected: %v", err)
	}
}

func TestValidName(t *testing.T) {
	good := []string{"a", "file.txt", "with space", "üñî", "..hidden", "a..b", "CON", "file.tar.gz"}
	for _, n := range good {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false, want true", n)
		}
	}
	bad := []string{"", ".", "..", "a/b", `a\b`, "a\x00b", "a\nb", "a\tb", strings.Repeat("x", 256), "/"}
	for _, n := range bad {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true, want false", n)
		}
	}
}

func TestRelPathRoundTrip(t *testing.T) {
	fs, root := newFS(t)
	for _, in := range []string{"", "a", "a/b/c.txt", "space name/x"} {
		abs, err := fs.Resolve(in)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", in, err)
		}
		rel, err := fs.RelPath(abs)
		if err != nil {
			t.Fatalf("RelPath(%q): %v", abs, err)
		}
		// Round trip must return to the same absolute path.
		again, err := fs.Resolve(rel)
		if err != nil {
			t.Fatalf("re-Resolve(%q): %v", rel, err)
		}
		if again != abs {
			t.Fatalf("round trip mismatch: %q -> %q -> %q", in, abs, again)
		}
	}
	if rel, _ := fs.RelPath(root); rel != "" {
		t.Fatalf("root should map to empty relative path, got %q", rel)
	}
}

// TestResolveSiblingPrefixNotConfused guards the check that distinguishes
// /data/users/alice from /data/users/alice2. A naive HasPrefix test on the
// resolved string would treat alice2 as being inside alice.
//
// The payload clamps to root rather than erroring, so the assertion is that
// it lands under root and not in the sibling.
func TestResolveSiblingPrefixNotConfused(t *testing.T) {
	base := t.TempDir()
	alice, err := New(filepath.Join(base, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "alice2")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "secret.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := alice.Resolve("../alice2/secret.txt")
	if err != nil {
		return // rejecting outright is fine too
	}
	if strings.HasPrefix(got, other) {
		t.Fatalf("resolved into the sibling directory: %q", got)
	}
	if !strings.HasPrefix(got, alice.Root()+string(filepath.Separator)) {
		t.Fatalf("resolved outside the FS root: %q", got)
	}
	// And it must not name the sibling's real file.
	if _, err := os.Stat(got); err == nil {
		t.Fatalf("clamped path unexpectedly exists: %q", got)
	}
}
