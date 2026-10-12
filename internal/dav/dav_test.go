package dav

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derek/my-cloud/internal/vfs"
)

// newTestDAV builds a handler over a temp files root with a single test user.
func newTestDAV(t *testing.T, user, pass string) (*Handler, *vfs.FS, string) {
	t.Helper()
	dir := t.TempDir()
	fs, err := vfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		UserRoot: func(string) (*vfs.FS, error) { return fs, nil },
		Auth: func(r *http.Request, u, p string) (string, bool) {
			if u == user && p == pass {
				return user, true
			}
			return "", false
		},
		Cache:       NewAuthCache(time.Minute, 16),
		MaxPutBytes: 1 << 20,
	}
	return h, fs, dir
}

// do issues a DAV request with Basic auth.
func do(h *Handler, method, path, user, pass string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+cred)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDAVRequiresAuth(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	rec := do(h, "PROPFIND", "/dav/", "", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PROPFIND returned %d", rec.Code)
	}
	// Without the realm, most clients never prompt for credentials.
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `Basic realm="My Cloud"`) {
		t.Fatalf("no realm in challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
	// Wrong credentials likewise.
	if rec := do(h, "PROPFIND", "/dav/", "alice", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad credentials returned %d", rec.Code)
	}
}

func TestDAVOptionsAdvertisesMethods(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	rec := do(h, "OPTIONS", "/dav/", "alice", "secret", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("OPTIONS returned %d", rec.Code)
	}
	allow := rec.Header().Get("Allow")
	for _, m := range []string{"PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PUT", "DELETE"} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow header missing %s: %q", m, allow)
		}
	}
	if !strings.Contains(rec.Header().Get("DAV"), "1") {
		t.Errorf("no DAV compliance header: %q", rec.Header().Get("DAV"))
	}
}

func TestDAVMkdirPutGetDelete(t *testing.T) {
	h, fs, _ := newTestDAV(t, "alice", "secret")

	// MKCOL
	if rec := do(h, "MKCOL", "/dav/Documents", "alice", "secret", nil); rec.Code != http.StatusCreated {
		t.Fatalf("MKCOL returned %d: %s", rec.Code, rec.Body)
	}
	if _, err := fs.Stat("Documents"); err != nil {
		t.Fatalf("collection not created: %v", err)
	}

	// PUT
	rec := do(h, "PUT", "/dav/Documents/note.txt", "alice", "secret", strings.NewReader("hello dav"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body)
	}
	e, err := fs.Stat("Documents/note.txt")
	if err != nil {
		t.Fatalf("PUT did not create the file: %v", err)
	}
	if e.Size != 9 {
		t.Fatalf("size after PUT is %d", e.Size)
	}

	// GET
	rec = do(h, "GET", "/dav/Documents/note.txt", "alice", "secret", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "hello dav" {
		t.Fatalf("GET returned %d %q", rec.Code, rec.Body.String())
	}

	// HEAD
	rec = do(h, "HEAD", "/dav/Documents/note.txt", "alice", "secret", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD returned %d", rec.Code)
	}

	// DELETE
	if rec := do(h, "DELETE", "/dav/Documents/note.txt", "alice", "secret", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", rec.Code)
	}
	if _, err := fs.Stat("Documents/note.txt"); err != vfs.ErrNotFound {
		t.Fatal("file survived DELETE")
	}
}

func TestDAVPropfind(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	do(h, "MKCOL", "/dav/Folder", "alice", "secret", nil)
	do(h, "PUT", "/dav/Folder/a.txt", "alice", "secret", strings.NewReader("a"))
	do(h, "PUT", "/dav/Folder/b.txt", "alice", "secret", strings.NewReader("bb"))

	req := httptest.NewRequest("PROPFIND", "/dav/Folder", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("Depth", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND returned %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"multistatus", "a.txt", "b.txt", "getcontentlength", "resourcetype", "getlastmodified", "getetag"} {
		if !strings.Contains(body, want) {
			t.Errorf("PROPFIND response missing %q", want)
		}
	}
	// Depth 1 lists the collection plus its children.
	if n := strings.Count(body, "<D:response>"); n != 3 {
		t.Errorf("expected 3 responses (self + 2 children), got %d", n)
	}

	// Depth 0 returns only the collection itself.
	req = httptest.NewRequest("PROPFIND", "/dav/Folder", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("Depth", "0")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if n := strings.Count(rec.Body.String(), "<D:response>"); n != 1 {
		t.Errorf("Depth 0 returned %d responses, want 1", n)
	}
}

func TestDAVCopyMove(t *testing.T) {
	h, fs, _ := newTestDAV(t, "alice", "secret")
	do(h, "MKCOL", "/dav/src", "alice", "secret", nil)
	do(h, "MKCOL", "/dav/dst", "alice", "secret", nil)
	do(h, "PUT", "/dav/src/file.txt", "alice", "secret", strings.NewReader("payload"))

	// COPY
	req := httptest.NewRequest("COPY", "/dav/src/file.txt", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("Destination", "http://host/dav/dst/copied.txt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("COPY returned %d: %s", rec.Code, rec.Body)
	}
	if _, err := fs.Stat("dst/copied.txt"); err != nil {
		t.Fatalf("copy not created: %v", err)
	}
	// The source must survive a COPY.
	if _, err := fs.Stat("src/file.txt"); err != nil {
		t.Fatal("COPY removed the source")
	}

	// MOVE
	req = httptest.NewRequest("MOVE", "/dav/src/file.txt", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("Destination", "http://host/dav/dst/moved.txt")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("MOVE returned %d: %s", rec.Code, rec.Body)
	}
	if _, err := fs.Stat("dst/moved.txt"); err != nil {
		t.Fatalf("moved file missing: %v", err)
	}
	if _, err := fs.Stat("src/file.txt"); err != vfs.ErrNotFound {
		t.Fatal("MOVE left the source behind")
	}
}

func TestDAVDestinationMustStayInMount(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	do(h, "PUT", "/dav/f.txt", "alice", "secret", strings.NewReader("x"))

	for _, dest := range []string{
		"http://host/other/f.txt",
		"http://host/",
		"not-a-url",
		"",
	} {
		req := httptest.NewRequest("MOVE", "/dav/f.txt", nil)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
		if dest != "" {
			req.Header.Set("Destination", dest)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusCreated {
			t.Errorf("MOVE with Destination %q was accepted", dest)
		}
	}
}

func TestDAVCopyIntoItselfRefused(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	do(h, "MKCOL", "/dav/tree", "alice", "secret", nil)
	req := httptest.NewRequest("COPY", "/dav/tree", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("Destination", "http://host/dav/tree/inner")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatal("copying a collection into itself was allowed; it would recurse forever")
	}
}

func TestDAVTraversalRejected(t *testing.T) {
	h, _, dir := newTestDAV(t, "alice", "secret")
	// A file outside the root that traversal would reach.
	outside := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/dav/../secret.txt",
		"/dav/../../etc/passwd",
		"/dav/%2e%2e/secret.txt",
	} {
		rec := do(h, "GET", p, "alice", "secret", nil)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "TOP SECRET") {
			t.Fatalf("traversal %q served a file outside the root", p)
		}
	}
	// The root itself must not be deletable through DAV.
	if rec := do(h, "DELETE", "/dav/", "alice", "secret", nil); rec.Code == http.StatusNoContent {
		t.Fatal("DAV DELETE removed the collection root")
	}
}

func TestDAVLockUnlock(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	do(h, "PUT", "/dav/f.txt", "alice", "secret", strings.NewReader("x"))

	body := strings.NewReader(`<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`)
	rec := do(h, "LOCK", "/dav/f.txt", "alice", "secret", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("LOCK returned %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Lock-Token"), "opaquelocktoken:") {
		t.Errorf("no Lock-Token header: %q", rec.Header().Get("Lock-Token"))
	}
	if !strings.Contains(rec.Body.String(), "lockdiscovery") {
		t.Errorf("no lockdiscovery in body: %s", rec.Body)
	}

	// UNLOCK always succeeds: no lock state is retained, so a stale lock can
	// never wedge the mount.
	if rec := do(h, "UNLOCK", "/dav/f.txt", "alice", "secret", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("UNLOCK returned %d", rec.Code)
	}
}

func TestDAVProppatchReportsForbidden(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	do(h, "PUT", "/dav/f.txt", "alice", "secret", strings.NewReader("x"))
	body := strings.NewReader(`<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:custom>x</D:custom></D:prop></D:set></D:propertyupdate>`)
	rec := do(h, "PROPPATCH", "/dav/f.txt", "alice", "secret", body)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("PROPPATCH returned %d", rec.Code)
	}
	// Properties are not stored; the response says so rather than pretending.
	if !strings.Contains(rec.Body.String(), "403 Forbidden") {
		t.Errorf("PROPPATCH did not report the properties as unsupported: %s", rec.Body)
	}
}

func TestDAVAuthCacheBounds(t *testing.T) {
	c := NewAuthCache(time.Minute, 4)
	for i := 0; i < 50; i++ {
		c.put(authKey("header-"+string(rune('a'+i))), "alice")
	}
	c.mu.Lock()
	n := len(c.items)
	c.mu.Unlock()
	// The bound is what stops an unauthenticated client from exhausting memory
	// by replaying distinct bogus headers.
	if n > 4 {
		t.Fatalf("cache grew to %d entries, bound is 4", n)
	}
}

func TestDAVAuthCacheHit(t *testing.T) {
	calls := 0
	verify := func(r *http.Request, u, p string) (string, bool) {
		calls++
		return "alice", true
	}
	c := NewAuthCache(time.Minute, 16)
	req := httptest.NewRequest("PROPFIND", "/dav/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))

	// A WebDAV client re-sends credentials on every request; the cache is what
	// keeps that from costing a hash verification each time.
	for i := 0; i < 5; i++ {
		if _, ok := authenticate(req, c, verify); !ok {
			t.Fatal("authentication failed")
		}
	}
	if calls != 1 {
		t.Fatalf("verifier called %d times over 5 requests, want 1", calls)
	}
}

func TestDAVPutWithoutParentConflicts(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	// Clients are expected to MKCOL first; auto-creating parents would mask a
	// genuinely wrong path.
	rec := do(h, "PUT", "/dav/missing/file.txt", "alice", "secret", strings.NewReader("x"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT into a missing collection returned %d, want 409", rec.Code)
	}
}

// TestDAVMissingPathIs404Not500 guards a bug found against rclone: PROPFIND on
// a path that does not exist returned 500, so rclone treated an ordinary "no
// such file" as a server fault and retried it three times.
func TestDAVMissingPathIs404Not500(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	for _, p := range []string{"/dav/missing", "/dav/a/b/c"} {
		if rec := do(h, "PROPFIND", p, "alice", "secret", nil); rec.Code != http.StatusNotFound {
			t.Errorf("PROPFIND %s returned %d, want 404", p, rec.Code)
		}
		if rec := do(h, "GET", p, "alice", "secret", nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s returned %d, want 404", p, rec.Code)
		}
		if rec := do(h, "DELETE", p, "alice", "secret", nil); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s returned %d, want 404", p, rec.Code)
		}
	}
}

func TestDAVMethodNotAllowed(t *testing.T) {
	h, _, _ := newTestDAV(t, "alice", "secret")
	rec := do(h, "BREW", "/dav/", "alice", "secret", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unknown method returned %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Allow"), "PROPFIND") {
		t.Errorf("no Allow header on 405: %q", rec.Header().Get("Allow"))
	}
}
