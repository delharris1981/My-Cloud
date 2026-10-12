package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestNoJSAcceptance walks the full user journey using nothing but form POSTs
// and plain GETs, exactly as a browser with scripting disabled would.
//
// This is the phase 3 exit gate, executed as a test rather than a manual
// check: if a future change breaks the no-JS path, this fails.
func TestNoJSAcceptance(t *testing.T) {
	s := newTestServer(t, false)
	srv := s.Handler()
	jar := &cookieJar{t: t}

	// 1. The setup wizard creates the first admin.
	body := loginGET(t, srv, jar)
	if !strings.Contains(body, `action="/setup"`) {
		t.Fatal("setup form not offered on a fresh install")
	}
	postForm(t, srv, jar, "/setup", url.Values{
		"csrf_token": {jar.last("mycloud_login_csrf")},
		"username":   {"alice"},
		"password":   {"secret123"},
	})

	// 2. Sign out, then sign in through the form.
	postForm(t, srv, jar, "/logout", url.Values{
		"csrf_token": {csrfOnPage(t, srv, jar, "/files")},
	})
	loginGET(t, srv, jar)
	postForm(t, srv, jar, "/login", url.Values{
		"csrf_token": {jar.last("mycloud_login_csrf")},
		"username":   {"alice"},
		"password":   {"secret123"},
	})

	// 3. Browse: the files page renders and offers an upload form.
	recPage := get(t, srv, jar, "/files")
	page := recPage.Body.String()
	csrfOnPage(t, srv, jar, "/files") // asserts a token is present on the page
	if !strings.Contains(page, `enctype="multipart/form-data"`) {
		t.Fatal("upload form missing; the no-JS upload path is broken")
	}
	if !strings.Contains(page, `action="/files/mkdir"`) {
		t.Fatal("mkdir form missing")
	}

	// 4. Create a folder.
	postForm(t, srv, jar, "/files/mkdir", url.Values{
		"csrf_token": {csrfOnPage(t, srv, jar, "/files")},
		"path":       {""},
		"name":       {"Documents"},
	})
	// Filenames render as attributes (checkbox value, data-path), not as bare
	// text, so assert on the attribute rather than a loose substring.
	page = pageBody(t, srv, jar, "/files?path=Documents")
	csrfOnPage(t, srv, jar, "/files?path=Documents")
	if !strings.Contains(page, `value="Documents"`) {
		t.Fatal("created folder not listed")
	}

	// 5. Upload via a plain multipart POST.
	csrf := csrfOnPage(t, srv, jar, "/files?path=Documents")
	uploadForm(t, srv, jar, "/files/upload?path=Documents", csrf, map[string]string{
		"notes.txt": "the quick brown fox",
	})
	page = pageBody(t, srv, jar, "/files?path=Documents")
	csrfOnPage(t, srv, jar, "/files?path=Documents")
	if !strings.Contains(page, `value="notes.txt"`) {
		t.Fatal("uploaded file not listed")
	}

	// 6. Rename.
	postForm(t, srv, jar, "/files/rename", url.Values{
		"csrf_token": {csrfOnPage(t, srv, jar, "/files?path=Documents")},
		"path":       {"Documents/notes.txt"},
		"name":       {"renamed.txt"},
	})
	page = pageBody(t, srv, jar, "/files?path=Documents")
	csrfOnPage(t, srv, jar, "/files?path=Documents")
	if !strings.Contains(page, `value="renamed.txt"`) || strings.Contains(page, `value="notes.txt"`) {
		t.Fatal("rename did not take effect")
	}

	// 7. Download returns the content.
	rec := get(t, srv, jar, "/api/files/download?path=Documents/renamed.txt")
	if rec.Body.String() != "the quick brown fox" {
		t.Fatalf("download content wrong: %q", rec.Body.String())
	}

	// 8. Delete moves to trash; it must not be in the listing afterwards.
	postForm(t, srv, jar, "/files/delete", url.Values{
		"csrf_token": {csrfOnPage(t, srv, jar, "/files?path=Documents")},
		"paths[]":    {"Documents/renamed.txt"},
	})
	page = pageBody(t, srv, jar, "/files?path=Documents")
	csrfOnPage(t, srv, jar, "/files?path=Documents")
	if strings.Contains(page, `value="renamed.txt"`) {
		t.Fatal("deleted file still listed")
	}

	// 9. The trash page lists it with a restore control.
	trashPage := pageBody(t, srv, jar, "/trash")
	if !strings.Contains(trashPage, "renamed.txt") {
		t.Fatal("trash page does not list the deleted file")
	}
	if !strings.Contains(trashPage, `action="/trash/restore"`) {
		t.Fatal("no restore form in the trash view")
	}

	// 10. Restore puts it back, contents intact.
	id := between(trashPage, `name="ids[]" value="`, `"`)
	postForm(t, srv, jar, "/trash/restore", url.Values{
		"csrf_token": {csrfOnPage(t, srv, jar, "/trash")},
		"ids[]":      {id},
	})
	rec = get(t, srv, jar, "/api/files/download?path=Documents/renamed.txt")
	if rec.Code != 200 || rec.Body.String() != "the quick brown fox" {
		t.Fatalf("restore did not return the file: %d %q", rec.Code, rec.Body.String())
	}

	// 11. A share link can be created and fetched anonymously.
	shJSON := postForm(t, srv, jar, "/api/shares", url.Values{
		"csrf_token": {csrfOnPage(t, srv, jar, "/files?path=Documents")},
		"paths[]":    {"Documents/renamed.txt"},
	})
	var created struct {
		Share struct {
			Token string `json:"token"`
		} `json:"share"`
	}
	if err := json.Unmarshal([]byte(shJSON), &created); err != nil {
		t.Fatalf("share create response: %v (%s)", err, shJSON)
	}
	if created.Share.Token == "" {
		t.Fatal("no share token returned")
	}
	anon := &cookieJar{t: t}
	rec = get(t, srv, anon, "/s/"+created.Share.Token)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "renamed.txt") {
		t.Fatalf("public share page wrong: %d", rec.Code)
	}
	rec = get(t, srv, anon, "/s/"+created.Share.Token+"/download")
	if rec.Code != 200 || rec.Body.String() != "the quick brown fox" {
		t.Fatalf("anonymous download wrong: %d %q", rec.Code, rec.Body.String())
	}

	// 12. A drop-box share accepts an anonymous upload.
	shJSON = postForm(t, srv, jar, "/api/shares", url.Values{
		"csrf_token":  {csrfOnPage(t, srv, jar, "/files")},
		"paths[]":     {""},
		"allowUpload": {"1"},
	})
	var drop struct {
		Share struct {
			Token string `json:"token"`
		} `json:"share"`
	}
	json.Unmarshal([]byte(shJSON), &drop)
	if drop.Share.Token == "" {
		t.Fatalf("drop-box share not created: %s", shJSON)
	}
	anon2 := &cookieJar{t: t}
	uploadForm(t, srv, anon2, "/s/"+drop.Share.Token+"/upload", "", map[string]string{
		"dropped.txt": "uploaded by a visitor",
	})
	rec = get(t, srv, jar, "/api/files/download?path=dropped.txt")
	if rec.Code != 200 || rec.Body.String() != "uploaded by a visitor" {
		t.Fatalf("drop-box upload did not land: %d %q", rec.Code, rec.Body.String())
	}
}

// TestMutationWithoutCSRFIsRefused proves the no-JS forms are still protected:
// working without JavaScript must not mean working without CSRF.
func TestMutationWithoutCSRFIsRefused(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	srv := s.Handler()
	for _, p := range []string{"/files/mkdir", "/files/rename", "/files/delete", "/files/upload", "/logout"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, authed("POST", p, cookie, "", "name=x&path="))
		if rec.Code != 403 {
			t.Errorf("%s without a CSRF token returned %d, want 403", p, rec.Code)
		}
	}
}

// TestPagesAreCompleteHTML guards against a template rendering only a
// fragment: a missing layout means no doctype, no CSS, no JS.
func TestPagesAreCompleteHTML(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	srv := s.Handler()
	for _, p := range []string{"/files", "/trash", "/shares", "/settings", "/admin"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, authed("GET", p, cookie, "", ""))
		if rec.Code != 200 {
			t.Errorf("%s returned %d", p, rec.Code)
			continue
		}
		body := rec.Body.String()
		for _, want := range []string{"<!DOCTYPE html>", "</html>", "/static/style.css"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", p, want)
			}
		}
	}
}

// TestZipStreamProducesValidArchive checks the streamed zip is readable.
func TestZipStreamProducesValidArchive(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	csrf := csrfFor(t, s.Handler(), cookie)
	jar := &cookieJar{t: t}
	jar.jar = map[string]string{"mycloud_session": cookie}

	// Two files in a folder.
	uploadForm(t, s.Handler(), jar, "/files/upload?path=pack", csrf, map[string]string{
		"one.txt": "first file",
	})
	csrf = csrfOnPage(t, s.Handler(), jar, "/files?path=pack")
	uploadForm(t, s.Handler(), jar, "/files/upload?path=pack", csrf, map[string]string{
		"two.txt": "second file",
	})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, authed("POST", "/api/files/zip", cookie, csrf, "paths[]=pack"))
	if rec.Code != 200 {
		t.Fatalf("zip: %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content type %q", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("archive is not readable: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["pack/one.txt"] || !names["pack/two.txt"] {
		t.Fatalf("archive contents wrong: %v", names)
	}
}

// --- small helpers ---

// cookieJar is a minimal cookie store: enough to drive a browser-like
// sequence without pulling in a dependency.
type cookieJar struct {
	t     *testing.T
	jar   map[string]string
	token string
}

func (j *cookieJar) last(name string) string {
	j.t.Helper()
	if j.jar == nil {
		j.t.Fatalf("no cookies stored (looking for %s)", name)
	}
	v, ok := j.jar[name]
	if !ok {
		j.t.Fatalf("cookie %s not set; have %v", name, keys(j.jar))
	}
	return v
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (j *cookieJar) add(rec *httptest.ResponseRecorder) {
	if j.jar == nil {
		j.jar = map[string]string{}
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j.jar, c.Name)
			continue
		}
		j.jar[c.Name] = c.Value
	}
}

func (j *cookieJar) header() string {
	var parts []string
	for k, v := range j.jar {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

// loginGET fetches a page (so the login CSRF cookie is set) and returns it.
func loginGET(t *testing.T, srv http.Handler, jar *cookieJar) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/login", nil)
	req.Header.Set("Accept", "text/html")
	if h := jar.header(); h != "" {
		req.Header.Set("Cookie", h)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	jar.add(rec)
	return rec.Body.String()
}

func get(t *testing.T, srv http.Handler, jar *cookieJar, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if h := jar.header(); h != "" {
		req.Header.Set("Cookie", h)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	jar.add(rec)
	return rec
}

// csrfOnPage fetches a page and extracts the session CSRF token from it.
func csrfOnPage(t *testing.T, srv http.Handler, jar *cookieJar, path string) string {
	t.Helper()
	rec := get(t, srv, jar, path)
	body := rec.Body.String()
	i := strings.Index(body, `name="csrf_token" value="`)
	if i < 0 {
		t.Fatalf("no CSRF token on %s (status %d)", path, rec.Code)
	}
	return between(body[i:], `value="`, `"`)
}

// pageBody fetches a page and returns its HTML.
func pageBody(t *testing.T, srv http.Handler, jar *cookieJar, path string) string {
	t.Helper()
	return get(t, srv, jar, path).Body.String()
}

func between(s, prefix, suffix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	s = s[i+len(prefix):]
	j := strings.Index(s, suffix)
	if j < 0 {
		return ""
	}
	return s[:j]
}

// postForm issues a form POST, following no redirects.
func postForm(t *testing.T, srv http.Handler, jar *cookieJar, path string, form url.Values) string {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if h := jar.header(); h != "" {
		req.Header.Set("Cookie", h)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	jar.add(rec)
	if rec.Code >= 400 {
		t.Fatalf("POST %s failed: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// uploadForm posts a multipart body.
func uploadForm(t *testing.T, srv http.Handler, jar *cookieJar, path, csrf string, files map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(fw, content)
	}
	w.Close()
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
		req.Form = url.Values{"csrf_token": {csrf}}
	}
	if h := jar.header(); h != "" {
		req.Header.Set("Cookie", h)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	jar.add(rec)
	if rec.Code >= 400 {
		t.Fatalf("upload to %s failed: %d %s", path, rec.Code, rec.Body.String())
	}
}
