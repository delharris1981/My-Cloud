package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// loginAs signs in and returns the session cookie plus CSRF token.
func loginAs(t *testing.T, s *Server, username, password string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rec := post(s, "/api/auth/login", form("username", username, "password", password))
	if rec.Code != 200 {
		t.Fatalf("login %s failed: %d %s", username, rec.Code, rec.Body)
	}
	c := sessionCookie(t, rec)
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req = withCookie(req, c)
	meRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(meRec, req)
	var me struct {
		CSRFToken string `json:"csrfToken"`
	}
	json.Unmarshal(meRec.Body.Bytes(), &me)
	return rec, me.CSRFToken
}

// authed issues an authenticated request with the cookie and CSRF token.
func authed(method, path, cookieValue, csrf, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookieValue != "" {
		r.AddCookie(&http.Cookie{Name: "mycloud_session", Value: cookieValue})
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	r.RemoteAddr = "10.0.0.5:9999"
	return r
}

func TestFileLifecycle(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, csrf := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	srv := s.Handler()

	// 1. mkdir
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/mkdir", cookie, csrf,
		url.Values{"name": {"Documents"}, "path": {""}}.Encode()))
	if rec.Code != 200 {
		t.Fatalf("mkdir: %d %s", rec.Code, rec.Body)
	}

	// 2. list it
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/list?path=Documents", cookie, csrf, ""))
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var listing struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		Usage map[string]any `json:"usage"`
	}
	json.Unmarshal(rec.Body.Bytes(), &listing)
	if len(listing.Items) != 0 {
		t.Fatalf("new dir not empty: %+v", listing.Items)
	}
	if listing.Usage["used"] == nil {
		t.Fatal("usage not reported alongside listing")
	}

	// 3. upload a file
	upload := func(path, name, content string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		fw, _ := w.CreateFormFile("files", name)
		fw.Write([]byte(content))
		w.Close()
		r := httptest.NewRequest("POST", "/api/files/upload?path="+url.QueryEscape(path), &buf)
		r.Header.Set("Content-Type", w.FormDataContentType())
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: "mycloud_session", Value: cookie})
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		return rec
	}
	rec = upload("Documents", "notes.txt", "hello world")
	if rec.Code != 200 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}

	// 4. download it back
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/download?path=Documents/notes.txt", cookie, csrf, ""))
	if rec.Code != 200 {
		t.Fatalf("download: %d", rec.Code)
	}
	if rec.Body.String() != "hello world" {
		t.Fatalf("content mismatch: %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("wrong content type: %q", ct)
	}

	// 5. rename
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/rename", cookie, csrf,
		url.Values{"path": {"Documents/notes.txt"}, "name": {"renamed.txt"}}.Encode()))
	if rec.Code != 200 {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}

	// 6. move to root
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/move", cookie, csrf,
		"paths[]=Documents/renamed.txt&dest="))
	if rec.Code != 200 {
		t.Fatalf("move: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/list", cookie, csrf, ""))
	var root struct {
		Items []struct {
			Name  string `json:"name"`
			IsDir bool   `json:"isDir"`
		} `json:"items"`
	}
	json.Unmarshal(rec.Body.Bytes(), &root)
	found := false
	for _, it := range root.Items {
		if it.Name == "renamed.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("file not at root after move: %+v", root.Items)
	}
}

func TestFileAPIRequiresAuth(t *testing.T) {
	s := newTestServer(t, true)
	srv := s.Handler()
	for _, p := range []string{
		"/api/files/list", "/api/files/usage", "/api/files/search?q=x", "/api/trash/list",
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 401 {
			t.Errorf("%s without a session returned %d, want 401", p, rec.Code)
		}
	}
}

func TestFileMutationRequiresCSRF(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	srv := s.Handler()
	for _, p := range []string{"/api/files/mkdir", "/api/files/rename", "/api/files/delete"} {
		rec := httptest.NewRecorder()
		// Valid cookie, no CSRF token.
		srv.ServeHTTP(rec, authed("POST", p, cookie, "", "name=x&path="))
		if rec.Code != 403 {
			t.Errorf("%s without CSRF returned %d, want 403", p, rec.Code)
		}
	}
}

// TestFileAPIIsolatesUsers is the core multi-tenant property: one user must
// never see or reach another user's files.
func TestFileAPIIsolatesUsers(t *testing.T) {
	s := newTestServer(t, true)
	ctx := t.Context()
	if _, err := s.app.Auth.CreateUser(ctx, "bob", "bobpass123", false, 0); err != nil {
		t.Fatal(err)
	}
	srv := s.Handler()

	aliceRec, _ := loginAs(t, s, "alice", "secret123")
	aliceCookie := sessionCookieValue(aliceRec, t)
	bobRec, _ := loginAs(t, s, "bob", "bobpass123")
	bobCookie := sessionCookieValue(bobRec, t)

	// Alice uploads a private file.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("files", "secret.txt")
	fw.Write([]byte("alice private data"))
	w.Close()
	r := httptest.NewRequest("POST", "/api/files/upload", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: "mycloud_session", Value: aliceCookie})
	aliceCSRF := csrfFor(t, srv, aliceCookie)
	r.Header.Set("X-CSRF-Token", aliceCSRF)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("alice upload: %d %s", rec.Code, rec.Body)
	}

	// Bob cannot download it.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/download?path=secret.txt", bobCookie, "", ""))
	if rec.Code == 200 {
		t.Fatal("bob downloaded alice's file; users are not isolated")
	}

	// Bob cannot list it either.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/list", bobCookie, "", ""))
	if strings.Contains(rec.Body.String(), "secret.txt") {
		t.Fatal("alice's file appeared in bob's listing")
	}

	// Bob cannot delete it.
	bobCSRF := csrfFor(t, srv, bobCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/delete", bobCookie, bobCSRF, "paths[]=secret.txt"))
	if rec.Code == 200 {
		var body struct {
			OK bool `json:"ok"`
		}
		json.Unmarshal(rec.Body.Bytes(), &body)
		if body.OK {
			t.Fatal("bob deleted alice's file")
		}
	}
	// And it still exists for alice.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/download?path=secret.txt", aliceCookie, aliceCSRF, ""))
	if rec.Code != 200 {
		t.Fatal("alice's file was destroyed by bob's delete attempt")
	}
}

func TestFileTraversalRejected(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	csrf := csrfFor(t, s.Handler(), cookie)
	srv := s.Handler()

	// Traversal on read paths.
	for _, p := range []string{
		"/api/files/download?path=../../../etc/passwd",
		"/api/files/content?path=../../../etc/passwd",
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, authed("GET", p, cookie, csrf, ""))
		if rec.Code == 200 && strings.Contains(rec.Body.String(), "root:") {
			t.Fatalf("traversal served a host file: %s", p)
		}
	}
	// Traversal on write paths.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/rename", cookie, csrf,
		url.Values{"path": {"../../etc/passwd"}, "name": {"pwned"}}.Encode()))
	if rec.Code == 200 {
		t.Fatal("rename accepted a traversal path")
	}
	// A name with a separator must be refused.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/mkdir", cookie, csrf,
		url.Values{"name": {"../escape"}, "path": {""}}.Encode()))
	if rec.Code == 200 {
		t.Fatal("mkdir accepted a name containing a traversal")
	}
}

func TestTrashFlowOverHTTP(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	csrf := csrfFor(t, s.Handler(), cookie)
	srv := s.Handler()

	// Create a file to trash.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("files", "doomed.txt")
	fw.Write([]byte("bye"))
	w.Close()
	r := httptest.NewRequest("POST", "/api/files/upload", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(&http.Cookie{Name: "mycloud_session", Value: cookie})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)

	// Delete moves to trash.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/delete", cookie, csrf, "paths[]=doomed.txt"))
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	// Gone from files.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/list", cookie, csrf, ""))
	if strings.Contains(rec.Body.String(), "doomed.txt") {
		t.Fatal("deleted file still listed")
	}
	// Present in trash.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/trash/list", cookie, csrf, ""))
	var trash struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	json.Unmarshal(rec.Body.Bytes(), &trash)
	if len(trash.Items) != 1 || trash.Items[0].Name != "doomed.txt" {
		t.Fatalf("trash listing wrong: %+v", trash.Items)
	}

	// Restore.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/trash/restore", cookie, csrf, "ids[]="+trash.Items[0].ID))
	if rec.Code != 200 {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/download?path=doomed.txt", cookie, csrf, ""))
	if rec.Code != 200 || rec.Body.String() != "bye" {
		t.Fatalf("restore did not bring the file back: %d %q", rec.Code, rec.Body.String())
	}
}

func TestContentWriteAtomicAndQuotaChecked(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	csrf := csrfFor(t, s.Handler(), cookie)
	srv := s.Handler()

	// Write a new file.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("PUT", "/api/files/content?path=note.txt", cookie, csrf, "hello editor"))
	if rec.Code != 200 {
		t.Fatalf("content write: %d %s", rec.Code, rec.Body)
	}
	// Read it back.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/content?path=note.txt", cookie, csrf, ""))
	if rec.Body.String() != "hello editor" {
		t.Fatalf("content round trip failed: %q", rec.Body.String())
	}
}

func TestResumableUploadOverHTTP(t *testing.T) {
	s := newTestServer(t, true)
	loginRec, _ := loginAs(t, s, "alice", "secret123")
	cookie := sessionCookieValue(loginRec, t)
	csrf := csrfFor(t, s.Handler(), cookie)
	srv := s.Handler()

	// Create a session.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/upload/session?filename=big.bin", cookie, csrf, "total=11"))
	if rec.Code != 200 {
		t.Fatalf("session create: %d %s", rec.Code, rec.Body)
	}
	var sess struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &sess)
	if sess.ID == "" {
		t.Fatal("no session id")
	}

	// Send chunk 1.
	r := authed("PUT", "/api/files/upload/session/"+sess.ID, cookie, csrf, "hello ")
	r.Header.Set("Content-Range", "bytes 0-5/11")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("chunk 1: %d %s", rec.Code, rec.Body)
	}

	// Status reports the offset a reconnecting client needs.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/upload/session/"+sess.ID, cookie, csrf, ""))
	var st struct {
		Offset int64 `json:"offset"`
	}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Offset != 6 {
		t.Fatalf("offset wrong: %d", st.Offset)
	}

	// A chunk at the wrong offset is refused.
	r = authed("PUT", "/api/files/upload/session/"+sess.ID, cookie, csrf, "x")
	r.Header.Set("Content-Range", "bytes 0-0/11")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	if rec.Code == 200 {
		t.Fatal("chunk at the wrong offset was accepted")
	}

	// Send the rest and complete.
	r = authed("PUT", "/api/files/upload/session/"+sess.ID, cookie, csrf, "world")
	r.Header.Set("Content-Range", "bytes 6-10/11")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("chunk 2: %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("POST", "/api/files/upload/session/"+sess.ID+"/complete?filename=big.bin", cookie, csrf, ""))
	if rec.Code != 200 {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}

	// The assembled file is correct.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/files/download?path=big.bin", cookie, csrf, ""))
	if rec.Body.String() != "hello world" {
		t.Fatalf("assembled file wrong: %q", rec.Body.String())
	}
}

func TestUploadEnforcesQuota(t *testing.T) {
	s := newTestServer(t, true)
	ctx := t.Context()
	// Give alice a tiny quota.
	if _, err := s.app.Auth.CreateUser(ctx, "tiny", "tinypass123", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.app.Auth.UpdateUser(ctx, "tiny", nil, intp(1)); err != nil { // 1 MB
		t.Fatal(err)
	}
	loginRec, _ := loginAs(t, s, "tiny", "tinypass123")
	cookie := sessionCookieValue(loginRec, t)
	csrf := csrfFor(t, s.Handler(), cookie)

	// A file bigger than the quota must be refused and leave nothing behind.
	big := strings.Repeat("A", 2*1024*1024)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("files", "toobig.bin")
	fw.Write([]byte(big))
	w.Close()
	r := httptest.NewRequest("POST", "/api/files/upload", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(&http.Cookie{Name: "mycloud_session", Value: cookie})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	if rec.Code == 200 {
		t.Fatal("upload exceeding quota was accepted")
	}

	// Nothing must be left on disk.
	_, files, _, _ := s.app.Cfg.UserDirs("tiny")
	entries, _ := readDirNames(files)
	for _, e := range entries {
		if e == "toobig.bin" {
			t.Fatal("refused upload left the file on disk")
		}
	}
}
