package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// sessionCookieValue extracts the raw session token from a login response.
func sessionCookieValue(rec *httptest.ResponseRecorder, t *testing.T) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "mycloud_session" {
			return c.Value
		}
	}
	t.Fatalf("no session cookie in login response: %s", rec.Body)
	return ""
}

// csrfFor fetches the CSRF token for a session cookie by calling /me, which is
// the same call the frontend makes on boot.
func csrfFor(t *testing.T, srv http.Handler, cookie string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authed("GET", "/api/auth/me", cookie, "", ""))
	if rec.Code != 200 {
		t.Fatalf("fetching CSRF token failed: %d %s", rec.Code, rec.Body)
	}
	var me struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decoding /me: %v", err)
	}
	if me.CSRFToken == "" {
		t.Fatal("no CSRF token issued")
	}
	return me.CSRFToken
}

// readDirNames lists the entries of a directory by name.
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func intp(v int) *int { return &v }
