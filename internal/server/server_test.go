package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/derek/my-cloud/internal/config"
	"github.com/derek/my-cloud/internal/crypt"
	"github.com/derek/my-cloud/internal/store/sqlite"
)

// newTestServer builds a Server over a temp config dir.
func newTestServer(t *testing.T, withUsers bool) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MYCLOUD_CONFIG_DIR", dir)
	t.Setenv("MYCLOUD_DATA_DIR", filepath.Join(dir, "data"))

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	db, err := sqlite.Open(cfg.DBPath())
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sealer, err := crypt.New(cfg.Secret)
	if err != nil {
		t.Fatalf("crypt.New: %v", err)
	}

	s, err := New(cfg, db, sealer, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if withUsers {
		if _, err := s.app.Auth.CreateUser(t.Context(), "alice", "secret123", true, 0); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	return s
}

func TestStatusReportsNeedsSetup(t *testing.T) {
	s := newTestServer(t, false)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status code: %d", rec.Code)
	}
	var body struct {
		NeedsSetup bool   `json:"needsSetup"`
		SiteName   string `json:"siteName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// No users means the setup wizard is open — this is the signal that a
	// failed migration must never be able to trigger.
	if !body.NeedsSetup {
		t.Fatal("empty database should report needsSetup")
	}
	if body.SiteName != "My Cloud" {
		t.Fatalf("siteName: got %q", body.SiteName)
	}
}

func TestStatusClosedWhenUsersExist(t *testing.T) {
	s := newTestServer(t, true)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))

	var body struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body.NeedsSetup {
		t.Fatal("with a user present, setup must be closed to the world")
	}
}

func TestHealthOK(t *testing.T) {
	s := newTestServer(t, false)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz code: %d", rec.Code)
	}
}

func TestUnknownPathReturnsJSON404(t *testing.T) {
	s := newTestServer(t, false)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("404 should be JSON, got %q", ct)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	s := newTestServer(t, false)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))

	for _, h := range []string{
		"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
		"Content-Security-Policy", "X-Download-Options", "X-Permitted-Cross-Domain-Policies",
	} {
		if rec.Header().Get(h) == "" {
			t.Fatalf("missing security header %s", h)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	// The plan requires a CSP without unsafe-inline for scripts; htmx is
	// vendored locally in phase 6 precisely so this can hold.
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatal("CSP allows inline scripts")
	}
	if !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Fatal("CSP missing frame-ancestors")
	}
	if !strings.Contains(csp, "object-src 'none'") {
		t.Fatal("CSP missing object-src none")
	}
}

func TestMethodRoutingIsStrict(t *testing.T) {
	s := newTestServer(t, false)
	// Go 1.22 ServeMux patterns must not let a POST reach a GET-only route.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/status", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("POST matched a GET-only route")
	}
}

func TestStatusHandlesClosedDatabase(t *testing.T) {
	s := newTestServer(t, false)
	// Closing the database underneath the server must produce a clean error,
	// not a crash and not an internal detail in the response body.
	s.app.DB.Close()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	// An error body must not leak SQL or a stack trace.
	body := rec.Body.String()
	for _, leak := range []string{"goroutine", "sql", "SQLITE", "database/sql"} {
		if strings.Contains(body, leak) {
			t.Fatalf("response leaked %q: %s", leak, body)
		}
	}
}
