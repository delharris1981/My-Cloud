// Package server wires the HTTP surface.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/config"
	"github.com/derek/my-cloud/internal/crypt"
	"github.com/derek/my-cloud/internal/middleware"
	"github.com/derek/my-cloud/internal/share"
	"github.com/derek/my-cloud/internal/store/sqlite"
	"github.com/derek/my-cloud/internal/version"
	"github.com/derek/my-cloud/internal/vfs"
	"github.com/derek/my-cloud/web"
)

// Server owns the mux and its dependencies.
type Server struct {
	app *App
	log *log.Logger
}

// New builds a Server from a config, database, and sealer.
func New(cfg *config.Config, db *sqlite.DB, sealer *crypt.Sealer, logger *log.Logger) (*Server, error) {
	app := &App{
		Cfg:   cfg,
		DB:    db,
		Auth:  auth.NewStore(db.DB),
		TOTP:  auth.NewTOTPStore(db.DB, sealer),
		AppPw: auth.NewAppPasswordStore(db.DB),
		Audit: auth.NewAuditLogger(db.DB, logger),
		// 240/min for the general public surface; the tighter per-route
		// limits for upload and zip download come in phase 3.
		LoginLimit: auth.NewRateLimiter(),
		Public:     auth.NewPublicLimiter(240, time.Minute),
		usageCache: vfs.NewQuotaCache(30 * time.Second),
		Shares:     share.New(db.DB),
		Passkeys:   auth.NewPasskeyStore(db.DB, sealer),
		Sealer:     sealer,
		Log:        logger,
	}
	// Assets are parsed once at startup: a template error should crash the
	// boot, not surface as a 500 to whoever browses that page first.
	tmpl, err := initTemplates(logger)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	static, err := initStatic(logger)
	if err != nil {
		return nil, fmt.Errorf("mount static assets: %w", err)
	}
	app.templates = tmpl
	app.static = static
	app.icons = web.Embedded()
	return &Server{app: app, log: logger}, nil
}

// StartHousekeeping launches the periodic maintenance loop (trash retention,
// session cleanup, stale upload parts) and returns a stop function.
func (s *Server) StartHousekeeping() (stop func()) { return s.app.StartHousekeeping() }

// Handler returns the fully-middleware-wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	a := s.app

	// --- public ---
	mux.HandleFunc("GET /api/status", a.handleStatus)
	mux.HandleFunc("GET /api/version", version.Handler)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// --- HTML pages ---
	// These are the no-JS front doors. Every mutation is a real form POST that
	// redirects, so the whole app is usable with scripting disabled.
	mux.HandleFunc("GET /{$}", a.rootRedirect)
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.htmlLogin)
	mux.HandleFunc("POST /setup", a.htmlSetup)
	mux.HandleFunc("POST /logout", a.htmlLogout)
	mux.HandleFunc("GET /files", a.handleFilesPage)
	mux.HandleFunc("GET /trash", a.handleTrashPage)
	mux.HandleFunc("GET /shares", a.handleSharesPage)
	mux.HandleFunc("GET /search", a.handleSearchPage)
	mux.HandleFunc("GET /settings", a.handleSettingsPage)
	mux.HandleFunc("GET /admin", a.handleAdminPage)

	mux.HandleFunc("POST /files/mkdir", a.htmlMkdir)
	mux.HandleFunc("POST /files/rename", a.htmlRename)
	mux.HandleFunc("POST /files/delete", a.htmlDelete)
	mux.HandleFunc("POST /files/upload", a.htmlUpload)
	mux.HandleFunc("POST /trash/restore", a.htmlTrashRestore)
	mux.HandleFunc("POST /trash/delete", a.htmlTrashDelete)
	mux.HandleFunc("POST /trash/empty", a.htmlTrashEmpty)

	// Embedded assets.
	mux.Handle("GET /static/", a.static)
	mux.HandleFunc("GET /manifest.webmanifest", a.handleManifest)
	mux.HandleFunc("GET /icon-192.png", a.handleIcon(192))
	mux.HandleFunc("GET /icon-512.png", a.handleIcon(512))
	mux.HandleFunc("GET /icon.png", a.handleIcon(512))

	// Login and setup are unauthenticated by necessity. Setup self-guards on
	// there being no users; login is rate limited and CSRF-free because
	// there is no session to bind a token to yet.
	mux.HandleFunc("POST /api/setup", a.handleSetup)
	mux.HandleFunc("POST /api/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", a.handleLogout)

	// --- authenticated ---
	// Mutating routes carry the CSRF gate: withAuth runs first so the session
	// is on the context, then csrfGuard validates the token against it.
	mux.Handle("GET /api/auth/me", a.withAuth(a.handleMe))
	mux.Handle("GET /api/auth/sessions", a.withAuth(a.handleSessions))

	mux.Handle("POST /api/auth/password", a.withAuth(a.csrfGuard(a.handleChangePassword)))
	mux.Handle("POST /api/auth/logout-all", a.withAuth(a.csrfGuard(a.handleLogoutAll)))
	mux.Handle("POST /api/auth/2fa/setup", a.withAuth(a.csrfGuard(a.handleTOTPSetup)))
	mux.Handle("POST /api/auth/2fa/enable", a.withAuth(a.csrfGuard(a.handleTOTPEnable)))
	mux.Handle("POST /api/auth/2fa/disable", a.withAuth(a.csrfGuard(a.handleTOTPDisable)))
	mux.Handle("POST /api/auth/apppw", a.withAuth(a.csrfGuard(a.handleAppPasswordCreate)))
	mux.Handle("DELETE /api/auth/apppw/{id}", a.withAuth(a.csrfGuard(a.handleAppPasswordDelete)))

	mux.Handle("GET /api/auth/apppw", a.withAuth(a.handleAppPasswordList))

	// --- shares: management ---
	mux.Handle("GET /api/shares", a.withAuth(a.handleShareList))
	mux.Handle("POST /api/shares", a.withAuth(a.csrfGuard(a.handleShareCreate)))
	mux.Handle("POST /api/shares/delete", a.withAuth(a.csrfGuard(a.handleShareDelete)))

	// --- shares: public ---
	// Unauthenticated by nature, so rate limited and sharing one uniform
	// failure response so the endpoint is not a token oracle.
	mux.HandleFunc("GET /s/{token}", a.handleSharePage)
	mux.HandleFunc("POST /s/{token}/unlock", a.handleShareUnlock)
	mux.HandleFunc("GET /s/{token}/info", a.handleShareInfo)
	mux.HandleFunc("GET /s/{token}/download", a.handleShareDownload)
	mux.HandleFunc("POST /s/{token}/upload", a.handleShareUpload)

	// Zip of the caller's own selection.
	mux.Handle("POST /api/files/zip", a.withAuth(a.handleFileZip))

	// --- WebDAV ---
	// Mounted before anything that might buffer a body: PUT streams raw.
	mux.Handle("/dav/", a.davHandler())
	mux.HandleFunc("/dav", func(w http.ResponseWriter, r *http.Request) {
		redirect(w, r, "/dav/")
	})

	// --- passkeys ---
	mux.Handle("GET /api/auth/passkeys", a.withAuth(a.handlePasskeyList))
	mux.Handle("POST /api/auth/passkeys/begin", a.withAuth(a.csrfGuard(a.handlePasskeyBeginRegistration)))
	mux.Handle("POST /api/auth/passkeys/finish", a.withAuth(a.csrfGuard(a.handlePasskeyFinishRegistration)))
	mux.Handle("POST /api/auth/passkeys/delete", a.withAuth(a.csrfGuard(a.handlePasskeyDelete)))
	mux.HandleFunc("POST /api/auth/passkeys/login/begin", a.handlePasskeyBeginLogin)
	mux.HandleFunc("POST /api/auth/passkeys/login/finish", a.handlePasskeyFinishLogin)

	// --- files ---
	mux.Handle("GET /api/files/list", a.withAuth(a.handleFileList))
	mux.Handle("GET /api/files/download", a.withAuth(a.handleFileDownload))
	mux.Handle("GET /api/files/search", a.withAuth(a.handleSearch))
	mux.Handle("GET /api/files/usage", a.withAuth(a.handleUsage))
	mux.Handle("GET /api/files/content", a.withAuth(a.handleContentRead))

	mux.Handle("POST /api/files/mkdir", a.withAuth(a.csrfGuard(a.handleMkdir)))
	mux.Handle("POST /api/files/rename", a.withAuth(a.csrfGuard(a.handleRename)))
	mux.Handle("POST /api/files/move", a.withAuth(a.csrfGuard(a.handleMove)))
	mux.Handle("POST /api/files/copy", a.withAuth(a.csrfGuard(a.handleCopy)))
	mux.Handle("POST /api/files/delete", a.withAuth(a.csrfGuard(a.handleDelete)))
	mux.Handle("PUT /api/files/content", a.withAuth(a.csrfGuard(a.handleContentWrite)))
	mux.Handle("POST /api/files/upload", a.withAuth(a.csrfGuard(a.handleUpload)))

	// --- resumable upload ---
	mux.Handle("POST /api/files/upload/session", a.withAuth(a.csrfGuard(a.handleUploadSessionCreate)))
	mux.Handle("GET /api/files/upload/session/{id}", a.withAuth(a.handleUploadSessionStatus))
	mux.Handle("PUT /api/files/upload/session/{id}", a.withAuth(a.handleUploadSessionChunk))
	mux.Handle("POST /api/files/upload/session/{id}/complete", a.withAuth(a.csrfGuard(a.handleUploadSessionComplete)))
	mux.Handle("DELETE /api/files/upload/session/{id}", a.withAuth(a.csrfGuard(a.handleUploadSessionCancel)))

	// --- trash ---
	mux.Handle("GET /api/trash/list", a.withAuth(a.handleTrashList))
	mux.Handle("POST /api/trash/restore", a.withAuth(a.csrfGuard(a.handleTrashRestore)))
	mux.Handle("POST /api/trash/delete", a.withAuth(a.csrfGuard(a.handleTrashDelete)))
	mux.Handle("POST /api/trash/empty", a.withAuth(a.csrfGuard(a.handleTrashEmpty)))

	// Everything else is 404 JSON, matching the Node version's final handler.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found."})
	})

	return middleware.Chain(mux,
		middleware.Recover(s.log),
		middleware.RequestLog(s.log),
		middleware.SecurityHeaders,
	)
}

// handleStatus is the compatibility endpoint the Docker HEALTHCHECK and the
// existing frontend both call. needsSetup drives the first-boot wizard: it is
// true only when the database has no users at all.
func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	empty, err := a.Auth.CountUsers(r.Context())
	if err != nil {
		a.Log.Printf("status: count users: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"needsSetup": empty == 0,
		"siteName":   a.Cfg.Settings.SiteName,
		// Reported here as well as on /api/version so a health probe or a
		// bug report can identify the build from one call.
		"version": version.Version,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.app.DB.PingContext(ctx); err != nil {
		s.log.Printf("health: db ping failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
