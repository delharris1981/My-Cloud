package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/version"
	"github.com/derek/my-cloud/internal/vfs"
	"github.com/derek/my-cloud/web"
)

// authSessionType is the concrete session type, aliased in pages.go.
type authSessionType = auth.Session

// Template returns a parsed template by name, or the whole set.
func (a *App) Template(name string) (*template.Template, error) {
	if a.templates == nil {
		return nil, errNoTemplates
	}
	if name == "" {
		return a.templates, nil
	}
	if t := a.templates.Lookup(name); t != nil {
		return t, nil
	}
	return a.templates, nil
}

var errNoTemplates = &templateError{}

type templateError struct{}

func (*templateError) Error() string { return "templates not initialised" }

// initTemplates parses the embedded templates once at startup, so a template
// error crashes the boot rather than surfacing as a 500 to a random visitor.
func initTemplates(logger *log.Logger) (*template.Template, error) {
	t, err := web.Templates()
	if err != nil {
		return nil, err
	}
	logger.Printf("templates parsed: %d", len(t.Templates()))
	return t, nil
}

// initStatic prepares the embedded static file server.
func initStatic(logger *log.Logger) (http.Handler, error) {
	sub, err := web.Static()
	if err != nil {
		return nil, err
	}
	logger.Printf("static assets mounted")
	return http.StripPrefix("/static/", cacheControl(http.FileServer(http.FS(sub)))), nil
}

// cacheControl sets caching headers. Fingerprinted vendor assets would be
// ideal, but the asset names are stable, so a short max-age with revalidation
// is the honest choice: a stale app.js after an upgrade is a confusing bug.
func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".html") {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		}
		next.ServeHTTP(w, r)
	})
}

// --- HTML pages ---

// handleLoginPage renders the login / setup form.
//
// With JavaScript disabled this is the only sign-in path, which is why the
// form is a real POST that returns HTML rather than a fetch() to JSON.
func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Already signed in? Go straight to the files.
	if sess, _, err := a.authenticate(r); err == nil && sess != nil {
		redirect(w, r, "/files")
		return
	}
	d := a.basePage(r, nil)
	d.Title = "Sign in"
	d.BodyClass = "auth-body"
	d.NeedsSetup = a.needsSetup(r)
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		d.Error = errMsg
	}
	// A password-only login that hit 2FA re-renders with the code field.
	if r.URL.Query().Get("twofa") == "1" {
		d.TwoFA = true
		d.Username = r.URL.Query().Get("u")
	}
	a.renderLogin(w, r, http.StatusOK, d)
}

// renderLogin renders the login page inside the layout shell.
//
// The login page has no session, so its CSRF token is issued per-request from a
// cookie-backed double-submit: the token is placed in a cookie and echoed in
// the form, and the handler compares them. A signed token would need a session
// that does not exist yet, and refusing to protect the login form would leave
// it open to login CSRF.
func (a *App) renderLogin(w http.ResponseWriter, r *http.Request, status int, d pageData) {
	if d.CSRFToken == "" {
		tok, err := randomToken()
		if err != nil {
			a.Log.Printf("login csrf: %v", err)
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     loginCSRFCookie,
			Value:    tok,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   1800,
			Secure:   r.TLS != nil || a.Cfg.ForceSecureCookie,
		})
		d.CSRFToken = tok
	}
	// The login card is rendered first, then wrapped in the full document.
	d.Content = a.mustRender("login", d)
	d.Script = false
	a.render(w, status, "layout", d)
}

// loginCSRFCookie holds the pre-session CSRF token for the login form.
const loginCSRFCookie = "mycloud_login_csrf"

// checkLoginCSRF validates the double-submit token on a login or setup POST.
func (a *App) checkLoginCSRF(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil {
		return false
	}
	submitted := r.FormValue("csrf_token")
	if submitted == "" {
		submitted = r.Header.Get("X-CSRF-Token")
	}
	ok := auth.ConstantTimeEqual(c.Value, submitted)
	if !ok {
		a.Audit.Log(r.Context(), auth.AuditEvent{
			Action: "login.csrf.fail", IP: clientIP(r), OK: false,
		})
	}
	return ok
}

// clearLoginCSRF removes the pre-session token once a session exists.
func (a *App) clearLoginCSRF(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: loginCSRFCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

// randomToken returns a hex random token for the login CSRF cookie.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (a *App) needsSetup(r *http.Request) bool {
	n, err := a.Auth.CountUsers(r.Context())
	return err == nil && n == 0
}

// handleFilesPage renders the file browser.
func (a *App) handleFilesPage(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		tr, err := a.userFS(u.Username)
		if err != nil {
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		entries, err := tr.Files().List(cleanRelPath(r.URL.Query().Get("path")))
		if err != nil {
			// A missing directory renders the root rather than an error page:
			// a bookmark to a deleted folder should not look broken.
			entries = nil
		}
		d := a.basePage(r, sess)
		d.Title = "Files"
		d.View = "files"
		d.Script = true
		d.ShowHeadbar = true
		d.Segments = crumbs(cleanRelPath(r.URL.Query().Get("path")))
		d.IsAdmin = u.IsAdmin
		if msg := r.URL.Query().Get("msg"); msg != "" {
			d.Notice = msg
		}
		d.Content = a.mustRender("browser", map[string]any{
			"Items":    entries,
			"Path":     cleanRelPath(r.URL.Query().Get("path")),
			"Segments": d.Segments,
			"CSRF":     sess.CSRFSecret,
			"ViewMode": d.ViewMode,
			"SortBy":   d.SortBy,
			"Query":    r.URL.Query().Get("q"),
			"Usage":    a.usagePayload(tr, u),
			"Selected": d.Selected,
		})
		a.render(w, http.StatusOK, "layout", d)
	})(w, r)
}

// crumbs splits a path into breadcrumb components.
func crumbs(p string) []crumb {
	segs := pathSegmentsFor(p)
	out := make([]crumb, 0, len(segs))
	for i, s := range segs {
		out = append(out, crumb{Name: s.Name, Path: s.Path, Last: i == len(segs)-1})
	}
	return out
}

// pathSegmentsFor splits a slash path into name/path pairs.
func pathSegmentsFor(p string) []crumb {
	clean := strings.Trim(strings.ReplaceAll(p, "\\", "/"), "/")
	if clean == "" {
		return []crumb{{Name: "Home", Path: "", Last: true}}
	}
	parts := strings.Split(clean, "/")
	out := []crumb{{Name: "Home", Path: ""}}
	acc := ""
	for i, part := range parts {
		if acc == "" {
			acc = part
		} else {
			acc += "/" + part
		}
		out = append(out, crumb{Name: part, Path: acc, Last: i == len(parts)-1})
	}
	return out
}

// mustRender renders a template fragment, logging and returning an error
// marker on failure rather than panicking mid-request.
func (a *App) mustRender(name string, data any) template.HTML {
	buf := &bytes.Buffer{}
	tmpl, err := a.Template(name)
	if err != nil {
		a.Log.Printf("render %s: %v", name, err)
		return template.HTML(`<div class="form-error">Could not render this view.</div>`)
	}
	if err := tmpl.Execute(buf, data); err != nil {
		a.Log.Printf("render %s: %v", name, err)
		return template.HTML(`<div class="form-error">Could not render this view.</div>`)
	}
	return template.HTML(buf.String())
}

// handleTrashPage renders the trash view.
func (a *App) handleTrashPage(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		tr, err := a.userFS(u.Username)
		if err != nil {
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		items, _ := tr.List()
		if items == nil {
			items = []vfs.TrashItem{}
		}
		d := a.basePage(r, sess)
		d.Title = "Trash"
		d.View = "trash"
		d.Script = true
		d.ShowHeadbar = true
		d.IsAdmin = u.IsAdmin
		d.Content = a.mustRender("trash", map[string]any{
			"Items": items,
			"CSRF":  sess.CSRFSecret,
		})
		a.render(w, http.StatusOK, "layout", d)
	})(w, r)
}

// handleSharesPage renders the share management view.
func (a *App) handleSharesPage(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		shares, err := a.Shares.List(r.Context(), u.Username)
		if err != nil {
			a.Log.Printf("shares list: %v", err)
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		d := a.basePage(r, sess)
		d.Title = "Shared links"
		d.View = "shares"
		d.Script = true
		d.ShowHeadbar = true
		d.IsAdmin = u.IsAdmin
		d.Content = a.mustRender("shares", map[string]any{
			"Shares":   shares,
			"CSRF":     sess.CSRFSecret,
			"Disabled": !a.Cfg.Settings.AllowPublicShares,
		})
		a.render(w, http.StatusOK, "layout", d)
	})(w, r)
}

// handleAdminPage renders user administration.
func (a *App) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	a.withAdmin(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		users, err := a.Auth.ListUsers(r.Context())
		if err != nil {
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		d := a.basePage(r, sess)
		d.Title = "Admin"
		d.View = "admin"
		d.Script = true
		d.ShowHeadbar = true
		d.IsAdmin = true
		d.Content = a.mustRender("admin", map[string]any{
			"Users":        users,
			"CSRF":         sess.CSRFSecret,
			"Settings":     a.Cfg.Settings,
			"DefaultQuota": a.Cfg.Settings.DefaultQuotaMB,
		})
		a.render(w, http.StatusOK, "layout", d)
	})(w, r)
}

// handleSettingsPage renders the account settings view.
func (a *App) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		devices, _ := a.Auth.ListSessions(r.Context(), u.Username)
		appPws, _ := a.AppPw.List(r.Context(), u.Username)
		d := a.basePage(r, sess)
		d.Title = "Settings"
		d.View = "settings"
		d.Script = true
		d.ShowHeadbar = true
		d.IsAdmin = u.IsAdmin
		d.Content = a.mustRender("settings", map[string]any{
			"User":         u,
			"Devices":      devices,
			"AppPasswords": appPws,
			"CSRF":         sess.CSRFSecret,
			"Sessions":     devices,
			// The fragment renders from its own map, not from pageData, so
			// the version has to be handed to it explicitly.
			"Version": version.Version,
			"Commit":  version.Commit,
		})
		a.render(w, http.StatusOK, "layout", d)
	})(w, r)
}

// handleSearch renders the search results page. With htmx the same route is
// requested with HX-Request and returns just the results fragment.
func (a *App) handleSearchPage(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		tr, err := a.userFS(u.Username)
		if err != nil {
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		var results []vfs.SearchResult
		if q != "" {
			results, _ = tr.Files().Search(q, 200)
		}
		if results == nil {
			results = []vfs.SearchResult{}
		}
		// An htmx request wants only the fragment; a plain navigation wants a
		// full page. One handler, two render modes.
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(a.mustRender("search-results", map[string]any{
				"Results": results, "Query": q,
			})))
			return
		}
		d := a.basePage(r, sess)
		d.Title = "Search"
		d.View = "files"
		d.Script = true
		d.ShowHeadbar = true
		d.IsAdmin = u.IsAdmin
		d.Content = a.mustRender("browser", map[string]any{
			"Items": []vfs.Entry{}, "Path": "", "Segments": d.Segments,
			"CSRF": sess.CSRFSecret, "ViewMode": d.ViewMode, "SortBy": d.SortBy,
			"Query": q,
			"SearchResults": a.mustRender("search-results", map[string]any{
				"Results": results, "Query": q,
			}),
			"Usage":    map[string]any{},
			"Selected": map[string]bool{},
		})
		a.render(w, http.StatusOK, "layout", d)
	})(w, r)
}
