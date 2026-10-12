package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/derek/my-cloud/internal/auth"
)

// The handlers in this file are the HTML form endpoints: real POSTs from a
// <form> tag that redirect afterwards, which is what the no-JS path needs.
//
// They delegate to the same logic as the JSON handlers rather than duplicating
// it, so there is one implementation of each operation and two front doors.

func backTo(w http.ResponseWriter, r *http.Request, msg string) {
	path := r.FormValue("path")
	if path == "" {
		path = r.URL.Query().Get("path")
	}
	target := "/files?path=" + url.QueryEscape(path)
	if msg != "" {
		target += "&msg=" + url.QueryEscape(msg)
	}
	redirect(w, r, target)
}

// htmlLogin is the no-JS sign-in. On 2FA it re-renders the login page with the
// code field rather than redirecting, so the username survives.
func (a *App) htmlLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() //nolint:errcheck
	if !a.checkLoginCSRF(w, r) {
		a.loginPage(w, r, http.StatusForbidden, "Your session expired. Please try again.")
		return
	}
	ip := clientIP(r)
	username := r.FormValue("username")
	password := r.FormValue("password")

	if !a.LoginLimit.Allow(ip, username) {
		a.loginPage(w, r, http.StatusTooManyRequests, "Too many login attempts. Try again in a few minutes.")
		return
	}

	u, err := a.Auth.VerifyPassword(r.Context(), username, password)
	if err != nil {
		a.Audit.Log(r.Context(), auth.AuditEvent{
			Username: username, Action: "login.fail", IP: ip, OK: false,
		})
		// One message for both wrong-username and wrong-password.
		a.loginPage(w, r, http.StatusUnauthorized, "Wrong username or password.")
		return
	}
	if u.HasTOTP {
		code := r.FormValue("code")
		if code == "" {
			// Password accepted, second factor still needed.
			d := a.basePage(r, nil)
			d.Title = "Sign in"
			d.BodyClass = "auth-body"
			d.TwoFA = true
			d.Username = u.Username
			a.renderLogin(w, r, http.StatusOK, d)
			return
		}
		if !a.TOTP.Verify(r.Context(), u.Username, code) {
			d := a.basePage(r, nil)
			d.Title = "Sign in"
			d.BodyClass = "auth-body"
			d.TwoFA = true
			d.Username = u.Username
			d.Error = "Incorrect authentication code."
			a.renderLogin(w, r, http.StatusForbidden, d)
			return
		}
	}

	a.LoginLimit.ClearLoginAttempts(u.Username)
	token, _, err := a.Auth.CreateSession(r.Context(), u.Username, r.UserAgent(), ip, a.sessionTTL())
	if err != nil {
		a.loginPage(w, r, http.StatusInternalServerError, "Server error.")
		return
	}
	a.setSessionCookie(w, r, token)
	a.Audit.Log(r.Context(), auth.AuditEvent{Username: u.Username, Action: "login.ok", IP: ip, OK: true})
	redirect(w, r, "/files")
}

// loginPage renders the login page with an error.
func (a *App) loginPage(w http.ResponseWriter, r *http.Request, status int, msg string) {
	d := a.basePage(r, nil)
	d.Title = "Sign in"
	d.BodyClass = "auth-body"
	d.Error = msg
	a.renderLogin(w, r, status, d)
}

// htmlSetup creates the first admin from a form POST.
func (a *App) htmlSetup(w http.ResponseWriter, r *http.Request) {
	n, err := a.Auth.CountUsers(r.Context())
	if err != nil {
		a.loginPage(w, r, http.StatusInternalServerError, "Server error.")
		return
	}
	if n > 0 {
		a.loginPage(w, r, http.StatusForbidden, "Setup already completed.")
		return
	}
	r.ParseForm() //nolint:errcheck
	if !a.checkLoginCSRF(w, r) {
		a.loginPage(w, r, http.StatusForbidden, "Your session expired. Please try again.")
		return
	}
	u, err := a.Auth.CreateUser(r.Context(), r.FormValue("username"), r.FormValue("password"), true, 0)
	if err != nil {
		a.loginPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	a.ensureUserDirs(u.Username)
	token, _, err := a.Auth.CreateSession(r.Context(), u.Username, r.UserAgent(), clientIP(r), a.sessionTTL())
	if err != nil {
		a.loginPage(w, r, http.StatusInternalServerError, "Server error.")
		return
	}
	a.setSessionCookie(w, r, token)
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "setup.complete", IP: clientIP(r), OK: true,
	})
	redirect(w, r, "/files")
}

// htmlLogout ends the session and returns to the login page.
//
// CSRF-checked like every other mutation. Logout is low-value to an attacker
// on its own, but an unprotected state change reachable by a cross-site POST
// is exactly the pattern the plan forbids, and the cost of checking is one
// header the form already carries.
func (a *App) htmlLogout(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.csrfGuard(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
			if c, err := r.Cookie(sessionCookieName); err == nil {
				_ = a.Auth.DeleteSession(r.Context(), c.Value)
				a.Audit.Log(r.Context(), auth.AuditEvent{
					Username: u.Username, Action: "logout", IP: clientIP(r), OK: true,
				})
			}
			a.clearSessionCookie(w, r)
			redirect(w, r, "/login")
		})(w, r, sess, u)
	})(w, r)
}

// htmlMkdir creates a folder from the toolbar form.
func (a *App) htmlMkdir(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			r.ParseForm() //nolint:errcheck
			if _, err := tr.Files().MkdirSingle(cleanRelPath(r.FormValue("path")), r.FormValue("name")); err != nil {
				backTo(w, r, err.Error())
				return
			}
			backTo(w, r, "")
		})).ServeHTTP(w, r)
	})(w, r)
}

// htmlRename renames from the per-row form.
func (a *App) htmlRename(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			r.ParseForm() //nolint:errcheck
			oldPath := r.FormValue("path")
			if _, err := tr.Files().Rename(oldPath, r.FormValue("name")); err != nil {
				backTo(w, r, err.Error())
				return
			}
			backTo(w, r, "Renamed.")
		})).ServeHTTP(w, r)
	})(w, r)
}

// htmlDelete moves the selection to the trash.
func (a *App) htmlDelete(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			r.ParseForm() //nolint:errcheck
			paths := formPaths(r, "paths")
			if len(paths) == 0 {
				backTo(w, r, "Nothing selected.")
				return
			}
			var failures []string
			for _, p := range paths {
				if _, err := tr.Delete(p); err != nil {
					failures = append(failures, err.Error())
				}
			}
			a.usageCache.Invalidate(u.Username)
			msg := "Moved to trash."
			if len(failures) > 0 {
				msg = strings.Join(failures, "; ")
			}
			backTo(w, r, msg)
		})).ServeHTTP(w, r)
	})(w, r)
}

// htmlUpload accepts the plain multipart form POST.
func (a *App) htmlUpload(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			dest := r.URL.Query().Get("path")
			sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")
			written, err := sink.SaveMultipart(r, dest)
			a.usageCache.Invalidate(u.Username)
			if err != nil {
				backTo(w, r, err.Error())
				return
			}
			backTo(w, r, pluralFiles(len(written)))
		})).ServeHTTP(w, r)
	})(w, r)
}

func pluralFiles(n int) string {
	if n == 1 {
		return "Uploaded 1 file."
	}
	return "Uploaded " + itoa(n) + " files."
}

// htmlTrashRestore restores selected items.
func (a *App) htmlTrashRestore(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			r.ParseForm() //nolint:errcheck
			for _, id := range formPaths(r, "ids") {
				tr.Restore(id)
			}
			a.usageCache.Invalidate(u.Username)
			redirect(w, r, "/trash?msg=Restored.")
		})).ServeHTTP(w, r)
	})(w, r)
}

// htmlTrashDelete permanently removes selected items.
func (a *App) htmlTrashDelete(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			r.ParseForm() //nolint:errcheck
			for _, id := range formPaths(r, "ids") {
				tr.Purge(id)
			}
			redirect(w, r, "/trash?msg=Deleted.")
		})).ServeHTTP(w, r)
	})(w, r)
}

// htmlTrashEmpty empties the trash.
func (a *App) htmlTrashEmpty(w http.ResponseWriter, r *http.Request) {
	a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		a.withCSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr, err := a.userFS(u.Username)
			if err != nil {
				http.Error(w, "Server error.", http.StatusInternalServerError)
				return
			}
			if _, err := tr.Empty(); err != nil {
				redirect(w, r, "/trash?msg=Could+not+empty+the+trash.")
				return
			}
			redirect(w, r, "/trash?msg=Trash+emptied.")
		})).ServeHTTP(w, r)
	})(w, r)
}
