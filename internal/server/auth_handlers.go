package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/derek/my-cloud/internal/auth"
)

// handleSetup creates the first admin account.
//
// It is only open while the database has no users. Any other state returns
// 403, so this can never be used to add an account to a live installation.
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	n, err := a.Auth.CountUsers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	if n > 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Setup already completed."})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	u, err := a.Auth.CreateUser(r.Context(), username, password, true, 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Ensure the directory layout exists for the new account.
	a.ensureUserDirs(u.Username)

	token, _, err := a.Auth.CreateSession(r.Context(), u.Username, r.UserAgent(), clientIP(r), a.sessionTTL())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.setSessionCookie(w, r, token)
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "setup.complete", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": u.Username})
}

// handleLogin verifies credentials and, when 2FA is on, the second factor.
//
// A wrong username and a wrong password produce the identical response, and
// the same work is done either way, so neither the status code nor the timing
// reveals whether an account exists.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Per-IP and per-username buckets. The username bucket is what stops a
	// distributed spray against one account.
	if !a.LoginLimit.Allow(ip, username) {
		a.Audit.Log(r.Context(), auth.AuditEvent{
			Username: username, Action: "login.ratelimited", IP: ip, OK: false,
		})
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "Too many login attempts. Try again in a few minutes.",
		})
		return
	}

	u, err := a.Auth.VerifyPassword(r.Context(), username, password)
	if err != nil {
		a.Audit.Log(r.Context(), auth.AuditEvent{
			Username: username, Action: "login.fail", IP: ip, OK: false,
		})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Wrong username or password."})
		return
	}

	if u.HasTOTP {
		code := r.FormValue("code")
		if code == "" {
			// No session yet: tell the client to prompt for a code.
			writeJSON(w, http.StatusOK, map[string]any{"twofa": true})
			return
		}
		if !a.TOTP.Verify(r.Context(), u.Username, code) {
			a.Audit.Log(r.Context(), auth.AuditEvent{
				Username: u.Username, Action: "login.2fa.fail", IP: ip, OK: false,
			})
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "Incorrect authentication code.", "twofa": true,
			})
			return
		}
	}

	a.LoginLimit.ClearLoginAttempts(u.Username)
	token, _, err := a.Auth.CreateSession(r.Context(), u.Username, r.UserAgent(), ip, a.sessionTTL())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.setSessionCookie(w, r, token)
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "login.ok", IP: ip, OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleLogout revokes the session server-side.
//
// The Node version only cleared the cookie, leaving a valid token in the
// browser history that anyone with it could reuse. Deleting the row makes the
// token genuinely dead.
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if sess := sessionFrom(r.Context()); sess != nil {
			a.Audit.Log(r.Context(), auth.AuditEvent{
				Username: sess.Username, Action: "logout", IP: clientIP(r), OK: true,
			})
		}
		_ = a.Auth.DeleteSession(r.Context(), c.Value)
	}
	a.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleLogoutAll revokes every session for the user.
func (a *App) handleLogoutAll(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	if err := a.Auth.LogoutAll(r.Context(), u.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "logout.all", IP: clientIP(r), OK: true,
	})
	a.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMe returns the signed-in user's profile.
func (a *App) handleMe(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	writeJSON(w, http.StatusOK, map[string]any{
		"username":          u.Username,
		"isAdmin":           u.IsAdmin,
		"quotaMB":           u.QuotaMB,
		"siteName":          a.Cfg.Settings.SiteName,
		"allowPublicShares": a.Cfg.Settings.AllowPublicShares,
		"totpEnabled":       u.HasTOTP,
		"csrfToken":         auth.CSRFToken(sess),
	})
}

// handleChangePassword updates the caller's own password.
func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	current := r.FormValue("current")
	next := r.FormValue("next")
	if _, err := a.Auth.VerifyPassword(r.Context(), u.Username, current); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Current password is wrong."})
		return
	}
	if err := a.Auth.SetPassword(r.Context(), u.Username, next); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// SetPassword clears every session for this user, including the current
	// one. Issue a fresh session so the user is not logged out of the tab they
	// just used.
	token, _, err := a.Auth.CreateSession(r.Context(), u.Username, r.UserAgent(), clientIP(r), a.sessionTTL())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.setSessionCookie(w, r, token)
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "password.change", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSessions lists the user's live sessions for the device view.
func (a *App) handleSessions(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	sessions, err := a.Auth.ListSessions(r.Context(), u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	type device struct {
		ID        string `json:"id"`
		Current   bool   `json:"current"`
		UserAgent string `json:"userAgent"`
		IP        string `json:"ip"`
		LastSeen  int64  `json:"lastSeen"`
		CreatedAt int64  `json:"createdAt"`
	}
	out := make([]device, 0, len(sessions))
	for _, s := range sessions {
		// Only a prefix of the hash is exposed: enough to correlate rows in
		// the UI, not enough to be useful if the response leaks.
		id := s.ID
		if len(id) > 8 {
			id = id[:8]
		}
		out = append(out, device{
			ID: id, Current: s.ID == sess.ID, UserAgent: s.UserAgent,
			IP: s.IP, LastSeen: s.LastSeen, CreatedAt: s.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleTOTPSetup starts enrolment, returning the secret and otpauth URI.
func (a *App) handleTOTPSetup(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	secret, uri, err := a.TOTP.BeginSetup(r.Context(), u.Username, a.Cfg.Settings.SiteName)
	if err != nil {
		a.Log.Printf("totp setup for %q: %v", u.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth": uri})
}

// handleTOTPEnable confirms enrolment and returns the recovery codes once.
func (a *App) handleTOTPEnable(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	code := r.FormValue("code")
	recovery, err := a.TOTP.Confirm(r.Context(), u.Username, code)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "totp.enable", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery": recovery})
}

// handleTOTPDisable removes 2FA, gated on the current password so a borrowed
// unlocked session cannot strip it.
func (a *App) handleTOTPDisable(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	if _, err := a.Auth.VerifyPassword(r.Context(), u.Username, r.FormValue("password")); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Current password is wrong."})
		return
	}
	if err := a.TOTP.Disable(r.Context(), u.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "totp.disable", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAppPasswords lists app passwords (never their tokens).
func (a *App) handleAppPasswordList(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	list, err := a.AppPw.List(r.Context(), u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"appPasswords": list})
}

// handleAppPasswordCreate mints an app password and returns the token once.
func (a *App) handleAppPasswordCreate(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	id, token, err := a.AppPw.Create(r.Context(), u.Username, r.FormValue("label"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "token": token})
}

// handleAppPasswordDelete removes one app password.
func (a *App) handleAppPasswordDelete(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	if err := a.AppPw.Remove(r.Context(), u.Username, r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ensureUserDirs creates the files/trash/thumbs layout for a user.
func (a *App) ensureUserDirs(username string) {
	_, files, trash, thumbs := a.Cfg.UserDirs(username)
	for _, d := range []string{files, trash, thumbs} {
		_ = mkdirAll(d)
	}
}

// errIsNoRows reports whether an error is sql.ErrNoRows.
func errIsNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// normaliseError strips internal detail from an error before it reaches a
// client.
func normaliseError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	// Paths and SQL never belong in a response body.
	if strings.Contains(msg, "SQL") || strings.Contains(msg, "sqlite") {
		return "Server error."
	}
	return msg
}
