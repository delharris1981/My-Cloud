package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/go-webauthn/webauthn/webauthn"
)

// purposePasskeySession is the sealing purpose for in-flight ceremony state.
// It is distinct from the credential purpose so a stolen ceremony cookie can
// never be replayed as a stored credential.
const purposePasskeySession = "passkey-session"

// passkeySessionAAD is the AAD for a sealed ceremony cookie.
const passkeySessionAAD = "passkey-session:state"

// passkeySessionCookie holds the in-flight ceremony state between the begin and
// finish halves. It must be server-signed or the client could forge a
// challenge, so it is sealed with the secrets subkey rather than merely
// base64-encoded.
const passkeySessionCookie = "mycloud_passkey_session"

// passkeySessionTTL bounds an unfinished ceremony. A challenge is single-use
// and short-lived by specification; a stale one must not be replayable.
const passkeySessionTTL = 5 * time.Minute

// webauthnFor builds a WebAuthn instance for the current request origin.
//
// The RP ID and origin come from the request rather than configuration: the
// server runs on a LAN address, a hostname, or behind a proxy, and hardcoding
// any of them breaks passkeys on the other two.
func (a *App) webauthnFor(r *http.Request) (*webauthn.WebAuthn, error) {
	rpID, origin := a.rpIdentity(r)
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: a.Cfg.Settings.SiteName,
		RPOrigins:     []string{origin},
	})
}

// rpIdentity derives the relying-party id and origin from the request.
//
// rpID must be a registrable suffix of the origin's host: using the host
// itself is correct, while guessing a parent domain would let a sibling host
// mint credentials for this one.
func (a *App) rpIdentity(r *http.Request) (rpID, origin string) {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	// Strip a port: the RP ID is a host, not an origin.
	if i := lastColon(host); i >= 0 && !isIPv6Literal(host) {
		host = host[:i]
	}
	return host, scheme + "://" + r.Host
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

func isIPv6Literal(host string) bool {
	return len(host) > 0 && host[0] == '['
}

// --- Registration ---

// handlePasskeyBeginRegistration starts enrolling a passkey. The caller must be
// signed in: enrolling a credential is an account change.
func (a *App) handlePasskeyBeginRegistration(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	wa, err := a.webauthnFor(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	user := auth.WebAuthnUser{Username: u.Username, ID: auth.UserHandle(u.Username)}
	options, state, err := wa.BeginRegistration(user)
	if err != nil {
		a.Log.Printf("passkey registration begin for %q: %v", u.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.stashPasskeySession(w, r, state)
	writeJSON(w, http.StatusOK, map[string]any{"options": options})
}

// handlePasskeyFinishRegistration completes enrolment.
func (a *App) handlePasskeyFinishRegistration(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	wa, err := a.webauthnFor(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	state, ok := a.popPasskeySession(w, r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Registration expired. Try again."})
		return
	}
	user := auth.WebAuthnUser{Username: u.Username, ID: auth.UserHandle(u.Username)}
	cred, err := wa.FinishRegistration(user, *state, r)
	if err != nil {
		a.Audit.Logf(r.Context(), auth.AuditEvent{
			Username: u.Username, Action: "passkey.register.fail", IP: clientIP(r), OK: false,
		}, "%v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "That passkey could not be registered."})
		return
	}
	label := r.FormValue("label")
	if label == "" {
		label = "Passkey"
	}
	if err := a.Passkeys.Save(r.Context(), u.Username, cred, label); err != nil {
		a.Log.Printf("save passkey: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "passkey.register", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Assertion (sign-in) ---

// handlePasskeyBeginLogin starts a passkey assertion for a known user.
//
// The username is supplied explicitly rather than using discoverable
// ("usernameless") login: the login form already knows the account, and the
// discoverable flow would require storing a large list of permitted
// credential IDs in a cookie.
func (a *App) handlePasskeyBeginLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() //nolint:errcheck
	username := auth.NormaliseUsername(r.FormValue("username"))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter your username first."})
		return
	}
	wa, err := a.webauthnFor(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	user, err := a.Passkeys.LoadUser(r.Context(), username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	if len(user.Credentials()) == 0 {
		// Say nothing about whether the account exists.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Wrong username or password."})
		return
	}
	options, state, err := wa.BeginLogin(user.WithUserCredentials())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	// The username rides along so the finish step knows whose credential to
	// check; it is not trusted, only re-verified against the credential id.
	a.stashPasskeySession(w, r, state, username)
	writeJSON(w, http.StatusOK, map[string]any{"options": options})
}

// handlePasskeyFinishLogin completes an assertion and issues a session.
func (a *App) handlePasskeyFinishLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() //nolint:errcheck
	username := auth.NormaliseUsername(r.FormValue("username"))
	wa, err := a.webauthnFor(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	state, ok := a.popPasskeySession(w, r)
	if !ok || username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Sign-in expired. Try again."})
		return
	}
	user, err := a.Passkeys.LoadUser(r.Context(), username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	cred, err := wa.FinishLogin(user.WithUserCredentials(), *state, r)
	if err != nil {
		a.Audit.Logf(r.Context(), auth.AuditEvent{
			Username: username, Action: "passkey.login.fail", IP: clientIP(r), OK: false,
		}, "%v", err)
		// The same message as a wrong password, so a passkey attempt reveals
		// nothing about the account.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Sign-in failed."})
		return
	}
	// Persist the advanced counter. go-webauthn has already judged whether a
	// non-increasing counter is acceptable for this platform; its decision is
	// respected rather than second-guessed here.
	if cred.Authenticator.CloneWarning {
		a.Audit.Logf(r.Context(), auth.AuditEvent{
			Username: username, Action: "passkey.clonewarning", IP: clientIP(r), OK: true,
		}, "authenticator reported a possible clone")
	}
	if err := a.Passkeys.UpdateSignCount(r.Context(), username, cred); err != nil {
		a.Log.Printf("passkey counter update: %v", err)
	}

	a.LoginLimit.ClearLoginAttempts(username)
	token, _, err := a.Auth.CreateSession(r.Context(), username, r.UserAgent(), clientIP(r), a.sessionTTL())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.setSessionCookie(w, r, token)
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: username, Action: "passkey.login.ok", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Management ---

// handlePasskeyList returns the user's passkeys.
func (a *App) handlePasskeyList(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	list, err := a.Passkeys.List(r.Context(), u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	if list == nil {
		list = []auth.PasskeyInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": list})
}

// handlePasskeyDelete removes a passkey. Gated on the current password so an
// unattended unlocked session cannot strip the account's second factors.
func (a *App) handlePasskeyDelete(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	if _, err := a.Auth.VerifyPassword(r.Context(), u.Username, r.FormValue("password")); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Current password is wrong."})
		return
	}
	if err := a.Passkeys.Delete(r.Context(), u.Username, r.FormValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "No such passkey."})
		return
	}
	a.Audit.Log(r.Context(), auth.AuditEvent{
		Username: u.Username, Action: "passkey.delete", IP: clientIP(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- ceremony state ---

// stashPasskeySession seals the in-flight ceremony state into a cookie.
//
// The state carries the challenge, so it must not be readable or forgeable by
// the client. Sealing with the server's own key means the browser holds an
// opaque blob and only this server can produce a valid one.
func (a *App) stashPasskeySession(w http.ResponseWriter, r *http.Request, state *webauthn.SessionData, username ...string) {
	payload := map[string]any{"session": state}
	if len(username) > 0 {
		payload["username"] = username[0]
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	sealed, err := a.Sealer.Seal(purposePasskeySession, passkeySessionAAD, raw)
	if err != nil {
		a.Log.Printf("seal passkey session: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     passkeySessionCookie,
		Value:    base64URL(sealed),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(passkeySessionTTL.Seconds()),
		Secure:   r.TLS != nil || a.Cfg.ForceSecureCookie,
	})
}

// popPasskeySession reads and clears the ceremony state. It reports false when
// the cookie is absent, tampered, or expired.
func (a *App) popPasskeySession(w http.ResponseWriter, r *http.Request) (*webauthn.SessionData, bool) {
	// Clear immediately: a challenge is single-use, and leaving the cookie
	// would allow a replay attempt with a stale state.
	a.clearPasskeySession(w, r)

	c, err := r.Cookie(passkeySessionCookie)
	if err != nil {
		return nil, false
	}
	raw, err := base64URLDecode(c.Value)
	if err != nil {
		return nil, false
	}
	plain, err := a.Sealer.Open(purposePasskeySession, passkeySessionAAD, raw)
	if err != nil {
		return nil, false
	}
	var payload struct {
		Session  *webauthn.SessionData `json:"session"`
		Username string                `json:"username"`
	}
	if err := json.Unmarshal(plain, &payload); err != nil || payload.Session == nil {
		return nil, false
	}
	if time.Now().After(payload.Session.Expires) {
		return nil, false
	}
	return payload.Session, true
}

func (a *App) clearPasskeySession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: passkeySessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
		Secure: r.TLS != nil || a.Cfg.ForceSecureCookie,
	})
}
