package server

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/config"
	"github.com/derek/my-cloud/internal/crypt"
	"github.com/derek/my-cloud/internal/share"
	"github.com/derek/my-cloud/internal/store/sqlite"
	"github.com/derek/my-cloud/internal/vfs"
)

// ctxKey is the private context key type for values this package sets.
type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
)

// sessionCookieName matches the Node cookie so an existing browser session
// name stays consistent across cutover.
const sessionCookieName = "mycloud_session"

// App holds the shared dependencies every handler needs.
type App struct {
	Cfg        *config.Config
	DB         *sqlite.DB
	Auth       *auth.Store
	TOTP       *auth.TOTPStore
	AppPw      *auth.AppPasswordStore
	Audit      *auth.AuditLogger
	LoginLimit *auth.RateLimiter
	Public     *auth.PublicLimiter
	// usageCache memoises per-user disk usage so a listing or a quota check
	// does not walk the whole tree on every request.
	usageCache *vfs.QuotaCache
	// Shares manages public share links.
	Shares *share.Store
	// Passkeys manages WebAuthn credentials.
	Passkeys *auth.PasskeyStore
	// Sealer is the encryption-at-rest envelope, shared with the auth
	// layer so a single master key covers every table.
	Sealer *crypt.Sealer
	Log    *log.Logger

	// templates and static are embedded assets, parsed once at startup.
	templates *template.Template
	static    http.Handler
	// icons is the raw embedded FS, used for the root-level PWA icons the
	// manifest points at.
	icons *embed.FS
}

// sessionTTL is the session lifetime from settings.
func (a *App) sessionTTL() time.Duration {
	return time.Duration(a.Cfg.Settings.SessionDays) * 24 * time.Hour
}

// authenticate resolves the session cookie to a user, or nil.
func (a *App) authenticate(r *http.Request) (*auth.Session, *auth.User, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil, nil
	}
	sess, err := a.Auth.LookupSession(r.Context(), c.Value, a.sessionTTL())
	if err != nil {
		if errors.Is(err, auth.ErrNoSession) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	u, err := a.Auth.FindUser(r.Context(), sess.Username)
	if err != nil {
		// The session outlived the account (deleted underneath it). Drop it.
		_ = a.Auth.DeleteSession(r.Context(), c.Value)
		return nil, nil, nil
	}
	return sess, u, nil
}

// withAuth wraps a handler that needs any signed-in user.
func (a *App) withAuth(next func(http.ResponseWriter, *http.Request, *auth.Session, *auth.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, u, err := a.authenticate(r)
		if err != nil {
			a.Log.Printf("auth: %v", err)
			http.Error(w, "Server error.", http.StatusInternalServerError)
			return
		}
		if sess == nil {
			// HTML navigations get a redirect to the login page; API calls get
			// a 401 so fetch() can handle it.
			if wantsHTML(r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not signed in."})
			return
		}
		next(w, r.WithContext(contextWithSession(r, sess, u)), sess, u)
	}
}

// withAdmin wraps a handler that requires the admin flag.
func (a *App) withAdmin(next func(http.ResponseWriter, *http.Request, *auth.Session, *auth.User)) http.HandlerFunc {
	return a.withAuth(func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		if !u.IsAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Admin access required."})
			return
		}
		next(w, r, sess, u)
	})
}

// sessionFrom pulls the session the middleware attached.
func sessionFrom(ctx context.Context) *auth.Session {
	s, _ := ctx.Value(ctxSession).(*auth.Session)
	return s
}

func userFrom(ctx context.Context) *auth.User {
	u, _ := ctx.Value(ctxUser).(*auth.User)
	return u
}

// checkCSRFMiddleware rejects a mutating request whose synchroniser token does
// not match the session.
//
// Every state-changing request goes through this. htmx carries the token in a
// header; a plain form post carries it in a hidden field, which is what keeps
// the no-JS path working. A request with neither is refused.
func (a *App) checkCSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		sess := sessionFrom(r.Context())
		if sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not signed in."})
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.FormValue("csrf_token")
		}
		if !auth.CheckCSRF(sess, token) {
			a.Audit.Logf(r.Context(), auth.AuditEvent{
				Username: sess.Username, Action: "csrf.fail",
				IP: clientIP(r), OK: false,
			}, "method=%s path=%s", r.Method, r.URL.Path)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Invalid or missing CSRF token."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// wantsHTML reports whether the client prefers a page over JSON.
func wantsHTML(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// clientIP resolves the caller address, honouring X-Forwarded-For only for
// loopback and link-local proxies.
//
// Trusting the header from any source would let a remote caller forge their IP
// and bypass the login rate limiter, which is exactly the hole the Node
// version closed with `trust proxy`.
func clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if !isTrustedProxy(remote) {
		return remote
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Left-most entry is the original client.
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	return remote
}

func isTrustedProxy(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "localhost" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast()
}

// setSessionCookie writes the session cookie.
//
// SameSite=Strict is safe here because every navigation is same-origin; the
// Node version used Lax. HttpOnly keeps it away from JS, and Secure is added
// when the request arrived over HTTPS or the operator forced it.
func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := r.TLS != nil || a.Cfg.ForceSecureCookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(a.sessionTTL().Seconds()),
		Secure:   secure,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Secure:   r.TLS != nil || a.Cfg.ForceSecureCookie,
	})
}
