package server

import (
	"context"
	"net/http"

	"github.com/derek/my-cloud/internal/auth"
)

// The routes below use one pattern, repeated deliberately rather than abstracted
// further:
//
//	mux.Handle(path, a.withAuth(a.csrfGuard(handler)))
//
// withAuth authenticates and puts the session on the context. csrfGuard then
// validates the synchroniser token against that session. Order is not
// incidental: CSRF only means anything once there is a session, so withAuth
// must run first.
//
// Reads skip the csrfGuard layer entirely, since a GET cannot mutate state.

// Template returns a parsed template by name, or the whole set.
// (defined in pages_render.go)

// csrfGuard wraps an auth-aware handler with the CSRF check.
func (a *App) csrfGuard(next func(http.ResponseWriter, *http.Request, *auth.Session, *auth.User)) func(http.ResponseWriter, *http.Request, *auth.Session, *auth.User) {
	return func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next(w, r, sess, u)
		})
		ctx := contextWithSession(r, sess, u)
		a.checkCSRFMiddleware(handler).ServeHTTP(w, r.WithContext(ctx))
	}
}

// withCSRFMiddleware is checkCSRFMiddleware as a method usable from inside a
// withAuth closure. It re-uses the session already on the context.
func (a *App) withCSRFMiddleware(next http.Handler) http.Handler {
	return a.checkCSRFMiddleware(next)
}

// contextWithSession attaches the authenticated session and user to a request
// context. withAuth normally does this, but the csrfGuard wrapper re-enters
// the middleware chain with a request that already carries them.
func contextWithSession(r *http.Request, sess *auth.Session, u *auth.User) context.Context {
	ctx := context.WithValue(r.Context(), ctxSession, sess)
	return context.WithValue(ctx, ctxUser, u)
}
