// Package middleware holds cross-cutting HTTP concerns: security headers,
// request logging, and the pieces phase 3's htmx frontend will need.
package middleware

import (
	"log"
	"net/http"
	"runtime/debug"
	"time"
)

// SecurityHeaders sets the baseline hardening headers on every response.
//
// The CSP is deliberately strict — no unsafe-inline for scripts or styles —
// which is why phase 6 vendors htmx locally rather than from a CDN, and why
// any inline bootstrap must move to a nonce or an external file. Frame-ancestors
// is 'self' rather than X-Frame-Options alone so both modern and legacy
// browsers are covered.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				// styles allow inline: the existing share/login pages set
				// element styles; tighten when phase 6 rewrites the UI.
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob:; "+
				"media-src 'self' blob:; "+
				"font-src 'self' data:; "+
				"connect-src 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'self'; "+
				"base-uri 'self'; "+
				"object-src 'none'")
		// Don't let a browser guess a content type for a download.
		h.Set("X-Download-Options", "noopen")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		// The Go rewrite serves no third-party resources, so a strict
		// referrer policy is safe and leaks the least.
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the status and byte count for logging without
// consuming the body.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush forwards to the underlying writer when it supports flushing — htmx
// streaming responses and zip downloads depend on this not being swallowed.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// RequestLog logs one line per request. Logs paths and statuses, never
// bodies or query values that might carry secrets (passwords, tokens).
func RequestLog(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			logger.Printf("%s %s %d %dB %s", r.Method, r.URL.Path, rec.status, rec.bytes, time.Since(start).Round(time.Millisecond))
		})
	}
}

// Recover turns a panic into a 500 rather than a dropped connection, and logs
// the stack server-side. The client gets a terse message: internals in an
// error body are an information leak.
func Recover(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Printf("panic: %v\n%s", err, debug.Stack())
					http.Error(w, "Server error.", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Chain applies middleware so that the first argument is the outermost
// wrapper. Chain(h, Recover, Log, SecurityHeaders) runs Recover, then Log,
// then SecurityHeaders, then h.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
