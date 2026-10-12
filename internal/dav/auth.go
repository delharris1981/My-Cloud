// Package dav implements the WebDAV verbs needed to mount a user's files as a
// network drive.
//
// It is hand-rolled on vfs rather than taken from a library: the interesting
// part is that every path is client-supplied and must funnel through
// vfs.Resolve, and a generic library would either do that badly or hide it.
//
// Basic auth accepts an app password always, and the account password only
// when 2FA is off — otherwise WebDAV would be a second-factor bypass.
package dav

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Mount is the URL prefix the DAV endpoint is served under.
const Mount = "/dav"

// Allow is the value sent in the Allow header on OPTIONS.
const Allow = "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK"

// BasicAuthenticator resolves a username and password to an authenticated
// user. It is supplied by the caller so this package does not depend on the
// auth store directly.
//
// The request is passed as a parameter rather than captured in a closure: a
// shared *http.Request across concurrent requests would be a data race.
type BasicAuthenticator func(r *http.Request, username, password string) (resolvedUsername string, ok bool)

// authCache memoises successful Basic-auth checks.
//
// WebDAV clients re-send credentials on every single request — a directory
// listing is dozens of requests — and each miss would otherwise cost a bcrypt
// or argon2id verification. The key is a hash of the whole Authorization
// header, so the cache never holds a credential.
type authCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	items map[string]authEntry
}

type authEntry struct {
	username string
	expiry   time.Time
}

// NewAuthCache returns a cache with the given TTL and a bound on entry count.
//
// The bound matters: without it, an unauthenticated client could grow the map
// with distinct bogus headers and exhaust memory.
func NewAuthCache(ttl time.Duration, max int) *authCache {
	if max <= 0 {
		max = 1024
	}
	return &authCache{ttl: ttl, max: max, items: make(map[string]authEntry)}
}

func (c *authCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expiry) {
		delete(c.items, key)
		return "", false
	}
	return e.username, true
}

func (c *authCache) put(key, username string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Evict expired entries first; if the map is still at the bound, drop an
	// arbitrary entry rather than growing without limit.
	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expiry) {
			delete(c.items, k)
		}
	}
	if len(c.items) >= c.max {
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}
	c.items[key] = authEntry{username: username, expiry: now.Add(c.ttl)}
}

// authKey hashes an Authorization header for use as a cache key.
func authKey(header string) string {
	sum := sha256.Sum256([]byte(header))
	return hex.EncodeToString(sum[:])
}

// parseBasic extracts username and password from an Authorization header.
func parseBasic(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	s := string(raw)
	i := strings.Index(s, ":")
	if i < 0 {
		// A password containing a colon is fine; a missing colon is not.
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// authenticate resolves the request to a username, using the cache to avoid
// re-verifying on every request.
func authenticate(r *http.Request, cache *authCache, verify BasicAuthenticator) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	key := authKey(header)
	if u, ok := cache.get(key); ok {
		return u, true
	}
	username, password, ok := parseBasic(header)
	if !ok {
		return "", false
	}
	resolved, ok := verify(r, username, password)
	if !ok {
		return "", false
	}
	cache.put(key, resolved)
	return resolved, true
}

// challenge sends the 401 with the realm a client needs to prompt for
// credentials. Without the realm most clients will not retry with a login.
func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="My Cloud", charset="UTF-8"`)
	w.WriteHeader(http.StatusUnauthorized)
}
