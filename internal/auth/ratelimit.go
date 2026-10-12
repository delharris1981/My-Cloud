package auth

import (
	"strings"
	"sync"
	"time"
)

// RateLimiter implements the two independent login buckets from the Node
// version: per-IP and per-username.
//
// Both are needed. Per-IP alone cannot catch a distributed spray against one
// account from many hosts; per-username alone lets one host lock out every
// account. The username bucket is what makes the second attack expensive.
type RateLimiter struct {
	mu          sync.Mutex
	window      time.Duration
	maxPerIP    int
	maxPerUser  int
	ipBuckets   map[string]*bucket
	userBuckets map[string]*bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter returns a limiter with the Node defaults: 20 per IP and 10
// per username in a 15-minute window.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		window:      15 * time.Minute,
		maxPerIP:    20,
		maxPerUser:  10,
		ipBuckets:   make(map[string]*bucket),
		userBuckets: make(map[string]*bucket),
	}
}

func (r *RateLimiter) bump(m map[string]*bucket, key string, max int, now time.Time) bool {
	b, ok := m[key]
	if !ok || now.After(b.resetAt) {
		b = &bucket{resetAt: now.Add(r.window)}
		m[key] = b
	}
	b.count++
	return b.count > max
}

// Allow records an attempt and reports whether it is permitted. username may
// be empty (an unauthenticated public route), in which case only the IP
// bucket applies.
func (r *RateLimiter) Allow(ip, username string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()

	blocked := r.bump(r.ipBuckets, ip, r.maxPerIP, now)
	username = NormaliseUsername(username)
	if username != "" {
		if r.bump(r.userBuckets, username, r.maxPerUser, now) {
			blocked = true
		}
	}
	return !blocked
}

// ClearLoginAttempts forgets a username's failures after a successful login,
// so a legitimate user is not locked out by their own earlier typos.
func (r *RateLimiter) ClearLoginAttempts(username string) {
	r.mu.Lock()
	delete(r.userBuckets, NormaliseUsername(username))
	r.mu.Unlock()
}

// Sweep drops expired buckets. Called periodically so the maps cannot grow
// unbounded across many distinct IPs.
func (r *RateLimiter) Sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, b := range r.ipBuckets {
		if now.After(b.resetAt) {
			delete(r.ipBuckets, k)
		}
	}
	for k, b := range r.userBuckets {
		if now.After(b.resetAt) {
			delete(r.userBuckets, k)
		}
	}
}

// PublicLimiter is the per-IP limiter for the unauthenticated share surface.
// It buckets IPv6 by /64 so a single allocation cannot rotate addresses freely.
type PublicLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	buckets map[string]*bucket
}

// NewPublicLimiter returns a limiter allowing max requests per window.
func NewPublicLimiter(max int, window time.Duration) *PublicLimiter {
	return &PublicLimiter{
		window:  window,
		max:     max,
		buckets: make(map[string]*bucket),
	}
}

// Allow records a request from ip.
func (p *PublicLimiter) Allow(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	b, ok := p.buckets[ipKey(ip)]
	if !ok || now.After(b.resetAt) {
		b = &bucket{resetAt: now.Add(p.window)}
		p.buckets[ipKey(ip)] = b
	}
	b.count++
	allowed := b.count <= p.max
	if !allowed {
		return false
	}
	return true
}

// ipKey buckets IPv6 by /64, IPv4 by full address.
func ipKey(ip string) string {
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) >= 4 {
			return strings.Join(parts[:4], ":")
		}
		return ip
	}
	return ip
}

// Sweep drops expired buckets.
func (p *PublicLimiter) Sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, b := range p.buckets {
		if now.After(b.resetAt) {
			delete(p.buckets, k)
		}
	}
}
