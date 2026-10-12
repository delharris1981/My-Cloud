package vfs

import (
	"sync"
	"time"
)

// quotaCache memoises per-user disk usage for a short TTL.
//
// Usage is derived from the filesystem, never stored in a column: a usage_bytes
// field would drift the moment a file changed outside the app (rsync, SMB, a
// shell in the container). The cache exists only so an upload quota check does
// not walk the whole tree on every chunk.
type quotaCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	now   func() time.Time
	users map[string]usageEntry
}

type usageEntry struct {
	bytes  int64
	reads  int
	expiry time.Time
}

// NewQuotaCache returns a cache with the given TTL.
func NewQuotaCache(ttl time.Duration) *QuotaCache {
	return &QuotaCache{quotaCache{
		ttl:   ttl,
		now:   time.Now,
		users: make(map[string]usageEntry),
	}}
}

// QuotaCache is the exported handle; the inner type is unexported so callers
// cannot mutate entries directly.
type QuotaCache struct {
	quotaCache
}

// Get returns cached usage for key, calling compute on a miss or a stale hit.
//
// The in-flight counter lets a burst of concurrent uploads for one user share
// a single walk instead of stampeding the disk. It is an optimisation only:
// if the stampede is slow the TTL still bounds how stale a value gets.
func (c *QuotaCache) Get(key string, compute func() int64) int64 {
	c.mu.Lock()
	e, ok := c.users[key]
	now := c.now()
	if ok && now.Before(e.expiry) {
		c.users[key] = usageEntry{bytes: e.bytes, reads: e.reads - 1, expiry: e.expiry}
		c.mu.Unlock()
		return e.bytes
	}
	if ok && e.reads > 0 {
		// A walk is already in flight for this user. Return the stale value
		// rather than starting another; uploads re-check on completion.
		c.users[key] = usageEntry{bytes: e.bytes, reads: e.reads - 1, expiry: e.expiry}
		c.mu.Unlock()
		return e.bytes
	}
	c.users[key] = usageEntry{bytes: e.bytes, reads: 1, expiry: e.expiry}
	c.mu.Unlock()

	fresh := compute()

	c.mu.Lock()
	defer c.mu.Unlock()
	reads := 0
	if cur, ok := c.users[key]; ok {
		reads = cur.reads - 1
	}
	if reads < 0 {
		reads = 0
	}
	c.users[key] = usageEntry{bytes: fresh, reads: reads, expiry: c.now().Add(c.ttl)}
	return fresh
}

// Invalidate drops the cached value for key so the next Get recomputes. Call
// after a mutation that changes usage by a significant amount.
func (c *QuotaCache) Invalidate(key string) {
	c.mu.Lock()
	delete(c.users, key)
	c.mu.Unlock()
}

// Sweep evicts expired entries so the map cannot grow without bound across
// many users.
func (c *QuotaCache) Sweep() {
	c.mu.Lock()
	now := c.now()
	for k, e := range c.users {
		if now.After(e.expiry) && e.reads <= 0 {
			delete(c.users, k)
		}
	}
	c.mu.Unlock()
}
